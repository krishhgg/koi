import { describe, expect, test } from 'bun:test';
import { join } from 'node:path';
import { PREVIEW_LABEL, PROVIDERS, TOKEN_PREFIXES } from '@koi/shared';
import type { EgressControl } from '../src/egress.ts';
import {
	FORGET_LIMITS,
	handleKeys,
	KEYS_HTML,
	KEYS_JS,
	MAX_BODY_BYTES,
	REGISTER_LIMITS,
	viewerSource,
} from '../src/keys.ts';
import { RateLimit } from '../src/ratelimit.ts';

const TOKEN = `koi_${'a'.repeat(32)}`;
const LABEL = 'storefront-pr-7';
const ORIGIN = 'https://keys.previews.example.net';

// The proxy's side: a fresh token per key, as koi_egress.py makes them.
function fakeEgress(fail = false) {
	const calls: Array<{
		op: string;
		label?: string;
		token?: string;
		keys?: Record<string, string>;
		source?: string;
	}> = [];
	let made = 0;
	const egress: EgressControl = {
		register: async (label, keys, source) => {
			if (fail) throw new Error(`proxy said: bad key ${JSON.stringify(keys)}`);
			calls.push({ op: 'register', label, keys, source });
			const tokens: Record<string, string> = {};
			for (const p of Object.keys(keys)) {
				made += 1;
				tokens[p] = `koi_${String(made).padStart(32, '0')}`;
			}
			return tokens;
		},
		forget: async (token) => {
			calls.push({ op: 'forget', token });
		},
		previews: async () => {},
	};
	return { egress, calls };
}

const post = (
	path: string,
	body: unknown,
	origin: string | null = ORIGIN,
	forwardedFor: string | null = null,
) =>
	new Request(`http://keys.previews.example.net${path}`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			...(origin ? { origin } : {}),
			...(forwardedFor !== null ? { 'x-koi-forwarded-for': forwardedFor } : {}),
		},
		body: typeof body === 'string' ? body : JSON.stringify(body),
	});

// The keys page as koid serves it, with the registration limits it uses.
const page = (
	request: Request,
	egress: EgressControl,
	register = new RateLimit(REGISTER_LIMITS),
	forget = new RateLimit(FORGET_LIMITS),
) => handleKeys(request, egress, { register, forget });

describe('keys page', () => {
	test('serves the page and its script with a strict content security policy', async () => {
		const { egress } = fakeEgress();
		for (const path of ['/', '/keys.js', '/keys.css']) {
			const res = await page(new Request(`http://keys.previews.example.net${path}`), egress);
			expect(res.status).toBe(200);
			const csp = res.headers.get('content-security-policy') ?? '';
			expect(csp).toContain("script-src 'self'");
			expect(csp).toContain("frame-ancestors 'none'");
			expect(res.headers.get('cache-control')).toBe('no-store');
		}
		expect(KEYS_HTML).not.toContain('<script>');
		for (const p of PROVIDERS) expect(KEYS_HTML).toContain(`name="${p.id}"`);
	});

	test('the script never sends keys anywhere but this origin', () => {
		const urls = KEYS_JS.match(/fetch\(([^,)]+)/g) ?? [];
		expect(urls).toEqual(['fetch(path']);
		expect(KEYS_JS).not.toMatch(/https?:\/\//);
	});
});

describe('register and forget', () => {
	test("registers keys for a preview and answers with the proxy's tokens", async () => {
		const { egress, calls } = fakeEgress();
		const res = await page(
			post('/api/register', { label: LABEL, keys: { openai: 'sk-1', anthropic: 'sk-2' } }),
			egress,
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({
			tokens: { openai: `koi_${'0'.repeat(31)}1`, anthropic: `koi_${'0'.repeat(31)}2` },
		});
		expect(calls).toEqual([
			{
				op: 'register',
				label: LABEL,
				keys: { openai: 'sk-1', anthropic: 'sk-2' },
				source: 'unknown',
			},
		]);
	});

	test('tells the secret hook every key and token of a successful registration, and nothing of a refused one', async () => {
		const { egress } = fakeEgress();
		const seen: string[][] = [];
		const register = new RateLimit(REGISTER_LIMITS);
		const forget = new RateLimit(FORGET_LIMITS);
		const res = await handleKeys(
			post('/api/register', { label: LABEL, keys: { openai: 'sk-1', anthropic: 'sk-2' } }),
			egress,
			{ register, forget },
			(values) => seen.push(values),
		);
		expect(res.status).toBe(200);
		// The keys as sent and the tokens the proxy made, so the evidence
		// sanitizers know both.
		expect(seen).toEqual([['sk-1', 'sk-2', `koi_${'0'.repeat(31)}1`, `koi_${'0'.repeat(31)}2`]]);
		// A proxy failure registers nothing.
		const failing = fakeEgress(true);
		const refused = await handleKeys(
			post('/api/register', { label: LABEL, keys: { openai: 'sk-3' } }),
			failing.egress,
			{ register, forget },
			(values) => seen.push(values),
		);
		expect(refused.status).toBe(503);
		expect(seen).toHaveLength(1);
	});

	test('forgets a token', async () => {
		const { egress, calls } = fakeEgress();
		expect((await page(post('/api/forget', { token: TOKEN }), egress)).status).toBe(200);
		expect(calls).toEqual([{ op: 'forget', token: TOKEN }]);
	});

	test('a caller who knows a token can forget it, never bind it to other keys or another preview', async () => {
		// The preview's code knows its tokens. A registration names no token,
		// so it always gets fresh ones; one that names a token is refused.
		const { egress, calls } = fakeEgress();
		for (const body of [
			{ token: TOKEN, label: LABEL, keys: { openai: 'sk-attacker' } },
			{ token: TOKEN, keys: { openai: 'sk-attacker' } },
			{ tokens: { openai: TOKEN }, label: 'evil-pr-8', keys: { openai: 'sk-attacker' } },
		]) {
			expect((await page(post('/api/register', body), egress)).status).toBe(400);
		}
		expect(
			(await page(post('/api/forget', { token: TOKEN, label: 'evil-pr-8' }), egress)).status,
		).toBe(400);
		expect(calls).toEqual([]);
	});

	test('refuses calls from any other origin, including previews', async () => {
		const { egress, calls } = fakeEgress();
		for (const origin of [
			'https://storefront-pr-1.previews.example.net',
			'https://evil.example',
			null,
		]) {
			const res = await page(
				post('/api/register', { label: LABEL, keys: { openai: 'k' } }, origin),
				egress,
			);
			expect(res.status).toBe(403);
		}
		expect(calls).toEqual([]);
	});

	test('rejects bad labels, no keys, unknown providers, multi-line keys and non-JSON', async () => {
		const { egress, calls } = fakeEgress();
		const bad = [
			{ keys: { openai: 'k' } },
			{ label: 'Not_A_Label', keys: { openai: 'k' } },
			{ label: LABEL, keys: {} },
			{ label: LABEL, keys: { notaprovider: 'k' } },
			{ label: LABEL, keys: { openai: 'k\r\nx: y' } },
			{ label: LABEL, keys: { openai: '' } },
		];
		for (const body of bad)
			expect((await page(post('/api/register', body), egress)).status).toBe(400);
		expect((await page(post('/api/register', '{not json'), egress)).status).toBe(400);
		expect((await page(post('/api/forget', { token: 'koi_short' }), egress)).status).toBe(400);
		expect(calls).toEqual([]);
	});

	test('a proxy failure is a 503 that echoes nothing', async () => {
		const { egress } = fakeEgress(true);
		const res = await page(
			post('/api/register', { label: LABEL, keys: { openai: 'sk-secret' } }),
			egress,
		);
		expect(res.status).toBe(503);
		expect(await res.text()).not.toContain('sk-secret');
	});
});

describe('registration limits', () => {
	test.each([
		['203.0.113.9', '203.0.113.9'],
		// Entries before the last are the client's own; CloudFront appends last.
		['6.6.6.6, 203.0.113.9', '203.0.113.9'],
		['6.6.6.6,203.0.113.9', '203.0.113.9'],
		['2001:db8:aa:bb:cc:dd:ee:ff', '2001:db8:aa:bb::/64'],
		['2001:0DB8:aa:bb::1', '2001:db8:aa:bb::/64'],
		['2001:db8::1', '2001:db8:0:0::/64'],
		// One /64 written five ways, "::" standing in different places.
		['2600::1234:1:2:3:4', '2600:0:0:1234::/64'],
		['2600:0:0:1234::1', '2600:0:0:1234::/64'],
		['2600:0000:0000:1234:0001:0002:0003:0004', '2600:0:0:1234::/64'],
		['2600:0:0:1234:ffff::', '2600:0:0:1234::/64'],
		['2600::1234:0:0:0:0', '2600:0:0:1234::/64'],
		// Neighbouring /64s stay apart.
		['2600::1235:0:0:0:1', '2600:0:0:1235::/64'],
		['2600::1', '2600:0:0:0::/64'],
		['2600:0:0:1233:ffff:ffff:ffff:ffff', '2600:0:0:1233::/64'],
		// IPv4 inside IPv6.
		['::ffff:203.0.113.9', '203.0.113.9'],
		['::ffff:cb00:7109', '203.0.113.9'],
		['64:ff9b::203.0.113.9', '64:ff9b:0:0::/64'],
		['1:2:3:4:5:6:1.2.3.4', '1:2:3:4::/64'],
		['::1', '0:0:0:0::/64'],
		['203.0.113.9, not-an-address', 'unknown'],
		['', 'unknown'],
		[null, 'unknown'],
	])('the source of X-Koi-Forwarded-For %p is %p', (forwardedFor, source) => {
		expect(viewerSource(post('/api/register', {}, ORIGIN, forwardedFor))).toBe(source);
	});

	test('passes the viewer address on to the proxy as the source', async () => {
		const { egress, calls } = fakeEgress();
		const req = post(
			'/api/register',
			{ label: LABEL, keys: { openai: 'k' } },
			ORIGIN,
			'6.6.6.6, 2001:db8:aa:bb::7',
		);
		expect((await page(req, egress)).status).toBe(200);
		expect(calls[0]?.source).toBe('2001:db8:aa:bb::/64');
	});

	test('limits registrations per address and from everyone, and starts again each window', async () => {
		const { egress, calls } = fakeEgress();
		let now = 0;
		const limit = new RateLimit({ perSource: 2, total: 3, windowMs: 60_000 }, () => now);
		const register = async (from: string) =>
			(
				await page(
					post('/api/register', { label: LABEL, keys: { openai: 'k' } }, ORIGIN, from),
					egress,
					limit,
				)
			).status;
		expect(await register('198.51.100.1')).toBe(200);
		expect(await register('198.51.100.1')).toBe(200);
		expect(await register('198.51.100.1')).toBe(429);
		// Another address in the same /64 is the same source.
		expect(await register('2001:db8:1:2::1')).toBe(200);
		expect(await register('2001:db8:1:2::9')).toBe(429);
		expect(await register('198.51.100.3')).toBe(429);
		expect(calls).toHaveLength(3);
		now += 60_000;
		expect(await register('198.51.100.1')).toBe(200);
	});

	test('a refused registration says why and never reaches the proxy', async () => {
		const { egress, calls } = fakeEgress();
		const limit = new RateLimit({ perSource: 0, total: 10, windowMs: 60_000 });
		const res = await page(
			post('/api/register', { label: LABEL, keys: { openai: 'sk-secret' } }),
			egress,
			limit,
		);
		expect(res.status).toBe(429);
		const text = await res.text();
		expect(text).toContain('too many registrations');
		expect(text).not.toContain('sk-secret');
		expect(calls).toEqual([]);
	});

	test('limits forgetting on its own limit, and registering does not use it up', async () => {
		const { egress, calls } = fakeEgress();
		const register = new RateLimit({ perSource: 0, total: 0, windowMs: 60_000 });
		const forget = new RateLimit({ perSource: 2, total: 10, windowMs: 60_000 });
		const forgetOne = async () =>
			(await page(post('/api/forget', { token: TOKEN }), egress, register, forget)).status;
		expect(await forgetOne()).toBe(200);
		expect(await forgetOne()).toBe(200);
		const refused = await page(post('/api/forget', { token: TOKEN }), egress, register, forget);
		expect(refused.status).toBe(429);
		expect(await refused.text()).toContain('too many requests to forget');
		expect(calls).toHaveLength(2);
	});

	test('a body over the limit is refused, unread when its length says so', async () => {
		const { egress, calls } = fakeEgress();
		let pulled = false;
		const unread = new Request('http://keys.previews.example.net/api/register', {
			method: 'POST',
			headers: { origin: ORIGIN, 'content-length': String(64 * 1024 * 1024) },
			// Pulled only when something reads it.
			body: new ReadableStream(
				{
					pull() {
						pulled = true;
					},
				},
				{ highWaterMark: 0 },
			),
		});
		expect((await page(unread, egress)).status).toBe(413);
		expect(pulled).toBe(false);
		// Without a length, it is read only until it passes the limit.
		let sent = 0;
		const endless = new Request('http://keys.previews.example.net/api/forget', {
			method: 'POST',
			headers: { origin: ORIGIN },
			body: new ReadableStream({
				pull(controller) {
					sent += 1024;
					controller.enqueue(new Uint8Array(1024).fill(32));
				},
			}),
		});
		expect((await page(endless, egress)).status).toBe(413);
		expect(sent).toBeLessThan(MAX_BODY_BYTES + 16 * 1024);
		// A largest real registration still fits.
		const keys = Object.fromEntries(PROVIDERS.map((p) => [p.id, 'k'.repeat(512)]));
		expect((await page(post('/api/register', { label: LABEL, keys }), egress)).status).toBe(200);
		expect(calls).toHaveLength(1);
	});
});

describe('the page', () => {
	test('names the preview from ?for=, and asks for one when there is none', () => {
		expect(KEYS_JS).toContain("new URLSearchParams(location.search).get('for')");
		expect(KEYS_JS).toContain(`var LABEL = ${PREVIEW_LABEL};`);
		expect(KEYS_HTML).toContain('id="no-preview"');
		expect(KEYS_HTML).toContain('<strong id="label"></strong>');
	});

	test('registers by label and shows the tokens as text (keys-page.test.ts runs it)', () => {
		expect(KEYS_JS).toContain("post('/api/register', { label: label, keys: keys })");
		expect(KEYS_JS).not.toContain('innerHTML');
		expect(KEYS_JS).not.toContain('newToken');
	});
});

describe('provider lists', () => {
	test('the egress proxy intercepts exactly the providers the keys page offers', async () => {
		const py = await Bun.file(join(import.meta.dir, '../../../host/egress/koi_egress.py')).text();
		const block = py.slice(
			py.indexOf('PROVIDERS = {'),
			py.indexOf('}', py.indexOf('PROVIDERS = {')),
		);
		const pairs = [...block.matchAll(/"([^"]+)":\s*"([^"]+)"/g)].map((m) => [m[1], m[2]]);
		expect(pairs.sort()).toEqual(PROVIDERS.map((p) => [p.host, p.id]).sort());
	});

	test('the egress proxy takes tokens after the same provider prefixes the keys page shows', async () => {
		const py = await Bun.file(join(import.meta.dir, '../../../host/egress/koi_egress.py')).text();
		const line = /^TOKEN_PREFIXES = (\{.*\})$/m.exec(py)?.[1] ?? '';
		expect(JSON.parse(line)).toEqual(TOKEN_PREFIXES);
	});

	test('the keys API checks bodies with the shared schemas, and declares none of its own', async () => {
		const source = await Bun.file(join(import.meta.dir, '../src/keys.ts')).text();
		expect(source).toContain('RegisterKeysSchema.safeParse(body)');
		expect(source).toContain('ForgetTokenSchema.safeParse(body)');
		expect(source).not.toContain("from 'zod'");
	});

	test('the egress proxy checks preview labels with the same pattern', async () => {
		const py = await Bun.file(join(import.meta.dir, '../../../host/egress/koi_egress.py')).text();
		const pattern = /^LABEL_RE = re\.compile\(r"([^"]+)"\)$/m.exec(py)?.[1];
		expect(`^${pattern}$`).toBe(PREVIEW_LABEL.source);
	});
});
