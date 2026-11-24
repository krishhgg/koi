import { describe, expect, test } from 'bun:test';
import { mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { caddyApplier, renderCaddyfile } from '../src/caddy.ts';

const base = { domain: 'previews.example.net', httpPort: 7777, logPort: 7778 };

describe('renderCaddyfile', () => {
	test('sends /__koi/* to koid before any preview route, and everything else to koid last', () => {
		const text = renderCaddyfile({
			...base,
			routes: [{ label: 'hello', upstream: '172.19.0.2:8080' }],
		});
		const koiPaths = text.indexOf('handle /__koi/*');
		const preview = text.indexOf('@p0 host hello.previews.example.net');
		const fallback = text.indexOf('\thandle {\n\t\treverse_proxy 127.0.0.1:7777');
		expect(koiPaths).toBeGreaterThan(0);
		expect(preview).toBeGreaterThan(koiPaths);
		expect(fallback).toBeGreaterThan(preview);
		expect(text).toContain('reverse_proxy 172.19.0.2:8080');
		expect(text).toContain('handle_errors 502 503 504');
		expect(text).toContain('output net 127.0.0.1:7778');
		expect(text).toContain('dns route53');
		// Without waiting for Route 53, the ACME server checks before the TXT
		// record is served and the certificate order fails.
		expect(text).toContain('wait_for_route53_sync true');
		expect(text).toContain('propagation_delay 30s');
	});

	test('streams preview responses and keeps WebSockets open across reloads', () => {
		const text = renderCaddyfile({
			...base,
			routes: [{ label: 'hello', upstream: '172.19.0.2:8080' }],
		});
		expect(text).toContain(
			'reverse_proxy 172.19.0.2:8080 {\n\t\t\tflush_interval -1\n\t\t\tstream_close_delay 8h\n\t\t}',
		);
	});

	test("passes the X-Forwarded-For CloudFront sent on to koid's own pages", () => {
		const text = renderCaddyfile({ ...base, routes: [] });
		expect(text).toContain(
			'\thandle {\n\t\treverse_proxy 127.0.0.1:7777 {\n\t\t\theader_up X-Koi-Forwarded-For {http.request.header.X-Forwarded-For}\n\t\t}\n\t}',
		);
	});

	test("off AWS, with no CloudFront in front, gives koid's pages Caddy's peer's address", () => {
		for (const tls of [
			{ kind: 'internal' },
			{ kind: 'acme-http' },
			{ kind: 'acme-dns', file: '/etc/koi/caddy/dns.caddy' },
		] as const) {
			const text = renderCaddyfile({ ...base, routes: [], tls });
			expect([tls.kind, text]).toEqual([
				tls.kind,
				expect.stringContaining(
					'\thandle {\n\t\treverse_proxy 127.0.0.1:7777 {\n\t\t\theader_up X-Koi-Forwarded-For {http.request.remote.host}\n\t\t}\n\t}',
				),
			]);
			expect(text).not.toContain('X-Forwarded-For}');
		}
	});

	test('is stable for the same routes in any order', () => {
		const a = { label: 'a', upstream: '172.19.0.2:80' };
		const b = { label: 'b', upstream: '172.19.0.3:80' };
		expect(renderCaddyfile({ ...base, routes: [a, b] })).toBe(
			renderCaddyfile({ ...base, routes: [b, a] }),
		);
	});

	test('renders the same file as before for the AWS box, which sets no TLS mode', () => {
		const routes = [{ label: 'hello', upstream: '172.19.0.2:8080' }];
		expect(renderCaddyfile({ ...base, routes, tls: { kind: 'route53' } })).toBe(
			renderCaddyfile({ ...base, routes }),
		);
		expect(renderCaddyfile({ ...base, routes })).not.toContain('on_demand');
	});

	test("takes each other host's TLS mode in place of Route 53, and nothing else changes", () => {
		const routes = [{ label: 'hello', upstream: '172.19.0.2:8080' }];
		const route53 = renderCaddyfile({ ...base, routes });
		const block = /\ttls \{\n\t\tdns route53[\s\S]*?\n\t\}\n/.exec(route53)?.[0] ?? '';
		expect(block).not.toBe('');
		// Off AWS the client's address is Caddy's peer's, not CloudFront's header.
		const offAws = route53.replace(
			'X-Koi-Forwarded-For {http.request.header.X-Forwarded-For}',
			'X-Koi-Forwarded-For {http.request.remote.host}',
		);
		const internal = renderCaddyfile({ ...base, routes, tls: { kind: 'internal' } });
		expect(internal).toBe(
			offAws
				.replace(block, '\ttls internal\n')
				.replace('\tadmin 127.0.0.1:2019\n}', '\tadmin 127.0.0.1:2019\n\tskip_install_trust\n}'),
		);
		const dns = renderCaddyfile({
			...base,
			routes,
			tls: { kind: 'acme-dns', file: '/etc/koi/caddy/dns.caddy' },
		});
		expect(dns).toBe(offAws.replace(block, '\ttls {\n\t\timport /etc/koi/caddy/dns.caddy\n\t}\n'));
		// On demand, with koid's answer to which names are previews'.
		const http = renderCaddyfile({ ...base, routes, tls: { kind: 'acme-http' } });
		expect(http).toBe(
			offAws
				.replace(block, '\ttls {\n\t\ton_demand\n\t}\n')
				.replace(
					'\thandle /__koi/* {',
					'\thandle /__koi/tls-ask {\n\t\trespond 404\n\t}\n\n\thandle /__koi/* {',
				)
				.replace(
					'\tadmin 127.0.0.1:2019\n}',
					'\tadmin 127.0.0.1:2019\n\ton_demand_tls {\n\t\task http://127.0.0.1:7777/__koi/tls-ask\n\t}\n}',
				),
		);
	});

	test("puts Caddy's admin API on a unix socket, mode 0660, when given one, and nothing else changes", () => {
		const routes = [{ label: 'hello', upstream: '172.19.0.2:8080' }];
		const tls = { kind: 'internal' } as const;
		const port = renderCaddyfile({ ...base, routes, tls });
		expect(port).toContain('\tadmin 127.0.0.1:2019\n');
		expect(renderCaddyfile({ ...base, routes, tls, adminSocket: '/run/caddy/admin.sock' })).toBe(
			port.replace('\tadmin 127.0.0.1:2019\n', '\tadmin unix//run/caddy/admin.sock|0660\n'),
		);
		for (const adminSocket of ['run/caddy.sock', '/a b', '/x}\n:80 {']) {
			expect(() => renderCaddyfile({ ...base, routes, tls, adminSocket })).toThrow(
				'bad admin socket',
			);
		}
	});

	test('refuses a DNS provider file that would not be one Caddyfile token', () => {
		for (const file of ['relative.caddy', '/a b', '/x}\n:80 {', '/{env.X}']) {
			expect(() =>
				renderCaddyfile({ ...base, routes: [], tls: { kind: 'acme-dns', file } }),
			).toThrow('bad DNS provider file');
		}
	});

	test('refuses labels and upstreams that could inject config', () => {
		expect(() =>
			renderCaddyfile({ ...base, routes: [{ label: 'x }\n:80 {', upstream: '172.19.0.2:80' }] }),
		).toThrow();
		expect(() =>
			renderCaddyfile({ ...base, routes: [{ label: 'ok', upstream: '172.19.0.2:80 {\n}' }] }),
		).toThrow(/bad upstream/);
		expect(() =>
			renderCaddyfile({ ...base, routes: [{ label: 'ok', upstream: 'evil.example:80' }] }),
		).toThrow(/bad upstream/);
	});
});

describe('caddyApplier', () => {
	// An applier on a real Caddyfile in a temporary directory, with an admin
	// API that answers with `status()` and records what it was sent. `onPost`
	// sees each body while its load is in flight, before the answer.
	async function applier(
		status: () => number,
		onPost: (body: string) => Promise<void> = async () => {},
	) {
		const dir = await mkdtemp(join(tmpdir(), 'koid-caddy-'));
		const file = join(dir, 'Caddyfile');
		await writeFile(file, 'provisioned\n');
		const posts: Array<{ url: string; type: string | null; body: string }> = [];
		const caddy = caddyApplier({
			...base,
			file,
			adminUrl: 'http://127.0.0.1:2019',
			fetch: (async (url: URL, init: RequestInit) => {
				const body = String(init.body);
				posts.push({ url: String(url), type: new Headers(init.headers).get('content-type'), body });
				await onPost(body);
				return new Response(status() < 400 ? '' : 'bad', { status: status() });
			}) as unknown as typeof fetch,
		});
		return { caddy, dir, file, posts, read: () => readFile(file, 'utf8') };
	}

	test('loads the config as a Caddyfile, saves it, loads it again, and skips identical updates', async () => {
		const seenDuringLoads: string[] = [];
		const t = await applier(
			() => 200,
			async () => {
				seenDuringLoads.push(await readFile(join(t.dir, 'Caddyfile'), 'utf8'));
			},
		);
		await t.caddy.apply([]);
		await t.caddy.apply([]);
		const text = renderCaddyfile({ ...base, routes: [] });
		const post = { url: 'http://127.0.0.1:2019/load', type: 'text/caddyfile', body: text };
		expect(t.posts).toEqual([post, post]);
		// The file changed only once Caddy had accepted the text.
		expect(seenDuringLoads).toEqual(['provisioned\n', text]);
		expect(await t.read()).toBe(text);
		// Nothing but the Caddyfile is left in its directory.
		expect(await readdir(t.dir)).toEqual(['Caddyfile']);
		await t.caddy.apply([{ label: 'a', upstream: '172.19.0.2:80' }]);
		expect(t.posts).toHaveLength(4);
	});

	test('loads through a unix socket for unix//PATH, and names that socket in the config', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-caddy-'));
		const file = join(dir, 'Caddyfile');
		const socket = join(dir, 'admin.sock');
		const posts: Array<{ path: string; type: string | null; body: string }> = [];
		const admin = Bun.serve({
			unix: socket,
			fetch: async (req) => {
				posts.push({
					path: new URL(req.url).pathname,
					type: req.headers.get('content-type'),
					body: await req.text(),
				});
				return new Response('');
			},
		});
		try {
			const tls = { kind: 'internal' } as const;
			await caddyApplier({ ...base, tls, file, adminUrl: `unix/${socket}` }).apply([]);
			const text = renderCaddyfile({ ...base, routes: [], tls, adminSocket: socket });
			expect(text).toContain(`\tadmin unix/${socket}|0660\n`);
			const post = { path: '/load', type: 'text/caddyfile', body: text };
			expect(posts).toEqual([post, post]);
			expect(await readFile(file, 'utf8')).toBe(text);
		} finally {
			await admin.stop(true);
		}
	});

	test('a Caddy that restarts between the load and the save ends up running the new config', async () => {
		// What the fake Caddy runs: the last config it accepted, or the file
		// when it starts.
		let running = '';
		let restartAfterNextLoad = false;
		const t = await applier(
			() => 200,
			async (body) => {
				running = body;
				if (restartAfterNextLoad) {
					restartAfterNextLoad = false;
					running = await t.read();
				}
			},
		);
		const before = [{ label: 'a', upstream: '172.19.0.2:80' }];
		await t.caddy.apply(before);
		restartAfterNextLoad = true;
		const after = [{ label: 'a', upstream: '172.19.0.3:80' }];
		await t.caddy.apply(after);
		expect(running).toBe(renderCaddyfile({ ...base, routes: after }));
		expect(await t.read()).toBe(running);
	});

	test("with a DNS provider, leaves Caddy's reason out of the error, since it may quote the provider's key", async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-caddy-'));
		const caddy = caddyApplier({
			...base,
			tls: { kind: 'acme-dns', file: '/etc/koi/caddy/dns.caddy' },
			file: join(dir, 'Caddyfile'),
			adminUrl: 'http://127.0.0.1:2019',
			fetch: (async () =>
				new Response("API token 'abc123' appears invalid", {
					status: 400,
				})) as unknown as typeof fetch,
		});
		const err = await caddy.apply([]).catch((e: unknown) => e);
		expect(String(err)).toBe(
			"Error: caddy rejected the config: 400 (the reason is in Caddy's log: journalctl -u caddy)",
		);
	});

	test('a failed second load fails the apply, and the next apply sends again', async () => {
		// The fourth load, the second of the second apply, is refused.
		const t = await applier(() => (t.posts.length === 4 ? 502 : 200));
		const routes = [{ label: 'a', upstream: '172.19.0.2:80' }];
		await t.caddy.apply([]);
		await expect(t.caddy.apply(routes)).rejects.toThrow('caddy rejected the config: 502');
		// Caddy accepted the text once, so the file holds it.
		expect(await t.read()).toBe(renderCaddyfile({ ...base, routes }));
		await t.caddy.apply(routes);
		expect(t.posts).toHaveLength(6);
	});

	test('a rejected load leaves the file alone and the next apply sends again', async () => {
		let status = 200;
		const t = await applier(() => status);
		const before = [{ label: 'a', upstream: '172.19.0.2:80' }];
		await t.caddy.apply(before);
		const saved = await t.read();
		status = 400;
		await expect(t.caddy.apply([])).rejects.toThrow(/caddy rejected/);
		expect(await t.read()).toBe(saved);
		// Going back to the routes Caddy had before is sent again, not skipped:
		// after a failure what Caddy runs is not known.
		status = 200;
		await t.caddy.apply(before);
		expect(t.posts).toHaveLength(5);
		expect(t.posts.at(-1)?.body).toBe(saved);
		await t.caddy.apply([]);
		expect(await t.read()).toBe(renderCaddyfile({ ...base, routes: [] }));
	});

	test('a load that fails without an answer is sent again too', async () => {
		let fail = false;
		const t = await applier(
			() => 200,
			async () => {
				if (fail) throw new Error('The operation timed out.');
			},
		);
		await t.caddy.apply([]);
		fail = true;
		await expect(t.caddy.apply([{ label: 'a', upstream: '172.19.0.2:80' }])).rejects.toThrow(
			'timed out',
		);
		fail = false;
		await t.caddy.apply([]);
		expect(t.posts).toHaveLength(5);
	});
});
