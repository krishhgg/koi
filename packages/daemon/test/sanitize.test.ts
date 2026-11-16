import { describe, expect, test } from 'bun:test';
import { SecretRegistry } from '../src/redact.ts';
import {
	isWithheldKind,
	LIMITATIONS,
	policyDigest,
	RESPONSE_HEADER_ALLOWLIST,
	SanitizeError,
	sanitizeHttpResponse,
	sanitizeNetwork,
	sanitizeScreenshot,
	sanitizeText,
	scrubUrl,
	WITHHELD_KINDS,
} from '../src/sanitize.ts';
import { PNG_STRIPPED, PNG_WITH_METADATA } from './png.ts';

const encode = (text: string) => new TextEncoder().encode(text);
const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

function registry(...values: string[]): SecretRegistry {
	const r = new SecretRegistry();
	for (const v of values) r.add(v);
	return r;
}

describe('policies', () => {
	test('each kind has a digest of its own, stable across calls', () => {
		const digests = new Set(
			(
				[
					'screenshot',
					'aria',
					'console',
					'network',
					'http-response',
					'trace',
					'har',
					'file',
				] as const
			).map(policyDigest),
		);
		expect(digests.size).toBe(8);
		expect(policyDigest('aria')).toBe(policyDigest('aria'));
		expect(policyDigest('aria')).toMatch(/^sha256:[0-9a-f]{64}$/);
	});

	test('trace, har and file are withheld with a reason', () => {
		expect(isWithheldKind('trace')).toBe(true);
		expect(isWithheldKind('screenshot')).toBe(false);
		for (const kind of ['trace', 'har', 'file'] as const) {
			expect(WITHHELD_KINDS[kind]).toContain('not');
			expect(LIMITATIONS[kind]).toEqual([WITHHELD_KINDS[kind]]);
		}
	});
});

describe('sanitizeScreenshot', () => {
	test('strips metadata chunks and says which', () => {
		const result = sanitizeScreenshot(PNG_WITH_METADATA);
		expect(result.bytes).toEqual(PNG_STRIPPED);
		expect(result.removedFields).toEqual(['png:tEXt', 'png:tIME']);
		expect(result.limitations[0]).toContain('pixels may contain');
	});

	test('refuses what is not a PNG, so the artifact is withheld', () => {
		expect(() => sanitizeScreenshot(encode('<svg/>'))).toThrow(SanitizeError);
	});
});

describe('sanitizeText', () => {
	test('scrubs known values and patterns line by line', () => {
		const secrets = registry('the-login-value-12345');
		const result = sanitizeText(
			encode(
				'- textbox "Key": the-login-value-12345\n- text: token sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789-AAAA',
			),
			secrets,
			'aria',
		);
		expect(decode(result.bytes)).toBe('- textbox "Key": [redacted]\n- text: token [redacted]\n');
		expect(result.limitations).toEqual([...LIMITATIONS.aria]);
		expect(result.removedFields).toEqual([]);
	});
});

describe('sanitizeNetwork', () => {
	const record = {
		id: 1,
		pageId: 'p1',
		method: 'GET',
		url: 'http://user:pw@app.x.invalid:8080/v1/models?key=AIzaSyA-abcdefghijklmnopqrstuvwxyz0123',
		resourceType: 'fetch',
		navigation: false,
		startedAt: '2026-10-06T12:00:00.000Z',
		endedAt: '2026-10-06T12:00:00.100Z',
		status: 200,
		headers: {
			'content-type': 'application/json',
			'set-cookie': 'session=abc',
			'x-provider-key': 'secret',
			'Content-Length': '12',
		},
		body: '{"should":"never be here"}',
	};

	test('projects each record to the kept fields, allowlists headers and scrubs the URL', () => {
		const result = sanitizeNetwork(
			encode(`${JSON.stringify(record)}\n{"dropped":3}\n`),
			registry(),
		);
		const lines = decode(result.bytes).trimEnd().split('\n');
		expect(JSON.parse(lines[0] ?? '')).toEqual({
			id: 1,
			pageId: 'p1',
			method: 'GET',
			url: 'http://app.x.invalid:8080/v1/models?key=[redacted]',
			resourceType: 'fetch',
			navigation: false,
			startedAt: '2026-10-06T12:00:00.000Z',
			endedAt: '2026-10-06T12:00:00.100Z',
			status: 200,
			headers: { 'content-type': 'application/json', 'content-length': '12' },
		});
		expect(JSON.parse(lines[1] ?? '')).toEqual({ dropped: 3 });
		expect(result.removedFields).toEqual([
			'bodies',
			'header:set-cookie',
			'header:x-provider-key',
			'network:body',
			'request-headers',
		]);
		expect(result.limitations).toContain(
			"3 observations past the recorder's limit were not recorded",
		);
		for (const name of ['content-type', 'location', 'cache-control']) {
			expect(RESPONSE_HEADER_ALLOWLIST).toContain(name);
		}
		expect(RESPONSE_HEADER_ALLOWLIST).not.toContain('set-cookie');
	});

	test('the method, the failure text and the names of dropped headers are scrubbed too', () => {
		const secret = 'the-login-value-12345';
		const secrets = registry(secret);
		const line = {
			...record,
			method: secret,
			resourceType: `fetch ${secret}`,
			failed: `net::ERR ${secret}`,
			headers: { [secret]: 'x', [`x-${secret}-id`]: 'y', 'content-type': secret },
		};
		const result = sanitizeNetwork(encode(`${JSON.stringify(line)}\n`), secrets);
		const kept = JSON.parse(decode(result.bytes).trimEnd()) as Record<string, unknown>;
		expect(kept.method).toBe('[redacted]');
		expect(kept.resourceType).toBe('fetch [redacted]');
		expect(kept.failed).toBe('net::ERR [redacted]');
		expect(kept.headers).toEqual({ 'content-type': '[redacted]' });
		expect(result.removedFields).toEqual([
			'bodies',
			'header:[redacted]',
			'header:x-[redacted]-id',
			'network:body',
			'request-headers',
		]);
		expect(JSON.stringify(result)).not.toContain(secret);
	});

	test('a known value past the cut is scrubbed before the cut, not after', () => {
		// 4,065 characters of padding put the value across the 4,096 bound:
		// cut first, 31 of its characters would stay and match no form.
		const secret = 'the-login-value-0123456789abcdefghijklmnop';
		const secrets = registry(secret);
		const past = `${'p'.repeat(4065)}${secret}`;
		const line = { ...record, method: past, headers: { 'content-type': past, [past]: 'x' } };
		const result = sanitizeNetwork(encode(`${JSON.stringify(line)}\n`), secrets);
		const kept = JSON.parse(decode(result.bytes).trimEnd()) as {
			method: string;
			headers: Record<string, string>;
		};
		expect(kept.method).toBe(`${'p'.repeat(4065)}[redacted]`);
		expect(kept.headers['content-type']).toBe(`${'p'.repeat(4065)}[redacted]`);
		expect(kept.method.length).toBeLessThanOrEqual(4096);
		expect(JSON.stringify(result)).not.toContain(secret.slice(0, 31));
	});

	test('removedFields and strings are bounded to what the manifest takes', () => {
		const headers: Record<string, string> = {};
		for (let i = 0; i < 1500; i++) headers[`x-h-${i}-${'n'.repeat(300)}`] = 'v';
		const result = sanitizeNetwork(
			encode(`${JSON.stringify({ ...record, headers, method: 'M'.repeat(10_000) })}\n`),
			registry(),
		);
		expect(result.removedFields).toHaveLength(1000);
		expect(result.removedFields.every((f) => f.length <= 200)).toBe(true);
		expect(result.removedFields.at(-1)).toBe('more:names past the manifest limit');
		const kept = JSON.parse(decode(result.bytes).trimEnd()) as { method: string };
		expect(kept.method).toHaveLength(4096);
	});

	test('an empty capture stays empty, and a line that is not a record is refused', () => {
		expect(sanitizeNetwork(new Uint8Array(0), registry()).bytes.length).toBe(0);
		expect(() => sanitizeNetwork(encode('not json\n'), registry())).toThrow(SanitizeError);
		expect(() => sanitizeNetwork(encode('[1,2]\n'), registry())).toThrow(SanitizeError);
		// The shared schema: a record without a field the recorder always
		// writes, or with one of another type, is refused, and the reason
		// names the field, never a value.
		const { url: _url, ...noUrl } = record;
		expect(() => sanitizeNetwork(encode(`${JSON.stringify(noUrl)}\n`), registry())).toThrow(
			/a network line is not a record the recorder writes: url/,
		);
		const secret = 'the-login-value-12345';
		let refused: unknown;
		try {
			sanitizeNetwork(encode(`${JSON.stringify({ ...record, status: secret })}\n`), registry());
		} catch (err) {
			refused = err;
		}
		expect(refused).toBeInstanceOf(SanitizeError);
		expect((refused as Error).message).toContain('status');
		expect((refused as Error).message).not.toContain(secret);
		// A dropped line past the limit is the one other shape.
		expect(() => sanitizeNetwork(encode('{"dropped":0}\n'), registry())).toThrow(SanitizeError);
	});
});

describe('sanitizeHttpResponse', () => {
	const read = (body: string, more: Record<string, unknown> = {}) =>
		encode(
			JSON.stringify({
				request: { method: 'GET', url: 'http://app.x.invalid:8080/api/state' },
				response: {
					status: 200,
					headers: { 'content-type': 'application/json', 'set-cookie': 'a=b' },
					bodyBase64: Buffer.from(body).toString('base64'),
					bodyBytes: Buffer.byteLength(body),
					truncated: false,
					...more,
				},
				startedAt: '2026-10-06T12:00:00.000Z',
				endedAt: '2026-10-06T12:00:00.050Z',
			}),
		);

	test('keeps status and allowlisted headers, and the body only under the policy', () => {
		const secrets = registry('hunter2hunter2');
		const without = sanitizeHttpResponse(read('{"name":"x"}'), secrets, {
			body: false,
			maxBodyBytes: 4096,
		});
		const projected = JSON.parse(decode(without.bytes)) as { response: Record<string, unknown> };
		expect(projected.response).toEqual({
			status: 200,
			headers: { 'content-type': 'application/json' },
			bodyBytes: 12,
			truncated: false,
			bodyOmitted: 'the point policy did not ask for the body',
		});
		expect(without.removedFields).toEqual(['body', 'header:set-cookie']);
		const withBody = sanitizeHttpResponse(read('{"name":"x","pw":"hunter2hunter2"}'), secrets, {
			body: true,
			maxBodyBytes: 4096,
		});
		expect(
			(JSON.parse(decode(withBody.bytes)) as { response: { body: string } }).response.body,
		).toBe('{"name":"x","pw":"[redacted]"}');
		expect(withBody.removedFields).toEqual(['header:set-cookie']);
	});

	test('scrubs the names of dropped headers, and refuses a method the recorder never sends', () => {
		const secret = 'the-login-value-12345';
		const result = sanitizeHttpResponse(
			read('', { headers: { [secret]: '1', 'set-cookie': 'a=b' } }),
			registry(secret),
			{ body: false, maxBodyBytes: 0 },
		);
		expect(result.removedFields).toEqual(['body', 'header:[redacted]', 'header:set-cookie']);
		expect(JSON.stringify(result)).not.toContain(secret);
		// The method is koid's own, GET or HEAD; anything else is not a
		// state read the recorder made, and the reason names the field, not
		// the value.
		const odd = encode(
			decode(read('')).replace('"method":"GET"', `"method":${JSON.stringify(secret)}`),
		);
		let refused: unknown;
		try {
			sanitizeHttpResponse(odd, registry(), { body: false, maxBodyBytes: 0 });
		} catch (err) {
			refused = err;
		}
		expect(refused).toBeInstanceOf(SanitizeError);
		expect(String((refused as Error).message)).toContain('request.method');
		expect(String((refused as Error).message)).not.toContain(secret);
	});

	test('omits a body over the bound or one that is not text', () => {
		const over = sanitizeHttpResponse(read('x'.repeat(100)), registry(), {
			body: true,
			maxBodyBytes: 50,
		});
		expect(
			(JSON.parse(decode(over.bytes)) as { response: { bodyOmitted: string } }).response
				.bodyOmitted,
		).toContain('over the policy');
		const binary = encode(
			JSON.stringify({
				request: { method: 'GET', url: 'http://app.x.invalid:8080/img' },
				response: {
					status: 200,
					headers: {},
					bodyBase64: Buffer.from([0x89, 0x50, 0x00, 0xff]).toString('base64'),
					bodyBytes: 4,
					truncated: false,
				},
				startedAt: '2026-10-06T12:00:00.000Z',
				endedAt: '2026-10-06T12:00:00.050Z',
			}),
		);
		expect(
			(
				JSON.parse(
					decode(sanitizeHttpResponse(binary, registry(), { body: true, maxBodyBytes: 50 }).bytes),
				) as { response: { bodyOmitted: string } }
			).response.bodyOmitted,
		).toBe('the body is not text');
	});

	test('says when the recorder cut the body before it was scrubbed', () => {
		const cut = sanitizeHttpResponse(read('x'.repeat(50), { truncated: true }), registry(), {
			body: true,
			maxBodyBytes: 50,
		});
		const projected = JSON.parse(decode(cut.bytes)) as {
			response: { body: string; truncated: boolean };
		};
		expect(projected.response.truncated).toBe(true);
		expect(projected.response.body).toBe('x'.repeat(50));
		expect(cut.limitations).toEqual([
			...LIMITATIONS['http-response'],
			expect.stringContaining('cut the body at the bound'),
		]);
		const whole = sanitizeHttpResponse(read('x'), registry(), { body: true, maxBodyBytes: 50 });
		expect(whole.limitations).toEqual([...LIMITATIONS['http-response']]);
	});

	test('refuses what is not a state read, with the shared schema', () => {
		expect(() =>
			sanitizeHttpResponse(encode('nope'), registry(), { body: false, maxBodyBytes: 0 }),
		).toThrow(SanitizeError);
		expect(() =>
			sanitizeHttpResponse(encode('{"response":{}}'), registry(), { body: false, maxBodyBytes: 0 }),
		).toThrow(SanitizeError);
		// A field the recorder always writes, missing: not a state read.
		const partial = JSON.parse(decode(read(''))) as { startedAt?: string };
		delete partial.startedAt;
		expect(() =>
			sanitizeHttpResponse(encode(JSON.stringify(partial)), registry(), {
				body: false,
				maxBodyBytes: 0,
			}),
		).toThrow('startedAt');
		// A field the recorder never writes: not a state read either.
		expect(() =>
			sanitizeHttpResponse(encode(decode(read('')).replace('"endedAt"', '"ended"')), registry(), {
				body: false,
				maxBodyBytes: 0,
			}),
		).toThrow(SanitizeError);
	});
});

describe('scrubUrl', () => {
	test('drops credentials and scrubs the rest', () => {
		expect(
			scrubUrl(
				'http://me:pw@app.x.invalid/?key=AIzaSyA-abcdefghijklmnopqrstuvwxyz0123',
				registry(),
			),
		).toBe('http://app.x.invalid/?key=[redacted]');
		expect(scrubUrl('not a url with koi_0123456789abcdefghijklmnopqrstuv', registry())).toBe(
			'not a url with [redacted]',
		);
	});
});
