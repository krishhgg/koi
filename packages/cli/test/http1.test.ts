import { describe, expect, test } from 'bun:test';
import { type ByteRelay, HttpRelayClient, RelayBrokenError, RelayIdleError } from '../src/http1.ts';

const encode = (text: string) => new TextEncoder().encode(text);
const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

// A relay whose far end is scripted: what the client writes lands in
// `written`, and `reply` feeds bytes back.
function relay() {
	const written: Uint8Array[] = [];
	let out!: ReadableStreamDefaultController<Uint8Array>;
	const readable = new ReadableStream<Uint8Array>({
		start(c) {
			out = c;
		},
	});
	const r: ByteRelay & {
		written: Uint8Array[];
		reply: (text: string) => void;
		close: () => void;
		sent: () => string;
	} = {
		readable,
		written,
		async write(chunk) {
			written.push(chunk);
		},
		reply: (text) => out.enqueue(encode(text)),
		close: () => out.close(),
		sent: () => decode(Buffer.concat(written)),
	};
	return r;
}

describe('HttpRelayClient', () => {
	test('writes a request with a byte body and reads a reply by its content length', async () => {
		const r = relay();
		const c = new HttpRelayClient(r);
		const pending = c.request({
			method: 'POST',
			path: '/v1/uploads',
			headers: { 'content-type': 'application/json' },
			body: encode('{"a":1}'),
		});
		await Bun.sleep(1);
		expect(r.sent()).toBe(
			'POST /v1/uploads HTTP/1.1\r\nHost: koid\r\nConnection: keep-alive\r\ncontent-type: application/json\r\nContent-Length: 7\r\n\r\n{"a":1}',
		);
		r.reply(
			'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
		);
		const reply = await pending;
		expect(reply.status).toBe(201);
		expect(reply.headers).toEqual({ 'content-type': 'application/json', 'content-length': '2' });
		expect(decode(reply.body)).toBe('{}');
	});

	test('reads a chunked reply, and one that ends with the connection', async () => {
		const r = relay();
		const c = new HttpRelayClient(r);
		const first = c.request({ method: 'GET', path: '/a' });
		r.reply(
			'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\nX-Trailer: 1\r\n\r\n',
		);
		expect(decode((await first).body)).toBe('abcde');
		const second = c.request({ method: 'GET', path: '/b' });
		r.reply('HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nrest of it');
		r.close();
		expect(decode((await second).body)).toBe('rest of it');
		// After Connection: close nothing more can be asked.
		await expect(c.request({ method: 'GET', path: '/c' })).rejects.toThrow(RelayBrokenError);
	});

	test('a reply cut short is a broken relay', async () => {
		const r = relay();
		const c = new HttpRelayClient(r);
		const pending = c.request({ method: 'GET', path: '/a' });
		r.reply('HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc');
		r.close();
		await expect(pending).rejects.toThrow(RelayBrokenError);
	});

	test('a reply that is not HTTP, or too large, is refused', async () => {
		const bad = relay();
		const pending = new HttpRelayClient(bad).request({ method: 'GET', path: '/a' });
		bad.reply('SSH-2.0-OpenSSH_9.6\r\n\r\n');
		await expect(pending).rejects.toThrow('not an HTTP reply');
		const big = relay();
		const large = new HttpRelayClient(big, 100).request({ method: 'GET', path: '/a' });
		big.reply('HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n');
		await expect(large).rejects.toThrow('an HTTP reply of 101 bytes; koi takes at most 100');
	});

	test('a streamed body goes out a chunk at a time, and stops once the host has answered', async () => {
		const r = relay();
		const c = new HttpRelayClient(r);
		let pulled = 0;
		const chunks = {
			async *[Symbol.asyncIterator]() {
				for (let i = 0; i < 100; i++) {
					pulled++;
					if (i === 3) r.reply('HTTP/1.1 413 Too Large\r\nContent-Length: 0\r\n\r\n');
					await Bun.sleep(1);
					yield new Uint8Array(10);
				}
			},
		};
		const reply = await c.request({
			method: 'PUT',
			path: '/source',
			body: { chunks, length: 1000 },
		});
		expect(reply.status).toBe(413);
		expect(pulled).toBeLessThan(100);
		expect(r.sent()).toContain('Content-Length: 1000');
	});

	test('a body that does not match its declared length is an error of the sender, at once', async () => {
		const r = relay();
		const c = new HttpRelayClient(r);
		const short = {
			async *[Symbol.asyncIterator]() {
				yield new Uint8Array(5);
			},
		};
		// No reply comes and the relay stays open: the host is waiting for
		// five more bytes. The sender does not wait with it.
		await expect(
			c.request({ method: 'PUT', path: '/s', body: { chunks: short, length: 10 } }),
		).rejects.toThrow('the body ended after 5 of its declared 10 bytes');
		await expect(c.request({ method: 'GET', path: '/a' })).rejects.toThrow(RelayBrokenError);
		const long = {
			async *[Symbol.asyncIterator]() {
				yield new Uint8Array(5);
				yield new Uint8Array(6);
			},
		};
		await expect(
			new HttpRelayClient(relay()).request({
				method: 'PUT',
				path: '/s',
				body: { chunks: long, length: 10 },
			}),
		).rejects.toThrow('the body grew past its declared 10 bytes');
	});

	test('a write that fails waits for the reply the host may have sent first', async () => {
		const r = relay();
		let writes = 0;
		r.write = async () => {
			writes++;
			if (writes > 1) throw new Error('EPIPE');
		};
		const c = new HttpRelayClient(r);
		const chunks = {
			async *[Symbol.asyncIterator]() {
				yield new Uint8Array(5);
				yield new Uint8Array(5);
			},
		};
		const pending = c.request({ method: 'PUT', path: '/s', body: { chunks, length: 10 } });
		await Bun.sleep(5);
		r.reply('HTTP/1.1 413 Too Large\r\nContent-Length: 0\r\n\r\n');
		expect((await pending).status).toBe(413);
		// And when none comes, the relay is reported broken with the write's error.
		const gone = relay();
		gone.write = async () => {
			throw new Error('EPIPE');
		};
		const none = new HttpRelayClient(gone).request({ method: 'GET', path: '/a' });
		gone.close();
		await expect(none).rejects.toThrow('sending failed: EPIPE');
	});

	test('a host that answers early and stops reading does not hold the request on a blocked write', async () => {
		const r = relay();
		let writes = 0;
		// The second write never settles: the pipe is full and the host is
		// not reading any more. Its 413 ends the request instead.
		r.write = async () => {
			writes++;
			if (writes === 2) {
				r.reply('HTTP/1.1 413 Too Large\r\nContent-Length: 0\r\n\r\n');
				await new Promise<never>(() => {});
			}
		};
		const c = new HttpRelayClient(r);
		let pulled = 0;
		const chunks = {
			async *[Symbol.asyncIterator]() {
				for (let i = 0; i < 100; i++) {
					pulled++;
					yield new Uint8Array(10);
				}
			},
		};
		const reply = await c.request({
			method: 'PUT',
			path: '/source',
			body: { chunks, length: 1000 },
		});
		expect(reply.status).toBe(413);
		expect(writes).toBe(2);
		expect(pulled).toBeLessThan(100);
		// The host did not read this body to its end, so the connection
		// cannot carry another request: what it reads next would be the rest
		// of the body.
		await expect(c.request({ method: 'GET', path: '/a' })).rejects.toThrow(RelayBrokenError);
	});

	test('one request at a time', async () => {
		const r = relay();
		const c = new HttpRelayClient(r);
		const first = c.request({ method: 'GET', path: '/a' });
		await expect(c.request({ method: 'GET', path: '/b' })).rejects.toThrow('one request at a time');
		r.reply('HTTP/1.1 204 No Content\r\n\r\n');
		expect((await first).status).toBe(204);
	});

	test('a relay that carries nothing for the idle limit fails the request; bytes either way keep it going', async () => {
		// Nothing comes back and the relay stays open: without the limit the
		// request would wait for good. With it the request fails at the
		// limit, and the relay is not used again.
		const r = relay();
		const c = new HttpRelayClient(r, undefined, 100);
		const began = Date.now();
		const err = await c.request({ method: 'GET', path: '/a' }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(RelayIdleError);
		expect((err as Error).message).toBe('nothing crossed the relay for 0.1 seconds');
		expect(Date.now() - began).toBeGreaterThanOrEqual(90);
		await expect(c.request({ method: 'GET', path: '/b' })).rejects.toBeInstanceOf(RelayBrokenError);

		// A body that goes out a chunk at a time, each within the limit, is
		// progress: the host says nothing until the end, and the request
		// outlives the limit several times over.
		const slow = relay();
		const d = new HttpRelayClient(slow, undefined, 100);
		async function* chunks() {
			for (let i = 0; i < 5; i++) {
				await Bun.sleep(50);
				yield encode('ab');
			}
		}
		const pending = d.request({
			method: 'PUT',
			path: '/c',
			body: { chunks: chunks(), length: 10 },
		});
		await Bun.sleep(300);
		slow.reply('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');
		expect((await pending).status).toBe(200);
		expect(slow.sent()).toEndWith('\r\n\r\nababababab');
	});

	// The body of the two tests below: 512 KiB, the most Bun's file stream
	// emits in one chunk, with a pattern so that a piece out of order shows.
	const LARGE = new Uint8Array(512 * 1024).map((_, i) => i % 251);
	async function* oneChunk() {
		yield LARGE;
	}

	for (const [form, body] of [
		['streamed', { chunks: oneChunk(), length: LARGE.byteLength }],
		['in bytes', LARGE],
	] as const) {
		test(`a slow transfer that never stalls outlives the idle limit inside one large chunk (${form})`, async () => {
			// Takes a write's bytes 16 KiB at a time, as ssh does on a slow link:
			// the write settles only when its last byte is gone, so the client
			// sees no progress inside one. The whole chunk takes about 800 ms
			// against a limit of 400 ms, and 64 KiB takes about 100 ms.
			const r = relay();
			let taken = 0;
			r.write = async (chunk) => {
				for (let at = 0; at < chunk.byteLength; at += 16 * 1024) await Bun.sleep(25);
				r.written.push(chunk);
				taken += chunk.byteLength;
				if (taken >= LARGE.byteLength) r.reply('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');
			};
			const c = new HttpRelayClient(r, undefined, 400);
			const reply = await c.request({ method: 'PUT', path: '/source', body });
			expect(reply.status).toBe(200);
			const sent = Buffer.concat(r.written);
			expect(sent.subarray(-LARGE.byteLength).equals(Buffer.from(LARGE))).toBe(true);
			expect(Math.max(...r.written.map((w) => w.byteLength))).toBeLessThanOrEqual(64 * 1024);
		});
	}

	test('a relay that truly stalls part way through a large chunk is reported as idle', async () => {
		// Takes 128 KiB, then never settles a write again, with the connection
		// up and nothing coming back.
		const r = relay();
		let taken = 0;
		let lastProgress = 0;
		r.write = async (chunk) => {
			if (taken >= 128 * 1024) await new Promise<never>(() => {});
			await Bun.sleep(5);
			taken += chunk.byteLength;
			lastProgress = Date.now();
		};
		const c = new HttpRelayClient(r, undefined, 150);
		const err = await c
			.request({ method: 'PUT', path: '/source', body: LARGE })
			.catch((e: unknown) => e);
		expect(err).toBeInstanceOf(RelayIdleError);
		expect(Date.now() - lastProgress).toBeGreaterThanOrEqual(140);
		expect(taken).toBeGreaterThanOrEqual(128 * 1024);
		expect(taken).toBeLessThan(LARGE.byteLength);
		// The body did not reach the host whole, so the relay is finished with.
		await expect(c.request({ method: 'GET', path: '/a' })).rejects.toBeInstanceOf(RelayBrokenError);
	});
});
