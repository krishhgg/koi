// An HTTP/1.1 client over a plain byte relay: the SSH transport speaks to
// koid's upload API through `tunnel-v1`, where the gateway on the host copies
// bytes between the session and koid's control socket (host/ssh). No URL, no
// socket, no fetch: the request is written as bytes and the reply parsed
// from bytes, one request at a time, with keep-alive so one tunnel carries
// the whole upload sequence.
//
// A request body may be a stream, for a source archive of up to 2 GiB that
// is read from disk a chunk at a time and never held whole. The reply is
// read while the body is still going out, so a host that refuses early and
// closes (a 413, say) is heard rather than written to until the pipe breaks.

export interface ByteRelay {
	write(chunk: Uint8Array): Promise<void>;
	readable: ReadableStream<Uint8Array>;
}

export interface RelayRequest {
	method: 'GET' | 'POST' | 'PUT';
	path: string;
	headers?: Record<string, string> | undefined;
	body?: Uint8Array | { chunks: AsyncIterable<Uint8Array>; length: number } | undefined;
}

export interface RelayReply {
	status: number;
	// Header names in lower case; repeated headers joined with ", ".
	headers: Record<string, string>;
	body: Uint8Array;
}

// The relay ended, or broke, before a whole reply arrived. What the host did
// with the request is unknown.
export class RelayBrokenError extends Error {}

// Nothing crossed the relay, in either direction, for the idle limit: the
// host stopped answering while the relay stayed up.
export class RelayIdleError extends RelayBrokenError {
	constructor(readonly idleMs: number) {
		super(`nothing crossed the relay for ${idleMs / 1000} seconds`);
	}
}

// The most header bytes a reply may have before its body.
const MAX_HEAD_BYTES = 64 * 1024;

// The most bytes one write hands to the relay. The real writer settles only
// once ssh has taken the whole write, so the idle clock sees no progress
// inside one, and Bun's file stream emits chunks of up to 512 KiB. A chunk is
// written in pieces of this size and the clock restarts after each. The relay
// must take one piece within the idle limit: with the SSH transport's two
// minutes, a link under about 550 bytes a second counts as stalled.
const MAX_WRITE_BYTES = 64 * 1024;

export class HttpRelayClient {
	private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
	private buffer = new Uint8Array(0);
	private eof = false;
	private busy = false;
	private closedByPeer = false;
	// The idle clock while a read waits: the timer, and what fires when it
	// runs out. Every read and every piece written starts the clock over
	// (touch).
	private idleTimer: ReturnType<typeof setTimeout> | undefined;
	private idleFired: ((err: Error) => void) | undefined;

	constructor(
		private readonly relay: ByteRelay,
		// The most body bytes a reply may carry; koid's are small JSON.
		private readonly maxReplyBytes = 1024 ** 2,
		// How long a read waits with nothing crossing the relay either way
		// before the request fails with RelayIdleError. Without it a read
		// waits for as long as the relay stays up: a host that hangs with
		// the connection open would hold the request for good.
		private readonly idleMs?: number,
	) {
		// The relay's stream may be typed by node:stream/web or by Bun; the
		// reader is the same either way.
		this.reader = relay.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
	}

	async request(req: RelayRequest): Promise<RelayReply> {
		if (this.busy) throw new Error('the relay carries one request at a time');
		if (this.closedByPeer) {
			throw new RelayBrokenError('the host closed the connection after the previous reply');
		}
		this.busy = true;
		try {
			let replied = false;
			const reply = this.readReply().finally(() => {
				replied = true;
			});
			// Keep the reply from counting as unhandled while the body goes out.
			reply.catch(() => {});
			// Settles, never rejects, once the reply has arrived or failed.
			const answered = reply.then(
				() => {},
				() => {},
			);
			// A write that failed: the host may have answered and closed, so
			// the reply is still waited for. Any other failure while sending
			// is the sender's own (a body shorter than declared, a file that
			// could not be read) and ends the request at once; the host is
			// still waiting for bytes that will never come, so the relay is
			// finished with.
			//
			// Each write gives way to the reply. A host that answers early and
			// stops reading leaves the pipe full and the write pending for good;
			// the reply ends the request instead, and the write is left behind
			// with the body unfinished, so the connection is not used again.
			let writeError: unknown;
			// Ends the wait for the piece in flight when the reply arrives. One
			// listener on the reply, not a race per piece: a 2 GiB body is about
			// 33,000 pieces, and each race would stay attached until the reply.
			let stopWaiting: (written: boolean) => void = () => {};
			answered.then(() => stopWaiting(false));
			const writePiece = (piece: Uint8Array) =>
				new Promise<boolean>((settle) => {
					if (replied) {
						settle(false);
						return;
					}
					stopWaiting = settle;
					this.relay.write(piece).then(
						() => {
							// A piece the relay took is progress: the idle clock restarts.
							this.touch();
							settle(true);
						},
						(err: unknown) => {
							writeError = err;
							settle(false);
						},
					);
				});
			const write = async (chunk: Uint8Array) => {
				for (let at = 0; at < chunk.byteLength; at += MAX_WRITE_BYTES) {
					if (!(await writePiece(chunk.subarray(at, at + MAX_WRITE_BYTES)))) return false;
				}
				return true;
			};
			let whole = false;
			try {
				if (await write(new TextEncoder().encode(head(req)))) {
					const { body } = req;
					if (body instanceof Uint8Array) {
						whole = body.byteLength === 0 || (await write(body));
					} else if (body !== undefined) {
						let sent = 0;
						for await (const chunk of body.chunks) {
							// The host has answered, or the pipe is gone: no more.
							if (replied || writeError !== undefined) break;
							if (sent + chunk.byteLength > body.length) {
								throw new Error(`the body grew past its declared ${body.length} bytes`);
							}
							if (!(await write(chunk))) break;
							sent += chunk.byteLength;
						}
						if (!replied && writeError === undefined && sent !== body.length) {
							throw new Error(`the body ended after ${sent} of its declared ${body.length} bytes`);
						}
						whole = sent === body.length;
					} else {
						whole = true;
					}
				}
			} catch (err) {
				this.closedByPeer = true;
				throw err;
			}
			// A request the host did not read to the end: what it reads next
			// would be the rest of this body, not another request.
			if (!whole) this.closedByPeer = true;
			try {
				return await reply;
			} catch (err) {
				// Nothing came back and the send failed too: the relay is gone.
				if (writeError !== undefined && err instanceof RelayBrokenError) {
					throw new RelayBrokenError(`${err.message} (sending failed: ${message(writeError)})`);
				}
				throw err;
			}
		} finally {
			this.busy = false;
		}
	}

	private async readReply(): Promise<RelayReply> {
		const headEnd = await this.find('\r\n\r\n', MAX_HEAD_BYTES);
		const text = new TextDecoder().decode(this.take(headEnd + 4)).slice(0, headEnd);
		const [statusLine = '', ...lines] = text.split('\r\n');
		const m = /^HTTP\/1\.[01] (\d{3})(?: .*)?$/.exec(statusLine);
		if (m === null)
			throw new Error(`not an HTTP reply: ${JSON.stringify(statusLine.slice(0, 80))}`);
		const status = Number(m[1]);
		const headers: Record<string, string> = {};
		for (const line of lines) {
			const colon = line.indexOf(':');
			if (colon <= 0) throw new Error(`not an HTTP header: ${JSON.stringify(line.slice(0, 80))}`);
			const name = line.slice(0, colon).trim().toLowerCase();
			const value = line.slice(colon + 1).trim();
			headers[name] = name in headers ? `${headers[name]}, ${value}` : value;
		}
		if (
			headers.connection
				?.toLowerCase()
				.split(/\s*,\s*/)
				.includes('close')
		) {
			this.closedByPeer = true;
		}
		let body: Uint8Array;
		if (headers['transfer-encoding']?.toLowerCase().includes('chunked')) {
			body = await this.readChunked();
		} else if (headers['content-length'] !== undefined) {
			const length = /^\d{1,15}$/.test(headers['content-length'])
				? Number(headers['content-length'])
				: Number.NaN;
			if (!Number.isInteger(length)) throw new Error('an HTTP reply with a bad Content-Length');
			if (length > this.maxReplyBytes) throw this.tooLarge(length);
			body = await this.exact(length);
		} else if (this.closedByPeer) {
			body = await this.untilEof();
		} else {
			body = new Uint8Array(0);
		}
		return { status, headers, body };
	}

	private async readChunked(): Promise<Uint8Array> {
		const parts: Uint8Array[] = [];
		let total = 0;
		for (;;) {
			const lineEnd = await this.find('\r\n', 1024);
			const line = new TextDecoder().decode(this.take(lineEnd + 2)).slice(0, lineEnd);
			const size = Number.parseInt(line.split(';')[0] ?? '', 16);
			if (!Number.isInteger(size) || size < 0) throw new Error('a bad HTTP chunk size');
			if (size === 0) {
				// Trailers, up to the empty line.
				for (;;) {
					const end = await this.find('\r\n', 1024);
					this.take(end + 2);
					if (end === 0) break;
				}
				return concat(parts, total);
			}
			total += size;
			if (total > this.maxReplyBytes) throw this.tooLarge(total);
			parts.push(await this.exact(size));
			const crlf = await this.exact(2);
			if (crlf[0] !== 13 || crlf[1] !== 10) throw new Error('a bad HTTP chunk end');
		}
	}

	private tooLarge(bytes: number): Error {
		return new Error(`an HTTP reply of ${bytes} bytes; koi takes at most ${this.maxReplyBytes}`);
	}

	// Starts the idle clock over, while a read is waiting on it.
	private touch(): void {
		if (this.idleMs === undefined || this.idleFired === undefined) return;
		clearTimeout(this.idleTimer);
		const fire = this.idleFired;
		this.idleTimer = setTimeout(() => fire(new RelayIdleError(this.idleMs ?? 0)), this.idleMs);
	}

	// Reads more into the buffer. False at the end of the stream. With an
	// idle limit the read races the idle clock; a read that loses stays
	// pending, and the relay is not used again, since the host is not
	// answering and the caller drops the relay for it.
	private async fill(): Promise<boolean> {
		if (this.eof) return false;
		let result: Awaited<ReturnType<typeof this.reader.read>>;
		if (this.idleMs === undefined) {
			result = await this.reader.read();
		} else {
			const idle = new Promise<never>((_, reject) => {
				this.idleFired = reject;
			});
			this.touch();
			try {
				result = await Promise.race([this.reader.read(), idle]);
			} catch (err) {
				this.closedByPeer = true;
				throw err;
			} finally {
				clearTimeout(this.idleTimer);
				this.idleFired = undefined;
			}
		}
		const { value, done } = result;
		if (done || value === undefined) {
			this.eof = true;
			return false;
		}
		const joined = new Uint8Array(this.buffer.byteLength + value.byteLength);
		joined.set(this.buffer);
		joined.set(value, this.buffer.byteLength);
		this.buffer = joined;
		return true;
	}

	// The offset of `needle` in the buffer, filling until it is there.
	private async find(needle: string, max: number): Promise<number> {
		const bytes = new TextEncoder().encode(needle);
		let from = 0;
		for (;;) {
			const at = indexOf(this.buffer, bytes, from);
			if (at >= 0) return at;
			if (this.buffer.byteLength > max) {
				throw new Error(`an HTTP reply with over ${max} bytes before ${JSON.stringify(needle)}`);
			}
			from = Math.max(0, this.buffer.byteLength - bytes.byteLength + 1);
			if (!(await this.fill())) {
				throw new RelayBrokenError('the connection ended before a whole reply arrived');
			}
		}
	}

	private take(n: number): Uint8Array {
		const out = this.buffer.slice(0, n);
		this.buffer = this.buffer.slice(n);
		return out;
	}

	private async exact(n: number): Promise<Uint8Array> {
		while (this.buffer.byteLength < n) {
			if (!(await this.fill())) {
				throw new RelayBrokenError('the connection ended before a whole reply arrived');
			}
		}
		return this.take(n);
	}

	private async untilEof(): Promise<Uint8Array> {
		while (await this.fill()) {
			if (this.buffer.byteLength > this.maxReplyBytes) throw this.tooLarge(this.buffer.byteLength);
		}
		return this.take(this.buffer.byteLength);
	}
}

function head(req: RelayRequest): string {
	const lines = [`${req.method} ${req.path} HTTP/1.1`, 'Host: koid', 'Connection: keep-alive'];
	for (const [name, value] of Object.entries(req.headers ?? {})) {
		if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) throw new Error('a header with a line break');
		lines.push(`${name}: ${value}`);
	}
	const length =
		req.body === undefined
			? 0
			: req.body instanceof Uint8Array
				? req.body.byteLength
				: req.body.length;
	if (req.body !== undefined || req.method !== 'GET') lines.push(`Content-Length: ${length}`);
	return `${lines.join('\r\n')}\r\n\r\n`;
}

function indexOf(haystack: Uint8Array, needle: Uint8Array, from: number): number {
	outer: for (let i = from; i + needle.byteLength <= haystack.byteLength; i++) {
		for (let j = 0; j < needle.byteLength; j++) {
			if (haystack[i + j] !== needle[j]) continue outer;
		}
		return i;
	}
	return -1;
}

function concat(parts: Uint8Array[], total: number): Uint8Array {
	const out = new Uint8Array(total);
	let at = 0;
	for (const part of parts) {
		out.set(part, at);
		at += part.byteLength;
	}
	return out;
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
