import { createHash, timingSafeEqual } from 'node:crypto';
import { connect, createServer, type Server, type Socket } from 'node:net';
import { inspectMessage, METHOD_NOT_FOUND } from './cdp-allowlist.ts';
import type { EventLog } from './events.ts';
import type { Origin } from './origin.ts';
import {
	closeFrame,
	FrameError,
	FrameParser,
	MAX_MESSAGE_BYTES,
	MessageAssembler,
	maskedTextFrame,
	OPCODE,
	textFrame,
} from './ws.ts';

// The browser port, TCP 4317: the verifier's way to drive the browser the
// recorder owns. Chromium listens for DevTools connections on loopback only;
// this proxy puts a run-scoped token in front of it, so a client needs the
// path koid gave the verifier and nothing else on the port answers, and it
// reads every message on the way in. Only a method on the allowlist in
// cdp-allowlist.ts goes through, some of them rewritten first; every other
// message gets a DevTools error reply instead. Sessions are flattened, so a
// message for an attached target is a top-level message with a sessionId
// and is checked like any other.
//
// A frame that passes unchanged is forwarded as the bytes it arrived in. A
// rewritten message is sent again as one masked frame.

// The most the handshake request may be.
const MAX_HEAD_BYTES = 16 * 1024;
const HANDSHAKE_TIMEOUT_MS = 10_000;

export interface Upstream {
	host: string;
	port: number;
	path: string;
}

export interface ProxyOptions {
	port: number;
	// The run's browser token: the path a client must connect to.
	token: string;
	// Chromium's DevTools browser endpoint, once the browser is up.
	upstream: () => Upstream | undefined;
	// Whether a browser context id is one the recorder made, for
	// Target.createTarget.
	ownsContext: (browserContextId: string) => boolean;
	origin: Origin;
	events: EventLog;
	maxClients?: number;
}

// What a client sent to connect, as far as the proxy reads it.
export interface Handshake {
	method: string;
	path: string;
	headers: Map<string, string>;
}

// The request head, or undefined when it is not a complete HTTP request.
export function parseHandshake(head: string): Handshake | undefined {
	const lines = head.split('\r\n');
	const requestLine = lines.shift();
	if (requestLine === undefined) return undefined;
	const parts = requestLine.split(' ');
	if (parts.length !== 3 || !parts[2]?.startsWith('HTTP/1.')) return undefined;
	const headers = new Map<string, string>();
	for (const line of lines) {
		if (line === '') continue;
		const at = line.indexOf(':');
		if (at <= 0) return undefined;
		headers.set(line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim());
	}
	return { method: parts[0] ?? '', path: parts[1] ?? '', headers };
}

// Whether `path` is exactly /<token>, compared in constant time.
export function pathHasToken(path: string, token: string): boolean {
	const a = createHash('sha256').update(path).digest();
	const b = createHash('sha256').update(`/${token}`).digest();
	return timingSafeEqual(a, b);
}

export function startProxy(options: ProxyOptions): Promise<Server> {
	const maxClients = options.maxClients ?? 4;
	let clients = 0;
	const server = createServer((client) => {
		clients += 1;
		client.once('close', () => {
			clients -= 1;
		});
		handshake(client, options, clients > maxClients).catch(() => client.destroy());
	});
	return new Promise((resolve, reject) => {
		server.once('error', reject);
		server.listen(options.port, '0.0.0.0', () => resolve(server));
	});
}

function reject(client: Socket, status: string): void {
	client.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}

async function handshake(client: Socket, options: ProxyOptions, over: boolean): Promise<void> {
	client.setNoDelay(true);
	const head = await readHead(client);
	if (head === undefined) {
		options.events.push('client-rejected', { reason: 'not an http request' });
		return reject(client, '400 Bad Request');
	}
	const request = parseHandshake(head.text);
	if (request === undefined || request.method !== 'GET') {
		options.events.push('client-rejected', { reason: 'not an http request' });
		return reject(client, '400 Bad Request');
	}
	if (!pathHasToken(request.path, options.token)) {
		options.events.push('client-rejected', { reason: 'wrong token' });
		return reject(client, '404 Not Found');
	}
	if (over) {
		options.events.push('client-rejected', { reason: 'too many clients' });
		return reject(client, '503 Service Unavailable');
	}
	const key = request.headers.get('sec-websocket-key');
	if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket' || key === undefined) {
		options.events.push('client-rejected', { reason: 'not a websocket upgrade' });
		return reject(client, '426 Upgrade Required');
	}
	const upstream = options.upstream();
	if (upstream === undefined) {
		options.events.push('client-rejected', { reason: 'browser not ready' });
		return reject(client, '503 Service Unavailable');
	}
	const browser = connect({ host: upstream.host, port: upstream.port });
	browser.setNoDelay(true);
	await new Promise<void>((resolve, rej) => {
		browser.once('connect', resolve);
		browser.once('error', rej);
	});
	// The client's key goes through, so the accept value Chromium computes
	// is the one the client expects. No Origin: Chromium refuses DevTools
	// connections that carry one.
	browser.write(
		`GET ${upstream.path} HTTP/1.1\r\nHost: ${upstream.host}:${upstream.port}\r\n` +
			`Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\n` +
			'Sec-WebSocket-Version: 13\r\n\r\n',
	);
	const answer = await readHead(browser);
	if (answer === undefined || !/^HTTP\/1\.1 101 /.test(answer.text)) {
		browser.destroy();
		options.events.push('client-rejected', { reason: 'browser refused' });
		return reject(client, '502 Bad Gateway');
	}
	options.events.push('client-connected', { client: client.remoteAddress ?? '' });
	client.write(`${answer.text}\r\n\r\n`);
	if (answer.rest.length > 0) client.write(answer.rest);
	relay(client, browser, head.rest, options);
}

// Reads a socket up to the end of an HTTP head. Returns the head's text
// and whatever bytes followed it, or undefined on a timeout, a close or a
// head over MAX_HEAD_BYTES.
function readHead(socket: Socket): Promise<{ text: string; rest: Uint8Array } | undefined> {
	return new Promise((resolve) => {
		let buffer = Buffer.alloc(0);
		const done = (value: { text: string; rest: Uint8Array } | undefined) => {
			socket.off('data', onData);
			socket.off('close', onClose);
			socket.off('error', onClose);
			clearTimeout(timer);
			resolve(value);
		};
		const onData = (data: Buffer) => {
			buffer = Buffer.concat([buffer, data]);
			const end = buffer.indexOf('\r\n\r\n');
			if (end >= 0) {
				done({ text: buffer.subarray(0, end).toString('latin1'), rest: buffer.subarray(end + 4) });
			} else if (buffer.length > MAX_HEAD_BYTES) done(undefined);
		};
		const onClose = () => done(undefined);
		const timer = setTimeout(() => done(undefined), HANDSHAKE_TIMEOUT_MS);
		socket.on('data', onData);
		socket.once('close', onClose);
		socket.once('error', onClose);
	});
}

// Bytes flow both ways until either side closes. The browser's frames are
// forwarded as they come; the client's are read message by message and
// each is allowed, rewritten or refused.
function relay(client: Socket, browser: Socket, first: Uint8Array, options: ProxyOptions): void {
	const { events } = options;
	const parser = new FrameParser();
	const assembler = new MessageAssembler();
	// Each rewritten method is noted once per connection.
	const rewritten = new Set<string>();
	// Sessions Chromium handed this client, from the Target.attachedToTarget
	// events the relay reads on the way back. A client message with a
	// sessionId not in here names a target the client never attached, and is
	// refused.
	const sessions = new Set<string>();
	const inbound = new InboundSessionReader();
	const knownSession = (sessionId: string): boolean => sessions.has(sessionId);
	// Replies the proxy writes itself, the refusals. The browser's bytes go
	// to the client in the chunks they arrive in, and a chunk can end inside
	// a frame; a reply written at that moment would sit inside the frame and
	// corrupt the client's stream. A reply waits here until the browser
	// stream is between messages, which the reader knows from the frame
	// heads it tracks.
	const replies: Uint8Array[] = [];
	const flushReplies = () => {
		if (!inbound.betweenMessages) return;
		for (const reply of replies) client.write(reply);
		replies.length = 0;
	};
	let closed = false;
	const close = (reason: string) => {
		if (closed) return;
		closed = true;
		events.push('client-disconnected', { reason });
		client.destroy();
		browser.destroy();
	};
	const onClientData = (data: Uint8Array) => {
		let frames: ReturnType<FrameParser['push']>;
		try {
			frames = parser.push(data);
		} catch (err) {
			if (err instanceof FrameError) client.write(closeFrame(1009, err.message));
			return close('bad frame');
		}
		for (const frame of frames) {
			if (frame.opcode >= OPCODE.close) {
				browser.write(frame.raw);
				continue;
			}
			let message: ReturnType<MessageAssembler['feed']>;
			try {
				message = assembler.feed(frame);
			} catch (err) {
				if (err instanceof FrameError) client.write(closeFrame(1009, err.message));
				return close('bad frame');
			}
			if (message === undefined) continue;
			// A binary message is not DevTools; it is refused like any other
			// message without a method.
			const verdict = inspectMessage(
				message.frames[0]?.opcode === OPCODE.text ? message.text : '',
				{ ownsContext: options.ownsContext, origin: options.origin, knownSession },
			);
			if (verdict.forward === undefined) {
				events.push('client-denied', {
					...(verdict.method !== undefined ? { method: verdict.method } : {}),
					reason: verdict.denied ?? 'refused',
				});
				if (verdict.id !== undefined) {
					// The reply carries the request's sessionId, as Chromium's own
					// error replies do. The client routes every reply by session,
					// so a refusal without it lands on the root session and the
					// refused request waits forever.
					replies.push(
						textFrame(
							JSON.stringify({
								id: verdict.id,
								error: { code: METHOD_NOT_FOUND, message: `koi recorder: ${verdict.denied}` },
								...(verdict.sessionId !== undefined ? { sessionId: verdict.sessionId } : {}),
							}),
						),
					);
					flushReplies();
				}
				continue;
			}
			if (verdict.rewritten !== undefined) {
				if (!rewritten.has(verdict.rewritten)) {
					rewritten.add(verdict.rewritten);
					events.push('client-rewritten', { method: verdict.rewritten });
				}
				browser.write(maskedTextFrame(verdict.forward));
				continue;
			}
			for (const f of message.frames) browser.write(f.raw);
		}
	};
	client.on('data', onClientData);
	browser.on('data', (data: Buffer) => {
		// Forward Chromium's bytes first and unchanged, then read the frames
		// among them that hand this client a session, or take one back, and
		// send the replies that waited for a message boundary. The reader
		// classifies without failing; an error from it is a bug, and the
		// connection ends rather than run on with sessions and boundaries
		// unknown.
		client.write(data);
		try {
			for (const text of inbound.read(data)) updateSessions(text, sessions);
		} catch {
			return close('relay error');
		}
		flushReplies();
	});
	client.on('close', () => close('client closed'));
	browser.on('close', () => close('browser closed'));
	client.on('error', () => close('client error'));
	browser.on('error', () => close('browser error'));
	if (first.length > 0) onClientData(first);
}

// How many payload bytes of a browser-to-client frame the reader looks at to
// decide whether the frame is a session event. Chromium writes `method` as
// the first key of an event and `id` as the first key of a result, so both
// are in the first bytes of the frame; the prefix leaves room for a few
// keys before them, whatever their order. A frame whose prefix names no
// session event, or carries an id, is dropped as it streams and never held,
// so a screenshot result costs nothing here. A frame whose prefix does name
// one is held whole, whatever its size up to MAX_MESSAGE_BYTES, because
// Target.attachedToTarget carries the target's URL, and an allowed URL with
// a long fragment makes the event far larger than a few hundred bytes.
export const SESSION_EVENT_PREFIX = 1024;

// The two events that hand the client a session or take one back, as the
// bytes Chromium writes them. The quotes are part of each needle: inside a
// JSON string they would be escaped, so a needle matches a key and its
// value, not the same text quoted in a result.
const SESSION_EVENT_NEEDLES = [
	'"method":"Target.attachedToTarget"',
	'"method":"Target.detachedFromTarget"',
].map((needle) => Buffer.from(needle, 'latin1'));

// The id key every result has and no event does. A Runtime.evaluate result
// that returns an attach event by value carries the method needle in the
// clear, with the result's id before it; the id tells the two apart before
// the frame is held, so a result is never held, whatever its size.
const ID_KEY = Buffer.from('"id":', 'latin1');

// Reads the browser-to-client byte stream for the frames that name a
// session, while the raw bytes are forwarded elsewhere. Chromium sends one
// unmasked WebSocket frame per DevTools message and does not fragment them,
// so each frame is a whole message. A frame that is binary, not final, over
// the message limit, or whose first SESSION_EVENT_PREFIX bytes name no
// session event or carry an id is skipped without being held: only its
// length is tracked, so the reader stays aligned to frame boundaries across
// chunk boundaries. A session event is held until its last byte arrives,
// then returned as text. Nothing the stream carries makes the reader fail:
// what it cannot classify is not a session event.
export class InboundSessionReader {
	// Bytes of a frame head and prefix not yet complete.
	private pending: Uint8Array = EMPTY;
	// Payload bytes still to drop from a frame being skipped.
	private skipping = 0;
	// A session event being held until its last byte arrives.
	private holding: { parts: Uint8Array[]; have: number; need: number } | undefined;
	// Whether the last frame head read did not end its message.
	private midMessage = false;

	// Whether the browser stream is between messages: no frame head, prefix
	// or payload is in flight, and the last frame ended its message. A reply
	// the proxy writes to the client can go only then.
	get betweenMessages(): boolean {
		return (
			this.pending.length === 0 &&
			this.skipping === 0 &&
			this.holding === undefined &&
			!this.midMessage
		);
	}

	read(data: Uint8Array): string[] {
		const out: string[] = [];
		let rest = data;
		for (;;) {
			if (this.skipping > 0) {
				const take = Math.min(this.skipping, rest.length);
				rest = rest.subarray(take);
				this.skipping -= take;
				if (this.skipping > 0) return out;
			}
			if (this.holding !== undefined) {
				const take = Math.min(this.holding.need - this.holding.have, rest.length);
				this.holding.parts.push(rest.subarray(0, take));
				this.holding.have += take;
				rest = rest.subarray(take);
				if (this.holding.have < this.holding.need) return out;
				out.push(new TextDecoder().decode(joinBytes(this.holding.parts)));
				this.holding = undefined;
			}
			if (rest.length > 0) {
				this.pending = this.pending.length === 0 ? rest : concatBytes(this.pending, rest);
				rest = EMPTY;
			}
			const header = frameHeader(this.pending);
			if (header === undefined) return out;
			const { fin, opcode, payloadLength, headerLength } = header;
			const prefixLength = Math.min(payloadLength, SESSION_EVENT_PREFIX);
			if (this.pending.length < headerLength + prefixLength) return out;
			const payload = this.pending.subarray(headerLength);
			this.pending = EMPTY;
			// Only a data frame (text, binary, continuation) moves a message
			// along. A control frame (close, ping, pong) may sit between the
			// fragments of one message; if it cleared the flag, a reply would
			// be written inside that message.
			if (opcode < OPCODE.close) this.midMessage = !fin;
			// Chromium caps a URL at 2 MiB, so a session event never nears the
			// message limit; a frame over it that names one is something else,
			// and is dropped as it streams like any other.
			if (
				!fin ||
				opcode !== OPCODE.text ||
				payloadLength > MAX_MESSAGE_BYTES ||
				!isSessionEvent(payload.subarray(0, prefixLength))
			) {
				const dropped = Math.min(payloadLength, payload.length);
				this.skipping = payloadLength - dropped;
				rest = payload.subarray(dropped);
				continue;
			}
			const have = Math.min(payloadLength, payload.length);
			this.holding = { parts: [payload.subarray(0, have)], have, need: payloadLength };
			rest = payload.subarray(have);
		}
	}
}

const EMPTY = new Uint8Array(0);

// Whether the first bytes of a frame's payload name a session event: one of
// the two method needles, and no id key. updateSessions checks both again on
// the whole frame, at the top level.
function isSessionEvent(prefix: Uint8Array): boolean {
	const bytes = Buffer.from(prefix.buffer, prefix.byteOffset, prefix.byteLength);
	return !bytes.includes(ID_KEY) && SESSION_EVENT_NEEDLES.some((needle) => bytes.includes(needle));
}

interface FrameHead {
	fin: boolean;
	opcode: number;
	payloadLength: number;
	headerLength: number;
}

// The fin flag, opcode, payload length and header length of the frame at the
// start of `bytes`, or undefined when fewer than the header's bytes have
// arrived. Server frames are unmasked; a mask bit, which Chromium never
// sets, only widens the header so the payload is skipped, never misread.
function frameHeader(bytes: Uint8Array): FrameHead | undefined {
	if (bytes.length < 2) return undefined;
	const b0 = bytes[0] ?? 0;
	const b1 = bytes[1] ?? 0;
	const fin = (b0 & 0x80) !== 0;
	const opcode = b0 & 0x0f;
	const masked = (b1 & 0x80) !== 0;
	let length = b1 & 0x7f;
	let offset = 2;
	if (length === 126) {
		if (bytes.length < 4) return undefined;
		length = ((bytes[2] ?? 0) << 8) | (bytes[3] ?? 0);
		offset = 4;
	} else if (length === 127) {
		if (bytes.length < 10) return undefined;
		const big = new DataView(bytes.buffer, bytes.byteOffset + 2, 8).getBigUint64(0);
		// Cap the length so arithmetic stays in range. A frame this long is
		// dropped as it streams like any other; it is over the message limit,
		// so it is never held.
		length = big > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(big);
		offset = 10;
	}
	return { fin, opcode, payloadLength: length, headerLength: offset + (masked ? 4 : 0) };
}

// Records or drops a session from one browser-to-client message. Only a
// top-level event, a message with no id, whose method is one of the two
// target-attach events carries a handle the client may then use. A result,
// whatever it returns by value, and every other event are left alone.
function updateSessions(text: string, sessions: Set<string>): void {
	if (!text.includes('Target.attachedToTarget') && !text.includes('Target.detachedFromTarget')) {
		return;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return;
	}
	if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return;
	const message = parsed as { id?: unknown; method?: unknown; params?: unknown };
	if ('id' in message) return;
	const params =
		typeof message.params === 'object' && message.params !== null
			? (message.params as { sessionId?: unknown })
			: {};
	if (typeof params.sessionId !== 'string') return;
	if (message.method === 'Target.attachedToTarget') sessions.add(params.sessionId);
	else if (message.method === 'Target.detachedFromTarget') sessions.delete(params.sessionId);
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}

// One array from the chunks of a held frame, copied once at the end rather
// than on every chunk, so holding a large event costs linear time.
function joinBytes(parts: Uint8Array[]): Uint8Array {
	if (parts.length === 1) return parts[0] ?? EMPTY;
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}
