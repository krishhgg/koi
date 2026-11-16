import { createHash, randomBytes } from 'node:crypto';

// Just enough of RFC 6455 for the browser-port proxy (proxy.ts): it splits
// the client's byte stream into frames, so each DevTools message can be
// read before it is forwarded, and builds the few frames the proxy sends
// itself. A frame that passes unchanged is forwarded as the bytes it
// arrived in; only the payload copy is unmasked, for reading.

export interface Frame {
	fin: boolean;
	opcode: number;
	// The payload, unmasked.
	payload: Uint8Array;
	// The frame as it arrived, mask and all.
	raw: Uint8Array;
}

export const OPCODE = {
	continuation: 0,
	text: 1,
	binary: 2,
	close: 8,
	ping: 9,
	pong: 10,
} as const;

// A frame larger than this, or a message assembled from frames that is, ends
// the connection. DevTools messages are small; Playwright's injected
// scripts are the largest at a few hundred kilobytes.
export const MAX_MESSAGE_BYTES = 32 * 1024 ** 2;

export class FrameError extends Error {}

// Turns a byte stream into frames. push() returns the frames completed by
// the bytes given so far and keeps the rest.
export class FrameParser {
	private pending: Uint8Array = new Uint8Array(0);

	push(data: Uint8Array): Frame[] {
		this.pending = concat(this.pending, data);
		if (this.pending.length > MAX_MESSAGE_BYTES + 14) {
			throw new FrameError('frame over the size limit');
		}
		const frames: Frame[] = [];
		for (;;) {
			const frame = parseFrame(this.pending);
			if (frame === undefined) return frames;
			frames.push(frame);
			this.pending = this.pending.subarray(frame.raw.length);
		}
	}
}

// One frame from the start of `bytes`, or undefined when more bytes are
// needed for it.
export function parseFrame(bytes: Uint8Array): Frame | undefined {
	if (bytes.length < 2) return undefined;
	const b0 = bytes[0] ?? 0;
	const b1 = bytes[1] ?? 0;
	if ((b0 & 0x70) !== 0) throw new FrameError('reserved bits set');
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
		const view = new DataView(bytes.buffer, bytes.byteOffset + 2, 8);
		const big = view.getBigUint64(0);
		if (big > BigInt(MAX_MESSAGE_BYTES)) throw new FrameError('frame over the size limit');
		length = Number(big);
		offset = 10;
	}
	if (length > MAX_MESSAGE_BYTES) throw new FrameError('frame over the size limit');
	if (opcode >= 8 && (length > 125 || !fin)) throw new FrameError('malformed control frame');
	const maskLength = masked ? 4 : 0;
	const total = offset + maskLength + length;
	if (bytes.length < total) return undefined;
	const payload = new Uint8Array(bytes.subarray(offset + maskLength, total));
	if (masked) {
		const key = bytes.subarray(offset, offset + 4);
		for (let i = 0; i < payload.length; i++) {
			payload[i] = (payload[i] ?? 0) ^ (key[i % 4] ?? 0);
		}
	}
	return { fin, opcode, payload, raw: bytes.subarray(0, total) };
}

// Joins the data frames of one message. feed() returns the message's
// frames and text once its final frame arrives, and nothing before.
export class MessageAssembler {
	private frames: Frame[] = [];
	private bytes = 0;

	feed(frame: Frame): { frames: Frame[]; text: string } | undefined {
		if (frame.opcode === OPCODE.continuation && this.frames.length === 0) {
			throw new FrameError('continuation without a start');
		}
		if (frame.opcode !== OPCODE.continuation && this.frames.length > 0) {
			throw new FrameError('a new message inside another');
		}
		this.frames.push(frame);
		this.bytes += frame.payload.length;
		if (this.bytes > MAX_MESSAGE_BYTES) throw new FrameError('message over the size limit');
		if (!frame.fin) return undefined;
		const frames = this.frames;
		this.frames = [];
		this.bytes = 0;
		const first = frames[0];
		const text =
			first?.opcode === OPCODE.text
				? new TextDecoder().decode(frames.length === 1 ? first.payload : concatAll(frames))
				: '';
		return { frames, text };
	}
}

// A text frame as a server sends it: unmasked.
export function textFrame(text: string): Uint8Array {
	return dataFrame(OPCODE.text, new TextEncoder().encode(text));
}

// A text frame as a client sends it: masked, which RFC 6455 requires of
// every client frame and Chromium's DevTools server checks. The proxy sends
// one when it forwards a message it rewrote.
export function maskedTextFrame(text: string, key: Uint8Array = randomBytes(4)): Uint8Array {
	const payload = new TextEncoder().encode(text);
	const header = frameHeader(OPCODE.text, payload.length, true);
	const out = new Uint8Array(header.length + 4 + payload.length);
	out.set(header, 0);
	out.set(key.subarray(0, 4), header.length);
	for (let i = 0; i < payload.length; i++) {
		out[header.length + 4 + i] = (payload[i] ?? 0) ^ (key[i % 4] ?? 0);
	}
	return out;
}

export function closeFrame(code: number, reason: string): Uint8Array {
	const text = new TextEncoder().encode(reason).subarray(0, 123);
	const payload = new Uint8Array(2 + text.length);
	payload[0] = code >> 8;
	payload[1] = code & 0xff;
	payload.set(text, 2);
	return dataFrame(OPCODE.close, payload);
}

function dataFrame(opcode: number, payload: Uint8Array): Uint8Array {
	return concat(frameHeader(opcode, payload.length, false), payload);
}

// The first bytes of a final frame: opcode, the mask bit, and the length in
// the shortest form that holds it.
function frameHeader(opcode: number, length: number, masked: boolean): Uint8Array {
	const mask = masked ? 0x80 : 0;
	if (length < 126) return new Uint8Array([0x80 | opcode, mask | length]);
	if (length < 65536)
		return new Uint8Array([0x80 | opcode, mask | 126, length >> 8, length & 0xff]);
	const header = new Uint8Array(10);
	header[0] = 0x80 | opcode;
	header[1] = mask | 127;
	new DataView(header.buffer).setBigUint64(2, BigInt(length));
	return header;
}

// The Sec-WebSocket-Accept value for a client key. The GUID is the one RFC
// 6455 fixes for this purpose.
export function acceptKey(key: string): string {
	return createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
	if (a.length === 0) return b;
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}

function concatAll(frames: Frame[]): Uint8Array {
	const out = new Uint8Array(frames.reduce((n, f) => n + f.payload.length, 0));
	let at = 0;
	for (const f of frames) {
		out.set(f.payload, at);
		at += f.payload.length;
	}
	return out;
}
