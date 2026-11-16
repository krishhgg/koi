import { describe, expect, test } from 'bun:test';
import {
	acceptKey,
	closeFrame,
	FrameError,
	FrameParser,
	MessageAssembler,
	maskedTextFrame,
	OPCODE,
	parseFrame,
	textFrame,
} from '../src/ws.ts';

// A frame as a client sends it: masked with `key`.
export function maskedFrame(
	opcode: number,
	payload: Uint8Array,
	options: { fin?: boolean; key?: Uint8Array } = {},
): Uint8Array {
	const key = options.key ?? new Uint8Array([0x12, 0x34, 0x56, 0x78]);
	const fin = options.fin ?? true;
	let header: number[];
	if (payload.length < 126) header = [(fin ? 0x80 : 0) | opcode, 0x80 | payload.length];
	else if (payload.length < 65536) {
		header = [(fin ? 0x80 : 0) | opcode, 0x80 | 126, payload.length >> 8, payload.length & 0xff];
	} else {
		header = [(fin ? 0x80 : 0) | opcode, 0x80 | 127, 0, 0, 0, 0];
		header.push(
			(payload.length >>> 24) & 0xff,
			(payload.length >>> 16) & 0xff,
			(payload.length >>> 8) & 0xff,
			payload.length & 0xff,
		);
	}
	const out = new Uint8Array(header.length + 4 + payload.length);
	out.set(header, 0);
	out.set(key, header.length);
	for (let i = 0; i < payload.length; i++) {
		out[header.length + 4 + i] = (payload[i] ?? 0) ^ (key[i % 4] ?? 0);
	}
	return out;
}

const text = (s: string) => new TextEncoder().encode(s);
const decode = (b: Uint8Array) => new TextDecoder().decode(b);

describe('parseFrame', () => {
	test('unmasks a small, a medium and a large payload and keeps the raw bytes', () => {
		for (const size of [5, 126, 70_000]) {
			const payload = text('a'.repeat(size));
			const raw = maskedFrame(OPCODE.text, payload);
			const frame = parseFrame(raw);
			expect(frame?.fin).toBe(true);
			expect(frame?.opcode).toBe(OPCODE.text);
			expect(frame?.payload).toEqual(payload);
			expect(frame?.raw).toEqual(raw);
		}
	});

	test('wants more bytes for a partial frame', () => {
		const raw = maskedFrame(OPCODE.text, text('hello'));
		expect(parseFrame(raw.subarray(0, 1))).toBeUndefined();
		expect(parseFrame(raw.subarray(0, 7))).toBeUndefined();
		expect(parseFrame(raw.subarray(0, raw.length - 1))).toBeUndefined();
	});

	test('refuses reserved bits, oversized and malformed control frames', () => {
		const raw = maskedFrame(OPCODE.text, text('hi'));
		const reserved = new Uint8Array(raw);
		reserved[0] = (reserved[0] ?? 0) | 0x40;
		expect(() => parseFrame(reserved)).toThrow(FrameError);
		const huge = new Uint8Array([0x81, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
		expect(() => parseFrame(huge)).toThrow('size limit');
		expect(() => parseFrame(maskedFrame(OPCODE.ping, text('x'.repeat(126))))).toThrow(
			'control frame',
		);
		expect(() => parseFrame(maskedFrame(OPCODE.close, text(''), { fin: false }))).toThrow(
			'control frame',
		);
	});
});

describe('FrameParser and MessageAssembler', () => {
	test('splits a stream into frames whatever the chunking', () => {
		const a = maskedFrame(OPCODE.text, text('{"id":1}'));
		const b = maskedFrame(OPCODE.ping, text(''));
		const c = maskedFrame(OPCODE.text, text('{"id":2}'));
		const all = new Uint8Array([...a, ...b, ...c]);
		const parser = new FrameParser();
		const frames = [];
		for (let i = 0; i < all.length; i += 3) frames.push(...parser.push(all.subarray(i, i + 3)));
		expect(frames.map((f) => [f.opcode, decode(f.payload)])).toEqual([
			[OPCODE.text, '{"id":1}'],
			[OPCODE.ping, ''],
			[OPCODE.text, '{"id":2}'],
		]);
	});

	test('joins fragments into one message and refuses interleaving', () => {
		const assembler = new MessageAssembler();
		const first = parseFrame(maskedFrame(OPCODE.text, text('{"id":'), { fin: false }));
		const second = parseFrame(maskedFrame(OPCODE.continuation, text('7}')));
		if (first === undefined || second === undefined) throw new Error('frames');
		expect(assembler.feed(first)).toBeUndefined();
		const message = assembler.feed(second);
		expect(message?.text).toBe('{"id":7}');
		expect(message?.frames).toEqual([first, second]);
		expect(() => assembler.feed(second)).toThrow('continuation without a start');
		assembler.feed(first);
		expect(() => assembler.feed(first)).toThrow('inside another');
	});
});

describe('frames the proxy sends', () => {
	test('a text frame is unmasked with a final bit', () => {
		const frame = textFrame('{"id":3}');
		expect([...frame.subarray(0, 2)]).toEqual([0x81, 8]);
		expect(decode(frame.subarray(2))).toBe('{"id":3}');
		const medium = textFrame('x'.repeat(300));
		expect([...medium.subarray(0, 4)]).toEqual([0x81, 126, 1, 44]);
	});

	test('a masked text frame is what a client sends, and parses back to its text', () => {
		const key = new Uint8Array([1, 2, 3, 4]);
		const frame = maskedTextFrame('{"id":3}', key);
		expect([...frame.subarray(0, 2)]).toEqual([0x81, 0x80 | 8]);
		expect([...frame.subarray(2, 6)]).toEqual([1, 2, 3, 4]);
		expect(frame).toEqual(maskedFrame(OPCODE.text, text('{"id":3}'), { key }));
		for (const size of [5, 126, 70_000]) {
			const parsed = parseFrame(maskedTextFrame('y'.repeat(size)));
			expect(parsed?.fin).toBe(true);
			expect(decode(parsed?.payload ?? new Uint8Array())).toBe('y'.repeat(size));
		}
		// A fresh random key each time.
		expect(maskedTextFrame('a').subarray(2, 6)).not.toEqual(maskedTextFrame('a').subarray(2, 6));
	});

	test('a close frame carries its code and a bounded reason', () => {
		const frame = closeFrame(1009, 'too big');
		expect([...frame.subarray(0, 4)]).toEqual([0x88, 9, 0x03, 0xf1]);
		expect(decode(frame.subarray(4))).toBe('too big');
		expect(closeFrame(1000, 'x'.repeat(200)).length).toBe(2 + 2 + 123);
	});

	test('accept key, with the vector from RFC 6455', () => {
		expect(acceptKey('dGhlIHNhbXBsZSBub25jZQ==')).toBe('s3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
	});
});
