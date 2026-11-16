import { describe, expect, test } from 'bun:test';
import { decodeCtlArgs, encodeCtlArgs } from '../src/control.ts';

describe('koid ctl arguments as base64', () => {
	test('decode to exactly what was encoded', () => {
		for (const args of [
			['ping'],
			['status', 'hello-pr-7', 'a'.repeat(20), '120'],
			['status', `x'; rm -rf / $(id) \`id\` "q" \\ | & > <\n\t é😀`, '', '-rf'],
		]) {
			const blob = encodeCtlArgs(args);
			expect(blob).toMatch(/^[A-Za-z0-9+/]+=*$/);
			expect(decodeCtlArgs(blob)).toEqual(args);
		}
	});

	test('refuse a blob that is not base64 of a list of strings', () => {
		const b64 = (text: string) => Buffer.from(text, 'utf8').toString('base64');
		for (const blob of [
			'',
			'not base64!',
			'$(id)',
			`${encodeCtlArgs(['ping'])} x`,
			// Base64 without its padding, or with characters base64url uses.
			encodeCtlArgs(['ping']).replace(/=+$/, ''),
			`-${encodeCtlArgs(['ping']).slice(1)}`,
			`_${encodeCtlArgs(['ping']).slice(1)}`,
			b64('{"0":"ping"}'),
			b64('"ping"'),
			b64('[]'),
			b64('[1]'),
			b64(JSON.stringify(Array.from({ length: 9 }, () => 'x'))),
			b64(JSON.stringify(['x'.repeat(1025)])),
			Buffer.from([0x5b, 0x22, 0xff, 0x22, 0x5d]).toString('base64'),
		]) {
			expect(() => decodeCtlArgs(blob)).toThrow();
		}
	});

	test('refuse to encode what koid would refuse to decode', () => {
		expect(() => encodeCtlArgs([])).toThrow();
		expect(() => encodeCtlArgs(['x'.repeat(1025)])).toThrow();
	});
});
