import { describe, expect, test } from 'bun:test';
import { labelFromHost } from '../src/preview.ts';

describe('labelFromHost', () => {
	test('returns the label of a preview address', () => {
		expect(labelFromHost('storefront-pr-2518.previews.example.net', 'previews.example.net')).toBe(
			'storefront-pr-2518',
		);
		expect(labelFromHost('a.previews.example.net', 'previews.example.net')).toBe('a');
	});

	test.each([
		'',
		'previews.example.net',
		'.previews.example.net',
		'evil.example',
		'-bad.previews.example.net',
		'bad-.previews.example.net',
		'Upper.previews.example.net',
		'a.b.previews.example.net',
		'a_b.previews.example.net',
		'x.previews.example.net.evil.example',
		'xpreviews.example.net',
		'x.previews.example.net:443',
		`${'a'.repeat(64)}.previews.example.net`,
	])('rejects %p', (host) => {
		expect(labelFromHost(host, 'previews.example.net')).toBeNull();
	});

	test('rejects a missing host or an empty domain', () => {
		expect(labelFromHost(undefined, 'previews.example.net')).toBeNull();
		expect(labelFromHost(null, 'previews.example.net')).toBeNull();
		expect(labelFromHost('abc.', '')).toBeNull();
	});
});
