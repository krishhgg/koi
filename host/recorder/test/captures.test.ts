import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { CaptureError, CaptureStore } from '../src/captures.ts';

describe('CaptureStore', () => {
	test('holds a copy of the bytes in memory until acknowledged, within its caps', () => {
		const store = new CaptureStore({ perCapture: 10, total: 16 });
		const source = new Uint8Array([1, 2, 3, 4]);
		const first = store.put('aria', 'text/plain', source);
		source[0] = 9;
		expect(first).toMatchObject({
			captureId: 'c1',
			kind: 'aria',
			mediaType: 'text/plain',
			size: 4,
			sha256: `sha256:${createHash('sha256')
				.update(new Uint8Array([1, 2, 3, 4]))
				.digest('hex')}`,
		});
		expect([...(store.get('c1')?.bytes ?? [])]).toEqual([1, 2, 3, 4]);
		expect(store.stats()).toEqual({ count: 1, bytes: 4 });
		expect(() => store.put('screenshot', 'image/png', new Uint8Array(11))).toThrow(CaptureError);
		store.put('screenshot', 'image/png', new Uint8Array(10));
		expect(() => store.put('aria', 'text/plain', new Uint8Array(3))).toThrow(
			'too many unacknowledged captures',
		);
		expect(store.delete('c1')).toBe(true);
		expect(store.delete('c1')).toBe(false);
		expect(store.get('c1')).toBeUndefined();
		expect(store.stats()).toEqual({ count: 1, bytes: 10 });
		expect(store.put('aria', 'text/plain', new Uint8Array(6)).captureId).toBe('c3');
	});
});
