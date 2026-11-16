import { describe, expect, test } from 'bun:test';
import { mkdtemp, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileLiveList } from '../src/file-live.ts';

async function file() {
	const root = await mkdtemp(join(tmpdir(), 'koid-live-'));
	return { root, path: join(root, 'state', 'live-previews.json') };
}

// 62 characters each: 63 of them fill an SSM parameter exactly; far more
// fit in a file.
const long = (i: number) => `x${String(i).padStart(3, '0')}${'a'.repeat(58)}`;
const labels = (n: number) => Array.from({ length: n }, (_, i) => long(i));

describe('fileLiveList', () => {
	test('writes the labels, each once and sorted, as one JSON line, readable by anyone', async () => {
		const f = await file();
		await fileLiveList(f.path).publish(['b', 'a', 'b']);
		expect(await readFile(f.path, 'utf8')).toBe('["a","b"]\n');
		expect((await stat(f.path)).mode & 0o777).toBe(0o644);
		// Only the file: the temporary it was written through is gone.
		expect(await readdir(join(f.root, 'state'))).toEqual(['live-previews.json']);
	});

	test('skips the write when the list has not changed, in any order', async () => {
		const f = await file();
		const live = fileLiveList(f.path);
		await live.publish(['a', 'b']);
		await writeFile(f.path, 'left alone');
		await live.publish(['b', 'a']);
		expect(await readFile(f.path, 'utf8')).toBe('left alone');
		await live.publish(['a']);
		expect(await readFile(f.path, 'utf8')).toBe('["a"]\n');
	});

	test('always has room, and publishes a list far longer than an SSM parameter holds', async () => {
		const f = await file();
		const live = fileLiveList(f.path);
		const many = labels(500);
		expect(live.room(many)).toEqual({ ok: true });
		await live.publish(many);
		expect(JSON.parse(await readFile(f.path, 'utf8'))).toEqual(many);
		expect((await stat(f.path)).size).toBeGreaterThan(4096 * 7);
	});

	test('refuses a label that is not a preview label without writing', async () => {
		const f = await file();
		await expect(fileLiveList(f.path).publish(['Bad_Label'])).rejects.toThrow();
		await expect(stat(f.path)).rejects.toThrow();
	});

	test('a reader sees a whole list, never part of one, while it is rewritten', async () => {
		const f = await file();
		const live = fileLiveList(f.path);
		await live.publish(labels(1));
		let reads = 0;
		let stop = false;
		const reader = (async () => {
			while (!stop) {
				const text = await readFile(f.path, 'utf8');
				// Each list parses and ends where a whole write ends.
				expect(text.endsWith('\n')).toBe(true);
				expect(Array.isArray(JSON.parse(text))).toBe(true);
				reads += 1;
			}
		})();
		for (let n = 2; n < 60; n++) await live.publish(labels(n));
		stop = true;
		await reader;
		expect(reads).toBeGreaterThan(0);
		expect(JSON.parse(await readFile(f.path, 'utf8'))).toHaveLength(59);
	});
});
