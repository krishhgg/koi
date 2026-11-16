import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { PreviewRecord } from '@koi/shared';
import {
	BuildLogs,
	capLine,
	diskFiles,
	fitJson,
	jsonSize,
	keepEnd,
	LINE_MAX_BYTES,
	type LogFile,
	pageAt,
	tailAt,
} from '../src/buildlog.ts';
import { PreviewStore } from '../src/store.ts';
import { countingFiles, memoryFile } from './fakes.ts';

// Log lines start with an ISO timestamp and a space.
const text = (line: string) => line.replace(/^\S+ /, '');

async function write(logs: BuildLogs, label: string, requestId: string, lines: string[]) {
	const log = await logs.open(label, requestId);
	for (const line of lines) log.line(line);
	await log.close();
}

const A = 'a'.repeat(16);
const B = 'b'.repeat(16);

describe('BuildLogs', () => {
	test("a new request's log replaces the label's earlier ones", async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-buildlog-'));
		const logs = new BuildLogs(state);
		await write(logs, 'hello', A, ['first build, line 1', 'first build, line 2']);
		await write(logs, 'other', A, ['another label']);
		await write(logs, 'hello', B, ['second']);
		expect(await readdir(join(state, 'logs', 'hello'))).toEqual([`${B}.build.log`]);
		expect(await logs.read('hello', A, 0, 200, 12_000)).toEqual({ next: 0, lines: [] });
		expect((await logs.read('hello', B, 0, 200, 12_000)).lines.map(text)).toEqual(['second']);
		expect((await logs.read('other', A, 0, 200, 12_000)).lines.map(text)).toEqual([
			'another label',
		]);
	});

	test('flush writes out the lines line() holds', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-buildlog-'));
		const log = await new BuildLogs(state).open('hello', A);
		log.line('one');
		log.line('two');
		await log.flush();
		const file = readFileSync(join(state, 'logs', 'hello', `${A}.build.log`), 'utf8');
		expect(file.split('\n').map(text)).toEqual(['one', 'two', '']);
		await log.close();
	});

	test('a request built again starts its log afresh', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-buildlog-'));
		const logs = new BuildLogs(state);
		await write(logs, 'hello', A, ['first attempt, line 1', 'first attempt, line 2']);
		await write(logs, 'hello', A, ['second attempt']);
		const file = await readFile(join(state, 'logs', 'hello', `${A}.build.log`), 'utf8');
		expect(file.split('\n').map(text)).toEqual(['second attempt', '']);
	});
});

// The page after `since` of a log holding `text`.
const page = (text: string, since: number, maxLines: number, maxChars: number) =>
	pageAt(memoryFile(text), since, maxLines, maxChars);

// Byte offsets in text: where its first `lines` lines end.
const offset = (text: string, lines: number) =>
	Buffer.byteLength(text.split('\n').slice(0, lines).join('\n')) + 1;

describe('pageAt', () => {
	test('counts only lines that end in a newline', async () => {
		expect(await page('a\nb\nhalf', 0, 200, 12_000)).toEqual({ next: 4, lines: ['a', 'b'] });
		expect(await page('', 0, 200, 12_000)).toEqual({ next: 0, lines: [] });
	});

	test('tells repeated lines apart by offset', async () => {
		const first = await page('a\nb\n', 0, 200, 12_000);
		expect(first).toEqual({ next: 4, lines: ['a', 'b'] });
		expect(await page('a\nb\nc\nb\nd\n', first.next, 200, 12_000)).toEqual({
			next: 10,
			lines: ['c', 'b', 'd'],
		});
	});

	test('stops at maxLines, or before the line that would pass maxChars', async () => {
		const text = Array.from({ length: 10 }, (_, i) => `${i}${'é'.repeat(99)}\n`).join('');
		const three = await page(text, offset(text, 2), 3, 12_000);
		expect(three.lines.map((l) => l[0])).toEqual(['2', '3', '4']);
		expect(three.next).toBe(offset(text, 5));
		// Each line costs 203: 100 characters taking 199 bytes, quotes and a comma.
		expect((await page(text, 0, 200, 650)).next).toBe(offset(text, 3));
	});

	test('cuts a line that alone is over maxChars, and moves past it', async () => {
		const longs = [
			'y'.repeat(50_000),
			'\u0001'.repeat(5000),
			'é'.repeat(30_000),
			`a${'é'.repeat(30_000)}`,
		];
		for (const long of longs) {
			const text = `${long}\nz\n`;
			const cut = await page(text, 0, 200, 12_000);
			expect(cut.next).toBe(offset(text, 1));
			expect(cut.lines).toHaveLength(1);
			expect(cut.lines[0]).toEndWith(' [cut by koid]');
			expect(cut.lines[0]).not.toContain('\ufffd');
			expect(jsonSize(cut.lines[0] as string) + 1).toBeLessThanOrEqual(12_000);
			expect(await page(text, cut.next, 200, 12_000)).toEqual({
				next: Buffer.byteLength(text),
				lines: ['z'],
			});
		}
	});

	test('waits at the end of the log, past it, and on a line still being written', async () => {
		expect(await page('a\n', 2, 200, 12_000)).toEqual({ next: 2, lines: [] });
		expect(await page('a\n', 5, 200, 12_000)).toEqual({ next: 5, lines: [] });
		expect(await page(`a\n${'y'.repeat(50_000)}`, 2, 200, 12_000)).toEqual({
			next: 2,
			lines: [],
		});
	});
});

// The last n whole lines of text, cut by keepEnd: what tailAt returns,
// computed from the whole text.
function wholeTail(text: string, n: number, max: number): string {
	const lines = text.slice(0, text.lastIndexOf('\n') + 1).split('\n');
	lines.pop();
	const last = lines.slice(-n);
	return keepEnd(last.length === 0 ? '' : `${last.join('\n')}\n`, max);
}

describe('tailAt', () => {
	test('returns the last whole lines', async () => {
		const tail = (text: string, n: number) => tailAt(memoryFile(text), n, 16_000);
		expect(await tail('a\nb\nc\nhal', 2)).toBe('b\nc\n');
		expect(await tail('a\nb\nc\nhal', 200)).toBe('a\nb\nc\n');
		expect(await tail('', 5)).toBe('');
		expect(await tail('no newline yet', 5)).toBe('');
	});

	test('cuts lines longer than maxBytes from their end, saying so', async () => {
		const many = Array.from({ length: 5000 }, (_, i) => `line ${i + 1} ${'é'.repeat(20)}\n`).join(
			'',
		);
		const texts = [
			`${'x'.repeat(20_000)}\n`,
			`${'ü'.repeat(20_000)}\n`,
			`x${'ü'.repeat(20_000)}\n`,
			`${'x'.repeat(30_000)}\nshort 1\nshort 2\n`,
			many,
			`${many}${'y'.repeat(40_000)}`,
			`a\n${'b'.repeat(15_990)}\n`,
		];
		for (const text of texts) {
			for (const n of [1, 2, 200, 5000]) {
				const out = await tailAt(memoryFile(text), n, 16_000);
				expect(out).toBe(wholeTail(text, n, 16_000));
				expect(Buffer.byteLength(out)).toBeLessThanOrEqual(16_000);
			}
		}
		const one = await tailAt(memoryFile(`${'x'.repeat(20_000)}\n`), 1, 16_000);
		expect(one).toStartWith('[koid: earlier output cut');
	});
});

describe('BuildLogs reads', () => {
	test('read a several-MiB log only as far as a reply needs', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-buildlog-'));
		const files = countingFiles(diskFiles);
		const logs = new BuildLogs(state, files);
		const log = await logs.open('hello', A);
		for (let i = 0; i < 60_000; i++)
			log.line(`step ${String(i).padStart(6, '0')} ${'x'.repeat(80)}`);
		await log.close();
		const { size } = await stat(join(state, 'logs', 'hello', `${A}.build.log`));
		expect(size).toBeGreaterThan(6 * 1024 ** 2);
		const read = async (since: number) => {
			const before = files.bytesRead();
			const result = await logs.read('hello', A, since, 200, 12_000);
			return { result, bytes: files.bytesRead() - before };
		};
		const first = await read(0);
		expect(first.result.lines).toHaveLength(100);
		expect(first.bytes).toBeGreaterThan(0);
		expect(first.bytes).toBeLessThanOrEqual(12_000);
		// Every line takes as many bytes: timestamp, space, text, newline.
		const lineBytes = size / 60_000;
		expect(Number.isInteger(lineBytes)).toBe(true);
		const middle = await read(30_000 * lineBytes);
		expect(middle.result.lines[0]).toContain('step 030000 ');
		expect(middle.bytes).toBeLessThanOrEqual(12_000);
		const end = await read(size);
		expect(end).toEqual({ result: { next: size, lines: [] }, bytes: 0 });
		const before = files.bytesRead();
		const tail = await logs.tail('hello', A, 5000, 16_000);
		expect(tail).toStartWith('[koid: earlier output cut');
		expect(tail).toContain(`step 059999 ${'x'.repeat(80)}\n`);
		expect(files.bytesRead() - before).toBeLessThanOrEqual(16_001 + 16 * 1024);
	});
});

describe('fitJson', () => {
	test('keeps text that fits and cuts text that does not, by its JSON size', () => {
		expect(fitJson('hello', 100)).toBe('hello');
		for (const text of [
			'é'.repeat(5000),
			'\u0001'.repeat(5000),
			'😀'.repeat(5000),
			'a'.repeat(5000),
		]) {
			const cut = fitJson(text, 1000);
			expect(jsonSize(cut)).toBeLessThanOrEqual(1000);
			expect(jsonSize(cut)).toBeGreaterThan(990);
			expect(cut).toEndWith(' [cut by koid]');
			expect(cut).not.toMatch(/[\ud800-\udbff] \[cut/);
		}
	});
});

// A log file of `size` bytes of x, ending in a newline if `ended`, that
// counts the bytes read from it.
function oneLongLine(size: number, ended: boolean) {
	let bytesRead = 0;
	const file: LogFile = {
		size,
		async read(position, length) {
			const count = Math.max(0, Math.min(length, size - position));
			const bytes = Buffer.alloc(count, 'x');
			if (ended && count > 0 && position + count === size) bytes[count - 1] = 0x0a;
			bytesRead += count;
			return bytes;
		},
		close: async () => {},
	};
	return { file, bytesRead: () => bytesRead };
}

describe('long lines', () => {
	test('line() stores at most 4 KiB of a line, cut on a character', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-buildlog-'));
		const logs = new BuildLogs(state);
		const long = ['x'.repeat(1024 ** 2), 'é'.repeat(1024 ** 2), '😀'.repeat(300_000)];
		await write(logs, 'hello', A, [...long, 'ok']);
		const file = await readFile(join(state, 'logs', 'hello', `${A}.build.log`), 'utf8');
		const stored = file.split('\n').slice(0, -1);
		expect(stored.map(text).at(-1)).toBe('ok');
		for (const line of stored.slice(0, 3)) {
			expect(Buffer.byteLength(`${line}\n`)).toBeLessThanOrEqual(LINE_MAX_BYTES);
			expect(Buffer.byteLength(`${line}\n`)).toBeGreaterThan(LINE_MAX_BYTES - 4);
			expect(line).toEndWith(' [cut by koid]');
			expect(line).not.toContain('\ufffd');
		}
		expect(capLine('short')).toBe('short');
	});

	test('line() masks a key before it cuts, so a key across the cut is not left in part', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-buildlog-'));
		const logs = new BuildLogs(state);
		const key = `sk-ant-api03-${'abcdefghij0123456789'.repeat(3)}`;
		// The key starts just before where line() cuts and ends after it, and
		// the line is too long even once the key is masked.
		const before = 'x '.repeat(2020);
		await write(logs, 'hello', A, [`${before}${key} ${'y '.repeat(100)}`]);
		const file = await readFile(join(state, 'logs', 'hello', `${A}.build.log`), 'utf8');
		expect(Buffer.byteLength(file)).toBeLessThanOrEqual(LINE_MAX_BYTES);
		expect(file).toEndWith(' [cut by koid]\n');
		expect(file).toContain(`${before}[redacted]`);
		expect(file).not.toContain(key.slice(0, 8));
	});

	test('a page reads at most 64 KiB of a line from before lines were cut', async () => {
		const MiB64 = 64 * 1024 ** 2;
		for (const ended of [true, false]) {
			const big = oneLongLine(MiB64, ended);
			const first = await pageAt(big.file, 0, 200, 12_000);
			expect(first.lines).toHaveLength(1);
			expect(first.lines[0]).toEndWith(' [cut by koid]');
			expect(first.next).toBe(64 * 1024);
			const second = await pageAt(big.file, first.next, 200, 12_000);
			expect(second.next).toBe(2 * 64 * 1024);
			expect(big.bytesRead()).toBeLessThanOrEqual(2 * (64 * 1024 + 3));
		}
	});

	test('a page waits on an unfinished line under 64 KiB, reading no more than it', async () => {
		const short = oneLongLine(50_000, false);
		expect(await pageAt(short.file, 0, 200, 12_000)).toEqual({ next: 0, lines: [] });
		expect(await pageAt(short.file, 0, 200, 12_000)).toEqual({ next: 0, lines: [] });
		expect(short.bytesRead()).toBe(2 * 50_000);
	});

	test('a tail reads at most 64 KiB and the part it returns', async () => {
		const MiB64 = 64 * 1024 ** 2;
		for (const ended of [true, false]) {
			const big = oneLongLine(MiB64, ended);
			const out = await tailAt(big.file, 1, 16_000);
			expect(out).toStartWith('[koid: earlier output cut');
			expect(Buffer.byteLength(out)).toBeLessThanOrEqual(16_000);
			expect(big.bytesRead()).toBeLessThanOrEqual(64 * 1024 + 16_001);
		}
		expect(await tailAt(oneLongLine(50_000, false).file, 1, 16_000)).toBe('');
	});
});

describe('BuildLogs.upgrade', () => {
	test('moves logs from before attempts to their latest attempt and removes the rest', async () => {
		// The state an older koid left: records with no attempt, and one log
		// per label in logs/<label>.build.log.
		const state = await mkdtemp(join(tmpdir(), 'koi-upgrade-'));
		await mkdir(join(state, 'previews'));
		await mkdir(join(state, 'logs'));
		const old = {
			label: 'hello',
			project: 'hello',
			repo: 'github.com/acme/hello',
			status: 'running',
			commit: 'c'.repeat(40),
			branch: 'main',
			dirty: false,
			requestId: 'r'.repeat(16),
			ttlDays: 7,
			createdAt: '2026-10-06T00:00:00.000Z',
			updatedAt: '2026-10-06T00:00:00.000Z',
		};
		const legacy = (label: string) => join(state, 'logs', `${label}.build.log`);
		await writeFile(join(state, 'previews', 'hello.json'), JSON.stringify(old));
		await writeFile(legacy('hello'), 'previous build output\nready\n');
		// A record a koid that read old records with an empty attempt wrote back.
		await writeFile(
			join(state, 'previews', 'empty.json'),
			JSON.stringify({ ...old, label: 'empty', attempt: '' }),
		);
		await writeFile(legacy('empty'), 'empty attempt output\n');
		// A preview since removed.
		await writeFile(legacy('gone'), 'old output\n');
		// A label that already has a log of the new kind.
		await writeFile(
			join(state, 'previews', 'both.json'),
			JSON.stringify({ ...old, label: 'both', attempt: B }),
		);
		await writeFile(legacy('both'), 'older output\n');
		await mkdir(join(state, 'logs', 'both'));
		await writeFile(join(state, 'logs', 'both', `${B}.build.log`), 'newer output\n');

		// As koid starts.
		const store = new PreviewStore(state);
		await store.init();
		const logs = new BuildLogs(state);
		await logs.upgrade(await store.list());

		const hello = await store.get('hello');
		expect(hello?.attempt).toMatch(/^[a-z0-9]{20}$/);
		expect(await logs.tail('hello', hello?.attempt ?? '', 200, 16_000)).toBe(
			'previous build output\nready\n',
		);
		const empty = await store.get('empty');
		expect(empty?.attempt).toMatch(/^[a-z0-9]{20}$/);
		expect(await logs.tail('empty', empty?.attempt ?? '', 200, 16_000)).toBe(
			'empty attempt output\n',
		);
		expect(await logs.tail('both', B, 200, 16_000)).toBe('newer output\n');
		expect((await readdir(join(state, 'logs'))).sort()).toEqual(['both', 'empty', 'hello']);
		// The label's next build leaves only its own log.
		await write(logs, 'hello', A, ['new build']);
		expect(await readdir(join(state, 'logs', 'hello'))).toEqual([`${A}.build.log`]);
	});
});

describe('a record with no attempt', () => {
	test('has no log to read, and keeps its old log for the next start', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-buildlog-'));
		const logs = new BuildLogs(state);
		expect(await logs.read('hello', '', 0, 200, 12_000)).toEqual({ next: 0, lines: [] });
		expect(await logs.tail('hello', '', 200, 16_000)).toBe('');
		await mkdir(join(state, 'logs'));
		await writeFile(join(state, 'logs', 'hello.build.log'), 'old output\n');
		const record = { label: 'hello', attempt: '' } as PreviewRecord;
		await logs.upgrade([record]);
		expect(await readdir(join(state, 'logs'))).toEqual(['hello.build.log']);
	});
});

describe('BuildLogs.read', () => {
	test("reads a request's lines by offset from its file, and nothing when there is none", async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-buildlog-'));
		const logs = new BuildLogs(state);
		expect(await logs.read('hello', A, 0, 200, 12_000)).toEqual({ next: 0, lines: [] });
		expect(await logs.read('hello', A, 3, 200, 12_000)).toEqual({ next: 3, lines: [] });
		await write(logs, 'hello', A, ['one', 'two', 'three']);
		const all = await logs.read('hello', A, 0, 200, 12_000);
		expect(all.lines.map(text)).toEqual(['one', 'two', 'three']);
		const one = await logs.read('hello', A, 0, 1, 12_000);
		const rest = await logs.read('hello', A, one.next, 200, 12_000);
		expect(rest.next).toBe(all.next);
		expect(rest.lines.map(text)).toEqual(['two', 'three']);
		expect(await logs.read('hello', B, 0, 200, 12_000)).toEqual({ next: 0, lines: [] });
	});
});

describe('keepEnd', () => {
	test('keeps the end of one long line, starting on a whole character', () => {
		const out = keepEnd(`${'ü'.repeat(20_000)}\n`, 1000);
		expect(Buffer.byteLength(out)).toBeLessThanOrEqual(1000);
		expect(out).not.toContain('\ufffd');
		expect(out).toEndWith('üü\n');
	});

	test('drops the part of a line the cut fell in', () => {
		const text = `${'a'.repeat(5000)}\n${'b'.repeat(500)}\n`;
		const out = keepEnd(text, 600);
		expect(out.split('\n')[1]).toBe('b'.repeat(500));
		expect(keepEnd('short\n', 600)).toBe('short\n');
	});
});
