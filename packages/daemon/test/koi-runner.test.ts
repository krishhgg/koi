import { afterAll, describe, expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifyLine, LineSplitter, PROTOCOL_LIMITS } from '../src/verifier.ts';

// Both runner clients, run as a runner runs them, with what they print read the
// way koid reads it. A line koid discards reads as an event the runner never
// sent, so the test is that each event arrives, whatever its text holds.

const CLIENTS = join(import.meta.dir, '../../../host/verifier/clients');
const POINT = 'hello.home';
const LINE = PROTOCOL_LIMITS.lineBytes;

const dirs: string[] = [];
afterAll(async () => {
	for (const dir of dirs) await rm(dir, { recursive: true, force: true });
});

async function runScript(cmd: string[]): Promise<{ out: string; err: string; code: number }> {
	const proc = Bun.spawn(cmd, { stdout: 'pipe', stderr: 'pipe', stdin: 'ignore' });
	const [out, err, code] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	return { out, err, code };
}

type Client = (texts: string[]) => Promise<{ out: string; err: string; code: number }>;

// Prints an assertion and a note for each text, which the script reads from a
// JSON file, so no shell or source quoting comes between the test and the client.
const clients: Record<string, Client> = {
	python: async (texts) => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-runner-py-'));
		dirs.push(dir);
		const input = join(dir, 'texts.json');
		await writeFile(input, JSON.stringify(texts));
		const script = `
import json, sys
sys.path.insert(0, sys.argv[1])
import koi_runner as koi
for text in json.load(open(sys.argv[2], encoding="utf-8")):
    koi.assertion("declared", "fail", [], detail=text, point=${JSON.stringify(POINT)})
    koi.note(text)
`;
		return runScript(['python3', '-I', '-c', script, CLIENTS, input]);
	},
	javascript: async (texts) => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-runner-js-'));
		dirs.push(dir);
		const input = join(dir, 'texts.json');
		const script = join(dir, 'runner.mjs');
		await writeFile(input, JSON.stringify(texts));
		await writeFile(
			script,
			`import { readFileSync } from 'node:fs';
import * as koi from ${JSON.stringify(join(CLIENTS, 'koi-runner.mjs'))};
for (const text of JSON.parse(readFileSync(${JSON.stringify(input)}, 'utf8'))) {
	koi.assertion('declared', 'fail', [], text, ${JSON.stringify(POINT)});
	koi.note(text);
}
`,
		);
		return runScript([process.execPath, script]);
	},
};

// What koid makes of a client's stdout.
function readAsKoid(out: string) {
	const splitter = new LineSplitter(LINE);
	const lines = [...splitter.push(new TextEncoder().encode(out)), ...splitter.end()];
	return lines.map((line) => {
		if ('discarded' in line) throw new Error('koid would have discarded a line');
		const read = classifyLine(line.text, 'k'.repeat(64));
		if (read.kind !== 'event') throw new Error(`koid read ${JSON.stringify(read)}`);
		return { event: read.event, bytes: Buffer.byteLength(line.text) };
	});
}

const CHINESE = '测试'.repeat(1000);
const TEXTS: Array<[string, string]> = [
	['2,000 Chinese characters', CHINESE],
	['4,000 Chinese characters', CHINESE.repeat(2)],
	['emoji', '😀'.repeat(3000)],
	['quotes', '"'.repeat(5000)],
	['control characters', '\u0001'.repeat(5000)],
	['more text than the schema takes', 'x'.repeat(5000)],
	// Within the bytes on the Python side, and past 4,000 as the schema counts.
	['ASCII with emoji at the end', `${'x'.repeat(3650)}${'😀'.repeat(350)}`],
];

describe.each(Object.keys(clients))('the %s client', (language) => {
	const client = clients[language] as Client;

	test.each(TEXTS)('%s reach koid as events, cut only as far as they must', async (_name, text) => {
		const { out, err, code } = await client([text]);
		expect(err).toBe('');
		expect(code).toBe(0);
		const events = readAsKoid(out);
		expect(events.map((e) => e.event.type)).toEqual(['assertion', 'note']);
		for (const { event, bytes } of events) {
			expect(bytes).toBeLessThanOrEqual(LINE);
			const kept = event.type === 'assertion' ? event.detail : event.type === 'note' && event.text;
			if (typeof kept !== 'string') throw new Error('no text');
			expect(kept.length).toBeGreaterThan(0);
			expect(text.startsWith(kept)).toBe(true);
			// Half a surrogate pair is not text.
			expect(kept.isWellFormed()).toBe(true);
			// Stopped by one bound or the other, within a character of it.
			expect(bytes > LINE - 12 || kept.length >= 3999 || kept === text).toBe(true);
		}
	});

	test('text that fits is kept whole', async () => {
		const { out } = await client(['测试 under the bound']);
		expect(readAsKoid(out).map((e) => e.event)).toEqual([
			{
				type: 'assertion',
				point: POINT,
				name: 'declared',
				outcome: 'fail',
				evidence: [],
				detail: '测试 under the bound',
			},
			{ type: 'note', text: '测试 under the bound' },
		]);
	});
});

test('the JavaScript client fails a second call under a label in flight, and sends it nowhere', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'koi-runner-js-'));
	dirs.push(dir);
	const script = join(dir, 'runner.mjs');
	await writeFile(
		script,
		`import * as koi from ${JSON.stringify(join(CLIENTS, 'koi-runner.mjs'))};
const first = koi.capture('screenshot', 'shot');
const second = await koi.read('/', 'shot').catch((err) => err.code);
console.error(second);
await first.catch((err) => console.error(err.code));
`,
	);
	const { out, err, code } = await runScript([process.execPath, script]);
	expect(code).toBe(0);
	// The second never went out, so koid's answer to the first can only reach the first.
	expect(readAsKoid(out).map((e) => e.event.type)).toEqual(['capture']);
	expect(err.trim().split('\n')).toEqual(['duplicate_label', 'stdin_closed']);
});

test('the JavaScript client throws for an event too large without its text, and leaves no one waiting', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'koi-runner-js-'));
	dirs.push(dir);
	const script = join(dir, 'runner.mjs');
	await writeFile(
		script,
		`import * as koi from ${JSON.stringify(join(CLIENTS, 'koi-runner.mjs'))};
const refs = Array.from({ length: 1000 }, (_, i) => 'recorder:screenshot:' + i);
try {
	koi.assertion('declared', 'pass', refs, 'why', ${JSON.stringify(POINT)});
	console.error('it printed');
} catch (err) {
	console.error(err.message);
}
try {
	koi.read('/' + '测'.repeat(4000), 'row');
	console.error('it printed');
} catch (err) {
	console.error(err.message);
}
`,
	);
	const { out, err, code } = await runScript([process.execPath, script]);
	expect(code).toBe(0);
	expect(out).toBe('');
	expect(err.trim().split('\n')).toEqual([
		expect.stringContaining('koid discards a line over 8192'),
		expect.stringContaining('koid discards a line over 8192'),
	]);
});
