import { describe, expect, spyOn, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
	type FileHandle,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	stat,
	symlink,
	utimes,
	writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
	EVIDENCE_LIMITS,
	EVIDENCE_RETENTION,
	EvidenceEventSchema,
	EvidenceManifestSchema,
	EvidenceTombstoneSchema,
	RunStatusSchema,
} from '@koi/shared';
import { type EvidenceLookup, judgePoint } from '../src/verdict.ts';
import type { Sanitize } from '../src/verification-sanitize.ts';
import {
	CapExceededError,
	DISK_WAIT_MS,
	EvidenceStore,
	EvidenceStuckError,
	MAX_PROBLEMS,
	PROBLEMS_CAPPED,
	type RunWriter,
	resolveArtifacts,
	writeAll,
} from '../src/verification-store.ts';
import {
	eventually,
	Gate,
	holdingRemoval,
	openingWith,
	refusingRemoval,
	refusingRename,
} from './fakes.ts';

const RUN = 'abcdefghijklmnop0123';
const DAY = 86_400_000;
const sha = (bytes: Uint8Array | string) =>
	`sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const redaction = {
	status: 'sanitized' as const,
	policyDigest: sha('policy'),
	removedFields: [],
	limitations: ['pixels may contain unknown application data'],
};

async function setup(
	options: {
		limits?: ConstructorParameters<typeof EvidenceStore>[0]['limits'];
		free?: number;
		scrub?: (text: string) => string;
		diskPollMs?: number;
	} = {},
) {
	const root = await mkdtemp(join(tmpdir(), 'koid-evidence-'));
	let clock = Date.parse('2026-10-06T12:00:00.000Z');
	const disk = { free: options.free ?? 60 * 1024 ** 3, size: 80 * 1024 ** 3 };
	const logs: string[] = [];
	const store = new EvidenceStore({
		stateDir: root,
		now: () => new Date(clock),
		diskSpace: async () => ({ ...disk }),
		...(options.limits !== undefined ? { limits: options.limits } : {}),
		...(options.scrub !== undefined ? { scrub: options.scrub } : {}),
		...(options.diskPollMs !== undefined ? { diskPollMs: options.diskPollMs } : {}),
		log: (m) => logs.push(m),
	});
	await store.init();
	return {
		root,
		store,
		disk,
		logs,
		advance(ms: number) {
			clock += ms;
		},
		now: () => new Date(clock).toISOString(),
	};
}

async function mode(path: string): Promise<number> {
	return (await stat(path)).mode & 0o777;
}

// The sizes of the files in `dir`, added up.
async function bytesIn(dir: string): Promise<number> {
	let total = 0;
	for (const name of await readdir(dir)) total += (await stat(join(dir, name))).size;
	return total;
}

// For openingWith: the next sync of the directory `dir` fails, as a disk
// error after an artifact was renamed into place does.
function failingSyncOf(dir: string): (path: string, handle: FileHandle) => void {
	let failed = false;
	return (path, handle) => {
		if (failed || path !== dir) return;
		failed = true;
		spyOn(handle, 'sync').mockImplementation(async () => {
			throw new Error('EIO: i/o error');
		});
	};
}

async function entry(
	run: RunWriter,
	kind: 'screenshot' | 'aria' = 'screenshot',
	bytes: Uint8Array = new Uint8Array([1, 2, 3]),
) {
	return run.writeArtifact(
		{
			pointId: 'hello.home',
			attempt: 1,
			kind,
			mediaType: kind === 'screenshot' ? 'image/png' : 'text/plain; charset=utf-8',
			capturedAt: '2026-10-06T12:00:00.000Z',
			eventRange: { first: 0, last: 0 },
			redaction,
		},
		bytes,
	);
}

describe('EvidenceStore', () => {
	test('makes its tree with 0700 directories and 0600 files', async () => {
		const t = await setup();
		for (const dir of ['', 'inputs', 'plans', 'runs']) {
			expect(await mode(join(t.store.root, dir))).toBe(0o700);
		}
		const run = await t.store.openRun(RUN);
		const dir = t.store.runDir(RUN);
		for (const sub of ['', '.pending', 'artifacts', 'points'])
			expect(await mode(join(dir, sub))).toBe(0o700);
		expect(await mode(join(dir, 'status.json'))).toBe(0o600);
		expect(await mode(join(dir, 'events.ndjson'))).toBe(0o600);
		await entry(run);
		expect(await mode(join(dir, 'artifacts', 'recorder:screenshot:1'))).toBe(0o600);
		await run.writeObservations('hello.home', { expected: 200, observed: 200 });
		expect(await mode(join(dir, 'points', 'hello.home'))).toBe(0o700);
		expect(await mode(join(dir, 'points', 'hello.home', 'observations.json'))).toBe(0o600);
		await run.abandon();
	});

	test('refuses a run whose directory exists, and a box short of space', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		await expect(t.store.openRun(RUN)).rejects.toThrow('is open already');
		await run.abandon();
		await expect(t.store.openRun(RUN)).rejects.toThrow('already has a directory');
		t.disk.free = 5 * 1024 ** 3;
		await expect(t.store.openRun('z'.repeat(20))).rejects.toThrow(CapExceededError);
		// 10% of 80 GiB is the reserve here; 8 GiB free leaves no room for a run.
		t.disk.free = 8 * 1024 ** 3 + 100 * 1024 ** 2;
		await expect(t.store.openRun('z'.repeat(20))).rejects.toThrow('reserve of 8 GiB');
	});

	test('on a large disk the reserve stops at its cap, not at a tenth of the disk', async () => {
		const t = await setup();
		t.disk.size = 2048 * 1024 ** 3;
		t.disk.free = 21 * 1024 ** 3;
		const run = await t.store.openRun(RUN);
		await run.abandon();
		t.disk.free = 20 * 1024 ** 3 + 100 * 1024 ** 2;
		await expect(t.store.openRun('z'.repeat(20))).rejects.toThrow('reserve of 20 GiB');
	});

	test('counts the allowance of every open run against free space until it finalizes or is abandoned', async () => {
		const t = await setup();
		// Room over the 8 GiB reserve for one run and a half.
		t.disk.free = 8 * 1024 ** 3 + 768 * 1024 ** 2;
		const first = await t.store.openRun(RUN);
		expect(t.store.reservedBytes()).toBe(512 * 1024 ** 2);
		await expect(t.store.openRun('z'.repeat(20))).rejects.toThrow(
			'0.5 GiB of it promised to runs still open',
		);
		await first.finalize({ limitations: [] });
		expect(t.store.reservedBytes()).toBe(0);
		const second = await t.store.openRun('z'.repeat(20));
		await expect(t.store.openRun('y'.repeat(20))).rejects.toThrow(CapExceededError);
		await second.abandon();
		expect(t.store.reservedBytes()).toBe(0);
		const third = await t.store.openRun('y'.repeat(20));
		await third.abandon();
		// A run refused keeps no reservation.
		t.disk.free = 1024 ** 3;
		await expect(t.store.openRun('x'.repeat(20))).rejects.toThrow(CapExceededError);
		expect(t.store.reservedBytes()).toBe(0);
	});
});

describe('writeAll', () => {
	test('writes every byte through short writes, and fails on no progress', async () => {
		const written: number[] = [];
		const short = {
			async write(buffer: Uint8Array, offset?: number, length?: number) {
				const n = Math.min(3, length ?? buffer.length);
				written.push(...buffer.subarray(offset ?? 0, (offset ?? 0) + n));
				return { bytesWritten: n, buffer };
			},
		};
		await writeAll(short as never, new Uint8Array([1, 2, 3, 4, 5, 6, 7]));
		expect(written).toEqual([1, 2, 3, 4, 5, 6, 7]);
		const stuck = {
			async write(buffer: Uint8Array) {
				return { bytesWritten: 0, buffer };
			},
		};
		await expect(writeAll(stuck as never, new Uint8Array(4))).rejects.toThrow('made no progress');
	});
});

describe('RunWriter', () => {
	test('numbers events and writes each line durably', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const first = await run.appendEvent({
			source: 'host',
			type: 'recorder-starting',
			container: 'c',
		});
		const second = await run.appendEvent({
			source: 'recorder',
			type: 'denied',
			pointId: 'hello.home',
			attempt: 1,
			url: 'http://example.com/',
		});
		expect([first.seq, second.seq]).toEqual([1, 2]);
		expect(first.at).toBe(t.now());
		const lines = (await readFile(join(t.store.runDir(RUN), 'events.ndjson'), 'utf8'))
			.trimEnd()
			.split('\n');
		expect(lines.map((l) => JSON.parse(l))).toEqual([first, second]);
		const big = await run.appendEvent({ source: 'runner', type: 'log', text: 'x'.repeat(20_000) });
		expect(big.type).toBe('oversized-event');
		expect(big.originalType).toBe('log');
		expect(run.status.counts.events).toBe(3);
		// Its content is gone, so the evidence is not whole.
		expect(run.status.problems.map((p) => p.code)).toEqual(['event_oversized']);
		expect(run.status.evidence).toBe('incomplete');
		await run.abandon();
	});

	test('writes an artifact through .pending into artifacts/ with its hash, size and a fresh id', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const bytes = new TextEncoder().encode('png bytes');
		const a = await entry(run, 'screenshot', bytes);
		expect(a).toEqual({
			id: 'recorder:screenshot:1',
			runId: RUN,
			pointId: 'hello.home',
			attempt: 1,
			kind: 'screenshot',
			mediaType: 'image/png',
			size: bytes.length,
			sha256: sha(bytes),
			origin: 'recorder',
			capturedAt: '2026-10-06T12:00:00.000Z',
			eventRange: { first: 0, last: 0 },
			redaction,
			availability: 'available',
			retainedUntil: new Date(Date.parse(t.now()) + 30 * DAY).toISOString(),
		});
		expect(await readFile(join(t.store.runDir(RUN), 'artifacts', a.id))).toEqual(
			Buffer.from(bytes),
		);
		expect(await readdir(join(t.store.runDir(RUN), '.pending'))).toEqual([]);
		// From an async iterable, in chunks.
		const chunks = (async function* () {
			yield new TextEncoder().encode('line one\n');
			yield new TextEncoder().encode('line two\n');
		})();
		const b = await run.writeArtifact(
			{
				pointId: 'hello.home',
				attempt: 1,
				kind: 'aria',
				mediaType: 'text/plain',
				capturedAt: t.now(),
				eventRange: { first: 0, last: 0 },
				redaction,
			},
			chunks,
		);
		expect(b.id).toBe('recorder:aria:2');
		expect(b.size).toBe(18);
		expect(b.sha256).toBe(sha('line one\nline two\n'));
		const c = await entry(run);
		expect(c.id).toBe('recorder:screenshot:3');
		expect(run.status.counts).toEqual({ events: 0, artifacts: 3, bytes: bytes.length + 18 + 3 });
		await run.abandon();
	});

	test('a cap stops capture: no file, a problem on the run, and later writes refused', async () => {
		const t = await setup({ limits: { bytesPerArtifact: 10 } });
		const run = await t.store.openRun(RUN);
		await entry(run, 'screenshot', new Uint8Array(10));
		const failing = (async function* () {
			yield new Uint8Array(8);
			yield new Uint8Array(8);
		})();
		await expect(
			run.writeArtifact(
				{
					pointId: 'hello.home',
					attempt: 1,
					kind: 'aria',
					mediaType: 'text/plain',
					capturedAt: t.now(),
					eventRange: { first: 0, last: 0 },
					redaction,
				},
				failing,
			),
		).rejects.toThrow('the most one artifact may be');
		const dir = t.store.runDir(RUN);
		expect(await readdir(join(dir, 'artifacts'))).toEqual(['recorder:screenshot:1']);
		expect(await readdir(join(dir, '.pending'))).toEqual([]);
		expect(run.capped?.cap).toBe('bytesPerArtifact');
		const status = RunStatusSchema.parse(
			JSON.parse(await readFile(join(dir, 'status.json'), 'utf8')),
		);
		expect(status.evidence).toBe('incomplete');
		expect(status.problems.map((p) => p.code)).toEqual(['cap_exceeded']);
		await expect(entry(run)).rejects.toThrow(CapExceededError);
		const again = RunStatusSchema.parse(
			JSON.parse(await readFile(join(dir, 'status.json'), 'utf8')),
		);
		expect(again.problems).toHaveLength(1);
		await run.abandon();
	});

	test('the run cap and the artifact count cap are enforced too', async () => {
		const t = await setup({ limits: { bytesPerRun: 5, artifactsPerRun: 1 } });
		const run = await t.store.openRun(RUN);
		await expect(entry(run, 'screenshot', new Uint8Array(6))).rejects.toThrow(
			'the most a run may keep',
		);
		await run.abandon();
		const u = await setup({ limits: { artifactsPerRun: 1 } });
		const other = await u.store.openRun(RUN);
		await entry(other);
		await expect(entry(other)).rejects.toThrow('the most it may keep');
		await other.abandon();
	});

	test('the artifact count cap applies to withheld and failed entries too', async () => {
		const t = await setup({ limits: { artifactsPerRun: 2 } });
		const run = await t.store.openRun(RUN);
		const withheld = {
			pointId: 'hello.home',
			attempt: 1,
			kind: 'trace' as const,
			capturedAt: t.now(),
			eventRange: { first: 0, last: 0 },
			redaction: { ...redaction, status: 'withheld' as const, limitations: ['not yet'] },
		};
		await run.recordArtifact(withheld);
		await run.recordArtifact({
			...withheld,
			redaction: { ...withheld.redaction, status: 'failed' },
		});
		await expect(run.recordArtifact(withheld)).rejects.toThrow('the most it may keep');
		expect(run.capped?.cap).toBe('artifactsPerRun');
		expect(run.status.evidence).toBe('incomplete');
		expect(run.status.problems.map((p) => p.code)).toEqual(['cap_exceeded']);
		await expect(entry(run)).rejects.toThrow(CapExceededError);
		expect(run.artifacts).toHaveLength(2);
		await run.abandon();
	});

	test('an entry the manifest schema refuses leaves no file and is recorded as failed', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const dir = t.store.runDir(RUN);
		const a = await run.writeArtifact(
			{
				pointId: 'hello.home',
				attempt: 1,
				kind: 'network',
				mediaType: 'application/x-ndjson',
				capturedAt: t.now(),
				eventRange: { first: 0, last: 0 },
				redaction: {
					...redaction,
					removedFields: Array.from({ length: 1500 }, (_, i) => `header:x-${i}`),
				},
			},
			new TextEncoder().encode('{}\n'),
		);
		expect(a.id).toBe('recorder:network:1');
		expect(a.availability).toBe('failed');
		expect(a.redaction.status).toBe('failed');
		expect(a.redaction.removedFields).toEqual([]);
		expect(a.redaction.limitations[0]).toStartWith("the artifact's entry was not valid: ");
		expect(a.redaction.limitations[0]).toContain('removedFields');
		expect(a.size).toBe(0);
		expect(await readdir(join(dir, 'artifacts'))).toEqual([]);
		expect(await readdir(join(dir, '.pending'))).toEqual([]);
		expect(run.status.problems.map((p) => p.code)).toEqual(['artifact_invalid']);
		expect(run.status.evidence).toBe('incomplete');
		expect(run.status.counts).toEqual({ events: 0, artifacts: 1, bytes: 0 });
		// The run goes on: the next artifact is kept as usual.
		const b = await entry(run);
		expect(b.id).toBe('recorder:screenshot:2');
		expect(b.availability).toBe('available');
		const manifest = await run.finalize({ limitations: [] });
		expect(manifest.artifacts.map((e) => e.availability)).toEqual(['failed', 'available']);
	});

	test('a withheld or failed artifact has an entry and no bytes', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const withheld = await run.recordArtifact({
			pointId: 'hello.home',
			attempt: 1,
			kind: 'trace',
			capturedAt: t.now(),
			eventRange: { first: 0, last: 0 },
			redaction: {
				...redaction,
				status: 'withheld',
				limitations: ['traces are not sanitized in this version'],
			},
		});
		expect(withheld.availability).toBe('withheld');
		expect(withheld.size).toBe(0);
		expect(withheld.sha256).toBe(sha(new Uint8Array(0)));
		expect(await readdir(join(t.store.runDir(RUN), 'artifacts'))).toEqual([]);
		await expect(
			run.recordArtifact({
				pointId: 'hello.home',
				attempt: 1,
				kind: 'trace',
				capturedAt: t.now(),
				eventRange: { first: 0, last: 0 },
				redaction,
			}),
		).rejects.toThrow('cannot be sanitized');
		await run.abandon();
	});

	test("every directory of a run is durable before the manifest, and the run's entry after it", async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const dir = t.store.runDir(RUN);
		await run.writeObservations('a.point', { assertions: [] });
		const order: string[] = [];
		const opens = openingWith((path, handle) => {
			const real = handle.sync.bind(handle);
			spyOn(handle, 'sync').mockImplementation(async () => {
				order.push(path);
				return real();
			});
		});
		try {
			await run.finalize({ limitations: [] });
		} finally {
			opens.mockRestore();
		}
		const at = (path: string) => order.lastIndexOf(path);
		const manifest = order.findIndex((path) => path.includes('.pending') && path.endsWith('.tmp'));
		expect(manifest).toBeGreaterThanOrEqual(0);
		const lastManifest = order.findLastIndex((path) => path.endsWith('.tmp'));
		for (const sub of ['points', 'artifacts', join('points', 'a.point')]) {
			const synced = order.indexOf(join(dir, sub));
			expect(synced, sub).toBeGreaterThanOrEqual(0);
			expect(synced, sub).toBeLessThan(lastManifest);
		}
		// runs/ for the run's entry comes before the manifest too, and the run
		// directory for the manifest's own entry after it.
		const runs = at(join(dir, '..'));
		expect(runs).toBeGreaterThanOrEqual(0);
		expect(runs).toBeLessThan(lastManifest);
		expect(at(dir)).toBeGreaterThan(lastManifest);
	});

	describe('a disk that stops answering', () => {
		// The first sync of what `picks` chooses waits at the gate, and the file's
		// write goes on from there once the gate opens.
		const holdingSync = (
			gate: Gate,
			picks: (path: string) => boolean,
			method: 'sync' | 'datasync' = 'sync',
			when: (path: string) => boolean | Promise<boolean> = () => true,
		) =>
			openingWith((path, handle) => {
				if (!picks(path)) return;
				const real = handle[method].bind(handle);
				spyOn(handle, method).mockImplementation(async () => {
					if (await when(path)) await gate.pass();
					return real();
				});
			});
		const eventsFile = (path: string) => path.endsWith('events.ndjson');
		const aTemporary = (path: string) => path.endsWith('.tmp');
		const event = { source: 'host', type: 'held' } as const;
		const failure = (promise: Promise<unknown>) =>
			promise.then(
				() => undefined,
				(e: unknown) => e,
			);

		test('a stalled event sync ends every wait at the limit, queued ones too', async () => {
			const t = await setup({ diskPollMs: 5 });
			const gate = new Gate();
			const opens = holdingSync(gate, eventsFile, 'datasync');
			const run = await t.store.openRun(RUN);
			opens.mockRestore();
			const first = failure(run.appendEvent(event));
			const queued = failure(run.appendEvent(event));
			await gate.reached;
			// Short of the limit, it may still come back.
			t.advance(DISK_WAIT_MS - 1_000);
			await Bun.sleep(30);
			expect(run.stuck).toBeUndefined();
			t.advance(2_000);
			const stuck = await first;
			expect(stuck).toBeInstanceOf(EvidenceStuckError);
			expect(await queued).toBe(stuck);
			expect(run.stuck).toBe(stuck as EvidenceStuckError);
			expect(run.stuck?.message).toStartWith('evidence_unwritable: the disk did not finish');
			// From here nothing waits, and nothing reaches the disk.
			expect(await failure(run.appendEvent(event))).toBe(stuck);
			expect(await failure(run.writeReport(() => 'text'))).toBe(stuck);
			expect(await stat(join(run.dir, 'report.md')).catch(() => undefined)).toBeUndefined();
			// A reader of the status still learns of it.
			expect(await failure(run.addProblem('late', 'said anyway'))).toBe(stuck);
			expect(run.status.evidence).toBe('incomplete');
			expect(run.status.problems.map((p) => p.code)).toEqual(['evidence_unwritable', 'late']);
			await run.abandon();
			gate.release();
		});

		test('a record whose sync comes back after the limit does not land', async () => {
			const t = await setup({ diskPollMs: 5 });
			const run = await t.store.openRun(RUN);
			const gate = new Gate();
			const opens = holdingSync(gate, aTemporary);
			const writing = failure(run.writeRecord('controller.json', { late: true }));
			await gate.reached;
			opens.mockRestore();
			t.advance(DISK_WAIT_MS + 1_000);
			expect(await writing).toBeInstanceOf(EvidenceStuckError);
			const path = join(run.dir, 'controller.json');
			expect(await stat(path).catch(() => undefined)).toBeUndefined();
			gate.release();
			await Bun.sleep(30);
			expect(await stat(path).catch(() => undefined)).toBeUndefined();
			expect(await readdir(join(run.dir, '.pending'))).toEqual([]);
			await run.abandon();
		});

		test.each<[string, (run: RunWriter) => Promise<void>, string]>([
			[
				'a declared record',
				(run) => run.writeDeclared('execution.json', { late: true }),
				'execution.json',
			],
			['the report', (run) => run.writeReport(() => 'late\n'), 'report.md'],
		])('%s is under the limit too, and does not land after it', async (_what, write, name) => {
			const t = await setup({ diskPollMs: 5 });
			const run = await t.store.openRun(RUN);
			const gate = new Gate();
			const opens = holdingSync(gate, aTemporary);
			const writing = failure(write(run));
			await gate.reached;
			opens.mockRestore();
			t.advance(DISK_WAIT_MS + 1_000);
			expect(await writing).toBeInstanceOf(EvidenceStuckError);
			gate.release();
			await Bun.sleep(30);
			expect(await stat(join(run.dir, name)).catch(() => undefined)).toBeUndefined();
			expect(await readdir(join(run.dir, '.pending'))).toEqual([]);
			await run.abandon();
		});

		test("a manifest whose sync comes back after the limit never lands, so the run's end stands", async () => {
			const t = await setup({ diskPollMs: 5 });
			const run = await t.store.openRun(RUN);
			const gate = new Gate();
			const isManifest = async (path: string) =>
				(await readFile(path, 'utf8')).includes('"finalizedAt"');
			const opens = holdingSync(gate, aTemporary, 'sync', isManifest);
			const finalizing = failure(run.finalize({ limitations: [] }));
			await gate.reached;
			opens.mockRestore();
			t.advance(DISK_WAIT_MS + 1_000);
			expect(await finalizing).toBeInstanceOf(EvidenceStuckError);
			gate.release();
			await Bun.sleep(30);
			expect(await t.store.readManifest(RUN)).toBeUndefined();
			await run.abandon();
			expect(await t.store.readManifest(RUN)).toBeUndefined();
		});

		test('a manifest that landed before the run gave up goes once the disk answers', async () => {
			const t = await setup({ diskPollMs: 5 });
			const run = await t.store.openRun(RUN);
			const gate = new Gate();
			const manifest = join(run.dir, 'manifest.json');
			// writeAtomic's sync of the directory, with the manifest renamed into place.
			const opens = holdingSync(
				gate,
				(path) => path === run.dir,
				'sync',
				() => existsSync(manifest),
			);
			const finalizing = failure(run.finalize({ limitations: [] }));
			await gate.reached;
			opens.mockRestore();
			expect(existsSync(manifest)).toBe(true);
			t.advance(DISK_WAIT_MS + 1_000);
			expect(await finalizing).toBeInstanceOf(EvidenceStuckError);
			gate.release();
			await eventually(() => !existsSync(manifest));
			await run.abandon();
			expect(await t.store.readManifest(RUN)).toBeUndefined();
		});

		test('abandon returns though the sync of the events never does', async () => {
			const t = await setup({ diskPollMs: 5 });
			const gate = new Gate();
			const opens = holdingSync(gate, eventsFile, 'datasync');
			const run = await t.store.openRun(RUN);
			opens.mockRestore();
			const abandoning = run.abandon();
			await gate.reached;
			t.advance(DISK_WAIT_MS + 1_000);
			await abandoning;
			expect(run.stuck).toBeInstanceOf(EvidenceStuckError);
			gate.release();
		});

		test('a slow disk gets the limit for each write, not for what waits in line', async () => {
			const t = await setup({ diskPollMs: 5 });
			const opens = openingWith((path, handle) => {
				if (!eventsFile(path)) return;
				const real = handle.datasync.bind(handle);
				spyOn(handle, 'datasync').mockImplementation(async () => {
					t.advance(DISK_WAIT_MS / 2);
					await Bun.sleep(15);
					return real();
				});
			});
			const run = await t.store.openRun(RUN);
			opens.mockRestore();
			await Promise.all(Array.from({ length: 5 }, () => run.appendEvent(event)));
			expect(run.stuck).toBeUndefined();
			expect(run.status.counts.events).toBe(5);
			await run.finalize({ limitations: [] });
		});
	});

	test('a manifest whose write fails after its rename does not stay behind', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const dir = t.store.runDir(RUN);
		let syncs = 0;
		const opens = openingWith((path, handle) => {
			if (path !== dir) return;
			const real = handle.sync.bind(handle);
			spyOn(handle, 'sync').mockImplementation(async () => {
				syncs += 1;
				// The first is the tree walk; the second is writeAtomic's, after the
				// manifest was renamed into place.
				if (syncs === 2) throw new Error('EIO: i/o error');
				return real();
			});
		});
		try {
			await expect(run.finalize({ limitations: [] })).rejects.toThrow('EIO');
		} finally {
			opens.mockRestore();
		}
		expect(syncs).toBe(2);
		expect(await t.store.readManifest(RUN)).toBeUndefined();
		// The events file closed on the way, so this run cannot finalize again.
		// It ends as a partial bundle, which the controller reports as such.
		await run.abandon();
		expect(await t.store.readManifest(RUN)).toBeUndefined();
	});

	test('an event line is the bytes a reader gets by parsing it and writing it again', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const event = { source: 'host', type: 'denied', pointId: 'hello.home', attempt: 1 } as const;
		await run.appendEvent({ ...event, url: 'http://example.com/', nested: { b: 1, a: [2] } });
		await run.appendEvent({ ...event, type: 'log', text: 'x'.repeat(20_000) });
		await run.abandon();
		const lines = (await readFile(join(t.store.runDir(RUN), 'events.ndjson'), 'utf8'))
			.trimEnd()
			.split('\n');
		expect(JSON.parse(lines[1] as string).type).toBe('oversized-event');
		for (const line of lines) {
			expect(JSON.stringify(EvidenceEventSchema.parse(JSON.parse(line)))).toBe(line);
		}
	});

	test('the digests are of the last thing written before finalize, and what it is given is in the manifest', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		await run.writeReport(() => 'first\n');
		await run.writeReport(() => 'second\n');
		await run.appendEvent({ source: 'host', type: 'late' });
		const manifest = await run.finalize({
			limitations: ['a limitation'],
			executionDigest: `sha256:${'e'.repeat(64)}`,
		});
		expect(manifest.limitations).toEqual(['a limitation']);
		expect(manifest.executionDigest).toBe(`sha256:${'e'.repeat(64)}`);
		expect(manifest.files['report.md']).toEqual({ sha256: sha('second\n'), bytes: 7 });
		expect(manifest.events.count).toBe(1);
		await expect(run.writeReport(() => 'third\n')).rejects.toThrow('is finalized');
	});

	test('a record of project text and koid values goes as it is, and no sanitizer sees it', async () => {
		const t = await setup();
		const seen: unknown[] = [];
		const sanitize: Sanitize = (record) => {
			seen.push(record);
			return record;
		};
		const plan = { profile: '[redacted]', uncovered: ['docs/redacted.md'] };
		const dir = t.store.planDir('p'.repeat(20));
		await t.store.writeDeclared(dir, 'plan.json', plan);
		expect(JSON.parse(await readFile(join(dir, 'plan.json'), 'utf8'))).toEqual(plan);
		const run = await t.store.openRun(RUN, { sanitize });
		await run.writeDeclared('execution.json', plan);
		const path = join(t.store.runDir(RUN), 'execution.json');
		expect(JSON.parse(await readFile(path, 'utf8'))).toEqual(plan);
		expect(seen).not.toContain(plan);
		// A record that carries runtime text has no way round it.
		await run.writeRecord('result.json', plan);
		expect(seen).toContain(plan);
		await run.abandon();
	});

	test('a write through the store takes the sanitizer it is given, and so does a writer', async () => {
		const t = await setup();
		const secret = 'koi-secret-value-1234567890';
		const sanitize = <T>(record: T) =>
			(typeof record === 'string'
				? record.replaceAll(secret, '[redacted]')
				: JSON.parse(JSON.stringify(record).replaceAll(secret, '[redacted]'))) as T;
		const dir = t.store.planDir('p'.repeat(20));
		await t.store.writeRecord(dir, 'planning.json', { note: secret }, sanitize);
		expect(await readFile(join(dir, 'planning.json'), 'utf8')).not.toContain(secret);
		const run = await t.store.openRun(RUN, { sanitize });
		await run.writeReport((clean) => clean(`# ${secret}\n`));
		await run.writeRecord('result.json', { reason: secret });
		await run.writeObservations('hello.home', { assertions: [secret] });
		await run.appendEvent({ source: 'host', type: 'note', note: secret });
		await run.addProblem('capture_failed', secret);
		const manifest = await run.finalize({ limitations: [secret] });
		expect(JSON.stringify(manifest)).not.toContain(secret);
		for (const name of await readdir(t.store.runDir(RUN), { recursive: true })) {
			const path = join(t.store.runDir(RUN), name);
			if (!(await stat(path)).isFile()) continue;
			expect(await readFile(path, 'utf8')).not.toContain(secret);
		}
	});

	test('a problem detail is scrubbed before it is kept and before it is cut', async () => {
		const secret = 'koi-secret-value-1234567890';
		const t = await setup({ scrub: (text) => text.replaceAll(secret, '[redacted]') });
		const run = await t.store.openRun(RUN);
		await run.addProblem('capture_failed', `screenshot ${secret}: failed`);
		await run.addProblem('capture_failed', `${'x'.repeat(1990)}${secret}`);
		const manifest = await run.finalize({ limitations: [] });
		const text = JSON.stringify(manifest);
		expect(text).toContain('screenshot [redacted]: failed');
		expect(text).not.toContain(secret);
		expect(text).not.toContain(secret.slice(0, 8));
	});

	test('a new store makes its own directories durable', async () => {
		const t = await setup();
		const order: string[] = [];
		const opens = openingWith((path, handle) => {
			const real = handle.sync.bind(handle);
			spyOn(handle, 'sync').mockImplementation(async () => {
				order.push(path);
				return real();
			});
		});
		try {
			await t.store.init();
		} finally {
			opens.mockRestore();
		}
		const root = dirname(t.store.runDir(RUN).replace(/\/runs\/.*$/, '/runs'));
		expect(order).toEqual([
			join(root, 'runs'),
			join(root, 'inputs'),
			join(root, 'plans'),
			root,
			dirname(root),
		]);
	});

	test('finalize writes the manifest last and closes the run', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const dir = t.store.runDir(RUN);
		await run.appendEvent({ source: 'host', type: 'recorder-ready' });
		const a = await entry(run);
		await run.writeReport(() => '# report\n');
		expect(await t.store.readManifest(RUN)).toBeUndefined();
		t.advance(60_000);
		const manifest = await run.finalize({
			planId: 'p'.repeat(20),
			planDigest: sha('plan'),
			limitations: ['sanitized means the stated policy ran'],
		});
		expect(
			EvidenceManifestSchema.parse(JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8'))),
		).toEqual(manifest);
		expect(manifest.status.state).toBe('completed');
		expect(manifest.status.finishedAt).toBe(t.now());
		expect(manifest.status.evidence).toBe('complete');
		expect(manifest.artifacts).toEqual([a]);
		const events = await readFile(join(dir, 'events.ndjson'));
		expect(manifest.events).toEqual({ count: 1, bytes: events.length, sha256: sha(events) });
		expect(Object.keys(manifest.files).sort()).toEqual(['report.md', 'status.json']);
		expect(manifest.files['report.md']?.sha256).toBe(sha('# report\n'));
		expect(manifest.retainedUntil).toBe(new Date(Date.parse(t.now()) + 30 * DAY).toISOString());
		expect(manifest.tombstoneUntil).toBe(new Date(Date.parse(t.now()) + 180 * DAY).toISOString());
		await expect(entry(run)).rejects.toThrow('finalized');
		await expect(run.appendEvent({ source: 'host', type: 'late' })).rejects.toThrow('finalized');
	});

	test('the status holds a thousand problems, the last a fixed one, and the run still finalizes', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		for (let i = 0; i < MAX_PROBLEMS + 5; i++)
			await run.addProblem('capture_failed', `problem ${i}`);
		expect(run.status.problems).toHaveLength(MAX_PROBLEMS);
		expect(run.status.problems[MAX_PROBLEMS - 2]).toMatchObject({
			code: 'capture_failed',
			detail: `problem ${MAX_PROBLEMS - 2}`,
		});
		expect(run.status.problems[MAX_PROBLEMS - 1]).toMatchObject(PROBLEMS_CAPPED);
		expect(run.status.evidence).toBe('incomplete');
		// On disk as well, and the manifest takes it.
		const status = await t.store.readStatus(RUN);
		expect(status?.problems).toHaveLength(MAX_PROBLEMS);
		const manifest = await run.finalize({ limitations: [] });
		expect(manifest.status.problems.at(-1)).toMatchObject(PROBLEMS_CAPPED);
		expect(manifest.status.evidence).toBe('incomplete');
		// Every problem is a durable status write.
	}, 120_000);

	test('the artifact count cap holds on every entry path, and never above what the manifest takes', async () => {
		const t = await setup({ limits: { artifactsPerRun: 2 } });
		const run = await t.store.openRun(RUN);
		// An entry the manifest schema refuses is recorded as failed: that
		// path counts too.
		await run.writeArtifact(
			{
				pointId: 'hello.home',
				attempt: 1,
				kind: 'aria',
				mediaType: 'not a media type',
				capturedAt: t.now(),
				eventRange: { first: 0, last: 0 },
				redaction,
			},
			new Uint8Array(1),
		);
		await entry(run);
		expect(run.artifacts).toHaveLength(2);
		await expect(entry(run)).rejects.toThrow('the most it may keep');
		await expect(
			run.recordArtifact({
				pointId: 'hello.home',
				attempt: 1,
				kind: 'trace',
				capturedAt: t.now(),
				eventRange: { first: 0, last: 0 },
				redaction: { ...redaction, status: 'failed', limitations: ['why'] },
			}),
		).rejects.toThrow('the most it may keep');
		expect(run.artifacts).toHaveLength(2);
		const manifest = await run.finalize({ limitations: [] });
		expect(manifest.artifacts).toHaveLength(2);
		expect(manifest.status.evidence).toBe('incomplete');
		// A cap above the manifest's bound is brought down to it.
		const u = await setup({ limits: { artifactsPerRun: EVIDENCE_LIMITS.artifactsPerRun + 1 } });
		expect(u.store.limits.artifactsPerRun).toBe(EVIDENCE_LIMITS.artifactsPerRun);
	});

	test('two writes that stream at once cannot both pass the count cap', async () => {
		const t = await setup({ limits: { artifactsPerRun: 1 } });
		const run = await t.store.openRun(RUN);
		const meta = {
			pointId: 'hello.home',
			attempt: 1,
			kind: 'aria' as const,
			mediaType: 'text/plain',
			capturedAt: t.now(),
			eventRange: { first: 0, last: 0 },
			redaction,
		};
		// Each body yields across a tick, so both writes are past their
		// first count check before either has an entry.
		const body = async function* () {
			await new Promise((resolve) => setTimeout(resolve, 5));
			yield new Uint8Array([1]);
		};
		const results = await Promise.allSettled([
			run.writeArtifact(meta, body()),
			run.writeArtifact(meta, body()),
		]);
		expect(results.map((r) => r.status).sort()).toEqual(['fulfilled', 'rejected']);
		const refused = results.find((r) => r.status === 'rejected');
		expect(refused?.status === 'rejected' && refused.reason).toBeInstanceOf(CapExceededError);
		expect(run.artifacts).toHaveLength(1);
		expect(await readdir(join(t.store.runDir(RUN), 'artifacts'))).toHaveLength(1);
		expect(await readdir(join(t.store.runDir(RUN), '.pending'))).toEqual([]);
		const manifest = await run.finalize({ limitations: [] });
		expect(manifest.artifacts).toHaveLength(1);
	});

	test('two writes that stream at once cannot together pass the byte cap', async () => {
		const t = await setup({ limits: { bytesPerRun: 10 } });
		const run = await t.store.openRun(RUN);
		const meta = {
			pointId: 'hello.home',
			attempt: 1,
			kind: 'aria' as const,
			mediaType: 'text/plain',
			capturedAt: t.now(),
			eventRange: { first: 0, last: 0 },
			redaction,
		};
		// Each body is 8 bytes: alone it fits under the cap of 10, the two
		// together do not. Both have 4 bytes in before the first asks for its
		// other 4, which the cap refuses. The second asks only once the first
		// has finished, its file gone, and gets the room the first gave back.
		let secondHasBytes = () => {};
		const bothHaveBytes = new Promise<void>((resolve) => {
			secondHasBytes = resolve;
		});
		const first = run.writeArtifact(
			meta,
			(async function* () {
				yield new Uint8Array(4);
				await bothHaveBytes;
				yield new Uint8Array(4);
			})(),
		);
		const firstFinished = first.catch(() => {});
		const second = run.writeArtifact(
			meta,
			(async function* () {
				yield new Uint8Array(4);
				secondHasBytes();
				await firstFinished;
				yield new Uint8Array(4);
			})(),
		);
		const results = await Promise.allSettled([first, second]);
		expect(results.map((r) => r.status)).toEqual(['rejected', 'fulfilled']);
		const refused = results.find((r) => r.status === 'rejected');
		const reason: unknown = refused?.status === 'rejected' ? refused.reason : undefined;
		expect(reason).toBeInstanceOf(CapExceededError);
		expect((reason as CapExceededError).cap).toBe('bytesPerRun');
		expect(run.artifacts).toHaveLength(1);
		expect(run.status.counts.bytes).toBe(8);
		expect(await readdir(join(t.store.runDir(RUN), 'artifacts'))).toHaveLength(1);
		expect(await readdir(join(t.store.runDir(RUN), '.pending'))).toEqual([]);
		expect(run.status.problems.map((p) => p.code)).toEqual(['cap_exceeded']);
		const manifest = await run.finalize({ limitations: [] });
		expect(manifest.status.evidence).toBe('incomplete');
		expect(manifest.status.counts.bytes).toBe(8);
		// A write that fails for another reason gives its reservation back:
		// the whole allowance is there for the next one.
		const u = await setup({ limits: { bytesPerRun: 10 } });
		const other = await u.store.openRun(RUN);
		const dropped = async function* () {
			yield new Uint8Array(6);
			throw new Error('the connection dropped');
		};
		await expect(other.writeArtifact(meta, dropped())).rejects.toThrow('the connection dropped');
		await other.writeArtifact(meta, new Uint8Array(10));
		expect(other.status.counts.bytes).toBe(10);
		expect(other.capped).toBeUndefined();
		await other.abandon();
	});

	test('two appends at once cannot both pass the event cap', async () => {
		const t = await setup({ limits: { eventsPerRun: 1 } });
		const run = await t.store.openRun(RUN);
		const results = await Promise.allSettled([
			run.appendEvent({ source: 'host', type: 'first' }),
			run.appendEvent({ source: 'host', type: 'second' }),
		]);
		expect(results.map((r) => r.status)).toEqual(['fulfilled', 'rejected']);
		const refused = results[1];
		const reason: unknown = refused?.status === 'rejected' ? refused.reason : undefined;
		expect(reason).toBeInstanceOf(CapExceededError);
		expect((reason as CapExceededError).cap).toBe('eventsPerRun');
		const lines = (await readFile(join(t.store.runDir(RUN), 'events.ndjson'), 'utf8'))
			.trimEnd()
			.split('\n');
		expect(lines.map((l) => JSON.parse(l).type)).toEqual(['first']);
		expect(run.status.counts.events).toBe(1);
		expect(run.status.problems.map((p) => p.code)).toEqual(['cap_exceeded']);
		const manifest = await run.finalize({ limitations: [] });
		expect(manifest.events.count).toBe(1);
		expect(manifest.status.evidence).toBe('incomplete');
	});

	test('an append that fails part way is cut out of the file, and the run says an event was lost', async () => {
		const t = await setup();
		let events: FileHandle | undefined;
		const opens = openingWith((path, handle) => {
			if (path.endsWith('events.ndjson')) events = handle;
		});
		try {
			const run = await t.store.openRun(RUN);
			const dir = t.store.runDir(RUN);
			const first = await run.appendEvent({ source: 'host', type: 'kept' });
			if (events === undefined) throw new Error('the events file was not opened');
			const real = events.write.bind(events);
			let calls = 0;
			// The first write takes five bytes of the line; the next fails, as
			// a full disk does part way through an event.
			const writes = spyOn(events, 'write').mockImplementation((async (
				buffer: Uint8Array,
				offset: number,
				length: number,
				position: number | null,
			) => {
				calls += 1;
				if (calls === 1) return real(buffer, offset, Math.min(5, length), position);
				throw new Error('ENOSPC: no space left on device');
			}) as typeof events.write);
			await expect(
				run.appendEvent({ source: 'host', type: 'lost', text: 'x'.repeat(100) }),
			).rejects.toThrow('ENOSPC');
			writes.mockRestore();
			expect(await readFile(join(dir, 'events.ndjson'), 'utf8')).toBe(`${JSON.stringify(first)}\n`);
			expect(run.status.counts.events).toBe(1);
			expect(run.status.evidence).toBe('incomplete');
			expect(run.status.problems.map((p) => [p.code, p.detail])).toEqual([
				['event_write_failed', 'event 2 was not written: ENOSPC: no space left on device'],
			]);
			// The next event takes the number the lost one would have had, so
			// the file counts up without a gap, and every line is one object.
			const next = await run.appendEvent({ source: 'host', type: 'after' });
			expect(next.seq).toBe(2);
			const manifest = await run.finalize({ limitations: [] });
			const lines = (await readFile(join(dir, 'events.ndjson'), 'utf8')).trimEnd().split('\n');
			expect(lines.map((l) => JSON.parse(l))).toEqual([first, next]);
			expect(manifest.events.count).toBe(2);
			expect(manifest.status.evidence).toBe('incomplete');
		} finally {
			opens.mockRestore();
		}
	});

	test('a directory sync that fails after the rename removes the file, so artifacts/ holds what the run counts', async () => {
		const t = await setup({ limits: { bytesPerRun: 10 } });
		const artifacts = join(t.store.runDir(RUN), 'artifacts');
		const opens = openingWith(failingSyncOf(artifacts));
		try {
			const run = await t.store.openRun(RUN);
			await expect(entry(run, 'screenshot', new Uint8Array(8))).rejects.toThrow('EIO');
			// No file and no count; the caller records the failure, as for
			// any write that fails.
			expect(await readdir(artifacts)).toEqual([]);
			expect(run.status.counts).toEqual({ events: 0, artifacts: 0, bytes: 0 });
			expect(run.status.problems).toEqual([]);
			// The bytes the write reserved came back: a write that fills the
			// cap is accepted, and the directory holds what the run counts.
			await entry(run, 'screenshot', new Uint8Array(10));
			expect(run.status.counts.bytes).toBe(10);
			expect(await bytesIn(artifacts)).toBe(10);
			await expect(entry(run, 'aria', new Uint8Array(1))).rejects.toThrow(
				'the most a run may keep',
			);
			const manifest = await run.finalize({ limitations: [] });
			expect(manifest.artifacts.map((a) => a.id)).toEqual(['recorder:screenshot:2']);
			expect(manifest.status.counts.bytes).toBe(10);
		} finally {
			opens.mockRestore();
		}
	});

	test('a published file that cannot be removed keeps its bytes under the cap and is a run problem', async () => {
		const t = await setup({ limits: { bytesPerRun: 10 } });
		const artifacts = join(t.store.runDir(RUN), 'artifacts');
		const opens = openingWith(failingSyncOf(artifacts));
		const removals = refusingRemoval(
			join(artifacts, 'recorder:screenshot:1'),
			'EBUSY: resource busy',
		);
		try {
			const run = await t.store.openRun(RUN);
			await expect(entry(run, 'screenshot', new Uint8Array(8))).rejects.toThrow('EIO');
			// The file is there and on no count, and the run says so.
			expect(await readdir(artifacts)).toEqual(['recorder:screenshot:1']);
			expect(run.status.counts).toEqual({ events: 0, artifacts: 0, bytes: 0 });
			expect(run.status.evidence).toBe('incomplete');
			expect(run.status.problems.map((p) => [p.code, p.detail])).toEqual([
				[
					'artifact_orphaned',
					"recorder:screenshot:1: its file is in artifacts/ but not on the run's count (EIO: i/o error), and removing it failed: EBUSY: resource busy",
				],
			]);
			// Its eight bytes stay under the cap of ten: two more fit, a
			// third does not.
			await entry(run, 'aria', new Uint8Array(2));
			expect(run.status.counts.bytes).toBe(2);
			expect(await bytesIn(artifacts)).toBe(10);
			await expect(entry(run, 'aria', new Uint8Array(1))).rejects.toThrow(
				'the most a run may keep',
			);
			const manifest = await run.finalize({ limitations: [] });
			expect(manifest.artifacts.map((a) => a.id)).toEqual(['recorder:aria:2']);
			expect(manifest.status.evidence).toBe('incomplete');
		} finally {
			removals.mockRestore();
			opens.mockRestore();
		}
	});

	// A failed rename leaves the file in .pending. Without the cleanup it held
	// bytes on disk that neither the count nor a reservation knew about.
	describe('an artifact that does not reach artifacts/', () => {
		const paths = (t: Awaited<ReturnType<typeof setup>>) => {
			const dir = t.store.runDir(RUN);
			return { artifacts: join(dir, 'artifacts'), pending: join(dir, '.pending') };
		};
		const meta = {
			pointId: 'hello.home',
			attempt: 1,
			kind: 'aria' as const,
			mediaType: 'text/plain',
			capturedAt: '2026-10-06T12:00:00.000Z',
			eventRange: { first: 0, last: 0 },
			redaction,
		};
		const orphaned = (id: string, cause: string) =>
			`${id}: its file is in .pending/ but not on the run's count (${cause}), and removing it failed: EBUSY: resource busy`;

		test('a rename that fails removes the pending file, so the bytes on disk match the count and the cap holds', async () => {
			const t = await setup({ limits: { bytesPerRun: 10 } });
			const { artifacts, pending } = paths(t);
			const renames = refusingRename((to) => to.startsWith(`${artifacts}/`), 'EIO: i/o error');
			try {
				const run = await t.store.openRun(RUN);
				// Each fits under the cap alone. Left behind, three would pass it.
				for (let i = 0; i < 3; i += 1) {
					await expect(entry(run, 'screenshot', new Uint8Array(8))).rejects.toThrow('EIO');
				}
				expect(await readdir(pending)).toEqual([]);
				expect(await readdir(artifacts)).toEqual([]);
				expect(run.status.counts).toEqual({ events: 0, artifacts: 0, bytes: 0 });
				// As for any write that fails, the caller records the failure.
				expect(run.status.problems).toEqual([]);
				renames.mockRestore();
				// The bytes came back: a write that fills the cap is accepted, and
				// nothing passes it after that.
				await entry(run, 'screenshot', new Uint8Array(10));
				expect(run.status.counts.bytes).toBe(10);
				expect((await bytesIn(pending)) + (await bytesIn(artifacts))).toBe(10);
				await expect(entry(run, 'aria', new Uint8Array(1))).rejects.toThrow(
					'the most a run may keep',
				);
				const manifest = await run.finalize({ limitations: [] });
				expect(manifest.artifacts.map((a) => a.id)).toEqual(['recorder:screenshot:4']);
				expect(manifest.status.counts.bytes).toBe(10);
			} finally {
				renames.mockRestore();
			}
		});

		test('a failed rename whose pending file cannot be removed keeps its bytes under the cap and is a run problem', async () => {
			const t = await setup({ limits: { bytesPerRun: 10 } });
			const { artifacts, pending } = paths(t);
			const renames = refusingRename((to) => to.startsWith(`${artifacts}/`), 'EIO: i/o error');
			const removals = refusingRemoval(
				(target) => target.startsWith(`${pending}/`),
				'EBUSY: resource busy',
			);
			try {
				const run = await t.store.openRun(RUN);
				await expect(entry(run, 'screenshot', new Uint8Array(8))).rejects.toThrow('EIO');
				renames.mockRestore();
				removals.mockRestore();
				expect(await bytesIn(pending)).toBe(8);
				expect(run.status.counts).toEqual({ events: 0, artifacts: 0, bytes: 0 });
				expect(run.status.evidence).toBe('incomplete');
				expect(run.status.problems.map((p) => [p.code, p.detail])).toEqual([
					['artifact_orphaned', orphaned('recorder:screenshot:1', 'EIO: i/o error')],
				]);
				// Its eight bytes stay under the cap of ten: two more fit, a third
				// does not.
				await entry(run, 'aria', new Uint8Array(2));
				expect(run.status.counts.bytes).toBe(2);
				expect((await bytesIn(pending)) + (await bytesIn(artifacts))).toBe(10);
				await expect(entry(run, 'aria', new Uint8Array(1))).rejects.toThrow(
					'the most a run may keep',
				);
				const manifest = await run.finalize({ limitations: [] });
				expect(manifest.artifacts.map((a) => a.id)).toEqual(['recorder:aria:2']);
				expect(manifest.status.evidence).toBe('incomplete');
			} finally {
				removals.mockRestore();
				renames.mockRestore();
			}
		});

		// For openingWith: the close of an artifact's file in .pending fails, as
		// a close that reports a deferred write error does. The descriptor is
		// released all the same, as it is on Linux.
		const failingClose = (pending: string) => (path: string, handle: FileHandle) => {
			if (!path.startsWith(`${pending}/`) || !path.endsWith('.part')) return;
			const close = handle.close.bind(handle);
			spyOn(handle, 'close').mockImplementation(async () => {
				await close();
				throw new Error('EIO: i/o error');
			});
		};

		test('a close that fails removes the pending file and gives its bytes back', async () => {
			const t = await setup({ limits: { bytesPerRun: 10 } });
			const { artifacts, pending } = paths(t);
			const run = await t.store.openRun(RUN);
			const opens = openingWith(failingClose(pending));
			try {
				await expect(run.writeArtifact(meta, new Uint8Array(8))).rejects.toThrow('EIO');
			} finally {
				opens.mockRestore();
			}
			expect(await readdir(pending)).toEqual([]);
			expect(await readdir(artifacts)).toEqual([]);
			expect(run.status.counts.bytes).toBe(0);
			// As for any write that fails, the caller records the failure.
			expect(run.status.problems).toEqual([]);
			await run.writeArtifact(meta, new Uint8Array(10));
			expect(run.status.counts.bytes).toBe(10);
			await run.abandon();
		});

		// Given back here, the bytes went to the next write: 8 bytes in .pending
		// and a 10-byte artifact under a cap of 10.
		test('a close that fails and a file that cannot be removed keep the bytes under the cap', async () => {
			const t = await setup({ limits: { bytesPerRun: 10 } });
			const { artifacts, pending } = paths(t);
			const run = await t.store.openRun(RUN);
			const opens = openingWith(failingClose(pending));
			const removals = refusingRemoval(
				(target) => target.startsWith(`${pending}/`),
				'EBUSY: resource busy',
			);
			try {
				await expect(run.writeArtifact(meta, new Uint8Array(8))).rejects.toThrow('EIO');
			} finally {
				removals.mockRestore();
				opens.mockRestore();
			}
			expect(await bytesIn(pending)).toBe(8);
			expect(run.status.problems.map((p) => [p.code, p.detail])).toEqual([
				['artifact_orphaned', orphaned('recorder:aria:1', 'EIO: i/o error')],
			]);
			await expect(run.writeArtifact(meta, new Uint8Array(10))).rejects.toThrow(
				'the most a run may keep',
			);
			expect(await bytesIn(pending)).toBe(8);
			expect(await readdir(artifacts)).toEqual([]);
			expect(run.status.counts.bytes).toBe(0);
			await run.abandon();
		});

		// The other ways out of writeArtifact remove the pending file too, and
		// a removal that fails must not lose the bytes or the first error.
		test('a stream that fails and cannot be removed keeps its bytes and its own error', async () => {
			const t = await setup({ limits: { bytesPerRun: 10 } });
			const { pending } = paths(t);
			const run = await t.store.openRun(RUN);
			const dropped = async function* () {
				yield new Uint8Array(8);
				throw new Error('the connection dropped');
			};
			const removals = refusingRemoval(
				(target) => target.startsWith(`${pending}/`),
				'EBUSY: resource busy',
			);
			try {
				await expect(run.writeArtifact(meta, dropped())).rejects.toThrow('the connection dropped');
			} finally {
				removals.mockRestore();
			}
			expect(await bytesIn(pending)).toBe(8);
			expect(run.status.problems.map((p) => [p.code, p.detail])).toEqual([
				['artifact_orphaned', orphaned('recorder:aria:1', 'the connection dropped')],
			]);
			await run.writeArtifact(meta, new Uint8Array(2));
			await expect(run.writeArtifact(meta, new Uint8Array(1))).rejects.toThrow(
				'the most a run may keep',
			);
			await run.abandon();
		});

		// Given back before the removal failed, the allowance went to the second
		// write: an 8-byte orphan and a 10-byte artifact under a cap of 10.
		test('a failed stream holds its bytes while its file is being removed', async () => {
			const t = await setup({ limits: { bytesPerRun: 10 } });
			const { artifacts, pending } = paths(t);
			const run = await t.store.openRun(RUN);
			const dropped = async function* () {
				yield new Uint8Array(8);
				throw new Error('the connection dropped');
			};
			const removal = holdingRemoval((target) => target.startsWith(`${pending}/`));
			try {
				const failing = run.writeArtifact(meta, dropped());
				await removal.reached;
				await expect(run.writeArtifact(meta, new Uint8Array(10))).rejects.toThrow(
					'the most a run may keep',
				);
				removal.finish('EBUSY: resource busy');
				// Only now: bun's expect blocks until the promise it is given settles.
				await expect(failing).rejects.toThrow('the connection dropped');
			} finally {
				removal.finish();
				removal.spy.mockRestore();
			}
			expect(await bytesIn(pending)).toBe(8);
			expect(await readdir(artifacts)).toEqual([]);
			expect(run.status.counts.bytes).toBe(0);
			expect(run.status.problems.map((p) => p.code)).toEqual(['cap_exceeded', 'artifact_orphaned']);
			await run.abandon();
		});

		test('a stream over the cap that cannot be removed still reaches the cap', async () => {
			const t = await setup({ limits: { bytesPerRun: 10 } });
			const { pending } = paths(t);
			const run = await t.store.openRun(RUN);
			const tooLong = async function* () {
				yield new Uint8Array(8);
				yield new Uint8Array(8);
			};
			const removals = refusingRemoval(
				(target) => target.startsWith(`${pending}/`),
				'EBUSY: resource busy',
			);
			try {
				await expect(run.writeArtifact(meta, tooLong())).rejects.toBeInstanceOf(CapExceededError);
			} finally {
				removals.mockRestore();
			}
			expect(await bytesIn(pending)).toBe(8);
			expect(run.capped?.cap).toBe('bytesPerRun');
			expect(run.status.problems.map((p) => p.code)).toEqual(['artifact_orphaned', 'cap_exceeded']);
			await run.abandon();
		});

		test('a write refused a place in the manifest that cannot be removed keeps its bytes', async () => {
			const t = await setup({ limits: { artifactsPerRun: 1, bytesPerRun: 10 } });
			const { pending } = paths(t);
			const run = await t.store.openRun(RUN);
			// Each body yields across a tick, so both writes are past their
			// first count check before either has an entry. Only the refused
			// write removes a file, so the refused removal below hits that one.
			const body = async function* () {
				await new Promise((resolve) => setTimeout(resolve, 5));
				yield new Uint8Array(4);
			};
			const removals = refusingRemoval(
				(target) => target.startsWith(`${pending}/`),
				'EBUSY: resource busy',
			);
			try {
				const results = await Promise.allSettled([
					run.writeArtifact(meta, body()),
					run.writeArtifact(meta, body()),
				]);
				expect(results.map((r) => r.status).sort()).toEqual(['fulfilled', 'rejected']);
			} finally {
				removals.mockRestore();
			}
			expect(await bytesIn(pending)).toBe(4);
			expect(run.capped?.cap).toBe('artifactsPerRun');
			expect(run.status.problems.map((p) => p.code)).toEqual(['artifact_orphaned', 'cap_exceeded']);
			await run.abandon();
		});

		test('an invalid entry whose file cannot be removed keeps its bytes and still gets its entry', async () => {
			const t = await setup({ limits: { bytesPerRun: 10 } });
			const { pending } = paths(t);
			const run = await t.store.openRun(RUN);
			const removals = refusingRemoval(
				(target) => target.startsWith(`${pending}/`),
				'EBUSY: resource busy',
			);
			let invalid: Awaited<ReturnType<RunWriter['writeArtifact']>>;
			try {
				invalid = await run.writeArtifact(
					{ ...meta, mediaType: 'not a media type' },
					new Uint8Array(8),
				);
			} finally {
				removals.mockRestore();
			}
			expect(invalid.availability).toBe('failed');
			expect(await bytesIn(pending)).toBe(8);
			expect(run.status.problems.map((p) => p.code)).toEqual([
				'artifact_orphaned',
				'artifact_invalid',
			]);
			await run.writeArtifact(meta, new Uint8Array(2));
			await expect(run.writeArtifact(meta, new Uint8Array(1))).rejects.toThrow(
				'the most a run may keep',
			);
			await run.abandon();
		});
	});

	test('a problem makes the evidence incomplete in the manifest', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		await run.addProblem('observation_gap', 'the recorder dropped 3 events');
		await run.setState('failed');
		const manifest = await run.finalize({ limitations: [] });
		expect(manifest.status.state).toBe('failed');
		expect(manifest.status.evidence).toBe('incomplete');
		expect(manifest.status.problems[0]?.code).toBe('observation_gap');
	});
});

describe('resolveEvidence', () => {
	const encode = (text: string) => new TextEncoder().encode(text);

	// A run with `count` screenshots, and what each file on disk is called.
	async function withArtifacts(count: number) {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		const entries = [];
		for (let i = 0; i < count; i++)
			entries.push(await entry(run, 'screenshot', encode('png bytes')));
		const file = (id: string) => join(t.store.runDir(RUN), 'artifacts', id);
		return { t, run, entries, file };
	}

	test('says what each file on disk is against its entry, with the redaction status', async () => {
		const { run, entries, file } = await withArtifacts(5);
		const [intact, sameSize, otherSize, gone, linked] = entries.map((e) => e.id) as [
			string,
			string,
			string,
			string,
			string,
		];
		await writeFile(file(sameSize), encode('PNG BYTES'));
		await writeFile(file(otherSize), encode('png bytes and more'));
		await rm(file(gone));
		await rm(file(linked));
		await symlink(file(intact), file(linked));
		const withheld = await run.recordArtifact({
			pointId: 'hello.home',
			attempt: 1,
			kind: 'trace',
			capturedAt: '2026-10-06T12:00:00.000Z',
			eventRange: { first: 0, last: 0 },
			redaction: { ...redaction, status: 'withheld', limitations: ['traces are withheld'] },
		});
		const resolve = await run.resolveEvidence([
			intact,
			sameSize,
			otherSize,
			gone,
			linked,
			withheld.id,
			'recorder:screenshot:99',
		]);
		const of = (id: string) => [resolve(id)?.integrity, resolve(id)?.redaction];
		expect(of(intact)).toEqual(['verified', 'sanitized']);
		// The same size with other bytes: only the hash can tell.
		expect(of(sameSize)).toEqual(['corrupt', 'sanitized']);
		expect(of(otherSize)).toEqual(['corrupt', 'sanitized']);
		expect(of(gone)).toEqual(['missing', 'sanitized']);
		// A symlink is not the file the run wrote, whatever it points at.
		expect(of(linked)).toEqual(['corrupt', 'sanitized']);
		expect(of(withheld.id)).toEqual(['missing', 'withheld']);
		expect(resolve(withheld.id)?.availability).toBe('withheld');
		expect(resolve('recorder:screenshot:99')).toBeUndefined();
		await run.abandon();
	});

	test('a claimed pass stands only on bytes that are still the ones the run recorded', async () => {
		const { run, entries, file } = await withArtifacts(1);
		const id = entries[0]?.id as string;
		const judged = (resolve: EvidenceLookup) =>
			judgePoint({
				id: 'hello.home',
				assertions: [{ name: 'home', evidence: ['screenshot'] }],
				reports: [{ name: 'home', outcome: 'pass', evidence: [id] }],
				resolve,
			});
		expect(judged(await run.resolveEvidence([id])).outcome).toBe('pass');
		await writeFile(file(id), encode('PNG BYTES'));
		const tampered = judged(await run.resolveEvidence([id]));
		expect(tampered.outcome).toBe('fail');
		expect(tampered.reasons).toContain(
			`corrupt_evidence: home references ${id}, whose bytes do not hash to the manifest`,
		);
		await rm(file(id));
		const gone = judged(await run.resolveEvidence([id]));
		expect(gone.outcome).toBe('fail');
		expect(gone.reasons).toContain(
			`missing_evidence: home references ${id}, whose bytes are not on disk`,
		);
		await run.abandon();
	});

	test('the lookup works from the entries alone, as a reader of a finished run has them', async () => {
		const { t, run, entries } = await withArtifacts(1);
		const id = entries[0]?.id as string;
		const resolve = await resolveArtifacts(t.store.runDir(RUN), run.artifacts, [id]);
		expect(resolve(id)?.integrity).toBe('verified');
		await run.abandon();
	});
});

describe('sweep', () => {
	async function finalized(t: Awaited<ReturnType<typeof setup>>, runId: string) {
		const run = await t.store.openRun(runId);
		await entry(run);
		await run.writeRecord('result.json', {});
		await run.writeRecord('controller.json', {});
		return run.finalize({ limitations: [] });
	}

	test('expires a run after 30 days to a tombstone with its manifest, and removes it after 180', async () => {
		const t = await setup();
		const manifest = await finalized(t, RUN);
		const dir = t.store.runDir(RUN);
		t.advance(29 * DAY);
		expect(await t.store.sweep()).toEqual({
			expired: [],
			removed: [],
			inputs: [],
			pendingInputs: [],
			plans: [],
		});
		t.advance(2 * DAY);
		expect((await t.store.sweep()).expired).toEqual([RUN]);
		// The controller's record stays with the manifest: the run's verdict
		// is still readable once its evidence has gone.
		expect((await readdir(dir)).sort()).toEqual([
			'controller.json',
			'manifest.json',
			'status.json',
			'tombstone.json',
		]);
		const tombstone = EvidenceTombstoneSchema.parse(
			JSON.parse(await readFile(join(dir, 'tombstone.json'), 'utf8')),
		);
		expect(tombstone.manifestSha256).toBe(sha(await readFile(join(dir, 'manifest.json'))));
		expect(tombstone.tombstoneUntil).toBe(manifest.tombstoneUntil);
		expect((await t.store.sweep()).expired).toEqual([]);
		t.advance(150 * DAY);
		expect((await t.store.sweep()).removed).toEqual([RUN]);
		expect(await readdir(join(t.store.root, 'runs'))).toEqual([]);
	});

	test('an expiry interrupted after its tombstone is finished by the next sweep', async () => {
		const t = await setup();
		await finalized(t, RUN);
		const dir = t.store.runDir(RUN);
		t.advance(31 * DAY);
		expect((await t.store.sweep()).expired).toEqual([RUN]);
		// As if the crash came between the tombstone and the removal: the
		// evidence is back beside the tombstone.
		await mkdir(join(dir, 'artifacts'), { recursive: true, mode: 0o700 });
		await writeFile(join(dir, 'artifacts', 'recorder:screenshot:1'), 'bytes');
		await writeFile(join(dir, 'events.ndjson'), '{}\n');
		await writeFile(join(dir, 'result.json'), '{}\n');
		const before = await readFile(join(dir, 'tombstone.json'), 'utf8');
		expect((await t.store.sweep()).expired).toEqual([RUN]);
		expect((await readdir(dir)).sort()).toEqual([
			'controller.json',
			'manifest.json',
			'status.json',
			'tombstone.json',
		]);
		expect(await readFile(join(dir, 'tombstone.json'), 'utf8')).toBe(before);
		expect(t.logs).toContain(`finishing the interrupted expiry of run ${RUN}`);
		expect((await t.store.sweep()).expired).toEqual([]);
	});

	test('a pin keeps the evidence for 90 days', async () => {
		const t = await setup();
		await finalized(t, RUN);
		await t.store.pin(RUN);
		t.advance(31 * DAY);
		expect((await t.store.sweep()).expired).toEqual([]);
		t.advance(60 * DAY);
		expect((await t.store.sweep()).expired).toEqual([RUN]);
		expect(EVIDENCE_RETENTION.pinnedDays).toBe(90);
	});

	test('removes a run that never finalized, an input snapshot and a plan past their time', async () => {
		const t = await setup();
		const run = await t.store.openRun(RUN);
		await entry(run);
		await run.abandon();
		const inputs = t.store.inputsDir('d'.repeat(20));
		await mkdir(inputs, { recursive: true, mode: 0o700 });
		await writeFile(join(inputs, 'snapshot.json'), JSON.stringify({ takenAt: t.now() }));
		const plan = join(t.store.root, 'plans', 'p'.repeat(20));
		await mkdir(plan, { recursive: true, mode: 0o700 });
		// A plan has no record of its own time yet; the sweep reads the
		// directory's, which the test's clock does not move.
		await utimes(plan, new Date(t.now()), new Date(t.now()));
		t.advance(31 * DAY);
		const swept = await t.store.sweep();
		expect(swept.removed).toEqual([RUN]);
		expect(swept.inputs).toEqual(['d'.repeat(20)]);
		expect(swept.plans).toEqual([]);
		t.advance(150 * DAY);
		expect((await t.store.sweep()).plans).toEqual(['p'.repeat(20)]);
	});

	describe('a snapshot koid was killed while copying', () => {
		const DEPLOYMENT = 'd'.repeat(20);
		const MINUTE = 60_000;

		async function leftBehind(t: Awaited<ReturnType<typeof setup>>, deploymentId = DEPLOYMENT) {
			const name = `.pending-${deploymentId}`;
			const dir = join(t.store.root, 'inputs', name);
			await mkdir(join(dir, 'source'), { recursive: true, mode: 0o700 });
			await writeFile(join(dir, 'source', 'half-copied'), 'bytes');
			// The sweep reads the directory's time, which the test's clock does
			// not move.
			await utimes(dir, new Date(t.now()), new Date(t.now()));
			return name;
		}

		test('goes after an hour, and a finished snapshot beside it stays', async () => {
			const t = await setup();
			const name = await leftBehind(t);
			const finished = t.store.inputsDir('e'.repeat(20));
			await mkdir(finished, { recursive: true, mode: 0o700 });
			await writeFile(join(finished, 'snapshot.json'), JSON.stringify({ takenAt: t.now() }));
			const inputs = join(t.store.root, 'inputs');
			// Younger than an hour, it may still be a snapshot in progress.
			t.advance(59 * MINUTE);
			expect((await t.store.sweep()).pendingInputs).toEqual([]);
			expect((await readdir(inputs)).sort()).toEqual([name, 'e'.repeat(20)]);
			t.advance(MINUTE);
			const swept = await t.store.sweep();
			expect(swept.pendingInputs).toEqual([DEPLOYMENT]);
			expect(swept.inputs).toEqual([]);
			expect(await readdir(inputs)).toEqual(['e'.repeat(20)]);
		});

		test('one that cannot be removed is logged, and the sweep goes on', async () => {
			const t = await setup();
			const stuck = await leftBehind(t);
			await leftBehind(t, 'f'.repeat(20));
			t.advance(60 * MINUTE);
			const stuckDir = join(t.store.root, 'inputs', stuck);
			const removals = refusingRemoval(stuckDir, 'EBUSY: resource busy');
			try {
				expect((await t.store.sweep()).pendingInputs).toEqual(['f'.repeat(20)]);
			} finally {
				removals.mockRestore();
			}
			expect(t.logs).toContain(`sweeping ${stuck}: EBUSY: resource busy`);
			expect((await t.store.sweep()).pendingInputs).toEqual([DEPLOYMENT]);
		});
	});
});
