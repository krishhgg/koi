import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, open, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	type ArtifactChunk,
	CTL_EXIT,
	type EvidenceExport,
	EvidenceExportSchema,
	type EvidenceReply,
	EvidenceReplySchema,
	type PlanReply,
	PlanReplySchema,
	type RunAccepted,
	type RunEventsPage,
	type RunStatusReply,
} from '@koi/shared';
import { USAGE } from '../src/args.ts';
import { type Box, BoxUnavailableError, type CtlResult } from '../src/box.ts';
import { type Runtime, run } from '../src/main.ts';
import type { HealthAnswer } from '../src/up.ts';
import {
	exportEvidence,
	FOLLOW_MARGIN_MS,
	formatExport,
	formatPlan,
	formatStatus,
	type OpenExportFile,
	VERIFY_POLL_MS,
	type VerifyDeps,
} from '../src/verify.ts';

const PLAN = 'p'.repeat(20);
const RUN = 'r'.repeat(20);
const DIGEST = `sha256:${'1'.repeat(64)}`;
const sha = (bytes: Uint8Array | string) =>
	`sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const deployment = {
	label: 'hello-pr-7',
	deploymentId: 'd'.repeat(20),
	imageDigest: `sha256:${'2'.repeat(64)}`,
	commit: 'c'.repeat(40),
	merge: { head: '3'.repeat(40), base: '4'.repeat(40), baseBranch: 'main' },
};

const limits = { runSeconds: 600, pointSeconds: 300, runRequests: 50, pointRequests: 20 };

function plan(over: Partial<PlanReply> = {}): PlanReply {
	return {
		version: 1,
		planId: PLAN,
		planDigest: DIGEST,
		label: 'hello-pr-7',
		deployment,
		profile: 'pr',
		advisory: false,
		counts: { selected: 2, blocked: 1, uncovered: 1, required: 1 },
		policy: {
			source: 'none',
			advisory: { path: '.koi/required.yaml', required: [{ id: 'hello.home', revision: 2 }] },
		},
		limits,
		runnerImage: 'curlimages/curl:8.11.1',
		originMode: 'private-app',
		notes: ['the verifier does not exist yet'],
		points: [
			{
				id: 'hello.home',
				revision: 2,
				why: 'always: listed by profile pr',
				proof: 'unverified',
				required: true,
			},
		],
		blocked: [],
		uncovered: [],
		createdAt: '2026-10-06T12:00:00.000Z',
		...over,
	};
}

const accepted: RunAccepted = {
	version: 1,
	runId: RUN,
	planId: PLAN,
	planDigest: DIGEST,
	deployment,
	state: 'running',
	leaseExpiresAt: '2026-10-06T12:12:00.000Z',
	limits,
	startedAt: '2026-10-06T12:00:00.000Z',
};

function status(over: Partial<RunStatusReply> = {}): RunStatusReply {
	return {
		version: 1,
		runId: RUN,
		planId: PLAN,
		planDigest: DIGEST,
		label: 'hello-pr-7',
		deployment,
		profile: 'pr',
		advisory: false,
		state: 'running',
		cancelRequested: false,
		readiness: { eligibleForMergeGate: false, reasons: ['the run is not finished'] },
		freshness: 'current',
		evidence: 'collecting',
		finalized: false,
		cleanup: 'unknown',
		limits,
		leaseExpiresAt: accepted.leaseExpiresAt,
		progress: { total: 2, done: 0 },
		points: [
			{ id: 'hello.home', state: 'running', evidence: [] },
			{ id: 'app.search', state: 'pending', evidence: [] },
		],
		problems: [],
		problemCount: 0,
		startedAt: accepted.startedAt,
		...over,
	};
}

const finished = status({
	state: 'completed',
	completion: 'evaluated',
	outcome: 'incomplete',
	evidence: 'complete',
	finalized: true,
	cleanup: 'succeeded',
	readiness: { eligibleForMergeGate: false, reasons: ['the run incomplete'] },
	progress: { total: 2, done: 2 },
	points: [
		{
			id: 'hello.home',
			state: 'done',
			outcome: 'blocked',
			reason: 'verifier_unavailable: nothing ran',
			evidence: ['recorder:screenshot:1', 'recorder:aria:2'],
		},
		{
			id: 'app.search',
			state: 'done',
			outcome: 'blocked',
			reason: 'verifier_unavailable',
			evidence: [],
		},
	],
	finishedAt: '2026-10-06T12:01:00.000Z',
});

const ok = (value: unknown): CtlResult => ({ code: 0, stdout: JSON.stringify(value), stderr: '' });
const refused = (status: number, code: string, message: string): CtlResult => ({
	code: 1,
	stdout: '',
	stderr: JSON.stringify({ version: 1, error: { code, message, retryable: status >= 500 } }),
});

type Handler = (args: string[], count: number) => CtlResult | Promise<CtlResult>;

// A box whose koid ctl verify answers come from `handle`, given the ctl
// arguments and how many calls came before. Health answers 200 unless told
// otherwise, so the preview is running.
function verifyRuntime(
	handle: Handler,
	options: { health?: HealthAnswer[] } = {},
): Runtime & { calls: string[][]; events: string[]; now: () => Date } {
	const calls: string[][] = [];
	const events: string[] = [];
	const health = options.health ?? [{ status: 200 }];
	let probed = 0;
	let clock = Date.parse('2026-10-06T12:00:00.000Z');
	const box: Box = {
		upload: async () => {},
		ensureAwake: async () => {
			events.push('awake');
		},
		ctl: async (args) => {
			calls.push(args);
			events.push(`ctl ${args.slice(0, 2).join(' ')}`);
			return handle(args, calls.length - 1);
		},
	};
	return {
		cwd: '/nonexistent',
		box: async () => ({ box, domain: 'previews.example.net' }),
		probe: async (url) => {
			probed += 1;
			events.push(`probe ${url}`);
			return health[Math.min(probed, health.length) - 1] ?? { status: 200 };
		},
		sleep: async (ms) => {
			clock += ms;
		},
		now: () => new Date(clock),
		calls,
		events,
	};
}

async function capture(argv: string[], runtime: Runtime) {
	let stdout = '';
	let stderr = '';
	const code = await run(
		argv,
		{
			stdout: (s) => {
				stdout += s;
			},
			stderr: (s) => {
				stderr += s;
			},
		},
		runtime,
	);
	return { code, stdout, stderr };
}

describe('koi verify plan', () => {
	test('reads every page of the plan and prints it, or JSON with --json', async () => {
		const runtime = verifyRuntime((args) => {
			if (args[1] === 'plan') return ok(plan({ next: 'blocked:0', truncated: ['notes'] }));
			if (args[1] === 'plan-page' && args[3] === 'blocked:0') {
				return ok(
					plan({
						points: [],
						blocked: [{ id: 'app.llm', reason: 'capability_missing:provider:anthropic' }],
						uncovered: ['README.md'],
						truncated: ['blocked[app.llm].reason', 'notes'],
					}),
				);
			}
			return refused(404, 'not_found', 'no');
		});
		const json = await capture(['verify', 'plan', 'hello-pr-7', '--json'], runtime);
		expect(json.code).toBe(0);
		expect(json.stderr).toBe('');
		expect(runtime.calls).toEqual([
			['verify', 'plan', 'hello-pr-7', '--profile', 'pr'],
			['verify', 'plan-page', PLAN, 'blocked:0'],
		]);
		const merged = PlanReplySchema.parse(JSON.parse(json.stdout));
		expect(merged.points.map((p) => p.id)).toEqual(['hello.home']);
		expect(merged.blocked.map((b) => b.id)).toEqual(['app.llm']);
		expect(merged.uncovered).toEqual(['README.md']);
		expect(merged.next).toBeUndefined();
		// What any page said it cut, the whole says it cut, once each.
		expect(merged.truncated).toEqual(['notes', 'blocked[app.llm].reason']);
		const text = await capture(['verify', 'plan', 'hello-pr-7', '--profile', 'nightly'], runtime);
		expect(text.code).toBe(0);
		expect(runtime.calls.at(-2)).toEqual(['verify', 'plan', 'hello-pr-7', '--profile', 'nightly']);
		expect(text.stdout).toContain(`plan ${PLAN} for hello-pr-7 (profile pr)`);
		expect(text.stdout).toContain(
			'hello.home  r2  always: listed by profile pr  [required]  (proof unverified)',
		);
		expect(text.stdout).toContain('app.llm  capability_missing:provider:anthropic');
		expect(text.stdout).toContain('uncovered changes (1):\n  README.md');
		expect(text.stdout).toContain('notes:\n  the verifier does not exist yet');
	});

	test('reports a refusal with its code and exits 1', async () => {
		const runtime = verifyRuntime(() =>
			refused(409, 'inputs_missing', 'the verification inputs were not kept'),
		);
		const r = await capture(['verify', 'plan', 'hello-pr-7'], runtime);
		expect(r).toEqual({
			code: 1,
			stdout: '',
			stderr: 'koi: the verification inputs were not kept (inputs_missing)\n',
		});
	});
});

describe('koi verify run', () => {
	// koid answers a run: the plan, the acceptance, then `statuses` in order,
	// the last repeating.
	function running(statuses: RunStatusReply[]): Handler {
		let polls = 0;
		return (args) => {
			switch (args[1]) {
				case 'plan':
					return ok(plan());
				case 'run':
					return ok(accepted);
				case 'status': {
					const reply = statuses[Math.min(polls, statuses.length - 1)] as RunStatusReply;
					polls += 1;
					return ok(reply);
				}
				default:
					return refused(404, 'not_found', `unexpected ${args[1]}`);
			}
		};
	}

	test('wakes the preview, plans, starts, follows the status, and exits 1 for an incomplete run', async () => {
		const runtime = verifyRuntime(running([status(), status(), finished]), {
			health: [{ status: 503 }, { status: 200 }],
		});
		const r = await capture(['verify', 'run', 'hello-pr-7', '--profile', 'pr', '--json'], runtime);
		expect(r.code).toBe(1);
		expect(runtime.events.slice(0, 5)).toEqual([
			'awake',
			'probe https://hello-pr-7.previews.example.net/__koi/health',
			'probe https://hello-pr-7.previews.example.net/__koi/health',
			'ctl verify plan',
			'ctl verify run',
		]);
		expect(runtime.calls[1]).toEqual(['verify', 'run', PLAN, DIGEST]);
		expect(runtime.calls.filter((c) => c[1] === 'status')).toHaveLength(3);
		const report = JSON.parse(r.stdout);
		expect(report.version).toBe(1);
		expect(report.plan.planId).toBe(PLAN);
		expect(report.accepted).toEqual(accepted);
		expect(report.run).toEqual(finished);
		expect(r.stderr).toContain('koi  waking hello-pr-7\n');
		expect(r.stderr).toContain(
			`koi  plan ${PLAN}: 2 point(s) selected, 1 blocked, 1 uncovered change(s)\n`,
		);
		expect(r.stderr).toContain('koi  note: the verifier does not exist yet\n');
		expect(r.stderr).toContain(`koi  run ${RUN} started; lease until 2026-10-06T12:12:00.000Z\n`);
		expect(r.stderr).toContain('koi  hello.home: blocked\n');
		expect(r.stderr).toContain('koi  app.search: blocked\n');
	});

	test('exits 0 only for an evaluated run that passed, and prints the summary', async () => {
		const passed = status({
			...finished,
			outcome: 'passed',
			points: [
				{ id: 'hello.home', state: 'done', outcome: 'pass', evidence: ['recorder:screenshot:1'] },
			],
			progress: { total: 1, done: 1 },
		});
		const runtime = verifyRuntime(running([passed]));
		const r = await capture(['verify', 'run', 'hello-pr-7'], runtime);
		expect(r.code).toBe(0);
		expect(r.stdout).toContain(`run ${RUN} of hello-pr-7: completed, evaluated: passed`);
		expect(r.stdout).toContain('hello.home  pass  [recorder:screenshot:1]');
		const interrupted = status({
			state: 'completed',
			completion: 'interrupted',
			outcome: 'incomplete',
			interruption: 'koid_restarted',
		});
		expect(
			(await capture(['verify', 'run', 'hello-pr-7'], verifyRuntime(running([interrupted])))).code,
		).toBe(1);
		const failed = status({ ...finished, outcome: 'failed' });
		expect(
			(await capture(['verify', 'run', 'hello-pr-7'], verifyRuntime(running([failed])))).code,
		).toBe(1);
		// A passed run whose bundle was not finalized counts for nothing.
		const unfinalized = status({ ...passed, finalized: false });
		expect(
			(await capture(['verify', 'run', 'hello-pr-7'], verifyRuntime(running([unfinalized])))).code,
		).toBe(1);
	});

	test('keeps following while the box cannot answer, and gives up after five minutes', async () => {
		let polls = 0;
		const runtime = verifyRuntime((args) => {
			if (args[1] === 'plan') return ok(plan());
			if (args[1] === 'run') return ok(accepted);
			polls += 1;
			if (polls <= 2) throw new BoxUnavailableError('ThrottlingException');
			return ok(finished);
		});
		const r = await capture(['verify', 'run', 'hello-pr-7', '--json'], runtime);
		expect(r.code).toBe(1);
		expect(JSON.parse(r.stdout).run.state).toBe('completed');
		expect(polls).toBe(3);
		const silent = verifyRuntime((args) => {
			if (args[1] === 'plan') return ok(plan());
			if (args[1] === 'run') return ok(accepted);
			throw new BoxUnavailableError('TimeoutError');
		});
		const gaveUp = await capture(['verify', 'run', 'hello-pr-7'], silent);
		expect(gaveUp.code).toBe(1);
		expect(gaveUp.stderr).toContain(
			`koi: could not read the status of run ${RUN} for 5 minutes: TimeoutError\n`,
		);
	});

	test('stops following a run that outlives its limit and the margin', async () => {
		const runtime = verifyRuntime(running([status()]));
		const r = await capture(['verify', 'run', 'hello-pr-7'], runtime);
		expect(r.code).toBe(1);
		expect(r.stderr).toContain(
			`koi: run ${RUN} is still running after its limit of 600 seconds and the follow margin; see koi verify status ${RUN}, or koi verify cancel ${RUN}\n`,
		);
		const polls = runtime.calls.filter((c) => c[1] === 'status').length;
		expect(polls).toBe(Math.ceil((600_000 + FOLLOW_MARGIN_MS) / VERIFY_POLL_MS));
	});

	test('stops at once when koid refuses the run, with the lease untouched', async () => {
		const runtime = verifyRuntime((args) => {
			if (args[1] === 'plan') return ok(plan());
			return refused(
				409,
				'deployment_mismatch',
				'hello-pr-7 serves another deployment; plan again',
			);
		});
		const r = await capture(['verify', 'run', 'hello-pr-7'], runtime);
		expect(r.code).toBe(1);
		expect(r.stderr).toEndWith(
			'koi: hello-pr-7 serves another deployment; plan again (deployment_mismatch)\n',
		);
		expect(runtime.calls.filter((c) => c[1] === 'status')).toEqual([]);
	});
});

describe('koi verify status and cancel', () => {
	test('status reads every page of points and exits 0 whatever the outcome', async () => {
		const runtime = verifyRuntime((args) => {
			if (args[1] !== 'status') return refused(404, 'not_found', 'no');
			if (args[3] === undefined) return ok({ ...finished, points: [finished.points[0]], next: 1 });
			return ok({
				...finished,
				points: [finished.points[1]],
				truncated: ['points[app.search].reason'],
			});
		});
		const json = await capture(['verify', 'status', RUN, '--json'], runtime);
		expect(json.code).toBe(0);
		expect(runtime.calls).toEqual([
			['verify', 'status', RUN],
			['verify', 'status', RUN, '1'],
		]);
		// The second page's cut is the whole's.
		expect(JSON.parse(json.stdout)).toEqual({
			...finished,
			truncated: ['points[app.search].reason'],
		});
		const text = await capture(['verify', 'status', RUN], runtime);
		expect(text.stdout).toContain(`run ${RUN} of hello-pr-7: completed, evaluated: incomplete`);
		expect(text.stdout).toContain('readiness   not eligible: the run incomplete');
		expect(text.stdout).toContain(
			'hello.home  blocked  verifier_unavailable: nothing ran  [recorder:screenshot:1, recorder:aria:2]',
		);
	});

	test('status shows a point by its id, with the reason as koid masked it', async () => {
		const reason = 'capability_missing: the recorder said [redacted]';
		const runtime = verifyRuntime((args) => {
			if (args[1] !== 'status') return refused(404, 'not_found', 'no');
			return ok({
				...finished,
				points: [
					{ id: 'hello.home', state: 'done', outcome: 'blocked', reason, evidence: [] },
					finished.points[1],
				],
			});
		});
		const text = await capture(['verify', 'status', RUN], runtime);
		expect(text.code).toBe(0);
		expect(text.stdout).toContain(`hello.home  blocked  ${reason}`);
	});

	test('an id that is no point id is not a status koi takes', async () => {
		const runtime = verifyRuntime((args) => {
			if (args[1] !== 'status') return refused(404, 'not_found', 'no');
			return ok({
				...finished,
				points: [{ id: 'refused:1', state: 'done', outcome: 'blocked', reason: 'x', evidence: [] }],
			});
		});
		const text = await capture(['verify', 'status', RUN], runtime);
		expect(text.code).not.toBe(0);
	});

	test('cancel asks koid to stop the run and prints the status', async () => {
		const runtime = verifyRuntime((args) => {
			if (args[1] === 'cancel') return ok(status({ cancelRequested: true }));
			return ok(
				status({
					cancelRequested: true,
					state: 'cancelled',
					completion: 'cancelled',
					outcome: 'incomplete',
				}),
			);
		});
		const r = await capture(['verify', 'cancel', RUN, '--json'], runtime);
		expect(r.code).toBe(0);
		expect(runtime.calls[0]).toEqual(['verify', 'cancel', RUN]);
		expect(JSON.parse(r.stdout).state).toBe('cancelled');
	});
});

describe('koi verify evidence', () => {
	const aria = `${'x'.repeat(99)}\n`.repeat(100);
	const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4]);
	const artifact = (
		id: string,
		kind: 'aria' | 'screenshot' | 'trace',
		bytes: Uint8Array,
		availability: 'available' | 'withheld',
	) => ({
		id,
		runId: RUN,
		pointId: 'hello.home',
		attempt: 1,
		kind,
		mediaType:
			kind === 'screenshot'
				? 'image/png'
				: kind === 'aria'
					? 'text/plain; charset=utf-8'
					: 'application/zip',
		size: availability === 'available' ? bytes.length : 0,
		sha256: sha(availability === 'available' ? bytes : new Uint8Array(0)),
		origin: 'recorder' as const,
		capturedAt: accepted.startedAt,
		eventRange: { first: 1, last: 2 },
		redaction: {
			status: availability === 'available' ? ('sanitized' as const) : ('withheld' as const),
			policyDigest: DIGEST,
			removedFields: [],
			limitations: availability === 'available' ? [] : ['traces are withheld in version 1'],
		},
		availability,
		retainedUntil: '2026-11-05T12:00:00.000Z',
	});
	const artifacts = [
		artifact('recorder:screenshot:1', 'screenshot', png, 'available'),
		artifact('recorder:aria:2', 'aria', new TextEncoder().encode(aria), 'available'),
		artifact('recorder:trace:3', 'trace', new Uint8Array(0), 'withheld'),
	];
	const events: RunEventsPage[] = [
		{
			version: 1,
			runId: RUN,
			events: [
				{ seq: 1, at: accepted.startedAt, source: 'host', type: 'run-started' },
				{
					seq: 2,
					at: accepted.startedAt,
					source: 'host',
					type: 'point-opened',
					pointId: 'hello.home',
				},
			],
			next: 2,
			more: true,
		},
		{
			version: 1,
			runId: RUN,
			events: [{ seq: 3, at: accepted.startedAt, source: 'host', type: 'recorder-stopped' }],
			next: 3,
			more: false,
		},
	];
	// The event file as the manifest hashes it.
	const eventBytes = events
		.flatMap((page) => page.events.map((e) => `${JSON.stringify(e)}\n`))
		.join('');
	const recordedEvents = { count: 3, bytes: eventBytes.length, sha256: sha(eventBytes) };
	const reply = (page: typeof artifacts, next?: number, truncated?: string[]): EvidenceReply => ({
		version: 1,
		runId: RUN,
		finalized: true,
		expired: false,
		status: {
			version: 1,
			runId: RUN,
			state: 'completed',
			evidence: 'complete',
			startedAt: accepted.startedAt,
			updatedAt: accepted.startedAt,
			finishedAt: accepted.startedAt,
			counts: { events: 3, artifacts: 3, bytes: 10_008 },
			problems: [],
		},
		retention: {
			retainedUntil: '2026-11-05T12:00:00.000Z',
			tombstoneUntil: '2027-04-04T12:00:00.000Z',
		},
		events: recordedEvents,
		limitations: ['pixels were not inspected'],
		artifactCount: 3,
		artifacts: page,
		...(next !== undefined ? { next } : {}),
		...(truncated !== undefined ? { truncated } : {}),
	});
	const chunkOf = (id: string, bytes: Uint8Array, offset: number, length = 6144): ArtifactChunk => {
		const slice = bytes.subarray(offset, offset + Math.min(length, 6144));
		const end = offset + slice.length;
		return {
			version: 1,
			runId: RUN,
			artifact: id,
			kind: id.includes('aria') ? 'aria' : 'screenshot',
			mediaType: id.includes('aria') ? 'text/plain; charset=utf-8' : 'image/png',
			size: bytes.length,
			sha256: sha(bytes),
			offset,
			length: slice.length,
			dataBase64: Buffer.from(slice).toString('base64'),
			...(end < bytes.length ? { next: end, note: 'the rest needs the channel (C2)' } : {}),
			truncated: end < bytes.length,
		};
	};
	const handler: Handler = (args) => {
		switch (args[1]) {
			case 'evidence':
				return args[3] === undefined
					? ok(reply(artifacts.slice(0, 2), 2))
					: ok(reply(artifacts.slice(2)));
			case 'status':
				return ok(finished);
			case 'events':
				return ok(args[3] === '2' ? events[1] : events[0]);
			case 'artifact': {
				const bytes = args[3] === 'recorder:aria:2' ? new TextEncoder().encode(aria) : png;
				return ok(chunkOf(args[3] as string, bytes, Number(args[4]), Number(args[5])));
			}
			default:
				return refused(404, 'not_found', `unexpected ${args[1]}`);
		}
	};

	test('writes the manifest, status, events and every artifact, checked against the manifest', async () => {
		const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'export');
		const runtime = verifyRuntime(handler);
		const r = await capture(['verify', 'evidence', RUN, '--out', out, '--json'], runtime);
		expect(r.code).toBe(0);
		const report = EvidenceExportSchema.parse(JSON.parse(r.stdout));
		expect(report.runId).toBe(RUN);
		expect(report.finalized).toBe(true);
		expect(report.events).toEqual({ count: 3, file: 'events.ndjson' });
		expect(report.artifacts).toEqual([
			{
				id: 'recorder:screenshot:1',
				kind: 'screenshot',
				availability: 'available',
				file: 'artifacts/screenshot-1.png',
				bytes: 8,
				sha256: sha(png),
				verified: true,
				truncated: false,
			},
			{
				id: 'recorder:aria:2',
				kind: 'aria',
				availability: 'available',
				file: 'artifacts/aria-2.txt',
				bytes: 10_000,
				sha256: sha(aria),
				verified: true,
				truncated: false,
			},
			{
				id: 'recorder:trace:3',
				kind: 'trace',
				availability: 'withheld',
				bytes: 0,
				sha256: sha(new Uint8Array(0)),
				verified: false,
				truncated: false,
				note: 'withheld: traces are withheld in version 1',
			},
		]);
		expect(await readFile(join(out, 'artifacts/aria-2.txt'), 'utf8')).toBe(aria);
		expect(new Uint8Array(await readFile(join(out, 'artifacts/screenshot-1.png')))).toEqual(png);
		expect(
			(await readFile(join(out, 'events.ndjson'), 'utf8')).split('\n').filter((l) => l !== ''),
		).toHaveLength(3);
		expect(JSON.parse(await readFile(join(out, 'status.json'), 'utf8'))).toEqual(finished);
		expect(JSON.parse(await readFile(join(out, 'evidence.json'), 'utf8')).artifacts).toHaveLength(
			3,
		);
		expect(JSON.parse(await readFile(join(out, 'export.json'), 'utf8'))).toEqual(report);
		expect((await readdir(join(out, 'artifacts'))).sort()).toEqual([
			'aria-2.txt',
			'screenshot-1.png',
		]);
		// The aria artifact took two chunks; the screenshot one.
		expect(
			runtime.calls.filter((c) => c[1] === 'artifact' && c[3] === 'recorder:aria:2'),
		).toHaveLength(2);
		const text = await capture(
			['verify', 'evidence', RUN, '--out', join(out, '..', 'again')],
			runtime,
		);
		expect(text.code).toBe(0);
		expect(text.stdout).toContain('recorder:aria:2  artifacts/aria-2.txt  verified');
		expect(text.stdout).toContain(
			'recorder:trace:3  withheld  withheld: traces are withheld in version 1',
		);
	});

	test('asks for no byte past a ceiling: an artifact over its own, or the export over its total, is partial', async () => {
		const big = new TextEncoder().encode(`${'y'.repeat(99)}\n`.repeat(101));
		expect(big.length).toBe(10_100);
		const two = [
			artifact('recorder:aria:1', 'aria', big, 'available'),
			artifact('recorder:aria:2', 'aria', big, 'available'),
		];
		const runtime = verifyRuntime((args) => {
			switch (args[1]) {
				case 'evidence':
					return ok(reply(two));
				case 'status':
					return ok(finished);
				case 'events':
					return ok(events[1]);
				case 'artifact':
					return ok(chunkOf(args[3] as string, big, Number(args[4]), Number(args[5])));
				default:
					return refused(404, 'not_found', `unexpected ${args[1]}`);
			}
		});
		const { box } = await runtime.box({} as never);
		const deps: VerifyDeps = {
			box,
			domain: 'previews.example.net',
			progress: () => {},
			probe: runtime.probe as VerifyDeps['probe'],
			sleep: runtime.sleep as VerifyDeps['sleep'],
			now: runtime.now,
			limits: { artifactBytes: 10_000, exportBytes: 12_000 },
		};
		const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'export');
		const report = await exportEvidence(RUN, out, deps);
		// The first artifact is a hundred bytes over its ceiling: exactly the
		// ceiling is fetched and written, and it is partial.
		expect(report.artifacts[0]).toMatchObject({
			id: 'recorder:aria:1',
			file: 'artifacts/aria-1.txt.partial',
			bytes: 10_000,
			verified: false,
			truncated: true,
		});
		expect(report.artifacts[0]?.note).toStartWith('partial: 10000 of 10100 bytes');
		expect((await stat(join(out, 'artifacts/aria-1.txt.partial'))).size).toBe(10_000);
		// Every request for it was for what the allowance had left, and none
		// came once it had none.
		const asked = runtime.calls
			.filter((c) => c[1] === 'artifact' && c[3] === 'recorder:aria:1')
			.map((c) => Number(c[5]));
		expect(asked).toEqual([6144, 3856]);
		// The second gets what the export's total has left, and the total
		// lands exactly on the ceiling.
		const eventsBytes = report.bytes - 10_000 - (report.artifacts[1]?.bytes ?? 0);
		expect(report.artifacts[1]).toMatchObject({
			bytes: 12_000 - 10_000 - eventsBytes,
			truncated: true,
		});
		expect(report.bytes).toBe(12_000);
	});

	// koid, honoring `after` and `limit` over `all`, and keeping count of what
	// it sent, so a test can hold the export to what actually crossed SSM.
	const serving = (all: RunEventsPage['events']) => {
		const sent = { bytes: 0, limits: [] as number[] };
		const runtime = verifyRuntime((args, n) => {
			if (args[1] !== 'events') return handler(args, n);
			const after = Number(args[3]);
			const limit = Number(args[4]);
			const page = all.filter((e) => e.seq > after).slice(0, limit);
			sent.limits.push(limit);
			sent.bytes += page.reduce((sum, e) => sum + `${JSON.stringify(e)}\n`.length, 0);
			const last = page.at(-1)?.seq ?? after;
			return ok({
				version: 1,
				runId: RUN,
				events: page,
				next: last,
				more: all.some((e) => e.seq > last),
			});
		});
		return { sent, runtime };
	};
	const exportWith = async (runtime: ReturnType<typeof verifyRuntime>, exportBytes: number) => {
		const { box } = await runtime.box({} as never);
		const deps: VerifyDeps = {
			box,
			domain: 'previews.example.net',
			progress: () => {},
			probe: runtime.probe as VerifyDeps['probe'],
			sleep: runtime.sleep as VerifyDeps['sleep'],
			now: runtime.now,
			limits: { artifactBytes: 1024 ** 2, exportBytes },
		};
		const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'export');
		return { out, report: await exportEvidence(RUN, out, deps) };
	};
	// An event whose line is exactly `size` bytes. Sequence numbers from 100
	// keep every line of a size the same.
	const eventOf = (seq: number, size: number) => {
		const bare = { seq, at: accepted.startedAt, source: 'host' as const, type: 'filler', pad: '' };
		const room = size - `${JSON.stringify(bare)}\n`.length;
		return { ...bare, pad: 'x'.repeat(room) };
	};

	test('the fetch stops at the ceiling: no page holds more than the allowance at the average line', async () => {
		const all = Array.from({ length: 200 }, (_, i) => eventOf(100 + i, 100));
		const { sent, runtime } = serving(all);
		const { out, report } = await exportWith(runtime, 1050);
		// 1050 bytes at the estimate of 256 a line is 4 events. The 650 left
		// at the average of 100 is 6. The 50 left holds none, so the minimum
		// of 1 is asked for, which does not fit. Then nothing more is asked.
		expect(sent.limits).toEqual([4, 6, 1]);
		// Of 20,000 bytes koid holds, one line past the ceiling crossed SSM.
		expect(sent.bytes).toBe(1100);
		expect(report.bytes).toBe(sent.bytes);
		expect(report.events.count).toBe(10);
		expect((await readFile(join(out, 'events.ndjson'))).length).toBe(1000);
		expect(report.notes).toContain(
			'events stop after sequence 109: the export reached its ceiling of 1050 bytes',
		);
		expect(runtime.calls.filter((c) => c[1] === 'artifact')).toEqual([]);
	});

	test('every line of a page counts, those after one that did not fit too', async () => {
		// The first lines are short, so the average promises room for more
		// than the longer lines that follow can use.
		const all = [
			...Array.from({ length: 3 }, (_, i) => eventOf(100 + i, 100)),
			...Array.from({ length: 50 }, (_, i) => eventOf(103 + i, 300)),
		];
		const { sent, runtime } = serving(all);
		const { out, report } = await exportWith(runtime, 1000);
		// 3 lines, then 700 left at an average of 100: 7 lines of 300 cross
		// SSM, of which 2 fit. The other 5 count, and end the export.
		expect(sent.limits).toEqual([3, 7]);
		expect(sent.bytes).toBe(2400);
		expect(report.bytes).toBe(2400);
		expect(report.events.count).toBe(5);
		expect((await readFile(join(out, 'events.ndjson'))).length).toBe(900);
		expect(runtime.calls.filter((c) => c[1] === 'artifact')).toEqual([]);
		expect(
			report.artifacts
				.filter((a) => a.availability === 'available')
				.map((a) => [a.truncated, a.note?.split(':')[0]]),
		).toEqual([
			[true, 'not exported'],
			[true, 'not exported'],
		]);
	});

	test('a ceiling smaller than a line asks for one event at a time, and writes what fits', async () => {
		const all = [...(events[0]?.events ?? []), ...(events[1]?.events ?? [])];
		const { sent, runtime } = serving(all);
		const { out, report } = await exportWith(runtime, 150);
		const first = `${JSON.stringify(all[0])}\n`;
		const second = `${JSON.stringify(all[1])}\n`;
		expect(first.length).toBeLessThan(150);
		expect(first.length + second.length).toBeGreaterThan(150);
		expect(sent.limits).toEqual([1, 1]);
		expect(report.events.count).toBe(1);
		expect(await readFile(join(out, 'events.ndjson'), 'utf8')).toBe(first);
		expect(report.notes).toContain(
			'events stop after sequence 1: the export reached its ceiling of 150 bytes',
		);
		expect(report.bytes).toBe(first.length + second.length);
	});

	test('what a later evidence page says it cut is in the whole', async () => {
		const runtime = verifyRuntime((args, n) => {
			if (args[1] !== 'evidence') return handler(args, n);
			return args[3] === undefined
				? ok(reply(artifacts.slice(0, 2), 2, ['limitations']))
				: ok(
						reply(artifacts.slice(2), undefined, [
							'artifacts[recorder:trace:3].redaction.limitations',
						]),
					);
		});
		const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'export');
		const r = await capture(['verify', 'evidence', RUN, '--out', out, '--json'], runtime);
		expect(r.code).toBe(0);
		const evidence = EvidenceReplySchema.parse(
			JSON.parse(await readFile(join(out, 'evidence.json'), 'utf8')),
		);
		expect(evidence.artifacts).toHaveLength(3);
		expect(evidence.truncated).toEqual([
			'limitations',
			'artifacts[recorder:trace:3].redaction.limitations',
		]);
		expect(evidence.next).toBeUndefined();
	});

	describe('a file that takes less than it is given', () => {
		// Real files, whose writes take at most what `take` says.
		const wrapped =
			(take: (path: string, length: number) => number): OpenExportFile =>
			async (path, flags, mode) => {
				const file = await open(path, flags, mode);
				return {
					write: async (bytes, offset, length) => {
						const allowed = take(path, length);
						return allowed === 0 ? { bytesWritten: 0 } : file.write(bytes, offset, allowed);
					},
					close: () => file.close(),
				};
			};
		const exportWith = async (
			runtime: ReturnType<typeof verifyRuntime>,
			more: Partial<VerifyDeps>,
		) => {
			const { box } = await runtime.box({} as never);
			const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'out');
			const done = exportEvidence(RUN, out, {
				box,
				domain: 'previews.example.net',
				progress: () => {},
				probe: runtime.probe as VerifyDeps['probe'],
				sleep: runtime.sleep as VerifyDeps['sleep'],
				now: runtime.now,
				...more,
			});
			return { out, done };
		};
		const eventLines = async (out: string) =>
			(await readFile(join(out, 'events.ndjson'), 'utf8'))
				.split('\n')
				.filter((l) => l !== '')
				.map((l) => JSON.parse(l).seq);

		test.each<[string, (length: number) => number]>([
			['a third of what is left', (length) => Math.max(1, Math.floor(length / 3))],
			['a byte at a time', () => 1],
		])('writes taking %s still make whole, verified files', async (_what, take) => {
			let writes = 0;
			const { out, done } = await exportWith(verifyRuntime(handler), {
				openFile: wrapped((_path, length) => {
					writes += 1;
					return take(length);
				}),
			});
			const report = await done;
			// More writes than there are chunks and lines, so writes did fall short.
			expect(writes).toBeGreaterThan(10);
			expect(report.artifacts[0]?.verified).toBe(true);
			expect(report.artifacts[0]?.bytes).toBe(png.length);
			expect(report.artifacts[1]?.verified).toBe(true);
			expect(report.artifacts[1]?.bytes).toBe(aria.length);
			expect(await readFile(join(out, 'artifacts/aria-2.txt'), 'utf8')).toBe(aria);
			expect(new Uint8Array(await readFile(join(out, 'artifacts/screenshot-1.png')))).toEqual(png);
			expect(report.events.count).toBe(3);
			expect(await eventLines(out)).toEqual([1, 2, 3]);
		});

		const stops = async (take: (path: string, length: number) => number, why: string) => {
			const { out, done } = await exportWith(verifyRuntime(handler), { openFile: wrapped(take) });
			await expect(done).rejects.toThrow(why);
			const left = await readdir(out, { recursive: true });
			expect(left.filter((name) => name.endsWith('.part'))).toEqual([]);
			// Nothing says this export finished.
			expect(left).not.toContain('export.json');
			return left;
		};

		test('an artifact write that takes nothing fails the export rather than looping', async () => {
			const left = await stops(
				(path, length) => (path.includes('aria-2') ? 0 : length),
				'made no progress',
			);
			expect(left).not.toContain('artifacts/aria-2.txt');
		});

		test('so does one that takes nothing after taking some', async () => {
			let writes = 0;
			const left = await stops((path, length) => {
				if (!path.includes('aria-2')) return length;
				writes += 1;
				return writes === 1 ? 10 : 0;
			}, 'made no progress');
			expect(left).not.toContain('artifacts/aria-2.txt');
		});

		test('an event write that takes nothing fails the export too', async () => {
			const left = await stops(
				(path, length) => (path.includes('events.ndjson') ? 0 : length),
				'made no progress',
			);
			expect(left).not.toContain('events.ndjson');
		});
	});

	describe('an export that fails part way', () => {
		const exportFrom = async (handle: Handler) => {
			const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'out');
			const r = await capture(['verify', 'evidence', RUN, '--out', out], verifyRuntime(handle));
			expect(r.code).toBe(1);
			const left = await readdir(out, { recursive: true });
			expect(left.filter((name) => name.endsWith('.part'))).toEqual([]);
			expect(left).not.toContain('export.json');
			return { r, left };
		};

		test('leaves no part file when an event page cannot be read', async () => {
			const { r, left } = await exportFrom((args, n) =>
				args[1] === 'events' && args[3] === '2'
					? refused(500, 'internal', 'the events could not be read')
					: handler(args, n),
			);
			expect(r.stderr).toContain('the events could not be read');
			expect(left).not.toContain('events.ndjson');
		});

		test('leaves no part file when a chunk cannot be read, or does not fit what was asked', async () => {
			const failed = await exportFrom((args, n) =>
				args[1] === 'artifact' && args[3] === 'recorder:aria:2' && args[4] !== '0'
					? refused(500, 'internal', 'the chunk could not be read')
					: handler(args, n),
			);
			expect(failed.r.stderr).toContain('the chunk could not be read');
			expect(failed.left).not.toContain('artifacts/aria-2.txt');
			const wrong = await exportFrom((args, n) =>
				args[1] === 'artifact' && args[3] === 'recorder:aria:2'
					? ok({ ...chunkOf('recorder:aria:2', png, 0), offset: 7 })
					: handler(args, n),
			);
			expect(wrong.r.stderr).toContain('koid sent');
			expect(wrong.left).not.toContain('artifacts/aria-2.txt');
		});
	});

	describe('a JSON file whose write fails part way', () => {
		const realOpen: OpenExportFile = (path, flags, mode) => open(path, flags, mode);
		// Real files, whose writes to a file of this name take `first` bytes and then fail.
		const failing =
			(name: string, first: number, opened: string[] = []): OpenExportFile =>
			async (path, flags, mode) => {
				opened.push(path);
				const file = await realOpen(path, flags, mode);
				if (!path.endsWith(`${name}.part`)) return file;
				let written = 0;
				return {
					write: async (bytes, offset, length) => {
						if (written >= first) throw new Error('ENOSPC: no space left on device');
						const part = Math.min(length, first - written);
						written += part;
						return file.write(bytes, offset, part);
					},
					close: () => file.close(),
				};
			};
		const exportWith = async (openFile: OpenExportFile) => {
			const { box } = await verifyRuntime(handler).box({} as never);
			const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'out');
			const done = exportEvidence(RUN, out, {
				box,
				domain: 'previews.example.net',
				progress: () => {},
				probe: async () => ({ status: 200 }),
				sleep: async () => {},
				now: () => new Date(),
				openFile,
			});
			return { out, done };
		};

		test.each(['status.json', 'evidence.json', 'export.json'])(
			'%s leaves neither a partial file nor a completion file',
			async (name) => {
				const { out, done } = await exportWith(failing(name, 10));
				await expect(done).rejects.toThrow('ENOSPC');
				const left = await readdir(out, { recursive: true });
				expect(left).not.toContain(name);
				expect(left).not.toContain(`${name}.part`);
				expect(left.filter((n) => n.endsWith('.part'))).toEqual([]);
				expect(left).not.toContain('export.json');
			},
		);

		test('every JSON file goes through a part file, and export.json is the last file made', async () => {
			const opened: string[] = [];
			const { out, done } = await exportWith(failing('nothing', 0, opened));
			await done;
			const names = opened.map((path) => path.slice(out.length + 1));
			expect(names).toEqual(expect.arrayContaining(['status.json.part', 'evidence.json.part']));
			expect(names.at(-1)).toBe('export.json.part');
			const left = await readdir(out, { recursive: true });
			expect(left.filter((n) => n.endsWith('.part'))).toEqual([]);
			expect(left).toEqual(expect.arrayContaining(['status.json', 'evidence.json', 'export.json']));
		});
	});

	describe('expired evidence', () => {
		// As koid answers once expiry has run: the manifest's fields and no
		// artifacts, and 410 for the events and for any artifact.
		const gone = (args: string[]): CtlResult => {
			switch (args[1]) {
				case 'evidence':
					return ok({ ...reply([]), expired: true, artifactCount: 3 });
				case 'status':
					return ok(finished);
				case 'events':
					return refused(410, 'evidence_expired', `the events of run ${RUN} are no longer kept`);
				case 'artifact':
					return refused(410, 'evidence_expired', `the evidence of run ${RUN} has expired`);
				default:
					return refused(404, 'not_found', `unexpected ${args[1]}`);
			}
		};
		const exportGone = async (argv: string[] = []) => {
			const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'out');
			const runtime = verifyRuntime(gone);
			const r = await capture(['verify', 'evidence', RUN, '--out', out, ...argv], runtime);
			return { out, runtime, r };
		};

		test('saves what is retained, asks for no events, and leaves nothing half written', async () => {
			const { out, runtime, r } = await exportGone(['--json']);
			expect(r.code).toBe(0);
			expect(runtime.calls.filter((c) => c[1] === 'events' || c[1] === 'artifact')).toEqual([]);
			expect((await readdir(out, { recursive: true })).sort()).toEqual([
				'artifacts',
				'evidence.json',
				'export.json',
				'status.json',
			]);
			expect(JSON.parse(await readFile(join(out, 'status.json'), 'utf8'))).toEqual(finished);
			expect(JSON.parse(await readFile(join(out, 'evidence.json'), 'utf8')).expired).toBe(true);
			expect(JSON.parse(await readFile(join(out, 'export.json'), 'utf8'))).toEqual(
				JSON.parse(r.stdout),
			);
		});

		test('export.json says it is not complete, and what is missing', async () => {
			const { out } = await exportGone();
			const report = EvidenceExportSchema.parse(
				JSON.parse(await readFile(join(out, 'export.json'), 'utf8')),
			);
			expect(report.complete).toBe(false);
			expect(report.expired).toBe(true);
			expect(report.finalized).toBe(true);
			expect(report.artifacts).toEqual([]);
			expect(report.bytes).toBe(0);
			// No file named, since none was saved, and the count is what was saved.
			expect(report.events).toEqual({ count: 0 });
			expect(report.missing).toEqual([
				'events: the 3 events of this run have expired',
				'3 of 3 artifacts: they have expired',
			]);
			expect(report.notes).toContain(
				'events are unavailable: koid no longer keeps them for this run',
			);
		});

		test('the text output says so too', async () => {
			const { r } = await exportGone();
			expect(r.code).toBe(0);
			expect(r.stdout).toContain('(expired)');
			expect(r.stdout).toContain('complete    no');
			expect(r.stdout).toContain('events      unavailable');
			expect(r.stdout).toContain('missing:\n  events: the 3 events of this run have expired');
			expect(r.stdout).not.toContain('events.ndjson');
			expect(r.stdout).not.toContain('verified');
		});

		test('the schema will not let an expired or unfinalized export call itself complete', () => {
			const report = {
				version: 1,
				runId: RUN,
				out: '/x',
				finalized: true,
				expired: false,
				complete: true,
				missing: [],
				artifacts: [],
				events: { count: 3, file: 'events.ndjson' },
				bytes: 300,
				notes: [],
			};
			expect(EvidenceExportSchema.safeParse(report).success).toBe(true);
			for (const over of [
				{ expired: true },
				{ finalized: false },
				{ missing: ['events'] },
				{ complete: false },
			]) {
				expect(EvidenceExportSchema.safeParse({ ...report, ...over }).success).toBe(false);
			}
		});
	});

	describe('what a whole export says', () => {
		const exportOf = async (handle: Handler) => {
			const out = join(await mkdtemp(join(tmpdir(), 'koi-evidence-')), 'out');
			const r = await capture(
				['verify', 'evidence', RUN, '--out', out, '--json'],
				verifyRuntime(handle),
			);
			expect(r.code).toBe(0);
			return EvidenceExportSchema.parse(JSON.parse(r.stdout));
		};
		const available = [artifacts[0], artifacts[1]] as typeof artifacts;

		test('complete when every event and every artifact is here and verified', async () => {
			const report = await exportOf((args, n) =>
				args[1] === 'evidence' ? ok({ ...reply(available), artifactCount: 2 }) : handler(args, n),
			);
			expect(report.complete).toBe(true);
			expect(report.missing).toEqual([]);
			expect(report.expired).toBe(false);
		});

		test('not complete with an artifact withheld, discarded or left out', async () => {
			const withheld = await exportOf(handler);
			expect(withheld.complete).toBe(false);
			expect(withheld.missing).toEqual([
				'recorder:trace:3: withheld: traces are withheld in version 1',
			]);
			const discarded = await exportOf((args, n) =>
				args[1] === 'artifact' && args[3] === 'recorder:screenshot:1'
					? ok({
							...chunkOf('recorder:screenshot:1', png, 0),
							dataBase64: Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]).toString('base64'),
						})
					: handler(args, n),
			);
			expect(discarded.complete).toBe(false);
			expect(discarded.missing[0]).toStartWith('recorder:screenshot:1: discarded');
			const unlisted = await exportOf((args, n) =>
				args[1] === 'evidence' ? ok({ ...reply(available), artifactCount: 5 }) : handler(args, n),
			);
			expect(unlisted.missing).toContain('3 of 5 artifacts: koid did not list them');
		});

		test('not complete with fewer events than the manifest records', async () => {
			const report = await exportOf((args, n) =>
				args[1] === 'evidence'
					? ok({
							...reply(available),
							artifactCount: 2,
							events: { count: 9, bytes: 900, sha256: DIGEST },
						})
					: handler(args, n),
			);
			expect(report.complete).toBe(false);
			expect(report.missing).toEqual(['events: koid gave 3 of the 9 recorded']);
		});

		describe('events koid gave that are not the events recorded', () => {
			const withEvents = (lines: RunEventsPage['events']): Handler => {
				return (args, n) => {
					if (args[1] === 'evidence') return ok({ ...reply(available), artifactCount: 2 });
					if (args[1] === 'events') {
						return ok({
							version: 1,
							runId: RUN,
							events: lines,
							next: lines.at(-1)?.seq ?? 0,
							more: false,
						});
					}
					return handler(args, n);
				};
			};
			const at = accepted.startedAt;
			const first = { seq: 1, at, source: 'host' as const, type: 'run-started' };
			const second = { seq: 2, at, source: 'host' as const, type: 'point-opened' };
			const third = { seq: 3, at, source: 'host' as const, type: 'recorder-stopped' };

			test('a repeated sequence number, with the count right, is not complete', async () => {
				const report = await exportOf(withEvents([first, first, third]));
				expect(report.events.count).toBe(3);
				expect(report.complete).toBe(false);
				expect(report.missing).toEqual(['events: sequence 1 comes after 1']);
			});

			test('a gap in the sequence, with the count right, is not complete', async () => {
				const report = await exportOf(withEvents([first, third, { ...third, seq: 4 }]));
				expect(report.complete).toBe(false);
				expect(report.missing).toEqual(['events: sequence 3 comes after 1']);
			});

			test('a sequence that does not start at the first event is not complete', async () => {
				const report = await exportOf(withEvents([second, third, { ...third, seq: 4 }]));
				expect(report.missing).toEqual(['events: sequence 2 comes after 0']);
			});

			test('events that run in order but are not the bytes the manifest hashed are not complete', async () => {
				const report = await exportOf(
					withEvents([first, { ...second, type: 'point-closed' }, third]),
				);
				expect(report.complete).toBe(false);
				expect(report.missing).toHaveLength(1);
				expect(report.missing[0]).toStartWith('events: the 3 lines koid gave hash to sha256:');
				expect(report.missing[0]).toEndWith(`and the manifest says ${recordedEvents.sha256}`);
			});

			test('the manifest counts no more than koid gave, and more than it recorded is not complete', async () => {
				const report = await exportOf(withEvents([first, second, third, { ...third, seq: 4 }]));
				expect(report.complete).toBe(false);
				expect(report.missing[0]).toContain('and the manifest says');
			});

			test('a run not finalized has no digest to check, and its order is still checked', async () => {
				const handle = withEvents([first, first]);
				const report = await exportOf((args, n) => {
					if (args[1] !== 'evidence') return handle(args, n);
					const { events: _events, retention: _retention, ...rest } = reply([]);
					return ok({ ...rest, finalized: false, artifactCount: 0 });
				});
				expect(report.complete).toBe(false);
				expect(report.missing).toEqual([
					'the manifest: the run is not finalized',
					'events: sequence 1 comes after 1',
				]);
			});
		});

		test('not complete for a run that is not finalized', async () => {
			const report = await exportOf((args, n) => {
				if (args[1] !== 'evidence') return handler(args, n);
				const { events: _events, retention: _retention, ...rest } = reply([]);
				return ok({ ...rest, finalized: false, artifactCount: 2 });
			});
			expect(report.complete).toBe(false);
			expect(report.events.file).toBe('events.ndjson');
			expect(report.missing).toEqual([
				'the manifest: the run is not finalized',
				'2 of 2 artifacts: the run is not finalized',
			]);
		});
	});

	test('discards bytes that do not hash to the manifest, and refuses a directory that is not empty', async () => {
		const root = await mkdtemp(join(tmpdir(), 'koi-evidence-'));
		const runtime = verifyRuntime((args, n) => {
			if (args[1] === 'artifact' && args[3] === 'recorder:screenshot:1') {
				const wrong = chunkOf('recorder:screenshot:1', png, 0);
				return ok({
					...wrong,
					dataBase64: Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]).toString('base64'),
				});
			}
			return handler(args, n);
		});
		const r = await capture(
			['verify', 'evidence', RUN, '--out', join(root, 'out'), '--json'],
			runtime,
		);
		expect(r.code).toBe(0);
		const report = EvidenceExportSchema.parse(JSON.parse(r.stdout));
		expect(report.artifacts[0]?.file).toBeUndefined();
		expect(report.artifacts[0]?.note).toStartWith('discarded: the bytes read hash to sha256:');
		expect(await readdir(join(root, 'out/artifacts'))).toEqual(['aria-2.txt']);
		const full = join(root, 'full');
		await mkdir(full, { recursive: true });
		await writeFile(join(full, 'x'), '');
		const refusedDir = await capture(['verify', 'evidence', RUN, '--out', full], runtime);
		expect(refusedDir.code).toBe(1);
		expect(refusedDir.stderr).toContain('is not empty');
	});
});

describe('control characters in what a person reads', () => {
	// ESC and BEL for an OSC 52 write to the clipboard and a screen wipe, then DEL, C1 CSI,
	// a line ending, a line separator and a right-to-left override.
	const HOSTILE = '\x1b]52;c;QUJD\x07\x1b[2J\x7f\x9b31m\r\n\u2028\u202e';
	const CONTROL = /[\p{Cc}\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;
	const poisoned = <T>(value: T): T => {
		if (typeof value === 'string') return `${value}${HOSTILE}` as T;
		if (Array.isArray(value)) return value.map(poisoned) as T;
		if (typeof value !== 'object' || value === null) return value;
		return Object.fromEntries(
			Object.entries(value).map(([key, field]) => [key, poisoned(field)]),
		) as T;
	};
	// No control character but the newlines the text is built from, and no more lines than
	// the same record makes with nothing hostile in it.
	const expectSafe = (text: string, plain: string) => {
		expect(text.replaceAll('\n', '')).not.toMatch(CONTROL);
		expect(text.split('\n').length).toBe(plain.split('\n').length);
		expect(text).toContain('\\x1b]52;c;QUJD\\x07');
		expect(text).toContain('\\u202e');
	};

	const fullPlan = plan({
		advisory: true,
		policy: {
			source: 'none',
			advisory: {
				path: '.koi/required.yaml',
				required: [{ id: 'hello.home', revision: 2 }],
				error: 'required: Invalid input',
			},
		},
		blocked: [{ id: 'app.llm', reason: 'capability_missing:provider:anthropic' }],
		uncovered: ['README.md'],
	});
	const fullStatus = status({
		state: 'completed',
		completion: 'interrupted',
		outcome: 'incomplete',
		interruption: 'recorder_lost: it went away',
		cancelRequested: true,
		evidence: 'incomplete',
		points: [
			{
				id: 'hello.home',
				state: 'done',
				outcome: 'blocked',
				reason: 'verifier_unavailable: nothing ran',
				evidence: ['recorder:screenshot:1'],
			},
			{ id: 'app.search', state: 'pending', evidence: [] },
		],
		problems: [{ code: 'capture_failed', detail: 'frames moved', at: accepted.startedAt }],
		problemCount: 1,
	});
	const fullExport: EvidenceExport = {
		version: 1,
		runId: RUN,
		out: '/tmp/koi-evidence',
		finalized: false,
		expired: true,
		complete: false,
		missing: ['events: gone'],
		artifacts: [
			{
				id: 'screenshot-1',
				kind: 'screenshot',
				availability: 'available',
				bytes: 3,
				sha256: DIGEST,
				verified: true,
				truncated: false,
				file: 'artifacts/screenshot-1.png',
				note: 'partial',
			},
			{
				id: 'aria-2',
				kind: 'aria',
				availability: 'withheld',
				bytes: 0,
				sha256: DIGEST,
				verified: false,
				truncated: false,
			},
		],
		events: { count: 3, file: 'events.ndjson' },
		bytes: 3,
		notes: ['it expired'],
	};

	test('formatPlan shows every string of a plan with its control characters escaped', () => {
		expectSafe(formatPlan(poisoned(fullPlan)), formatPlan(fullPlan));
	});

	test('formatStatus does, for a status', () => {
		expectSafe(formatStatus(poisoned(fullStatus)), formatStatus(fullStatus));
		const notReady = status({
			readiness: { eligibleForMergeGate: false, reasons: ['one', 'two'] },
		});
		expectSafe(formatStatus(poisoned(notReady)), formatStatus(notReady));
	});

	test('formatExport does, for what an export of the evidence reply says', () => {
		expectSafe(formatExport(poisoned(fullExport)), formatExport(fullExport));
		const unavailable: EvidenceExport = { ...fullExport, events: { count: 0 } };
		const bare = formatExport(poisoned(unavailable));
		expect(bare.replaceAll('\n', '')).not.toMatch(CONTROL);
	});

	test('a changed file name cannot forge the plan a reviewer reads', async () => {
		const forged = 'a.ts\n\nblocked (0):\n  none\x1b[2A';
		const runtime = verifyRuntime(() => ok(plan({ uncovered: [forged] })));
		const r = await capture(['verify', 'plan', 'hello-pr-7'], runtime);
		expect(r.code).toBe(0);
		expect(r.stdout).toContain('  a.ts\\x0a\\x0ablocked (0):\\x0a  none\\x1b[2A\n');
		expect(r.stdout.match(/^blocked \(/gm)?.length).toBe(1);
	});

	test('an error koid sends is escaped, and only for koi verify', async () => {
		const refusal = await capture(
			['verify', 'plan', 'hello-pr-7'],
			verifyRuntime(() => refused(409, 'no_such_point', `no point ${HOSTILE}`)),
		);
		expect(refusal.code).toBe(1);
		expect(refusal.stderr.endsWith('\n')).toBe(true);
		expect(refusal.stderr.slice(0, -1)).not.toMatch(CONTROL);
		expect(refusal.stderr).toContain('no point \\x1b]52;c;QUJD\\x07');

		const unavailable = await capture(
			['verify', 'status', RUN],
			verifyRuntime(() => ({ code: CTL_EXIT.unavailable, stdout: '', stderr: HOSTILE })),
		);
		expect(unavailable.code).toBe(1);
		expect(unavailable.stderr.slice(0, -1)).not.toMatch(CONTROL);
	});

	test('progress is escaped, whatever it quotes', async () => {
		const runtime = verifyRuntime((args) => {
			if (args[1] === 'plan') return ok(plan({ notes: [`a note ${HOSTILE}`] }));
			if (args[1] === 'run') return ok(accepted);
			return ok(finished);
		});
		const r = await capture(['verify', 'run', 'hello-pr-7'], runtime);
		expect(r.stderr).toContain('note: a note \\x1b]52;c;QUJD\\x07');
		expect(r.stderr.replaceAll('\n', '')).not.toMatch(CONTROL);
		// Each line is one of koi's own, so a note cannot start one.
		for (const line of r.stderr.trimEnd().split('\n')) expect(line).toStartWith('koi  ');
	});

	test('--json stays as it is: the value is whole, and JSON escapes what can end a line', async () => {
		const name = 'a.ts\x1b]52;c;QUJD\x07\n';
		const runtime = verifyRuntime(() => ok(plan({ uncovered: [name] })));
		const r = await capture(['verify', 'plan', 'hello-pr-7', '--json'], runtime);
		expect(PlanReplySchema.parse(JSON.parse(r.stdout)).uncovered).toEqual([name]);
		expect(r.stdout).toContain('a.ts\\u001b]52;c;QUJD\\u0007\\n');
	});
});

describe('koi verify usage', () => {
	test('exits 2 and asks nothing of the box for bad arguments', async () => {
		const runtime = verifyRuntime(() => ok({}));
		const bad = [
			['verify'],
			['verify', 'act', RUN],
			['verify', 'plan'],
			['verify', 'plan', 'Bad_Label'],
			['verify', 'plan', 'hello-pr-7', '--profile', 'Not Slug'],
			['verify', 'plan', 'hello-pr-7', '--out', 'x'],
			['verify', 'status'],
			['verify', 'status', 'not-an-id'],
			['verify', 'status', RUN, '--profile', 'pr'],
			['verify', 'evidence', RUN],
			['verify', 'cancel', RUN, 'extra'],
			['list', '--profile', 'pr'],
			['logs', 'hello-pr-7', '--out', 'x'],
		];
		for (const argv of bad) {
			const r = await capture(argv, runtime);
			expect(r.code).toBe(2);
			expect(r.stdout).toBe('');
			expect(r.stderr).toStartWith('koi: ');
			expect(r.stderr).toEndWith(USAGE);
		}
		expect(runtime.calls).toEqual([]);
	});

	test('the usage names the verify commands', () => {
		expect(USAGE).toContain('verify plan NAME');
		expect(USAGE).toContain('verify run NAME');
		expect(USAGE).toContain('verify evidence RUN --out DIR');
		expect(USAGE).toContain('--profile NAME');
	});
});
