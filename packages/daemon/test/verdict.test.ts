import { describe, expect, test } from 'bun:test';
import { ResultSchema } from '@koi/shared';
import {
	type AssertionReport,
	escapeText,
	judgePoint,
	judgeReadiness,
	judgeRun,
	type PointInput,
	type PointVerdict,
	type ReadinessInput,
	type ReportInput,
	type ResolvedEvidence,
	renderComment,
	renderReport,
	withLostEvidence,
} from '../src/verdict.ts';

const RUN = 'r'.repeat(20);

// An artifact as a pass may use it: available, sanitized and verified.
function good(kind: string, over: Partial<ResolvedEvidence> = {}): ResolvedEvidence {
	return {
		kind,
		availability: 'available',
		redaction: 'sanitized',
		integrity: 'verified',
		...over,
	};
}

// A point with two assertions, each wanting a screenshot, and a run that
// holds the artifacts `held` names.
function point(
	reports: AssertionReport[],
	held: Record<string, ResolvedEvidence> = {
		'recorder:screenshot:1': good('screenshot'),
		'recorder:screenshot:2': good('screenshot'),
	},
	more: Partial<PointInput> = {},
): PointInput {
	return {
		id: 'app.save',
		assertions: [
			{ name: 'saved', evidence: ['screenshot'] },
			{ name: 'persists', evidence: ['screenshot'] },
		],
		reports,
		resolve: (ref) => held[ref],
		...more,
	};
}

const pass = (name: string, evidence = ['recorder:screenshot:1']): AssertionReport => ({
	name,
	outcome: 'pass',
	evidence,
});

describe('judgePoint', () => {
	test('passes when every assertion passes with available evidence of each declared kind', () => {
		const v = judgePoint(point([pass('saved'), pass('persists', ['recorder:screenshot:2'])]));
		expect(v).toEqual({
			id: 'app.save',
			outcome: 'pass',
			reasons: [],
			evidence: ['recorder:screenshot:1', 'recorder:screenshot:2'],
		});
	});

	test('an explicit failure fails the point, and keeps every other reason', () => {
		const v = judgePoint(
			point([{ name: 'saved', outcome: 'fail', evidence: [], detail: 'no row' }]),
		);
		expect(v.outcome).toBe('fail');
		// The other assertion never reported: that is kept too, after the
		// failure, in the table's order.
		expect(v.reasons).toEqual(['saved failed: no row', 'not_run: no terminal event for persists']);
	});

	test('every applicable condition is kept, and the outcome is the first row that applies', () => {
		const v = judgePoint(
			point(
				[
					{ name: 'saved', outcome: 'fail', evidence: [], detail: 'no row' },
					{ name: 'persists', outcome: 'needs-review', evidence: [] },
				],
				undefined,
				{ cleanup: 'failed', proofMissing: true, recovery: true },
			),
		);
		expect(v.outcome).toBe('fail');
		expect(v.reasons).toEqual([
			'saved failed: no row',
			'cleanup_failed: the required cleanup failed',
			'proof_missing: the point is required and has no proof at this revision',
			'persists needs review',
			'recovery: success needed a retry of failed behavior',
		]);
		// With no failure, the next row decides, and the later reasons stay.
		const review = judgePoint(
			point(
				[pass('saved'), { name: 'persists', outcome: 'needs-review', evidence: [] }],
				undefined,
				{
					recovery: true,
				},
			),
		);
		expect(review.outcome).toBe('needs-review');
		expect(review.reasons).toEqual([
			'persists needs review',
			'recovery: success needed a retry of failed behavior',
		]);
	});

	test('conflicting terminal events for one assertion fail it', () => {
		const v = judgePoint(
			point([pass('saved'), { name: 'saved', outcome: 'blocked', evidence: [] }, pass('persists')]),
		);
		expect(v.outcome).toBe('fail');
		expect(v.reasons).toContain('conflicting_assertion: saved reported blocked and pass');
	});

	test('a claimed pass whose evidence is missing, withheld or failed is a fail', () => {
		const cases: Array<[Record<string, ResolvedEvidence>, string]> = [
			[
				{},
				'missing_evidence: saved references recorder:screenshot:1, which this run does not hold',
			],
			[
				{ 'recorder:screenshot:1': good('screenshot', { availability: 'withheld' }) },
				'missing_evidence: saved references recorder:screenshot:1, which is withheld',
			],
			[
				{ 'recorder:screenshot:1': good('screenshot', { availability: 'failed' }) },
				'missing_evidence: saved references recorder:screenshot:1, which is failed',
			],
		];
		for (const [held, reason] of cases) {
			const v = judgePoint(point([pass('saved'), pass('persists')], held));
			expect(v.outcome).toBe('fail');
			expect(v.reasons).toContain(reason);
		}
	});

	test('a claimed pass over an artifact that is not sanitized, or whose bytes are not verified, is a fail', () => {
		const cases: Array<[Partial<ResolvedEvidence>, string]> = [
			[
				{ redaction: 'failed' },
				'unsafe_evidence: saved references recorder:screenshot:1, whose redaction failed',
			],
			[
				{ redaction: 'withheld' },
				'unsafe_evidence: saved references recorder:screenshot:1, whose redaction withheld',
			],
			[
				{ integrity: 'corrupt' },
				'corrupt_evidence: saved references recorder:screenshot:1, whose bytes do not hash to the manifest',
			],
			[
				{ integrity: 'missing' },
				'missing_evidence: saved references recorder:screenshot:1, whose bytes are not on disk',
			],
		];
		for (const [over, reason] of cases) {
			const v = judgePoint(
				point([pass('saved'), pass('persists', ['recorder:screenshot:2'])], {
					'recorder:screenshot:1': good('screenshot', over),
					'recorder:screenshot:2': good('screenshot'),
				}),
			);
			expect(v.outcome).toBe('fail');
			expect(v.reasons).toContain(reason);
			// What cannot support a pass is not listed as its evidence either.
			expect(v.evidence).toEqual(['recorder:screenshot:2']);
		}
	});

	test('a pass with evidence of the wrong kind lacks the declared kind and fails', () => {
		const v = judgePoint(
			point([pass('saved', ['recorder:aria:3']), pass('persists')], {
				'recorder:aria:3': good('aria'),
				'recorder:screenshot:1': good('screenshot'),
			}),
		);
		expect(v.outcome).toBe('fail');
		expect(v.reasons).toEqual(['missing_evidence: saved has no available screenshot evidence']);
	});

	test('what the host saw fails the point whatever the runner reported', () => {
		const v = judgePoint(
			point([pass('saved'), pass('persists', ['recorder:screenshot:2'])], undefined, {
				failures: ['runner_failed: the run step exited 1'],
			}),
		);
		expect(v.outcome).toBe('fail');
		expect(v.reasons).toEqual(['runner_failed: the run step exited 1']);
	});

	test('a failed cleanup fails the point even when every assertion passed', () => {
		const v = judgePoint(
			point([pass('saved'), pass('persists')], undefined, { cleanup: 'failed' }),
		);
		expect(v.outcome).toBe('fail');
		expect(v.reasons).toEqual(['cleanup_failed: the required cleanup failed']);
	});

	test('a cleanup that never ran fails the point too, unless the host blocked it first', () => {
		const v = judgePoint(
			point([pass('saved'), pass('persists')], undefined, { cleanup: 'not-run' }),
		);
		expect(v.outcome).toBe('fail');
		expect(v.reasons).toEqual(['cleanup_not_run: the required cleanup did not run']);
		for (const cleanup of ['succeeded', 'none'] as const) {
			expect(
				judgePoint(point([pass('saved'), pass('persists')], undefined, { cleanup })).outcome,
			).toBe('pass');
		}
		// Nothing ran on a point the host blocked, so there was nothing to
		// clean up; the block is the reason.
		const blocked = judgePoint(
			point([], undefined, { blocked: 'verifier_unavailable', cleanup: 'not-run' }),
		);
		expect(blocked.outcome).toBe('blocked');
		expect(blocked.reasons).toEqual(['verifier_unavailable']);
	});

	test('an assertion that never reported a terminal event makes the point not-run', () => {
		const v = judgePoint(point([pass('saved')]));
		expect(v.outcome).toBe('not-run');
		expect(v.reasons).toEqual(['not_run: no terminal event for persists']);
		// A reported not-run is not terminal.
		const reported = judgePoint(
			point([pass('saved'), { name: 'persists', outcome: 'not-run', evidence: [] }]),
		);
		expect(reported.outcome).toBe('not-run');
	});

	test('a failure is not hidden by a later missing assertion', () => {
		const v = judgePoint(point([{ name: 'saved', outcome: 'fail', evidence: [] }]));
		expect(v.outcome).toBe('fail');
		expect(v.reasons).toEqual(['saved failed', 'not_run: no terminal event for persists']);
	});

	test('a host-diagnosed block accounts for unstarted assertions, but a failure still wins', () => {
		const blocked = judgePoint(point([], undefined, { blocked: 'capability_missing:dns' }));
		expect(blocked).toEqual({
			id: 'app.save',
			outcome: 'blocked',
			reasons: ['capability_missing:dns'],
			evidence: [],
		});
		const failed = judgePoint(
			point([{ name: 'saved', outcome: 'fail', evidence: [] }], undefined, {
				blocked: 'capability_missing:dns',
			}),
		);
		expect(failed.outcome).toBe('fail');
		expect(failed.reasons).toEqual(['saved failed', 'capability_missing:dns']);
	});

	test('a block the runner reported is a claim, kept as blocked with the reason', () => {
		const v = judgePoint(
			point([
				{ name: 'saved', outcome: 'blocked', evidence: [], detail: 'no provider' },
				pass('persists'),
			]),
		);
		expect(v.outcome).toBe('blocked');
		expect(v.reasons).toEqual([
			'runner_blocked: saved reported blocked (no provider); a claim koid could not confirm',
		]);
	});

	test('a policy mismatch, a missing proof or a review request make the point needs-review', () => {
		const mismatch = judgePoint(
			point([pass('saved'), pass('persists')], undefined, {
				policyMismatch: 'runner home.sh differs from the approved digest',
			}),
		);
		expect(mismatch.outcome).toBe('needs-review');
		expect(mismatch.reasons).toEqual([
			'policy_mismatch: runner home.sh differs from the approved digest',
		]);
		const proof = judgePoint(
			point([pass('saved'), pass('persists')], undefined, { proofMissing: true }),
		);
		expect(proof.outcome).toBe('needs-review');
		const asked = judgePoint(
			point([pass('saved'), { name: 'persists', outcome: 'needs-review', evidence: [] }]),
		);
		expect(asked.outcome).toBe('needs-review');
		expect(asked.reasons).toEqual(['persists needs review']);
	});

	test('a pass that needed recovery stays apart from a clean pass', () => {
		const reported = judgePoint(
			point([
				pass('saved'),
				{ name: 'persists', outcome: 'pass-with-recovery', evidence: ['recorder:screenshot:2'] },
			]),
		);
		expect(reported.outcome).toBe('pass-with-recovery');
		expect(reported.reasons).toEqual(['persists passed after recovery']);
		const observed = judgePoint(
			point([pass('saved'), pass('persists')], undefined, { recovery: true }),
		);
		expect(observed.outcome).toBe('pass-with-recovery');
		expect(observed.reasons).toEqual(['recovery: success needed a retry of failed behavior']);
	});

	test('an event for an undeclared assertion satisfies nothing', () => {
		const v = judgePoint(point([pass('saved'), pass('persists'), pass('made-up')]));
		expect(v.outcome).toBe('pass');
		const only = judgePoint(point([pass('made-up')]));
		expect(only.outcome).toBe('not-run');
	});

	test('keeps the evidence the host captured whatever the outcome', () => {
		const v = judgePoint(
			point([], undefined, { blocked: 'verifier_unavailable', hostEvidence: ['recorder:aria:9'] }),
		);
		expect(v.evidence).toEqual(['recorder:aria:9']);
	});
});

describe('withLostEvidence', () => {
	const held: PointVerdict = {
		id: 'hello.home',
		outcome: 'blocked',
		reasons: ['verifier_unavailable'],
		evidence: ['recorder:screenshot:1', 'recorder:aria:2'],
	};

	test('nothing lost leaves the verdict as it was', () => {
		expect(withLostEvidence(held, [])).toEqual(held);
	});

	test('fails the point, names what was lost first and drops it from the evidence', () => {
		expect(
			withLostEvidence(held, [
				{ ref: 'recorder:screenshot:1', integrity: 'corrupt' },
				{ ref: 'recorder:aria:2', integrity: 'missing' },
			]),
		).toEqual({
			id: 'hello.home',
			outcome: 'fail',
			reasons: [
				'corrupt_evidence: recorder:screenshot:1, whose bytes do not hash to the manifest',
				'missing_evidence: recorder:aria:2, whose bytes are not on disk',
				'verifier_unavailable',
			],
			evidence: [],
		});
	});

	test('a passed point fails too', () => {
		const passed: PointVerdict = { ...held, outcome: 'pass', reasons: [] };
		const v = withLostEvidence(passed, [{ ref: 'recorder:aria:2', integrity: 'corrupt' }]);
		expect(v.outcome).toBe('fail');
		expect(v.evidence).toEqual(['recorder:screenshot:1']);
	});
});

const verdict = (id: string, outcome: PointVerdict['outcome'], reasons: string[] = []) => ({
	id,
	outcome,
	reasons,
	evidence: [],
});

describe('judgeRun', () => {
	test('passed only when the run was evaluated and every point passed', () => {
		const r = judgeRun({
			runId: RUN,
			completion: 'evaluated',
			points: [verdict('a', 'pass'), verdict('b', 'pass')],
			uncovered: [],
		});
		expect(r.outcome).toBe('passed');
		expect(r.result?.outcome).toBe('passed');
		expect(ResultSchema.parse(r.result)).toEqual(r.result as never);
	});

	test('failed when any point failed, whatever the others did', () => {
		const r = judgeRun({
			runId: RUN,
			completion: 'evaluated',
			points: [
				verdict('a', 'pass'),
				verdict('b', 'fail', ['x failed']),
				verdict('c', 'blocked', ['no']),
			],
			uncovered: [],
		});
		expect(r.outcome).toBe('failed');
		expect(r.result?.points.find((p) => p.id === 'b')?.reason).toBe('x failed');
	});

	test('incomplete when no point failed and one is blocked, not-run, needs-review or recovered', () => {
		for (const outcome of ['blocked', 'not-run', 'needs-review', 'pass-with-recovery'] as const) {
			const r = judgeRun({
				runId: RUN,
				completion: 'evaluated',
				points: [verdict('a', 'pass'), verdict('b', outcome, ['why'])],
				uncovered: ['src/x.ts'],
			});
			expect(r.outcome).toBe('incomplete');
			expect(r.result?.outcome).toBe('incomplete');
			expect(r.result?.uncovered).toEqual(['src/x.ts']);
		}
	});

	test('any other completion is incomplete with no Result, even over passed points', () => {
		for (const completion of ['cancelled', 'interrupted', 'capture-error', 'empty-plan'] as const) {
			const r = judgeRun({
				runId: RUN,
				completion,
				points: [verdict('a', 'pass')],
				uncovered: [],
			});
			expect(r).toEqual({ outcome: 'incomplete', result: null });
		}
	});

	test('an evaluated run with no point is incomplete with no Result', () => {
		expect(judgeRun({ runId: RUN, completion: 'evaluated', points: [], uncovered: [] })).toEqual({
			outcome: 'incomplete',
			result: null,
		});
	});

	test('a point that did not pass without a reason gets one, so the Result validates', () => {
		const r = judgeRun({
			runId: RUN,
			completion: 'evaluated',
			points: [verdict('a', 'blocked')],
			uncovered: [],
		});
		expect(r.result?.points[0]?.reason).toBe('no reason recorded');
	});
});

function readiness(over: Partial<ReadinessInput> = {}): ReadinessInput {
	return {
		outcome: 'passed',
		completion: 'evaluated',
		policy: { source: 'base-branch', required: [{ id: 'a', revision: 2 }] },
		planned: [{ id: 'a', revision: 2 }],
		points: [verdict('a', 'pass')],
		proofs: [{ pointId: 'a', revision: 2, status: 'verified' }],
		freshness: 'current',
		uncovered: [],
		cleanup: 'succeeded',
		advisory: false,
		...over,
	};
}

describe('judgeReadiness', () => {
	test('eligible only when every condition holds', () => {
		expect(judgeReadiness(readiness())).toEqual({ eligibleForMergeGate: true, reasons: [] });
	});

	test('names every failing condition', () => {
		const cases: Array<[Partial<ReadinessInput>, string]> = [
			[{ outcome: 'incomplete' }, 'the run incomplete'],
			[{ completion: 'interrupted' }, 'the run was not evaluated (interrupted)'],
			[
				{ advisory: true },
				'advisory run: an explicit subset, a dirty tree or no pull request context',
			],
			[
				{ policy: { source: 'none', required: [] } },
				'no required policy from the protected base branch (advisory rollout)',
			],
			[{ planned: [] }, 'required point a was not in the plan'],
			[
				{ planned: [{ id: 'a', revision: 1 }] },
				'required point a ran at revision 1, not the required 2',
			],
			[
				{ points: [verdict('a', 'blocked', ['x'])], outcome: 'incomplete' },
				'required point a is blocked',
			],
			[{ proofs: [] }, 'required point a has no proof at revision 2'],
			[
				{ proofs: [{ pointId: 'a', revision: 2, status: 'unverified' }] },
				'the proof of a at revision 2 is not verified',
			],
			[{ freshness: 'stale' }, 'the run is stale'],
			[{ uncovered: ['src/x.ts'] }, '1 uncovered change(s) without a maintainer disposition'],
			[{ cleanup: 'failed' }, 'cleanup failed'],
		];
		for (const [over, reason] of cases) {
			const r = judgeReadiness(readiness(over));
			expect(r.eligibleForMergeGate).toBe(false);
			expect(r.reasons).toContain(reason);
		}
	});

	test('a maintainer disposition covers the uncovered changes', () => {
		expect(
			judgeReadiness(readiness({ uncovered: ['src/x.ts'], uncoveredDisposition: true }))
				.eligibleForMergeGate,
		).toBe(true);
	});

	test('a passed subset never satisfies a required policy it omits', () => {
		const r = judgeReadiness(
			readiness({
				advisory: true,
				planned: [{ id: 'b', revision: 1 }],
				points: [verdict('b', 'pass')],
			}),
		);
		expect(r.eligibleForMergeGate).toBe(false);
		expect(r.reasons).toContain('required point a was not in the plan');
	});
});

function report(over: Partial<ReportInput> = {}): ReportInput {
	return {
		runId: RUN,
		outcome: 'incomplete',
		readiness: { eligibleForMergeGate: false, reasons: ['advisory rollout'] },
		commit: 'c'.repeat(40),
		head: 'h'.repeat(40),
		baseBranch: 'main',
		base: 'b'.repeat(40),
		deploymentId: 'd'.repeat(20),
		imageDigest: `sha256:${'1'.repeat(64)}`,
		planDigest: `sha256:${'2'.repeat(64)}`,
		executionDigest: `sha256:${'3'.repeat(64)}`,
		freshness: 'current',
		checkedAt: '2026-10-06T12:00:00.000Z',
		origin: 'http://app.rrrrrrrrrrrrrrrrrrrr.invalid:8080',
		points: [
			{
				id: 'hello.home',
				outcome: 'blocked',
				reason: 'verifier_unavailable: nothing ran',
				evidence: ['recorder:screenshot:1', 'recorder:aria:2'],
			},
		],
		exclusions: [],
		uncovered: ['src/app.ts'],
		recoveries: [],
		completion: 'evaluated',
		interruption: undefined,
		cleanup: 'succeeded',
		evidenceLink: undefined,
		retainedUntil: '2026-11-05T12:00:00.000Z',
		unavailable: [],
		label: 'hello-pr-7',
		profile: 'pr',
		...over,
	};
}

describe('renderComment', () => {
	test('fills the template literally', () => {
		expect(renderComment(report())).toBe(
			`<!-- koi-verification:${RUN} -->
## koi verification: incomplete

Run: ${RUN}. Verification policy satisfied: no (advisory rollout).
Tested commit: ${'c'.repeat(40)}.
PR head: ${'h'.repeat(40)}. Base: main at ${'b'.repeat(40)}.
Deployment: ${'d'.repeat(20)}. Image: sha256:${'1'.repeat(64)}.
Plan: sha256:${'2'.repeat(64)}. Execution: sha256:${'3'.repeat(64)}.
Freshness: current, checked at 2026-10-06T12:00:00.000Z.
Origin: http://app.rrrrrrrrrrrrrrrrrrrr.invalid:8080. Public ingress and TLS were not tested.

| Point | Outcome | Reason | Evidence |
|---|---|---|---|
| hello.home | blocked | verifier_unavailable: nothing ran | recorder:screenshot:1, recorder:aria:2 |

Exclusions: none.
Uncovered changes: src/app.ts.
Recovery and retries: none.
Completion: evaluated. Cleanup: succeeded.
Evidence: Not published. Export with koi verify evidence ${RUN} --out ./koi-evidence..
Retention: 2026-11-05T12:00:00.000Z. Unavailable artifacts: none.
Capture limits: Text and declared secret fields were filtered. Pixels, encoded secrets, and unknown application data cannot be certified secret-free. Unsafe artifacts were withheld.

Rerun: \`koi verify run hello-pr-7 --profile pr\`.
This run checks the declared preview points. CI and code-review approvals are separate.
`,
		);
	});

	test('says yes only when the policy is satisfied, and unavailable for a missing identity', () => {
		const text = renderComment(
			report({
				outcome: 'passed',
				readiness: { eligibleForMergeGate: true, reasons: [] },
				head: undefined,
				baseBranch: undefined,
				base: undefined,
				executionDigest: undefined,
				origin: undefined,
				completion: 'interrupted',
				interruption: 'koid_restarted',
				retainedUntil: undefined,
			}),
		);
		expect(text).toContain('## koi verification: passed\n');
		expect(text).toContain('Verification policy satisfied: yes.');
		expect(text).toContain('PR head: unavailable. Base: unavailable at unavailable.');
		expect(text).toContain('Execution: unavailable.');
		expect(text).toContain('Origin: unavailable.');
		expect(text).toContain('Completion: interrupted (koid_restarted). Cleanup: succeeded.');
		expect(text).toContain('Retention: unavailable.');
	});

	test('escapes project text: no mention, no markup, no table break', () => {
		const text = renderComment(
			report({
				points: [
					{
						id: 'hello.home',
						outcome: 'fail',
						reason: 'saw <b>@maintainer</b> | `rm -rf` [link](x)\nnext',
						evidence: [],
					},
				],
				uncovered: ['src/@x|y.ts'],
			}),
		);
		expect(text).toContain(
			'| hello.home | fail | saw &lt;b&gt;&#64;maintainer&lt;/b&gt; &#124; &#96;rm -rf&#96; &#91;link&#93;(x)\\x0anext | none |',
		);
		expect(text).toContain('Uncovered changes: src/&#64;x&#124;y.ts.');
		expect(text).not.toContain('@maintainer');
		expect(escapeText('x'.repeat(600), 10)).toBe('xxxxxxxxx…');
	});
});

describe('renderReport', () => {
	test('is the comment, then the reasons, problems and limitations', () => {
		const text = renderReport(report(), {
			problems: [
				{
					code: 'capture_failed',
					detail: 'screenshot point-opened: frames moved',
					at: '2026-10-06T12:00:01.000Z',
				},
			],
			limitations: ['pixels were not inspected'],
			reasons: [{ id: 'hello.home', reasons: ['verifier_unavailable: nothing ran'] }],
		});
		expect(text).toStartWith(`<!-- koi-verification:${RUN} -->`);
		expect(text).toContain('## Point reasons\n\n- hello.home: verifier_unavailable: nothing ran\n');
		expect(text).toContain(
			'## Problems\n\n- 2026-10-06T12:00:01.000Z capture_failed: screenshot point-opened: frames moved\n',
		);
		expect(text).toContain('## Capture limitations\n\n- pixels were not inspected\n');
		const empty = renderReport(report(), { problems: [], limitations: [], reasons: [] });
		expect(empty).toContain('## Problems\n\n- none\n');
	});

	const extra = (text: string) => ({
		problems: [{ code: text, detail: text, at: '2026-10-06T12:00:01.000Z' }],
		limitations: [text],
		reasons: [{ id: text, reasons: [text] }],
	});

	test('a file name cannot break the table, forge a section or send a control character', () => {
		const name = 'src/a.ts\n\n## Problems\n\n- none\n| `x` | y |\x1b]52;c;QUJD\x07\x9b31m';
		const filled = (text: string) => ({
			uncovered: [text],
			points: [{ id: 'hello.home', outcome: 'blocked' as const, reason: text, evidence: [text] }],
			interruption: text,
			completion: 'interrupted' as const,
			unavailable: [text],
		});
		const plain = renderReport(report(filled('src/a.ts')), extra('src/a.ts'));
		const text = renderReport(report(filled(name)), extra(name));
		const lines = text.split('\n');
		expect(lines.length).toBe(plain.split('\n').length);
		expect(lines.filter((l) => l.startsWith('#'))).toEqual(
			plain.split('\n').filter((l) => l.startsWith('#')),
		);
		expect(lines.filter((l) => l.startsWith('|')).length).toBe(3);
		expect(text.replaceAll('\n', '')).not.toMatch(/\p{Cc}/u);
		expect(text).toContain('src/a.ts\\x0a\\x0a## Problems\\x0a\\x0a- none');
		expect(text).toContain('&#124; &#96;x&#96; &#124; y &#124;\\x1b');
	});

	test('no string of the input reaches the report with a control character in it', () => {
		const hostile = '\x1b]52;c;QUJD\x07\x9b31m\r\n\u2028\u202e';
		const poisoned = <T>(value: T): T => {
			if (typeof value === 'string') return `${value}${hostile}` as T;
			if (Array.isArray(value)) return value.map(poisoned) as T;
			if (typeof value !== 'object' || value === null) return value;
			return Object.fromEntries(
				Object.entries(value).map(([key, field]) => [key, poisoned(field)]),
			) as T;
		};
		const full = report({
			completion: 'interrupted',
			interruption: 'koid_restarted',
			evidenceLink: 'https://koi.example/runs/1',
			exclusions: ['one'],
			recoveries: ['one'],
			unavailable: ['one'],
		});
		const plain = renderReport(full, extra('plain'));
		const text = renderReport(poisoned(full), poisoned(extra('plain')));
		expect(text.replaceAll('\n', '')).not.toMatch(/[\p{Cc}\u2028\u202e]/u);
		expect(text.split('\n').length).toBe(plain.split('\n').length);
	});
});
