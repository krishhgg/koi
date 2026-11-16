import {
	type Completion,
	escapeControls,
	type Outcome,
	type Readiness,
	type Result,
	ResultSchema,
	type RunOutcome,
} from '@koi/shared';

// The verdict rules (docs/verify.md, "Running a verification"; the design's
// point and run decision tables), as pure functions over what the host
// observed. Nothing here reads a file or asks a runner: the controller
// gathers the declared assertions, the assertion events, the artifacts and
// what it diagnosed itself, and this decides. A runner's own words are
// claims; only evidence koid holds counts.

// What a point declared: each assertion's name and the kinds of evidence
// it must show.
export interface DeclaredAssertion {
	name: string;
	evidence: string[];
}

// One assertion event, as the host accepted it from the runner.
export interface AssertionReport {
	name: string;
	outcome: Outcome;
	evidence: string[];
	detail?: string | undefined;
}

export type Availability = 'available' | 'withheld' | 'failed' | 'expired';

// What koid found when it checked an artifact's bytes on disk against its
// entry (verification-store.ts, artifactIntegrity): `verified` when they are
// the recorded size and hash to the recorded digest, `corrupt` when they are
// not, `missing` when there are none to check.
export type Integrity = 'verified' | 'corrupt' | 'missing';

// What an evidence reference resolves to in this run and point, or
// undefined when it names nothing koid holds. A pass takes only an
// artifact that is available, sanitized and verified: a withheld or failed
// redaction has no bytes a reviewer may see, and bytes that do not hash to
// the manifest prove nothing.
export interface ResolvedEvidence {
	kind: string;
	availability: Availability;
	redaction: 'sanitized' | 'withheld' | 'failed';
	integrity: Integrity;
}

export type EvidenceLookup = (ref: string) => ResolvedEvidence | undefined;

export interface PointInput {
	id: string;
	assertions: DeclaredAssertion[];
	reports: AssertionReport[];
	resolve: EvidenceLookup;
	// A block the host diagnosed: a missing capability, a provider it could
	// not register, an origin it cannot serve, a verifier it could not
	// start, a point stopped at its budget.
	blocked?: string | undefined;
	// What the host saw that fails the point whatever the runner reported: a
	// step that exited with an error, a protocol limit, a supervisor whose
	// summary contradicts the container's exit state.
	failures?: string[] | undefined;
	// How the point's cleanup ended; `none` when it declared none.
	cleanup?: 'succeeded' | 'failed' | 'not-run' | 'none' | undefined;
	// The host saw a recovery phase or a second attempt at failed behavior.
	recovery?: boolean | undefined;
	// The point's approved definition differs from the protected policy's.
	policyMismatch?: string | undefined;
	// The point is required and has no proof at its revision.
	proofMissing?: boolean | undefined;
	// Evidence koid captured on its own for the point, kept whatever the
	// outcome.
	hostEvidence?: string[] | undefined;
}

export interface PointVerdict {
	id: string;
	outcome: Outcome;
	// Every condition that applied, in the table's order. A failure is never
	// hidden by a later missing assertion.
	reasons: string[];
	evidence: string[];
}

// Outcomes that end an assertion. A reported `not-run` leaves it unreported.
const TERMINAL: ReadonlySet<Outcome> = new Set([
	'pass',
	'fail',
	'blocked',
	'needs-review',
	'pass-with-recovery',
]);

// The point decision table. Every condition is checked and every reason
// kept, in the table's order; the outcome is the first row that applies:
// fail, blocked (when the host diagnosed it, which accounts for assertions
// that never started), not-run, blocked (as the runner claimed it),
// needs-review, pass-with-recovery, pass. A reader of the reasons sees
// what else was wrong with a failed point, not only the failure.
export function judgePoint(input: PointInput): PointVerdict {
	const declared = new Map(input.assertions.map((a) => [a.name, a]));
	// An event for an undeclared assertion is a protocol violation, not a
	// declaration: it satisfies nothing and decides nothing.
	const reports = input.reports.filter((r) => declared.has(r.name));
	const evidence = new Set<string>(input.hostEvidence ?? []);

	// Row one: failures, the host's first.
	const failures: string[] = [...(input.failures ?? [])];
	for (const r of reports) {
		if (r.outcome === 'fail') failures.push(`${r.name} failed${r.detail ? `: ${r.detail}` : ''}`);
	}
	for (const [name] of declared) {
		const outcomes = new Set(
			reports.filter((r) => r.name === name && TERMINAL.has(r.outcome)).map((r) => r.outcome),
		);
		if (outcomes.size > 1) {
			failures.push(
				`conflicting_assertion: ${name} reported ${[...outcomes].sort().join(' and ')}`,
			);
		}
	}
	for (const r of reports) {
		if (r.outcome !== 'pass' && r.outcome !== 'pass-with-recovery') continue;
		const kinds = new Set<string>();
		for (const ref of r.evidence) {
			const found = input.resolve(ref);
			const problem = evidenceProblem(found);
			if (problem !== undefined) {
				failures.push(`${problem.code}: ${r.name} references ${ref}, ${problem.detail}`);
			} else if (found !== undefined) {
				kinds.add(found.kind);
				evidence.add(ref);
			}
		}
		for (const kind of declared.get(r.name)?.evidence ?? []) {
			if (!kinds.has(kind)) {
				failures.push(`missing_evidence: ${r.name} has no available ${kind} evidence`);
			}
		}
	}
	if (input.cleanup === 'failed') failures.push('cleanup_failed: the required cleanup failed');
	// Cleanup that never ran leaves the app as the journey left it, which is
	// a failure whatever the assertions said: approved cleanup must succeed
	// for a pass. A point the host blocked never started, so there was
	// nothing to clean up, and its block stands as the reason.
	if (input.cleanup === 'not-run' && input.blocked === undefined) {
		failures.push('cleanup_not_run: the required cleanup did not run');
	}

	// Row two: a block the host diagnosed.
	const hostBlocked = input.blocked === undefined ? [] : [input.blocked];

	// Row three: assertions with no terminal event. A host-diagnosed block
	// accounts for them: nothing could have run.
	const unreported = [...declared.keys()].filter(
		(name) => !reports.some((r) => r.name === name && TERMINAL.has(r.outcome)),
	);
	const notRun =
		unreported.length > 0 && input.blocked === undefined
			? [`not_run: no terminal event for ${unreported.join(', ')}`]
			: [];

	// Row four: a block the runner claimed.
	const claimedBlocked = reports
		.filter((r) => r.outcome === 'blocked')
		.map(
			(r) =>
				`runner_blocked: ${r.name} reported blocked${r.detail ? ` (${r.detail})` : ''}; a claim koid could not confirm`,
		);

	// Row five: review.
	const review: string[] = [];
	if (input.policyMismatch !== undefined) review.push(`policy_mismatch: ${input.policyMismatch}`);
	if (input.proofMissing === true)
		review.push('proof_missing: the point is required and has no proof at this revision');
	for (const r of reports) {
		if (r.outcome === 'needs-review') {
			review.push(`${r.name} needs review${r.detail ? `: ${r.detail}` : ''}`);
		}
	}

	// Row six: recovery.
	const recovery: string[] = [];
	const recovered = reports.filter((r) => r.outcome === 'pass-with-recovery');
	for (const r of recovered) recovery.push(`${r.name} passed after recovery`);
	if (input.recovery === true && recovered.length === 0) {
		recovery.push('recovery: success needed a retry of failed behavior');
	}

	const rows: Array<[Outcome, string[]]> = [
		['fail', failures],
		['blocked', hostBlocked],
		['not-run', notRun],
		['blocked', claimedBlocked],
		['needs-review', review],
		['pass-with-recovery', recovery],
	];
	const outcome = rows.find(([, reasons]) => reasons.length > 0)?.[0] ?? 'pass';
	return {
		id: input.id,
		outcome,
		reasons: rows.flatMap(([, reasons]) => reasons),
		evidence: [...evidence],
	};
}

// Evidence koid held for a point whose bytes on disk failed the check against
// their entry, and how.
export interface LostEvidence {
	ref: string;
	integrity: Exclude<Integrity, 'verified'>;
}

// A verdict once evidence it holds has failed that check. Row one of the
// point table: nothing that rests on those bytes can stand, whatever else the
// point was, and the verdict no longer holds them. The controller applies this
// whenever it finds out, so a file that changes after its point was judged
// counts the same as one that changed before.
export function withLostEvidence(verdict: PointVerdict, lost: LostEvidence[]): PointVerdict {
	if (lost.length === 0) return verdict;
	const refs = new Set(lost.map((l) => l.ref));
	return {
		...verdict,
		outcome: 'fail',
		reasons: [
			...lost.map(({ ref, integrity }) => {
				const { code, detail } = INTEGRITY_PROBLEMS[integrity];
				return `${code}: ${ref}, ${detail}`;
			}),
			...verdict.reasons,
		],
		evidence: verdict.evidence.filter((ref) => !refs.has(ref)),
	};
}

const INTEGRITY_PROBLEMS = {
	corrupt: { code: 'corrupt_evidence', detail: 'whose bytes do not hash to the manifest' },
	missing: { code: 'missing_evidence', detail: 'whose bytes are not on disk' },
} as const;

// Why a reference cannot support a pass, or undefined when it can.
function evidenceProblem(
	found: ResolvedEvidence | undefined,
): { code: string; detail: string } | undefined {
	if (found === undefined) {
		return { code: 'missing_evidence', detail: 'which this run does not hold' };
	}
	if (found.availability !== 'available') {
		return { code: 'missing_evidence', detail: `which is ${found.availability}` };
	}
	if (found.redaction !== 'sanitized') {
		return { code: 'unsafe_evidence', detail: `whose redaction ${found.redaction}` };
	}
	return found.integrity === 'verified' ? undefined : INTEGRITY_PROBLEMS[found.integrity];
}

export interface RunInput {
	runId: string;
	completion: Completion;
	points: PointVerdict[];
	uncovered: string[];
}

export interface RunVerdict {
	outcome: RunOutcome;
	// A validated Result for an evaluated run with at least one point; null
	// otherwise. A manifest without one can never satisfy readiness.
	result: Result | null;
}

// The run decision table. Only a normal finalization is evaluated; any
// other completion is incomplete with no Result, whatever the points said.
export function judgeRun(input: RunInput): RunVerdict {
	if (input.completion !== 'evaluated' || input.points.length === 0) {
		return { outcome: 'incomplete', result: null };
	}
	const failed = input.points.some((p) => p.outcome === 'fail');
	const notPassed = input.points.some((p) => p.outcome !== 'pass');
	const outcome: RunOutcome = failed ? 'failed' : notPassed ? 'incomplete' : 'passed';
	const result = ResultSchema.parse({
		version: 1,
		runId: input.runId,
		outcome,
		points: input.points.map((p) => ({
			id: p.id,
			outcome: p.outcome,
			...(p.outcome === 'pass' ? {} : { reason: reasonText(p.reasons) }),
			evidence: p.evidence,
		})),
		uncovered: input.uncovered,
	});
	return { outcome, result };
}

// A point's reasons as one bounded string for the Result.
export function reasonText(reasons: string[]): string {
	const text = reasons.join('; ');
	return (text === '' ? 'no reason recorded' : text).slice(0, 2000);
}

export interface ReadinessInput {
	outcome: RunOutcome | undefined;
	completion: Completion | undefined;
	policy: {
		source: 'base-branch' | 'none';
		required: Array<{ id: string; revision: number }>;
	};
	// The points the plan took, with the revision each was taken at.
	planned: Array<{ id: string; revision: number }>;
	points: PointVerdict[];
	proofs: Array<{ pointId: string; revision: number; status: 'verified' | 'unverified' | 'none' }>;
	freshness: 'current' | 'stale' | 'unknown';
	uncovered: string[];
	// A protected maintainer said the uncovered changes need no point.
	uncoveredDisposition?: boolean | undefined;
	cleanup: 'succeeded' | 'failed' | 'unknown';
	// An explicit subset, a dirty tree, or a build with no pull request.
	advisory: boolean;
}

// The readiness column of the run table: every condition that keeps a run
// from satisfying the declared verification policy, and true only when
// none applies. Selection and requirement are separate: a required point
// absent from the plan fails readiness however the selected points did.
export function judgeReadiness(input: ReadinessInput): Readiness {
	const reasons: string[] = [];
	if (input.completion !== 'evaluated') {
		reasons.push(`the run was not evaluated (${input.completion ?? 'not finished'})`);
	} else if (input.outcome !== 'passed') {
		reasons.push(`the run ${input.outcome ?? 'has no outcome'}`);
	}
	if (input.advisory)
		reasons.push('advisory run: an explicit subset, a dirty tree or no pull request context');
	if (input.policy.source !== 'base-branch') {
		reasons.push('no required policy from the protected base branch (advisory rollout)');
	}
	const judged = new Map(input.points.map((p) => [p.id, p]));
	const planned = new Map(input.planned.map((p) => [p.id, p.revision]));
	for (const required of input.policy.required) {
		const revision = planned.get(required.id);
		if (revision === undefined) {
			reasons.push(`required point ${required.id} was not in the plan`);
			continue;
		}
		if (revision !== required.revision) {
			reasons.push(
				`required point ${required.id} ran at revision ${revision}, not the required ${required.revision}`,
			);
		}
		const verdict = judged.get(required.id);
		if (verdict === undefined) reasons.push(`required point ${required.id} was not judged`);
		else if (verdict.outcome !== 'pass') {
			reasons.push(`required point ${required.id} is ${verdict.outcome}`);
		}
		const proof = input.proofs.find(
			(p) => p.pointId === required.id && p.revision === required.revision,
		);
		if (proof === undefined || proof.status === 'none') {
			reasons.push(`required point ${required.id} has no proof at revision ${required.revision}`);
		} else if (proof.status !== 'verified') {
			reasons.push(`the proof of ${required.id} at revision ${required.revision} is not verified`);
		}
	}
	if (input.freshness !== 'current') reasons.push(`the run is ${input.freshness}`);
	if (input.uncovered.length > 0 && input.uncoveredDisposition !== true) {
		reasons.push(`${input.uncovered.length} uncovered change(s) without a maintainer disposition`);
	}
	if (input.cleanup !== 'succeeded') reasons.push(`cleanup ${input.cleanup}`);
	return { eligibleForMergeGate: reasons.length === 0, reasons: reasons.slice(0, 50) };
}

// -- The PR comment and the report -------------------------------------------

export interface ReportInput {
	runId: string;
	outcome: RunOutcome;
	readiness: Readiness;
	commit: string;
	head: string | undefined;
	baseBranch: string | undefined;
	base: string | undefined;
	deploymentId: string;
	imageDigest: string;
	planDigest: string;
	executionDigest: string | undefined;
	freshness: 'current' | 'stale' | 'unknown';
	checkedAt: string;
	origin: string | undefined;
	points: Array<{
		id: string;
		outcome: Outcome | undefined;
		reason: string | undefined;
		evidence: string[];
	}>;
	exclusions: string[];
	uncovered: string[];
	recoveries: string[];
	completion: Completion | undefined;
	interruption: string | undefined;
	cleanup: 'succeeded' | 'failed' | 'unknown';
	// An authenticated report link, or undefined to print the export
	// instruction instead.
	evidenceLink: string | undefined;
	retainedUntil: string | undefined;
	unavailable: string[];
	label: string;
	profile: string;
}

// Project-controlled text as it may appear in a comment: no mention, no
// markup, no table break, no control character, and bounded. Entities
// render as the characters and `&#64;` is no mention. A newline in a file
// name shows as \x0a, so it can neither start a section nor pass for a space.
export function escapeText(text: string, max = 500): string {
	const plain = escapeControls(text);
	const cut = plain.length > max ? `${plain.slice(0, max - 1)}…` : plain;
	return cut
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/\|/g, '&#124;')
		.replace(/@/g, '&#64;')
		.replace(/`/g, '&#96;')
		.replace(/\[/g, '&#91;')
		.replace(/\]/g, '&#93;');
}

const NONE = 'none';

function list(items: string[]): string {
	return items.length === 0 ? NONE : items.map((i) => escapeText(i)).join(', ');
}

function orUnavailable(value: string | undefined): string {
	return value === undefined || value === '' ? 'unavailable' : escapeText(value, 200);
}

export const COMMENT_MARKER_PREFIX = 'koi-verification';

// The pull request comment, filled literally from the template. One
// comment per run; the hidden marker is for finding it again.
export function renderComment(r: ReportInput): string {
	const rows = r.points.map(
		(p) =>
			`| ${escapeText(p.id, 100)} | ${p.outcome ?? 'pending'} | ${p.reason === undefined ? '-' : escapeText(p.reason)} | ${p.evidence.length === 0 ? NONE : p.evidence.map((e) => escapeText(e, 100)).join(', ')} |`,
	);
	const completion =
		r.completion === 'evaluated' || r.completion === undefined
			? (r.completion ?? 'not finished')
			: `${r.completion}${r.interruption === undefined ? '' : ` (${escapeText(r.interruption, 300)})`}`;
	const evidence =
		r.evidenceLink ??
		`Not published. Export with koi verify evidence ${r.runId} --out ./koi-evidence.`;
	return [
		`<!-- ${COMMENT_MARKER_PREFIX}:${r.runId} -->`,
		`## koi verification: ${r.outcome}`,
		'',
		`Run: ${r.runId}. Verification policy satisfied: ${r.readiness.eligibleForMergeGate ? 'yes' : `no (${list(r.readiness.reasons)})`}.`,
		`Tested commit: ${r.commit}.`,
		`PR head: ${orUnavailable(r.head)}. Base: ${orUnavailable(r.baseBranch)} at ${orUnavailable(r.base)}.`,
		`Deployment: ${r.deploymentId}. Image: ${r.imageDigest}.`,
		`Plan: ${r.planDigest}. Execution: ${orUnavailable(r.executionDigest)}.`,
		`Freshness: ${r.freshness}, checked at ${r.checkedAt}.`,
		`Origin: ${orUnavailable(r.origin)}. Public ingress and TLS were not tested.`,
		'',
		'| Point | Outcome | Reason | Evidence |',
		'|---|---|---|---|',
		...rows,
		'',
		`Exclusions: ${list(r.exclusions)}.`,
		`Uncovered changes: ${list(r.uncovered)}.`,
		`Recovery and retries: ${list(r.recoveries)}.`,
		`Completion: ${completion}. Cleanup: ${r.cleanup}.`,
		`Evidence: ${evidence}.`,
		`Retention: ${orUnavailable(r.retainedUntil)}. Unavailable artifacts: ${list(r.unavailable)}.`,
		'Capture limits: Text and declared secret fields were filtered. Pixels, encoded secrets, and unknown application data cannot be certified secret-free. Unsafe artifacts were withheld.',
		'',
		`Rerun: \`koi verify run ${r.label} --profile ${r.profile}\`.`,
		'This run checks the declared preview points. CI and code-review approvals are separate.',
		'',
	]
		.map(escapeControls)
		.join('\n');
}

// runs/<runId>/report.md: the comment, then what the comment leaves out.
export function renderReport(
	r: ReportInput,
	extra: {
		problems: Array<{ code: string; detail: string; at: string }>;
		limitations: string[];
		reasons: Array<{ id: string; reasons: string[] }>;
	},
): string {
	const lines = ['## Point reasons', ''];
	for (const p of extra.reasons) {
		lines.push(
			`- ${escapeText(p.id, 100)}: ${p.reasons.length === 0 ? NONE : p.reasons.map((x) => escapeText(x, 1000)).join('; ')}`,
		);
	}
	if (extra.reasons.length === 0) lines.push(`- ${NONE}`);
	lines.push('', '## Problems', '');
	for (const p of extra.problems) {
		lines.push(`- ${p.at} ${escapeText(p.code, 64)}: ${escapeText(p.detail, 1000)}`);
	}
	if (extra.problems.length === 0) lines.push(`- ${NONE}`);
	lines.push('', '## Capture limitations', '');
	for (const l of extra.limitations) lines.push(`- ${escapeText(l, 500)}`);
	if (extra.limitations.length === 0) lines.push(`- ${NONE}`);
	lines.push('');
	return `${renderComment(r)}\n${lines.map(escapeControls).join('\n')}`;
}
