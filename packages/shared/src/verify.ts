import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { type FileHandle, lstat, open, readdir } from 'node:fs/promises';
import { join, posix } from 'node:path';
import { z } from 'zod';
import { GlobWork, globProblem } from './glob.ts';
import { RelativePathSchema } from './paths.ts';
import { type DeploymentSource, PreviewLabelSchema, type PreviewRecord } from './preview.ts';
import { ProviderIdSchema } from './providers.ts';
import { CommitSchema } from './request.ts';

// The files a project puts under .koi/ to say what koi should check on a
// preview, and the records koi writes when it checks them. The project's
// files come from the pull request, so every schema here is strict: an
// unknown key is an error, a command is an argument array, and a path stays
// inside .koi/. The loader at the end reads a tree's files and applies the
// checks a schema cannot make on its own. See docs/verify.md.
//
// The runner protocol at the end (events, acknowledgments, the supervisor's
// own lines) is what the verifier container speaks with koid
// (packages/daemon/src/verifier.ts, host/verifier/).

// Where a project keeps its koi files, relative to the source root, and the
// manifest inside it.
export const KOI_DIR = '.koi';
export const VERIFY_MANIFEST = 'verify.yaml';

// The most a file the loader reads may hold. Points and manifests are a few
// kilobytes; anything near this is a mistake or an attempt to fill memory.
export const MAX_VERIFY_FILE_BYTES = 256 * 1024;

// A point's id: lowercase words in segments joined by dots, like
// app.canvas.save. It is permanent, so a file may be renamed and the id keeps
// its history.
export const POINT_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)*$/;

export const PointIdSchema = z
	.string()
	.max(100)
	.regex(
		POINT_ID,
		'lowercase words joined by dashes, in segments joined by dots, like app.canvas.save',
	);

// A short name: an assertion, a profile, a skill, a capture label.
export const SlugSchema = z
	.string()
	.max(64)
	.regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'lowercase letters and digits in dash-separated words');

// A name the project and koi agree on outside these files: a service, a
// network policy, a kind of evidence. Some projects name services with
// underscores.
const NameSchema = z
	.string()
	.max(64)
	.regex(/^[a-z0-9][a-z0-9_.-]*$/, 'lowercase letters, digits, dots, dashes and underscores');

// The most free text koi keeps may hold, in the units a JavaScript string's
// length counts (UTF-16), since that is what the schema below checks.
export const TEXT_MAX = 2000;

// Free text koi keeps: a reason, a selection note, an uncovered path.
export const TextSchema = z.string().min(1).max(TEXT_MAX);

// `text` with each control character written out as an escape a reader can see: ESC as
// \x1b, a newline as \x0a. A file name comes from the pull request and can hold anything
// but a NUL, so shown as it is it could erase or forge what a reviewer reads, or, where a
// terminal allows OSC 52, replace the clipboard. C0, DEL and C1 are the control characters.
// The line separators and the explicit bidi controls go too: they can break a line or
// reorder one without being control characters.
export function escapeControls(text: string): string {
	return text.replace(/[\p{Cc}\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu, (char) => {
		const code = char.charCodeAt(0);
		return code > 0xff ? `\\u${code.toString(16)}` : `\\x${code.toString(16).padStart(2, '0')}`;
	});
}

// A path inside .koi/, written relative to it: points/save.yaml,
// fixtures/probe.txt, or a glob such as points/*.yaml. Parsing drops "."
// segments and repeated slashes. The loader joins it to .koi/ and checks
// that what is there is a real file inside .koi/.
export const KoiPathSchema = z
	.string()
	.min(1)
	.max(255)
	.refine((p) => !/\p{Cc}/u.test(p), 'must not contain control characters')
	.refine((p) => !p.includes('\\'), 'must use forward slashes')
	.refine((p) => !p.startsWith('/'), 'must be relative to .koi/, not absolute')
	.refine((p) => !p.split('/').includes('..'), 'must not contain a .. segment')
	.transform((p) =>
		p
			.split('/')
			.filter((segment) => segment !== '' && segment !== '.')
			.join('/'),
	)
	.refine((p) => p !== '', 'must name a file inside .koi/');

// A program and its arguments, as koi will pass them to exec: never a line a
// shell reads. A control character in an argument is a mistake or a trick.
export const CommandSchema = z
	.array(
		z
			.string()
			.min(1)
			.max(4096)
			.refine((a) => !/\p{Cc}/u.test(a), 'must not contain control characters'),
	)
	.min(1);

// A Docker image reference: busybox:1.37, ghcr.io/acme/runner@sha256:....
// Syntax only; which images a host lets a runner use is its policy.
export const ImageRefSchema = z
	.string()
	.min(1)
	.max(255)
	.regex(
		/^[A-Za-z0-9][A-Za-z0-9._:/@-]*$/,
		'a Docker image reference, like ghcr.io/acme/runner:1.2',
	);

// A glob in the grammar glob.ts matches. The check runs before the path rules, so a
// backslash gets the message that says what a glob may hold. It runs again after them, as
// dropping a leading `./` can expose a `!`.
function globSchema<T extends z.ZodType<string, string>>(path: T) {
	const check = (glob: string, ctx: z.RefinementCtx) => {
		const problem = globProblem(glob);
		if (problem !== undefined) ctx.addIssue({ code: 'custom', message: problem });
	};
	return z.string().superRefine(check).pipe(path).superRefine(check);
}

// A glob of `select.paths`, relative to the source root.
const SelectGlobSchema = globSchema(RelativePathSchema);

// The most point globs a manifest lists. A project has a few. Each runs over every file
// under .koi/, and the snapshot lets .koi/ hold 2,000.
export const MANIFEST_GLOBS_MAX = 200;

// What one plan may match, checked before any glob runs (docs/verify.md, "Planning
// limits"). A plan over one is refused, so no point is left out without a word.
// GLOB_STEP_BUDGET bounds the matching itself.
export const PLAN_LIMITS = {
	// 1 MiB of names, the snapshot's bound, comes to about this many real ones.
	changedFiles: 20_000,
	// PATH_MAX on Linux. A longer path cannot be checked out.
	changedNameChars: 4096,
	// Across all points: 2,000 point files, the most .koi/ holds, at 2.5 each.
	globs: 5000,
} as const;

// sha256 of some bytes, as koi writes digests everywhere.
export const DigestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/);

// Plan, run and deployment ids: the alphabet of request ids, safe in a file
// name and on a command line.
export const VerifyIdSchema = z.string().regex(/^[a-z0-9]{16,40}$/);

// A reference to evidence koi holds: a capture, an artifact, a read of the
// app's state. The exact forms come with the recorder.
const EvidenceRefSchema = z
	.string()
	.min(1)
	.max(255)
	.refine((e) => !/\p{Cc}/u.test(e), 'must not contain control characters');

const RevisionSchema = z.number().int().positive();

// Time and request limits. A point's budgets go over the manifest's.
export const BudgetsSchema = z.strictObject({
	timeoutSeconds: z.number().int().positive().max(3600).optional(),
	// Requests to an LLM provider, the ones that cost money.
	maxRequests: z.number().int().positive().optional(),
});

// -- .koi/verify.yaml ---------------------------------------------------------

export const SkillRefSchema = z.strictObject({
	id: SlugSchema,
	// The skill's SKILL.md, inside .koi/.
	path: KoiPathSchema,
});

// Which points a run takes. `always` lists points every run of the profile
// takes; `select: changed` adds the points whose select.paths match what the
// pull request changed; `include` adds points by id for a profile that is
// about them (a provider matrix). None of this makes a point required: the
// required set is policy on the base branch (RequiredPolicySchema).
export const ProfileSchema = z.strictObject({
	always: z.array(PointIdSchema).default([]),
	select: z.enum(['changed', 'none']).default('none'),
	include: z.array(PointIdSchema).default([]),
});

// The reference a manifest's runner.image uses for the box's default
// verifier image (host/verifier), which the operator builds and names in
// KOI_VERIFIER_IMAGE. koid never pulls an image a pull request names; any
// other reference must be on the box and on the operator's allowlist.
export const DEFAULT_VERIFIER_IMAGE = 'koi-verifier';

export const RunnerSchema = z.strictObject({
	image: ImageRefSchema,
	// An argv prefix put before each step's command: the step's argv is
	// appended to it. Absent, the step's command runs as it is.
	command: CommandSchema.optional(),
});

// What koi does with changed files no point selects: suggest a point from
// the diff, or nothing; and what the gap counts as.
export const FallbackSchema = z.strictObject({
	mode: z.enum(['suggest', 'off']),
	onUnmapped: z.enum(['needs-review', 'blocked']),
});

export const VerifyManifestSchema = z
	.strictObject({
		version: z.literal(1),
		skills: z.array(SkillRefSchema).default([]),
		// Globs, relative to .koi/, for the point files.
		points: z.array(globSchema(KoiPathSchema)).min(1).max(MANIFEST_GLOBS_MAX),
		profiles: z.record(SlugSchema, ProfileSchema),
		runner: RunnerSchema,
		budgets: BudgetsSchema.optional(),
		fallback: FallbackSchema.optional(),
	})
	.refine((m) => new Set(m.skills.map((s) => s.id)).size === m.skills.length, {
		message: 'skill ids are unique',
		path: ['skills'],
	});

export type VerifyManifest = z.infer<typeof VerifyManifestSchema>;

// -- .koi/points/*.yaml -------------------------------------------------------

// When a point is taken: for every run of a profile that selects by change
// when `always`, or when a changed file matches one of `paths` (globs
// relative to the source root). List the callers and consumers of a feature,
// not only its directory.
export const SelectSchema = z
	.strictObject({
		paths: z.array(SelectGlobSchema),
		always: z.boolean().optional(),
	})
	.refine((s) => s.paths.length > 0 || s.always === true, {
		message: 'needs at least one path, or always: true',
		path: ['paths'],
	});

// What a point needs from the preview and the host. These are requests the
// host checks against its policy, not grants: a point that asks for what the
// host does not give is blocked, with the reason.
export const RequiresSchema = z.strictObject({
	services: z.array(NameSchema).optional(),
	// Files inside .koi/ the runner is given.
	fixtures: z.array(KoiPathSchema).optional(),
	browser: z.boolean().optional(),
	// A real LLM provider, through a reviewer's registered key.
	provider: ProviderIdSchema.optional(),
	// A named network policy beyond the preview itself.
	network: NameSchema.optional(),
});

// A step of a point: the program to run, and the files under .koi/ it
// depends on. The loader finds the files a command names on its own; `files`
// is for what a command reaches another way, a module it imports or a
// fixture it opens, so that a change to one shows in the point's runner
// digests (see LoadedPoint).
export const StepSchema = z.strictObject({
	command: CommandSchema,
	files: z.array(KoiPathSchema).optional(),
});

// One thing the runner must show, by name, and the kinds of evidence it
// must show it with. koi computes the point's outcome from these; a runner
// cannot report a point verdict.
export const AssertionSchema = z.strictObject({
	name: SlugSchema,
	description: TextSchema,
	evidence: z.array(NameSchema).min(1),
});

export const PointSchema = z
	.strictObject({
		id: PointIdSchema,
		// Raised when the claim or the assertions change. koi also hashes the
		// file, so a forgotten bump still shows as a change.
		revision: RevisionSchema,
		// The user outcome, in one sentence a reviewer can disagree with.
		claim: TextSchema,
		// The feature this point belongs to, usually the skill's feature file.
		feature: z.string().min(1).max(255).optional(),
		select: SelectSchema,
		requires: RequiresSchema.optional(),
		setup: StepSchema.optional(),
		run: StepSchema,
		cleanup: StepSchema.optional(),
		assertions: z.array(AssertionSchema).min(1),
		budgets: BudgetsSchema.optional(),
	})
	.refine((p) => new Set(p.assertions.map((a) => a.name)).size === p.assertions.length, {
		message: 'assertion names are unique',
		path: ['assertions'],
	});

export type Point = z.infer<typeof PointSchema>;

// -- What a run produces ------------------------------------------------------

// A point's outcome, as koi decides it from the assertions that reported.
// An assertion that never reported makes the point not-run.
export const OutcomeSchema = z.enum([
	'pass',
	'fail',
	'blocked',
	'not-run',
	'needs-review',
	'pass-with-recovery',
]);

export type Outcome = z.infer<typeof OutcomeSchema>;

// What a runner prints, one JSON object per line. Anything else on stdout is
// kept as the runner's log and means nothing to koi. A capture and a read
// ask the recorder, through koid, for evidence; koid answers on the
// runner's stdin with a RunnerAck naming the artifact, and the runner cites
// that artifact in an assertion's evidence (docs/verify.md, "Writing a
// runner"). A read is the one event the design's four did not have: it is
// how a runner gets an http-response artifact, the recorder's own record of
// what the app served at a path, which no capture of the page can give.
export const RunnerEventSchema = z.discriminatedUnion('type', [
	z.strictObject({
		type: z.literal('assertion'),
		point: PointIdSchema,
		name: SlugSchema,
		outcome: OutcomeSchema,
		evidence: z.array(EvidenceRefSchema),
		detail: z.string().max(4000).optional(),
	}),
	z.strictObject({
		type: z.literal('capture'),
		kind: z.enum(['screenshot', 'trace', 'har', 'aria', 'file']),
		label: SlugSchema,
	}),
	z.strictObject({
		type: z.literal('read'),
		label: SlugSchema,
		// A path on the app's origin, requested by the recorder from inside
		// the point's context.
		path: z.string().startsWith('/').max(2048),
		method: z.enum(['GET', 'HEAD']).optional(),
	}),
	z.strictObject({
		type: z.literal('note'),
		text: z.string().max(4000),
	}),
	z.strictObject({
		type: z.literal('phase'),
		name: z.enum(['setup', 'journey', 'recovery', 'cleanup']),
		state: z.enum(['start', 'end']),
	}),
]);

export type RunnerEvent = z.infer<typeof RunnerEventSchema>;

// -- The runner protocol's other lines -----------------------------------------

export const RUNNER_PROTOCOL_VERSION = 1;

// A stable code for why a capture or a read gave no artifact.
const AckErrorSchema = z
	.string()
	.max(64)
	.regex(/^[a-z][a-z0-9_]*$/);

// What koid writes to the verifier's stdin, one JSON object per line. `start`
// is the first line, once the firewall has bound the run's permits to the
// container's bridge port; the supervisor runs nothing before it, keeps it to
// itself, and signs its own lines with its key. It says how many seconds the
// point has left: opening its context and staging its inputs came out of the
// budget, and only here does koid know what they took. The supervisor forwards
// every later line to the running step's stdin. A capture-result answers a
// capture or a read by its label: only `ready` carries an artifact reference.
export const RunnerAckSchema = z.discriminatedUnion('type', [
	z.strictObject({
		version: z.literal(RUNNER_PROTOCOL_VERSION),
		type: z.literal('start'),
		key: z.string().regex(/^[0-9a-f]{64}$/),
		timeoutSeconds: z.number().positive(),
	}),
	z
		.strictObject({
			version: z.literal(RUNNER_PROTOCOL_VERSION),
			type: z.literal('capture-result'),
			label: SlugSchema,
			status: z.enum(['ready', 'failed']),
			artifact: z
				.string()
				.regex(/^recorder:[a-z-]+:[1-9][0-9]*$/)
				.optional(),
			error: AckErrorSchema.optional(),
		})
		.refine((a) => (a.status === 'ready') === (a.artifact !== undefined), {
			message: 'a ready result names its artifact, and only a ready one does',
			path: ['artifact'],
		})
		.refine((a) => (a.status === 'failed') === (a.error !== undefined), {
			message: 'a failed result names its error, and only a failed one does',
			path: ['error'],
		}),
]);

export type RunnerAck = z.infer<typeof RunnerAckSchema>;

export const SupervisorStepSchema = z.enum(['setup', 'run', 'cleanup']);

// How a step ended: exited with a code, killed by a signal, stopped at its
// time budget or left with none, never started (`failed`, with the reason),
// or skipped because an earlier step failed.
export const StepResultSchema = z.strictObject({
	step: SupervisorStepSchema,
	status: z.enum(['exited', 'signalled', 'timeout', 'failed', 'skipped']),
	code: z.number().int().optional(),
	signal: z.number().int().optional(),
	seconds: z.number().nonnegative().optional(),
	reason: z.string().max(500).optional(),
	// The supervisor stopped reading the step's stdout before its end, so bytes
	// the step wrote may be gone. koid fails the point on this
	// (runner_output_incomplete).
	output_incomplete: z.literal(true).optional(),
});

export type StepResult = z.infer<typeof StepResultSchema>;

// What the supervisor (host/verifier/supervisor.py) prints on the
// verifier's stdout among the runner's own lines: that it started, each
// step as it ends, and last an exit line naming the step the sequence ended
// on and how. A runner shares that stdout and could print such a line, so
// each also carries `seq` and `mac`, which koid checks and strips before this
// shape applies (verifier.ts, classifyLine). The lines say how the steps ended;
// they are never evidence about the app.
export const SupervisorLineSchema = z.discriminatedUnion('event', [
	z.strictObject({
		version: z.literal(RUNNER_PROTOCOL_VERSION),
		type: z.literal('supervisor'),
		event: z.literal('started'),
	}),
	z.strictObject({
		version: z.literal(RUNNER_PROTOCOL_VERSION),
		type: z.literal('supervisor'),
		event: z.literal('step'),
		...StepResultSchema.shape,
	}),
	z.strictObject({
		version: z.literal(RUNNER_PROTOCOL_VERSION),
		type: z.literal('supervisor'),
		event: z.literal('exit'),
		// The step the sequence ended on, or none when nothing ran.
		step: SupervisorStepSchema.optional(),
		status: z.enum(['exited', 'signalled', 'timeout', 'failed', 'skipped', 'not-started']),
		code: z.number().int().optional(),
		steps: z.array(StepResultSchema).max(3),
	}),
]);

export type SupervisorLine = z.infer<typeof SupervisorLineSchema>;

// A supervisor line as it is printed: the fields above, with the place in the sequence
// and the signature koid checks and strips first (verifier.ts, classifyLine).
export const SignedSupervisorLineSchema = z.looseObject({
	seq: z.number().int(),
	mac: z.string(),
});

// The build a run is bound to: the preview, the deployment serving it, the
// image by content, and the commit built. For a pull request built as
// GitHub's merge, the merge's parents and the base branch, which is where
// the required policy comes from.
export const DeploymentIdentitySchema = z.strictObject({
	label: PreviewLabelSchema,
	deploymentId: VerifyIdSchema,
	imageDigest: DigestSchema,
	commit: CommitSchema,
	merge: z
		.strictObject({
			head: CommitSchema,
			base: CommitSchema,
			baseBranch: z.string().min(1).max(255),
		})
		.optional(),
});

export type DeploymentIdentity = z.infer<typeof DeploymentIdentitySchema>;

// The identity of what serves under a record, or undefined while nothing
// does: no deployment, one koid stopped for disk use, or one recorded before
// koid kept ids and digests (the next koi up replaces it with one that has
// them). The merge goes in only with its base branch, which the identity
// requires: it is where the required policy comes from.
export function deploymentIdentity(record: PreviewRecord): DeploymentIdentity | undefined {
	const d = record.deployment;
	if (d === undefined || d.halted !== undefined || record.status === 'expired') return undefined;
	if (d.deploymentId === undefined || d.imageDigest === undefined) return undefined;
	const merge = d.merge;
	return {
		label: record.label,
		deploymentId: d.deploymentId,
		imageDigest: d.imageDigest,
		commit: d.commit,
		...(merge?.baseBranch !== undefined
			? { merge: { head: merge.head, base: merge.base, baseBranch: merge.baseBranch } }
			: {}),
	};
}

// What the deployment deploymentIdentity names was built from, as koid
// computed it (DeploymentSourceSchema): undefined whenever that identity
// is, and for a deployment koid has no source for.
export function deploymentSource(record: PreviewRecord): DeploymentSource | undefined {
	return deploymentIdentity(record) !== undefined ? record.deployment?.source : undefined;
}

const uniqueIds = (items: Array<{ id: string }>) =>
	new Set(items.map((i) => i.id)).size === items.length;

// A file under .koi/ that a point's commands depend on, by path relative to
// the source root (.koi/runners/home.sh), and its digest in the build. The
// path is .koi/ and then a path KoiPathSchema accepts, in the form it gives
// (no "." or empty segment). The loader builds its runner paths with the
// same schema, so every runner it returns is one a plan can hold. A second
// rule here would drift from the loader's: RelativePathSchema refuses a
// colon that KoiPathSchema allows in a `files` entry.
export const RunnerFileSchema = z.strictObject({
	path: z
		.string()
		.refine((p) => p.startsWith(`${KOI_DIR}/`), `must be inside ${KOI_DIR}/`)
		.refine((p) => {
			const inside = p.slice(KOI_DIR.length + 1);
			const parsed = KoiPathSchema.safeParse(inside);
			return parsed.success && parsed.data === inside;
		}, `must be ${KOI_DIR}/ and a path inside it, as the loader writes it`),
	digest: DigestSchema,
});

export type RunnerFile = z.infer<typeof RunnerFileSchema>;

// What a run will do, frozen before it starts: the points it takes and why
// each one, the ones it cannot take and why, and what the change touches
// that no point covers. planDigest is over the plan without itself.
export const PlanSchema = z
	.strictObject({
		version: z.literal(1),
		planId: VerifyIdSchema,
		deployment: DeploymentIdentitySchema,
		profile: SlugSchema,
		points: z.array(
			z.strictObject({
				id: PointIdSchema,
				revision: RevisionSchema,
				digest: DigestSchema,
				// The point's runner files (see LoadedPoint). The point's own
				// digest does not change when only a runner does, so these are
				// how a pull request's change to a runner is seen.
				runners: z.array(RunnerFileSchema),
				why: TextSchema,
			}),
		),
		blocked: z.array(z.strictObject({ id: PointIdSchema, reason: TextSchema })),
		uncovered: z.array(TextSchema),
		// The image the manifest's runner image resolved to when the plan was
		// made, absent when it did not resolve. A tag can move, so the digest
		// covers what will run, and a run refuses a plan it no longer matches.
		runnerImageDigest: DigestSchema.optional(),
		planDigest: DigestSchema,
	})
	.refine((p) => uniqueIds([...p.points, ...p.blocked]), {
		message: 'a point appears once, taken or blocked',
		path: ['points'],
	});

export type Plan = z.infer<typeof PlanSchema>;

export const RunSchema = z
	.strictObject({
		version: z.literal(1),
		runId: VerifyIdSchema,
		planId: VerifyIdSchema,
		deployment: DeploymentIdentitySchema,
		planDigest: DigestSchema,
		state: z.enum(['running', 'completed', 'cancelled']),
		startedAt: z.iso.datetime(),
		finishedAt: z.iso.datetime().optional(),
	})
	.refine((r) => (r.state === 'running') === (r.finishedAt === undefined), {
		message: 'a run has finishedAt exactly when it is no longer running',
		path: ['finishedAt'],
	});

export type Run = z.infer<typeof RunSchema>;

// What a finished run found. The run's outcome follows from the points':
// `passed` when every point passed, `failed` when one failed, and
// `incomplete` otherwise, when no point failed and one did not pass (it was
// blocked, not run, needs review, or passed with a recovery). A point that
// did not pass says why in `reason`. The schema holds the result to this,
// so a record cannot say `passed` over a point that did not.
export const ResultSchema = z
	.strictObject({
		version: z.literal(1),
		runId: VerifyIdSchema,
		outcome: z.enum(['passed', 'incomplete', 'failed']),
		points: z.array(
			z.strictObject({
				id: PointIdSchema,
				outcome: OutcomeSchema,
				reason: TextSchema.optional(),
				evidence: z.array(EvidenceRefSchema),
			}),
		),
		uncovered: z.array(TextSchema),
	})
	.refine((r) => uniqueIds(r.points), { message: 'point ids are unique', path: ['points'] })
	.superRefine((r, ctx) => {
		const mismatch = outcomeMismatch(r.outcome, r.points);
		if (mismatch !== undefined)
			ctx.addIssue({ code: 'custom', message: mismatch, path: ['outcome'] });
		for (const [i, p] of r.points.entries()) {
			if (p.outcome !== 'pass' && p.reason === undefined) {
				ctx.addIssue({
					code: 'custom',
					message: `a point that did not pass needs a reason; ${p.id} is ${p.outcome} without one`,
					path: ['points', i, 'reason'],
				});
			}
		}
	});

export type Result = z.infer<typeof ResultSchema>;

// Why a run's outcome does not follow from its points' outcomes, or
// undefined when it does.
function outcomeMismatch(
	outcome: Result['outcome'],
	points: Array<{ outcome: Outcome }>,
): string | undefined {
	const failed = points.some((p) => p.outcome === 'fail');
	const notPassed = points.some((p) => p.outcome !== 'pass');
	switch (outcome) {
		case 'passed':
			return notPassed ? 'passed needs every point to pass' : undefined;
		case 'failed':
			return failed ? undefined : 'failed needs a point that failed';
		case 'incomplete':
			if (failed) return 'incomplete needs no failed point; a failed point makes the run failed';
			return notPassed
				? undefined
				: 'incomplete needs a point that did not pass; every point passing makes the run passed';
	}
}

// Proof that a point can fail: a run against a deliberately broken build
// failed it, and a run against the fixed build passed it. A point without
// one cannot be required.
export const ProofRecordSchema = z
	.strictObject({
		pointId: PointIdSchema,
		revision: RevisionSchema,
		// What was broken: a commit, or a patch koi applied, by digest.
		mutation: z.strictObject({
			kind: z.enum(['ref', 'patch']),
			digest: DigestSchema,
		}),
		failingRunId: VerifyIdSchema,
		passingRunId: VerifyIdSchema,
		provenAt: z.iso.datetime(),
	})
	.refine((p) => p.failingRunId !== p.passingRunId, {
		message: 'the failing and passing runs are different runs',
		path: ['passingRunId'],
	});

export type ProofRecord = z.infer<typeof ProofRecordSchema>;

// Which points a pull request must pass, at which revision. Read from the
// protected base branch, never from the pull request's tree, so a pull
// request cannot make its own checks optional. A required point needs a
// proof record at that revision (ProofRecordSchema); the policy has no
// field to waive that, so a point nobody has seen fail cannot be required.
export const RequiredPolicySchema = z
	.strictObject({
		version: z.literal(1),
		required: z.array(z.strictObject({ id: PointIdSchema, revision: RevisionSchema })),
	})
	.refine((p) => uniqueIds(p.required), { message: 'point ids are unique', path: ['required'] });

export type RequiredPolicy = z.infer<typeof RequiredPolicySchema>;

// -- Loading a tree's files ---------------------------------------------------

export interface LoadedPoint {
	// The point's file, relative to the source root: .koi/points/save.yaml.
	path: string;
	point: Point;
	// The files under .koi/ the point's commands depend on, with their
	// digests, sorted by path: what setup, run and cleanup list in `files`,
	// any argument of theirs that names a file under .koi/, and what the
	// manifest's runner.command names, since it goes before every step. A pull
	// request can change a check by changing only its runner, which leaves
	// the point's own digest as it was, so these are hashed too.
	runners: RunnerFile[];
}

export interface VerifyConfig {
	manifest: VerifyManifest;
	// Every point the manifest's globs matched, by path.
	points: LoadedPoint[];
	// sha256 of each file read, by its path relative to the source root: the
	// manifest, every point file and every runner file. The bytes as they
	// are in the tree.
	digests: Record<string, string>;
}

// Something wrong with a project's verification files. The message names
// the file, and the field when there is one.
export class VerifyConfigError extends Error {
	constructor(
		readonly file: string,
		readonly field: string | undefined,
		detail: string,
	) {
		super(field === undefined ? `${file}: ${detail}` : `${file}: ${field}: ${detail}`);
		this.name = 'VerifyConfigError';
	}
}

// Reads .koi/verify.yaml under `root`, the point files its globs name and
// the runner files the points depend on, and checks what the schemas
// cannot: that nothing under .koi/ is a symlink, that no file is over
// MAX_VERIFY_FILE_BYTES, that point ids are unique, and that skills,
// fixtures, runner files and profiles name files and points that exist. A plan passes its
// own `work`, so loading counts toward the plan's one budget. Only a test sets `budget`.
export async function loadVerifyConfig(
	root: string,
	options: { work?: GlobWork | undefined; budget?: number } = {},
): Promise<VerifyConfig> {
	const manifestPath = `${KOI_DIR}/${VERIFY_MANIFEST}`;
	const koi = join(root, KOI_DIR);
	const koiStat = await lstat(koi).catch(() => undefined);
	if (koiStat === undefined) throw new VerifyConfigError(manifestPath, undefined, 'not found');
	if (koiStat.isSymbolicLink()) {
		throw new VerifyConfigError(KOI_DIR, undefined, 'is a symlink; .koi/ must be a real directory');
	}
	if (!koiStat.isDirectory()) throw new VerifyConfigError(KOI_DIR, undefined, 'is not a directory');
	const files = await listFiles(koi);
	const digests: Record<string, string> = {};
	const read = async (relative: string): Promise<Uint8Array> => {
		const file = `${KOI_DIR}/${relative}`;
		if (!files.has(relative)) throw new VerifyConfigError(file, undefined, 'not found');
		const bytes = await readVerifyFile(join(koi, relative), file);
		digests[file] = digest(bytes);
		return bytes;
	};
	// A runner file shared by several points is read once.
	const digestOf = async (relative: string): Promise<string> =>
		digests[`${KOI_DIR}/${relative}`] ?? digest(await read(relative));

	if (!files.has(VERIFY_MANIFEST))
		throw new VerifyConfigError(manifestPath, undefined, 'not found');
	const manifest = parseYaml(manifestPath, VerifyManifestSchema, await read(VERIFY_MANIFEST));
	const prefix = prefixFiles(manifestPath, manifest.runner.command ?? [], files);

	const matched = new Set<string>();
	const globs =
		options.work ??
		new GlobWork({
			budget: options.budget,
			over: (budget) =>
				new VerifyConfigError(
					manifestPath,
					'points',
					`matching the point globs went past the ${budget} steps allowed`,
				),
		});
	for (const [i, pattern] of manifest.points.entries()) {
		const glob = globs.compile(pattern);
		let any = false;
		for (const file of files) {
			const hit = globs.match(glob, file);
			if (!(typeof hit === 'boolean' ? hit : await hit)) continue;
			matched.add(file);
			any = true;
		}
		if (!any) {
			throw new VerifyConfigError(
				manifestPath,
				`points[${i}]`,
				`matches no file under ${KOI_DIR}/`,
			);
		}
	}

	const points: LoadedPoint[] = [];
	const byId = new Map<string, string>();
	for (const file of [...matched].sort()) {
		const path = `${KOI_DIR}/${file}`;
		const point = parseYaml(path, PointSchema, await read(file));
		const first = byId.get(point.id);
		if (first !== undefined) {
			throw new VerifyConfigError(path, 'id', `${point.id} is also the id of ${first}`);
		}
		byId.set(point.id, path);
		for (const [i, fixture] of (point.requires?.fixtures ?? []).entries()) {
			if (!files.has(fixture)) {
				throw new VerifyConfigError(
					path,
					`requires.fixtures[${i}]`,
					`no file ${fixture} under ${KOI_DIR}/`,
				);
			}
		}
		const runners: RunnerFile[] = [];
		for (const runner of runnerFiles(path, point, files, prefix)) {
			runners.push({ path: `${KOI_DIR}/${runner}`, digest: await digestOf(runner) });
		}
		points.push({ path, point, runners });
	}

	for (const [i, skill] of manifest.skills.entries()) {
		if (!files.has(skill.path)) {
			throw new VerifyConfigError(
				manifestPath,
				`skills[${i}].path`,
				`no file ${skill.path} under ${KOI_DIR}/`,
			);
		}
	}
	for (const [name, profile] of Object.entries(manifest.profiles)) {
		for (const list of ['always', 'include'] as const) {
			for (const [i, id] of profile[list].entries()) {
				if (!byId.has(id)) {
					throw new VerifyConfigError(
						manifestPath,
						`profiles.${name}.${list}[${i}]`,
						`no point ${id}`,
					);
				}
			}
		}
	}

	return { manifest, points, digests };
}

export function digest(bytes: Uint8Array): string {
	return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

const STEPS = ['setup', 'run', 'cleanup'] as const;

// The files under .koi/ a manifest's runner.command names, by path relative to
// .koi/. The prefix goes before every step of every point, so each one is a
// runner file of every point, and without it in the snapshot every step fails.
// A step can list what its command misses in `files`. A manifest has no such
// list, so an argument here that reads as a path in the project answers for
// itself, as a `files` entry does: one that leaves the project or names no file
// under .koi/ is an error. Anything else stays an argument: a program on the
// image's PATH, a flag, an absolute path in the image.
function prefixFiles(manifestPath: string, command: string[], files: Set<string>): string[] {
	const found: string[] = [];
	for (const [i, arg] of command.entries()) {
		if (arg.startsWith('/') || arg.startsWith('-')) continue;
		const field = `runner.command[${i}]`;
		if (arg.split('/').includes('..')) {
			throw new VerifyConfigError(manifestPath, field, 'must not contain a .. segment');
		}
		const normal = posix.normalize(arg);
		if (!normal.startsWith(`${KOI_DIR}/`)) continue;
		const inside = KoiPathSchema.safeParse(normal.slice(KOI_DIR.length + 1));
		if (!inside.success) {
			throw new VerifyConfigError(
				manifestPath,
				field,
				inside.error.issues[0]?.message ?? `must name a file inside ${KOI_DIR}/`,
			);
		}
		if (!files.has(inside.data)) {
			throw new VerifyConfigError(manifestPath, field, `no file ${inside.data} under ${KOI_DIR}/`);
		}
		found.push(inside.data);
	}
	return found;
}

// The files under .koi/ a point's commands depend on, by path relative to
// .koi/, sorted: what the manifest's runner.command names (`prefix`), what
// each step lists in `files`, which must name a file the loader listed, and
// any argument of a command that names one when read as a path from the source
// root, where the commands run. The loader cannot tell a path from any other
// string, so a step's argument counts only when a file is there; an argument
// that names nothing is not an error.
function runnerFiles(path: string, point: Point, files: Set<string>, prefix: string[]): string[] {
	const found = new Set<string>(prefix);
	for (const step of STEPS) {
		const s = point[step];
		if (s === undefined) continue;
		for (const [i, file] of (s.files ?? []).entries()) {
			if (!files.has(file)) {
				throw new VerifyConfigError(
					path,
					`${step}.files[${i}]`,
					`no file ${file} under ${KOI_DIR}/`,
				);
			}
			found.add(file);
		}
		for (const arg of s.command) {
			const inside = insideKoi(arg);
			if (inside !== undefined && files.has(inside)) found.add(inside);
		}
	}
	return [...found].sort();
}

// `arg` as a path relative to .koi/ when, read as a path from the source
// root, it is inside .koi/: ".koi/runners/x.sh" and "./.koi/runners/x.sh"
// both give "runners/x.sh". Anything else gives undefined. The result goes
// through KoiPathSchema, the rule a `files` entry follows and the one
// RunnerFileSchema checks, so a runner found here is one a plan can hold.
// An absolute path never starts with .koi/, and the schema refuses a
// backslash, so neither needs a check of its own.
function insideKoi(arg: string): string | undefined {
	const normal = posix.normalize(arg);
	if (!normal.startsWith(`${KOI_DIR}/`)) return undefined;
	const inside = KoiPathSchema.safeParse(normal.slice(KOI_DIR.length + 1));
	return inside.success ? inside.data : undefined;
}

// Every regular file under dir, by path relative to it with forward slashes.
// A symlink anywhere under dir is an error, to a file or to a directory,
// wherever it points. The loader records a file at the path it lists it at
// and matches a command's arguments against those paths, so a link would
// let a command name a file by a path the loader did not record, and a
// change to that file would change no digest. Refusing every link keeps
// the rule simple and the walk finite.
async function listFiles(dir: string): Promise<Set<string>> {
	const files = new Set<string>();
	const walk = async (relative: string): Promise<void> => {
		const entries = await readdir(join(dir, relative), { withFileTypes: true });
		for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
			const path = relative === '' ? entry.name : `${relative}/${entry.name}`;
			if (entry.isSymbolicLink()) {
				throw new VerifyConfigError(
					`${KOI_DIR}/${path}`,
					undefined,
					`is a symlink; nothing under ${KOI_DIR}/ may be one`,
				);
			}
			if (entry.isDirectory()) await walk(path);
			else if (entry.isFile()) files.add(path);
		}
	};
	await walk('');
	return files;
}

// The bytes of the regular file at `path`, named `file` in errors, refused
// past MAX_VERIFY_FILE_BYTES. The file is opened without following a
// symlink in its last segment, and its kind and size come from the open
// descriptor, so what was checked is what is read: a file swapped for a
// symlink after listFiles saw it is refused, not followed, and the read
// stops one byte past the limit, so a file that grows after the size check
// is refused, not read whole. The loader expects a static tree (koid reads
// an extracted tarball); a parent directory swapped for a symlink is out of
// scope, since O_NOFOLLOW covers the last segment only.
export async function readVerifyFile(path: string, file: string): Promise<Uint8Array> {
	let handle: FileHandle;
	try {
		handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
	} catch (err) {
		if ((err as { code?: string }).code === 'ELOOP') {
			throw new VerifyConfigError(file, undefined, 'is a symlink; it was listed as a regular file');
		}
		throw err;
	}
	try {
		const info = await handle.stat();
		if (!info.isFile()) throw new VerifyConfigError(file, undefined, 'is not a regular file');
		if (info.size > MAX_VERIFY_FILE_BYTES) {
			throw new VerifyConfigError(
				file,
				undefined,
				`is ${info.size} bytes; the most koi reads is ${MAX_VERIFY_FILE_BYTES}`,
			);
		}
		const buffer = new Uint8Array(MAX_VERIFY_FILE_BYTES + 1);
		let length = 0;
		while (length < buffer.length) {
			const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
			if (bytesRead === 0) break;
			length += bytesRead;
		}
		if (length > MAX_VERIFY_FILE_BYTES) {
			throw new VerifyConfigError(
				file,
				undefined,
				`is over ${MAX_VERIFY_FILE_BYTES} bytes; it grew while koi read it`,
			);
		}
		return buffer.slice(0, length);
	} finally {
		await handle.close();
	}
}

function parseYaml<T>(file: string, schema: z.ZodType<T>, bytes: Uint8Array): T {
	let data: unknown;
	try {
		data = Bun.YAML.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
	} catch (err) {
		throw new VerifyConfigError(file, undefined, (err as Error).message);
	}
	const parsed = schema.safeParse(data);
	if (!parsed.success) {
		const issue = parsed.error.issues[0];
		const field =
			issue === undefined || issue.path.length === 0 ? undefined : fieldName(issue.path);
		throw new VerifyConfigError(file, field, issue?.message ?? 'invalid');
	}
	return parsed.data;
}

// a.b[0].c for a zod issue path.
function fieldName(path: PropertyKey[]): string {
	return path
		.map((p, i) => (typeof p === 'number' ? `[${p}]` : i === 0 ? String(p) : `.${String(p)}`))
		.join('');
}
