import { z } from 'zod';
import {
	ArtifactIdSchema,
	ArtifactKindSchema,
	ArtifactSchema,
	EvidenceEventSchema,
	RunProblemSchema,
	RunStatusSchema,
} from './evidence.ts';
import { PreviewLabelSchema } from './preview.ts';
import {
	DeploymentIdentitySchema,
	DigestSchema,
	ImageRefSchema,
	OutcomeSchema,
	PointIdSchema,
	SlugSchema,
	TextSchema,
	VerifyIdSchema,
} from './verify.ts';

// The control routes that plan and run a verification, and the ctl and CLI
// commands over them (docs/verify.md, "Running a verification"). Every
// request and every reply has a version, and every reply fits the bound the
// CLI reads replies through: SSM returns the first 24,000 characters of a
// command's output, so a reply is at most VERIFICATION_REPLY_MAX_BYTES
// once serialized, and a list that does not fit is paged with a cursor.
// Errors are {version, error: {code, message, retryable}}. The controller
// allocates ids and judges results; a caller never sends an outcome.

export const VERIFICATION_API_VERSION = 1;

// Bounds. A reply is serialized and measured before it is sent; one that
// is over the bound has its unpaged lists cut and says so in `truncated`
// (the controller does this; see fitReply in the daemon). An error reply
// is bounded too: its message is cut to VERIFICATION_ERROR_MESSAGE_MAX
// bytes, and a validation error names at most VERIFICATION_ERROR_ISSUES_MAX
// issues, since zod's own message for a 64 KiB body runs to hundreds of
// kilobytes.
export const VERIFICATION_REPLY_MAX_BYTES = 16 * 1024;
export const VERIFICATION_BODY_MAX_BYTES = 64 * 1024;
export const VERIFICATION_ERROR_MESSAGE_MAX = 2 * 1024;
export const VERIFICATION_ERROR_ISSUES_MAX = 20;
// One entry of a paged list is cut to this once serialized, so that a page
// always holds at least one entry under the reply bound.
export const VERIFICATION_ENTRY_MAX_BYTES = 4 * 1024;
// Raw artifact bytes per chunk reply: 6 KiB encodes to 8 KiB of base64.
export const ARTIFACT_CHUNK_BYTES = 6 * 1024;
// The most events one page holds, before the byte bound cuts it shorter.
export const EVENTS_PAGE_MAX = 200;
// What one export over SSM may fetch in all, and per artifact; past either
// the export notes the artifact as truncated and says a channel is needed.
export const SSM_EXPORT_MAX_BYTES = 8 * 1024 ** 2;
export const SSM_ARTIFACT_MAX_BYTES = 1024 ** 2;

// How long a run may take before koid stops it, and what the operator may
// raise that to; the lease outlives the run by the teardown allowance.
export const RUN_LIMIT_DEFAULTS = {
	runSeconds: 900,
	pointSeconds: 300,
	runRequests: 50,
	pointRequests: 20,
} as const;
export const RUN_LIMIT_CEILINGS = {
	runSeconds: 3600,
	pointSeconds: 900,
	runRequests: 200,
	pointRequests: 50,
} as const;
export const TEARDOWN_ALLOWANCE_SECONDS = 120;

// Who holds the lease a run takes: verify: and the run id.
export function runLeaseHolder(runId: string): string {
	return `verify:${VerifyIdSchema.parse(runId)}`;
}

export function runIdOfHolder(holder: string): string | undefined {
	const match = /^verify:([a-z0-9]{16,40})$/.exec(holder);
	return match?.[1];
}

// -- Errors -------------------------------------------------------------------

export const VerificationErrorCodeSchema = z
	.string()
	.max(64)
	.regex(/^[a-z][a-z0-9_]*$/);

export const VerificationErrorReplySchema = z.strictObject({
	version: z.literal(1),
	error: z.strictObject({
		code: VerificationErrorCodeSchema,
		message: z.string().max(4000),
		retryable: z.boolean(),
	}),
});

// What a reply cut to fit the bound names: the paths of the lists it
// shortened or dropped, such as `problems` or
// `artifacts[recorder:aria:2].redaction.removedFields`. Absent when nothing
// was cut. Bounded itself, so the reply reserves a fixed room for it.
export const TRUNCATED_NAME_MAX = 100;
export const TRUNCATED_NAMES_MAX = 20;
export const TruncatedSchema = z
	.array(z.string().max(TRUNCATED_NAME_MAX))
	.max(TRUNCATED_NAMES_MAX)
	.optional();

export type VerificationErrorReply = z.infer<typeof VerificationErrorReplySchema>;

// -- Limits -------------------------------------------------------------------

export const RunLimitsSchema = z.strictObject({
	runSeconds: z.number().int().positive(),
	pointSeconds: z.number().int().positive(),
	runRequests: z.number().int().nonnegative(),
	pointRequests: z.number().int().nonnegative(),
});

export type RunLimits = z.infer<typeof RunLimitsSchema>;

// -- Plans --------------------------------------------------------------------

// POST /v1/verification-plans. `points` names an explicit subset, which is
// advisory: a run of it cannot assert readiness. `expectedDeploymentId`
// refuses a plan of any other deployment.
export const PlanRequestSchema = z.strictObject({
	version: z.literal(1),
	label: PreviewLabelSchema,
	profile: SlugSchema,
	expectedDeploymentId: VerifyIdSchema.optional(),
	points: z.array(PointIdSchema).min(1).max(500).optional(),
});

export type PlanRequest = z.infer<typeof PlanRequestSchema>;

// Whether a point has a proof record (ProofRecordSchema) in the snapshot's
// .koi/proofs/. `unverified` means one names a failing and a passing run
// that koid has not resolved to finalized bundles, so it is a claim.
export const ProofStatusSchema = z.enum(['none', 'unverified']);

export const PlannedPointSchema = z.strictObject({
	id: PointIdSchema,
	revision: z.number().int().positive(),
	why: TextSchema,
	proof: ProofStatusSchema,
	// Named by the advisory required policy, at this revision.
	required: z.boolean(),
});

export type PlannedPoint = z.infer<typeof PlannedPointSchema>;

export const BlockedPointSchema = z.strictObject({ id: PointIdSchema, reason: TextSchema });

// Where the required policy came from. Only base-branch can count toward
// readiness; none means no trusted source exists yet, and `advisory` is
// what the snapshot's own .koi/required.yaml said, if it had one.
export const PlanPolicySchema = z.strictObject({
	source: z.enum(['base-branch', 'none']),
	advisory: z
		.strictObject({
			path: z.string().max(512),
			required: z.array(
				z.strictObject({ id: PointIdSchema, revision: z.number().int().positive() }),
			),
			error: z.string().max(2000).optional(),
		})
		.optional(),
});

// A cursor into a plan's lists: which list and the index to start from.
export const PlanCursorSchema = z
	.string()
	.regex(/^(?:points|blocked|uncovered):(?:0|[1-9][0-9]{0,6})$/);

// The most characters one note of a plan may be. koid cuts a note to this
// when it builds the plan, so it never writes a record it cannot read back.
export const PLAN_NOTE_MAX = 500;

// The plan as a reply: the Plan's identity and counts, the points taken and
// why, the ones blocked and why, and what the change touches that no point
// covers. The lists are paged: `next` is the cursor to ask for the rest with
// (GET /v1/verification-plans/{plan}?after=).
export const PlanReplySchema = z.strictObject({
	version: z.literal(1),
	planId: VerifyIdSchema,
	planDigest: DigestSchema,
	label: PreviewLabelSchema,
	deployment: DeploymentIdentitySchema,
	profile: SlugSchema,
	// A plan of an explicit subset, a dirty tree or a build with no pull
	// request context is advisory: it cannot assert readiness.
	advisory: z.boolean(),
	counts: z.strictObject({
		selected: z.number().int().nonnegative(),
		blocked: z.number().int().nonnegative(),
		uncovered: z.number().int().nonnegative(),
		required: z.number().int().nonnegative(),
	}),
	policy: PlanPolicySchema,
	limits: RunLimitsSchema,
	runnerImage: ImageRefSchema,
	// What that reference resolved to when the plan was made; absent when it did
	// not resolve (Plan, runnerImageDigest).
	runnerImageDigest: DigestSchema.optional(),
	originMode: z.literal('private-app'),
	// What a run of this plan can and cannot do today.
	notes: z.array(z.string().max(PLAN_NOTE_MAX)).max(20),
	points: z.array(PlannedPointSchema),
	blocked: z.array(BlockedPointSchema),
	uncovered: z.array(TextSchema),
	next: PlanCursorSchema.optional(),
	truncated: TruncatedSchema,
	createdAt: z.iso.datetime(),
});

export type PlanReply = z.infer<typeof PlanReplySchema>;

// -- Runs ---------------------------------------------------------------------

const IdempotencyKeySchema = z.string().regex(/^[A-Za-z0-9_-]{8,64}$/);

// POST /v1/verification-runs. The plan by id and digest, so a plan changed
// or made for another build is refused. `mode` is the deterministic runner;
// an exploratory session is later work. The same `idempotencyKey` returns
// the run it first started.
export const RunRequestSchema = z.strictObject({
	version: z.literal(1),
	planId: VerifyIdSchema,
	planDigest: DigestSchema,
	mode: z.literal('runner'),
	idempotencyKey: IdempotencyKeySchema.optional(),
});

export type RunRequest = z.infer<typeof RunRequestSchema>;

export const RunAcceptedSchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	planId: VerifyIdSchema,
	planDigest: DigestSchema,
	deployment: DeploymentIdentitySchema,
	state: z.literal('running'),
	leaseExpiresAt: z.iso.datetime(),
	limits: RunLimitsSchema,
	startedAt: z.iso.datetime(),
});

export type RunAccepted = z.infer<typeof RunAcceptedSchema>;

// How a run ended. Only `evaluated` carries a Result; the others end in
// outcome incomplete with result null and keep what points had been judged.
// `finalize-failed` is a run that was judged but whose bundle could not be
// closed: the manifest was never written, so nothing of it counts.
export const CompletionSchema = z.enum([
	'evaluated',
	'cancelled',
	'interrupted',
	'capture-error',
	'empty-plan',
	'finalize-failed',
]);

export type Completion = z.infer<typeof CompletionSchema>;

export const RunOutcomeSchema = z.enum(['passed', 'incomplete', 'failed']);

export type RunOutcome = z.infer<typeof RunOutcomeSchema>;

export const RunStateSchema = z.enum(['running', 'completed', 'cancelled']);

export const FreshnessSchema = z.enum(['current', 'stale', 'unknown']);

export const ReadinessSchema = z.strictObject({
	eligibleForMergeGate: z.boolean(),
	reasons: z.array(z.string().max(500)).max(50),
});

export type Readiness = z.infer<typeof ReadinessSchema>;

// One point as the run has it so far: pending before its turn, running,
// then done with its outcome and the evidence koid holds for it.
export const PointStatusSchema = z.strictObject({
	id: PointIdSchema,
	state: z.enum(['pending', 'running', 'done']),
	outcome: OutcomeSchema.optional(),
	reason: TextSchema.optional(),
	evidence: z.array(ArtifactIdSchema).max(200),
});

export type PointStatus = z.infer<typeof PointStatusSchema>;

export const CleanupStatusSchema = z.enum(['succeeded', 'failed', 'unknown']);

// runs/<runId>/controller.json: the controller's own record of a run, which
// the B1 Run and Result shapes cannot hold: how the run ended, what was
// judged before an interruption, and the lease it holds. The lease id is
// here so a restart can release the lease; the status reply leaves it out.
// The idempotency key is here so a retry after a restart finds the run the
// key started; the status reply leaves that out too.
export const RunControllerRecordSchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	planId: VerifyIdSchema,
	planDigest: DigestSchema,
	idempotencyKey: IdempotencyKeySchema.optional(),
	executionDigest: DigestSchema.optional(),
	label: PreviewLabelSchema,
	deployment: DeploymentIdentitySchema,
	profile: SlugSchema,
	advisory: z.boolean(),
	state: RunStateSchema,
	completion: CompletionSchema.optional(),
	outcome: RunOutcomeSchema.optional(),
	// Why the run did not reach an evaluated completion, as a code and text.
	interruption: z.string().max(2000).optional(),
	cancelRequested: z.boolean(),
	points: z.array(PointStatusSchema),
	uncovered: z.array(TextSchema),
	policy: PlanPolicySchema,
	limits: RunLimitsSchema,
	lease: z.strictObject({ leaseId: z.string().max(64), expiresAt: z.iso.datetime() }),
	readiness: ReadinessSchema,
	// Freshness as checked at finalization; the status reply checks again.
	freshness: FreshnessSchema,
	cleanup: CleanupStatusSchema,
	startedAt: z.iso.datetime(),
	finishedAt: z.iso.datetime().optional(),
	updatedAt: z.iso.datetime(),
});

export type RunControllerRecord = z.infer<typeof RunControllerRecordSchema>;

// GET /v1/verification-runs/{run}/status?after=. The controller's record
// without the lease id, with freshness computed now, whether the evidence
// bundle is finalized, and the evidence store's own status. Points are
// paged by index.
export const RunStatusReplySchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	planId: VerifyIdSchema,
	planDigest: DigestSchema,
	executionDigest: DigestSchema.optional(),
	label: PreviewLabelSchema,
	deployment: DeploymentIdentitySchema,
	profile: SlugSchema,
	advisory: z.boolean(),
	state: RunStateSchema,
	completion: CompletionSchema.optional(),
	outcome: RunOutcomeSchema.optional(),
	interruption: z.string().max(2000).optional(),
	cancelRequested: z.boolean(),
	readiness: ReadinessSchema,
	freshness: FreshnessSchema,
	evidence: z.enum(['collecting', 'complete', 'incomplete']),
	finalized: z.boolean(),
	cleanup: CleanupStatusSchema,
	limits: RunLimitsSchema,
	leaseExpiresAt: z.iso.datetime(),
	progress: z.strictObject({
		total: z.number().int().nonnegative(),
		done: z.number().int().nonnegative(),
	}),
	points: z.array(PointStatusSchema),
	next: z.number().int().nonnegative().optional(),
	problems: z.array(RunProblemSchema),
	problemCount: z.number().int().nonnegative(),
	truncated: TruncatedSchema,
	startedAt: z.iso.datetime(),
	finishedAt: z.iso.datetime().optional(),
});

export type RunStatusReply = z.infer<typeof RunStatusReplySchema>;

// GET /v1/verification-runs/{run}/events?after=&limit=. Host-sequenced
// events after `after`; `next` is the last sequence number in the page, to
// ask after next; `more` says whether any follow.
export const RunEventsPageSchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	events: z.array(EvidenceEventSchema),
	next: z.number().int().nonnegative(),
	more: z.boolean(),
	truncated: TruncatedSchema,
});

export type RunEventsPage = z.infer<typeof RunEventsPageSchema>;

// GET /v1/verification-runs/{run}/evidence?after=. The manifest's fields
// without the artifact list, which is paged by index; before finalization,
// the status so far and no artifacts, since entries are durable only in
// the manifest.
export const EvidenceReplySchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	finalized: z.boolean(),
	expired: z.boolean(),
	status: RunStatusSchema,
	retention: z
		.strictObject({
			retainedUntil: z.iso.datetime(),
			tombstoneUntil: z.iso.datetime(),
		})
		.optional(),
	events: z
		.strictObject({
			count: z.number().int().nonnegative(),
			bytes: z.number().int().nonnegative(),
			sha256: DigestSchema,
		})
		.optional(),
	limitations: z.array(z.string().max(500)).max(50),
	artifactCount: z.number().int().nonnegative(),
	artifacts: z.array(ArtifactSchema),
	next: z.number().int().nonnegative().optional(),
	truncated: TruncatedSchema,
});

export type EvidenceReply = z.infer<typeof EvidenceReplySchema>;

// GET /v1/verification-runs/{run}/artifacts/{artifact}?offset=&length=.
// One bounded chunk of a finalized, available artifact's sanitized bytes,
// as base64 for the SSM path. `truncated` says the reply does not hold the
// whole artifact; `next` is the offset of the rest, and `note` says what
// an export over SSM should do about it.
export const ArtifactChunkSchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	artifact: ArtifactIdSchema,
	kind: ArtifactKindSchema,
	mediaType: z.string().max(200),
	size: z.number().int().nonnegative(),
	sha256: DigestSchema,
	offset: z.number().int().nonnegative(),
	length: z.number().int().nonnegative(),
	dataBase64: z.string(),
	next: z.number().int().nonnegative().optional(),
	truncated: z.boolean(),
	note: z.string().max(500).optional(),
});

export type ArtifactChunk = z.infer<typeof ArtifactChunkSchema>;

// A byte offset or length as a query parameter: digits only.
export const ByteCountSchema = z
	.string()
	.regex(/^(?:0|[1-9][0-9]{0,11})$/, 'a byte count')
	.transform(Number);

// An index cursor as a query parameter.
export const IndexCursorSchema = z
	.string()
	.regex(/^(?:0|[1-9][0-9]{0,8})$/, 'an index')
	.transform(Number);

// -- The CLI's results --------------------------------------------------------

// What `koi verify evidence RUN --out DIR --json` prints, and export.json holds:
// where each artifact went, or why it did not. `complete` is true only when every
// event and every artifact the manifest records is in the export, the events run in
// order and hash to the manifest, and each artifact hashes to it too. `missing` says
// what is not, so an export of expired evidence, which holds only the manifest and
// the status, cannot read as whole.
export const EvidenceExportSchema = z
	.strictObject({
		version: z.literal(1),
		runId: VerifyIdSchema,
		out: z.string(),
		finalized: z.boolean(),
		expired: z.boolean(),
		complete: z.boolean(),
		missing: z.array(z.string().max(500)),
		artifacts: z.array(
			z.strictObject({
				id: ArtifactIdSchema,
				kind: ArtifactKindSchema,
				availability: z.enum(['available', 'withheld', 'failed', 'expired']),
				file: z.string().optional(),
				bytes: z.number().int().nonnegative(),
				sha256: DigestSchema,
				// The bytes written match the manifest's hash. False for a partial
				// export, which is named in `note`.
				verified: z.boolean(),
				truncated: z.boolean(),
				note: z.string().max(500).optional(),
			}),
		),
		// No file when there are no events to save: they have expired.
		events: z.strictObject({
			count: z.number().int().nonnegative(),
			file: z.string().optional(),
		}),
		bytes: z.number().int().nonnegative(),
		notes: z.array(z.string().max(500)),
	})
	.refine((e) => e.complete === (e.missing.length === 0), {
		message: 'an export is complete exactly when nothing is missing from it',
		path: ['complete'],
	})
	.refine((e) => !e.complete || (e.finalized && !e.expired), {
		message: 'an unfinalized or expired export is not complete',
		path: ['complete'],
	});

export type EvidenceExport = z.infer<typeof EvidenceExportSchema>;

// The file an exported artifact is written under: its kind and number with
// an extension for its media type, since an id's colons are not a file
// name everywhere.
export function artifactFileName(id: string, mediaType: string): string {
	const [, kind = 'artifact', n = '0'] = ArtifactIdSchema.parse(id).split(':');
	const type = mediaType.split(';')[0]?.trim().toLowerCase() ?? '';
	const extension =
		type === 'image/png'
			? 'png'
			: type === 'application/json'
				? 'json'
				: type === 'application/x-ndjson'
					? 'ndjson'
					: type.startsWith('text/')
						? 'txt'
						: 'bin';
	return `${kind}-${n}.${extension}`;
}
