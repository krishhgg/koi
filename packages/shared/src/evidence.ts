import { createHash } from 'node:crypto';
import { z } from 'zod';
import { CommitSchema } from './request.ts';
import {
	DeploymentIdentitySchema,
	DigestSchema,
	ImageRefSchema,
	PointIdSchema,
	VerifyIdSchema,
} from './verify.ts';

// What koid keeps of a verification run: the artifacts the recorder
// captured, sanitized, with the record that says what was done to each; the
// run's status; the manifest that closes a run's evidence; the descriptor
// of what ran; and the snapshot of a deployment's verification inputs. The
// daemon writes these under <stateDir>/verification (docs/verify.md,
// "Recorder and evidence"); the commands that read them come later. Every
// object is strict: these are records koi writes and reads back, and an
// unknown key means a writer and a reader disagree.

// -- Limits and retention -----------------------------------------------------

// Application caps on what a run may persist. Exceeding one stops capture
// and is recorded, so the run cannot pass; nothing is truncated to fit.
export const EVIDENCE_LIMITS = {
	bytesPerRun: 512 * 1024 ** 2,
	bytesPerArtifact: 32 * 1024 ** 2,
	artifactsPerRun: 10_000,
	eventsPerRun: 10_000,
	// The larger of these two stays free on the evidence filesystem: the fixed
	// reserve, or the share of the filesystem up to reserveShareCap. A run on a
	// 2 TB disk does not need 200 GiB left over.
	reserveBytes: 5 * 1024 ** 3,
	reserveShare: 0.1,
	reserveShareCap: 20 * 1024 ** 3,
} as const;

export type EvidenceLimits = { -readonly [K in keyof typeof EVIDENCE_LIMITS]: number };

// Ordinary run evidence lasts 30 days after finalization, 90 when an
// operator pins the run. The manifest and a tombstone last 180 days, so a
// verdict stays explainable after its evidence is gone.
export const EVIDENCE_RETENTION = {
	runDays: 30,
	pinnedDays: 90,
	manifestDays: 180,
	// A deployment's input snapshot, and a run that never finalized.
	inputDays: 30,
} as const;

// -- Artifacts ----------------------------------------------------------------

// The kinds of artifact koid records. The runner's capture kinds
// (RunnerEventSchema) map onto the first four; the rest are the recorder's
// own observations. trace, har and file are accepted and always withheld in
// this version (see WITHHELD_KINDS in the daemon).
export const ARTIFACT_KINDS = [
	'screenshot',
	'aria',
	'console',
	'network',
	'http-response',
	'trace',
	'har',
	'file',
] as const;

export const ArtifactKindSchema = z.enum(ARTIFACT_KINDS);

export type ArtifactKind = z.infer<typeof ArtifactKindSchema>;

// recorder:<kind>:<n>. koid gives these out, counting up within a run and
// never reusing a number; a reference resolves only inside its run, point
// and attempt. The id names no path: the store derives the file from it.
export const ArtifactIdSchema = z.string().regex(/^recorder:[a-z-]+:[1-9][0-9]*$/);

export const RedactionStatusSchema = z.enum(['sanitized', 'withheld', 'failed']);

// What was done to an artifact before it was kept. `sanitized` means the
// stated policy ran, not that nothing sensitive is left; `limitations`
// says what the policy cannot do. A withheld or failed artifact has no
// payload.
export const RedactionSchema = z.strictObject({
	status: RedactionStatusSchema,
	policyDigest: DigestSchema,
	removedFields: z.array(z.string().max(200)).max(1000),
	limitations: z.array(z.string().max(500)).max(50),
});

export type Redaction = z.infer<typeof RedactionSchema>;

export const AvailabilitySchema = z.enum(['available', 'withheld', 'failed', 'expired']);

// One manifest entry, as the design gives it. Size and hash describe the
// sanitized bytes on disk, never the raw capture. eventRange is the span of
// host-sequenced events over which the capture happened.
export const ArtifactSchema = z.strictObject({
	id: ArtifactIdSchema,
	runId: VerifyIdSchema,
	pointId: PointIdSchema,
	attempt: z.number().int().positive(),
	kind: ArtifactKindSchema,
	mediaType: z
		.string()
		.min(1)
		.max(200)
		.regex(/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:;.*)?$/i),
	size: z.number().int().nonnegative(),
	sha256: DigestSchema,
	origin: z.literal('recorder'),
	capturedAt: z.iso.datetime(),
	eventRange: z
		.strictObject({
			first: z.number().int().nonnegative(),
			last: z.number().int().nonnegative(),
		})
		.refine((r) => r.last >= r.first, 'last comes at or after first'),
	redaction: RedactionSchema,
	availability: AvailabilitySchema,
	retainedUntil: z.iso.datetime(),
});

export type Artifact = z.infer<typeof ArtifactSchema>;

// -- Events -------------------------------------------------------------------

// One line of runs/<runId>/events.ndjson: a host sequence number and time,
// where the event came from, its type, and what the source said, sanitized
// and bounded before it was written. Not strict: each source has its own
// fields, and the reader takes the envelope.
export const EvidenceEventSchema = z.looseObject({
	seq: z.number().int().positive(),
	at: z.iso.datetime(),
	source: z.enum(['host', 'recorder', 'runner']),
	type: z
		.string()
		.min(1)
		.max(64)
		.regex(/^[a-z][a-z0-9-]*$/),
	pointId: PointIdSchema.optional(),
	attempt: z.number().int().positive().optional(),
});

export type EvidenceEvent = z.infer<typeof EvidenceEventSchema>;

// The most one stored event line may hold, envelope included. Leaves room
// for a single event in a 16 KiB control page.
export const MAX_EVENT_BYTES = 12 * 1024;

// -- Status -------------------------------------------------------------------

// Something that keeps a run from passing: a cap exceeded, a capture that
// failed, a gap in observation, a recorder that stopped answering.
export const RunProblemSchema = z.strictObject({
	code: z
		.string()
		.max(64)
		.regex(/^[a-z][a-z0-9_]*$/),
	detail: z.string().max(2000),
	at: z.iso.datetime(),
});

export type RunProblem = z.infer<typeof RunProblemSchema>;

// runs/<runId>/status.json: how far the run is and whether its evidence can
// be relied on. `state` is the controller's; `evidence` says whether every
// capture asked for was kept (`complete`), or something was lost or capped
// (`incomplete`), which makes a pass impossible whatever the runner said.
export const RunStatusSchema = z
	.strictObject({
		version: z.literal(1),
		runId: VerifyIdSchema,
		state: z.enum(['running', 'completed', 'cancelled', 'failed']),
		evidence: z.enum(['collecting', 'complete', 'incomplete']),
		startedAt: z.iso.datetime(),
		updatedAt: z.iso.datetime(),
		finishedAt: z.iso.datetime().optional(),
		counts: z.strictObject({
			events: z.number().int().nonnegative(),
			artifacts: z.number().int().nonnegative(),
			bytes: z.number().int().nonnegative(),
		}),
		problems: z.array(RunProblemSchema).max(1000),
	})
	.refine((s) => (s.state === 'running') === (s.finishedAt === undefined), {
		message: 'a run has finishedAt exactly when it is no longer running',
		path: ['finishedAt'],
	})
	.refine((s) => s.problems.length === 0 || s.evidence !== 'complete', {
		message: 'a run with a problem does not have complete evidence',
		path: ['evidence'],
	});

export type RunStatus = z.infer<typeof RunStatusSchema>;

// -- Execution descriptor -----------------------------------------------------

// A version the recorder says of itself. It says so once, before any page opens, and
// from the operator's image, but execution.json is not scrubbed. So this holds it to a
// version's form: no spaces and no separators, which leaves no room for a sentence, an
// error or `name=value`. A recorder that says anything else stops the run.
const ReportedVersionSchema = (max: number) =>
	z
		.string()
		.max(max)
		.regex(/^[A-Za-z0-9][A-Za-z0-9._+-]*$/, 'a version, like 142.0.7444.52');

// What a run executed with, frozen next to the plan: the images by digest,
// the browser, where the required policy came from, the proofs relied on,
// the origin the browser saw, and the limits in force. Its digest joins the
// plan's in the manifest. Kept apart from the plan so the strict Plan object
// stays as it is.
export const ExecutionDescriptorSchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	planId: VerifyIdSchema,
	// The runner image by reference and by content. The digest is absent when
	// the image did not resolve, and a descriptor without it cannot belong to
	// a passed run.
	runnerImage: z.strictObject({ reference: ImageRefSchema, digest: DigestSchema.optional() }),
	recorderImage: z.strictObject({ reference: ImageRefSchema, digest: DigestSchema }),
	browser: z.strictObject({ name: z.literal('chromium'), version: ReportedVersionSchema(100) }),
	playwright: ReportedVersionSchema(50),
	policy: z.strictObject({
		source: z.enum(['base-branch', 'none']),
		commit: CommitSchema.optional(),
		digest: DigestSchema,
	}),
	proofs: z.array(
		z.strictObject({
			pointId: PointIdSchema,
			revision: z.number().int().positive(),
			failingRunId: VerifyIdSchema,
			passingRunId: VerifyIdSchema,
		}),
	),
	// The browser reaches the app at its private name on the run network,
	// not through Caddy and public TLS.
	originMode: z.literal('private-app'),
	origin: z.url(),
	limits: z.strictObject({
		runSeconds: z.number().int().positive(),
		pointSeconds: z.number().int().positive(),
		runRequests: z.number().int().nonnegative(),
		pointRequests: z.number().int().nonnegative(),
		artifactBytes: z.number().int().positive(),
		runBytes: z.number().int().positive(),
		artifacts: z.number().int().positive(),
		events: z.number().int().positive(),
	}),
	// What the runner could do beyond driving the page: raw-cdp means it
	// could hold a DevTools connection and run any script in the page, so its
	// oracle is a claim the recorder cannot vouch for. There is no value for
	// request interception: the recorder refuses Fetch and the Network
	// interception methods, so no runner can pause or fulfil a browser request.
	capabilities: z.array(z.enum(['raw-cdp', 'login-key'])),
	executionDigest: DigestSchema,
});

export type ExecutionDescriptor = z.infer<typeof ExecutionDescriptorSchema>;

// -- Manifest -----------------------------------------------------------------

// runs/<runId>/manifest.json, written last, once every artifact, the status
// and whatever result and report exist are durable. A run directory without
// one is not a completed evidence bundle. `files` hashes the other records
// in the directory as they were when the manifest was written.
export const EvidenceManifestSchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	deployment: DeploymentIdentitySchema.optional(),
	planId: VerifyIdSchema.optional(),
	planDigest: DigestSchema.optional(),
	executionDigest: DigestSchema.optional(),
	status: RunStatusSchema,
	artifacts: z.array(ArtifactSchema).max(EVIDENCE_LIMITS.artifactsPerRun),
	events: z.strictObject({
		count: z.number().int().nonnegative(),
		bytes: z.number().int().nonnegative(),
		sha256: DigestSchema,
	}),
	files: z.partialRecord(
		z.enum([
			'run.json',
			'plan.json',
			'execution.json',
			'result.json',
			'report.md',
			'controller.json',
			'status.json',
		]),
		z.strictObject({ sha256: DigestSchema, bytes: z.number().int().nonnegative() }),
	),
	// What no sanitizer here can promise, copied into every bundle.
	limitations: z.array(z.string().max(500)).max(50),
	finalizedAt: z.iso.datetime(),
	retainedUntil: z.iso.datetime(),
	tombstoneUntil: z.iso.datetime(),
});

export type EvidenceManifest = z.infer<typeof EvidenceManifestSchema>;

// What stays of a run once its evidence has expired: enough to say that it
// existed, when it went, and what manifest it had.
export const EvidenceTombstoneSchema = z.strictObject({
	version: z.literal(1),
	runId: VerifyIdSchema,
	expiredAt: z.iso.datetime(),
	manifestSha256: DigestSchema,
	tombstoneUntil: z.iso.datetime(),
});

export type EvidenceTombstone = z.infer<typeof EvidenceTombstoneSchema>;

// -- Input snapshot -----------------------------------------------------------

// A file copied into a snapshot, by its path relative to the source root.
const SnapshotFileSchema = z.strictObject({
	path: z.string().min(1).max(512),
	digest: DigestSchema,
	size: z.number().int().nonnegative(),
});

// inputs/<deploymentId>/snapshot.json: what the deployer kept of a build's
// verification inputs before it removed the build directory, so a plan
// made later reads the files the build had. `verify` says whether the
// project has verification files, and when it does, the digests the loader
// computed over the copy, with the fixtures read and hashed as well.
export const InputSnapshotSchema = z.strictObject({
	version: z.literal(1),
	deploymentId: VerifyIdSchema,
	label: z.string().min(1).max(63),
	request: z.strictObject({
		id: VerifyIdSchema,
		repo: z.string().min(1),
		commit: CommitSchema,
		branch: z.string().min(1),
		pr: z.number().int().positive().optional(),
		merge: z
			.strictObject({
				head: CommitSchema,
				base: CommitSchema,
				baseBranch: z.string().min(1).max(255).optional(),
			})
			.optional(),
		dirty: z.boolean(),
		createdAt: z.iso.datetime(),
	}),
	recipe: z.strictObject({
		kind: z.enum(['builtin', 'repo']),
		name: z.string().min(1).optional(),
		// For a repo recipe, over the request's recipe as JSON with sorted
		// keys. For a built-in one, over its name and the digest of every
		// file in the recipe directory the daemon used (recipe.json, the
		// Dockerfile, scripts), so a changed recipe changes the snapshot.
		digest: DigestSchema,
		// A built-in recipe's files by path within its directory, as hashed.
		files: z.record(z.string().min(1).max(512), DigestSchema).optional(),
	}),
	source: z.strictObject({
		archiveDigest: DigestSchema,
		archiveBytes: z.number().int().nonnegative(),
	}),
	// .koi-runtime/changed-files.txt, when the build had one.
	changedFiles: z
		.strictObject({
			file: SnapshotFileSchema,
			count: z.number().int().nonnegative(),
		})
		.optional(),
	verify: z.discriminatedUnion('status', [
		z.strictObject({ status: z.literal('absent') }),
		z.strictObject({ status: z.literal('invalid'), error: z.string().max(2000) }),
		z.strictObject({
			status: z.literal('present'),
			// Every file the loader read, by path from the source root, as
			// loadVerifyConfig returns them for the copy.
			digests: z.record(z.string(), DigestSchema),
			points: z.array(
				z.strictObject({
					id: PointIdSchema,
					revision: z.number().int().positive(),
					path: z.string().min(1),
				}),
			),
			fixtures: z.array(SnapshotFileSchema),
			// Files copied that the loader does not read: skills and koi.yaml.
			other: z.array(SnapshotFileSchema),
		}),
	]),
	takenAt: z.iso.datetime(),
});

export type InputSnapshot = z.infer<typeof InputSnapshotSchema>;

// sha256 over JSON with keys sorted at every level, so two writers of the
// same object get the same digest.
export function canonicalDigest(value: unknown): string {
	return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

export function canonicalJson(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
	if (value !== null && typeof value === 'object') {
		const entries = Object.entries(value as Record<string, unknown>)
			.filter(([, v]) => v !== undefined)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
		return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
	}
	return JSON.stringify(value);
}
