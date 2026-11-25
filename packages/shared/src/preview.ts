import { z } from 'zod';
import { DeploymentSliceSchema } from './recipe.ts';

export const PreviewStatusSchema = z.enum([
	// Accepted by koid and waiting for its turn to build.
	'queued',
	'building',
	'starting',
	'running',
	'stopped',
	'failed',
	'expired',
]);

export type PreviewStatus = z.infer<typeof PreviewStatusSchema>;

// The statuses of a request koid is still working on. Any other status is a
// verdict on the build: the preview runs, failed, was stopped or expired,
// and its build log will not grow.
export const IN_FLIGHT_STATUSES: ReadonlySet<PreviewStatus> = new Set<PreviewStatus>([
	'queued',
	'building',
	'starting',
]);

// A hostname label as RFC 1123 allows it: 1 to 63 lowercase letters, digits and
// dashes, no leading or trailing dash. Every preview is one label under the
// base domain, and this is the one definition of what that label may be.
// A preview's label: one DNS label. The egress proxy (koi_egress.py,
// LABEL_RE) and the keys page check labels with the same pattern.
export const PREVIEW_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export const PreviewLabelSchema = z.string().regex(PREVIEW_LABEL);

// The preview label in a Host header, or null unless the host is exactly one
// valid label followed by ".<domain>". Rejects other domains, nested
// subdomains, ports and the bare domain.
export function labelFromHost(host: string | null | undefined, domain: string): string | null {
	const suffix = `.${domain}`;
	if (!host || !domain || !host.endsWith(suffix)) {
		return null;
	}
	const label = host.slice(0, -suffix.length);
	return PreviewLabelSchema.safeParse(label).success ? label : null;
}

// A pull request number. The upper bound keeps it an exact integer, so it
// prints as plain digits (1e21 would print as "1e+21").
export const PrNumberSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);

// A pull request built as GitHub's merge of it into its base branch
// (refs/pull/N/merge). The request's and the record's `commit` is then that
// merge, and this names the merge's two parents: the pull request's head and
// the base it was merged into, with the base branch's name when the CLI could
// learn it from gh. A working tree, and a pull request built from its head
// with --head, have none.
export const PullRequestMergeSchema = z.object({
	head: z.string().regex(/^[0-9a-f]{40}$/),
	base: z.string().regex(/^[0-9a-f]{40}$/),
	baseBranch: z.string().min(1).max(255).optional(),
});

export type PullRequestMerge = z.infer<typeof PullRequestMergeSchema>;

// A git object id as koi's repositories name objects: SHA-1, 40 hex digits.
const GitObjectIdSchema = z.string().regex(/^[0-9a-f]{40}$/);

// What a deployment was built from, as koid computed it from the directory
// it unpacked the build's source tarball into, after unpacking and before
// the build (daemon/src/source-tree.ts), never from anything the CLI says
// about it. `digest` is exact over every entry the build could read,
// .koi-runtime/ included; `tree` is git's view of the project's files and
// `runtimeTree` that of what koi added under .koi-runtime/, which no commit
// holds. `matchesCommit` says whether `tree` is the tree of the
// deployment's commit, which koid reads from the commit object the request
// carried after checking that it hashes to the commit (deploymentSourceOf
// in the daemon). Absent when the request had none, as from a CLI older
// than this field, or one that does not hash to the commit.
//
// Evidence about a deployment is bound to deploymentId and `digest`:
// `digest` says which upload the build was given, `tree` which commit's
// content that upload is, by comparison with a tree the consumer computes
// itself.
export const DeploymentSourceSchema = z.object({
	digest: z
		.string()
		.regex(/^sha256:[0-9a-f]{64}$/)
		.describe(
			"The SHA-256 of a listing of every entry under the directory koid unpacked the source into, read after unpacking and before the build, .koi-runtime/ included: each path, its type, its permission bits, a file's size and the SHA-256 of its bytes, a symlink's target, every directory whether or not it holds a file, which paths are second names of an inode named earlier, and fifos, sockets and devices by path and mode, never opened. Owners and times are left out. Two deployments with the same digest were given the same unpacked upload; which of its entries the Docker build reads is up to the recipe's Dockerfile and .dockerignore. Bind evidence to deployment.deploymentId together with source.digest; use source.tree to learn which commit's content that is. The format is in packages/daemon/src/source-tree.ts.",
		),
	tree: GitObjectIdSchema.optional().describe(
		"The git tree id of the files of the upload koid unpacked for the build, .koi-runtime/ left out: a file is a blob of its bytes as unpacked, 100755 when the owner may execute it and 100644 otherwise, a symlink a blob of its target, a directory with no file under it left out. When the upload is exactly a commit's files it is what git rev-parse COMMIT^{tree} prints. It keeps only what git keeps, so uploads that differ in empty directories, other permission bits or hard links share it; source.digest tells them apart. To learn which commit's content an upload is, compare tree with a tree you compute yourself from your own copy of the repository, packed as the upload was: git rev-parse COMMIT^{tree}; or, where git converts files on checkout (eol=crlf, core.autocrlf, a filter such as LFS) or the commit has a submodule, for a koi up --pr build what git archive COMMIT | bun scripts/source-tree.ts - prints (export-ignore and export-subst apply), and for a local build of a clean checkout of COMMIT what git ls-files -z | tar --null -T - -czf - | bun scripts/source-tree.ts - prints. Use the build's core.autocrlf. Absent when the source holds a fifo, socket or device, which git has no object for.",
	),
	runtimeTree: GitObjectIdSchema.optional().describe(
		'The git tree id of .koi-runtime/, the files koi adds to every build (changed-files.txt, which decides what a slicing recipe keeps), computed by koid the same way. No commit holds them. Absent for an upload without them, and whenever tree is.',
	),
	matchesCommit: z
		.boolean()
		.optional()
		.describe(
			"Whether tree is exactly the tree of the deployment's commit, as koid read it from the commit object the request carried, which koid checked hashes to that commit. true means the upload is exactly the commit's files as git stores them. false says only that tree differs from the commit's: a change not committed, a file git converts on checkout and a submodule each make it false, and dirty, which is only the CLI's report, does not tell which. Absent when the request carried no commit object, as from a koi older than this field, and when tree is.",
		),
});

export type DeploymentSource = z.infer<typeof DeploymentSourceSchema>;

// Names one attempt at building a request: koid gives each acceptance of a
// request a new one, a retry of the same request id included.
export const AttemptSchema = z.string().regex(/^[a-z0-9]{16,40}$/);

// What is serving under a label: the image built from one request and how it
// was started. Kept even while a newer build runs or after one fails, so the
// previous version keeps serving until a new one is healthy.
export const DeploymentSchema = z.object({
	requestId: z.string().regex(/^[a-z0-9]{16,40}$/),
	// The attempt that built this deployment, which is its id. An attempt
	// builds at most once, so no two deployments share one; the request id
	// would not do, since the same request accepted again after koi down
	// builds a new image under the same id. It is also the name of the
	// build log the deployment came from. Absent in records written before
	// koid kept it.
	deploymentId: AttemptSchema.optional(),
	// The image by content: the id Docker gave the image koid built, the
	// sha256 of its configuration (DigestSchema in verify.ts, which this
	// file cannot import). Two builds of one commit are told apart by it.
	// Absent in records written before koid kept it.
	imageDigest: z
		.string()
		.regex(/^sha256:[0-9a-f]{64}$/)
		.optional(),
	commit: z.string().regex(/^[0-9a-f]{40}$/),
	// What `commit` merges, when the request built GitHub's merge of a pull
	// request (see PullRequestMergeSchema). The record's own `merge` is the
	// latest request's, which is not what serves while that request builds
	// or after it failed. Absent for a working tree, a pull request's head,
	// and records written before koid kept it.
	merge: PullRequestMergeSchema.optional(),
	image: z.string().min(1),
	container: z.string().min(1),
	port: z.number().int().min(1).max(65535),
	healthPath: z.string().startsWith('/'),
	healthTimeoutSeconds: z.number().int().positive(),
	user: z.string().min(1),
	env: z.record(z.string(), z.string()),
	deployedAt: z.iso.datetime(),
	// What the build kept of the project, read from the image at the
	// recipe's sliceFile (DeploymentSliceSchema). Absent for a recipe with
	// none, and in records written before koid kept it.
	slice: DeploymentSliceSchema.optional(),
	// What the build read, as koid computed it (DeploymentSourceSchema).
	// Absent when koid could not compute it, and in records written before
	// koid kept it.
	source: DeploymentSourceSchema.optional(),
	// Set when koid stopped this deployment for good: "disk" when its writable
	// layer grew past the limit. A visit does not start it again; the next
	// deployment replaces it.
	halted: z.enum(['disk']).optional(),
});

export type Deployment = z.infer<typeof DeploymentSchema>;

// A preview's login key: random, per preview, stable across redeploys.
export const LoginKeySchema = z.string().regex(/^koi-[a-z0-9]{24}$/);

// The most a lease may run, in seconds: two hours. Long enough for a
// verification run, short enough that a lease nobody released does not
// block a label for a working day.
export const LEASE_MAX_SECONDS = 2 * 60 * 60;

// Who holds a lease, in their own words: a user and host, or a run id.
// Printed in the message a refused build gets, so no control characters.
export const LeaseHolderSchema = z
	.string()
	.min(1)
	.max(200)
	.refine((h) => !/\p{Cc}/u.test(h), 'must not contain control characters');

// A lease's id, from the same alphabet as request ids and attempts.
export const LeaseIdSchema = z.string().regex(/^[a-z0-9]{16,40}$/);

// A hold on a preview, so that a verification run sees one build from start
// to end: while it lasts, koid refuses a build for the label before building
// anything, and koi down needs --force. A preview has at most one, bound to
// the deployment serving when it was taken. Expiry is wall clock, so the
// lease outlives a koid restart and the box sleeping, and ends on time
// either way.
export const LeaseSchema = z.object({
	leaseId: LeaseIdSchema,
	deploymentId: AttemptSchema,
	holder: LeaseHolderSchema,
	acquiredAt: z.iso.datetime(),
	expiresAt: z.iso.datetime(),
});

export type Lease = z.infer<typeof LeaseSchema>;

// One record per preview, kept by the daemon on the box. The hostname label is
// the primary key. `status`, `error`, `commit`, `branch`, `pr`, `merge`,
// `dirty`, `requestId` and `attempt` describe the latest attempt;
// `deployment` is what serves, and `lease` holds it there.
export const PreviewRecordSchema = z.object({
	label: PreviewLabelSchema,
	project: z.string().min(1),
	// host/owner/name of the source repository. A label belongs to one repo; the
	// daemon refuses to replace it from another.
	repo: z.string().min(1),
	status: PreviewStatusSchema,
	commit: z.string().regex(/^[0-9a-f]{40}$/),
	branch: z.string().min(1),
	pr: PrNumberSchema.optional(),
	// Absent in records written before koid kept it, and for builds of a
	// working tree or a pull request's head.
	merge: PullRequestMergeSchema.optional(),
	dirty: z.boolean(),
	requestId: z.string().regex(/^[a-z0-9]{16,40}$/),
	// Which acceptance of requestId the record describes (see AttemptSchema).
	// A build changes the record only while it still carries the build's
	// attempt. Empty in records written before koid kept it, until koid gives
	// them one as it starts (PreviewStore.init); no build has that one.
	attempt: AttemptSchema.or(z.literal('')).default(''),
	ttlDays: z.number().int().positive(),
	createdAt: z.iso.datetime(),
	updatedAt: z.iso.datetime(),
	lastVisitAt: z.iso.datetime().optional(),
	error: z.string().optional(),
	// The preview's login key, when its recipe has a loginKeyEnv.
	loginKey: LoginKeySchema.optional(),
	deployment: DeploymentSchema.optional(),
	// Kept until it expires or is released; an expired one is ignored and
	// swept away (Deployer.expire). Absent in records written before koid
	// kept it.
	lease: LeaseSchema.optional(),
});

export type PreviewRecord = z.infer<typeof PreviewRecordSchema>;

// Labels of previews allowed to wake the box. The daemon writes this to the
// SSM parameter; the wake function reads it.
export const LivePreviewsSchema = z.array(PreviewLabelSchema);

// The SSM parameter that holds the list is a standard one, which holds at
// most 4,096 bytes: about 60 previews with the longest labels.
export const LIVE_PREVIEWS_MAX_BYTES = 4096;

// The list as the daemon publishes it: each label once, sorted, as JSON.
export function encodeLivePreviews(labels: string[]): string {
	return JSON.stringify(LivePreviewsSchema.parse([...new Set(labels)].sort()));
}

// Whether the list of these labels fits in the parameter.
export function livePreviewsFit(labels: string[]): boolean {
	return new TextEncoder().encode(encodeLivePreviews(labels)).length <= LIVE_PREVIEWS_MAX_BYTES;
}
