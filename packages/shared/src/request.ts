import { createHash } from 'node:crypto';
import { z } from 'zod';
import { PreviewLabelSchema, PrNumberSchema, PullRequestMergeSchema } from './preview.ts';
import { ProjectNameSchema, RepoRecipeSchema } from './recipe.ts';

// What `koi up` asks the daemon to do. The CLI writes it to the uploads bucket
// next to the source tarball; the SSM command that wakes the daemon carries
// only the request id, so no caller-supplied text is ever interpreted by a
// shell on the box.

// Lowercase letters and digits only: safe to place in an S3 key and on a
// command line without quoting.
export const RequestIdSchema = z.string().regex(/^[a-z0-9]{16,40}$/);

// 20 random lowercase letters and digits, as RequestIdSchema and
// AttemptSchema take: a new request id, or a new attempt.
export function randomId(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(20));
	return Array.from(bytes, (b) => 'abcdefghijklmnopqrstuvwxyz0123456789'[b % 36]).join('');
}

// A source repository as host/owner/name, lowercased: github.com/acme/app.
export const RepoIdSchema = z
	.string()
	.regex(/^[a-z0-9.-]+\/[a-z0-9._-]+\/[a-z0-9._-]+$/, 'host/owner/name, lowercase');

export const CommitSchema = z.string().regex(/^[0-9a-f]{40}$/);

// A name koi up --keep passes to the recipe: something its slice keeps
// whatever the pull request changed, which the recipe alone gives a meaning
// (a node, say). Letters, digits, dots, dashes and underscores, starting
// with a letter or digit, so a recipe's build may put it on a command line
// or in a file without quoting.
export const KEEP_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const MAX_KEEP = 32;

export const KeepNameSchema = z
	.string()
	.regex(
		KEEP_NAME,
		'1 to 64 letters, digits, dots, dashes and underscores, from a letter or digit',
	);

// The names, each once. koid hands them to the build as the build argument
// KOI_KEEP, joined by single spaces.
export const KeepSchema = z
	.array(KeepNameSchema)
	.min(1)
	.max(MAX_KEEP)
	.refine((names) => new Set(names).size === names.length, 'each name once');

// The most bytes of a commit object a request carries. A commit's headers
// take a few hundred bytes, a signature about a thousand more; past this the
// message is long, and koi up sends no object.
export const MAX_COMMIT_OBJECT_BYTES = 32 * 1024;

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// How many bytes base64 text (BASE64, padded) decodes to.
function base64Bytes(text: string): number {
	return (text.length / 4) * 3 - (text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0);
}

// The id git gives a commit object of these bytes: the SHA-1 of its header
// ("commit", its size, a NUL) and the bytes.
export function commitObjectId(bytes: Uint8Array): string {
	return createHash('sha1').update(`commit ${bytes.length}\0`).update(bytes).digest('hex');
}

// The tree a commit object names on its first line, as git writes every
// commit, or undefined when it does not start so.
export function commitObjectTree(bytes: Uint8Array): string | undefined {
	return /^tree ([0-9a-f]{40})\n/.exec(Buffer.from(bytes.subarray(0, 46)).toString('latin1'))?.[1];
}

export const UpRequestSchema = z.object({
	version: z.literal(1),
	id: RequestIdSchema,
	label: PreviewLabelSchema,
	project: ProjectNameSchema,
	repo: RepoIdSchema,
	commit: CommitSchema,
	// The commit object of `commit`, as git cat-file commit prints it, in
	// base64, for koid to read the commit's tree from. koid takes it only
	// when it hashes to `commit` (deploymentSourceOf in the daemon), so it
	// can name no tree but that commit's. Absent from a CLI older than it,
	// and when the object is over MAX_COMMIT_OBJECT_BYTES.
	commitObject: z
		.string()
		.max(Math.ceil(MAX_COMMIT_OBJECT_BYTES / 3) * 4)
		.regex(BASE64, 'base64')
		.refine(
			(text) => base64Bytes(text) <= MAX_COMMIT_OBJECT_BYTES,
			`at most ${MAX_COMMIT_OBJECT_BYTES} bytes`,
		)
		.optional(),
	branch: z.string().min(1).max(255),
	pr: PrNumberSchema.optional(),
	// With `pr`, when `commit` is GitHub's merge of the pull request into its
	// base: the head and base it merged (see PullRequestMergeSchema).
	merge: PullRequestMergeSchema.optional(),
	// The working tree had changes not in `commit`.
	dirty: z.boolean(),
	// koi up --keep: names the recipe's slice keeps (KeepSchema). Only for a
	// built-in recipe with a sliceFile, whose slice says what it kept.
	keep: KeepSchema.optional(),
	recipe: z.discriminatedUnion('kind', [
		z.object({ kind: z.literal('builtin'), name: ProjectNameSchema }),
		z.object({ kind: z.literal('repo'), recipe: RepoRecipeSchema }),
	]),
	createdAt: z.iso.datetime(),
});

export type UpRequest = z.infer<typeof UpRequestSchema>;

// Object keys in the uploads bucket. Both take a validated id.
export function requestKey(id: string): string {
	return `requests/${RequestIdSchema.parse(id)}.json`;
}

export function sourceKey(id: string): string {
	return `sources/${RequestIdSchema.parse(id)}.tar.gz`;
}

// Normalises the common git remote forms to host/owner/name:
//   https://github.com/Acme/App.git, git@github.com:acme/app, ssh://git@github.com/acme/app
export function repoIdFromRemote(remote: string): string {
	const trimmed = remote.trim();
	let host: string;
	let path: string;
	const scp = /^[^@/\s]+@([^:/\s]+):(.+)$/.exec(trimmed);
	if (scp?.[1] !== undefined && scp[2] !== undefined) {
		host = scp[1];
		path = scp[2];
	} else {
		let url: URL;
		try {
			url = new URL(trimmed);
		} catch {
			throw new Error(`cannot read a repository from remote ${JSON.stringify(remote)}`);
		}
		host = url.hostname;
		path = url.pathname;
	}
	const parts = path
		.replace(/\.git$/i, '')
		.split('/')
		.filter((p) => p !== '');
	const owner = parts[0];
	const name = parts[1];
	if (parts.length !== 2 || owner === undefined || name === undefined) {
		throw new Error(`cannot read owner/name from remote ${JSON.stringify(remote)}`);
	}
	return RepoIdSchema.parse(`${host}/${owner}/${name}`.toLowerCase());
}
