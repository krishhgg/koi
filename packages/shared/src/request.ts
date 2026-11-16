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

export const UpRequestSchema = z.object({
	version: z.literal(1),
	id: RequestIdSchema,
	label: PreviewLabelSchema,
	project: ProjectNameSchema,
	repo: RepoIdSchema,
	commit: CommitSchema,
	branch: z.string().min(1).max(255),
	pr: PrNumberSchema.optional(),
	// With `pr`, when `commit` is GitHub's merge of the pull request into its
	// base: the head and base it merged (see PullRequestMergeSchema).
	merge: PullRequestMergeSchema.optional(),
	// The working tree had changes not in `commit`.
	dirty: z.boolean(),
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
