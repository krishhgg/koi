import { z } from 'zod';

// What `gh` prints for the calls `koi up --pr N` makes, as far as koi reads it.

// `gh pr view N --json headRefName,baseRefName`.
export const GhPullRequestSchema = z.object({
	headRefName: z.string(),
	baseRefName: z.string(),
	// The head commit, when asked for.
	headRefOid: z.string().optional(),
});

// `gh api repos/{owner}/{repo}/pulls/N` with --jq picking out, from the one
// response, the base branch's name, the head commit, and whether GitHub can
// merge the pull request (null while it works that out).
export const GhPullRequestMergeSchema = z.object({
	base: z.string().min(1),
	head: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
	mergeable: z.boolean().nullable(),
});

// An issue comment from the GitHub REST API. A deleted account's comments
// have no user.
export const GhCommentSchema = z.object({
	id: z.number().int().positive(),
	body: z.string().nullable(),
	html_url: z.string(),
	user: z.object({ login: z.string() }).nullable(),
});

export type GhComment = z.infer<typeof GhCommentSchema>;

// `gh api --paginate --slurp`: one array per page.
export const GhCommentPagesSchema = z.array(z.array(GhCommentSchema));
