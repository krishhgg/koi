import {
	GhCommentPagesSchema,
	GhCommentSchema,
	GhPullRequestMergeSchema,
	GhPullRequestSchema,
} from '@koi/shared';
import {
	ExecError,
	type ExecOptions,
	type ExecResult,
	exec,
	FULL_OUTPUT,
	SpawnError,
} from './exec.ts';

// The pull request side of `koi up --pr N --comment`, through the gh CLI so it
// uses whatever GitHub login the user already has. Both throw GhMissingError
// when gh cannot be started.
export interface GitHub {
	// The pull request's head branch, the base branch it is opened against,
	// and the head commit as GitHub has it now. Any is undefined when gh
	// names none. Throws when gh cannot describe the pull request (an
	// ExecError with what gh said).
	pullRequestBranches(pr: number): Promise<PullRequestBranches>;
	// The paths a pull request changes, as GitHub lists them for its head
	// now (at most 3,000: a list that long may be cut). Throws when gh cannot
	// list them.
	pullRequestFiles(pr: number): Promise<string[]>;
	// The pull request as one GET of it through the REST API answers: the
	// base branch it is opened against, its head commit, and whether GitHub
	// can merge it into the base. Asking is what makes GitHub recompute its
	// merge (refs/pull/N/merge) when the base has moved on; fetching the ref
	// does not. Throws when gh cannot ask, or has no answer within
	// `timeoutMs` (at most GH_TIMEOUT_MS).
	pullRequestMergeState(
		pr: number,
		options?: { timeoutMs?: number },
	): Promise<PullRequestMergeState>;
	// Creates the preview comment, or edits the one already there. Returns its URL.
	upsertComment(pr: number, marker: string, body: string): Promise<string>;
}

export interface PullRequestBranches {
	head: string | undefined;
	base: string | undefined;
	// The head commit GitHub has now; undefined when gh did not say.
	headOid?: string | undefined;
}

export interface PullRequestMergeState {
	baseBranch: string;
	head: string;
	// True or false, or null while GitHub works it out.
	mergeable: boolean | null;
}

export class GhMissingError extends Error {
	constructor(cause: SpawnError) {
		super(
			`the GitHub CLI (gh) is not installed or cannot be started (${cause.message}); install it from https://cli.github.com and sign in with gh auth login`,
			{ cause },
		);
	}
}

// How long one gh command may take. gh talks to GitHub over the network; a
// stalled one fails koi up with an error rather than holding it forever.
export const GH_TIMEOUT_MS = 2 * 60_000;

// `run` is exec, or a stand-in for it in tests.
export function ghCli(
	ownerRepo: string,
	run: (cmd: string[], options?: ExecOptions) => Promise<ExecResult> = exec,
): GitHub {
	// Throws when gh could not be started or ran out of time: GH_TIMEOUT_MS,
	// or less when `options` says so.
	const gh = async (cmd: string[], options: ExecOptions = {}) => {
		const timeoutMs = Math.min(GH_TIMEOUT_MS, options.timeoutMs ?? GH_TIMEOUT_MS);
		let r: ExecResult;
		try {
			r = await run(cmd, { ...options, timeoutMs });
		} catch (err) {
			throw err instanceof SpawnError ? new GhMissingError(err) : err;
		}
		if (r.timedOut) throw new ExecError(cmd, r, timeoutMs);
		return r;
	};
	// gh api output is parsed whole, so a long page is an error, never a cut one.
	const api = async (...args: string[]) => {
		const cmd = ['gh', 'api', ...args];
		const r = await gh(cmd, { maxBytes: FULL_OUTPUT });
		if (r.code !== 0) throw new ExecError(cmd, r);
		return r;
	};
	return {
		async pullRequestBranches(pr) {
			const cmd = [
				'gh',
				'pr',
				'view',
				String(pr),
				'--repo',
				ownerRepo,
				'--json',
				'headRefName,baseRefName,headRefOid',
			];
			const r = await gh(cmd);
			if (r.code !== 0) throw new ExecError(cmd, r);
			const view = GhPullRequestSchema.parse(JSON.parse(r.stdout));
			const named = (name: string | undefined) =>
				name !== undefined && name !== '' ? name : undefined;
			return {
				head: named(view.headRefName),
				base: named(view.baseRefName),
				headOid: named(view.headRefOid),
			};
		},
		async pullRequestFiles(pr) {
			// Names only. The full records carry each file's patch, and those run
			// past exec's default limit for a pull request with only a few large
			// diffs: one seen in practice changes 17 files and lists 285,542 bytes.
			const r = await api(
				'--paginate',
				'--jq',
				'.[].filename',
				`repos/${ownerRepo}/pulls/${pr}/files`,
			);
			return r.stdout.split('\n').filter((f) => f !== '');
		},
		async pullRequestMergeState(pr, options = {}) {
			// The response's base.sha is not read. It is not the base branch's
			// tip: GitHub leaves it where the base was at the pull request's
			// last push, and does not move it when it remakes the merge onto a
			// later base, as the base of git/git#2000 showed (base.sha 16bd9f2,
			// the remade merge's first parent 77904e5, master's tip).
			const cmd = [
				'gh',
				'api',
				'--jq',
				'{base: .base.ref, head: .head.sha, mergeable: .mergeable}',
				`repos/${ownerRepo}/pulls/${pr}`,
			];
			const r = await gh(cmd, options);
			if (r.code !== 0) throw new ExecError(cmd, r);
			let answer: unknown;
			try {
				answer = JSON.parse(r.stdout);
			} catch {
				answer = undefined;
			}
			const parsed = GhPullRequestMergeSchema.safeParse(answer);
			if (!parsed.success) {
				throw new Error(
					`gh api repos/${ownerRepo}/pulls/${pr} answered ${JSON.stringify(r.stdout.trim().slice(0, 120))}, not the pull request's base branch, head commit and mergeability`,
				);
			}
			const { base, head, mergeable } = parsed.data;
			return { baseBranch: base, head, mergeable };
		},
		async upsertComment(pr, marker, body) {
			// Only a comment this gh user wrote whose first line is the marker is
			// edited. Anyone can quote the marker, or start their own comment with it.
			const me = (await api('user', '--jq', '.login')).stdout.trim();
			if (me === '') throw new Error('gh api user did not say who is signed in');
			const listed = await api('--paginate', '--slurp', `repos/${ownerRepo}/issues/${pr}/comments`);
			const comments = GhCommentPagesSchema.parse(JSON.parse(listed.stdout)).flat();
			const existing = comments.find(
				(c) => c.user?.login === me && firstLine(c.body ?? '') === marker,
			);
			const out = existing
				? await api(
						'--method',
						'PATCH',
						`repos/${ownerRepo}/issues/comments/${existing.id}`,
						'-f',
						`body=${body}`,
					)
				: await api(
						'--method',
						'POST',
						`repos/${ownerRepo}/issues/${pr}/comments`,
						'-f',
						`body=${body}`,
					);
			return GhCommentSchema.parse(JSON.parse(out.stdout)).html_url;
		},
	};
}

// GitHub may store a comment edited in the browser with CRLF line ends.
function firstLine(text: string): string {
	const end = text.indexOf('\n');
	return (end === -1 ? text : text.slice(0, end)).replace(/\r$/, '');
}

// github.com/acme/app -> acme/app; previews of other hosts cannot comment.
export function ownerRepoFor(repoId: string): string {
	const [host, owner, name] = repoId.split('/');
	if (host !== 'github.com' || owner === undefined || name === undefined) {
		throw new Error(`--comment only works for GitHub repositories, not ${repoId}`);
	}
	return `${owner}/${name}`;
}

export function commentMarker(label: string): string {
	return `<!-- koi-preview:${label} -->`;
}

export function commentBody(p: {
	label: string;
	url: string;
	// What was built, in words (see builtFrom in up.ts): "#7 (abc1234) merged
	// into develop (def5678), merge commit 9abcdef".
	built: string;
	status: string;
	error?: string | undefined;
	loginKey?: string | undefined;
	// The keys page for this preview (see keysPageUrl).
	keysUrl: string;
}): string {
	const lines = [commentMarker(p.label)];
	if (p.status === 'running') {
		lines.push(`**Preview:** ${p.url}`);
		if (p.loginKey !== undefined) {
			lines.push(
				`**Login key:** \`${p.loginKey}\` (this preview only; it holds no secrets of yours)`,
			);
		}
		lines.push(
			'',
			`Built from ${p.built}. The first visit after a quiet spell takes about a minute while the box wakes up.`,
			'',
			`Nodes that call an LLM need a key: open ${p.keysUrl}, paste your provider keys there, and use the koi tokens it gives you in the nodes, one per provider. The tokens work only in this preview, which never sees your real keys.`,
		);
	} else {
		lines.push(
			`**Preview build failed** for ${p.built}. ${p.url} still serves the previous version, if there was one.`,
			'',
			`The author can see why with \`koi logs --build ${p.label}\`.`,
		);
	}
	return lines.join('\n');
}
