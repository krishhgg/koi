import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	CTL_EXIT,
	NO_SUCH_PREVIEW,
	type PullRequestMerge,
	previewHostLabel,
	type Recipe,
	repoIdFromRemote,
	type StatusReply,
	StatusReplySchema,
	UpAcceptedSchema,
	type UpRequest,
	UpRequestSchema,
	type UpResult,
} from '@koi/shared';
import { type Box, BoxUnavailableError, type CtlResult, ctlErrorText } from './box.ts';
import { ExecError } from './exec.ts';
import { finishTarball, type Git, koiFiles, type PullRequestRefs, packWorkingTree } from './git.ts';
import {
	commentBody,
	commentMarker,
	GhMissingError,
	type GitHub,
	type PullRequestBranches,
} from './github.ts';
import { resolveRecipe } from './recipe.ts';

export interface UpOptions {
	pr?: number | undefined;
	comment: boolean;
	// With pr: build the pull request's head as pushed, not GitHub's merge of
	// it into its base.
	head?: boolean | undefined;
	// Names the recipe's slice keeps whatever the change touched (KeepSchema).
	// Only for a recipe that reports its slice.
	keep?: string[] | undefined;
}

export interface UpDeps {
	git: Git;
	box: Box;
	domain: string;
	builtins: Recipe[];
	github: (ownerRepo: string) => GitHub;
	ownerRepo: (repoId: string) => string;
	progress: (message: string) => void;
	buildLine: (line: string) => void;
	randomId: () => string;
	now: () => Date;
	// Milliseconds on a clock that only moves forward (performance.now()),
	// for deadlines: now() jumps when the system clock is set.
	clock: () => number;
	sleep: (ms: number) => Promise<void>;
}

// How long koi up waits for koid to start building a request queued behind
// other builds. koid keeps the request after that and builds it in turn.
export const QUEUE_WAIT_MS = 6 * 60 * 60_000;

// What a build takes beyond its recipe's build and health time limits:
// fetching and unpacking the source, starting and routing the container,
// and the time between polls.
export const BUILD_MARGIN_MS = 15 * 60_000;

// How long koi up keeps asking for a preview's status while SSM or koid
// cannot answer, as while koid restarts.
export const STATUS_RETRY_MS = 5 * 60_000;

// The keys page for one preview, where reviewers register provider keys and
// get koi tokens that work only in that preview: the reserved label keys
// under the previews' domain, with the preview's label in ?for=.
export function keysPageUrl(domain: string, label: string): string {
	return `https://keys.${domain}/?for=${encodeURIComponent(label)}`;
}

// What one request to a preview's health URL came back with: the status, or
// why nothing answered.
export type HealthAnswer = { status: number } | { error: string };

export interface WakeDeps {
	probe: (url: string) => Promise<HealthAnswer>;
	sleep: (ms: number) => Promise<void>;
	now: () => Date;
	progress: (message: string) => void;
}

// How long koi lease waits for a preview to answer its health check, and
// how often it asks. A start takes seconds, or the recipe's health time
// limit when the app is slow; past this, something is wrong and the
// caller should look rather than wait.
export const WAKE_WAIT_MS = 90_000;
export const WAKE_POLL_MS = 3_000;
// How often the wait says it is still waiting.
const WAKE_REPORT_MS = 15_000;

// Starts a preview the way a visit does, and returns once it serves. After
// the box wakes every preview is stopped until someone asks for it, and
// koid refuses to lease a stopped one. Caddy sends /__koi/* to koid
// whatever the preview does; koid starts a stopped preview on the request
// and answers 200 only once the container runs and is routed, which is the
// check koid makes before it leases. Throws after WAKE_WAIT_MS with the
// last answer, and at once when koid has no such preview.
export async function wakePreview(label: string, domain: string, deps: WakeDeps): Promise<void> {
	const url = `https://${label}.${domain}/__koi/health`;
	const since = deps.now().getTime();
	// Whether the wait has been announced, and when it last said anything.
	let said = false;
	let reported = since;
	for (;;) {
		const answer = await deps.probe(url);
		if ('status' in answer && answer.status === 200) return;
		if ('status' in answer && answer.status === 404) {
			throw new Error(`koid has no preview named ${label}; see koi list`);
		}
		const last = 'status' in answer ? `HTTP ${answer.status}` : `no answer (${answer.error})`;
		const now = deps.now().getTime();
		if (now - since >= WAKE_WAIT_MS) {
			throw new Error(
				`${label} did not start within ${seconds(WAKE_WAIT_MS)} seconds; the last check of ${url} got ${last}. See koi list, or koi logs ${label}`,
			);
		}
		if (!said) {
			// Only once the first answer is not 200, so a running preview adds
			// nothing to the output.
			deps.progress(`waking ${label}`);
			said = true;
		} else if (now - reported >= WAKE_REPORT_MS) {
			deps.progress(`still waiting for ${label} to start (${last} after ${seconds(now - since)}s)`);
			reported = now;
		}
		await deps.sleep(WAKE_POLL_MS);
	}
}

export async function up(options: UpOptions, deps: UpDeps): Promise<UpResult> {
	const { git, box } = deps;
	const root = await git.root();
	const repo = repoIdFromRemote(await git.remote());
	const work = await mkdtemp(join(tmpdir(), 'koi-up-'));
	const tar = join(work, 'source.tar');
	try {
		let commit: string;
		let merge: PullRequestMerge | undefined;
		// Whether koi made the merge itself, GitHub's being out of date.
		let madeByKoi = false;
		let branch: string;
		let dirty: boolean;
		let read: (path: string) => Promise<string | undefined>;
		let changed: string[];
		const ownerRepo =
			options.pr !== undefined || options.comment ? deps.ownerRepo(repo) : undefined;

		if (options.pr !== undefined) {
			deps.progress(`fetching pull request ${options.pr}`);
			const refs = await git.fetchPullRequest(options.pr);
			if (refs.head === undefined) throw new Error(noPullRequest(options.pr));
			const gh = ownerRepo !== undefined ? await askGh(deps.github(ownerRepo), options.pr) : {};
			// --comment posts through gh, so without gh it stops here, before
			// anything is built.
			if (options.comment && gh.failed instanceof GhMissingError) {
				throw new Error(`--comment posts through gh, and ${gh.failed.message}`);
			}
			branch = gh.branches?.head ?? `pr-${options.pr}`;
			if (options.head) {
				commit = refs.head;
			} else {
				// A merge of the head into the base, which is what merging the
				// pull request now would give, as long as both parents are
				// current: GitHub's, or koi's own when GitHub's stays out of date
				// (see currentMerge). Checking the base needs its branch's name,
				// which only gh can give.
				if (refs.merge === undefined) throw new Error(noMerge(options.pr, gh.branches?.base));
				const baseBranch = gh.branches?.base;
				if (baseBranch === undefined || ownerRepo === undefined) {
					throw new Error(needsGh(options.pr, ownerRepo ?? repo, gh.failed));
				}
				const built = await currentMerge(
					options.pr,
					{ baseBranch, head: gh.branches?.headOid },
					{ head: refs.head, merge: refs.merge },
					deps.github(ownerRepo),
					deps,
				);
				commit = built.commit;
				merge = built.merge;
				madeByKoi = built.madeByKoi;
			}
			dirty = false;
			const at = commit;
			read = (path) => git.show(at, path);
			// What the pull request changes decides the preview's slice (what the
			// recipe keeps of the project), so the list must describe the tree
			// koi builds, whole. A merge build lists it from the merge itself,
			// against the base it was merged into: the one list tied to that
			// tree, with no limit. A head build takes GitHub's list, which
			// describes the head GitHub has now and stops at 3,000 files, so it
			// is taken only when that head is the one koi fetched and the list
			// is short of the limit; when gh cannot list the files, git can,
			// given GitHub's merge: the head against the merge's base parent.
			// Without either, koi stops here rather than guess.
			if (merge !== undefined) {
				changed = await git.mergeFiles(options.pr, commit);
			} else {
				const listed =
					ownerRepo === undefined
						? new Error('koi has no GitHub repository to ask')
						: await pullRequestFiles(deps, ownerRepo, options.pr);
				if (listed instanceof Error) {
					const base = refs.merge?.parents[0];
					if (base === undefined) throw new Error(noFileList(options.pr, listed));
					deps.progress(
						`gh could not list the files pull request ${options.pr} changes (${listed.message}); listing them from git, the head ${refs.head.slice(0, 7)} against its base ${base.slice(0, 7)}`,
					);
					changed = await git.diffFiles(base, refs.head);
				} else {
					const now = gh.branches?.headOid;
					if (now !== undefined && now !== refs.head) {
						throw new Error(movedHead(options.pr, refs.head, now));
					}
					if (listed.length >= GITHUB_FILES_LIMIT) {
						throw new Error(cutFileList(options.pr, listed.length));
					}
					changed = listed;
				}
			}
			await git.archive(commit, tar);
			deps.progress(`building ${builtFrom({ commit, pr: options.pr, merge, madeByKoi })}`);
		} else {
			if (options.comment) throw new Error('--comment needs --pr');
			commit = await git.head();
			branch = await git.branch();
			dirty = await git.dirty();
			read = async (path) => readFile(join(root, path), 'utf8').catch(() => undefined);
			const listed = await git.changedFiles();
			if (listed === undefined) throw new Error(noBaseBranch());
			changed = listed;
			const count = await packWorkingTree(root, await git.files(), tar);
			deps.progress(
				`packed ${count} files from ${branch}${dirty ? ' (with uncommitted changes)' : ''}`,
			);
		}

		const tarball = await finishTarball(tar, koiFiles(changed));
		const { project, recipe, limits, reportsSlice } = await resolveRecipe(
			repo,
			deps.builtins,
			read,
		);
		// Before anything is uploaded. koid checks again, against the recipe
		// as installed on the box.
		if (options.keep !== undefined && !reportsSlice) {
			const which = recipe.kind === 'builtin' ? `the recipe ${recipe.name}` : `${repo}'s koi.yaml`;
			throw new Error(
				`--keep needs a recipe that reports what its slice kept (a sliceFile in its recipe.json), and ${which} has none; run koi up without --keep`,
			);
		}
		const label = previewHostLabel(
			project,
			options.pr !== undefined ? { pr: options.pr } : { branch },
		);
		const url = `https://${label}.${deps.domain}`;
		const request: UpRequest = UpRequestSchema.parse({
			version: 1,
			id: deps.randomId(),
			label,
			project,
			repo,
			commit,
			branch,
			...(options.pr !== undefined ? { pr: options.pr } : {}),
			...(merge !== undefined ? { merge } : {}),
			dirty,
			...(options.keep !== undefined ? { keep: options.keep } : {}),
			recipe,
			createdAt: deps.now().toISOString(),
		});

		deps.progress(`uploading ${label}`);
		await box.upload(request, tarball);
		await box.ensureAwake(deps.progress);
		const accepted = await box.ctl(['up', request.id]);
		if (accepted.code !== 0)
			throw new Error(ctlErrorText(accepted) || 'the box refused the request');
		if (UpAcceptedSchema.parse(JSON.parse(accepted.stdout)).queued) {
			deps.progress(
				`waiting for another build on the box to finish; koi waits up to ${hours(QUEUE_WAIT_MS)} hours for its turn`,
			);
		}

		const buildMs =
			limits.buildTimeoutMinutes * 60_000 + limits.healthTimeoutSeconds * 1000 + BUILD_MARGIN_MS;
		const followed = await follow(label, request.id, buildMs, deps);
		const record = followed?.record;
		const deployment = followed?.deployment;
		const slice = followed?.slice;
		// A koid older than this CLI drops --keep from the request and has no
		// slice to give, so the build ran without the names. No reply of
		// koid's says its version before the upload, so koi up finds out
		// here, and fails: the preview does not hold what was asked for.
		const unkept =
			options.keep !== undefined && record?.status === 'running' && slice === undefined
				? `koid did not apply --keep: it returned no slice for ${label}, so it is probably older than this koi and built the preview without the names; update the box and run koi up again`
				: undefined;
		const error =
			record === undefined
				? `${label} was removed by koi down while koi up waited for its build`
				: (unkept ?? record.error);
		const result: UpResult = {
			schemaVersion: 1,
			label,
			url,
			status: record?.status === 'running' && unkept === undefined ? 'running' : 'failed',
			commit,
			...(options.pr !== undefined ? { pr: options.pr } : {}),
			...(merge !== undefined ? { merge } : {}),
			...(deployment !== undefined ? { deployment } : {}),
			...(slice !== undefined ? { slice } : {}),
			...(record?.loginKey !== undefined ? { loginKey: record.loginKey } : {}),
			keysUrl: keysPageUrl(deps.domain, label),
			...(error !== undefined ? { error } : {}),
		};
		// No comment on a preview koi down removed: whoever removed it meant
		// to, and a comment that GitHub refused would lose this result.
		if (
			options.comment &&
			options.pr !== undefined &&
			ownerRepo !== undefined &&
			record !== undefined
		) {
			result.comment = await deps.github(ownerRepo).upsertComment(
				options.pr,
				commentMarker(label),
				commentBody({
					label,
					url,
					built: builtFrom({ ...result, madeByKoi }),
					status: result.status,
					error: result.error,
					loginKey: result.loginKey,
					keysUrl: result.keysUrl,
				}),
			);
		}
		return result;
	} finally {
		await rm(work, { recursive: true, force: true });
	}
}

// What a build was made from, in plain words, for koi up's output and the
// pull request comment: "#7 (abc1234) merged into develop (def5678), merge
// commit 9abcdef" for a pull request built as a merge of it, the head for
// one built with --head, and the commit alone for a working tree. A merge
// koi made itself says so, since GitHub does not have its commit.
export function builtFrom(p: {
	commit: string;
	pr?: number | undefined;
	merge?: PullRequestMerge | undefined;
	madeByKoi?: boolean | undefined;
}): string {
	const short = (c: string) => c.slice(0, 7);
	if (p.pr === undefined) return short(p.commit);
	if (p.merge === undefined) {
		return `#${p.pr} (${short(p.commit)}), its head as pushed, not merged into its base`;
	}
	const merged = `#${p.pr} (${short(p.merge.head)}) merged into ${p.merge.baseBranch ?? 'its base branch'} (${short(p.merge.base)}), merge commit ${short(p.commit)}`;
	return p.madeByKoi === true
		? `${merged}, which koi made because GitHub's was out of date`
		: merged;
}

// How long koi up waits for GitHub to recompute a pull request's merge once
// it has asked, and how often it fetches the merge again in that time.
export const MERGE_WAIT_MS = 90_000;
export const MERGE_POLL_MS = 15_000;

// How many times koi reads a pull request from GitHub and fetches it again,
// before it merges the pull request itself, when the two name different
// heads, as when the author pushes in between.
export const MERGE_INPUT_TRIES = 3;

// How many times koi tries one such read when gh fails, each with gh's
// usual time limit, and how long it waits between tries.
export const MERGE_STATE_READS = 3;
export const MERGE_STATE_RETRY_MS = 5_000;

// The merge a merge build builds, its parents, and whether koi made it.
interface CurrentMerge {
	commit: string;
	merge: PullRequestMerge;
	madeByKoi: boolean;
}

// What GitHub said of a pull request in one answer: the base branch it is
// opened against, and its head commit, undefined when gh did not say.
interface Said {
	baseBranch: string;
	head: string | undefined;
}

// A merge of the pull request's head now into its base branch's tip now.
// GitHub's merge (refs/pull/N/merge) when it is current. GitHub remakes it
// after a push, but may keep it for a long time after the base alone moves
// on, and fetching it does not make GitHub remake it. Asking the REST API
// whether the pull request can merge does. So koi asks, and fetches the
// merge again every MERGE_POLL_MS for up to MERGE_WAIT_MS, checking it each
// time as before. If it is still out of date after that, koi merges the head
// into the base itself (see mergeItself), when the two merge cleanly, and
// records that merge just as it would GitHub's. A pull request that
// conflicts with its base has no merge to build, as on GitHub.
//
// The wait ends at a deadline on deps.clock, and nothing in it runs past
// the deadline: each sleep, gh call and fetch is given only the time left.
// A fetch or gh call that fails or runs out of that time ends the wait, and
// koi merges the pull request itself if it can still fetch what it merges.
//
// Each look during the wait takes the base branch and the head from the
// answer GitHub gave just before, so a pull request retargeted at another
// base, or pushed again, is checked against what it is now.
//
// `said` is what gh pr view said, which the first look takes the base
// branch from. The caller has it before calling, since checking the base
// needs its name and only gh can give it.
async function currentMerge(
	pr: number,
	said: Said,
	fetched: { head: string; merge: { commit: string; parents: string[] } },
	github: GitHub,
	deps: UpDeps,
): Promise<CurrentMerge> {
	const { git } = deps;
	// The first look, at the merge koi up fetched. It ignores the head gh
	// pr view named: GitHub's merge of the head koi fetched with it is a
	// merge of a head the pull request had, whichever push gh saw.
	const first = checkMerge(
		pr,
		{ baseBranch: said.baseBranch, head: undefined },
		fetched,
		await git.remoteBranchTips(),
	);
	if ('merge' in first) return first.merge;
	// Why GitHub's merge is out of date, as of the last look.
	let behind = first.behind;
	deps.progress(
		`GitHub's merge of pull request ${pr} into ${said.baseBranch} is out of date. ${behind.join(' ')} Asking GitHub to recompute it, and waiting up to ${seconds(MERGE_WAIT_MS)} seconds`,
	);
	const deadline = deps.clock() + MERGE_WAIT_MS;
	const left = () => deadline - deps.clock();
	// Why koi stopped waiting for GitHub.
	let gaveUp = `GitHub did not recompute its merge of pull request ${pr} within ${seconds(MERGE_WAIT_MS)} seconds`;
	let current = said;
	while (left() > 0) {
		const asked = await attempt(() => github.pullRequestMergeState(pr, { timeoutMs: left() }));
		if (asked instanceof Error) {
			gaveUp = `koi could not ask GitHub to recompute its merge of pull request ${pr} (${asked.message})`;
			break;
		}
		current = { baseBranch: asked.baseBranch, head: asked.head };
		if (asked.mergeable === false) {
			gaveUp = `GitHub says pull request ${pr} cannot be merged into ${current.baseBranch}`;
			break;
		}
		await deps.sleep(Math.min(MERGE_POLL_MS, Math.max(0, left())));
		if (left() <= 0) break;
		let refs: PullRequestRefs;
		let tips: Map<string, string>;
		try {
			refs = await git.fetchPullRequest(pr, { timeoutMs: left() });
			if (left() <= 0) break;
			tips = await git.remoteBranchTips({ timeoutMs: left() });
		} catch (err) {
			gaveUp = `koi could not fetch pull request ${pr} again while it waited (${err instanceof Error ? err.message : String(err)})`;
			break;
		}
		if (refs.head === undefined) throw new Error(noPullRequest(pr));
		// GitHub may drop its merge while it recomputes, or once it finds a
		// conflict; koi's own merge says which.
		if (refs.merge === undefined) {
			gaveUp = `GitHub dropped its merge of pull request ${pr} (refs/pull/${pr}/merge) while koi waited`;
			break;
		}
		const look = checkMerge(pr, current, { head: refs.head, merge: refs.merge }, tips);
		if ('merge' in look) {
			deps.progress(`GitHub recomputed its merge of pull request ${pr}`);
			return look.merge;
		}
		behind = look.behind;
	}
	return mergeItself(pr, { baseBranch: current.baseBranch, behind, gaveUp }, github, deps);
}

// koi's own merge of a pull request's head into its base branch's tip, once
// GitHub's has stayed out of date, or GitHub's after all if it has caught
// up by now. What it merges comes from one answer of GitHub's, read here
// whatever happened during the wait: the base branch, and the head, which
// must be the head koi fetches from origin after it. When they differ the
// author pushed in between, and koi reads and fetches again, up to
// MERGE_INPUT_TRIES times, then stops. Without an answer (see readToMerge)
// koi stops too, rather than merge a base branch or head GitHub named
// earlier: the pull request may have been retargeted or pushed since.
// These reads and fetches are not part of the wait, and have their own
// time limits.
//
// `wait.baseBranch` is the base branch of the last answer before, which
// only names GitHub's out-of-date merge when koi stops without an answer.
async function mergeItself(
	pr: number,
	wait: { baseBranch: string; behind: string[]; gaveUp: string },
	github: GitHub,
	deps: UpDeps,
): Promise<CurrentMerge> {
	const { git } = deps;
	const short = (c: string) => c.slice(0, 7);
	// Why koi stops without a merge into `into`, after the wait.
	const cannotMerge = (into: string, why: string) =>
		new Error(
			`GitHub's merge of pull request ${pr} into ${into} (refs/pull/${pr}/merge on origin) is out of date. ${wait.behind.join(' ')} ${wait.gaveUp}, and koi could not merge the pull request itself: ${why}. Try again in a minute, or build the head as pushed with koi up --pr ${pr} --head.`,
		);
	let said: { baseBranch: string; head: string };
	let fetched: { head: string; merge: PullRequestRefs['merge'] };
	for (let tries = 1; ; tries++) {
		const read = await readToMerge(pr, github, deps);
		if (read instanceof Error) {
			throw cannotMerge(
				wait.baseBranch,
				`it takes the base branch and head to merge from GitHub just before it merges, and gh could not read them in ${MERGE_STATE_READS} tries (${read.message})`,
			);
		}
		said = read;
		const refs = await git.fetchPullRequest(pr);
		if (refs.head === undefined) throw new Error(noPullRequest(pr));
		if (said.head === refs.head) {
			fetched = { head: refs.head, merge: refs.merge };
			break;
		}
		if (tries >= MERGE_INPUT_TRIES) {
			throw new Error(movedWhileMerging(pr, said.head, refs.head));
		}
	}
	const { baseBranch } = said;
	const head = fetched.head;
	const base = await git.fetchBranch(baseBranch);
	if (fetched.merge !== undefined) {
		const tips = new Map([[baseBranch, base]]);
		const look = checkMerge(pr, said, { head, merge: fetched.merge }, tips);
		if ('merge' in look) {
			deps.progress(`GitHub recomputed its merge of pull request ${pr}`);
			return look.merge;
		}
	}
	deps.progress(`${wait.gaveUp}; koi merges its head ${short(head)} into ${baseBranch} itself`);
	let made: Awaited<ReturnType<Git['mergeCommit']>>;
	try {
		made = await git.mergeCommit(base, head);
	} catch (err) {
		throw cannotMerge(baseBranch, err instanceof Error ? err.message : String(err));
	}
	if ('conflicts' in made) {
		throw new Error(conflicts(pr, baseBranch, { head, base }, made.conflicts));
	}
	deps.progress(
		`koi merged pull request ${pr} (${short(head)}) into ${baseBranch} (${short(base)}) itself, merge commit ${short(made.commit)}, since GitHub's merge is out of date`,
	);
	return { commit: made.commit, merge: { head, base, baseBranch }, madeByKoi: true };
}

// GitHub's merge as one fetch found it, checked against what GitHub said of
// the pull request and the branch tips on origin: the merge to build, when
// it is current, or why it is not (see mergeBehind). Throws when it is not
// a merge of two commits.
function checkMerge(
	pr: number,
	said: Said,
	refs: { head: string; merge: { commit: string; parents: string[] } },
	tips: Map<string, string>,
): { merge: CurrentMerge } | { behind: string[] } {
	const [base, head, ...more] = refs.merge.parents;
	if (base === undefined || head === undefined || more.length > 0) {
		throw new Error(
			`refs/pull/${pr}/merge on origin is ${refs.merge.commit}, which is not a merge of two commits`,
		);
	}
	const behind = mergeBehind({ base, head }, refs.head, pr, said, tips);
	if (behind.length > 0) return { behind };
	const merge = { head, base, baseBranch: said.baseBranch };
	return { merge: { commit: refs.merge.commit, merge, madeByKoi: false } };
}

// The base branch and head GitHub names for a pull request now, from one
// successful read, or the error of the last of MERGE_STATE_READS tries.
async function readToMerge(
	pr: number,
	github: GitHub,
	deps: UpDeps,
): Promise<{ baseBranch: string; head: string } | Error> {
	let failed = new Error('gh was not asked');
	for (let read = 1; read <= MERGE_STATE_READS; read++) {
		if (read > 1) await deps.sleep(MERGE_STATE_RETRY_MS);
		const asked = await attempt(() => github.pullRequestMergeState(pr));
		if (!(asked instanceof Error)) return { baseBranch: asked.baseBranch, head: asked.head };
		failed = asked;
	}
	return failed;
}

// What a call returns, or the error it threw.
async function attempt<T>(call: () => Promise<T>): Promise<T | Error> {
	try {
		return await call();
	} catch (err) {
		return err instanceof Error ? err : new Error(String(err));
	}
}

// Why koi stops when the pull request's head on origin is not the one
// GitHub named, however often it asks: the author keeps pushing.
function movedWhileMerging(pr: number, said: string, fetched: string): string {
	return `pull request ${pr} moved while koi was fetching it to merge it: GitHub named its head ${said.slice(0, 7)}, and origin had ${fetched.slice(0, 7)}. Run koi up again.`;
}

// Why a merge build stops when the pull request's head conflicts with its
// base branch's tip: there is no merge to build, as GitHub would have none.
function conflicts(
	pr: number,
	baseBranch: string,
	at: { head: string; base: string },
	files: string[],
): string {
	const short = (c: string) => c.slice(0, 7);
	const named = files.slice(0, 10).join(', ');
	const more = files.length > 10 ? ` and ${files.length - 10} more` : '';
	return `pull request ${pr} (${short(at.head)}) conflicts with ${baseBranch} (${short(at.base)}) in ${named}${more}, so there is no merge of it to build, and GitHub's merge (refs/pull/${pr}/merge on origin) is of an earlier head or base. Rebase onto ${baseBranch} or merge it in and push. To build the head as pushed instead, without ${baseBranch}'s later changes, run koi up --pr ${pr} --head.`;
}

// Why koi up --pr stops when the fetch found no head: a pull request that
// origin does not have, as opposed to a fetch that failed.
function noPullRequest(pr: number): string {
	return `origin has no pull request ${pr} (no refs/pull/${pr}/head there). Check the number, and that origin is the repository the pull request was opened in.`;
}

// Why koi up --pr stops when origin has the pull request's head but GitHub
// has made no merge of it into its base: the two conflict, or GitHub has not
// got to it yet. `base` is the base branch's name when gh could say.
function noMerge(pr: number, base: string | undefined): string {
	const into = base ?? 'its base branch';
	const onto = base ?? 'the base branch';
	return `GitHub has no merge of pull request ${pr} into ${into} (no refs/pull/${pr}/merge on origin). Either the pull request conflicts with ${into}, or GitHub has not finished checking it. Rebase onto ${onto} or merge it in and push, or try again in a minute. To build the head as pushed instead, without ${onto}'s later changes, run koi up --pr ${pr} --head.`;
}

// How GitHub's merge of a pull request lags what it should merge now, as
// sentences, or none when it is current. Its head must be the pull request's
// head now, as origin has it and, when GitHub named one, as GitHub named
// it, and its base the tip now of the base branch GitHub named, as origin
// lists it. No other branch's tip will do: a branch left at the old base, a
// release branch say, says nothing about where the base is. Throws when
// origin has no branch of the name GitHub gave.
function mergeBehind(
	merge: { base: string; head: string },
	head: string,
	pr: number,
	said: Said,
	tips: Map<string, string>,
): string[] {
	const short = (c: string) => c.slice(0, 7);
	const { baseBranch } = said;
	const behind: string[] = [];
	if (said.head !== undefined && said.head !== head) {
		behind.push(
			`The pull request moved while koi looked: GitHub named its head ${short(said.head)}, and origin had ${short(head)}.`,
		);
	}
	if (merge.head !== head) {
		behind.push(
			`Its head ${short(merge.head)} is an earlier push, and the pull request is now at ${short(head)}.`,
		);
	}
	const tip = tips.get(baseBranch);
	if (tip === undefined) {
		throw new Error(
			`origin has no branch ${baseBranch}, which GitHub names as the base of pull request ${pr}. Check that origin is the repository the pull request was opened in.`,
		);
	}
	if (merge.base !== tip) {
		behind.push(`Its base ${short(merge.base)} is behind ${baseBranch}, now at ${short(tip)}.`);
	}
	return behind;
}

// Why a merge build stops when gh could not name the pull request's base
// branch: without the name koi cannot check GitHub's merge against the base,
// and a merge GitHub kept after the base moved on would preview the pull
// request on a base that is gone. `failed` is what stood in gh's way, if
// anything did.
function needsGh(pr: number, ownerRepo: string, failed: GhMissingError | ExecError | undefined) {
	const need = `checking GitHub's merge of pull request ${pr} against its base branch needs gh`;
	const orHead = `or build the head as pushed with koi up --pr ${pr} --head`;
	if (failed instanceof GhMissingError) return `${need}, and ${failed.message}, ${orHead}.`;
	if (failed !== undefined) {
		return `${need}, and gh could not describe the pull request (${failed.message}). Sign in with gh auth login and check that it can see ${ownerRepo}, ${orHead}.`;
	}
	return `${need}, and gh pr view ${pr} did not name one. Check the pull request on GitHub, ${orHead}.`;
}

// What gh says of the pull request, or what stood in its way: GhMissingError
// when gh is not installed, ExecError when it ran and failed (not signed in,
// or no access to the repository). The head branch's name only goes in the
// preview's record, so a --head build does without; a merge build needs the
// base branch's name (see needsGh).
async function askGh(
	github: GitHub,
	pr: number,
): Promise<{ branches?: PullRequestBranches; failed?: GhMissingError | ExecError }> {
	try {
		return { branches: await github.pullRequestBranches(pr) };
	} catch (err) {
		if (err instanceof GhMissingError || err instanceof ExecError) return { failed: err };
		throw err;
	}
}

// GitHub lists at most this many files for a pull request; a list this long
// may be cut.
export const GITHUB_FILES_LIMIT = 3000;

// The files a pull request changes, as gh lists them, or why gh could not.
async function pullRequestFiles(
	deps: UpDeps,
	ownerRepo: string,
	pr: number,
): Promise<string[] | Error> {
	try {
		return await deps.github(ownerRepo).pullRequestFiles(pr);
	} catch (err) {
		return err instanceof Error ? err : new Error(String(err));
	}
}

// Why koi stops when gh could not list a pull request's files and there is
// no merge of it to compare the head with. The list decides the preview's
// slice (what the recipe keeps of the project), so a guess would build a
// preview without the pull request's own nodes and apps.
function noFileList(pr: number, failed: Error): string {
	return `koi could not tell which files pull request ${pr} changes: gh could not list them (${failed.message}), and without GitHub's merge of the pull request there is nothing to compare its head with. The preview keeps only what that list names, so koi stops rather than build one without the pull request's nodes and apps. Install and sign in to gh (gh auth login), or push the branch so GitHub makes the merge, and try again.`;
}

// A head build takes GitHub's file list, which describes the head GitHub
// has now; a push between koi's fetch and gh's answer makes it describe
// another tree, and slicing by it could drop what the fetched tree changed.
function movedHead(pr: number, fetched: string, now: string): string {
	return `pull request ${pr} moved while koi was fetching it: koi fetched its head ${fetched.slice(0, 7)}, and GitHub now lists files for ${now.slice(0, 7)}. Run koi up again.`;
}

function cutFileList(pr: number, count: number): string {
	return `GitHub lists at most ${GITHUB_FILES_LIMIT.toLocaleString('en-US')} files for a pull request, and pull request ${pr} lists ${count}, so the list may be cut, and koi cannot decide what the preview keeps from it. Build GitHub's merge of the pull request instead (koi up --pr ${pr} without --head), which lists the files from git.`;
}

function noBaseBranch(): string {
	return 'koi could not tell which files this working tree changes: there is no origin/HEAD, origin/main, origin/master or origin/develop to compare it with. The preview keeps only what that list names, so koi stops. Fetch origin (git fetch origin) and try again.';
}

// Polls the preview's status until this request has finished, passing along
// its build log, and returns the record and the identity of the deployment
// then serving, or undefined when koi down removed the preview first. The
// first poll learns which attempt at the request koid is on. Each poll after
// asks for the lines of that attempt's log from where the last page ended
// (koid's `next`), so no line is skipped or shown twice however many arrive
// between polls, and no other request's line is shown. Until the build opens
// its log there are no lines. When koid builds this request again, the new
// attempt's log is shown from its start.
//
// An attempt may wait QUEUE_WAIT_MS in koid's queue, then buildMs from when
// koi first sees it out of the queue. Time spent behind other builds does not
// count against the build's own limit.
//
// A status read that fails in a way that can pass is tried again, for up to
// STATUS_RETRY_MS. Any other failure ends the wait.
async function follow(
	label: string,
	id: string,
	buildMs: number,
	deps: UpDeps,
): Promise<Pick<StatusReply, 'record' | 'deployment' | 'slice'> | undefined> {
	let attempt: string | undefined;
	let next = 0;
	let wait = true;
	// When koi first saw this attempt, or saw it leave the queue.
	let since = deps.now().getTime();
	let building = false;
	let finished = false;
	// When status reads began to fail, and why the last one did.
	let failing: { since: number; why: string } | undefined;
	for (;;) {
		if (wait) await deps.sleep(3000);
		wait = true;
		const read = await readStatus(
			deps.box,
			label,
			attempt === undefined ? ['status', label] : ['status', label, attempt, String(next)],
		);
		if ('removed' in read) return undefined;
		if ('unavailable' in read) {
			failing = { since: failing?.since ?? deps.now().getTime(), why: read.unavailable };
			if (deps.now().getTime() - failing.since > STATUS_RETRY_MS) {
				throw new Error(
					`could not read the status of ${label} for ${minutes(STATUS_RETRY_MS)} minutes: ${failing.why}`,
				);
			}
		} else {
			failing = undefined;
			const { record, log, deployment, slice } = read.reply;
			// Lines of the attempt asked about, which is this request's.
			for (const line of log.lines) deps.buildLine(line);
			next = log.next;
			// koid recorded this request before accepting it, so another id means a
			// newer koi up for the label replaced it.
			if (record.requestId !== id) throw new Error(`superseded by a newer koi up for ${label}`);
			if (record.attempt !== attempt) {
				if (attempt !== undefined) {
					deps.progress(
						'koid is building this request again; showing its new build log from the start',
					);
				}
				attempt = record.attempt;
				next = 0;
				wait = false;
				since = deps.now().getTime();
				building = false;
				// A retry can start while the earlier attempt's log is still being
				// read; the new attempt gets the time limits again.
				finished = false;
				continue;
			}
			if (!building && record.status !== 'queued') {
				building = true;
				since = deps.now().getTime();
			}
			if (record.status === 'running' || record.status === 'failed') {
				// The build has finished; show the rest of its log first, however
				// long that takes.
				// That last read, with no lines, carries the deployment's
				// slice when it has one.
				if (log.lines.length === 0) {
					return {
						record,
						...(deployment !== undefined ? { deployment } : {}),
						...(slice !== undefined && deployment !== undefined ? { slice } : {}),
					};
				}
				finished = true;
				wait = false;
				continue;
			}
		}
		if (finished) continue;
		const waited = deps.now().getTime() - since;
		if (!building && waited > QUEUE_WAIT_MS) {
			throw new Error(
				`gave up after ${hours(QUEUE_WAIT_MS)} hours waiting for ${label} to start building behind other builds on the box. koid keeps it queued and builds it in turn; see koi list, or run koi up again later`,
			);
		}
		if (building && waited > buildMs) {
			throw new Error(
				`gave up waiting for ${label} after ${minutes(buildMs)} minutes of building: its recipe's build and health time limits and ${minutes(BUILD_MARGIN_MS)} minutes more`,
			);
		}
	}
}

// One status read: koid's reply, why it could not be had this time, or that
// the preview is gone. koid recorded the request before it accepted it, and
// only koi down removes a record. Throws on a failure that asking again will
// not fix.
async function readStatus(
	box: Box,
	label: string,
	args: string[],
): Promise<{ reply: StatusReply } | { unavailable: string } | { removed: true }> {
	let r: CtlResult;
	try {
		r = await box.ctl(args);
	} catch (err) {
		if (err instanceof BoxUnavailableError) return { unavailable: err.message };
		throw err;
	}
	if (r.code === CTL_EXIT.unavailable) return { unavailable: ctlErrorText(r) };
	if (r.code !== CTL_EXIT.ok) {
		const why = ctlErrorText(r) || `koid ctl status exited ${r.code}`;
		if (why === NO_SUCH_PREVIEW) return { removed: true };
		throw new Error(`stopped following ${label}: ${why}`);
	}
	return { reply: StatusReplySchema.parse(JSON.parse(r.stdout)) };
}

function hours(ms: number): number {
	return Math.round(ms / 3_600_000);
}

function minutes(ms: number): number {
	return Math.round(ms / 60_000);
}

function seconds(ms: number): number {
	return Math.round(ms / 1000);
}
