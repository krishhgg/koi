import type { Stats } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { join, sep } from 'node:path';
import { ExecError, type ExecOptions, type ExecResult, exec, execOk, FULL_OUTPUT } from './exec.ts';

// How long a fetch from the remote may take: a stalled network or credential
// helper fails koi up with an error rather than holding it forever.
export const FETCH_TIMEOUT_MS = 5 * 60_000;

// What `koi up` needs from git, run in the user's checkout. Every call passes
// arguments as an array; nothing goes through a shell.
export interface Git {
	root(): Promise<string>;
	remote(): Promise<string>;
	head(): Promise<string>;
	branch(): Promise<string>;
	dirty(): Promise<boolean>;
	// Tracked and untracked files that git does not ignore, relative to the root.
	files(): Promise<string[]>;
	// Fetches a pull request's refs from origin without touching local
	// branches. A ref origin does not have comes back undefined; a fetch that
	// fails (network, sign-in, a remote that is not there) throws.
	fetchPullRequest(pr: number): Promise<PullRequestRefs>;
	// The branches on origin and the commit each is at now, by name, as
	// asked of origin without fetching anything.
	remoteBranchTips(): Promise<Map<string, string>>;
	// Fetches a branch from origin without touching local branches, and
	// returns the commit it is at. Throws when the fetch fails, a branch
	// origin does not have included.
	fetchBranch(branch: string): Promise<string>;
	// Merges a pull request's head into a base commit, as GitHub makes
	// refs/pull/N/merge, when the two merge cleanly: the commit, made as
	// localMerge describes, or the files that conflict. Throws when git
	// cannot merge them at all, as a git older than 2.38 cannot.
	mergeCommit(base: string, head: string): Promise<{ commit: string } | { conflicts: string[] }>;
	// An uncompressed tar of a commit's tree.
	archive(commit: string, out: string): Promise<void>;
	// Files changed on this branch: everything that differs from where it
	// left the remote's default branch, committed or not, plus untracked files.
	// Undefined when there is no such branch to compare with.
	changedFiles(): Promise<string[] | undefined>;
	// Files a head commit changes against where it left a base commit, by
	// name: what GitHub lists for a pull request of that head.
	diffFiles(base: string, head: string): Promise<string[]>;
	// Files a merge commit changes against its first parent, by name: for
	// GitHub's merge of a pull request, what the pull request changes against
	// the base it was merged into, and the one list that describes that
	// merge's tree. A shallow checkout that lacks the parent (actions/checkout
	// fetches the merge at depth one) is deepened by one along the pull
	// request's merge ref first.
	mergeFiles(pr: number, merge: string): Promise<string[]>;
	// A file's content at a commit, or undefined when it does not exist there.
	show(commit: string, path: string): Promise<string | undefined>;
}

// A pull request's refs on origin, as one fetch found them.
export interface PullRequestRefs {
	// refs/pull/N/head: the pull request's head commit. Undefined when origin
	// has no pull request N.
	head: string | undefined;
	// refs/pull/N/merge: GitHub's merge of the head into the base branch, with
	// its parents as the commit object names them, the base commit first and
	// then the head it merged. Undefined when GitHub has none: the pull
	// request conflicts with its base, GitHub has not finished checking it,
	// or it is closed.
	merge: { commit: string; parents: string[] } | undefined;
}

export function cliGit(
	cwd: string,
	run: (cmd: string[], options?: ExecOptions) => Promise<ExecResult> = exec,
): Git {
	const ok = async (cmd: string[], options: ExecOptions = {}) => {
		const result = await run(cmd, options);
		if (result.code !== 0 || result.timedOut) throw new ExecError(cmd, result, options.timeoutMs);
		return result;
	};
	// Commands run at the top of the work tree, found once from the directory
	// koi was started in. ls-files prints paths relative to the directory it
	// runs in, and the packer joins them to the root.
	let top: Promise<string> | undefined;
	const root = () => {
		top ??= ok(['git', '-C', cwd, 'rev-parse', '--show-toplevel']).then((r) =>
			r.stdout.replace(/\n$/, ''),
		);
		return top;
	};
	const at = async (args: string[]) => ['git', '-C', await root(), ...args];
	const git = async (...args: string[]) => (await ok(await at(args))).stdout;
	// For output that is used whole, however long: an error rather than a cut list.
	const gitAll = async (...args: string[]) =>
		(await ok(await at(args), { maxBytes: FULL_OUTPUT })).stdout;
	// A commit's parents as its object names them, from the raw object rather
	// than rev-list or log. In a shallow checkout (actions/checkout fetches
	// the pull request's merge at depth one) a commit at the shallow boundary
	// has its parents hidden from the history walkers, but the object still
	// lists them. The headers end at the first blank line; a signature's
	// continuation lines start with a space, so none matches.
	const parentsOf = async (commit: string) => {
		const headers = (await git('cat-file', '-p', commit)).split('\n\n', 1)[0] ?? '';
		return headers.split('\n').flatMap((line) => {
			const parent = /^parent ([0-9a-f]{40})$/.exec(line)?.[1];
			return parent !== undefined ? [parent] : [];
		});
	};
	return {
		root,
		async remote() {
			return (await git('remote', 'get-url', 'origin')).trim();
		},
		async head() {
			return (await git('rev-parse', 'HEAD')).trim();
		},
		async branch() {
			const name = (await git('rev-parse', '--abbrev-ref', 'HEAD')).trim();
			// Detached HEAD: name the preview after the commit instead.
			return name === 'HEAD'
				? `detached-${(await git('rev-parse', '--short=12', 'HEAD')).trim()}`
				: name;
		},
		async dirty() {
			return (await gitAll('status', '--porcelain', '--untracked-files=normal')).trim() !== '';
		},
		async files() {
			const out = await gitAll('ls-files', '--cached', '--others', '--exclude-standard', '-z');
			return [...new Set(out.split('\0').filter((f) => f !== ''))];
		},
		async fetchPullRequest(pr) {
			// One fetch takes every ref under refs/pull/N/ (GitHub keeps head and
			// merge there) into refs of koi's own. FETCH_HEAD is shared, and
			// another fetch in this repository can replace it before koi reads it.
			//
			// A pattern, not the two names: git fails a fetch of a named ref that
			// origin lacks with the same exit code as a network or sign-in
			// failure, but a pattern that matches nothing is no error. So a failed
			// fetch here always means git could not fetch, and a ref origin lacks
			// is just missing afterwards.
			const prefix = `refs/koi/pr-${pr}-${randomSuffix()}`;
			const args = ['fetch', '--quiet', '--no-tags', 'origin', `+refs/pull/${pr}/*:${prefix}/*`];
			await ok(await at(args), { timeoutMs: FETCH_TIMEOUT_MS });
			const fetched = (await git('for-each-ref', '--format=%(refname)', `${prefix}/`))
				.split('\n')
				.filter((r) => r !== '');
			try {
				const commitAt = async (name: string) =>
					fetched.includes(`${prefix}/${name}`)
						? (await git('rev-parse', '--verify', `${prefix}/${name}^{commit}`)).trim()
						: undefined;
				const head = await commitAt('head');
				const merge = await commitAt('merge');
				if (merge === undefined) return { head, merge: undefined };
				return { head, merge: { commit: merge, parents: await parentsOf(merge) } };
			} finally {
				// Tidying only: a ref left behind keeps its commits, and nothing reads it.
				for (const ref of fetched) await git('update-ref', '-d', ref).catch(() => {});
			}
		},
		async remoteBranchTips() {
			// One line per branch: the commit, a tab, refs/heads/<name>.
			const out = (
				await ok(await at(['ls-remote', '--heads', 'origin']), {
					maxBytes: FULL_OUTPUT,
					timeoutMs: FETCH_TIMEOUT_MS,
				})
			).stdout;
			const tips = new Map<string, string>();
			for (const line of out.split('\n')) {
				const m = /^([0-9a-f]{40})\trefs\/heads\/(.+)$/.exec(line);
				if (m?.[1] !== undefined && m[2] !== undefined) tips.set(m[2], m[1]);
			}
			return tips;
		},
		async fetchBranch(branch) {
			// A name git does not take for a branch could read as a pattern or
			// a second refspec. gh names real branches; this does not rely on it.
			const ref = `refs/heads/${branch}`;
			if ((await run(await at(['check-ref-format', ref]))).code !== 0) {
				throw new Error(`${JSON.stringify(branch)} is not a branch name git accepts`);
			}
			const local = `refs/koi/branch-${randomSuffix()}`;
			// --refmap= keeps git from also moving the clone's origin/<branch>,
			// which it does for a branch named on the command line.
			const args = ['fetch', '--quiet', '--no-tags', '--refmap=', 'origin', `+${ref}:${local}`];
			try {
				await ok(await at(args), { timeoutMs: FETCH_TIMEOUT_MS });
				return (await git('rev-parse', '--verify', `${local}^{commit}`)).trim();
			} finally {
				await git('update-ref', '-d', local).catch(() => {});
			}
		},
		async mergeCommit(base, head) {
			// Rename handling pinned to git's defaults, so that a user's merge
			// settings do not change the tree.
			const mergeTree = await at([
				'-c',
				'merge.renames=true',
				'-c',
				'merge.directoryRenames=conflict',
				'merge-tree',
				'--write-tree',
				'-z',
				'--name-only',
				'--no-messages',
				base,
				head,
			]);
			const merged = await run(mergeTree, { maxBytes: FULL_OUTPUT, timeoutMs: MERGE_TIMEOUT_MS });
			if (merged.code === 129 && !merged.timedOut && /write-tree/.test(merged.stderr)) {
				throw new Error(
					`this git does not know git merge-tree --write-tree, which koi merges with; it needs git 2.38 or later (${(await git('version')).trim()})`,
				);
			}
			// With -z and --name-only: the tree, then each conflicted path, each
			// ended by a NUL. It exits 0 for a clean merge and 1 for one with
			// conflicts, but also 1, printing no tree, for a commit it cannot
			// find. Any other answer, as for histories with no commit in common,
			// means no merge was made.
			const [tree = '', ...paths] = merged.stdout.split('\0');
			const conflicted = names(paths.join('\0'));
			const clean = merged.code === 0 && conflicted.length === 0;
			const conflicting = merged.code === 1 && conflicted.length > 0;
			if (merged.timedOut || !/^[0-9a-f]{40}$/.test(tree) || !(clean || conflicting)) {
				throw new ExecError(mergeTree, merged, MERGE_TIMEOUT_MS);
			}
			if (conflicting) return { conflicts: conflicted };
			const made = localMerge(
				tree,
				base,
				head,
				(await git('show', '-s', '--format=%ct', base, head))
					.split('\n')
					.filter((t) => t !== '')
					.map(Number),
			);
			return {
				commit: (await ok(await at(made.args), { env: made.env })).stdout.trim(),
			};
		},
		async archive(commit, out) {
			await ok(await at(['archive', '--format=tar', `--output=${out}`, commit]), {
				timeoutMs: 10 * 60_000,
			});
		},
		async changedFiles() {
			const base = await defaultBranchBase(async (args) => run(await at(args)));
			if (base === undefined) return undefined;
			const diff = await gitAll('diff', '--name-only', '-z', base);
			const untracked = await gitAll('ls-files', '--others', '--exclude-standard', '-z');
			return [
				...new Set([...diff.split('\0'), ...untracked.split('\0')].filter((f) => f !== '')),
			].sort();
		},
		async diffFiles(base, head) {
			const out = await gitAll('diff', '--name-only', '-z', `${base}...${head}`);
			return names(out);
		},
		async mergeFiles(pr, merge) {
			const diff = async () =>
				run(await at(['diff', '--name-only', '-z', `${merge}^1`, merge]), {
					maxBytes: FULL_OUTPUT,
				});
			let r = await diff();
			if (r.code !== 0) {
				// The parent is missing, as in a shallow checkout: one more commit
				// along the merge ref brings both parents, then the diff can run.
				const ref = `refs/koi/pr-${pr}-${randomSuffix()}/merge`;
				const args = [
					'fetch',
					'--quiet',
					'--no-tags',
					'--deepen=1',
					'origin',
					`+refs/pull/${pr}/merge:${ref}`,
				];
				try {
					await ok(await at(args), { timeoutMs: FETCH_TIMEOUT_MS });
				} finally {
					await git('update-ref', '-d', ref).catch(() => {});
				}
				r = await diff();
				if (r.code !== 0)
					throw new ExecError(await at(['diff', '--name-only', `${merge}^1`, merge]), r);
			}
			return names(r.stdout);
		},
		async show(commit, path) {
			const r = await run(await at(['show', `${commit}:${path}`]));
			return r.code === 0 ? r.stdout : undefined;
		},
	};
}

// How long git may take to merge a pull request's head into its base.
const MERGE_TIMEOUT_MS = 10 * 60_000;

// Who koi's own merge commits name as author and committer. The address is
// under .invalid, which no one can hold.
const KOI_MERGE_IDENT = { name: 'koi', email: 'koi@koi.invalid' };

// The git commit-tree command, and the variables to run it with, that make
// koi's merge of a pull request from the tree git merge-tree wrote and the
// two parents' committer times (seconds since the epoch). Everything that
// goes into the commit is fixed by the parents, so anyone with them gets
// the same commit:
//
//   tree       what git merge-tree --write-tree <base> <head> writes
//   parents    the base, then the head, as GitHub orders its merge's
//   message    "Merge <head> into <base>", GitHub's own for its merge
//   author and committer
//              koi <koi@koi.invalid>, at the later of the two parents'
//              committer times, in UTC
//
// It is never signed, and its message is UTF-8 with no encoding header,
// whatever the user's git config says.
function localMerge(
	tree: string,
	base: string,
	head: string,
	parentTimes: number[],
): { args: string[]; env: Record<string, string> } {
	const latest = Math.max(...parentTimes);
	if (!Number.isSafeInteger(latest)) throw new Error('git did not give the parents a commit time');
	const when = `@${latest} +0000`;
	return {
		args: [
			'-c',
			'i18n.commitEncoding=UTF-8',
			'commit-tree',
			'--no-gpg-sign',
			'-p',
			base,
			'-p',
			head,
			'-m',
			`Merge ${head} into ${base}`,
			tree,
		],
		env: {
			GIT_AUTHOR_NAME: KOI_MERGE_IDENT.name,
			GIT_AUTHOR_EMAIL: KOI_MERGE_IDENT.email,
			GIT_AUTHOR_DATE: when,
			GIT_COMMITTER_NAME: KOI_MERGE_IDENT.name,
			GIT_COMMITTER_EMAIL: KOI_MERGE_IDENT.email,
			GIT_COMMITTER_DATE: when,
		},
	};
}

// Paths from `git ... -z` output, each once, sorted.
function names(out: string): string[] {
	return [...new Set(out.split('\0').filter((f) => f !== ''))].sort();
}

function randomSuffix(): string {
	return Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) =>
		b.toString(16).padStart(2, '0'),
	).join('');
}

// Where this branch left the remote's default branch: origin/HEAD if the clone
// knows it, else the first of main, master or develop that exists.
async function defaultBranchBase(
	git: (args: string[]) => Promise<ExecResult>,
): Promise<string | undefined> {
	const head = await git(['rev-parse', '--abbrev-ref', 'origin/HEAD']);
	const candidates = head.code === 0 ? [head.stdout.trim()] : [];
	candidates.push('origin/main', 'origin/master', 'origin/develop');
	for (const ref of candidates) {
		const base = await git(['merge-base', 'HEAD', ref]);
		if (base.code === 0) return base.stdout.trim();
	}
	return undefined;
}

// The directory koi reserves in every source tarball for files of its own.
// The build may read them (a recipe can seed or trim the preview from
// changed-files.txt); they are not part of the repository, and a tree that
// has the directory is refused (see finishTarball). The project's own .koi/
// is not touched: that is where a project keeps its koi.yaml and its
// verification files.
export const RUNTIME_DIR = '.koi-runtime';

export function koiFiles(changed: string[]): Record<string, string> {
	return { 'changed-files.txt': `${changed.join('\n')}\n` };
}

// Packs the working tree's files (as listed by Git.files) into an uncompressed
// tarball. Files listed but deleted on disk are skipped. A file that is itself
// a symlink is stored as a symlink; the daemon refuses any that point outside
// the tree. tar does follow symlinks in the directories above a file, so a
// listed file under a directory that has become a symlink would be read from
// wherever the link points. Packing refuses that, naming the files.
//
// git lists an initialized submodule, or another repository inside the tree,
// as one directory and none of its files. Packing refuses those too, naming
// them, rather than leave their files out. A submodule that is not
// initialized is an empty directory, with nothing to leave out.
export async function packWorkingTree(root: string, files: string[], out: string): Promise<number> {
	const realRoot = await realpath(root);
	// Directory relative to the root -> what is there.
	const dirs = new Map<string, Promise<DirState>>();
	const dirState = (dir: string): Promise<DirState> => {
		let state = dirs.get(dir);
		if (state === undefined) {
			state = inspectDir(root, realRoot, dir);
			dirs.set(dir, state);
		}
		return state;
	};
	const present: string[] = [];
	const refused: string[] = [];
	const repositories: string[] = [];
	for (const file of files) {
		const parts = file.split('/');
		let state: DirState = 'dir';
		let at = '';
		for (let i = 1; i < parts.length && state === 'dir'; i++) {
			at = parts.slice(0, i).join('/');
			state = await dirState(at);
		}
		if (state === 'symlink') {
			refused.push(`${file} (${at} is a symlink)`);
			continue;
		}
		if (state === 'outside') {
			refused.push(`${file} (${at} resolves outside the repository)`);
			continue;
		}
		if (state === 'missing') continue;
		const stat = await lstatOrMissing(join(root, file));
		if (stat?.isFile() || stat?.isSymbolicLink()) present.push(file);
		else if (stat?.isDirectory() && (await lstatOrMissing(join(root, file, '.git')))) {
			repositories.push(file.replace(/\/$/, ''));
		}
	}
	if (refused.length > 0) {
		throw new Error(
			`refusing to pack files under a directory that is a symlink or resolves outside the repository, because tar would read them from outside it:\n${listed(refused)}\nMake those directories real ones inside the repository again, or remove the files from git (git rm --cached), then run koi up again.`,
		);
	}
	if (repositories.length > 0) {
		throw new Error(
			`refusing to pack a checkout with initialized submodules or other git repositories inside it, because koi would leave out their files:\n${listed(repositories)}\nCopy the files the build needs into the repository, or remove what it does not need (git submodule deinit for a submodule), then run koi up again.`,
		);
	}
	await execOk(['tar', '-cf', out, '-C', root, '--null', '--no-recursion', '--files-from=-'], {
		stdin: present.join('\0'),
		timeoutMs: 10 * 60_000,
	});
	return present.length;
}

// Adds koi's own files under .koi-runtime/ and gzips the tarball in place:
// <tar> becomes <tar>.gz. The tree's own files, .koi/ included, stay as they
// are. A tree with a .koi-runtime/ of its own is refused: the recipe reads
// what is there as koi's, so nothing there may come from the pull request.
// The listing is the one check for both build kinds, since a pull request
// build comes from git archive and never passes through packWorkingTree.
export async function finishTarball(tar: string, extra: Record<string, string>): Promise<string> {
	const listing = await execOk(['tar', '-tf', tar], {
		maxBytes: FULL_OUTPUT,
		timeoutMs: 10 * 60_000,
	});
	const reserved = listing.stdout.split('\n').filter(isRuntimePath);
	if (reserved.length > 0) {
		throw new Error(
			`refusing to pack a tree that has ${RUNTIME_DIR}/, which koi reserves for files it adds to every build:\n${listed(reserved)}\nRemove it from the repository (a project's own koi files belong under .koi/), then run koi up again.`,
		);
	}
	const dir = `${tar}.extra`;
	await execOk(['mkdir', '-p', `${dir}/${RUNTIME_DIR}`]);
	for (const [name, text] of Object.entries(extra)) {
		if (!/^[a-z0-9-]+\.[a-z]+$/.test(name)) throw new Error(`bad koi file name ${name}`);
		await Bun.write(`${dir}/${RUNTIME_DIR}/${name}`, text);
	}
	await execOk(['tar', '-rf', tar, '-C', dir, RUNTIME_DIR]);
	await execOk(['gzip', '-n', '-f', tar], { timeoutMs: 10 * 60_000 });
	await execOk(['rm', '-rf', dir]);
	return `${tar}.gz`;
}

// Whether a tar member name is the reserved directory or anything in it.
// Names come without a leading ./ from git archive and from packWorkingTree,
// but one is stripped in case a tar was made another way.
function isRuntimePath(name: string): boolean {
	const plain = name.replace(/^(?:\.\/)+/, '');
	return plain === RUNTIME_DIR || plain.startsWith(`${RUNTIME_DIR}/`);
}

// Up to ten entries, one per line, and how many more there are.
function listed(entries: string[]): string {
	const shown = entries.slice(0, 10).map((e) => `  ${e}`);
	if (entries.length > shown.length) shown.push(`  and ${entries.length - shown.length} more`);
	return shown.join('\n');
}

// A directory above a listed file: a real directory inside the repository,
// a symlink, a real directory that resolves outside it, or nothing (the file
// was deleted).
type DirState = 'dir' | 'symlink' | 'outside' | 'missing';

async function inspectDir(root: string, realRoot: string, dir: string): Promise<DirState> {
	const stat = await lstatOrMissing(join(root, dir));
	if (stat === undefined) return 'missing';
	if (stat.isSymbolicLink()) return 'symlink';
	if (!stat.isDirectory()) return 'missing';
	const real = await realpath(join(root, dir));
	return real.startsWith(`${realRoot}${sep}`) ? 'dir' : 'outside';
}

async function lstatOrMissing(path: string): Promise<Stats | undefined> {
	try {
		return await lstat(path);
	} catch (err) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code === 'ENOENT' || code === 'ENOTDIR') return undefined;
		throw err;
	}
}
