import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type ExecOptions, type ExecResult, exec, execOk } from '../src/exec.ts';
import { cliGit, FETCH_TIMEOUT_MS, finishTarball, koiFiles, packWorkingTree } from '../src/git.ts';
import { pullRequestOrigin, shallowCheckout } from './pulls.ts';

async function repo() {
	const dir = await mkdtemp(join(tmpdir(), 'koi-git-'));
	const git = (...args: string[]) =>
		exec(['git', '-C', dir, '-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args]);
	await git('init', '-q', '-b', 'main');
	await git('remote', 'add', 'origin', 'git@github.com:acme/hello.git');
	await writeFile(join(dir, '.gitignore'), 'node_modules/\n*.log\n');
	await writeFile(join(dir, 'Dockerfile'), 'FROM scratch\n');
	await mkdir(join(dir, 'src'));
	await writeFile(join(dir, 'src', 'a.ts'), 'export {};\n');
	await writeFile(join(dir, 'gone.txt'), 'x\n');
	await git('add', '.');
	await git('commit', '-q', '-m', 'init');
	return { dir, git };
}

// The names in a tarball, gzipped or not.
async function listTarball(tarball: string): Promise<string[]> {
	const r = await exec(['tar', '-tf', tarball]);
	return r.stdout
		.split('\n')
		.filter((l) => l !== '')
		.sort();
}

describe('cliGit', () => {
	test('reads root, remote, head, branch and dirtiness', async () => {
		const { dir, git } = await repo();
		const g = cliGit(dir);
		expect(await g.remote()).toBe('git@github.com:acme/hello.git');
		expect(await g.head()).toMatch(/^[0-9a-f]{40}$/);
		expect(await g.branch()).toBe('main');
		expect(await g.dirty()).toBe(false);
		await writeFile(join(dir, 'new.txt'), 'y\n');
		expect(await g.dirty()).toBe(true);
		await git('checkout', '-q', '--detach');
		expect(await g.branch()).toMatch(/^detached-[0-9a-f]{12}$/);
	});

	test('lists every file when the list is longer than 256 KiB', async () => {
		const { dir } = await repo();
		await mkdir(join(dir, 'many'));
		const names = Array.from({ length: 3000 }, (_, i) => `many/${String(i).padStart(96, 'f')}`);
		await Promise.all(names.map((name) => writeFile(join(dir, name), '')));
		const files = await cliGit(dir).files();
		// 3000 names of 101 bytes plus separators: about 300 KB of output.
		expect(files.length).toBe(4 + names.length);
		expect(files).toContain('.gitignore');
		expect(files).toContain(names[0] as string);
		expect(files).toContain(names[2999] as string);
		expect(files.every((f) => f.startsWith('many/') || !f.includes('f'.repeat(10)))).toBe(true);
	});

	test("fetches a pull request's head and merge, and reads the merge's parents", async () => {
		const o = await pullRequestOrigin();
		const g = cliGit(o.user);
		// Not in the clone until fetched.
		await expect(o.userGit('cat-file', '-e', o.head7)).rejects.toThrow();
		expect(await g.fetchPullRequest(7)).toEqual({
			head: o.head7,
			merge: { commit: o.merge7, parents: [o.base, o.head7] },
		});
		const out = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		await g.archive(o.merge7, out);
		const extracted = await mkdtemp(join(tmpdir(), 'koi-x-'));
		await exec(['tar', '-xf', out, '-C', extracted]);
		expect(await Bun.file(join(extracted, 'pr.txt')).text()).toBe('seven\n');
		expect(await Bun.file(join(extracted, 'base.txt')).text()).toBe('base moved\n');
		expect(await o.userGit('for-each-ref', 'refs/koi')).toBe('');
	});

	test('a pull request with no merge ref, as when it conflicts, comes back with its head only', async () => {
		const o = await pullRequestOrigin();
		expect(await cliGit(o.user).fetchPullRequest(8)).toEqual({ head: o.head8, merge: undefined });
		expect(await o.userGit('for-each-ref', 'refs/koi')).toBe('');
	});

	test("a pull request origin does not have comes back with neither, not another's refs", async () => {
		const o = await pullRequestOrigin();
		// Origin has refs/pull/90/head, which a pattern for 9 must not take.
		expect(await cliGit(o.user).fetchPullRequest(9)).toEqual({ head: undefined, merge: undefined });
		expect(await cliGit(o.user).fetchPullRequest(90)).toEqual({ head: o.head90, merge: undefined });
	});

	test('lists the branches on origin and where each is now, without fetching', async () => {
		const o = await pullRequestOrigin();
		const g = cliGit(o.user);
		expect(await g.remoteBranchTips()).toEqual(new Map([['main', o.base]]));
		// Branches move and appear on origin; the clone learns nothing.
		await o.author(
			'push',
			'-q',
			o.origin,
			`+${o.head90}:refs/heads/main`,
			`${o.head8}:refs/heads/x/y`,
		);
		expect(await g.remoteBranchTips()).toEqual(
			new Map([
				['main', o.head90],
				['x/y', o.head8],
			]),
		);
		expect(await o.userGit('rev-parse', 'origin/main')).toBe(o.base);
		await expect(o.userGit('cat-file', '-e', o.head90)).rejects.toThrow();
	});

	test('a fetch that fails throws, rather than finding no refs', async () => {
		const o = await pullRequestOrigin();
		await o.userGit('remote', 'set-url', 'origin', join(o.origin, 'gone'));
		await expect(cliGit(o.user).fetchPullRequest(7)).rejects.toThrow(
			/^git fetch exited 128: [\s\S]*does not appear to be a git repository/,
		);
	});

	test("reads a merge ref's parents as they are, one parent included", async () => {
		const o = await pullRequestOrigin();
		await o.author('push', '-q', o.origin, `${o.head8}:refs/pull/8/merge`);
		expect(await cliGit(o.user).fetchPullRequest(8)).toEqual({
			head: o.head8,
			merge: { commit: o.head8, parents: [o.init] },
		});
		expect(await o.userGit('for-each-ref', 'refs/koi')).toBe('');
	});

	test("reads the merge's parents from a shallow checkout of it, as actions/checkout makes", async () => {
		const o = await pullRequestOrigin();
		const shallow = await shallowCheckout(o.origin, 'refs/pull/7/merge');
		// The merge is the shallow boundary: git's history walkers show it
		// with no parents, though the commit object names both.
		expect(
			(await exec(['git', '-C', shallow, 'rev-list', '--parents', '-n', '1', 'HEAD'])).stdout,
		).toBe(`${o.merge7}\n`);
		expect(await cliGit(shallow).fetchPullRequest(7)).toEqual({
			head: o.head7,
			merge: { commit: o.merge7, parents: [o.base, o.head7] },
		});
	});

	test('reads the refs it fetched even if FETCH_HEAD changes before they are read', async () => {
		const o = await pullRequestOrigin();
		// Another koi up in the same checkout fetches pull request 8 right after
		// this one's fetch finished.
		let raced = false;
		const g = cliGit(o.user, async (cmd, options) => {
			const result = await exec(cmd, options);
			if (cmd.includes('fetch') && !raced) {
				raced = true;
				await o.userGit('fetch', '-q', 'origin', 'refs/pull/8/head');
			}
			return result;
		});
		const refs = await g.fetchPullRequest(7);
		expect(raced).toBe(true);
		expect(await o.userGit('rev-parse', 'FETCH_HEAD')).toBe(o.head8);
		expect(refs.head).toBe(o.head7);
		expect(refs.merge?.commit).toBe(o.merge7);
	});

	test('gives up on a fetch that does not finish after 5 minutes, saying so', async () => {
		const { dir } = await repo();
		const limits: Array<number | undefined> = [];
		// A git fetch that never exits. exec still stops it, at a limit short
		// enough for a test.
		const g = cliGit(dir, (cmd, options) => {
			if (!cmd.includes('fetch')) return exec(cmd, options);
			limits.push(options?.timeoutMs);
			return exec(['sleep', '600'], { ...options, timeoutMs: 200 });
		});
		const err = await g.fetchPullRequest(7).catch((e: unknown) => e);
		expect(limits).toEqual([FETCH_TIMEOUT_MS]);
		expect(FETCH_TIMEOUT_MS).toBe(5 * 60_000);
		expect((err as Error).message).toBe('git fetch did not finish within 5 minutes');
	});

	test('show reads a file at a commit, or nothing', async () => {
		const { dir } = await repo();
		const g = cliGit(dir);
		const head = await g.head();
		expect(await g.show(head, 'Dockerfile')).toBe('FROM scratch\n');
		expect(await g.show(head, 'koi.yaml')).toBeUndefined();
	});
});

describe('changedFiles', () => {
	test('lists what changed since the default branch, committed or not, and untracked files', async () => {
		const { dir, git } = await repo();
		const bare = await mkdtemp(join(tmpdir(), 'koi-origin-'));
		await exec(['git', 'init', '-q', '--bare', bare]);
		await git('remote', 'set-url', 'origin', bare);
		await git('push', '-q', 'origin', 'main');
		await git('fetch', '-q', 'origin');
		await git('checkout', '-q', '-b', 'feature');
		await writeFile(join(dir, 'src', 'a.ts'), 'export const changed = 1;\n');
		await git('commit', '-q', '-am', 'change a');
		await writeFile(join(dir, 'Dockerfile'), 'FROM changed\n');
		await writeFile(join(dir, 'new.ts'), 'untracked\n');
		expect(await cliGit(dir).changedFiles()).toEqual(['Dockerfile', 'new.ts', 'src/a.ts']);
	});

	test('is undefined when there is no default branch to compare with', async () => {
		const { dir } = await repo();
		expect(await cliGit(dir).changedFiles()).toBeUndefined();
	});
});

describe('diffFiles', () => {
	test("lists what a head changes against where it left its base, not the base's later changes", async () => {
		const { dir, git } = await repo();
		const base = (await git('rev-parse', 'HEAD')).stdout.trim();
		await git('checkout', '-q', '-b', 'feature');
		await writeFile(join(dir, 'src', 'a.ts'), 'export const changed = 1;\n');
		await writeFile(join(dir, 'new.ts'), 'export {};\n');
		await git('add', '.');
		await git('commit', '-q', '-m', 'change a, add new');
		const head = (await git('rev-parse', 'HEAD')).stdout.trim();
		await git('checkout', '-q', 'main');
		await writeFile(join(dir, 'Dockerfile'), 'FROM later\n');
		await git('commit', '-q', '-am', 'base moves on');
		const later = (await git('rev-parse', 'HEAD')).stdout.trim();
		expect(await cliGit(dir).diffFiles(base, head)).toEqual(['new.ts', 'src/a.ts']);
		expect(await cliGit(dir).diffFiles(later, head)).toEqual(['new.ts', 'src/a.ts']);
	});
});

describe('mergeFiles', () => {
	test("lists what a merge changes against its base parent: the pull request's files, not the base's", async () => {
		const o = await pullRequestOrigin();
		expect(await cliGit(o.user).mergeFiles(7, o.merge7)).toEqual(['pr.txt']);
	});

	test('deepens a shallow checkout by one to reach the base parent, then lists the same', async () => {
		const o = await pullRequestOrigin();
		const shallow = await shallowCheckout(o.origin, 'refs/pull/7/merge');
		const parent = await exec(['git', '-C', shallow, 'cat-file', '-e', `${o.merge7}^1`]);
		expect(parent.code).not.toBe(0);
		expect(await cliGit(shallow).mergeFiles(7, o.merge7)).toEqual(['pr.txt']);
		expect((await exec(['git', '-C', shallow, 'cat-file', '-e', `${o.merge7}^1`])).code).toBe(0);
		// Tidied: no ref of koi's left behind.
		const refs = await exec(['git', '-C', shallow, 'for-each-ref', 'refs/koi/']);
		expect(refs.stdout).toBe('');
	});
});

describe('fetchBranch', () => {
	test('fetches the commit a branch on origin is at, leaving no ref behind', async () => {
		const o = await pullRequestOrigin();
		await o.author('checkout', '-q', '--detach', o.base);
		await o.author('commit', '-q', '--allow-empty', '-m', 'main moved on');
		const moved = await o.author('rev-parse', 'HEAD');
		await o.author('push', '-q', o.origin, `${moved}:refs/heads/main`);
		expect(await cliGit(o.user).fetchBranch('main')).toBe(moved);
		expect((await exec(['git', '-C', o.user, 'cat-file', '-e', moved])).code).toBe(0);
		expect((await exec(['git', '-C', o.user, 'for-each-ref', 'refs/koi/'])).stdout).toBe('');
		// The clone's own view of origin is left as it was.
		expect(await o.userGit('rev-parse', 'refs/remotes/origin/main')).toBe(o.base);
	});

	test('refuses a name git does not take for a branch, and fails for one origin lacks', async () => {
		const o = await pullRequestOrigin();
		await expect(cliGit(o.user).fetchBranch('main:refs/heads/x')).rejects.toThrow(
			'"main:refs/heads/x" is not a branch name git accepts',
		);
		await expect(cliGit(o.user).fetchBranch('ma*')).rejects.toThrow(
			'"ma*" is not a branch name git accepts',
		);
		await expect(cliGit(o.user).fetchBranch('develop')).rejects.toThrow(/^git fetch exited 128/);
	});
});

describe('mergeCommit', () => {
	test('merges cleanly into a commit with the base, then the head, as parents', async () => {
		const o = await pullRequestOrigin();
		await o.userGit('fetch', '-q', 'origin', 'refs/pull/7/head');
		const made = await cliGit(o.user).mergeCommit(o.base, o.head7);
		if (!('commit' in made)) throw new Error(`conflicts in ${made.conflicts}`);
		const object = await o.userGit('cat-file', '-p', made.commit);
		expect(object.split('\n').filter((l) => l.startsWith('parent '))).toEqual([
			`parent ${o.base}`,
			`parent ${o.head7}`,
		]);
		// The same tree as the merge in the fixture, which git merge made.
		expect(await o.userGit('rev-parse', `${made.commit}^{tree}`)).toBe(
			await o.author('rev-parse', `${o.merge7}^{tree}`),
		);
	});

	test('lists the conflicting files of a merge that does not go cleanly', async () => {
		const o = await pullRequestOrigin();
		await o.userGit('fetch', '-q', 'origin', 'refs/pull/8/head');
		expect(await cliGit(o.user).mergeCommit(o.base, o.head8)).toEqual({ conflicts: ['base.txt'] });
	});

	test('throws, rather than finding no conflicts, for a commit the repository lacks', async () => {
		const o = await pullRequestOrigin();
		// Pull request 8 was never fetched.
		await expect(cliGit(o.user).mergeCommit(o.base, o.head8)).rejects.toThrow(
			`git merge-base exited 128: fatal: Not a valid commit name ${o.head8}`,
		);
	});

	test('says it needs git 2.40, and merges nothing, on an older git', async () => {
		const o = await pullRequestOrigin();
		await o.userGit('fetch', '-q', 'origin', 'refs/pull/7/head');
		const calls: string[][] = [];
		// git version as Apple's git of 2024 answers it.
		const old = (cmd: string[], options?: ExecOptions): Promise<ExecResult> => {
			calls.push(cmd);
			return cmd.at(-1) === 'version'
				? Promise.resolve({
						code: 0,
						stdout: 'git version 2.39.5 (Apple Git-154)\n',
						stderr: '',
						timedOut: false,
					})
				: exec(cmd, options);
		};
		await expect(cliGit(o.user, old).mergeCommit(o.base, o.head7)).rejects.toThrow(
			'koi merges with git merge-tree --write-tree and git --attr-source, which need git 2.40 or later (this is git version 2.39.5 (Apple Git-154))',
		);
		expect(calls.some((c) => c.includes('merge-tree') || c.includes('fetch'))).toBe(false);
	});

	test("neither the checkout's nor the machine's attributes or merge drivers change the merge", async () => {
		const o = await pullRequestOrigin();
		await o.userGit('fetch', '-q', 'origin', 'refs/pull/8/head');
		const conflict = { conflicts: ['base.txt'] };
		const union = 'base.txt merge=union\n';
		// An untracked .gitattributes in the work tree, which git merge-tree
		// in the checkout reads.
		await writeFile(join(o.user, '.gitattributes'), union);
		expect(await cliGit(o.user).mergeCommit(o.base, o.head8)).toEqual(conflict);
		await rm(join(o.user, '.gitattributes'));
		// The checkout's own attributes file.
		await mkdir(join(o.user, '.git', 'info'), { recursive: true });
		await writeFile(join(o.user, '.git', 'info', 'attributes'), union);
		expect(await cliGit(o.user).mergeCommit(o.base, o.head8)).toEqual(conflict);
		await rm(join(o.user, '.git', 'info', 'attributes'));
		// A merge driver the user's global config sets up for every path,
		// which takes the base's side and reports success.
		const home = await mkdtemp(join(tmpdir(), 'koi-home-'));
		await writeFile(join(home, 'attributes'), '* merge=keep-base\n');
		await writeFile(
			join(home, 'gitconfig'),
			`[core]\n\tattributesFile = ${join(home, 'attributes')}\n[merge "keep-base"]\n\tdriver = true\n`,
		);
		// git as it runs in that user's environment, where koi's own
		// variables still come last.
		const machine = (cmd: string[], options?: ExecOptions): Promise<ExecResult> =>
			exec(cmd, {
				...options,
				env: { GIT_CONFIG_GLOBAL: join(home, 'gitconfig'), ...options?.env },
			});
		expect(
			(
				await execOk(['git', 'config', '--get', 'merge.keep-base.driver'], {
					env: { GIT_CONFIG_GLOBAL: join(home, 'gitconfig') },
				})
			).stdout,
		).toBe('true\n');
		expect(await cliGit(o.user, machine).mergeCommit(o.base, o.head8)).toEqual(conflict);
	});

	test("the checkout's merge.renormalize does not change the merge", async () => {
		// A file committed with CRLF line ends. The base adds `* text=auto` and
		// stores the file with LF; the head changes a line and keeps CRLF. git
		// merges the two cleanly only when it renormalizes them.
		const dir = await mkdtemp(join(tmpdir(), 'koi-git-'));
		const git = async (...args: string[]) =>
			(
				await execOk([
					'git',
					'-C',
					dir,
					'-c',
					'user.email=t@example.com',
					'-c',
					'user.name=t',
					...args,
				])
			).stdout.trim();
		await git('init', '-q', '-b', 'main');
		await writeFile(join(dir, 'file.txt'), 'a\r\nb\r\nc\r\n');
		await git('add', 'file.txt');
		await git('commit', '-q', '-m', 'crlf');
		await git('checkout', '-q', '-b', 'head');
		await writeFile(join(dir, 'file.txt'), 'a\r\nB\r\nc\r\n');
		await git('commit', '-q', '-am', 'head');
		const head = await git('rev-parse', 'HEAD');
		await git('checkout', '-q', 'main');
		await writeFile(join(dir, '.gitattributes'), '* text=auto\n');
		await writeFile(join(dir, 'file.txt'), 'a\nb\nc\n');
		await git('add', '.gitattributes', 'file.txt');
		await git('commit', '-q', '-m', 'base');
		const base = await git('rev-parse', 'HEAD');
		const conflict = { conflicts: ['file.txt'] };
		expect(await cliGit(dir).mergeCommit(base, head)).toEqual(conflict);
		await git('config', 'merge.renormalize', 'true');
		expect(await cliGit(dir).mergeCommit(base, head)).toEqual(conflict);
	});

	test("takes attributes from the base's .gitattributes, not the head's", async () => {
		const o = await pullRequestOrigin();
		// main moves on by a commit that merges base.txt as a union.
		await o.author('checkout', '-q', '--detach', o.base);
		const unionBase = await o.commit('.gitattributes', 'base.txt merge=union\n', 'union');
		await o.author('push', '-q', o.origin, `${unionBase}:refs/heads/main`);
		await o.userGit('fetch', '-q', 'origin', 'main', 'refs/pull/8/head');
		const made = await cliGit(o.user).mergeCommit(unionBase, o.head8);
		if (!('commit' in made)) throw new Error(`conflicts in ${made.conflicts}`);
		expect(await o.userGit('show', `${made.commit}:base.txt`)).toBe('base moved\nsomething else');
		// The pull request adds the same rule, and the base it merges into has
		// none.
		await o.author('checkout', '-q', '--detach', o.head8);
		const unionHead = await o.commit('.gitattributes', 'base.txt merge=union\n', 'union too');
		await o.author('push', '-q', o.origin, `${unionHead}:refs/pull/8/head`);
		await o.userGit('fetch', '-q', 'origin', 'refs/pull/8/head');
		expect(await cliGit(o.user).mergeCommit(o.base, unionHead)).toEqual({
			conflicts: ['base.txt'],
		});
	});
});

describe('koiFiles', () => {
	test('lists every changed file, however many', () => {
		const changed = Array.from({ length: 6000 }, (_, i) => `src/m${i}/x.py`);
		const text = koiFiles(changed)['changed-files.txt'] ?? '';
		expect(text.split('\n').filter((l) => l !== '')).toEqual(changed);
	});
});

describe('finishTarball', () => {
	test("adds koi's own files under .koi-runtime/, keeps the tree's .koi/ and gzips", async () => {
		const { dir } = await repo();
		await mkdir(join(dir, '.koi'));
		await writeFile(join(dir, '.koi', 'verify.yaml'), 'version: 1\n');
		await writeFile(join(dir, '.koi', 'changed-files.txt'), 'the project may name a file so\n');
		const tar = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		await exec(['tar', '-cf', tar, '-C', dir, 'Dockerfile', '.koi']);
		const gz = await finishTarball(tar, { 'changed-files.txt': 'real\n' });
		expect(gz).toBe(`${tar}.gz`);
		expect(await listTarball(gz)).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'.koi/',
			'.koi/changed-files.txt',
			'.koi/verify.yaml',
			'Dockerfile',
		]);
		const runtime = await exec(['tar', '-xzOf', gz, '.koi-runtime/changed-files.txt']);
		expect(runtime.stdout).toBe('real\n');
		const project = await exec(['tar', '-xzOf', gz, '.koi/changed-files.txt']);
		expect(project.stdout).toBe('the project may name a file so\n');
	});

	test('refuses a tree with a .koi-runtime/ of its own, naming what is there', async () => {
		const { dir } = await repo();
		await mkdir(join(dir, '.koi-runtime'));
		await writeFile(join(dir, '.koi-runtime', 'changed-files.txt'), 'forged\n');
		const tar = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		await exec(['tar', '-cf', tar, '-C', dir, 'Dockerfile', '.koi-runtime']);
		const err = await finishTarball(tar, { 'changed-files.txt': 'real\n' }).catch(
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(Error);
		expect((err as Error).message).toContain('.koi-runtime/, which koi reserves');
		expect((err as Error).message).toContain('.koi-runtime/changed-files.txt');
		expect(await Bun.file(`${tar}.gz`).exists()).toBe(false);
	});
});

describe('packWorkingTree', () => {
	test("packs tracked and untracked files, the project's .koi/ among them, skips ignored and deleted ones", async () => {
		const { dir } = await repo();
		await writeFile(join(dir, 'untracked.ts'), 'u\n');
		await mkdir(join(dir, 'node_modules'));
		await writeFile(join(dir, 'node_modules', 'big.js'), 'ignored\n');
		await writeFile(join(dir, 'debug.log'), 'ignored\n');
		await mkdir(join(dir, '.koi', 'points'), { recursive: true });
		await writeFile(join(dir, '.koi', 'verify.yaml'), 'version: 1\n');
		await writeFile(join(dir, '.koi', 'points', 'home.yaml'), 'id: hello.home\n');
		await rm(join(dir, 'gone.txt'));
		await symlink('src/a.ts', join(dir, 'link.ts'));
		const out = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		const count = await packWorkingTree(dir, await cliGit(dir).files(), out);
		const names = await listTarball(await finishTarball(out, {}));
		expect(names).toEqual([
			'.gitignore',
			'.koi-runtime/',
			'.koi/points/home.yaml',
			'.koi/verify.yaml',
			'Dockerfile',
			'link.ts',
			'src/a.ts',
			'untracked.ts',
		]);
		expect(count).toBe(7);
	});

	test('refuses a working tree with a .koi-runtime/ in it', async () => {
		const { dir } = await repo();
		await mkdir(join(dir, '.koi-runtime'));
		await writeFile(join(dir, '.koi-runtime', 'changed-files.txt'), 'forged\n');
		const out = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		await packWorkingTree(dir, await cliGit(dir).files(), out);
		await expect(finishTarball(out, { 'changed-files.txt': 'real\n' })).rejects.toThrow(
			'.koi-runtime/changed-files.txt',
		);
	});

	test('refuses files under a directory that became a symlink to somewhere else', async () => {
		const { dir } = await repo();
		const outside = await mkdtemp(join(tmpdir(), 'koi-outside-'));
		await writeFile(join(outside, 'a.ts'), 'secret\n');
		await rm(join(dir, 'src'), { recursive: true });
		await symlink(outside, join(dir, 'src'));
		const files = await cliGit(dir).files();
		// The index still lists src/a.ts; on disk it is the file outside.
		expect(files).toContain('src/a.ts');
		const out = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		const err = await packWorkingTree(dir, files, out).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(Error);
		expect((err as Error).message).toContain('src/a.ts (src is a symlink)');
		expect(await Bun.file(out).exists()).toBe(false);
	});

	test('refuses a checkout with an initialized submodule, naming it', async () => {
		const { dir, git } = await repo();
		const lib = await repo();
		await git('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', lib.dir, 'vendor/lib');
		// Another repository inside the tree, not a submodule.
		await exec(['git', 'init', '-q', join(dir, 'nested')]);
		await writeFile(join(dir, 'nested', 'n.ts'), 'n\n');
		const out = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar.gz');
		const err = await packWorkingTree(dir, await cliGit(dir).files(), out).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(Error);
		const message = (err as Error).message;
		expect(message).toStartWith('refusing to pack a checkout with initialized submodules');
		expect(message).toContain('\n  vendor/lib\n');
		expect(message).toContain('\n  nested\n');
		expect(await Bun.file(out).exists()).toBe(false);
	});

	test('packs a checkout whose submodule is not initialized', async () => {
		const { dir, git } = await repo();
		const lib = await repo();
		await git('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', lib.dir, 'vendor/lib');
		await git('submodule', 'deinit', '-q', '-f', 'vendor/lib');
		const out = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar.gz');
		expect(await packWorkingTree(dir, await cliGit(dir).files(), out)).toBe(5);
		expect(await listTarball(out)).toEqual([
			'.gitignore',
			'.gitmodules',
			'Dockerfile',
			'gone.txt',
			'src/a.ts',
		]);
	});

	test('packs the whole tree when koi starts in a subdirectory', async () => {
		const { dir } = await repo();
		await writeFile(join(dir, 'src', 'b.ts'), 'untracked\n');
		const g = cliGit(join(dir, 'src'));
		const files = await g.files();
		expect([...files].sort()).toEqual([
			'.gitignore',
			'Dockerfile',
			'gone.txt',
			'src/a.ts',
			'src/b.ts',
		]);
		const out = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		expect(await packWorkingTree(await g.root(), files, out)).toBe(5);
		expect(await listTarball(out)).toEqual([
			'.gitignore',
			'Dockerfile',
			'gone.txt',
			'src/a.ts',
			'src/b.ts',
		]);
		const archived = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		await g.archive(await g.head(), archived);
		expect(await listTarball(archived)).toEqual([
			'.gitignore',
			'Dockerfile',
			'gone.txt',
			'src/',
			'src/a.ts',
		]);
	});

	test('archives a commit, ignoring the working tree', async () => {
		const { dir } = await repo();
		await writeFile(join(dir, 'Dockerfile'), 'FROM changed\n');
		const g = cliGit(dir);
		const out = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'src.tar');
		await g.archive(await g.head(), out);
		const extracted = await mkdtemp(join(tmpdir(), 'koi-x-'));
		await exec(['tar', '-xf', out, '-C', extracted]);
		expect(await Bun.file(join(extracted, 'Dockerfile')).text()).toBe('FROM scratch\n');
	});
});
