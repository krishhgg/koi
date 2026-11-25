import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { chmod, link, mkdir, mkdtemp, rm, rmdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exec } from '../../cli/src/exec.ts';
import { cliGit, finishTarball, koiFiles, packWorkingTree } from '../../cli/src/git.ts';
import { hashSourceDir, hashSourceTarball } from '../src/source-tree.ts';

const DIGEST = expect.stringMatching(/^sha256:[0-9a-f]{64}$/);

// A repository whose one commit has what a tree id must get right: nested
// directories, an executable, a symlink, an empty file, bytes that are not
// text, a name that is not ASCII, a path longer than a tar header's name
// field and one with a segment longer than it, and names that sort
// differently once a directory's is read as ending in '/'.
async function repo() {
	const dir = await mkdtemp(join(tmpdir(), 'koi-tree-'));
	const git = async (...args: string[]) => {
		const r = await exec(
			['git', '-C', dir, '-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args],
			{ maxBytes: 64 * 1024 * 1024 },
		);
		if (r.code !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
		return r.stdout.trim();
	};
	await git('init', '-q', '-b', 'main');
	await git('remote', 'add', 'origin', 'git@github.com:acme/hello.git');
	const files: Record<string, string | Uint8Array> = {
		Dockerfile: 'FROM scratch\n',
		'src/app.ts': 'export {};\n',
		'src/lib/deep/x.ts': 'x\n',
		'a.b': 'file before the directory a\n',
		'a/x': 'in a\n',
		'a-b': 'dash\n',
		empty: '',
		'bin.dat': new Uint8Array([0, 1, 2, 13, 10, 255, 0]),
		'café.txt': 'not ascii\n',
		[`long/${'d'.repeat(60)}/${'e'.repeat(60)}.txt`]: 'past 100 bytes\n',
		[`seg/${'s'.repeat(120)}`]: 'one segment past 100 bytes\n',
	};
	for (const [path, content] of Object.entries(files)) {
		await mkdir(join(dir, path, '..'), { recursive: true });
		await writeFile(join(dir, path), content);
	}
	await writeFile(join(dir, 'run.sh'), '#!/bin/sh\n', { mode: 0o755 });
	await symlink('src/app.ts', join(dir, 'link.ts'));
	await git('add', '.');
	await git('commit', '-q', '-m', 'init');
	await git('update-ref', 'refs/remotes/origin/main', 'HEAD');
	return { dir, git, tree: await git('rev-parse', 'HEAD^{tree}') };
}

// The tarball koi up uploads for the working tree: what packWorkingTree
// packs, with koi's own files added and gzipped.
async function packed(dir: string, changed: string[] = []): Promise<string> {
	const tar = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'source.tar');
	await packWorkingTree(dir, await cliGit(dir).files(), tar);
	return finishTarball(tar, koiFiles(changed));
}

// The tarball koi up --pr uploads for a commit: git archive of it.
async function archived(dir: string, commit: string, changed: string[] = []): Promise<string> {
	const tar = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'source.tar');
	await cliGit(dir).archive(commit, tar);
	return finishTarball(tar, koiFiles(changed));
}

// The tree git writes for the files in the working tree as they are,
// tracked or not, in an index of its own: what a commit of them would hold.
async function workingTree(dir: string): Promise<string> {
	const index = join(await mkdtemp(join(tmpdir(), 'koi-index-')), 'index');
	const env = { GIT_INDEX_FILE: index };
	const add = await exec(['git', '-C', dir, 'add', '-A'], { env });
	if (add.code !== 0) throw new Error(add.stderr);
	return (await exec(['git', '-C', dir, 'write-tree'], { env })).stdout.trim();
}

// git's id of a tree holding the one file changed-files.txt with `text`.
async function runtimeTreeOf(dir: string, text: string): Promise<string> {
	const blob = (
		await exec(['git', '-C', dir, 'hash-object', '-w', '--stdin'], { stdin: text })
	).stdout.trim();
	const tree = await exec(['git', '-C', dir, 'mktree'], {
		stdin: `100644 blob ${blob}\tchanged-files.txt\n`,
	});
	return tree.stdout.trim();
}

describe('hashSourceTarball, as koid unpacks and walks an upload', () => {
	test("gives a commit's tree for git archive of it, as koi up --pr uploads it", async () => {
		const { dir, git, tree } = await repo();
		const out = await hashSourceTarball(
			await archived(dir, await git('rev-parse', 'HEAD'), ['a/x']),
		);
		expect(out).toEqual({ digest: DIGEST, tree, runtimeTree: await runtimeTreeOf(dir, 'a/x\n') });
	});

	test("gives HEAD's tree for a clean working tree, and the tree of its files once they change", async () => {
		const { dir, tree } = await repo();
		const clean = await hashSourceTarball(await packed(dir));
		expect(clean.tree).toBe(tree);
		expect(clean.runtimeTree).toBe(await runtimeTreeOf(dir, '\n'));

		// A change not committed: another tree, the one git would commit.
		await writeFile(join(dir, 'src/app.ts'), 'export const changed = 1;\n');
		const edited = await hashSourceTarball(await packed(dir));
		expect(edited.tree).not.toBe(tree);
		expect(edited.tree).toBe(await workingTree(dir));

		// An untracked file is in the tarball too, so in the tree.
		await writeFile(join(dir, 'src/app.ts'), 'export {};\n');
		expect((await hashSourceTarball(await packed(dir))).tree).toBe(tree);
		await writeFile(join(dir, 'notes.txt'), 'untracked\n');
		const untracked = await hashSourceTarball(await packed(dir));
		expect(untracked.tree).not.toBe(tree);
		expect(untracked.tree).toBe(await workingTree(dir));

		// So is a file whose mode alone changed.
		await rm(join(dir, 'notes.txt'));
		await exec(['chmod', '+x', join(dir, 'Dockerfile')]);
		const mode = await hashSourceTarball(await packed(dir));
		expect(mode.tree).not.toBe(tree);
		expect(mode.tree).toBe(await workingTree(dir));
	});

	test('reads names tar -C DIR . writes, the directory itself among them', async () => {
		const { dir, tree } = await repo();
		const tar = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'source.tar');
		await exec(['tar', '-cf', tar, '--exclude=./.git', '-C', dir, '.']);
		expect((await exec(['tar', '-tf', tar])).stdout).toStartWith('./\n');
		await exec(['gzip', '-n', '-f', tar]);
		expect(await hashSourceTarball(`${tar}.gz`)).toEqual({ digest: DIGEST, tree });
	});

	test('reads a second name GNU tar packs as a hard link as the file it links to', async () => {
		const { dir, git } = await repo();
		await rm(join(dir, 'a-b'));
		await link(join(dir, 'a.b'), join(dir, 'a-b'));
		await git('add', '.');
		await git('commit', '-q', '-m', 'linked');
		const tarball = await packed(dir);
		const listing = (await exec(['tar', '-tvzf', tarball])).stdout;
		expect(listing).toMatch(/^h.* a\.b link to a-b$/m);
		expect((await hashSourceTarball(tarball)).tree).toBe(await git('rev-parse', 'HEAD^{tree}'));
	});

	test('leaves out a directory with no file under it, as git does, so a submodule never matches', async () => {
		const { dir, git, tree } = await repo();
		// A submodule: the commit's tree names a commit, git archive writes
		// an empty directory.
		await git('update-index', '--add', '--cacheinfo', `160000,${'1'.repeat(40)},sub`);
		await git('commit', '-q', '-m', 'submodule');
		const withSub = await git('rev-parse', 'HEAD^{tree}');
		const tarball = await archived(dir, await git('rev-parse', 'HEAD'));
		expect((await exec(['tar', '-tzf', tarball])).stdout.split('\n')).toContain('sub/');
		const out = await hashSourceTarball(tarball);
		expect(out.tree).not.toBe(withSub);
		expect(out.tree).toBe(tree);
	});

	test('hashes the bytes as checked out, so a file git converts gives another tree', async () => {
		const { dir, git, tree } = await repo();
		await writeFile(join(dir, '.gitattributes'), '*.bat text eol=crlf\n');
		await writeFile(join(dir, 'build.bat'), 'echo one\necho two\n');
		await git('add', '.');
		await git('commit', '-q', '-m', 'bat');
		const commitTree = await git('rev-parse', 'HEAD^{tree}');
		expect(commitTree).not.toBe(tree);
		const out = await hashSourceTarball(await archived(dir, await git('rev-parse', 'HEAD')));
		expect(out.tree).not.toBe(commitTree);
		// The tree of the same files with build.bat as git archive wrote it,
		// CRLF line endings and all.
		const index = join(await mkdtemp(join(tmpdir(), 'koi-index-')), 'index');
		const env = { GIT_INDEX_FILE: index };
		await exec(['git', '-C', dir, 'read-tree', 'HEAD'], { env });
		const crlf = (
			await exec(['git', '-C', dir, 'hash-object', '-w', '--no-filters', '--stdin'], {
				stdin: 'echo one\r\necho two\r\n',
			})
		).stdout.trim();
		await exec(['git', '-C', dir, 'update-index', '--cacheinfo', `100644,${crlf},build.bat`], {
			env,
		});
		expect(out.tree).toBe((await exec(['git', '-C', dir, 'write-tree'], { env })).stdout.trim());
	});

	test('is what scripts/source-tree.ts prints for git archive of the commit, gzipped or not', async () => {
		const { dir, git, tree } = await repo();
		const script = join(import.meta.dir, '../../../scripts/source-tree.ts');
		const commit = await git('rev-parse', 'HEAD');
		const plain = join(await mkdtemp(join(tmpdir(), 'koi-plain-')), 'source.tar');
		await cliGit(dir).archive(commit, plain);
		const fromStdin = Bun.spawnSync(['bun', script, '-'], { stdin: Bun.file(plain) });
		expect(fromStdin.stderr.toString()).toBe('');
		expect(JSON.parse(fromStdin.stdout.toString())).toEqual({ digest: DIGEST, tree });
		const gz = await archived(dir, commit, ['a/x']);
		const fromFile = Bun.spawnSync(['bun', script, gz]);
		expect(JSON.parse(fromFile.stdout.toString())).toEqual(await hashSourceTarball(gz));
	});

	test('streams a large file through, past any one chunk', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-big-'));
		const src = join(dir, 'src');
		await mkdir(src);
		const big = new Uint8Array(64 * 1024 * 1024).map((_, i) => (i * 31) % 251);
		await writeFile(join(src, 'big.bin'), big);
		const tar = join(dir, 'source.tar');
		await exec(['tar', '-cf', tar, '-C', dir, 'src']);
		await exec(['gzip', '-n', '-f', '-1', tar]);
		const g = (args: string[], stdin?: string) =>
			exec(['git', ...args], {
				env: { GIT_DIR: join(dir, 'g') },
				...(stdin !== undefined ? { stdin } : {}),
			}).then((r) => r.stdout.trim());
		await g(['init', '-q', '--bare']);
		const blob = await g(['hash-object', '-w', '--no-filters', join(src, 'big.bin')]);
		const sub = await g(['mktree'], `100644 blob ${blob}\tbig.bin\n`);
		const root = await g(['mktree'], `040000 tree ${sub}\tsrc\n`);
		expect(await hashSourceTarball(`${tar}.gz`)).toEqual({ digest: DIGEST, tree: root });
	});
});

describe('hashSourceDir', () => {
	const sha256 = (bytes: string | Uint8Array) => createHash('sha256').update(bytes).digest('hex');
	const listing = (...fields: string[]) =>
		`sha256:${sha256(['koi-source-digest/1', ...fields].map((f) => `${f}\0`).join(''))}`;
	const scratch = () => mkdtemp(join(tmpdir(), 'koi-walk-'));

	test('hashes the listing source-tree.ts describes, sorted by path with a directory read as ending in /', async () => {
		const dir = await scratch();
		await writeFile(join(dir, 'a.b'), 'hi\n');
		await mkdir(join(dir, 'a'));
		await symlink('../a.b', join(dir, 'a', 'l'));
		await link(join(dir, 'a.b'), join(dir, 'a', 'h'));
		await chmod(join(dir, 'a.b'), 0o640);
		await chmod(join(dir, 'a'), 0o750);
		const out = await hashSourceDir(dir);
		expect(out.digest).toBe(
			listing(
				...['file', 'a.b', '0640', '3', sha256('hi\n')],
				...['dir', 'a/', '0750'],
				...['hardlink', 'a/h', 'a.b'],
				...['symlink', 'a/l', '0777', '../a.b'],
			),
		);
		expect(out.tree).toMatch(/^[0-9a-f]{40}$/);
	});

	test('an empty directory and permission bits git does not keep change the digest, not the tree', async () => {
		const dir = await scratch();
		await writeFile(join(dir, 'f'), 'x\n');
		await chmod(join(dir, 'f'), 0o644);
		const before = await hashSourceDir(dir);

		await mkdir(join(dir, 'empty'));
		const empty = await hashSourceDir(dir);
		expect(empty.tree).toBe(before.tree as string);
		expect(empty.digest).not.toBe(before.digest);
		await rmdir(join(dir, 'empty'));
		expect(await hashSourceDir(dir)).toEqual(before);

		await chmod(join(dir, 'f'), 0o600);
		const mode = await hashSourceDir(dir);
		expect(mode.tree).toBe(before.tree as string);
		expect(mode.digest).not.toBe(before.digest);
		// The owner's execute bit is one git keeps.
		await chmod(join(dir, 'f'), 0o700);
		expect((await hashSourceDir(dir)).tree).not.toBe(before.tree as string);
	});

	test('a hard link and a copy of the same bytes share a tree, not a digest', async () => {
		const copied = await scratch();
		await writeFile(join(copied, 'a'), 'same\n');
		await writeFile(join(copied, 'b'), 'same\n');
		const linked = await scratch();
		await writeFile(join(linked, 'a'), 'same\n');
		await link(join(linked, 'a'), join(linked, 'b'));
		for (const dir of [copied, linked]) {
			await chmod(join(dir, 'a'), 0o644);
			await chmod(join(dir, 'b'), 0o644);
		}
		const copy = await hashSourceDir(copied);
		const hard = await hashSourceDir(linked);
		expect(hard.tree).toBe(copy.tree as string);
		expect(hard.digest).not.toBe(copy.digest);
	});

	test('a hard-linked symlink and two symlinks to one target share a tree, not a digest', async () => {
		const separate = await scratch();
		await symlink('t', join(separate, 'a'));
		await symlink('t', join(separate, 'b'));
		const linked = await scratch();
		await symlink('t', join(linked, 'a'));
		// link(2) does not follow a symlink on Linux: b is a second name for a.
		await link(join(linked, 'a'), join(linked, 'b'));
		const apart = await hashSourceDir(separate);
		const hard = await hashSourceDir(linked);
		expect(hard.tree).toBe(apart.tree as string);
		expect(hard.digest).not.toBe(apart.digest);
	});

	test('records a fifo by path and mode without opening it, and gives no tree', async () => {
		const dir = await scratch();
		await writeFile(join(dir, 'x'), 'x\n');
		await chmod(join(dir, 'x'), 0o644);
		await mkdir(join(dir, '.koi-runtime'));
		await chmod(join(dir, '.koi-runtime'), 0o755);
		// No process ever opens the other end, so an open to read it would
		// wait forever.
		expect((await exec(['mkfifo', '-m', '600', join(dir, '.koi-runtime', 'p')])).code).toBe(0);
		expect(await hashSourceDir(dir)).toEqual({
			digest: listing(
				...['dir', '.koi-runtime/', '0755'],
				...['fifo', '.koi-runtime/p', '0600'],
				...['file', 'x', '0644', '2', sha256('x\n')],
			),
			noTree: '".koi-runtime/p" is a fifo, which git has no object for',
		});
		// .koi-runtime/ as anything but a directory leaves no tree either.
		await rm(join(dir, '.koi-runtime'), { recursive: true });
		await writeFile(join(dir, '.koi-runtime'), '');
		expect((await hashSourceDir(dir)).noTree).toBe('".koi-runtime" is a file, not a directory');
	});

	test('reads names as bytes, as git does', async () => {
		const dir = await scratch();
		const name = Buffer.from('caf\xe9.txt', 'latin1');
		await writeFile(Buffer.concat([Buffer.from(`${dir}/`), name]), 'latin1\n');
		await writeFile(join(dir, 'café.txt'), 'utf-8\n');
		const git = (...args: string[]) =>
			exec(['git', '-C', dir, ...args]).then((r) => {
				if (r.code !== 0) throw new Error(r.stderr);
				return r.stdout.trim();
			});
		await git('init', '-q');
		await git('add', '-A');
		const tree = await git('write-tree');
		await rm(join(dir, '.git'), { recursive: true });
		expect((await hashSourceDir(dir)).tree).toBe(tree);
	});

	test('stops past the limits unpacking has, counting a file with two names once', async () => {
		const dir = await scratch();
		await writeFile(join(dir, 'a'), 'x');
		await link(join(dir, 'a'), join(dir, 'b'));
		await mkdir(join(dir, 'c'));
		await expect(hashSourceDir(dir, { limits: { entries: 2, bytes: 100 } })).rejects.toThrow(
			'the source has more than 2 files and directories',
		);
		expect((await hashSourceDir(dir, { limits: { entries: 3, bytes: 1 } })).tree).toBeDefined();
		await writeFile(join(dir, 'c', 'd'), 'y');
		await expect(hashSourceDir(dir, { limits: { entries: 10, bytes: 1 } })).rejects.toThrow(
			'the source unpacks to more than 1 bytes',
		);
	});

	test('stops when the build is aborted', async () => {
		const dir = await scratch();
		await writeFile(join(dir, 'a'), 'x');
		const stop = new AbortController();
		stop.abort(new Error('koi down removed the preview'));
		await expect(hashSourceDir(dir, { signal: stop.signal })).rejects.toThrow(
			'koi down removed the preview',
		);
	});
});
