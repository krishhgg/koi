import { describe, expect, test } from 'bun:test';
import { link, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { exec } from '../../cli/src/exec.ts';
import { cliGit, finishTarball, koiFiles, packWorkingTree } from '../../cli/src/git.ts';
import { sourceTrees } from '../src/source-tree.ts';

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

describe('sourceTrees', () => {
	test("gives a commit's tree for git archive of it, as koi up --pr uploads it", async () => {
		const { dir, git, tree } = await repo();
		const out = await sourceTrees(await archived(dir, await git('rev-parse', 'HEAD'), ['a/x']));
		expect(out).toEqual({ tree, runtimeTree: await runtimeTreeOf(dir, 'a/x\n') });
	});

	test("gives HEAD's tree for a clean working tree, and the tree of its files once they change", async () => {
		const { dir, tree } = await repo();
		const clean = await sourceTrees(await packed(dir));
		expect(clean.tree).toBe(tree);
		expect(clean.runtimeTree).toBe(await runtimeTreeOf(dir, '\n'));

		// A change not committed: another tree, the one git would commit.
		await writeFile(join(dir, 'src/app.ts'), 'export const changed = 1;\n');
		const edited = await sourceTrees(await packed(dir));
		expect(edited.tree).not.toBe(tree);
		expect(edited.tree).toBe(await workingTree(dir));

		// An untracked file is in the tarball too, so in the tree.
		await writeFile(join(dir, 'src/app.ts'), 'export {};\n');
		expect((await sourceTrees(await packed(dir))).tree).toBe(tree);
		await writeFile(join(dir, 'notes.txt'), 'untracked\n');
		const untracked = await sourceTrees(await packed(dir));
		expect(untracked.tree).not.toBe(tree);
		expect(untracked.tree).toBe(await workingTree(dir));

		// So is a file whose mode alone changed.
		await rm(join(dir, 'notes.txt'));
		await exec(['chmod', '+x', join(dir, 'Dockerfile')]);
		const mode = await sourceTrees(await packed(dir));
		expect(mode.tree).not.toBe(tree);
		expect(mode.tree).toBe(await workingTree(dir));
	});

	test('reads names tar -C DIR . writes, the directory itself among them', async () => {
		const { dir, tree } = await repo();
		const tar = join(await mkdtemp(join(tmpdir(), 'koi-pack-')), 'source.tar');
		await exec(['tar', '-cf', tar, '--exclude=./.git', '-C', dir, '.']);
		expect((await exec(['tar', '-tf', tar])).stdout).toStartWith('./\n');
		await exec(['gzip', '-n', '-f', tar]);
		expect(await sourceTrees(`${tar}.gz`)).toEqual({ tree });
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
		expect((await sourceTrees(tarball)).tree).toBe(await git('rev-parse', 'HEAD^{tree}'));
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
		const out = await sourceTrees(tarball);
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
		const out = await sourceTrees(await archived(dir, await git('rev-parse', 'HEAD')));
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
		expect(JSON.parse(fromStdin.stdout.toString())).toEqual({ tree });
		const gz = await archived(dir, commit, ['a/x']);
		const fromFile = Bun.spawnSync(['bun', script, gz]);
		expect(JSON.parse(fromFile.stdout.toString())).toEqual(await sourceTrees(gz));
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
		expect(await sourceTrees(`${tar}.gz`)).toEqual({ tree: root });
	});
});

// A tar header by hand, for what neither git nor GNU tar writes: ustar,
// with the name and link target given and a correct checksum.
function header(name: string, type: string, size = 0, linkname = ''): Uint8Array {
	const h = new Uint8Array(512);
	const put = (text: string, at: number, length: number) =>
		h.set(new TextEncoder().encode(text).subarray(0, length), at);
	put(name, 0, 100);
	put('0000644\0', 100, 8);
	put('0000000\0', 108, 8);
	put('0000000\0', 116, 8);
	put(`${size.toString(8).padStart(11, '0')}\0`, 124, 12);
	put('00000000000\0', 136, 12);
	put(type, 156, 1);
	put(linkname, 157, 100);
	put('ustar\0', 257, 6);
	put('00', 263, 2);
	put('        ', 148, 8);
	const sum = h.reduce((a, b) => a + b, 0);
	put(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8);
	return h;
}

function data(text: string): Uint8Array {
	const bytes = new TextEncoder().encode(text);
	const out = new Uint8Array(Math.ceil(bytes.length / 512) * 512);
	out.set(bytes);
	return out;
}

function pax(records: Record<string, string>): string {
	let body = '';
	for (const [key, value] of Object.entries(records)) {
		const rest = ` ${key}=${value}\n`;
		let length = rest.length + 1;
		while (`${length}${rest}`.length !== length) length += 1;
		body += `${length}${rest}`;
	}
	return body;
}

async function tarballOf(...parts: Array<Uint8Array | string>): Promise<string> {
	const blocks = parts.map((p) => (typeof p === 'string' ? data(p) : p));
	const end = new Uint8Array(1024);
	const all = new Uint8Array([...blocks.flatMap((b) => [...b]), ...end]);
	const file = join(await mkdtemp(join(tmpdir(), 'koi-hand-')), 'source.tar.gz');
	await writeFile(file, gzipSync(all));
	return file;
}

describe('sourceTrees refuses a tarball its id could not describe exactly', () => {
	const file = (name: string, text: string) => [header(name, '0', text.length), text];

	test('a path given twice', async () => {
		await expect(
			sourceTrees(await tarballOf(...file('a', 'x'), ...file('a', 'y'))),
		).rejects.toThrow('"a" is in the archive twice');
	});

	test('a path that is a file and a directory, as under a symlink', async () => {
		await expect(
			sourceTrees(await tarballOf(header('a', '2', 0, '/etc'), ...file('a/passwd', 'x'))),
		).rejects.toThrow('"a" is both a file and a directory');
	});

	test('a path tar would unpack elsewhere', async () => {
		for (const name of ['../x', '/etc/passwd', 'a//b', 'a/./b']) {
			await expect(sourceTrees(await tarballOf(...file(name, 'x')))).rejects.toThrow(
				'which is not a plain relative path',
			);
		}
	});

	test('an entry that is not a file, symlink, hard link to a file or directory', async () => {
		await expect(sourceTrees(await tarballOf(header('dev', '3')))).rejects.toThrow(
			'"dev" is a character device',
		);
		await expect(sourceTrees(await tarballOf(header('fifo', '6')))).rejects.toThrow(
			'"fifo" is a fifo',
		);
		await expect(sourceTrees(await tarballOf(header('l', '1', 0, 'missing')))).rejects.toThrow(
			'which is not a file before it in the archive',
		);
	});

	test('a PAX record that could change what an entry holds', async () => {
		const records = pax({ size: '1' });
		await expect(
			sourceTrees(await tarballOf(header('x', 'x', records.length), records, ...file('a', 'x'))),
		).rejects.toThrow('a PAX record "size"');
	});

	test('a symlink with data, and data after the end of the archive', async () => {
		await expect(sourceTrees(await tarballOf(header('l', '2', 1, 'a'), 'x'))).rejects.toThrow(
			'"l" is a symlink with data',
		);
		const tail = [...file('a', 'x'), new Uint8Array(512), ...file('b', 'y')];
		await expect(sourceTrees(await tarballOf(...tail))).rejects.toThrow(
			'the archive has data after its end',
		);
	});

	test('more entries or bytes than unpacking takes', async () => {
		const two = await tarballOf(...file('a', 'x'), ...file('b', 'y'));
		await expect(sourceTrees(two, { entries: 1, bytes: 100 })).rejects.toThrow(
			'more than 1 files and directories',
		);
		await expect(sourceTrees(two, { entries: 10, bytes: 1 })).rejects.toThrow(
			'unpacks to more than 1 bytes',
		);
	});

	test('reads a PAX path, and names a tree a hand-made archive gives', async () => {
		const records = pax({ path: 'renamed.txt', mtime: '1' });
		const out = await sourceTrees(
			await tarballOf(header('x', 'x', records.length), records, ...file('ignored', 'hi\n')),
		);
		// git mktree of one file renamed.txt holding "hi\n".
		const dir = await mkdtemp(join(tmpdir(), 'koi-hand-git-'));
		await exec(['git', 'init', '-q', '--bare', dir]);
		const blob = (
			await exec(['git', 'hash-object', '-w', '--stdin'], { stdin: 'hi\n', env: { GIT_DIR: dir } })
		).stdout.trim();
		const tree = (
			await exec(['git', 'mktree'], {
				stdin: `100644 blob ${blob}\trenamed.txt\n`,
				env: { GIT_DIR: dir },
			})
		).stdout.trim();
		expect(out).toEqual({ tree });
	});
});
