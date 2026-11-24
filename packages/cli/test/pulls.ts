import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type ExecOptions, type ExecResult, exec, execOk } from '../src/exec.ts';

// A bare repository standing in for GitHub, holding pull requests the way
// GitHub keeps them, and a clone of it as the user's checkout:
//
//   main      init, then "base moved" (base), which adds base.txt
//   #7        refs/pull/7/head is init plus pr.txt (head7); refs/pull/7/merge
//             is a real merge of it into base (merge7)
//   #8        refs/pull/8/head changes base.txt as main does, so it conflicts
//             with main and has no refs/pull/8/merge
//   #90       refs/pull/90/head only, so that a fetch of #9 must not take it
//
// The clone has main only. Fetching a pull request brings its commits over
// the file:// transport, as from a real remote. `author` runs git in the
// repository the fixture was made in (`authorDir`), and `commit` commits a
// file there on whatever is checked out, as GitHub's side of a test moves
// a branch or remakes a merge.
export async function pullRequestOrigin() {
	const author = await mkdtemp(join(tmpdir(), 'koi-author-'));
	const git = async (...args: string[]) =>
		(
			await execOk([
				'git',
				'-C',
				author,
				'-c',
				'user.email=t@example.com',
				'-c',
				'user.name=t',
				...args,
			])
		).stdout.trim();
	const commit = async (file: string, text: string, message: string) => {
		await writeFile(join(author, file), text);
		await git('add', file);
		await git('commit', '-q', '-m', message);
		return git('rev-parse', 'HEAD');
	};
	await git('init', '-q', '-b', 'main');
	await writeFile(join(author, 'Dockerfile'), 'FROM scratch\n');
	const init = await commit('koi.yaml', 'port: 8080\nbuild:\n  kind: dockerfile\n', 'init');
	await git('checkout', '-q', '-b', 'feature');
	const head7 = await commit('pr.txt', 'seven\n', 'pull request 7');
	await git('checkout', '-q', 'main');
	const base = await commit('base.txt', 'base moved\n', 'base moved');
	await git('checkout', '-q', '--detach', base);
	await git('merge', '-q', '--no-ff', '-m', `Merge ${head7} into ${base}`, head7);
	const merge7 = await git('rev-parse', 'HEAD');
	await git('checkout', '-q', '-b', 'conflict', init);
	const head8 = await commit('base.txt', 'something else\n', 'pull request 8');
	await git('checkout', '-q', '-b', 'ninety', init);
	const head90 = await commit('ninety.txt', '90\n', 'pull request 90');

	const origin = await mkdtemp(join(tmpdir(), 'koi-origin-'));
	await execOk(['git', 'init', '-q', '--bare', origin]);
	await git(
		'push',
		'-q',
		origin,
		`${base}:refs/heads/main`,
		`${head7}:refs/pull/7/head`,
		`${merge7}:refs/pull/7/merge`,
		`${head8}:refs/pull/8/head`,
		`${head90}:refs/pull/90/head`,
	);
	const user = join(await mkdtemp(join(tmpdir(), 'koi-user-')), 'checkout');
	await execOk(['git', 'clone', '-q', `file://${origin}`, user]);
	const userGit = async (...args: string[]) =>
		(
			await execOk([
				'git',
				'-C',
				user,
				'-c',
				'user.email=t@example.com',
				'-c',
				'user.name=t',
				...args,
			])
		).stdout.trim();
	return {
		author: git,
		authorDir: author,
		commit,
		origin,
		user,
		userGit,
		init,
		base,
		head7,
		merge7,
		head8,
		head90,
	};
}

// A checkout of one ref of `origin` as actions/checkout makes one by default:
// a depth-one clone, then a depth-one fetch of the ref, checked out. The
// commit checked out is the shallow boundary, so its parents are not in the
// repository and git's history walkers show it with none.
export async function shallowCheckout(origin: string, ref: string): Promise<string> {
	const dir = join(await mkdtemp(join(tmpdir(), 'koi-shallow-')), 'checkout');
	await execOk(['git', 'clone', '-q', '--depth', '1', `file://${origin}`, dir]);
	const git = (...args: string[]) => execOk(['git', '-C', dir, ...args]);
	await git('fetch', '-q', '--depth', '1', 'origin', `+${ref}:refs/remotes/origin/checkout`);
	await git('checkout', '-q', '--force', 'refs/remotes/origin/checkout');
	return dir;
}

// exec, except that git names origin as GitHub would: the clone's real
// origin is a local path, which koi cannot read a repository id from.
export function asGitHub(url = 'https://github.com/acme/hello.git') {
	return (cmd: string[], options?: ExecOptions): Promise<ExecResult> =>
		cmd[0] === 'git' && cmd.includes('get-url')
			? Promise.resolve({ code: 0, stdout: `${url}\n`, stderr: '', timedOut: false })
			: exec(cmd, options);
}
