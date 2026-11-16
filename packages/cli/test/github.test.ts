import { describe, expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type ExecOptions, type ExecResult, exec, FULL_OUTPUT } from '../src/exec.ts';
import {
	commentBody,
	commentMarker,
	GH_TIMEOUT_MS,
	GhMissingError,
	ghCli,
	ownerRepoFor,
} from '../src/github.ts';

interface FakeComment {
	id: number;
	body: string;
	html_url: string;
	user: { login: string } | null;
}

// gh as koi-bot: who is signed in, the comment list, and a reply to any write.
function fakeRun(comments: FakeComment[]) {
	const calls: string[][] = [];
	const options: Array<ExecOptions | undefined> = [];
	const run = async (cmd: string[], opts?: ExecOptions): Promise<ExecResult> => {
		calls.push(cmd);
		options.push(opts);
		const ok = (stdout: string) => ({ code: 0, stdout, stderr: '', timedOut: false });
		if (cmd[2] === 'user') return ok('koi-bot\n');
		if (cmd.includes('--paginate')) return ok(JSON.stringify([comments]));
		return ok(
			JSON.stringify({
				id: 9,
				body: '',
				html_url: 'https://x/comment',
				user: { login: 'koi-bot' },
			}),
		);
	};
	const write = () => calls.find((c) => c.includes('--method')) ?? [];
	return { run, calls, options, write };
}

const me = { login: 'koi-bot' };
const someoneElse = { login: 'mallory' };

describe('upsertComment', () => {
	test('edits our own comment that starts with the marker', async () => {
		const marker = commentMarker('hello-pr-7');
		const f = fakeRun([
			{ id: 1, body: 'unrelated', html_url: 'u1', user: me },
			{ id: 2, body: `${marker}\nold`, html_url: 'u2', user: me },
		]);
		await ghCli('acme/hello', f.run).upsertComment(7, marker, 'new body');
		expect(f.calls[0]).toEqual(['gh', 'api', 'user', '--jq', '.login']);
		expect(f.write()).toContain('PATCH');
		expect(f.write()).toContain('repos/acme/hello/issues/comments/2');
		expect(f.write()).toContain('body=new body');
	});

	test('finds the marker on a first line that ends in CRLF', async () => {
		const marker = commentMarker('hello-pr-7');
		const f = fakeRun([{ id: 2, body: `${marker}\r\nold`, html_url: 'u2', user: me }]);
		await ghCli('acme/hello', f.run).upsertComment(7, marker, 'b');
		expect(f.write()).toContain('repos/acme/hello/issues/comments/2');
	});

	test("leaves someone else's comment alone even when it starts with the marker", async () => {
		const marker = commentMarker('hello-pr-7');
		const f = fakeRun([
			{ id: 3, body: `${marker}\nfake preview link`, html_url: 'u3', user: someoneElse },
			{ id: 4, body: `${marker}\nghost`, html_url: 'u4', user: null },
		]);
		await ghCli('acme/hello', f.run).upsertComment(7, marker, 'b');
		expect(f.write()).toContain('POST');
		expect(f.write()).toContain('repos/acme/hello/issues/7/comments');
	});

	test('leaves our own comment alone when it only quotes the marker', async () => {
		const marker = commentMarker('hello-pr-7');
		const f = fakeRun([
			{ id: 5, body: `why does the preview say\n> ${marker}\n?`, html_url: 'u5', user: me },
			{ id: 6, body: ` ${marker}\nindented`, html_url: 'u6', user: me },
		]);
		await ghCli('acme/hello', f.run).upsertComment(7, marker, 'b');
		expect(f.write()).toContain('POST');
	});

	test('accepts gh api output of any length rather than the default cap', async () => {
		const f = fakeRun([]);
		await ghCli('acme/hello', f.run).upsertComment(7, commentMarker('hello-pr-7'), 'b');
		expect(f.options.length).toBeGreaterThan(0);
		for (const o of f.options) expect(o?.maxBytes).toBe(FULL_OUTPUT);
	});

	test('refuses a comment list that is not what GitHub sends, writing nothing', async () => {
		const marker = commentMarker('hello-pr-7');
		const f = fakeRun([
			{ id: '2' as unknown as number, body: `${marker}\nold`, html_url: 'u2', user: me },
		]);
		const err = await ghCli('acme/hello', f.run)
			.upsertComment(7, marker, 'b')
			.catch((e: unknown) => e);
		expect(err).toBeInstanceOf(Error);
		expect(f.write()).toEqual([]);
	});

	test('stops when a gh api call fails', async () => {
		const run = async (cmd: string[]): Promise<ExecResult> => ({
			code: 4,
			stdout: '',
			stderr: `gh: To get started with GitHub CLI, please run: gh auth login (${cmd[2]})`,
			timedOut: false,
		});
		await expect(
			ghCli('acme/hello', run).upsertComment(7, commentMarker('hello-pr-7'), 'b'),
		).rejects.toThrow(/gh auth login \(user\)/);
	});

	test('creates one when none has the marker', async () => {
		const f = fakeRun([{ id: 1, body: 'unrelated', html_url: 'u1', user: me }]);
		await ghCli('acme/hello', f.run).upsertComment(7, commentMarker('hello-pr-7'), 'b');
		expect(f.write()).toContain('POST');
		expect(f.write()).toContain('repos/acme/hello/issues/7/comments');
	});
});

describe('pullRequestFiles', () => {
	// gh as a program that prints `stdout`, run through the real exec with the
	// options pullRequestFiles passes, so exec's output limit applies.
	async function ghPrinting(stdout: string) {
		const file = join(await mkdtemp(join(tmpdir(), 'koi-gh-')), 'out');
		await writeFile(file, stdout);
		const calls: string[][] = [];
		const run = (cmd: string[], opts?: ExecOptions) => {
			calls.push(cmd);
			return exec(['cat', file], opts);
		};
		return { run, calls };
	}

	test("lists every file of a pull request whose listing passes exec's default limit", async () => {
		const names = Array.from(
			{ length: 3000 },
			(_, i) => `src/modules/module_${i}/${'deeply/nested/'.repeat(6)}file_${i}.py`,
		);
		const listing = `${names.join('\n')}\n`;
		expect(listing.length).toBeGreaterThan(256 * 1024);
		const gh = await ghPrinting(listing);
		expect(await ghCli('acme/hello', gh.run).pullRequestFiles(7)).toEqual(names);
		expect(gh.calls).toEqual([
			['gh', 'api', '--paginate', '--jq', '.[].filename', 'repos/acme/hello/pulls/7/files'],
		]);
	});

	test('throws when gh cannot list the files', async () => {
		const run = (_cmd: string[], opts?: ExecOptions) =>
			exec(['sh', '-c', 'echo "gh: Not Found (HTTP 404)" >&2; exit 1'], opts);
		await expect(ghCli('acme/hello', run).pullRequestFiles(7)).rejects.toThrow(/Not Found/);
	});
});

describe('pullRequestBranches', () => {
	// gh pr view printing `stdout` and exiting with `code`.
	function prView(code: number, stdout: string) {
		const calls: string[][] = [];
		const run = async (cmd: string[]): Promise<ExecResult> => {
			calls.push(cmd);
			return { code, stdout, stderr: code === 0 ? '' : 'no pull requests found', timedOut: false };
		};
		return { run, calls };
	}

	test("asks gh for the pull request's head and base branches", async () => {
		const f = prView(
			0,
			'{"headRefName":"feature/from-pr","baseRefName":"develop","headRefOid":"abc123"}\n',
		);
		expect(await ghCli('acme/hello', f.run).pullRequestBranches(7)).toEqual({
			head: 'feature/from-pr',
			base: 'develop',
			headOid: 'abc123',
		});
		expect(f.calls).toEqual([
			[
				'gh',
				'pr',
				'view',
				'7',
				'--repo',
				'acme/hello',
				'--json',
				'headRefName,baseRefName,headRefOid',
			],
		]);
	});

	test('throws what gh said when it fails, and names only the branches gh names', async () => {
		await expect(ghCli('acme/hello', prView(1, '').run).pullRequestBranches(7)).rejects.toThrow(
			'gh pr view exited 1: no pull requests found',
		);
		const empty = prView(0, '{"headRefName":"","baseRefName":"main"}\n');
		expect(await ghCli('acme/hello', empty.run).pullRequestBranches(7)).toEqual({
			head: undefined,
			base: 'main',
			headOid: undefined,
		});
	});

	test('refuses a reply that is not what gh prints', async () => {
		const f = prView(0, '{"headRefName":7,"baseRefName":"main"}\n');
		await expect(ghCli('acme/hello', f.run).pullRequestBranches(7)).rejects.toThrow();
		const short = prView(0, '{"headRefName":"feature/from-pr"}\n');
		await expect(ghCli('acme/hello', short.run).pullRequestBranches(7)).rejects.toThrow();
	});
});

describe('without gh installed', () => {
	// The real exec, on a machine where gh is not there.
	const noGh = (cmd: string[], options?: ExecOptions) =>
		exec(['/nonexistent/gh', ...cmd.slice(1)], options);

	test('both calls say gh is missing and where to get it', async () => {
		const g = ghCli('acme/hello', noGh);
		for (const call of [g.pullRequestBranches(7), g.upsertComment(7, 'm', 'b')]) {
			const err = await call.catch((e: unknown) => e);
			expect(err).toBeInstanceOf(GhMissingError);
			expect((err as Error).message).toStartWith(
				'the GitHub CLI (gh) is not installed or cannot be started (cannot run /nonexistent/gh: ',
			);
			expect((err as Error).message).toContain('https://cli.github.com');
		}
	});
});

describe('a gh that does not finish', () => {
	test('each call gives up after 2 minutes, saying which', async () => {
		const limits: Array<number | undefined> = [];
		// gh never exits. exec still stops it, at a limit short enough for a test.
		const hanging = (_cmd: string[], options?: ExecOptions) => {
			limits.push(options?.timeoutMs);
			return exec(['sleep', '600'], { ...options, timeoutMs: 200 });
		};
		const g = ghCli('acme/hello', hanging);
		await expect(g.pullRequestBranches(7)).rejects.toThrow(
			/^gh pr view did not finish within 2 minutes$/,
		);
		await expect(g.upsertComment(7, 'm', 'b')).rejects.toThrow(
			/^gh api user did not finish within 2 minutes$/,
		);
		expect(limits).toEqual([GH_TIMEOUT_MS, GH_TIMEOUT_MS]);
		expect(GH_TIMEOUT_MS).toBe(2 * 60_000);
	});
});

describe('commentBody', () => {
	const built = '#7 (abcdef1) merged into main (1234567), merge commit 89abcde';

	test('links the preview when it is running, saying what was built', () => {
		const body = commentBody({
			label: 'hello-pr-7',
			url: 'https://hello-pr-7.previews.example.net',
			built,
			status: 'running',
			keysUrl: 'https://keys.previews.example.net',
		});
		expect(body.startsWith('<!-- koi-preview:hello-pr-7 -->')).toBe(true);
		expect(body).toContain('**Preview:** https://hello-pr-7.previews.example.net');
		expect(body).toContain(
			'Built from #7 (abcdef1) merged into main (1234567), merge commit 89abcde. The first visit',
		);
	});

	test("includes the login key and points at the preview's keys page", () => {
		const body = commentBody({
			label: 'storefront-pr-7',
			url: 'https://storefront-pr-7.example.dev',
			built,
			status: 'running',
			loginKey: 'koi-abcdefghijklmnopqrstuvwx',
			keysUrl: 'https://keys.example.dev/?for=storefront-pr-7',
		});
		expect(body).toContain('**Login key:** `koi-abcdefghijklmnopqrstuvwx`');
		expect(body).toContain('open https://keys.example.dev/?for=storefront-pr-7,');
		expect(body).toContain('The tokens work only in this preview');
		expect(body).not.toContain('previews.example.net');
	});

	test('says the build failed without pasting the error into the pull request', () => {
		const body = commentBody({
			label: 'hello-pr-7',
			url: 'https://hello-pr-7.previews.example.net',
			built,
			status: 'failed',
			error: 'npm ERR! token=secret',
			keysUrl: 'https://keys.previews.example.net',
		});
		expect(body).toContain(
			'**Preview build failed** for #7 (abcdef1) merged into main (1234567), merge commit 89abcde.',
		);
		expect(body).not.toContain('secret');
	});
});

describe('ownerRepoFor', () => {
	test('only GitHub repositories', () => {
		expect(ownerRepoFor('github.com/acme/hello')).toBe('acme/hello');
		expect(() => ownerRepoFor('gitlab.com/acme/hello')).toThrow(/GitHub/);
	});
});
