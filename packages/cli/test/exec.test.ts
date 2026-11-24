import { describe, expect, test } from 'bun:test';
import {
	commandName,
	ExecError,
	exec,
	execOk,
	FULL_OUTPUT,
	killRunning,
	OutputTooLargeError,
	PIPE_GRACE_MS,
	SpawnError,
} from '../src/exec.ts';

// Whether a process is still running, waiting up to two seconds for one
// that was just killed to be reaped.
async function running(pid: number): Promise<boolean> {
	for (let i = 0; i < 20; i++) {
		try {
			process.kill(pid, 0);
		} catch {
			return false;
		}
		await Bun.sleep(100);
	}
	return true;
}

// `seq 1 100000` writes 588,895 bytes, more than the default 256 KiB.
const BIG = ['seq', '1', '100000'];

describe('exec', () => {
	test('keeps the whole stdout, start included, up to maxBytes', async () => {
		const r = await exec(BIG, { maxBytes: FULL_OUTPUT });
		expect(r.code).toBe(0);
		expect(r.stdout.length).toBe(588_895);
		expect(r.stdout.startsWith('1\n2\n3\n')).toBe(true);
		expect(r.stdout.endsWith('\n99999\n100000\n')).toBe(true);
	});

	test('refuses stdout past the limit instead of keeping part of it', async () => {
		await expect(exec(BIG)).rejects.toBeInstanceOf(OutputTooLargeError);
		await expect(exec(BIG, { maxBytes: 1000 })).rejects.toThrow(/more than 1000 bytes/);
	});

	test('says which program it could not start', async () => {
		for (const program of ['/nonexistent/koi-gh', 'koi-no-such-program']) {
			const err = await exec([program, 'pr']).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(SpawnError);
			expect((err as Error).message).toStartWith(`cannot run ${program}: `);
		}
	});

	test('names a command that ran out of time, and its limit', async () => {
		const err = await execOk(['sleep', '600'], { timeoutMs: 100 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ExecError);
		expect((err as Error).message).toBe('sleep did not finish within 0.1 seconds');
		expect(commandName(['git', '-C', '/repo', '-c', 'a=b', 'fetch', '--quiet', 'origin'])).toBe(
			'git fetch',
		);
		expect(
			commandName(['git', '-C', '/repo', '--attr-source=abc', 'merge-tree', '--write-tree']),
		).toBe('git merge-tree');
		expect(commandName(['gh', 'pr', 'view', '7', '--repo', 'acme/hello'])).toBe('gh pr view');
		expect(commandName(['gh', 'api', '--paginate', 'repos/acme/hello'])).toBe('gh api');
	});

	test('sets the variables it is given, and removes the ones given as undefined', async () => {
		expect(process.env.HOME).toBeDefined();
		const r = await execOk(['env'], { env: { HOME: undefined, KOI_EXEC_TEST: 'set' } });
		const names = r.stdout.split('\n').map((line) => line.split('=')[0]);
		expect(names).toContain('KOI_EXEC_TEST');
		expect(names).not.toContain('HOME');
		expect(r.stdout).toContain('KOI_EXEC_TEST=set\n');
	});

	test('reports the end of stderr when a command fails', async () => {
		const err = await execOk(['git', 'no-such-command']).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ExecError);
		expect((err as Error).message).toContain('no-such-command');
	});

	test('kills what a program started along with it when it runs out of time', async () => {
		// sh starts a sleep that keeps sh's stdout and stderr open, and
		// prints its pid. Killing sh alone would leave exec waiting on them.
		const started = performance.now();
		const r = await exec(['sh', '-c', 'sleep 600 & echo $!; wait'], { timeoutMs: 300 });
		expect(r.timedOut).toBe(true);
		expect(performance.now() - started).toBeLessThan(PIPE_GRACE_MS);
		const pid = Number(r.stdout.trim());
		expect(pid).toBeGreaterThan(0);
		expect(await running(pid)).toBe(false);
	}, 10_000);

	test.skipIf(Bun.which('setsid') === null)(
		'stops waiting for output a process outside the group holds open, after a grace',
		async () => {
			// The sleep left sh's process group, so killing the group misses it,
			// and it holds the pipes open until it ends.
			const escaped = "setsid sh -c 'echo $$; exec sleep 600' & sleep 600";
			const started = performance.now();
			const r = await exec(['sh', '-c', escaped], { timeoutMs: 300 });
			const waited = performance.now() - started;
			const pid = Number(r.stdout.trim());
			try {
				expect(r.timedOut).toBe(true);
				expect(waited).toBeGreaterThanOrEqual(300 + PIPE_GRACE_MS - 50);
				expect(waited).toBeLessThan(300 + PIPE_GRACE_MS + 3_000);
				expect(pid).toBeGreaterThan(0);
			} finally {
				if (pid > 0) process.kill(pid, 'SIGKILL');
			}
		},
		10_000,
	);

	test('killRunning ends the programs exec is running', async () => {
		const pending = exec(['sh', '-c', 'sleep 600 & echo $!; wait']);
		await Bun.sleep(200);
		killRunning();
		const r = await pending;
		expect(r.code).not.toBe(0);
		expect(await running(Number(r.stdout.trim()))).toBe(false);
	}, 10_000);
});
