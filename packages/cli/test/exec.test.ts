import { describe, expect, test } from 'bun:test';
import {
	commandName,
	ExecError,
	exec,
	execOk,
	FULL_OUTPUT,
	OutputTooLargeError,
	SpawnError,
} from '../src/exec.ts';

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
		expect(commandName(['gh', 'pr', 'view', '7', '--repo', 'acme/hello'])).toBe('gh pr view');
		expect(commandName(['gh', 'api', '--paginate', 'repos/acme/hello'])).toBe('gh api');
	});

	test('reports the end of stderr when a command fails', async () => {
		const err = await execOk(['git', 'no-such-command']).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ExecError);
		expect((err as Error).message).toContain('no-such-command');
	});
});
