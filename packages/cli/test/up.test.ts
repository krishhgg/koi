import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deploymentIdentity, type PreviewRecord, type UpRequest, type UpResult } from '@koi/shared';
import { type BuildLog, BuildLogs } from '../../daemon/src/buildlog.ts';
import { awsBox, type Box, BoxUnavailableError, type CtlResult } from '../src/box.ts';
import {
	type ExecOptions,
	type ExecResult,
	exec,
	execOk,
	OutputTooLargeError,
} from '../src/exec.ts';
import { cliGit, type Git } from '../src/git.ts';
import type { GitHub, PullRequestMergeState } from '../src/github.ts';
import { ghCli, ownerRepoFor } from '../src/github.ts';
import {
	builtFrom,
	MERGE_INPUT_TRIES,
	MERGE_POLL_MS,
	MERGE_WAIT_MS,
	type UpDeps,
	up,
} from '../src/up.ts';
import { koidClients, koidDeps, previewRecord, s3Stub, settings } from './koid.ts';
import { asGitHub, pullRequestOrigin, shallowCheckout } from './pulls.ts';

const COMMIT = 'c'.repeat(40);
// A pull request as fakeGit fetches it: its head, and GitHub's merge of that
// head into the base.
const PR_HEAD = 'd'.repeat(40);
const PR_BASE = 'e'.repeat(40);
const PR_MERGE = 'f'.repeat(40);

// gh's mergeability check, for a pull request whose merge is current or not
// built: koi has nothing to ask GitHub to recompute.
const notAsked = async (): Promise<PullRequestMergeState> => {
	throw new Error('koi asked GitHub to recompute a merge that is current');
};

async function fakeGit(
	overrides: Partial<Git> = {},
): Promise<Git & { root: () => Promise<string> }> {
	const root = await mkdtemp(join(tmpdir(), 'koi-up-'));
	await writeFile(join(root, 'Dockerfile'), 'FROM scratch\n');
	await writeFile(join(root, 'koi.yaml'), 'port: 8080\nbuild:\n  kind: dockerfile\n');
	return {
		root: async () => root,
		remote: async () => 'https://github.com/acme/hello.git',
		head: async () => COMMIT,
		branch: async () => 'feature/x',
		dirty: async () => true,
		files: async () => ['Dockerfile', 'koi.yaml'],
		fetchPullRequest: async () => ({
			head: PR_HEAD,
			merge: { commit: PR_MERGE, parents: [PR_BASE, PR_HEAD] },
		}),
		remoteBranchTips: async () => new Map([['main', PR_BASE]]),
		// GitHub's merge above is current, so koi makes no merge of its own.
		fetchBranch: async () => {
			throw new Error('koi fetched the base to merge a pull request whose merge is current');
		},
		mergeCommit: async () => {
			throw new Error('koi merged a pull request whose merge is current');
		},
		archive: async (_commit, out) => {
			await exec(['tar', '-cf', out, '-C', root, 'Dockerfile']);
		},
		changedFiles: async () => ['src/payments/stripe.py', 'README.md'],
		diffFiles: async () => ['src/payments/stripe.py'],
		mergeFiles: async () => ['src/payments/stripe.py'],
		show: async (_commit, path) =>
			path === 'koi.yaml' ? 'port: 9000\nbuild:\n  kind: dockerfile\n' : undefined,
		...overrides,
	};
}

function record(over: Partial<PreviewRecord>): PreviewRecord {
	return {
		label: 'hello-pr-7',
		project: 'hello',
		repo: 'github.com/acme/hello',
		status: 'building',
		commit: COMMIT,
		branch: 'feature/x',
		dirty: false,
		requestId: 'r'.repeat(16),
		attempt: 't'.repeat(20),
		ttlDays: 7,
		createdAt: '2026-10-06T00:00:00.000Z',
		updatedAt: '2026-10-06T00:00:00.000Z',
		...over,
	};
}

// A box whose status answers come from a script: per poll, the record and the
// whole build log of the record's attempt at that moment. Replies page the log
// as koid does, at most 200 lines from `since`, and only for the record's
// attempt. koid's `next` is a byte offset; koi only passes it back, so a line
// count stands in for it here.
function fakeBox(statuses: Array<{ record: PreviewRecord; log: string[] }>, upReply?: CtlResult) {
	const uploads: UpRequest[] = [];
	const tarballs: string[][] = [];
	const calls: string[][] = [];
	let woke = 0;
	const box: Box = {
		upload: async (request, tarball) => {
			uploads.push(request);
			const listed = await exec(['tar', '-tzf', tarball]);
			tarballs.push(
				listed.stdout
					.split('\n')
					.filter((l) => l !== '')
					.sort(),
			);
			const changed = await exec(['tar', '-xzOf', tarball, '.koi-runtime/changed-files.txt']);
			tarballs.push([`changed:${changed.stdout.trim()}`]);
		},
		ensureAwake: async () => {
			woke += 1;
		},
		ctl: async (args) => {
			calls.push(args);
			if (args[0] === 'up')
				return upReply ?? { code: 0, stdout: '{"label":"x","queued":false}', stderr: '' };
			const now = (statuses.length > 1 ? statuses.shift() : statuses[0]) as {
				record: PreviewRecord;
				log: string[];
			};
			const { deployment: _deployment, ...record } = now.record;
			const deployment = deploymentIdentity(now.record);
			const since = Number(args[3] ?? 0);
			const lines = args[2] === record.attempt ? now.log.slice(since, since + 200) : [];
			const next = since + lines.length;
			return {
				code: 0,
				stdout: JSON.stringify({
					record,
					log: { next, lines },
					...(deployment !== undefined ? { deployment } : {}),
				}),
				stderr: '',
			};
		},
	};
	return { box, uploads, tarballs, calls, woke: () => woke };
}

function deps(git: Git, box: Box, extra: Partial<UpDeps> = {}) {
	const lines: string[] = [];
	const progress: string[] = [];
	let clock = 0;
	const d: UpDeps = {
		git,
		box,
		domain: 'previews.example.net',
		builtins: [],
		github: () => {
			throw new Error('no github in this test');
		},
		ownerRepo: ownerRepoFor,
		progress: (m) => progress.push(m),
		buildLine: (l) => lines.push(l),
		randomId: () => 'r'.repeat(16),
		now: () => new Date(clock),
		clock: () => clock,
		sleep: async (ms) => {
			clock += ms;
		},
		...extra,
	};
	return { d, lines, progress, clock: () => clock };
}

// koid as koi up meets it on the box, while it builds one request.
interface Koid {
	logs: BuildLogs;
	// The request's label and id, once koi up has uploaded it.
	label: string;
	id: string;
	record: PreviewRecord | undefined;
	// Writes an attempt's whole build log.
	write(attempt: string, lines: string[]): Promise<void>;
}

// Runs koi up through awsBox against the real koid ctl, control API and
// build logs behind a mocked SSM client. `accept` runs when koid accepts the
// request, and `beforeRead` before koid reads a build log for a status reply,
// with the number of that read.
async function upThroughKoid(
	accept: (koid: Koid) => Promise<void>,
	beforeRead: (koid: Koid, read: number) => Promise<void> = async () => {},
) {
	const logs = new BuildLogs(await mkdtemp(join(tmpdir(), 'koi-state-')));
	const koid: Koid = {
		logs,
		label: '',
		id: '',
		record: undefined,
		async write(attempt, lines) {
			const log = await logs.open(koid.label, attempt);
			for (const line of lines) log.line(line);
			await log.close();
		},
	};
	let reads = 0;
	let touches = 0;
	const clients = koidClients(
		koidDeps({
			keepAwake: async () => {
				touches += 1;
			},
			deployer: {
				...koidDeps({}).deployer,
				up: async () => {
					await accept(koid);
					return { label: koid.label, queued: false };
				},
				down: async () => false,
			},
			store: { get: async () => koid.record, list: async () => [] },
			buildLogs: {
				read: async (...args) => {
					reads += 1;
					await beforeRead(koid, reads);
					return logs.read(...args);
				},
				tail: (...args) => logs.tail(...args),
			},
		}),
	);
	const box: Box = {
		...awsBox(settings, clients, async () => {}),
		upload: async (request) => {
			koid.label = request.label;
			koid.id = request.id;
		},
	};
	const { d, lines, progress } = deps(await fakeGit(), box);
	let result: UpResult | undefined;
	let error: Error | undefined;
	try {
		result = await up({ comment: false }, d);
	} catch (err) {
		error = err as Error;
	}
	return {
		result,
		error,
		label: koid.label,
		// Without the timestamp koid writes before each line.
		lines: lines.map((line) => line.replace(/^\S+ /, '')),
		progress,
		polls: clients.commands.filter((c) => c[0] === 'status'),
		commands: clients.commands.length,
		// Times koid refreshed the activity stamp.
		touches,
	};
}

describe('up from the working tree', () => {
	test('uploads a request for the branch, then follows the build to running', async () => {
		const git = await fakeGit();
		const label = 'hello-feature-x-';
		const fb = fakeBox([
			// Until its build starts, the request has no log.
			{ record: record({ status: 'queued' }), log: [] },
			{ record: record({ status: 'building' }), log: ['a', 'b'] },
			{ record: record({ status: 'building' }), log: ['a', 'b'] },
			{ record: record({ status: 'running' }), log: ['a', 'b', 'c', 'ready'] },
		]);
		const { d, lines } = deps(git, fb.box);
		const result = await up({ comment: false }, d);
		const request = fb.uploads[0];
		expect(request?.label.startsWith(label)).toBe(true);
		expect(request?.dirty).toBe(true);
		expect(request?.commit).toBe(COMMIT);
		expect(request?.recipe).toEqual({
			kind: 'repo',
			recipe: expect.objectContaining({ port: 8080 }),
		});
		expect(fb.woke()).toBe(1);
		expect(fb.calls[0]).toEqual(['up', 'r'.repeat(16)]);
		expect(fb.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'Dockerfile',
			'koi.yaml',
		]);
		expect(fb.tarballs[1]).toEqual(['changed:src/payments/stripe.py\nREADME.md']);
		// The first poll learns the attempt. Its log is read from where the last
		// page ended, and once more after the build finished, until a page comes
		// back empty.
		const name = request?.label ?? '';
		expect(fb.calls.slice(1)).toEqual([
			['status', name],
			...['0', '2', '2', '4'].map((since) => ['status', name, 't'.repeat(20), since]),
		]);
		expect(lines).toEqual(['a', 'b', 'c', 'ready']);
		expect(result).toEqual({
			schemaVersion: 1,
			label: request?.label ?? '',
			url: `https://${request?.label}.previews.example.net`,
			status: 'running',
			commit: COMMIT,
			keysUrl: `https://keys.previews.example.net/?for=${request?.label}`,
		});
	});

	test('returns the identity of the deployment serving when the build ends', async () => {
		const git = await fakeGit();
		const deployment = {
			requestId: 'r'.repeat(16),
			deploymentId: 't'.repeat(20),
			imageDigest: `sha256:${'1'.repeat(64)}`,
			commit: COMMIT,
			image: 'koi-preview/hello:r',
			container: 'koi-hello-r',
			port: 8080,
			healthPath: '/',
			healthTimeoutSeconds: 60,
			user: '65534:65534',
			env: {},
			deployedAt: '2026-10-06T00:00:00.000Z',
		};
		const fb = fakeBox([{ record: record({ status: 'running', deployment }), log: [] }]);
		const result = await up({ comment: false }, deps(git, fb.box).d);
		// The fake's record keeps its own label, whatever was uploaded.
		expect(result.deployment).toEqual({
			label: 'hello-pr-7',
			deploymentId: 't'.repeat(20),
			imageDigest: `sha256:${'1'.repeat(64)}`,
			commit: COMMIT,
		});
		// After a failed build the previous deployment serves, and is named.
		const failed = fakeBox([
			{
				record: record({
					status: 'failed',
					error: 'RUN npm ci failed',
					deployment: { ...deployment, requestId: 'p'.repeat(16), commit: 'b'.repeat(40) },
				}),
				log: [],
			},
		]);
		const after = await up({ comment: false }, deps(git, failed.box).d);
		expect(after.status).toBe('failed');
		expect(after.deployment?.commit).toBe('b'.repeat(40));
		// Nothing serves: no identity.
		const none = fakeBox([{ record: record({ status: 'failed', error: 'x' }), log: [] }]);
		expect((await up({ comment: false }, deps(git, none.box).d)).deployment).toBeUndefined();
	});

	test('returns the preview login key when the record has one', async () => {
		const git = await fakeGit();
		const fb = fakeBox([
			{
				record: record({ status: 'running', loginKey: 'koi-abcdefghijklmnopqrstuvwx' }),
				log: [],
			},
		]);
		const result = await up({ comment: false }, deps(git, fb.box).d);
		expect(result.loginKey).toBe('koi-abcdefghijklmnopqrstuvwx');
	});

	test('reports a failed build with its reason', async () => {
		const git = await fakeGit();
		const fb = fakeBox([
			{ record: record({ status: 'failed', error: 'RUN npm ci failed' }), log: ['x'] },
		]);
		const result = await up({ comment: false }, deps(git, fb.box).d);
		expect(result.status).toBe('failed');
		expect(result.error).toBe('RUN npm ci failed');
	});

	test('shows every line of a burst longer than one status page, in order', async () => {
		const git = await fakeGit();
		const burst = Array.from({ length: 450 }, (_, i) => `step ${i + 1}`);
		const fb = fakeBox([
			{ record: record({ status: 'building' }), log: ['start'] },
			{ record: record({ status: 'building' }), log: ['start'] },
			{ record: record({ status: 'building' }), log: ['start', ...burst] },
			{ record: record({ status: 'running' }), log: ['start', ...burst, 'ready'] },
		]);
		const { d, lines } = deps(git, fb.box);
		expect((await up({ comment: false }, d)).status).toBe('running');
		expect(lines).toEqual(['start', ...burst, 'ready']);
	});

	test('shows a line again when the build prints it again', async () => {
		const git = await fakeGit();
		const fb = fakeBox([
			{ record: record({ status: 'building' }), log: ['a', 'b'] },
			{ record: record({ status: 'building' }), log: ['a', 'b'] },
			{ record: record({ status: 'running' }), log: ['a', 'b', 'c', 'b', 'd'] },
		]);
		const { d, lines } = deps(git, fb.box);
		await up({ comment: false }, d);
		expect(lines).toEqual(['a', 'b', 'c', 'b', 'd']);
	});

	test('stops at once when a newer koi up for the label replaces the request', async () => {
		const git = await fakeGit();
		const newer = 'n'.repeat(16);
		const fb = fakeBox([
			{ record: record({ status: 'building' }), log: ['a'] },
			{ record: record({ status: 'building' }), log: ['a'] },
			{
				record: record({ status: 'building', requestId: newer, attempt: 'u'.repeat(20) }),
				log: [],
			},
			{ record: record({ status: 'running', requestId: newer, attempt: 'u'.repeat(20) }), log: [] },
		]);
		const { d, lines } = deps(git, fb.box);
		const err = (await up({ comment: false }, d).catch((e: unknown) => e)) as Error;
		expect(err).toBeInstanceOf(Error);
		expect(err.message).toMatch(/^superseded by a newer koi up for hello-feature-x-[a-z]{8}$/);
		expect(lines).toEqual(['a']);
		expect(fb.calls.filter((c) => c[0] === 'status')).toHaveLength(3);
	});

	test("never shows a newer request's lines, even when it finishes mid-reply", async () => {
		// As on the box: koid loads this request's record for a status reply,
		// then a newer request for the label is accepted, builds and finishes
		// before koid reads the log.
		const mine = 'm'.repeat(20);
		const newer = 'w'.repeat(20);
		const r = await upThroughKoid(
			async (k) => {
				k.record = previewRecord({
					label: k.label,
					requestId: k.id,
					attempt: mine,
					status: 'building',
				});
				await k.write(mine, ['mine 1', 'mine 2']);
			},
			async (k, read) => {
				if (read !== 2 || k.record === undefined) return;
				await k.write(newer, ['newer 1', 'newer 2', 'newer 3', 'newer 4', 'newer 5', 'ready']);
				k.record = { ...k.record, requestId: 'n'.repeat(16), attempt: newer, status: 'running' };
			},
		);
		expect(r.error?.message).toMatch(/^superseded by a newer koi up for hello-feature-x-[a-z]{8}$/);
		expect(r.lines).toEqual(['mine 1', 'mine 2']);
		// The reply koid was making when the newer request finished still has
		// this request's record; the one after shows the newer request.
		expect(r.polls.map((c) => c.slice(0, 3))).toEqual([
			['status', r.label],
			['status', r.label, mine],
			['status', r.label, mine],
			['status', r.label, mine],
		]);
	});

	test("follows its own request built again from the start of the new attempt's log", async () => {
		// koid accepts a failed request again, and the new attempt writes a log
		// shorter than the old offset, or one where that offset falls inside a
		// character.
		const cases = [
			{
				first: ['step 1', `failed: ${'x'.repeat(3000)}`, `${'y'.repeat(3000)}`],
				second: ['short', 'ready'],
			},
			{ first: ['old'], second: ['ab😀', 'ready'] },
		];
		for (const { first, second } of cases) {
			const r = await upThroughKoid(
				async (k) => {
					k.record = previewRecord({
						label: k.label,
						requestId: k.id,
						attempt: 'f'.repeat(20),
						status: 'building',
					});
					await k.write('f'.repeat(20), first);
				},
				async (k, read) => {
					if (read !== 2 || k.record === undefined) return;
					await k.write('s'.repeat(20), second);
					k.record = { ...k.record, attempt: 's'.repeat(20), status: 'running' };
				},
			);
			expect(r.error).toBeUndefined();
			expect(r.result?.status).toBe('running');
			expect(r.lines).toEqual([...first, ...second]);
			expect(r.progress).toContain(
				'koid is building this request again; showing its new build log from the start',
			);
			const firstEnd = String(
				Buffer.byteLength(first.map((l) => `${'t'.repeat(24)} ${l}\n`).join('')),
			);
			expect(r.polls.map((c) => c.slice(2))).toEqual([
				[],
				['f'.repeat(20), '0'],
				['f'.repeat(20), firstEnd],
				['f'.repeat(20), firstEnd],
				['s'.repeat(20), '0'],
				['s'.repeat(20), expect.any(String)],
			]);
		}
	});

	test('shows a build log of many pages and line lengths exactly once, in order', async () => {
		// Lines of 7 to over 3,000 bytes, so that pages end on the 200 line
		// limit or the 12,000 character one, and byte offsets differ from line
		// counts.
		const all = Array.from({ length: 700 }, (_, i) =>
			i % 50 === 7 ? `step ${i} ${'é'.repeat(1500)}` : `step ${i} ${'é😀a'.repeat((i * 7) % 41)}`,
		);
		// What the build writes before each read of the log.
		const batches = [all.slice(0, 10), all.slice(10, 400), all.slice(400, 450), all.slice(450)];
		const attempt = 'p'.repeat(20);
		let log: BuildLog | undefined;
		const r = await upThroughKoid(
			async (k) => {
				k.record = previewRecord({ label: k.label, requestId: k.id, attempt, status: 'building' });
				log = await k.logs.open(k.label, attempt);
			},
			async (k, read) => {
				if (log === undefined || k.record === undefined) return;
				const batch = batches[read - 1];
				if (batch === undefined) return;
				for (const line of batch) log.line(line);
				if (read === batches.length) {
					log.line('ready');
					await log.close();
					k.record = { ...k.record, status: 'running' };
				} else {
					await log.flush();
				}
			},
		);
		expect(r.error).toBeUndefined();
		expect(r.result?.status).toBe('running');
		expect(r.lines).toEqual([...all, 'ready']);
		// More status replies than batches: some batches took several pages.
		expect(r.polls.length).toBeGreaterThan(batches.length + 2);
		// Each command, ping and up included, counted as activity on the box.
		expect(r.touches).toBe(r.commands);
		expect(r.commands).toBe(r.polls.length + 2);
	});

	test("keeps the project's .koi/ files in the upload", async () => {
		const git = await fakeGit({
			files: async () => ['.koi/koi.yaml', '.koi/verify.yaml', 'Dockerfile'],
		});
		const root = await git.root();
		await mkdir(join(root, '.koi'));
		await writeFile(join(root, '.koi', 'koi.yaml'), 'port: 8080\nbuild:\n  kind: dockerfile\n');
		await writeFile(join(root, '.koi', 'verify.yaml'), 'version: 1\n');
		await rm(join(root, 'koi.yaml'));
		const fb = fakeBox([{ record: record({ status: 'running' }), log: [] }]);
		await up({ comment: false }, deps(git, fb.box).d);
		expect(fb.uploads[0]?.recipe).toEqual({
			kind: 'repo',
			recipe: expect.objectContaining({ port: 8080 }),
		});
		expect(fb.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'.koi/koi.yaml',
			'.koi/verify.yaml',
			'Dockerfile',
		]);
	});

	test('refuses a working tree with a .koi-runtime/ before uploading anything', async () => {
		const git = await fakeGit({
			files: async () => ['.koi-runtime/changed-files.txt', 'Dockerfile'],
		});
		const root = await git.root();
		await mkdir(join(root, '.koi-runtime'));
		await writeFile(join(root, '.koi-runtime', 'changed-files.txt'), 'forged\n');
		const fb = fakeBox([]);
		await expect(up({ comment: false }, deps(git, fb.box).d)).rejects.toThrow(
			/\.koi-runtime\/, which koi reserves/,
		);
		expect(fb.uploads).toEqual([]);
	});

	test('refuses a working tree with an initialized submodule before uploading anything', async () => {
		const git = await fakeGit({ files: async () => ['Dockerfile', 'koi.yaml', 'vendor/lib'] });
		const root = await git.root();
		await mkdir(join(root, 'vendor', 'lib'), { recursive: true });
		await writeFile(join(root, 'vendor', 'lib', '.git'), 'gitdir: ../../.git/modules/vendor/lib\n');
		const fb = fakeBox([]);
		await expect(up({ comment: false }, deps(git, fb.box).d)).rejects.toThrow(
			/initialized submodules[\s\S]*\n {2}vendor\/lib\n/,
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});

	test('stops before asking koid anything when the upload fails', async () => {
		const clients = koidClients(koidDeps({}));
		const keys: unknown[] = [];
		const s3 = s3Stub(async (_name, input) => {
			keys.push(input.Key);
			throw Object.assign(new Error('Access Denied'), { name: 'AccessDenied' });
		});
		const box = awsBox(settings, { ...clients, s3 }, async () => {});
		const { d } = deps(await fakeGit(), box);
		await expect(up({ comment: false }, d)).rejects.toThrow('Access Denied');
		expect(keys).toEqual([`sources/${'r'.repeat(16)}.tar.gz`]);
		expect(clients.commands).toEqual([]);
	});

	test('ends failed at once when koi down removes the preview during the build', async () => {
		const r = await upThroughKoid(
			async (k) => {
				k.record = previewRecord({
					label: k.label,
					requestId: k.id,
					attempt: 'f'.repeat(20),
					status: 'building',
				});
				await k.write('f'.repeat(20), ['step 1']);
			},
			async (k, read) => {
				if (read === 2) k.record = undefined;
			},
		);
		expect(r.error).toBeUndefined();
		expect(r.result?.status).toBe('failed');
		expect(r.result?.error).toMatch(
			/^hello-feature-x-[a-z]{8} was removed by koi down while koi up waited for its build$/,
		);
		expect(r.result?.deployment).toBeUndefined();
		expect(r.lines).toEqual(['step 1']);
		expect(r.polls).toHaveLength(4);
	});

	test('stops at once on any other error koid gives', async () => {
		const git = await fakeGit();
		for (const reply of [
			{ code: 1, stdout: '', stderr: '{"error":"bad request","detail":"x"}\n' },
			{ code: 2, stdout: '', stderr: 'koid ctl: lines must be a positive integer\n' },
			{ code: 127, stdout: '', stderr: 'koid: not found\n' },
		]) {
			const fb = fakeBox([{ record: record({ status: 'building' }), log: [] }]);
			const box: Box = {
				...fb.box,
				ctl: async (args) => (args[0] === 'status' ? reply : fb.box.ctl(args)),
			};
			const err = (await up({ comment: false }, deps(git, box).d).catch(
				(e: unknown) => e,
			)) as Error;
			expect(err.message).toMatch(/^stopped following hello-feature-x-[a-z]{8}: /);
			expect(err.message).toContain(reply.code === 1 ? 'bad request' : reply.stderr.trim());
		}
	});

	test('reads the status again while SSM or koid cannot answer for a while', async () => {
		const git = await fakeGit();
		const fb = fakeBox([
			{ record: record({ status: 'building' }), log: ['a'] },
			{ record: record({ status: 'building' }), log: ['a'] },
			{ record: record({ status: 'running' }), log: ['a', 'b'] },
		]);
		let reads = 0;
		const box: Box = {
			...fb.box,
			ctl: async (args) => {
				if (args[0] !== 'status') return fb.box.ctl(args);
				reads += 1;
				if (reads === 2) throw new BoxUnavailableError('Rate exceeded');
				if (reads === 3) return { code: 3, stdout: '', stderr: 'koid ctl: cannot reach koid' };
				return fb.box.ctl(args);
			},
		};
		const { d, lines } = deps(git, box);
		expect((await up({ comment: false }, d)).status).toBe('running');
		expect(lines).toEqual(['a', 'b']);
		expect(reads).toBeGreaterThan(4);
	});

	test('gives up when the status cannot be read for 5 minutes', async () => {
		const git = await fakeGit();
		const fb = fakeBox([]);
		const box: Box = {
			...fb.box,
			ctl: async (args) =>
				args[0] === 'status'
					? { code: 3, stdout: '', stderr: 'koid ctl: cannot reach koid: ENOENT\n' }
					: fb.box.ctl(args),
		};
		const { d, clock } = deps(git, box);
		await expect(up({ comment: false }, d)).rejects.toThrow(
			/^could not read the status of hello-feature-x-[a-z]{8} for 5 minutes: koid ctl: cannot reach koid: ENOENT$/,
		);
		expect(clock()).toBeGreaterThan(5 * 60_000);
		expect(clock()).toBeLessThan(5 * 60_000 + 10_000);
	});

	test('surfaces the box refusing the request', async () => {
		const git = await fakeGit();
		const fb = fakeBox([], {
			code: 1,
			stdout: '',
			stderr: '{"error":"hello-feature-x belongs to branch main"}',
		});
		await expect(up({ comment: false }, deps(git, fb.box).d)).rejects.toThrow(
			'belongs to branch main',
		);
	});

	test("refuses an up reply that is not koid's", async () => {
		const git = await fakeGit();
		for (const stdout of ['{"label":"Not A Label","queued":false}', '{"label":"x"}', '[]']) {
			const fb = fakeBox([], { code: 0, stdout, stderr: '' });
			await expect(up({ comment: false }, deps(git, fb.box).d)).rejects.toThrow();
			expect(fb.calls.map((c) => c[0])).toEqual(['up']);
		}
	});

	test("gives up once the build has run past its recipe's limits", async () => {
		const git = await fakeGit();
		const fb = fakeBox([{ record: record({ status: 'building' }), log: [] }]);
		const { d, clock } = deps(git, fb.box);
		// The default limits, 45 minutes to build and 180 seconds to start,
		// and 15 minutes more.
		await expect(up({ comment: false }, d)).rejects.toThrow(
			/^gave up waiting for hello-feature-x-[a-z]{8} after 63 minutes of building/,
		);
		expect(clock()).toBeGreaterThan(63 * 60_000);
		expect(clock()).toBeLessThan(63 * 60_000 + 10_000);
	});

	test('a retry that starts while the failed attempt is still being read keeps the time limits', async () => {
		const git = await fakeGit();
		const failed = record({ status: 'failed', attempt: 'a'.repeat(20) });
		const retried = record({ status: 'building', attempt: 'b'.repeat(20) });
		const fb = fakeBox([
			{ record: failed, log: ['failed: boom'] },
			{ record: failed, log: ['failed: boom'] },
			{ record: retried, log: [] },
		]);
		// Without the limits koi up would poll forever; 63 minutes is about
		// 1,300 polls.
		const ctl = fb.box.ctl;
		fb.box.ctl = async (args) => {
			if (fb.calls.length > 5000) throw new Error('still polling');
			return ctl(args);
		};
		const { d, clock } = deps(git, fb.box);
		await expect(up({ comment: false }, d)).rejects.toThrow(
			/^gave up waiting for hello-feature-x-[a-z]{8} after 63 minutes of building/,
		);
		expect(clock()).toBeLessThan(63 * 60_000 + 10_000);
	});

	test('waits for a long build its recipe allows, not counting time in the queue', async () => {
		const git = await fakeGit();
		await writeFile(
			join(await git.root(), 'koi.yaml'),
			'port: 8080\nbuildTimeoutMinutes: 180\nbuild:\n  kind: dockerfile\n',
		);
		// Polls are 3 seconds apart: 5 hours in the queue, then 170 minutes of
		// building.
		const polls = (n: number, status: PreviewRecord['status']) =>
			Array.from({ length: n }, () => ({ record: record({ status }), log: [] }));
		const fb = fakeBox(
			[
				...polls(6000, 'queued'),
				...polls(3400, 'building'),
				{ record: record({ status: 'running' }), log: [] },
			],
			{ code: 0, stdout: '{"label":"hello-feature-x-abcdefgh","queued":true}', stderr: '' },
		);
		const { d, progress, clock } = deps(git, fb.box);
		expect((await up({ comment: false }, d)).status).toBe('running');
		// Longer than the queue wait, and the build alone longer than 90 minutes.
		expect(clock()).toBeGreaterThan(7 * 3_600_000);
		expect(progress).toContain(
			'waiting for another build on the box to finish; koi waits up to 6 hours for its turn',
		);
	});

	test('reads the whole log of a finished build, even past the time limit', async () => {
		const git = await fakeGit();
		const long = Array.from({ length: 10_000 }, (_, i) => `line ${i}`);
		const fb = fakeBox([
			...Array.from({ length: 100 }, () => ({ record: record({ status: 'building' }), log: [] })),
			{ record: record({ status: 'running' }), log: long },
		]);
		// Each status read takes 30 seconds, as a slow SSM round trip can.
		let clock = 0;
		const box: Box = {
			...fb.box,
			ctl: async (args) => {
				clock += 30_000;
				return fb.box.ctl(args);
			},
		};
		const { d, lines } = deps(git, box, {
			now: () => new Date(clock),
			sleep: async (ms) => {
				clock += ms;
			},
		});
		expect((await up({ comment: false }, d)).status).toBe('running');
		expect(lines).toEqual(long);
		expect(clock).toBeGreaterThan(63 * 60_000 + 60_000);
	});

	test('gives up on a queue that does not move, and says koid keeps the request', async () => {
		const git = await fakeGit();
		const fb = fakeBox([{ record: record({ status: 'queued' }), log: [] }]);
		const { d, clock } = deps(git, fb.box);
		await expect(up({ comment: false }, d)).rejects.toThrow(
			/^gave up after 6 hours waiting for hello-feature-x-[a-z]{8} to start building behind other builds on the box\. koid keeps it queued/,
		);
		expect(clock()).toBeGreaterThan(6 * 3_600_000);
		expect(clock()).toBeLessThan(6 * 3_600_000 + 10_000);
	});
});

describe('builtFrom', () => {
	test('names the pull request, the head and the base, or the commit alone', () => {
		const merge = { head: 'a'.repeat(40), base: 'b'.repeat(40), baseBranch: 'develop' };
		expect(builtFrom({ commit: 'c'.repeat(40), pr: 2518, merge })).toBe(
			'#2518 (aaaaaaa) merged into develop (bbbbbbb), merge commit ccccccc',
		);
		// Without gh, the base branch's name is unknown.
		const { baseBranch: _, ...unnamed } = merge;
		expect(builtFrom({ commit: 'c'.repeat(40), pr: 2518, merge: unnamed })).toBe(
			'#2518 (aaaaaaa) merged into its base branch (bbbbbbb), merge commit ccccccc',
		);
		expect(builtFrom({ commit: 'a'.repeat(40), pr: 2518 })).toBe(
			'#2518 (aaaaaaa), its head as pushed, not merged into its base',
		);
		expect(builtFrom({ commit: 'c'.repeat(40) })).toBe('ccccccc');
	});
});

describe('up --pr', () => {
	test('builds the pull request merged into its base, with its own koi.yaml, and comments', async () => {
		const merges: Array<[number, string]> = [];
		const git = await fakeGit({
			mergeFiles: async (pr, merge) => {
				merges.push([pr, merge]);
				return ['src/search/index.py'];
			},
		});
		const fb = fakeBox([{ record: record({ status: 'running', commit: PR_MERGE }), log: [] }]);
		const comments: Array<{ pr: number; marker: string; body: string }> = [];
		const github: GitHub = {
			pullRequestMergeState: notAsked,
			pullRequestBranches: async () => ({
				head: 'feature/from-pr',
				base: 'main',
				headOid: PR_HEAD,
			}),
			pullRequestFiles: async () => {
				throw new Error('a merge build lists its files from the merge, not from gh');
			},
			upsertComment: async (pr, marker, body) => {
				comments.push({ pr, marker, body });
				return 'https://github.com/acme/hello/pull/7#issuecomment-1';
			},
		};
		const result = await up(
			{ pr: 7, comment: true },
			deps(git, fb.box, { github: () => github }).d,
		);
		const request = fb.uploads[0];
		expect(request?.label).toBe('hello-pr-7');
		expect(request?.pr).toBe(7);
		expect(request?.branch).toBe('feature/from-pr');
		expect(request?.dirty).toBe(false);
		expect(request?.commit).toBe(PR_MERGE);
		expect(request?.merge).toEqual({ head: PR_HEAD, base: PR_BASE, baseBranch: 'main' });
		expect(request?.recipe.kind === 'repo' && request.recipe.recipe.port).toBe(9000);
		expect(fb.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'Dockerfile',
		]);
		expect(fb.tarballs[1]).toEqual(['changed:src/search/index.py']);
		expect(merges).toEqual([[7, PR_MERGE]]);
		expect(comments[0]?.marker).toBe('<!-- koi-preview:hello-pr-7 -->');
		expect(comments[0]?.body).toContain('https://hello-pr-7.previews.example.net');
		expect(comments[0]?.body).toContain(
			'Built from #7 (ddddddd) merged into main (eeeeeee), merge commit fffffff.',
		);
		expect(result.comment).toBe('https://github.com/acme/hello/pull/7#issuecomment-1');
	});

	test("refuses a pull request whose tree has a .koi-runtime/, and keeps the tree's .koi/", async () => {
		const github: GitHub = {
			pullRequestMergeState: notAsked,
			pullRequestBranches: async () => ({
				head: 'feature/from-pr',
				base: 'main',
				headOid: PR_HEAD,
			}),
			pullRequestFiles: async () => {
				throw new Error('a merge build lists its files from the merge, not from gh');
			},
			upsertComment: async () => {
				throw new Error('nothing to comment on');
			},
		};
		const git = await fakeGit({
			archive: async (_commit, out) => {
				const root = await mkdtemp(join(tmpdir(), 'koi-archive-'));
				await mkdir(join(root, '.koi-runtime'));
				await writeFile(join(root, '.koi-runtime', 'changed-files.txt'), 'forged\n');
				await writeFile(join(root, 'Dockerfile'), 'FROM scratch\n');
				await exec(['tar', '-cf', out, '-C', root, 'Dockerfile', '.koi-runtime']);
			},
		});
		const fb = fakeBox([]);
		await expect(
			up({ pr: 7, comment: false }, deps(git, fb.box, { github: () => github }).d),
		).rejects.toThrow(/\.koi-runtime\/, which koi reserves/);
		expect(fb.uploads).toEqual([]);

		const kept = await fakeGit({
			archive: async (_commit, out) => {
				const root = await mkdtemp(join(tmpdir(), 'koi-archive-'));
				await mkdir(join(root, '.koi', 'points'), { recursive: true });
				await writeFile(join(root, '.koi', 'verify.yaml'), 'version: 1\n');
				await writeFile(join(root, '.koi', 'points', 'home.yaml'), 'id: hello.home\n');
				await writeFile(join(root, 'Dockerfile'), 'FROM scratch\n');
				await exec(['tar', '-cf', out, '-C', root, 'Dockerfile', '.koi']);
			},
		});
		const ok = fakeBox([{ record: record({ status: 'running', commit: PR_MERGE }), log: [] }]);
		await up({ pr: 7, comment: false }, deps(kept, ok.box, { github: () => github }).d);
		expect(ok.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'.koi/',
			'.koi/points/',
			'.koi/points/home.yaml',
			'.koi/verify.yaml',
			'Dockerfile',
		]);
	});

	test("--head lists the files from git, against GitHub's merge, when gh cannot list them", async () => {
		const diffs: Array<[string, string]> = [];
		const git = await fakeGit({
			diffFiles: async (base, head) => {
				diffs.push([base, head]);
				return ['src/search/index.py', 'README.md'];
			},
		});
		const fb = fakeBox([{ record: record({ status: 'running', commit: PR_HEAD }), log: [] }]);
		// The real client, with a gh that fails as it does past exec's limit.
		const gh = ghCli('acme/hello', async (cmd) => {
			throw new OutputTooLargeError(cmd, 256 * 1024);
		});
		const github: GitHub = {
			...gh,
			pullRequestBranches: async () => ({
				head: 'feature/from-pr',
				base: 'main',
				headOid: PR_HEAD,
			}),
		};
		const run = deps(git, fb.box, { github: () => github });
		const result = await up({ pr: 7, comment: false, head: true }, run.d);
		expect(result.status).toBe('running');
		expect(fb.uploads).toHaveLength(1);
		expect(diffs).toEqual([[PR_BASE, PR_HEAD]]);
		expect(fb.tarballs[1]).toEqual(['changed:src/search/index.py\nREADME.md']);
		expect(
			run.progress.some((m) => m.startsWith('gh could not list the files pull request 7 changes')),
		).toBe(true);
	});

	test('a merge build lists its files from the merge it builds, whatever gh would say', async () => {
		const merges: Array<[number, string]> = [];
		const git = await fakeGit({
			mergeFiles: async (pr, merge) => {
				merges.push([pr, merge]);
				return ['src/search/index.py'];
			},
		});
		const fb = fakeBox([{ record: record({ status: 'running', commit: PR_MERGE }), log: [] }]);
		const asked: number[] = [];
		const github: GitHub = {
			pullRequestMergeState: notAsked,
			pullRequestBranches: async () => ({
				head: 'feature/from-pr',
				base: 'main',
				headOid: 'c'.repeat(40),
			}),
			pullRequestFiles: async (pr) => {
				asked.push(pr);
				return Array.from({ length: 3000 }, (_, i) => `other/${i}.py`);
			},
			upsertComment: async () => 'unused',
		};
		const result = await up(
			{ pr: 7, comment: false },
			deps(git, fb.box, { github: () => github }).d,
		);
		expect(result.status).toBe('running');
		expect(asked).toEqual([]);
		expect(merges).toEqual([[7, PR_MERGE]]);
		expect(fb.tarballs[1]).toEqual(['changed:src/search/index.py']);
	});

	test("--head takes gh's list when it describes the fetched head", async () => {
		const git = await fakeGit();
		const fb = fakeBox([{ record: record({ status: 'running', commit: PR_HEAD }), log: [] }]);
		const github: GitHub = {
			pullRequestMergeState: notAsked,
			pullRequestBranches: async () => ({
				head: 'feature/from-pr',
				base: 'main',
				headOid: PR_HEAD,
			}),
			pullRequestFiles: async () => ['src/search/index.py'],
			upsertComment: async () => 'unused',
		};
		await up({ pr: 7, comment: false, head: true }, deps(git, fb.box, { github: () => github }).d);
		expect(fb.uploads[0]?.commit).toBe(PR_HEAD);
		expect(fb.tarballs[1]).toEqual(['changed:src/search/index.py']);
	});

	test('--head stops before uploading when the pull request moved since koi fetched it', async () => {
		const git = await fakeGit();
		const fb = fakeBox([]);
		const github: GitHub = {
			pullRequestMergeState: notAsked,
			pullRequestBranches: async () => ({
				head: 'feature/from-pr',
				base: 'main',
				headOid: 'c'.repeat(40),
			}),
			pullRequestFiles: async () => ['src/search/index.py', 'src/search/rank.py'],
			upsertComment: async () => 'unused',
		};
		await expect(
			up({ pr: 7, comment: false, head: true }, deps(git, fb.box, { github: () => github }).d),
		).rejects.toThrow(/^pull request 7 moved while koi was fetching it/);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});

	test("--head stops before uploading when gh's list may be cut at GitHub's 3,000 files", async () => {
		const git = await fakeGit();
		const fb = fakeBox([]);
		const github: GitHub = {
			pullRequestMergeState: notAsked,
			pullRequestBranches: async () => ({
				head: 'feature/from-pr',
				base: 'main',
				headOid: PR_HEAD,
			}),
			pullRequestFiles: async () => Array.from({ length: 3000 }, (_, i) => `src/m${i}/x.py`),
			upsertComment: async () => 'unused',
		};
		await expect(
			up({ pr: 7, comment: false, head: true }, deps(git, fb.box, { github: () => github }).d),
		).rejects.toThrow(
			/^GitHub lists at most 3,000 files for a pull request, and pull request 7 lists 3000/,
		);
		expect(fb.uploads).toEqual([]);
	});

	test("points the comment at the keys page of the box's own domain", async () => {
		const git = await fakeGit();
		const fb = fakeBox([{ record: record({ status: 'running', commit: PR_MERGE }), log: [] }]);
		const bodies: string[] = [];
		const github: GitHub = {
			pullRequestMergeState: notAsked,
			pullRequestBranches: async () => ({ head: 'feature/from-pr', base: 'main' }),
			pullRequestFiles: async () => [],
			upsertComment: async (_pr, _marker, body) => {
				bodies.push(body);
				return 'https://github.com/acme/hello/pull/7#issuecomment-1';
			},
		};
		await up(
			{ pr: 7, comment: true },
			deps(git, fb.box, { domain: 'example.dev', github: () => github }).d,
		);
		expect(bodies[0]).toContain('https://hello-pr-7.example.dev');
		expect(bodies[0]).toContain('open https://keys.example.dev/?for=hello-pr-7,');
		expect(bodies[0]).not.toContain('previews.example.net');
	});
});

// gh through the real exec, on a machine where gh is not there.
const noGh = (ownerRepo: string) =>
	ghCli(ownerRepo, (cmd, options) => exec(['/nonexistent/gh', ...cmd.slice(1)], options));

describe('up --pr without gh installed', () => {
	test('builds the head as pushed, naming the branch after the pull request', async () => {
		const git = await fakeGit();
		const fb = fakeBox([{ record: record({ status: 'running', commit: PR_HEAD }), log: [] }]);
		const result = await up(
			{ pr: 7, comment: false, head: true },
			deps(git, fb.box, { github: noGh }).d,
		);
		expect(fb.uploads[0]?.branch).toBe('pr-7');
		expect(fb.uploads[0]?.commit).toBe(PR_HEAD);
		expect(result.status).toBe('running');
	});

	test('without --head, says gh is needed before uploading anything', async () => {
		const git = await fakeGit();
		const fb = fakeBox([]);
		await expect(
			up({ pr: 7, comment: false }, deps(git, fb.box, { github: noGh }).d),
		).rejects.toThrow(
			/^checking GitHub's merge of pull request 7 against its base branch needs gh, and the GitHub CLI \(gh\) is not installed or cannot be started/,
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});

	test('with --comment, says gh is needed before uploading anything', async () => {
		const git = await fakeGit();
		const fb = fakeBox([]);
		await expect(
			up({ pr: 7, comment: true }, deps(git, fb.box, { github: noGh }).d),
		).rejects.toThrow(
			/^--comment posts through gh, and the GitHub CLI \(gh\) is not installed or cannot be started/,
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});
});

// koi up --pr with the real git client, against a bare repository holding
// pull requests as GitHub does (see pulls.ts).
describe('up --pr against a real origin', () => {
	type Origin = Awaited<ReturnType<typeof pullRequestOrigin>>;
	// GitHub's answer when asked whether pull request `pr` of `o` can merge:
	// `mergeable`, with the base branch main and the head as origin has it.
	const mergeState = async (
		o: Origin,
		pr: number,
		mergeable: boolean | null,
		baseBranch = 'main',
	): Promise<PullRequestMergeState> => ({
		baseBranch,
		head: (
			await execOk(['git', '-C', o.origin, 'rev-parse', `refs/pull/${pr}/head`])
		).stdout.trim(),
		mergeable,
	});
	// gh as it answers for o's pull requests: each is opened from a branch
	// called feature against main, and changes pr.txt. Asked whether one can
	// merge, GitHub keeps working it out and never remakes its merge, as it
	// did for nine pull requests through a whole cost run.
	const github = (o: Origin): GitHub => ({
		pullRequestBranches: async () => ({ head: 'feature', base: 'main' }),
		pullRequestFiles: async () => ['pr.txt'],
		pullRequestMergeState: (pr) => mergeState(o, pr, null),
		upsertComment: async () => {
			throw new Error('no comment in this test');
		},
	});
	const running = (commit: string) =>
		fakeBox([{ record: record({ status: 'running', commit }), log: [] }]);
	const short = (c: string) => c.slice(0, 7);
	// koi up's dependencies, its progress, and how long it waited before
	// uploading (or in all, when it uploaded nothing).
	const all = (o: Origin, box: Box, gh: UpDeps['github'] = () => github(o)) => {
		let uploadedAt: number | undefined;
		const timed: Box = {
			...box,
			upload: async (request, tarball) => {
				uploadedAt = r.clock();
				await box.upload(request, tarball);
			},
		};
		const r = deps(cliGit(o.user, asGitHub()), timed, { github: gh });
		return { ...r, waited: () => uploadedAt ?? r.clock() };
	};
	const run = (o: Origin, box: Box, gh: UpDeps['github'] = () => github(o)) => all(o, box, gh).d;
	// main moves on past the base GitHub merged into: by a commit that adds
	// `file` when given, or by an empty one. Returns where main is now.
	const moveMain = async (o: Origin, file?: { path: string; text: string }) => {
		await o.author('checkout', '-q', '--detach', o.base);
		const moved =
			file === undefined
				? await o
						.author('commit', '-q', '--allow-empty', '-m', 'main moved on')
						.then(() => o.author('rev-parse', 'HEAD'))
				: await o.commit(file.path, file.text, 'main moved on');
		await o.author('push', '-q', o.origin, `${moved}:refs/heads/main`);
		return moved;
	};
	// The author pushes pull request 7 again, and GitHub does not remake its
	// merge. Returns the new head.
	const pushAgain = async (o: Origin) => {
		await o.author('checkout', '-q', '--detach', o.head7);
		await o.author('commit', '-q', '--allow-empty', '-m', 'pull request 7, pushed again');
		const pushed = await o.author('rev-parse', 'HEAD');
		await o.author('push', '-q', o.origin, `${pushed}:refs/pull/7/head`);
		return pushed;
	};
	// The author pushes pull request 7 once more, on top of where it is now,
	// as push number `n`. Returns the new head.
	const pushOnTop = async (o: Origin, n: number) => {
		await o.author('fetch', '-q', o.origin, 'refs/pull/7/head');
		await o.author('checkout', '-q', '--detach', 'FETCH_HEAD');
		await o.author('commit', '-q', '--allow-empty', '-m', `pull request 7, push ${n}`);
		const pushed = await o.author('rev-parse', 'HEAD');
		await o.author('push', '-q', o.origin, `${pushed}:refs/pull/7/head`);
		return pushed;
	};
	// A branch develop on origin, a commit past the base GitHub merged into.
	// Returns its tip.
	const develop = async (o: Origin) => {
		await o.author('checkout', '-q', '--detach', o.base);
		const tip = await o.commit('dev.txt', 'develop\n', 'develop');
		await o.author('push', '-q', o.origin, `${tip}:refs/heads/develop`);
		return tip;
	};
	// GitHub remakes its merge of pull request 7, of `head` into `base`,
	// replacing the ref.
	const remerge = async (o: Origin, head: string, base: string) => {
		await o.author('checkout', '-q', '--detach', base);
		await o.author('merge', '-q', '--no-ff', '-m', `Merge ${head} into ${base}`, head);
		const merge = await o.author('rev-parse', 'HEAD');
		await o.author('push', '-q', o.origin, `+${merge}:refs/pull/7/merge`);
		return merge;
	};
	// A commit's parents, as its object names them.
	const parents = async (o: Origin, commit: string) =>
		(await o.userGit('cat-file', '-p', commit))
			.split('\n')
			.filter((l) => l.startsWith('parent '))
			.map((l) => l.slice('parent '.length));

	test("builds GitHub's merge of the pull request into its base, seeded from what the pull request changed", async () => {
		const o = await pullRequestOrigin();
		const fb = running(o.merge7);
		// The merge is current, so koi asks GitHub nothing and waits for nothing.
		let asked = 0;
		const current: GitHub = {
			...github(o),
			pullRequestMergeState: async (pr) => {
				asked += 1;
				return mergeState(o, pr, true);
			},
		};
		const d = all(o, fb.box, () => current);
		const result = await up({ pr: 7, comment: false }, d.d);
		expect(asked).toBe(0);
		expect(d.waited()).toBe(0);
		expect(d.progress.some((m) => m.includes('out of date') || m.includes('koi merged'))).toBe(
			false,
		);
		const request = fb.uploads[0];
		expect(request?.commit).toBe(o.merge7);
		expect(request?.pr).toBe(7);
		expect(request?.merge).toEqual({ head: o.head7, base: o.base, baseBranch: 'main' });
		expect(request?.branch).toBe('feature');
		expect(request?.dirty).toBe(false);
		// The merge's tree: the pull request's file, and what main gained after
		// the pull request branched from it.
		expect(fb.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'base.txt',
			'koi.yaml',
			'pr.txt',
		]);
		// Seeding reads what the pull request changed, not what the merge holds.
		expect(fb.tarballs[1]).toEqual(['changed:pr.txt']);
		expect(result.status).toBe('running');
		expect(result.commit).toBe(o.merge7);
		expect(result.pr).toBe(7);
		expect(result.merge).toEqual({ head: o.head7, base: o.base, baseBranch: 'main' });
	});

	test('--head builds the head as pushed, whether GitHub has a merge or not', async () => {
		const o = await pullRequestOrigin();
		const seven = running(o.head7);
		const result = await up({ pr: 7, comment: false, head: true }, run(o, seven.box));
		expect(seven.uploads[0]?.commit).toBe(o.head7);
		expect(seven.uploads[0]?.pr).toBe(7);
		expect(seven.uploads[0]?.merge).toBeUndefined();
		expect(seven.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'koi.yaml',
			'pr.txt',
		]);
		expect(result.commit).toBe(o.head7);
		expect(result.merge).toBeUndefined();
		// Pull request 8 conflicts with main and has no merge.
		const eight = running(o.head8);
		await up({ pr: 8, comment: false, head: true }, run(o, eight.box));
		expect(eight.uploads[0]?.commit).toBe(o.head8);
		expect(eight.uploads[0]?.merge).toBeUndefined();
		expect(eight.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'base.txt',
			'koi.yaml',
		]);
	});

	test('builds from a shallow checkout of the merge, as actions/checkout makes, in both modes', async () => {
		const o = await pullRequestOrigin();
		const shallow = await shallowCheckout(o.origin, 'refs/pull/7/merge');
		const at = (box: Box) => deps(cliGit(shallow, asGitHub()), box, { github: () => github(o) }).d;
		const merged = running(o.merge7);
		await up({ pr: 7, comment: false }, at(merged.box));
		expect(merged.uploads[0]?.commit).toBe(o.merge7);
		expect(merged.uploads[0]?.merge).toEqual({ head: o.head7, base: o.base, baseBranch: 'main' });
		expect(merged.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'base.txt',
			'koi.yaml',
			'pr.txt',
		]);
		// The list comes from the merge against its base parent, which the
		// shallow checkout lacked until koi deepened it by one.
		expect(merged.tarballs[1]).toEqual(['changed:pr.txt']);
		const head = running(o.head7);
		await up({ pr: 7, comment: false, head: true }, at(head.box));
		expect(head.uploads[0]?.commit).toBe(o.head7);
		expect(head.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'koi.yaml',
			'pr.txt',
		]);
	});

	test('refuses a merge ref that is not a merge of two commits, unless --head', async () => {
		const o = await pullRequestOrigin();
		await o.author('push', '-q', o.origin, `${o.head8}:refs/pull/8/merge`);
		const fb = fakeBox([]);
		await expect(up({ pr: 8, comment: false }, run(o, fb.box))).rejects.toThrow(
			`refs/pull/8/merge on origin is ${o.head8}, which is not a merge of two commits`,
		);
		expect(fb.uploads).toEqual([]);
		const head = running(o.head8);
		await up({ pr: 8, comment: false, head: true }, run(o, head.box));
		expect(head.uploads[0]?.commit).toBe(o.head8);
	});

	test('stops before uploading when GitHub has no merge of the pull request, naming its base', async () => {
		const o = await pullRequestOrigin();
		const fb = fakeBox([]);
		await expect(up({ pr: 8, comment: false }, run(o, fb.box))).rejects.toThrow(
			"GitHub has no merge of pull request 8 into main (no refs/pull/8/merge on origin). Either the pull request conflicts with main, or GitHub has not finished checking it. Rebase onto main or merge it in and push, or try again in a minute. To build the head as pushed instead, without main's later changes, run koi up --pr 8 --head.",
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});

	test('without gh, the base branch goes unnamed in that message', async () => {
		const o = await pullRequestOrigin();
		const fb = fakeBox([]);
		await expect(up({ pr: 8, comment: false }, run(o, fb.box, noGh))).rejects.toThrow(
			"GitHub has no merge of pull request 8 into its base branch (no refs/pull/8/merge on origin). Either the pull request conflicts with its base branch, or GitHub has not finished checking it. Rebase onto the base branch or merge it in and push, or try again in a minute. To build the head as pushed instead, without the base branch's later changes, run koi up --pr 8 --head.",
		);
		expect(fb.uploads).toEqual([]);
	});

	test('asks GitHub to recompute a merge it kept after the base moved on, and builds the new one', async () => {
		const o = await pullRequestOrigin();
		const moved = await moveMain(o);
		// GitHub, asked, is working it out, then has remade the merge.
		let asked = 0;
		let remade = '';
		const recomputing: GitHub = {
			...github(o),
			pullRequestMergeState: async (pr) => {
				asked += 1;
				if (asked === 1) return mergeState(o, pr, null);
				remade = await remerge(o, o.head7, moved);
				return mergeState(o, pr, true);
			},
		};
		const fb = running(COMMIT);
		const d = all(o, fb.box, () => recomputing);
		const result = await up({ pr: 7, comment: false }, d.d);
		expect(asked).toBe(2);
		expect(fb.uploads[0]?.commit).toBe(remade);
		expect(fb.uploads[0]?.merge).toEqual({ head: o.head7, base: moved, baseBranch: 'main' });
		expect(result.commit).toBe(remade);
		expect(result.merge).toEqual({ head: o.head7, base: moved, baseBranch: 'main' });
		// GitHub's merge holds main's change as well as the pull request's.
		expect(fb.tarballs[1]).toEqual(['changed:pr.txt']);
		// Two fetches, one wait apart, after the first look.
		expect(d.waited()).toBe(2 * MERGE_POLL_MS);
		expect(d.progress).toContain(
			`GitHub's merge of pull request 7 into main is out of date. Its base ${short(o.base)} is behind main, now at ${short(moved)}. Asking GitHub to recompute it, and waiting up to 90 seconds`,
		);
		expect(d.progress).toContain('GitHub recomputed its merge of pull request 7');
		expect(d.progress).toContain(
			`building #7 (${short(o.head7)}) merged into main (${short(moved)}), merge commit ${short(remade)}`,
		);
	});

	test("merges the pull request itself when GitHub keeps an out-of-date merge, and records it as it would GitHub's", async () => {
		const o = await pullRequestOrigin();
		const moved = await moveMain(o, { path: 'later.txt', text: 'main moved on\n' });
		let asked = 0;
		const bodies: string[] = [];
		const stuck: GitHub = {
			...github(o),
			pullRequestMergeState: async (pr) => {
				asked += 1;
				return mergeState(o, pr, null);
			},
			upsertComment: async (_pr, _marker, body) => {
				bodies.push(body);
				return 'https://github.com/acme/hello/pull/7#issuecomment-1';
			},
		};
		const fb = running(COMMIT);
		const d = all(o, fb.box, () => stuck);
		const result = await up({ pr: 7, comment: true }, d.d);
		const made = result.commit;
		expect(made).not.toBe(o.merge7);
		// Recorded as GitHub's merge is: the commit, and its head, base and
		// base branch, which are the commit's own parents, base first.
		expect(fb.uploads[0]?.commit).toBe(made);
		expect(fb.uploads[0]?.merge).toEqual({ head: o.head7, base: moved, baseBranch: 'main' });
		expect(result.merge).toEqual({ head: o.head7, base: moved, baseBranch: 'main' });
		expect(await parents(o, made)).toEqual([moved, o.head7]);
		// The tree holds main's later change and the pull request's, and the
		// preview is seeded from what the pull request changed.
		expect(fb.tarballs[0]).toEqual([
			'.koi-runtime/',
			'.koi-runtime/changed-files.txt',
			'base.txt',
			'koi.yaml',
			'later.txt',
			'pr.txt',
		]);
		expect(fb.tarballs[1]).toEqual(['changed:pr.txt']);
		// koi asked, and fetched again, for the whole wait and no longer, then
		// asked once more for the base branch and head to merge.
		expect(d.waited()).toBe(MERGE_WAIT_MS);
		expect(asked).toBe(MERGE_WAIT_MS / MERGE_POLL_MS + 1);
		// It says it made the merge, in its progress and the comment.
		expect(d.progress).toContain(
			`GitHub did not recompute its merge of pull request 7 within 90 seconds; koi merges its head ${short(o.head7)} into main itself`,
		);
		expect(d.progress).toContain(
			`koi merged pull request 7 (${short(o.head7)}) into main (${short(moved)}) itself, merge commit ${short(made)}, since GitHub's merge is out of date`,
		);
		const built = `#7 (${short(o.head7)}) merged into main (${short(moved)}), merge commit ${short(made)}, which koi made because GitHub's was out of date`;
		expect(d.progress).toContain(`building ${built}`);
		expect(bodies[0]).toContain(`Built from ${built}.`);
		// Anyone with the two parents gets the same commit, with plain git in
		// another repository: the tree git merge-tree writes, the base then
		// the head, GitHub's message, and koi as author and committer at the
		// later parent's commit time, in UTC.
		const tree = await o.author('merge-tree', '--write-tree', moved, o.head7);
		const time = Math.max(
			...(await o.author('show', '-s', '--format=%ct', moved, o.head7)).split('\n').map(Number),
		);
		const when = `@${time} +0000`;
		const again = await execOk(
			[
				'git',
				'-C',
				o.authorDir,
				'commit-tree',
				'--no-gpg-sign',
				'-p',
				moved,
				'-p',
				o.head7,
				'-m',
				`Merge ${o.head7} into ${moved}`,
				tree,
			],
			{
				env: {
					GIT_AUTHOR_NAME: 'koi',
					GIT_AUTHOR_EMAIL: 'koi@koi.invalid',
					GIT_AUTHOR_DATE: when,
					GIT_COMMITTER_NAME: 'koi',
					GIT_COMMITTER_EMAIL: 'koi@koi.invalid',
					GIT_COMMITTER_DATE: when,
				},
			},
		);
		expect(again.stdout.trim()).toBe(made);
		// And koi up again makes it again.
		const twice = running(made);
		await up(
			{ pr: 7, comment: false },
			run(o, twice.box, () => stuck),
		);
		expect(twice.uploads[0]?.commit).toBe(made);
	});

	test('refuses a pull request that conflicts with the base GitHub kept an out-of-date merge for', async () => {
		const o = await pullRequestOrigin();
		// main adds the pull request's file with other text.
		const moved = await moveMain(o, { path: 'pr.txt', text: 'not seven\n' });
		const fb = fakeBox([]);
		const d = all(o, fb.box);
		await expect(up({ pr: 7, comment: false }, d.d)).rejects.toThrow(
			`pull request 7 (${short(o.head7)}) conflicts with main (${short(moved)}) in pr.txt, so there is no merge of it to build, and GitHub's merge (refs/pull/7/merge on origin) is of an earlier head or base. Rebase onto main or merge it in and push. To build the head as pushed instead, without main's later changes, run koi up --pr 7 --head.`,
		);
		expect(d.waited()).toBe(MERGE_WAIT_MS);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
		// GitHub saying it cannot merge ends the wait at once, with the same
		// refusal.
		const cannot: GitHub = {
			...github(o),
			pullRequestMergeState: (pr) => mergeState(o, pr, false),
		};
		const early = all(o, fakeBox([]).box, () => cannot);
		await expect(up({ pr: 7, comment: false }, early.d)).rejects.toThrow(
			`pull request 7 (${short(o.head7)}) conflicts with main (${short(moved)}) in pr.txt`,
		);
		expect(early.waited()).toBe(0);
		expect(early.progress).toContain(
			`GitHub says pull request 7 cannot be merged into main; koi merges its head ${short(o.head7)} into main itself`,
		);
		// --head is unaffected.
		const head = running(o.head7);
		await up({ pr: 7, comment: false, head: true }, run(o, head.box));
		expect(head.uploads[0]?.commit).toBe(o.head7);
	});

	test("merges the new push itself when GitHub's merge is of an earlier one, naming what was out of date", async () => {
		const o = await pullRequestOrigin();
		const pushed = await pushAgain(o);
		const fb = running(COMMIT);
		const d = all(o, fb.box);
		const result = await up({ pr: 7, comment: false }, d.d);
		expect(fb.uploads[0]?.merge).toEqual({ head: pushed, base: o.base, baseBranch: 'main' });
		expect(await parents(o, result.commit)).toEqual([o.base, pushed]);
		expect(d.progress).toContain(
			`GitHub's merge of pull request 7 into main is out of date. Its head ${short(o.head7)} is an earlier push, and the pull request is now at ${short(pushed)}. Asking GitHub to recompute it, and waiting up to 90 seconds`,
		);
		// main moves on as well, and both are named.
		const moved = await moveMain(o);
		const both = all(o, running(COMMIT).box);
		const again = await up({ pr: 7, comment: false }, both.d);
		expect(await parents(o, again.commit)).toEqual([moved, pushed]);
		expect(both.progress).toContain(
			`GitHub's merge of pull request 7 into main is out of date. Its head ${short(o.head7)} is an earlier push, and the pull request is now at ${short(pushed)}. Its base ${short(o.base)} is behind main, now at ${short(moved)}. Asking GitHub to recompute it, and waiting up to 90 seconds`,
		);
		// --head takes the new push.
		const head = running(pushed);
		await up({ pr: 7, comment: false, head: true }, run(o, head.box));
		expect(head.uploads[0]?.commit).toBe(pushed);
	});

	test('merges without waiting when gh cannot ask GitHub to recompute', async () => {
		const o = await pullRequestOrigin();
		const moved = await moveMain(o);
		const failing: GitHub = {
			...github(o),
			pullRequestMergeState: async () => {
				throw new Error('gh api exited 1: HTTP 502');
			},
		};
		const fb = running(COMMIT);
		const d = all(o, fb.box, () => failing);
		await up({ pr: 7, comment: false }, d.d);
		expect(fb.uploads[0]?.merge).toEqual({ head: o.head7, base: moved, baseBranch: 'main' });
		expect(d.waited()).toBe(0);
		expect(d.progress).toContain(
			`koi could not ask GitHub to recompute its merge of pull request 7 (gh api exited 1: HTTP 502); koi merges its head ${short(o.head7)} into main itself`,
		);
	});

	test('ends the wait at its deadline on a clock that only moves forward, however long each step stalls', async () => {
		const o = await pullRequestOrigin();
		const moved = await moveMain(o);
		// Each fetch, listing of origin's branches and gh call takes 40
		// seconds, or fails at its time limit when that is shorter, as exec
		// would. The wall clock is set back an hour once koi first asks.
		const calls: Array<[number, string, number | undefined]> = [];
		let setBack = 0;
		const stall = async <T>(
			what: string,
			timeoutMs: number | undefined,
			call: () => Promise<T>,
		) => {
			calls.push([t.clock(), what, timeoutMs]);
			if (what === 'ask') setBack = 3_600_000;
			if (timeoutMs !== undefined && timeoutMs < 40_000) {
				await t.d.sleep(timeoutMs);
				throw new Error(`${what} did not finish within ${timeoutMs / 1000} seconds`);
			}
			await t.d.sleep(40_000);
			return call();
		};
		const real = cliGit(o.user, asGitHub());
		const git: Git = {
			...real,
			fetchPullRequest: (pr, options) =>
				stall('fetch', options?.timeoutMs, () => real.fetchPullRequest(pr)),
			remoteBranchTips: (options) =>
				stall('branches', options?.timeoutMs, () => real.remoteBranchTips()),
		};
		const slow: GitHub = {
			...github(o),
			pullRequestMergeState: (pr, options) =>
				stall('ask', options?.timeoutMs, () => mergeState(o, pr, null)),
		};
		const fb = running(COMMIT);
		const t = deps(git, fb.box, {
			github: () => slow,
			now: () => new Date(t.clock() - setBack),
		});
		await up({ pr: 7, comment: false }, t.d);
		// The wait starts at 80 seconds, after the first fetch and look, and
		// ends at 170, when the fetch given the last 35 seconds runs out.
		// What follows, to make the merge, has its own time limits.
		expect(calls).toEqual([
			[0, 'fetch', undefined],
			[40_000, 'branches', undefined],
			[80_000, 'ask', MERGE_WAIT_MS],
			[80_000 + 40_000 + MERGE_POLL_MS, 'fetch', 35_000],
			[80_000 + MERGE_WAIT_MS, 'ask', undefined],
			[80_000 + MERGE_WAIT_MS + 40_000, 'fetch', undefined],
		]);
		expect(t.progress).toContain(
			`koi could not fetch pull request 7 again while it waited (fetch did not finish within 35 seconds); koi merges its head ${short(o.head7)} into main itself`,
		);
		expect(fb.uploads[0]?.merge).toEqual({ head: o.head7, base: moved, baseBranch: 'main' });
	});

	test('merges the pull request itself when a fetch fails while it waits, and it can fetch again', async () => {
		const o = await pullRequestOrigin();
		const moved = await moveMain(o);
		const real = cliGit(o.user, asGitHub());
		let fetches = 0;
		const git: Git = {
			...real,
			fetchPullRequest: async (pr, options) => {
				fetches += 1;
				// The first fetch while koi waits fails, as when the network drops.
				if (fetches === 2) throw new Error('git fetch exited 128: Could not resolve host');
				return real.fetchPullRequest(pr, options);
			},
		};
		const fb = running(COMMIT);
		const d = deps(git, fb.box, { github: () => github(o) });
		const result = await up({ pr: 7, comment: false }, d.d);
		expect(fetches).toBe(3);
		expect(result.merge).toEqual({ head: o.head7, base: moved, baseBranch: 'main' });
		expect(await parents(o, result.commit)).toEqual([moved, o.head7]);
		expect(d.progress).toContain(
			`koi could not fetch pull request 7 again while it waited (git fetch exited 128: Could not resolve host); koi merges its head ${short(o.head7)} into main itself`,
		);
	});

	test("accepts GitHub's remade merge of a pull request retargeted while koi waits, against the branch it targets now", async () => {
		const o = await pullRequestOrigin();
		await moveMain(o);
		const tip = await develop(o);
		// gh pr view said main. Asked, GitHub says develop, then remakes its
		// merge onto develop.
		let asked = 0;
		let remade = '';
		const retargeted: GitHub = {
			...github(o),
			pullRequestMergeState: async (pr) => {
				asked += 1;
				if (asked === 2) remade = await remerge(o, o.head7, tip);
				return mergeState(o, pr, asked === 1 ? null : true, 'develop');
			},
		};
		const fb = running(COMMIT);
		const d = all(o, fb.box, () => retargeted);
		const result = await up({ pr: 7, comment: false }, d.d);
		expect(result.commit).toBe(remade);
		expect(result.merge).toEqual({ head: o.head7, base: tip, baseBranch: 'develop' });
		expect(d.progress).toContain('GitHub recomputed its merge of pull request 7');
	});

	test('merges a pull request retargeted while koi waits into the branch it targets now', async () => {
		const o = await pullRequestOrigin();
		await moveMain(o);
		const tip = await develop(o);
		const retargeted: GitHub = {
			...github(o),
			pullRequestMergeState: (pr) => mergeState(o, pr, null, 'develop'),
		};
		const fb = running(COMMIT);
		const d = all(o, fb.box, () => retargeted);
		const result = await up({ pr: 7, comment: false }, d.d);
		expect(result.merge).toEqual({ head: o.head7, base: tip, baseBranch: 'develop' });
		expect(await parents(o, result.commit)).toEqual([tip, o.head7]);
		expect(d.progress).toContain(
			`GitHub did not recompute its merge of pull request 7 within 90 seconds; koi merges its head ${short(o.head7)} into develop itself`,
		);
	});

	test('merges the head GitHub answered for, not the one koi fetched before it asked', async () => {
		const o = await pullRequestOrigin();
		const moved = await moveMain(o);
		// The author pushes as koi asks, and GitHub answers for the new push.
		let asked = 0;
		let pushed = '';
		const pushing: GitHub = {
			...github(o),
			pullRequestMergeState: async (pr) => {
				asked += 1;
				if (asked === 1) pushed = await pushAgain(o);
				return mergeState(o, pr, false);
			},
		};
		const fb = running(COMMIT);
		const d = all(o, fb.box, () => pushing);
		const result = await up({ pr: 7, comment: false }, d.d);
		expect(result.merge).toEqual({ head: pushed, base: moved, baseBranch: 'main' });
		expect(d.progress).toContain(
			`GitHub says pull request 7 cannot be merged into main; koi merges its head ${short(pushed)} into main itself`,
		);
	});

	test('reads GitHub again when the author pushes between its answer and the fetch, and stops when the pushes keep coming', async () => {
		const o = await pullRequestOrigin();
		const moved = await moveMain(o);
		// GitHub says the pull request cannot merge, so koi merges it at once.
		// The author pushes just after GitHub answers koi's first read of what
		// to merge, then stops.
		let asked = 0;
		let pushed = '';
		const once: GitHub = {
			...github(o),
			pullRequestMergeState: async (pr) => {
				asked += 1;
				const said = await mergeState(o, pr, false);
				if (asked === 2) pushed = await pushOnTop(o, asked);
				return said;
			},
		};
		const fb = running(COMMIT);
		const result = await up({ pr: 7, comment: false }, all(o, fb.box, () => once).d);
		expect(asked).toBe(3);
		expect(result.merge).toEqual({ head: pushed, base: moved, baseBranch: 'main' });
		// An author who pushes after every answer.
		let again = 0;
		const named: string[] = [];
		const busy: GitHub = {
			...github(o),
			pullRequestMergeState: async (pr) => {
				again += 1;
				const said = await mergeState(o, pr, false);
				named.push(said.head);
				if (again >= 2) await pushOnTop(o, 10 + again);
				return said;
			},
		};
		const stopped = fakeBox([]);
		const err = await up({ pr: 7, comment: false }, all(o, stopped.box, () => busy).d).catch(
			(e: unknown) => e,
		);
		const now = (await execOk(['git', '-C', o.origin, 'rev-parse', 'refs/pull/7/head'])).stdout;
		expect(err).toBeInstanceOf(Error);
		expect((err as Error).message).toBe(
			`pull request 7 moved while koi was fetching it to merge it: GitHub named its head ${short(named.at(-1) ?? '')}, and origin had ${short(now)}. Run koi up again.`,
		);
		expect(again).toBe(1 + MERGE_INPUT_TRIES);
		expect(stopped.uploads).toEqual([]);
	});

	test('stops before uploading when git is too old to merge the pull request itself', async () => {
		const o = await pullRequestOrigin();
		const moved = await moveMain(o);
		// git version as Apple's git of 2024 answers it.
		const old = (cmd: string[], options?: ExecOptions): Promise<ExecResult> =>
			cmd.at(-1) === 'version'
				? Promise.resolve({
						code: 0,
						stdout: 'git version 2.39.5 (Apple Git-154)\n',
						stderr: '',
						timedOut: false,
					})
				: asGitHub()(cmd, options);
		const fb = fakeBox([]);
		const d = deps(cliGit(o.user, old), fb.box, { github: () => github(o) });
		await expect(up({ pr: 7, comment: false }, d.d)).rejects.toThrow(
			new RegExp(
				`^GitHub's merge of pull request 7 into main \\(refs/pull/7/merge on origin\\) is out of date\\. Its base ${short(o.base)} is behind main, now at ${short(moved)}\\. GitHub did not recompute its merge of pull request 7 within 90 seconds, and koi could not merge the pull request itself: koi merges with git merge-tree --write-tree and git --attr-source, which need git 2\\.43 or later \\(this is git version 2\\.39\\.5 \\(Apple Git-154\\)\\)\\. Try again in a minute, or build the head as pushed with koi up --pr 7 --head\\.$`,
			),
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});

	test('stops before uploading when gh cannot name the base, even with another branch still at the old one', async () => {
		const o = await pullRequestOrigin();
		// release stays at the old base while main moves on, and GitHub keeps
		// the old merge. That a branch sits at the old base says nothing
		// about main, so without the base's name koi cannot check the merge.
		await o.author('push', '-q', o.origin, `${o.base}:refs/heads/release`);
		await o.author('checkout', '-q', '--detach', o.base);
		await o.author('commit', '-q', '--allow-empty', '-m', 'main moved on');
		const moved = await o.author('rev-parse', 'HEAD');
		await o.author('push', '-q', o.origin, `${moved}:refs/heads/main`);
		// gh not installed.
		const missing = fakeBox([]);
		await expect(up({ pr: 7, comment: false }, run(o, missing.box, noGh))).rejects.toThrow(
			/^checking GitHub's merge of pull request 7 against its base branch needs gh, and the GitHub CLI \(gh\) is not installed or cannot be started \(.*\); install it from https:\/\/cli\.github\.com and sign in with gh auth login, or build the head as pushed with koi up --pr 7 --head\.$/,
		);
		expect(missing.uploads).toEqual([]);
		expect(missing.woke()).toBe(0);
		// gh installed but failing, as when not signed in.
		const signedOut = (ownerRepo: string) =>
			ghCli(ownerRepo, async () => ({
				code: 1,
				stdout: '',
				stderr: 'To get started with GitHub CLI, please run:  gh auth login\n',
				timedOut: false,
			}));
		const failing = fakeBox([]);
		await expect(up({ pr: 7, comment: false }, run(o, failing.box, signedOut))).rejects.toThrow(
			"checking GitHub's merge of pull request 7 against its base branch needs gh, and gh could not describe the pull request (gh pr view exited 1: To get started with GitHub CLI, please run:  gh auth login). Sign in with gh auth login and check that it can see acme/hello, or build the head as pushed with koi up --pr 7 --head.",
		);
		expect(failing.uploads).toEqual([]);
		// gh answering, but naming no base.
		const unnamed: GitHub = {
			...github(o),
			pullRequestBranches: async () => ({ head: 'feature', base: undefined }),
		};
		await expect(
			up(
				{ pr: 7, comment: false },
				run(o, fakeBox([]).box, () => unnamed),
			),
		).rejects.toThrow(
			"checking GitHub's merge of pull request 7 against its base branch needs gh, and gh pr view 7 did not name one. Check the pull request on GitHub, or build the head as pushed with koi up --pr 7 --head.",
		);
		// With gh naming main, the merge is seen to be behind it, and koi
		// merges into main, not the old base release is at.
		const named = all(o, running(COMMIT).box);
		await up({ pr: 7, comment: false }, named.d);
		expect(named.progress).toContain(
			`GitHub's merge of pull request 7 into main is out of date. Its base ${short(o.base)} is behind main, now at ${short(moved)}. Asking GitHub to recompute it, and waiting up to 90 seconds`,
		);
		expect(
			(
				await parents(o, (await up({ pr: 7, comment: false }, run(o, running(COMMIT).box))).commit)
			)[0],
		).toBe(moved);
		// --head needs no gh.
		const head = running(o.head7);
		await up({ pr: 7, comment: false, head: true }, run(o, head.box, noGh));
		expect(head.uploads[0]?.commit).toBe(o.head7);
		expect(head.uploads[0]?.branch).toBe('pr-7');
	});

	test('stops before uploading when gh names a base branch origin does not have', async () => {
		const o = await pullRequestOrigin();
		const elsewhere: GitHub = {
			...github(o),
			pullRequestBranches: async () => ({ head: 'feature', base: 'develop' }),
		};
		const fb = fakeBox([]);
		await expect(
			up(
				{ pr: 7, comment: false },
				run(o, fb.box, () => elsewhere),
			),
		).rejects.toThrow(
			'origin has no branch develop, which GitHub names as the base of pull request 7. Check that origin is the repository the pull request was opened in.',
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});

	test('says what it built, in its progress, its result and the pull request comment', async () => {
		const o = await pullRequestOrigin();
		const bodies: string[] = [];
		const commenting: GitHub = {
			...github(o),
			upsertComment: async (_pr, _marker, body) => {
				bodies.push(body);
				return 'https://github.com/acme/hello/pull/7#issuecomment-1';
			},
		};
		const merged = `#7 (${short(o.head7)}) merged into main (${short(o.base)}), merge commit ${short(o.merge7)}`;
		const fb = running(o.merge7);
		const d = deps(cliGit(o.user, asGitHub()), fb.box, { github: () => commenting });
		const result = await up({ pr: 7, comment: true }, d.d);
		expect(d.progress).toContain(`building ${merged}`);
		expect(builtFrom(result)).toBe(merged);
		expect(bodies[0]).toContain(`Built from ${merged}.`);
		// With --head, the head and no base.
		const head = running(o.head7);
		const dh = deps(cliGit(o.user, asGitHub()), head.box, { github: () => commenting });
		const asPushed = `#7 (${short(o.head7)}), its head as pushed, not merged into its base`;
		expect(builtFrom(await up({ pr: 7, comment: true, head: true }, dh.d))).toBe(asPushed);
		expect(dh.progress).toContain(`building ${asPushed}`);
		expect(bodies[1]).toContain(`Built from ${asPushed}.`);
	});

	test('posts no comment for a preview koi down removed during the build', async () => {
		const o = await pullRequestOrigin();
		const fb = running(o.merge7);
		// koid's answer to a status read once the record is gone. The
		// github above throws on any comment.
		const box: Box = {
			...fb.box,
			ctl: async (args) =>
				args[0] === 'status'
					? { code: 1, stdout: '', stderr: '{"error":"no such preview"}' }
					: fb.box.ctl(args),
		};
		const result = await up({ pr: 7, comment: true }, run(o, box));
		expect(result.status).toBe('failed');
		expect(result.error).toMatch(/was removed by koi down while koi up waited for its build$/);
		expect(result.comment).toBeUndefined();
	});

	test('stops before uploading when origin has no such pull request', async () => {
		const o = await pullRequestOrigin();
		const fb = fakeBox([]);
		await expect(up({ pr: 9, comment: false }, run(o, fb.box))).rejects.toThrow(
			'origin has no pull request 9 (no refs/pull/9/head there). Check the number, and that origin is the repository the pull request was opened in.',
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});
});

describe('up without a list of changed files', () => {
	test("--pr --head without gh and without GitHub's merge stops before uploading anything", async () => {
		const git = await fakeGit({
			fetchPullRequest: async () => ({ head: PR_HEAD, merge: undefined }),
		});
		const fb = fakeBox([]);
		await expect(
			up({ pr: 7, comment: false, head: true }, deps(git, fb.box, { github: noGh }).d),
		).rejects.toThrow(/^koi could not tell which files pull request 7 changes/);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});

	test('a working tree with no default branch to compare with stops before uploading anything', async () => {
		const git = await fakeGit({ changedFiles: async () => undefined });
		const fb = fakeBox([]);
		await expect(up({ comment: false }, deps(git, fb.box).d)).rejects.toThrow(
			/^koi could not tell which files this working tree changes/,
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
	});
});
