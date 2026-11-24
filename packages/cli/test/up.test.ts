import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deploymentIdentity, type PreviewRecord, type UpRequest, type UpResult } from '@koi/shared';
import { type BuildLog, BuildLogs } from '../../daemon/src/buildlog.ts';
import { awsBox, type Box, BoxUnavailableError, type CtlResult } from '../src/box.ts';
import { exec, OutputTooLargeError } from '../src/exec.ts';
import { cliGit, type Git } from '../src/git.ts';
import type { GitHub } from '../src/github.ts';
import { ghCli, ownerRepoFor } from '../src/github.ts';
import { builtFrom, type UpDeps, up } from '../src/up.ts';
import { koidClients, koidDeps, previewRecord, s3Stub, settings } from './koid.ts';
import { asGitHub, pullRequestOrigin, shallowCheckout } from './pulls.ts';

const COMMIT = 'c'.repeat(40);
// A pull request as fakeGit fetches it: its head, and GitHub's merge of that
// head into the base.
const PR_HEAD = 'd'.repeat(40);
const PR_BASE = 'e'.repeat(40);
const PR_MERGE = 'f'.repeat(40);

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
	// gh as it answers for that origin's pull requests: each is opened from
	// a branch called feature against main, and changes pr.txt.
	const github: GitHub = {
		pullRequestBranches: async () => ({ head: 'feature', base: 'main' }),
		pullRequestFiles: async () => ['pr.txt'],
		upsertComment: async () => {
			throw new Error('no comment in this test');
		},
	};
	const running = (commit: string) =>
		fakeBox([{ record: record({ status: 'running', commit }), log: [] }]);
	const short = (c: string) => c.slice(0, 7);
	const run = (
		o: Awaited<ReturnType<typeof pullRequestOrigin>>,
		box: Box,
		gh: UpDeps['github'] = () => github,
	) => deps(cliGit(o.user, asGitHub()), box, { github: gh }).d;

	test("builds GitHub's merge of the pull request into its base, seeded from what the pull request changed", async () => {
		const o = await pullRequestOrigin();
		const fb = running(o.merge7);
		const result = await up({ pr: 7, comment: false }, run(o, fb.box));
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
		const at = (box: Box) => deps(cliGit(shallow, asGitHub()), box, { github: () => github }).d;
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

	test("stops before uploading when GitHub's merge is of an earlier push than the head", async () => {
		const o = await pullRequestOrigin();
		// The author pushes again, and GitHub has not remade the merge yet.
		await o.author('checkout', '-q', '--detach', o.head7);
		await o.author('commit', '-q', '--allow-empty', '-m', 'pull request 7, pushed again');
		const pushed = await o.author('rev-parse', 'HEAD');
		await o.author('push', '-q', o.origin, `${pushed}:refs/pull/7/head`);
		const fb = fakeBox([]);
		await expect(up({ pr: 7, comment: false }, run(o, fb.box))).rejects.toThrow(
			`GitHub's merge of pull request 7 into main (refs/pull/7/merge on origin) is out of date. Its head ${short(o.head7)} is an earlier push, and the pull request is now at ${short(pushed)}. GitHub has not recomputed the merge yet. Try again in a minute, or build the head as pushed with koi up --pr 7 --head.`,
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
		// --head takes the new push.
		const head = running(pushed);
		await up({ pr: 7, comment: false, head: true }, run(o, head.box));
		expect(head.uploads[0]?.commit).toBe(pushed);
	});

	test('stops before uploading when the base moved on and GitHub kept the merge of the old one', async () => {
		const o = await pullRequestOrigin();
		// main moves on. GitHub may keep the merge after a base-only update,
		// and its head is still the pull request's.
		await o.author('checkout', '-q', '--detach', o.base);
		await o.author('commit', '-q', '--allow-empty', '-m', 'main moved on');
		const moved = await o.author('rev-parse', 'HEAD');
		await o.author('push', '-q', o.origin, `${moved}:refs/heads/main`);
		const fb = fakeBox([]);
		await expect(up({ pr: 7, comment: false }, run(o, fb.box))).rejects.toThrow(
			`GitHub's merge of pull request 7 into main (refs/pull/7/merge on origin) is out of date. Its base ${short(o.base)} is behind main, now at ${short(moved)}. GitHub has not recomputed the merge yet. Try again in a minute, or build the head as pushed with koi up --pr 7 --head.`,
		);
		expect(fb.uploads).toEqual([]);
		expect(fb.woke()).toBe(0);
		// --head is unaffected.
		const head = running(o.head7);
		await up({ pr: 7, comment: false, head: true }, run(o, head.box));
		expect(head.uploads[0]?.commit).toBe(o.head7);
		// A new push on top of that, and both are named.
		await o.author('checkout', '-q', '--detach', o.head7);
		await o.author('commit', '-q', '--allow-empty', '-m', 'pull request 7, pushed again');
		const pushed = await o.author('rev-parse', 'HEAD');
		await o.author('push', '-q', o.origin, `${pushed}:refs/pull/7/head`);
		await expect(up({ pr: 7, comment: false }, run(o, fakeBox([]).box))).rejects.toThrow(
			`is out of date. Its head ${short(o.head7)} is an earlier push, and the pull request is now at ${short(pushed)}. Its base ${short(o.base)} is behind main, now at ${short(moved)}. GitHub has not recomputed`,
		);
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
			...github,
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
		// With gh naming main, the merge is seen to be behind it.
		await expect(up({ pr: 7, comment: false }, run(o, fakeBox([]).box))).rejects.toThrow(
			`Its base ${short(o.base)} is behind main, now at ${short(moved)}.`,
		);
		// --head needs no gh.
		const head = running(o.head7);
		await up({ pr: 7, comment: false, head: true }, run(o, head.box, noGh));
		expect(head.uploads[0]?.commit).toBe(o.head7);
		expect(head.uploads[0]?.branch).toBe('pr-7');
	});

	test('stops before uploading when gh names a base branch origin does not have', async () => {
		const o = await pullRequestOrigin();
		const elsewhere: GitHub = {
			...github,
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
			...github,
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
