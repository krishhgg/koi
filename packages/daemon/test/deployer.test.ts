import { describe, expect, spyOn, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LEASE_MAX_SECONDS, type PreviewRecord, RecipeSchema } from '@koi/shared';
import { Activity } from '../src/activity.ts';
import { caddyApplier, type Route } from '../src/caddy.ts';
import {
	CapacityError,
	chooseUser,
	LeaseError,
	NoSuchLeaseError,
	NoSuchPreviewError,
	OwnershipError,
	sameOwner,
} from '../src/deployer.ts';
import { eventually, Gate, request, setup } from './fakes.ts';

// 62 characters each: with quotes and commas, 63 of them make a live list of
// exactly 1 + 63 * 65 = 4096 bytes.
const long = (i: number) => `x${String(i).padStart(3, '0')}${'a'.repeat(58)}`;

// Records for `count` live previews with long labels, deployed before.
async function seedLive(t: Awaited<ReturnType<typeof setup>>, count: number) {
	const at = new Date(t.now()).toISOString();
	for (let i = 0; i < count; i++) {
		await t.store.put({
			label: long(i),
			project: 'hello',
			repo: 'github.com/acme/hello',
			status: 'running',
			commit: 'a'.repeat(40),
			branch: `branch-${i}`,
			dirty: false,
			requestId: `seed${String(i).padStart(12, '0')}`,
			attempt: `seed${String(i).padStart(12, '0')}`,
			ttlDays: 7,
			createdAt: at,
			updatedAt: at,
		});
	}
}

describe('up', () => {
	test('builds, starts, waits for health, routes and publishes the preview', async () => {
		const t = await setup();
		await t.up(request());
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('running');
		expect(record?.deployment?.image).toBe('koi-preview/hello-pr-7:aaaaaaaaaaaaaaaa1');
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.2:8080' }]);
		expect(t.published.at(-1)).toEqual(['hello-pr-7']);
		const run = t.docker.runs[0];
		expect(run?.network).toBe('koi-previews');
		expect(run?.env.KOI_PREVIEW_URL).toBe('https://hello-pr-7.previews.example.net');
		expect(t.awakeCalls()).toBeGreaterThan(0);
	});

	test("records the deployment's id, the image's digest and the merge it was built from", async () => {
		const t = await setup();
		const merge = { head: 'b'.repeat(40), base: 'c'.repeat(40), baseBranch: 'develop' };
		await t.up(request({ merge }));
		const record = await t.store.get('hello-pr-7');
		const d = record?.deployment;
		// The attempt that built it names it, and is where its build log is.
		expect(d?.deploymentId).toBe(record?.attempt ?? '');
		expect(d?.imageDigest).toBe(t.docker.digests.get(d?.image ?? '') ?? '');
		expect(d?.imageDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
		expect(d?.merge).toEqual(merge);
		expect(await readFile(logPath(t.stateDir, record), 'utf8')).toContain(
			`image ${d?.imageDigest}`,
		);
		// A working tree build has no merge.
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) }));
		expect((await t.store.get('hello-pr-7'))?.deployment?.merge).toBeUndefined();
	});

	test('the same request accepted again after koi down makes a deployment with a new id, whatever Docker gives the image', async () => {
		const t = await setup();
		await t.up(request());
		const first = (await t.store.get('hello-pr-7'))?.deployment;
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		await t.up(request());
		const second = (await t.store.get('hello-pr-7'))?.deployment;
		expect(second?.requestId).toBe(first?.requestId ?? '');
		// Docker's image id is a hash of the image configuration, so a cached
		// rebuild of the same input keeps it: the digest says which image,
		// not which deployment. The deployment id is what is new each time.
		expect(second?.imageDigest).toBe(first?.imageDigest ?? '');
		expect(second?.deploymentId).not.toBe(first?.deploymentId ?? '');
	});

	test('a second up replaces the first only after the new one is healthy', async () => {
		const t = await setup();
		await t.up(request());
		const first = (await t.store.get('hello-pr-7'))?.deployment;
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) }));
		const second = (await t.store.get('hello-pr-7'))?.deployment;
		expect(second?.commit).toBe('b'.repeat(40));
		expect(second?.container).not.toBe(first?.container);
		// The old container and image are gone; the route points at the new one.
		expect(t.docker.containers.has(first?.container ?? '')).toBe(false);
		expect(t.docker.images.has(first?.image ?? '')).toBe(false);
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.3:8080' }]);
	});

	test('a build that never gets healthy fails and leaves the previous version serving', async () => {
		const t = await setup();
		await t.up(request());
		const first = (await t.store.get('hello-pr-7'))?.deployment;
		// Only the first container's address answers.
		t.setHealthy((url) => url.startsWith('http://172.19.0.2:'));
		await t.up(request({ id: 'cccccccccccccccc3' }));
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toContain('no answer on port 8080');
		expect(record?.error).toContain('logs of koi-hello-pr-7-cccccccccccccccc3');
		expect(record?.deployment).toEqual(first);
		expect(t.docker.containers.has('koi-hello-pr-7-cccccccccccccccc3')).toBe(false);
		expect(t.docker.images.has('koi-preview/hello-pr-7:cccccccccccccccc3')).toBe(false);
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.2:8080' }]);
	});

	test('a container that exits during start-up fails fast with its logs', async () => {
		const t = await setup();
		t.docker.crashing.add('koi-hello-pr-7-aaaaaaaaaaaaaaaa1');
		await t.up(request());
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toContain('stopped before it answered');
		expect(record?.deployment).toBeUndefined();
		expect(t.lastRoutes()).toEqual([]);
		// Still listed, so its address can explain the failure.
		expect(t.published.at(-1)).toEqual(['hello-pr-7']);
	});

	test('keeps the head and base a merge commit was built from, and names them in the log', async () => {
		const t = await setup();
		const merge = { head: 'b'.repeat(40), base: 'c'.repeat(40), baseBranch: 'develop' };
		await t.up(request({ merge }));
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('running');
		expect(record?.merge).toEqual(merge);
		const log = await readFile(logPath(t.stateDir, record), 'utf8');
		expect(log).toContain(
			`request aaaaaaaaaaaaaaaa1: github.com/acme/hello ${'a'.repeat(40)} (#7 at ${merge.head} merged into develop at ${merge.base})`,
		);
		// A working tree build, as before.
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) }));
		const plain = await t.store.get('hello-pr-7');
		expect(plain?.merge).toBeUndefined();
		expect(await readFile(logPath(t.stateDir, plain), 'utf8')).toContain(
			`request bbbbbbbbbbbbbbbb2: github.com/acme/hello ${'b'.repeat(40)}\n`,
		);
	});

	test('a failed build records the reason and writes the build log', async () => {
		const t = await setup();
		t.docker.buildError = 'docker build exited 1: RUN npm ci failed';
		await t.up(request());
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toContain('RUN npm ci failed');
		const log = await readFile(logPath(t.stateDir, record), 'utf8');
		expect(log).toContain('step 1/1');
		expect(log).toContain('failed:');
	});

	test('a request accepted again after it failed builds as a new attempt, with a new log', async () => {
		const t = await setup();
		t.docker.buildError = 'docker build exited 1: RUN npm ci failed';
		await t.up(request());
		const first = await t.store.get('hello-pr-7');
		expect(first?.status).toBe('failed');
		t.docker.buildError = undefined;
		await t.up(request());
		const second = await t.store.get('hello-pr-7');
		expect(second?.status).toBe('running');
		expect(second?.requestId).toBe(first?.requestId);
		expect(second?.attempt).not.toBe(first?.attempt);
		expect(await readdir(join(t.stateDir, 'logs', 'hello-pr-7'))).toEqual([
			`${second?.attempt}.build.log`,
		]);
		const log = await readFile(logPath(t.stateDir, second), 'utf8');
		expect(log).not.toContain('failed:');
		expect(log).toContain('ready');
		// Accepting it again once it is deployed changes nothing.
		await t.up(request());
		expect((await t.store.get('hello-pr-7'))?.attempt).toBe(second?.attempt);
	});

	test('the build log is written out before the record says how the build ended', async () => {
		// koi up reads the log to its end once the record says running or
		// failed, and stops there. This log keeps lines in memory until flush
		// or close, and its first flush waits until the test lets it go on.
		for (const buildError of [undefined, 'docker build exited 1: RUN npm ci failed']) {
			const t = await setup();
			t.docker.buildError = buildError;
			const log = heldLog();
			t.deps.buildLogs = { open: async () => log };
			// The lines written out when the record first said the build ended.
			let atEnd: string[] | undefined;
			const update = t.store.update.bind(t.store);
			t.store.update = (label, change) =>
				update(label, (r) => {
					const next = change(r);
					const ended = ['running', 'failed'].includes(next.status) && next.status !== r.status;
					if (ended && atEnd === undefined) atEnd = [...log.written];
					return next;
				});
			const done = t.up(request());
			await Promise.race([log.flushing.reached, done]);
			// While the flush waits, the record does not say the build ended.
			expect(['building', 'starting']).toContain((await t.store.get('hello-pr-7'))?.status ?? '');
			log.flushing.release();
			await done;
			expect(atEnd?.at(-1)).toBe(buildError === undefined ? 'ready' : `failed: ${buildError}`);
		}
	});

	test('masks key-shaped values in the build log and in the error the record keeps', async () => {
		const t = await setup();
		const token = `koi_${'0123456789abcdefghijklmnopqrstuv'}`;
		const key = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789';
		t.docker.buildOutput = [`#5 echo ${token}`, `#6 Authorization: Bearer ${key}`];
		// The health check fails, and the error carries the container's log.
		t.docker.containerLogs = `starting with ANTHROPIC_API_KEY=${key} and ${token}`;
		t.setHealthy(() => false);
		await t.up(request());
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toContain('no answer on port 8080');
		expect(record?.error).toContain('ANTHROPIC_API_KEY=[redacted]');
		const log = await readFile(logPath(t.stateDir, record), 'utf8');
		expect(log).toContain('#6 Authorization: Bearer [redacted]');
		for (const text of [record?.error ?? '', log]) {
			expect(text).not.toContain(token);
			expect(text).not.toContain(key);
		}
	});

	test('masks a Hugging Face token of letters only in the build log and the saved error', async () => {
		const t = await setup();
		// hf_ and 34 letters: no digit, so only its prefix gives it away.
		const token = `hf_${'AbCdEfGhIjKlMnOpQ'.repeat(2)}`;
		t.docker.buildOutput = [`#5 huggingface-cli login --token ${token}`];
		t.docker.containerLogs = `downloading the model as ${token}`;
		t.setHealthy(() => false);
		await t.up(request());
		const error = (await t.store.get('hello-pr-7'))?.error ?? '';
		expect(error).toContain('downloading the model as [redacted]');
		const log = await readFile(logPath(t.stateDir, await t.store.get('hello-pr-7')), 'utf8');
		expect(log).toContain('#5 huggingface-cli login --token [redacted]');
		expect(log).toContain('downloading the model as [redacted]');
		expect(error).not.toContain(token);
		expect(log).not.toContain(token);
	});

	test('keeps the checksums of a failed npm install in the build log', async () => {
		const t = await setup();
		const wanted = `sha512-${createHash('sha512').update('wanted').digest('base64')}`;
		const got = `sha512-${createHash('sha512').update('got').digest('base64')}`;
		const line = `#9 npm ERR! ${wanted} integrity checksum failed when using sha512: wanted ${wanted} but got ${got}. (1234 bytes)`;
		t.docker.buildOutput = [line];
		t.docker.buildError = 'docker buildx exited 1: npm ci failed';
		await t.up(request());
		const log = await readFile(logPath(t.stateDir, await t.store.get('hello-pr-7')), 'utf8');
		expect(log).toContain(line);
	});

	test('a build log that cannot be opened fails the request, and a retry builds it', async () => {
		const t = await setup();
		// A file where the log directory should be.
		await writeFile(join(t.stateDir, 'logs'), '');
		await t.up(request());
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toContain('ENOTDIR');
		expect(t.docker.builds).toHaveLength(0);
		await rm(join(t.stateDir, 'logs'));
		await t.up(request());
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(t.docker.builds).toHaveLength(1);
	});

	test('removes the request work directory whether the build fails or succeeds', async () => {
		const t = await setup();
		const work = (id: string) => join(t.stateDir, 'builds', 'hello-pr-7', id);
		t.docker.buildError = 'boom';
		await t.up(request());
		t.docker.buildError = undefined;
		await t.up(request({ id: 'dddddddddddddddd4' }));
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		// Both builds unpacked into their own directory, and neither is left.
		expect(t.extracted).toEqual([
			join(work('aaaaaaaaaaaaaaaa1'), 'src'),
			join(work('dddddddddddddddd4'), 'src'),
		]);
		for (const id of ['aaaaaaaaaaaaaaaa1', 'dddddddddddddddd4']) {
			await expect(stat(work(id))).rejects.toMatchObject({ code: 'ENOENT' });
		}
	});

	test('when Caddy refuses the cutover, the previous version stays recorded, running and routed', async () => {
		const t = await setup();
		await t.up(request());
		const first = (await t.store.get('hello-pr-7'))?.deployment;
		const routed = t.lastRoutes();
		t.rejectNextApply('caddy rejected the config: 400 bad');
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) }));
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toContain('caddy rejected');
		expect(record?.deployment).toEqual(first);
		expect((await t.docker.inspect(first?.container ?? '')).running).toBe(true);
		expect(t.docker.images.has(first?.image ?? '')).toBe(true);
		expect(t.lastRoutes()).toEqual(routed);
		// Only the new attempt's container and image are gone.
		expect(t.docker.containers.has('koi-hello-pr-7-bbbbbbbbbbbbbbbb2')).toBe(false);
		expect(t.docker.images.has('koi-preview/hello-pr-7:bbbbbbbbbbbbbbbb2')).toBe(false);
	});

	test('a failed attempt keeps its container while Caddy may still route to it', async () => {
		const t = await setup();
		await t.up(request());
		const first = (await t.store.get('hello-pr-7'))?.deployment;
		// Caddy refuses the cutover (it may have taken it before failing) and
		// the sync after the failure, which would have taken the route away.
		// The sync before the container starts passes.
		t.rejectApplies(2, undefined, 1);
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) }));
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.deployment).toEqual(first);
		expect(t.docker.containers.has('koi-hello-pr-7-bbbbbbbbbbbbbbbb2')).toBe(true);
		expect(t.docker.images.has('koi-preview/hello-pr-7:bbbbbbbbbbbbbbbb2')).toBe(true);
		// Once Caddy takes routes without it, reconcile removes it.
		await t.deployer.reconcile();
		expect(t.docker.containers.has('koi-hello-pr-7-bbbbbbbbbbbbbbbb2')).toBe(false);
		expect(t.docker.images.has('koi-preview/hello-pr-7:bbbbbbbbbbbbbbbb2')).toBe(false);
		expect(t.docker.containers.has(first?.container ?? '')).toBe(true);
	});

	test('a retry of that request removes the container its failed attempt left, then deploys', async () => {
		const t = await setup();
		await t.up(request());
		const retried = request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) });
		const left = 'koi-hello-pr-7-bbbbbbbbbbbbbbbb2';
		t.rejectApplies(2, undefined, 1);
		await t.up(retried);
		expect(t.docker.containers.has(left)).toBe(true);
		await t.up(retried);
		const record = await t.store.get('hello-pr-7');
		expect(record?.error).toBeUndefined();
		expect(record?.status).toBe('running');
		expect(record?.deployment?.container).toBe(left);
		expect(t.docker.runs.filter((r) => r.name === left)).toHaveLength(2);
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.4:8080' }]);
	});

	test('a retry fails, keeping the left container, while Caddy refuses routes without it', async () => {
		const t = await setup();
		await t.up(request());
		const retried = request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) });
		const left = 'koi-hello-pr-7-bbbbbbbbbbbbbbbb2';
		t.rejectApplies(2, undefined, 1);
		await t.up(retried);
		t.rejectApplies(1);
		await t.up(retried);
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toBe(
			`${left}, left by an earlier attempt of this request, stays until Caddy takes routes without it; run koi up again: caddy rejected the config: 400 bad`,
		);
		expect(t.docker.containers.has(left)).toBe(true);
		expect(t.docker.runs.filter((r) => r.name === left)).toHaveLength(1);
	});

	test('a failed attempt is cleaned up even when its failure cannot be recorded', async () => {
		const t = await setup();
		t.setHealthy(() => false);
		// The store refuses to write the failure, as on a full disk.
		const update = t.store.update.bind(t.store);
		t.store.update = async (label, change) => {
			const current = await t.store.get(label);
			if (current !== undefined && change(current).status === 'failed') {
				throw new Error('ENOSPC: no space left on device');
			}
			return update(label, change);
		};
		await t.up(request());
		expect(t.docker.containers.has('koi-hello-pr-7-aaaaaaaaaaaaaaaa1')).toBe(false);
		expect(t.logs.join('\n')).toContain('ENOSPC');
	});

	test('a build superseded while it ran is discarded instead of cut over', async () => {
		const t = await setup();
		await t.up(request());
		// The second build waits in its health check while a third is accepted.
		const gate = t.hold('probe');
		t.addRequest(request({ id: 'bbbbbbbbbbbbbbbb2' }));
		await t.deployer.up('bbbbbbbbbbbbbbbb2');
		await gate.reached;
		t.addRequest(request({ id: 'cccccccccccccccc3' }));
		await t.deployer.up('cccccccccccccccc3');
		gate.release();
		await t.deployer.settled('hello-pr-7');
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('running');
		expect(record?.deployment?.requestId).toBe('cccccccccccccccc3');
		// The second build's container (172.19.0.3) was never routed.
		expect(t.applied.flat().map((r) => r.upstream)).not.toContain('172.19.0.3:8080');
		expect(t.docker.containers.has('koi-hello-pr-7-bbbbbbbbbbbbbbbb2')).toBe(false);
		expect(t.docker.images.has('koi-preview/hello-pr-7:bbbbbbbbbbbbbbbb2')).toBe(false);
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.4:8080' }]);
	});

	test('retrying a request that already deployed changes nothing', async () => {
		const t = await setup();
		await t.up(request());
		const before = await t.store.get('hello-pr-7');
		const routed = t.lastRoutes();
		expect(await t.up(request())).toEqual({ label: 'hello-pr-7', queued: false });
		expect(t.docker.builds).toHaveLength(1);
		expect(await t.store.get('hello-pr-7')).toEqual(before);
		expect(t.docker.containers.has(before?.deployment?.container ?? '')).toBe(true);
		expect(t.docker.images.has(before?.deployment?.image ?? '')).toBe(true);
		expect(t.lastRoutes()).toEqual(routed);
	});

	test('retrying a request that is still building starts nothing new', async () => {
		const t = await setup();
		const gate = t.hold('keepAwake');
		t.addRequest(request());
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		await gate.reached;
		expect((await t.store.get('hello-pr-7'))?.status).toBe('building');
		expect(await t.deployer.up('aaaaaaaaaaaaaaaa1')).toEqual({
			label: 'hello-pr-7',
			queued: false,
		});
		gate.release();
		await t.deployer.settled('hello-pr-7');
		expect(t.docker.builds).toHaveLength(1);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
	});

	test('a retry after koi down, while the first build runs, deploys once and is not marked failed', async () => {
		const t = await setup();
		// The first build of the request is under way.
		const gate = t.hold('keepAwake');
		t.addRequest(request());
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		await gate.reached;
		const first = (await t.store.get('hello-pr-7'))?.attempt;
		// koi down removes the record; the same request is sent again and
		// queues a second build behind the first.
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		expect(await t.deployer.up('aaaaaaaaaaaaaaaa1')).toEqual({ label: 'hello-pr-7', queued: true });
		const second = (await t.store.get('hello-pr-7'))?.attempt;
		expect(second).not.toBe(first);
		gate.release();
		await t.deployer.settled('hello-pr-7');
		// The first build saw the record was no longer its own and stood down;
		// the second deployed.
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('running');
		expect(record?.error).toBeUndefined();
		expect(record?.attempt).toBe(second);
		expect(record?.deployment?.requestId).toBe('aaaaaaaaaaaaaaaa1');
		const container = record?.deployment?.container ?? '';
		expect((await t.docker.inspect(container)).running).toBe(true);
		expect(t.docker.runs.filter((r) => r.name === container)).toHaveLength(1);
		expect(t.lastRoutes()).toHaveLength(1);
		const log = await readFile(logPath(t.stateDir, record), 'utf8');
		expect(log).not.toContain('already exists');
	});

	test('a build queued before koi down and a retry skips itself', async () => {
		const t = await setup();
		// Another preview's build holds the box, so this one waits in the queue.
		const gate = t.hold('keepAwake');
		t.addRequest(request({ id: 'oooooooooooooooo9', label: 'other', pr: 8 }));
		await t.deployer.up('oooooooooooooooo9');
		await gate.reached;
		t.addRequest(request());
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		gate.release();
		await t.deployer.settled('other');
		await t.deployer.settled('hello-pr-7');
		expect(t.logs).toContain(
			'build aaaaaaaaaaaaaaaa1 for hello-pr-7: superseded before it started',
		);
		expect(t.docker.builds.filter((b) => b.labels['koi.preview'] === 'hello-pr-7')).toHaveLength(1);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
	});

	test('a build that fails after koi down and a retry leaves the retry its own status', async () => {
		const t = await setup();
		// The first build waits in its health check.
		const probing = t.hold('probe');
		t.addRequest(request());
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		await probing.reached;
		// koi down removes its container, and the retry is queued.
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		// The retry's build waits once it has started.
		const retrying = t.hold('keepAwake');
		probing.release();
		await retrying.reached;
		// The first build failed (its container went), and wrote nothing.
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('building');
		expect(record?.error).toBeUndefined();
		retrying.release();
		await t.deployer.settled('hello-pr-7');
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
	});

	test('records an accepted request as queued before answering', async () => {
		const t = await setup();
		await t.up(request());
		const gate = t.hold('keepAwake');
		t.addRequest(request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) }));
		// Holds the global build slot, so the next request has to wait.
		await t.deployer.up('bbbbbbbbbbbbbbbb2');
		await gate.reached;
		t.addRequest(request({ id: 'cccccccccccccccc3', commit: 'c'.repeat(40) }));
		expect(await t.deployer.up('cccccccccccccccc3')).toEqual({
			label: 'hello-pr-7',
			queued: true,
		});
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('queued');
		expect(record?.requestId).toBe('cccccccccccccccc3');
		expect(record?.commit).toBe('c'.repeat(40));
		expect(record?.deployment?.requestId).toBe('aaaaaaaaaaaaaaaa1');
		gate.release();
		await t.deployer.settled('hello-pr-7');
	});

	test('of two first deployments from different repos, exactly one is accepted', async () => {
		const t = await setup();
		t.addRequest(request());
		t.addRequest(request({ id: 'eeeeeeeeeeeeeeee5', repo: 'github.com/evil/hello' }));
		const results = await Promise.allSettled([
			t.deployer.up('aaaaaaaaaaaaaaaa1'),
			t.deployer.up('eeeeeeeeeeeeeeee5'),
		]);
		const refused = results.flatMap((r) => (r.status === 'rejected' ? [r.reason] : []));
		expect(refused).toHaveLength(1);
		expect(refused[0]).toBeInstanceOf(OwnershipError);
		await t.deployer.settled('hello-pr-7');
		expect(t.docker.builds).toHaveLength(1);
		const accepted =
			results[0]?.status === 'fulfilled' ? 'github.com/acme/hello' : 'github.com/evil/hello';
		expect((await t.store.get('hello-pr-7'))?.repo).toBe(accepted);
	});

	test('refuses a label that belongs to another repo before changing anything', async () => {
		const t = await setup();
		await t.up(request());
		t.addRequest(request({ id: 'eeeeeeeeeeeeeeee5', repo: 'github.com/evil/hello' }));
		await expect(t.deployer.up('eeeeeeeeeeeeeeee5')).rejects.toBeInstanceOf(OwnershipError);
		expect((await t.store.get('hello-pr-7'))?.requestId).toBe('aaaaaaaaaaaaaaaa1');
		expect(t.docker.builds).toHaveLength(1);
	});

	test('refuses a new label once the live list would pass the 4096 bytes its parameter holds', async () => {
		const t = await setup();
		await seedLive(t, 62);
		// The 63rd fills the list exactly.
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', label: long(62), pr: 62 }));
		expect((await t.store.get(long(62)))?.status).toBe('running');
		expect(t.published.at(-1)).toHaveLength(63);
		expect(JSON.stringify(t.published.at(-1)).length).toBe(4096);
		// A 64th, however short, does not fit, and nothing changes.
		t.addRequest(request({ id: 'cccccccccccccccc3', label: 'a', pr: 64 }));
		const refused = t.deployer.up('cccccccccccccccc3');
		await expect(refused).rejects.toBeInstanceOf(CapacityError);
		await expect(refused).rejects.toThrow(
			'koi has 63 live previews, and the list that lets a visit wake the box cannot take a as well: it would pass the 4096 bytes its SSM parameter holds; remove a preview with koi down NAME and run koi up again',
		);
		expect(await t.store.get('a')).toBeUndefined();
		expect(t.docker.builds).toHaveLength(1);
		// A label already live still redeploys, and one that expired frees room.
		await t.up(request({ id: 'dddddddddddddddd4', label: long(62), pr: 62 }));
		expect((await t.store.get(long(62)))?.deployment?.requestId).toBe('dddddddddddddddd4');
		await t.store.update(long(0), (r) => ({ ...r, status: 'expired' }));
		await t.up(request({ id: 'cccccccccccccccc3', label: 'a', pr: 64 }));
		expect((await t.store.get('a'))?.status).toBe('running');
	});

	test('claims the upload as it accepts the request and releases it once the source is copied', async () => {
		const t = await setup();
		const r = request({ id: 'cccccccccccccccc3', label: 'a' });
		t.addRequest(r);
		const gate = t.hold('keepAwake');
		await t.deployer.up(r.id);
		await gate.reached;
		// Accepted and building, the source not copied yet: the claim holds.
		expect(t.uploadEvents).toEqual([`claim ${r.id}`]);
		gate.release();
		await t.deployer.settled('a');
		expect(t.uploadEvents).toEqual([`claim ${r.id}`, `download ${r.id}`, `release ${r.id}`]);
		expect((await t.store.get('a'))?.status).toBe('running');
		// Accepting the same request again while it is deployed changes
		// nothing, and claims nothing.
		await t.up(r);
		expect(t.uploadEvents).toHaveLength(3);
	});

	test('releases the claim when the build fails before it copies the source', async () => {
		const t = await setup();
		const r = request({ id: 'cccccccccccccccc3', label: 'a' });
		// No room on the disk: makeRoom refuses the build before the download.
		t.disk.free = 0;
		await t.up(r);
		expect((await t.store.get('a'))?.status).toBe('failed');
		expect(t.uploadEvents).toEqual([`claim ${r.id}`, `release ${r.id}`]);
	});

	test('releases the claim when the request is refused after it was claimed', async () => {
		const t = await setup();
		await seedLive(t, 63);
		const r = request({ id: 'cccccccccccccccc3', label: 'a', pr: 64 });
		t.addRequest(r);
		await expect(t.deployer.up(r.id)).rejects.toBeInstanceOf(CapacityError);
		expect(t.uploadEvents).toEqual([`claim ${r.id}`, `release ${r.id}`]);
		expect(await t.store.get('a')).toBeUndefined();
	});

	test('releases the claim when the record cannot be read as the build starts', async () => {
		const t = await setup();
		const r = request({ id: 'cccccccccccccccc3', label: 'a' });
		t.addRequest(r);
		// The first read after the record is written is the build's check
		// that its attempt is still the latest; it fails.
		let fail = false;
		const get = t.store.get.bind(t.store);
		const upsert = t.store.upsert.bind(t.store);
		const writing = spyOn(t.store, 'upsert').mockImplementation(async (label, change) => {
			const record = await upsert(label, change);
			fail = true;
			return record;
		});
		const reading = spyOn(t.store, 'get').mockImplementation(async (label) => {
			if (!fail) return get(label);
			fail = false;
			throw Object.assign(new Error('EIO: i/o error, read'), { code: 'EIO' });
		});
		try {
			await t.deployer.up(r.id);
			await t.deployer.settled('a');
		} finally {
			writing.mockRestore();
			reading.mockRestore();
		}
		expect(t.uploadEvents).toEqual([`claim ${r.id}`, `release ${r.id}`]);
		expect(t.logs).toContain(`build ${r.id} for a: failed: EIO: i/o error, read`);
		expect((await t.store.get('a'))?.status).toBe('failed');
	});

	test('refuses a request whose upload is gone before it is accepted, recording nothing', async () => {
		const t = await setup();
		const r = request({ id: 'cccccccccccccccc3', label: 'a' });
		t.addRequest(r);
		t.rejectClaims(`no upload for request ${r.id}`);
		await expect(t.deployer.up(r.id)).rejects.toThrow(`no upload for request ${r.id}`);
		expect(await t.store.get('a')).toBeUndefined();
		expect(t.uploadEvents).toEqual([]);
	});

	test('a live list with no cap takes the label an SSM parameter could not', async () => {
		const t = await setup({ unboundedLive: true });
		await seedLive(t, 63);
		await t.up(request({ id: 'cccccccccccccccc3', label: 'a', pr: 64 }));
		expect((await t.store.get('a'))?.status).toBe('running');
		expect(t.published.at(-1)).toHaveLength(64);
		expect(JSON.stringify(t.published.at(-1)).length).toBeGreaterThan(4096);
	});

	test('two new labels racing for the last room do not both get it', async () => {
		const t = await setup();
		await seedLive(t, 62);
		t.addRequest(request({ id: 'bbbbbbbbbbbbbbbb2', label: long(62), pr: 62 }));
		t.addRequest(request({ id: 'cccccccccccccccc3', label: long(63), pr: 63 }));
		const results = await Promise.allSettled([
			t.deployer.up('bbbbbbbbbbbbbbbb2'),
			t.deployer.up('cccccccccccccccc3'),
		]);
		expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1);
		await t.deployer.settled(long(62));
		await t.deployer.settled(long(63));
	});

	test('builds a built-in recipe from a copy of its directory in the build directory, not the source tree', async () => {
		const builtin = RecipeSchema.parse({
			name: 'hello',
			port: 9000,
			build: { kind: 'dockerfile', from: 'recipe', path: 'Dockerfile', context: '.' },
		});
		const t = await setup({ builtin });
		await t.up(request({ recipe: { kind: 'builtin', name: 'hello' } }));
		const build = t.docker.builds[0];
		const copy = join('builds', 'hello-pr-7', 'aaaaaaaaaaaaaaaa1', 'recipe');
		expect(build?.dockerfile).toEndWith(join(copy, 'Dockerfile'));
		expect(build?.dockerfile).not.toContain(join(t.root, 'recipes'));
		expect(build?.contexts?.recipe).toEndWith(copy);
		expect(build?.context).toContain(join('builds', 'hello-pr-7', 'aaaaaaaaaaaaaaaa1', 'src'));
		expect(t.lastRoutes()[0]?.upstream).toEndWith(':9000');
		// The copy went with the build directory.
		expect(
			await stat(join(t.stateDir, 'builds', 'hello-pr-7', 'aaaaaaaaaaaaaaaa1')).catch(
				() => undefined,
			),
		).toBeUndefined();
	});
});

describe('sameOwner', () => {
	const base = { repo: 'github.com/acme/hello', status: 'running' } as const;
	test('a pull request label belongs to that pull request of that repo', () => {
		const r = { ...base, pr: 7, branch: 'a' };
		expect(sameOwner(r as never, request({ pr: 7, branch: 'renamed' }))).toBe(true);
		expect(sameOwner(r as never, request({ pr: 8 }))).toBe(false);
		expect(sameOwner(r as never, request({ repo: 'github.com/other/hello' }))).toBe(false);
	});

	test('a branch label belongs to that exact branch', () => {
		const r = { ...base, branch: 'feature/x' };
		const { pr: _pr, ...noPr } = request();
		expect(sameOwner(r as never, { ...noPr, branch: 'feature/x' })).toBe(true);
		expect(sameOwner(r as never, { ...noPr, branch: 'feature-x' })).toBe(false);
		expect(sameOwner(r as never, request({ pr: 7 }))).toBe(false);
	});

	test('an expired label is free', () => {
		const r = { ...base, status: 'expired', repo: 'github.com/someone/else', branch: 'x' };
		expect(sameOwner(r as never, request())).toBe(true);
	});
});

describe('chooseUser', () => {
	test('prefers the recipe, then a numeric non-root image user, then nobody', () => {
		expect(chooseUser('1000:1000', 'root')).toBe('1000:1000');
		expect(chooseUser('1000', '1001')).toBe('1000:1000');
		expect(chooseUser(undefined, '1001')).toBe('1001:1001');
		expect(chooseUser(undefined, '1001:0')).toBe('1001:0');
		expect(chooseUser(undefined, ' 1001:1002 ')).toBe('1001:1002');
		expect(chooseUser(undefined, '65534:65534')).toBe('65534:65534');
	});

	test('runs as nobody for names, root in any spelling, or no user', () => {
		// A name means whatever the image's /etc/passwd says; "app" can be uid 0.
		for (const user of [
			'',
			' ',
			'root',
			'app',
			'storefront',
			'app:app',
			'1000:app',
			'0',
			'00',
			'0:0',
			'000:5',
			'root:root',
		]) {
			expect(chooseUser(undefined, user)).toBe('65534:65534');
		}
	});

	test('refuses a recipe user that is not a numeric non-root user', () => {
		expect(() => chooseUser('00', '1000')).toThrow();
		expect(() => chooseUser('app', '1000')).toThrow();
	});
});

describe('ensureRunning', () => {
	test('starts a stopped preview once, however many visitors ask', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		expect(t.lastRoutes()).toEqual([]);
		await Promise.all([1, 2, 3].map(() => t.deployer.ensureRunning('hello-pr-7')));
		expect(t.docker.starts).toEqual(['koi-hello-pr-7-aaaaaaaaaaaaaaaa1']);
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('recreates a container that disappeared, from the deployed image', async () => {
		const t = await setup();
		await t.up(request());
		const d = (await t.store.get('hello-pr-7'))?.deployment;
		await t.docker.remove(d?.container ?? '');
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.docker.runs.at(-1)?.image).toBe(d?.image ?? '');
		expect(t.docker.runs.at(-1)?.user).toBe(d?.user ?? '');
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('does nothing for an unknown label', async () => {
		const t = await setup();
		await t.deployer.ensureRunning('nobody');
		expect(t.docker.starts).toEqual([]);
	});

	test('a start in progress holds the label, so down cannot leave a container behind', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		// The start has read the record and waits before touching Docker.
		const gate = t.hold('keepAwake');
		const wake = t.deployer.ensureRunning('hello-pr-7');
		await gate.reached;
		const removed = t.deployer.down('hello-pr-7');
		// Without the lock, down removes everything here and the start then
		// recreates a container nothing refers to.
		await Promise.race([removed, Bun.sleep(100)]);
		gate.release();
		await Promise.all([wake, removed]);
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect(t.docker.containers.size).toBe(0);
		expect(t.lastRoutes()).toEqual([]);
	});

	test('a container that never answers is stopped, the reason recorded, and nothing retried', async () => {
		const t = await setup();
		await t.up(request());
		const before = await t.store.get('hello-pr-7');
		t.docker.stopAll();
		await t.deployer.sync();
		t.setHealthy(() => false);
		await t.deployer.ensureRunning('hello-pr-7');
		const after = await t.store.get('hello-pr-7');
		expect(after?.status).toBe('running');
		expect(after?.deployment).toEqual(before?.deployment);
		expect(after?.error).toContain('the preview did not start: no answer on port 8080');
		expect((await t.docker.inspect(before?.deployment?.container ?? '')).running).toBe(false);
		expect(t.docker.starts).toHaveLength(1);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'stopped' });
		// The next visit tries again, and success clears the reason.
		t.setHealthy(undefined);
		await t.deployer.ensureRunning('hello-pr-7');
		expect((await t.store.get('hello-pr-7'))?.error).toBeUndefined();
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
	});

	test('masks key-shaped values in the error a failed start records', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		const token = `koi_${'0123456789abcdefghijklmnopqrstuv'}`;
		t.docker.containerLogs = `calling the provider with ${token}`;
		t.setHealthy(() => false);
		await t.deployer.ensureRunning('hello-pr-7');
		const error = (await t.store.get('hello-pr-7'))?.error ?? '';
		expect(error).toContain('the preview did not start: no answer on port 8080');
		expect(error).toContain('calling the provider with [redacted]');
		expect(error).not.toContain(token);
	});

	test('a container that never answers is stopped even when the failure cannot be recorded', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		await t.deployer.sync();
		t.setHealthy(() => false);
		// The store refuses to write the failure, as on a full disk.
		const update = t.store.update.bind(t.store);
		t.store.update = async (label, change) => {
			const current = await t.store.get(label);
			if (current !== undefined && change(current).error?.startsWith('the preview did not start')) {
				throw new Error('ENOSPC: no space left on device');
			}
			return update(label, change);
		};
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([container]);
		expect((await t.docker.inspect(container)).running).toBe(false);
		expect(t.lastRoutes()).toEqual([]);
		expect(t.logs.join('\n')).toContain(`recording that hello-pr-7 did not start: ENOSPC`);
	});

	test('a sync during the health check does not route the container, and a failed check unroutes it before it stops', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		await t.deployer.sync();
		t.setHealthy(() => false);
		const gate = t.hold('probe');
		const wake = t.deployer.ensureRunning('hello-pr-7');
		await gate.reached;
		// Started, with an address, and not yet healthy.
		expect((await t.docker.inspect(container)).running).toBe(true);
		await t.deployer.sync();
		expect(t.lastRoutes()).toEqual([]);
		gate.release();
		await wake;
		expect((await t.docker.inspect(container)).running).toBe(false);
		expect(t.lastRoutes()).toEqual([]);
	});

	test('a sync that overlaps a wake does not route the restarted container before it answers', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		// The container exits on its own while it is ready and routed.
		await t.docker.stop(container);
		// A sync has read the records and waits in its inspection of it.
		const inspecting = t.hold('inspect');
		const syncing = t.deployer.sync();
		await inspecting.reached;
		// A visit wakes the preview meanwhile, and its health check waits.
		const checking = t.hold('probe');
		const wake = t.deployer.ensureRunning('hello-pr-7');
		await Promise.race([checking.reached, Bun.sleep(50)]);
		inspecting.release();
		await syncing;
		// Here the sync would have found the restarted container running at
		// its new address, and routed it.
		expect(t.lastRoutes()).toEqual([]);
		await checking.reached;
		expect(t.lastRoutes()).toEqual([]);
		checking.release();
		await wake;
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.3:8080' }]);
	});

	test('a container that failed its health check keeps running while Caddy refuses routes', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		await t.deployer.sync();
		t.setHealthy(() => false);
		// The sync before the start passes; the one that would unroute it fails.
		t.rejectApplies(1, 'caddy rejected the config: 400 bad', 1);
		await t.deployer.ensureRunning('hello-pr-7');
		// Stopping it would free an address Caddy may still route to.
		expect((await t.docker.inspect(container)).running).toBe(true);
		expect((await t.store.get('hello-pr-7'))?.error).toContain('the preview did not start');
		expect(t.logs.join('\n')).toContain(`keeping ${container}`);
		// The next visit checks it again, and routes it once it answers.
		t.setHealthy(undefined);
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('expires a preview past its ttl instead of starting it', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		t.advance(8 * 86_400_000);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'overdue' });
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([]);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('expired');
		expect(t.docker.containers.size).toBe(0);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'expired' });
	});
});

describe('view', () => {
	test('reports running only for a routed preview', async () => {
		const t = await setup();
		await t.up(request());
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
		// Running in Docker, but Caddy does not route to it.
		t.docker.stopAll();
		await t.deployer.sync();
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		await t.docker.start(container);
		expect((await t.docker.inspect(container)).running).toBe(true);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'stopped' });
	});

	test('reports a routed container that has exited as stopped, and takes its route away', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		// It exits on its own; nothing has synced since.
		await t.docker.stop(container);
		expect(t.lastRoutes()).toHaveLength(1);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'stopped' });
		await eventually(() => t.lastRoutes().length === 0);
	});
});

describe('expire', () => {
	test('a redeploy after a quiet spell counts as use', async () => {
		const t = await setup();
		await t.up(request());
		await t.deployer.recordVisits([['hello-pr-7', t.now()]]);
		t.advance(10 * 86_400_000);
		// Expiry has not run yet; a new deploy lands first.
		await t.up(request({ id: 'ffffffffffffffff6', commit: 'f'.repeat(40) }));
		expect(await t.deployer.expire()).toEqual([]);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
	});

	test('removes a preview nobody visited for its ttl and keeps a tombstone', async () => {
		const t = await setup();
		await t.up(request());
		t.advance(6 * 86_400_000);
		expect(await t.deployer.expire()).toEqual([]);
		t.advance(2 * 86_400_000);
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('expired');
		expect(record?.deployment).toBeUndefined();
		expect(t.docker.containers.size).toBe(0);
		expect(t.docker.images.size).toBe(0);
		await t.deployer.published();
		expect(t.published.at(-1)).toEqual([]);
	});

	test('a visit pushes expiry back', async () => {
		const t = await setup();
		await t.up(request());
		t.advance(6 * 86_400_000);
		await t.deployer.recordVisits([['hello-pr-7', Date.parse('2026-10-12T12:00:00.000Z')]]);
		t.advance(2 * 86_400_000);
		expect(await t.deployer.expire()).toEqual([]);
	});

	test('takes the preview out of the routes before removing its container', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.advance(8 * 86_400_000);
		const gate = t.hold('apply');
		const expiring = t.deployer.expire();
		await gate.reached;
		// The record already says expired and names no container; the container
		// is still there.
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('expired');
		expect(record?.deployment).toBeUndefined();
		expect(t.docker.containers.has(container)).toBe(true);
		gate.release();
		expect(await expiring).toEqual(['hello-pr-7']);
		expect(t.docker.containers.has(container)).toBe(false);
		expect(t.lastRoutes()).toEqual([]);
	});

	test('keeps the container when Caddy refuses the routes without it', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.advance(8 * 86_400_000);
		t.rejectNextApply('caddy rejected the config: 400 bad');
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('expired');
		expect(t.docker.containers.has(container)).toBe(true);
		await t.deployer.reconcile();
		expect(t.docker.containers.has(container)).toBe(false);
	});

	test('reads the record again under the lock, so a visit that lands first saves it', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		// A wake holds the label while the preview passes its ttl.
		const gate = t.hold('keepAwake');
		const wake = t.deployer.ensureRunning('hello-pr-7');
		await gate.reached;
		// Someone visits a minute before the deadline; the visit is written
		// after expiry has listed the preview as overdue.
		t.advance(7 * 86_400_000 - 60_000);
		const visitedAt = t.now();
		t.advance(120_000);
		const expiring = t.deployer.expire();
		await t.deployer.recordVisits([['hello-pr-7', visitedAt]]);
		gate.release();
		await wake;
		expect(await expiring).toEqual([]);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(t.lastRoutes()).toHaveLength(1);
	});

	// When the preview just deployed in `t` passes its ttl.
	async function deadlineOf(t: Awaited<ReturnType<typeof setup>>): Promise<number> {
		const record = await t.store.get('hello-pr-7');
		return (
			Math.max(
				Date.parse(record?.updatedAt ?? ''),
				Date.parse(record?.deployment?.deployedAt ?? ''),
			) +
			7 * 86_400_000
		);
	}

	test('writes visits not yet saved before deciding, so one in time renews the preview', async () => {
		const t = await setup();
		await t.up(request());
		const deadline = await deadlineOf(t);
		t.advance(deadline - 5_000 - t.now());
		t.activity.visit('hello-pr-7');
		// Past the deadline, with the visit still in memory.
		t.advance(10_000);
		expect(await t.deployer.expire()).toEqual([]);
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBe(
			new Date(deadline - 5_000).toISOString(),
		);
	});

	test('waits for visits another flush is writing before deciding', async () => {
		const t = await setup();
		await t.up(request());
		const deadline = await deadlineOf(t);
		t.advance(deadline - 5_000 - t.now());
		t.activity.visit('hello-pr-7');
		t.advance(10_000);
		// The 30-second flush has taken the visit and not yet written it.
		const update = t.store.update.bind(t.store);
		const gate = new Gate();
		t.store.update = async (label, change) => {
			t.store.update = update;
			await gate.pass();
			return update(label, change);
		};
		const flushing = t.deployer.flushVisits();
		await gate.reached;
		const expiring = t.deployer.expire();
		await Bun.sleep(20);
		gate.release();
		await flushing;
		expect(await expiring).toEqual([]);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
	});

	test('a wake writes visits not yet saved before deciding the preview is overdue', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		const deadline = await deadlineOf(t);
		t.advance(deadline - 5_000 - t.now());
		t.activity.visit('hello-pr-7');
		t.advance(10_000);
		await t.deployer.ensureRunning('hello-pr-7');
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(t.docker.starts).toHaveLength(1);
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('a page view writes visits not yet saved before calling the preview overdue', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		const deadline = await deadlineOf(t);
		t.advance(deadline - 5_000 - t.now());
		t.activity.visit('hello-pr-7');
		t.advance(10_000);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'stopped' });
		// With nothing pending, a preview past its new deadline is overdue.
		t.advance(7 * 86_400_000);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'overdue' });
	});

	// The store refuses to write visits to `label`, as on a full disk.
	function refuseVisitWrites(t: Awaited<ReturnType<typeof setup>>, label = 'hello-pr-7') {
		const update = t.store.update.bind(t.store);
		t.store.update = async (l, change) => {
			const current = await t.store.get(l);
			if (
				l === label &&
				current !== undefined &&
				change(current).lastVisitAt !== current.lastVisitAt
			) {
				throw new Error('ENOSPC: no space left on device');
			}
			return update(l, change);
		};
		return () => {
			t.store.update = update;
		};
	}

	test('a visit in time whose write fails stays pending, and the preview does not expire', async () => {
		const t = await setup();
		await t.up(request());
		const deadline = await deadlineOf(t);
		t.advance(deadline - 5_000 - t.now());
		t.activity.visit('hello-pr-7');
		const allow = refuseVisitWrites(t);
		await t.deployer.flushVisits().catch(() => {});
		expect(t.logs.join('\n')).toContain(
			'writing visits to hello-pr-7: ENOSPC: no space left on device; kept for the next try',
		);
		// Past the deadline, with the write still failing.
		t.advance(10_000);
		expect(await t.deployer.expire()).toEqual([]);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		// With room again, the next decision writes it first.
		allow();
		expect(await t.deployer.expire()).toEqual([]);
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBe(
			new Date(deadline - 5_000).toISOString(),
		);
		// Seven days on with no other visit, it expires as usual.
		t.advance(7 * 86_400_000);
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
	});

	test('a wake starts a preview that a visit it could not write renewed', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		const deadline = await deadlineOf(t);
		t.advance(deadline - 5_000 - t.now());
		t.activity.visit('hello-pr-7');
		refuseVisitWrites(t);
		await t.deployer.flushVisits().catch(() => {});
		t.advance(10_000);
		await t.deployer.ensureRunning('hello-pr-7');
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(t.docker.starts).toHaveLength(1);
	});

	test('a failed write for one preview does not hold up the others', async () => {
		const t = await setup();
		await t.up(request());
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', label: 'other', pr: 8 }));
		t.activity.visit('hello-pr-7');
		t.activity.visit('other');
		refuseVisitWrites(t);
		await t.deployer.flushVisits().catch(() => {});
		expect((await t.store.get('other'))?.lastVisitAt).toBe(new Date(t.now()).toISOString());
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBeUndefined();
	});

	test('a visit after the deadline does not hold off expiry, written or not', async () => {
		const t = await setup();
		await t.up(request());
		const deadline = await deadlineOf(t);
		t.advance(deadline + 5_000 - t.now());
		t.activity.visit('hello-pr-7');
		refuseVisitWrites(t);
		t.advance(5_000);
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
	});

	// A request whose recipe keeps an unvisited preview for one day.
	function daily() {
		const base = request();
		if (base.recipe.kind !== 'repo') throw new Error('expected a repo recipe');
		return request({ recipe: { kind: 'repo', recipe: { ...base.recipe.recipe, ttlDays: 1 } } });
	}
	const HOUR = 3_600_000;

	test('steady visits while writes fail for a day and a half keep the preview, and the latest is written once they work', async () => {
		const t = await setup();
		await t.up(daily());
		const start = t.now();
		const allow = refuseVisitWrites(t);
		// A visit every ten minutes from hour 12 to hour 48; flushes and
		// expiry run as often as they do in koid.
		t.advance(12 * HOUR);
		while (t.now() <= start + 48 * HOUR) {
			t.activity.visit('hello-pr-7');
			await t.deployer.flushVisits();
			expect(await t.deployer.expire()).toEqual([]);
			t.advance(10 * 60_000);
		}
		const last = t.now() - 10 * 60_000;
		allow();
		await t.deployer.flushVisits();
		expect(await t.deployer.expire()).toEqual([]);
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('running');
		expect(record?.lastVisitAt).toBe(new Date(last).toISOString());
		const d = record?.deployment;
		expect(t.docker.containers.has(d?.container ?? '')).toBe(true);
		expect(t.docker.images.has(d?.image ?? '')).toBe(true);
	});

	test('with a one-day ttl, visits at days 0.9, 1.5 and 2.2 all count while writes fail', async () => {
		const t = await setup();
		await t.up(daily());
		const start = t.now();
		const allow = refuseVisitWrites(t);
		for (const day of [0.9, 1.5, 2.2]) {
			t.advance(start + day * 24 * HOUR - t.now());
			t.activity.visit('hello-pr-7');
			await t.deployer.flushVisits();
			expect(await t.deployer.expire()).toEqual([]);
		}
		// The deadline the chain reached is day 3.2.
		t.advance(start + 3.1 * 24 * HOUR - t.now());
		expect(await t.deployer.expire()).toEqual([]);
		allow();
		await t.deployer.flushVisits();
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBe(
			new Date(start + 2.2 * 24 * HOUR).toISOString(),
		);
		t.advance(0.2 * 24 * HOUR);
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
	});

	test('a preview with a pending visit in time still expires a ttl after it, while writes keep failing', async () => {
		const t = await setup();
		await t.up(daily());
		const start = t.now();
		refuseVisitWrites(t);
		t.advance(20 * HOUR);
		t.activity.visit('hello-pr-7');
		await t.deployer.flushVisits();
		// Past the record's own deadline, inside the visit's.
		t.advance(10 * HOUR);
		expect(await t.deployer.expire()).toEqual([]);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
		// Past the visit's deadline too, with nothing written.
		t.advance(start + 44 * HOUR + 1 - t.now());
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'overdue' });
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
	});

	test('a gap past the deadline breaks the chain: the visit after it does not count', async () => {
		const t = await setup();
		await t.up(daily());
		const start = t.now();
		refuseVisitWrites(t);
		t.advance(12 * HOUR);
		t.activity.visit('hello-pr-7');
		await t.deployer.flushVisits();
		// The visit at hour 12 holds it until hour 36; the next comes at 40.
		t.advance(start + 40 * HOUR - t.now());
		t.activity.visit('hello-pr-7');
		await t.deployer.flushVisits();
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
	});

	// The next store update fails before it reads the record, as on an I/O
	// error; the ones after work.
	function failNextRead(t: Awaited<ReturnType<typeof setup>>) {
		const update = t.store.update.bind(t.store);
		t.store.update = async () => {
			t.store.update = update;
			throw new Error('EIO: i/o error reading the record');
		};
	}

	test('a visit in time whose record could not be read keeps the preview from expiring', async () => {
		const t = await setup();
		await t.up(daily());
		const start = t.now();
		t.advance(24 * HOUR - 1_000);
		t.activity.visit('hello-pr-7');
		t.advance(2_000);
		// The flush before expiry cannot read the record; everything after can.
		failNextRead(t);
		expect(await t.deployer.expire()).toEqual([]);
		expect(t.logs.join('\n')).toContain('writing visits to hello-pr-7: EIO');
		const d = (await t.store.get('hello-pr-7'))?.deployment;
		expect(t.docker.containers.has(d?.container ?? '')).toBe(true);
		expect(t.docker.images.has(d?.image ?? '')).toBe(true);
		await t.deployer.flushVisits();
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBe(
			new Date(start + 24 * HOUR - 1_000).toISOString(),
		);
	});

	test('a visit not yet checked extends a chain whose writes failed, when expiry checks it', async () => {
		const t = await setup();
		await t.up(daily());
		const start = t.now();
		refuseVisitWrites(t);
		t.advance(20 * HOUR);
		t.activity.visit('hello-pr-7');
		await t.deployer.flushVisits();
		// Inside the deadline the visit at hour 20 set (hour 44).
		t.advance(start + 40 * HOUR - t.now());
		t.activity.visit('hello-pr-7');
		// Past hour 44; the flush before expiry cannot read the record.
		t.advance(start + 45 * HOUR - t.now());
		failNextRead(t);
		expect(await t.deployer.expire()).toEqual([]);
		// Past the deadline the visit at hour 40 set, it expires.
		t.advance(start + 64 * HOUR + 1 - t.now());
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
	});

	test('a page view does not call a preview overdue while a visit to it is unchecked', async () => {
		const t = await setup();
		await t.up(daily());
		t.advance(24 * HOUR - 1_000);
		t.activity.visit('hello-pr-7');
		t.advance(2_000);
		failNextRead(t);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
	});

	test('a visit after the deadline, unchecked when expiry reads the record, does not hold it off', async () => {
		const t = await setup();
		await t.up(daily());
		t.advance(24 * HOUR + 1_000);
		t.activity.visit('hello-pr-7');
		t.advance(1_000);
		failNextRead(t);
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
	});

	test('a visit after the deadline does not save a preview that is still routed', async () => {
		const t = await setup();
		await t.up(request());
		// Past its ttl and not yet expired, so Caddy still sends visitors to it.
		t.advance(7 * 86_400_000 + 60_000);
		expect(t.lastRoutes()).toHaveLength(1);
		await t.deployer.recordVisits([['hello-pr-7', t.now()]]);
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBeUndefined();
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
	});

	test('a visit just before the deadline renews the preview, though one just after it comes in the same batch', async () => {
		const t = await setup();
		await t.up(request());
		const record = await t.store.get('hello-pr-7');
		const deadline =
			Math.max(
				Date.parse(record?.updatedAt ?? ''),
				Date.parse(record?.deployment?.deployedAt ?? ''),
			) +
			7 * 86_400_000;
		let now = deadline - 5_000;
		const activity = new Activity(join(t.root, 'last-activity'), () => now);
		activity.visit('hello-pr-7');
		now = deadline + 5_000;
		activity.visit('hello-pr-7');
		t.advance(deadline + 30_000 - t.now());
		await t.deployer.recordVisits(activity.drainVisits());
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBe(new Date(now).toISOString());
		expect(await t.deployer.expire()).toEqual([]);
	});

	test('visits are written oldest first, whatever order they come in', async () => {
		const t = await setup();
		await t.up(request());
		const deadline = t.now() + 7 * 86_400_000;
		t.advance(7 * 86_400_000 + 30_000);
		await t.deployer.recordVisits([
			['hello-pr-7', deadline + 5_000],
			['hello-pr-7', deadline - 5_000],
		]);
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBe(
			new Date(deadline + 5_000).toISOString(),
		);
	});

	test('a visit to an expired preview changes nothing', async () => {
		const t = await setup();
		await t.up(request());
		t.advance(8 * 86_400_000);
		await t.deployer.expire();
		const before = await t.store.get('hello-pr-7');
		await t.deployer.recordVisits([['hello-pr-7', t.now()]]);
		expect(await t.store.get('hello-pr-7')).toEqual(before);
	});

	test('visits only move forward', async () => {
		const t = await setup();
		await t.up(request());
		await t.deployer.recordVisits([['hello-pr-7', Date.parse('2026-10-08T00:00:00.000Z')]]);
		await t.deployer.recordVisits([['hello-pr-7', Date.parse('2026-10-07T00:00:00.000Z')]]);
		expect((await t.store.get('hello-pr-7'))?.lastVisitAt).toBe('2026-10-08T00:00:00.000Z');
	});
});

describe('disk', () => {
	const GiB = 1024 ** 3;

	test('stops a preview whose writable layer and volumes pass the limit, and visits do not restart it', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(container, 9 * GiB);
		expect(await t.deployer.stopOversized()).toEqual([]);
		t.docker.diskBytes.set(container, 11 * GiB);
		expect(await t.deployer.stopOversized()).toEqual([container]);
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('running');
		expect(record?.error).toBe(
			'stopped for disk use: its writable layer and volumes reached 11 GiB, over the 10 GiB limit',
		);
		expect(record?.deployment?.halted).toBe('disk');
		expect((await t.docker.inspect(container)).running).toBe(false);
		expect(t.lastRoutes()).toEqual([]);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'halted' });
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([]);
		// A new koi up does not wake it while it builds, and replaces it.
		t.addRequest(request({ id: 'bbbbbbbbbbbbbbbb2' }));
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2' }));
		const after = await t.store.get('hello-pr-7');
		expect(after?.deployment?.requestId).toBe('bbbbbbbbbbbbbbbb2');
		expect(after?.deployment?.halted).toBeUndefined();
		expect(after?.error).toBeUndefined();
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
		expect(t.docker.containers.has(container)).toBe(false);
	});

	// The store refuses to mark a deployment halted, as on a disk the preview filled.
	function refuseHaltMarkers(t: Awaited<ReturnType<typeof setup>>) {
		const update = t.store.update.bind(t.store);
		t.store.update = async (label, change) => {
			const current = await t.store.get(label);
			if (current !== undefined && change(current).deployment?.halted === 'disk') {
				throw new Error('ENOSPC: no space left on device');
			}
			return update(label, change);
		};
		return () => {
			t.store.update = update;
		};
	}

	test('a stopped preview stays stopped when its halt marker cannot be saved', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(container, 11 * GiB);
		const allow = refuseHaltMarkers(t);
		expect(await t.deployer.stopOversized()).toEqual([container]);
		expect((await t.store.get('hello-pr-7'))?.deployment?.halted).toBeUndefined();
		expect(t.logs.join('\n')).toContain(
			`recording that ${container} was stopped for disk use: ENOSPC: no space left on device`,
		);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'halted' });
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([]);
		expect((await t.docker.inspect(container)).running).toBe(false);
		// With room on the disk again, the next run saves the marker, and the
		// one after has nothing to do.
		allow();
		expect(await t.deployer.stopOversized()).toEqual([container]);
		expect((await t.store.get('hello-pr-7'))?.deployment?.halted).toBe('disk');
		expect(await t.deployer.stopOversized()).toEqual([]);
	});

	test('after a restart, the startup run blocks a stopped preview whose marker was never saved', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(container, 11 * GiB);
		refuseHaltMarkers(t);
		await t.deployer.stopOversized();
		// koid restarts; the container is stopped and still over the limit.
		const deployer = t.restart();
		await deployer.reconcile();
		expect(await deployer.stopOversized()).toEqual([container]);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'halted' });
		await deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([]);
		expect((await t.docker.inspect(container)).running).toBe(false);
	});

	test('after a restart, a failed startup scan keeps an oversized preview stopped until a scan succeeds', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(container, 11 * GiB);
		refuseHaltMarkers(t);
		await t.deployer.stopOversized();
		const deployer = t.restart();
		await deployer.reconcile();
		t.docker.diskUsageError = 'docker system df timed out';
		await expect(deployer.stopOversized()).rejects.toThrow('timed out');
		await deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([]);
		// The next run of the watchdog's timer measures it, and blocks it.
		t.docker.diskUsageError = undefined;
		expect(await deployer.stopOversized()).toEqual([container]);
		await deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([]);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'halted' });
	});

	test('after a restart, a stopped preview under the limit starts once a scan has succeeded', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		const deployer = t.restart();
		await deployer.reconcile();
		t.docker.diskUsageError = 'docker system df timed out';
		await expect(deployer.stopOversized()).rejects.toThrow('timed out');
		await deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([]);
		t.docker.diskUsageError = undefined;
		expect(await deployer.stopOversized()).toEqual([]);
		await deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([container]);
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('an oversized container stays blocked when stopping it fails for it alone', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(container, 11 * GiB);
		refuseHaltMarkers(t);
		await t.deployer.stopOversized();
		const deployer = t.restart();
		await deployer.reconcile();
		// The scan succeeds, but Caddy refuses the routes this container's
		// stop waits for.
		t.rejectNextApply('caddy rejected the config: 400 bad');
		expect(await deployer.stopOversized()).toEqual([]);
		expect(t.logs.join('\n')).toContain(`stopping ${container} for disk use: caddy rejected`);
		await deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([]);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'halted' });
	});

	test('stops a container only once Caddy has taken routes without it', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(container, 11 * GiB);
		t.rejectNextApply('caddy rejected the config: 400 bad');
		expect(await t.deployer.stopOversized()).toEqual([]);
		// Stopping it would free an address Caddy may still route to.
		expect((await t.docker.inspect(container)).running).toBe(true);
		expect((await t.store.get('hello-pr-7'))?.deployment?.halted).toBeUndefined();
		expect(t.logs.join('\n')).toContain(`keeping ${container}`);
		// The next run, with Caddy taking routes again, stops it.
		expect(await t.deployer.stopOversized()).toEqual([container]);
		expect(t.lastRoutes()).toEqual([]);
		expect((await t.store.get('hello-pr-7'))?.deployment?.halted).toBe('disk');
	});

	test('stops a container once Caddy has taken routes without it, even if the live list cannot be published', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(container, 11 * GiB);
		t.rejectPublishes(1);
		expect(await t.deployer.stopOversized()).toEqual([container]);
		expect(t.lastRoutes()).toEqual([]);
		expect((await t.docker.inspect(container)).running).toBe(false);
		expect((await t.store.get('hello-pr-7'))?.deployment?.halted).toBe('disk');
		await t.deployer.published();
		expect(t.logs.join('\n')).toContain('publishing the live previews: ThrottlingException');
	});

	test('a container that will not stop does not keep the others running', async () => {
		const t = await setup();
		await t.up(request());
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', label: 'other', pr: 8 }));
		const first = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		const second = (await t.store.get('other'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(first, 11 * GiB);
		t.docker.diskBytes.set(second, 11 * GiB);
		t.docker.unstoppable.add(first);
		expect(await t.deployer.stopOversized()).toEqual([second]);
		expect((await t.docker.inspect(second)).running).toBe(false);
		expect((await t.store.get('other'))?.deployment?.halted).toBe('disk');
		expect((await t.store.get('hello-pr-7'))?.deployment?.halted).toBeUndefined();
		expect(t.logs.join('\n')).toContain(`stopping ${first} for disk use: docker stop`);
	});

	test('stops an oversized container no record uses yet, failing its build', async () => {
		const t = await setup();
		const gate = t.hold('probe');
		t.addRequest(request());
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		await gate.reached;
		t.docker.diskBytes.set('koi-hello-pr-7-aaaaaaaaaaaaaaaa1', 11 * GiB);
		expect(await t.deployer.stopOversized()).toEqual(['koi-hello-pr-7-aaaaaaaaaaaaaaaa1']);
		gate.release();
		await t.deployer.settled('hello-pr-7');
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		// It passed its health check before the stop, and the cutover noticed.
		expect(record?.error).toBe(
			'koi-hello-pr-7-aaaaaaaaaaaaaaaa1 stopped before it could be routed',
		);
		expect(t.docker.containers.size).toBe(0);
	});

	test('trims the build cache after each successful deploy, and a failure to trim is only logged', async () => {
		const t = await setup();
		await t.up(request());
		expect(t.docker.prunes).toEqual(['30gb']);
		t.docker.pruneError = 'buildx prune exited 1';
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2' }));
		expect(t.docker.prunes).toEqual(['30gb', '30gb']);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(t.logs).toContain('pruning the build cache: buildx prune exited 1');
		t.docker.buildError = 'boom';
		await t.up(request({ id: 'cccccccccccccccc3' }));
		expect(t.docker.prunes).toHaveLength(2);
	});

	test('trims the build cache before a build when the disk is under 20% free', async () => {
		const t = await setup();
		t.disk.free = 0.15 * t.disk.size;
		t.docker.onPrune = () => {
			t.disk.free = 0.3 * t.disk.size;
		};
		await t.up(request());
		expect(t.docker.prunes).toEqual(['20gb', '30gb']);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
	});

	test('on a large disk a build needs a fixed amount free, not a share of it', async () => {
		const gib = 1024 ** 3;
		// A tenth of this disk is far more than a build can use.
		for (const [free, trimmed, status] of [
			[90 * gib, false, 'running'],
			[30 * gib, true, 'running'],
			[10 * gib, true, 'failed'],
		] as const) {
			const t = await setup();
			t.disk.size = 2048 * gib;
			t.disk.free = free;
			await t.up(request());
			expect(t.docker.prunes.includes('20gb')).toBe(trimmed);
			expect((await t.store.get('hello-pr-7'))?.status).toBe(status);
		}
	});

	test('refuses a build when trimming the cache leaves the disk under 10% free', async () => {
		const t = await setup();
		t.disk.free = 0.05 * t.disk.size;
		await t.up(request());
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toBe(
			'the box is short of disk: 4 GiB of 80 GiB free after trimming the build cache, and a build needs 8 GiB; remove previews with koi down and run koi up again',
		);
		expect(t.docker.prunes).toEqual(['20gb']);
		expect(t.docker.builds).toHaveLength(0);
	});
});

describe('isLive', () => {
	test('is true for previews with a record that has not expired, as of the last sync', async () => {
		const t = await setup();
		expect(t.deployer.isLive('hello-pr-7')).toBe(false);
		await t.up(request());
		expect(t.deployer.isLive('hello-pr-7')).toBe(true);
		expect(t.deployer.isLive('nobody')).toBe(false);
		t.advance(8 * 86_400_000);
		await t.deployer.expire();
		expect(t.deployer.isLive('hello-pr-7')).toBe(false);
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2' }));
		expect(t.deployer.isLive('hello-pr-7')).toBe(true);
		await t.deployer.down('hello-pr-7');
		expect(t.deployer.isLive('hello-pr-7')).toBe(false);
	});
});

describe('sync', () => {
	test('a sync started while another runs applies the newer state last', async () => {
		const t = await setup();
		await t.up(request());
		// This sync has read the records, hello-pr-7 included, and waits to apply.
		const gate = t.hold('apply');
		const slow = t.deployer.sync();
		await gate.reached;
		const removed = t.deployer.down('hello-pr-7');
		// Unserialised, down's own sync applies and publishes here, and the slow
		// one then lands on top with the removed preview in it.
		await Promise.race([removed, Bun.sleep(100)]);
		gate.release();
		await Promise.all([slow, removed]);
		expect(t.lastRoutes()).toEqual([]);
		await t.deployer.published();
		expect(t.published.at(-1)).toEqual([]);
	});

	test('calls made while a sync runs share one more run', async () => {
		const t = await setup();
		await t.up(request());
		const before = t.applied.length;
		const gate = t.hold('apply');
		const first = t.deployer.sync();
		await gate.reached;
		const later = [t.deployer.sync(), t.deployer.sync(), t.deployer.sync()];
		gate.release();
		await Promise.all([first, ...later]);
		expect(t.applied.length - before).toBe(2);
	});
});

describe('down', () => {
	test('removes the record and the route before the container', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		const gate = t.hold('apply');
		const removed = t.deployer.down('hello-pr-7');
		await gate.reached;
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect(t.docker.containers.has(container)).toBe(true);
		gate.release();
		expect(await removed).toBe(true);
		expect(t.docker.containers.has(container)).toBe(false);
	});

	test('keeps the container when Caddy refuses the routes without it, and a retry removes it', async () => {
		const t = await setup();
		await t.up(request());
		const d = (await t.store.get('hello-pr-7'))?.deployment;
		const container = d?.container ?? '';
		t.rejectNextApply('caddy rejected the config: 400 bad');
		await expect(t.deployer.down('hello-pr-7')).rejects.toThrow('caddy rejected');
		// Caddy may still send the label's visitors to its address, so the
		// container keeps it.
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect((await t.docker.inspect(container)).running).toBe(true);
		expect(t.logs.join('\n')).toContain(`keeping ${container}`);
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		expect(t.docker.containers.has(container)).toBe(false);
		expect(t.docker.images.has(d?.image ?? '')).toBe(false);
		expect(t.lastRoutes()).toEqual([]);
		expect(await t.deployer.down('hello-pr-7')).toBe(false);
	});

	test('removes what a failed expiry left, along with the tombstone', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.advance(8 * 86_400_000);
		t.rejectNextApply('caddy rejected the config: 400 bad');
		await t.deployer.expire();
		expect(t.docker.containers.has(container)).toBe(true);
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect(t.docker.containers.has(container)).toBe(false);
		expect(t.docker.images.size).toBe(0);
	});

	test('removes the container even if the live list cannot be published, and the next sync publishes it', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.rejectPublishes(1);
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		expect(t.docker.containers.has(container)).toBe(false);
		await t.deployer.published();
		expect(t.published.at(-1)).toEqual(['hello-pr-7']);
		expect(t.logs.join('\n')).toContain('the next sync tries again');
		await t.deployer.sync();
		await t.deployer.published();
		expect(t.published.at(-1)).toEqual([]);
	});

	test('reconcile removes what a down that Caddy refused left behind', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.rejectNextApply('caddy rejected the config: 400 bad');
		await expect(t.deployer.down('hello-pr-7')).rejects.toThrow();
		await t.deployer.reconcile();
		expect(t.docker.containers.has(container)).toBe(false);
	});

	test('removes the container, image and record', async () => {
		const t = await setup();
		await t.up(request());
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect(t.docker.containers.size).toBe(0);
		expect(t.lastRoutes()).toEqual([]);
		expect(await t.deployer.down('hello-pr-7')).toBe(false);
	});

	test('stops a docker build in progress, which frees its slot and leaves nothing behind', async () => {
		const t = await setup();
		// The first build runs until something ends it.
		const building = new Gate();
		t.docker.onBuild = () => {
			t.docker.onBuild = undefined;
			return building.pass();
		};
		t.addRequest(request());
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		await building.reached;
		const stopped = await t.store.get('hello-pr-7');
		expect(stopped?.status).toBe('building');
		// A retry of the label waits behind it, and another preview waits for
		// the slot it holds.
		const retry = request({ id: 'bbbbbbbbbbbbbbbb2' });
		t.addRequest(retry);
		expect(await t.deployer.up(retry.id)).toEqual({ label: 'hello-pr-7', queued: true });
		const other = request({ id: 'oooooooooooooooo9', label: 'other', pr: 8 });
		t.addRequest(other);
		expect(await t.deployer.up(other.id)).toEqual({ label: 'other', queued: true });
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		await eventually(() => t.docker.builds[0]?.signal?.aborted === true);
		// The other preview gets the slot and deploys.
		await t.deployer.settled('other');
		expect((await t.store.get('other'))?.status).toBe('running');
		await t.deployer.settled('hello-pr-7');
		// Neither request of the label wrote its record back, built again,
		// started a container or left an image, and both let go of their
		// uploads.
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect(t.docker.builds.map((b) => b.labels['koi.preview'])).toEqual(['hello-pr-7', 'other']);
		expect(t.docker.runs.map((r) => r.labels['koi.preview'])).toEqual(['other']);
		expect([...t.docker.images].filter((i) => i.startsWith('koi-preview/hello-pr-7:'))).toEqual([]);
		expect(t.lastRoutes().map((r) => r.label)).toEqual(['other']);
		expect(t.uploadEvents).toContain('release aaaaaaaaaaaaaaaa1');
		expect(t.uploadEvents).toContain('release bbbbbbbbbbbbbbbb2');
		expect(t.logs).toContain(
			'build bbbbbbbbbbbbbbbb2 for hello-pr-7: superseded before it started',
		);
		// The build that was stopped says why in its log.
		expect(await readFile(logPath(t.stateDir, stopped), 'utf8')).toContain(
			'superseded: koi down removed the preview',
		);
		expect(await readdir(join(t.stateDir, 'builds', 'hello-pr-7'))).toEqual([]);
	});

	test('stops a build in its health check', async () => {
		const t = await setup();
		t.setHealthy(() => false);
		const probing = t.hold('probe');
		t.addRequest(request());
		await t.deployer.up('aaaaaaaaaaaaaaaa1');
		await probing.reached;
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('starting');
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		probing.release();
		await t.deployer.settled('hello-pr-7');
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect(t.docker.containers.size).toBe(0);
		expect(t.docker.images.size).toBe(0);
		expect(t.lastRoutes()).toEqual([]);
		// Ended by koi down, not by its container going.
		const log = await readFile(logPath(t.stateDir, record), 'utf8');
		expect(log).toContain('superseded: koi down removed the preview');
		expect(log).not.toContain('the container stopped before it answered');
	});

	test('drops a request still queued behind another preview', async () => {
		const t = await setup();
		// Another preview's build holds the slot.
		const gate = t.hold('keepAwake');
		t.addRequest(request({ id: 'oooooooooooooooo9', label: 'other', pr: 8 }));
		await t.deployer.up('oooooooooooooooo9');
		await gate.reached;
		t.addRequest(request());
		expect(await t.deployer.up('aaaaaaaaaaaaaaaa1')).toEqual({
			label: 'hello-pr-7',
			queued: true,
		});
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
		gate.release();
		await t.deployer.settled('other');
		await t.deployer.settled('hello-pr-7');
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect(t.docker.builds.map((b) => b.labels['koi.preview'])).toEqual(['other']);
		expect(t.uploadEvents).toContain('release aaaaaaaaaaaaaaaa1');
		expect(t.logs).toContain(
			'build aaaaaaaaaaaaaaaa1 for hello-pr-7: superseded before it started',
		);
	});
});

describe('reconcile', () => {
	test('after a restart, routes only the running containers that answer', async () => {
		const t = await setup();
		await t.up(request());
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', label: 'other', pr: 8 }));
		const routes = t.lastRoutes();
		expect(routes).toHaveLength(2);
		// koid restarts while both keep running; only hello-pr-7 answers.
		t.setHealthy((url) => url.startsWith('http://172.19.0.2:'));
		const deployer = t.restart();
		await deployer.reconcile();
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.2:8080' }]);
		expect(await deployer.view('other')).toEqual({ kind: 'stopped' });
		// A visit checks it again and routes it once it answers.
		t.setHealthy(undefined);
		await deployer.ensureRunning('other');
		expect(t.lastRoutes()).toEqual(routes);
		expect(t.docker.starts).toEqual([]);
	});

	test('takes a preview that runs outside the slice out of the routes, then stops it, and its next visit starts it in the slice', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		// Docker restarted with live-restore on: the preview kept running in
		// the slice it had before.
		const kept = t.docker.containers.get(container);
		if (kept === undefined) throw new Error('no container');
		kept.slice = 'system.slice';
		expect(t.lastRoutes()).toHaveLength(1);
		let routedAtStop: Route[] | undefined;
		t.docker.onStop = (name) => {
			if (name === container) routedAtStop = t.lastRoutes();
		};
		const deployer = t.restart();
		await deployer.reconcile();
		// Caddy had taken routes without it before it stopped.
		expect(routedAtStop).toEqual([]);
		expect((await t.docker.inspect(container)).running).toBe(false);
		expect(t.logs).toContain(
			`stopped ${container}, which ran outside koi.slice; its next visit starts it there`,
		);
		await deployer.stopOversized();
		await deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([container]);
		expect(await t.docker.slice(container)).toBe('koi.slice');
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('a preview that runs outside the slice and will not stop stays out of the routes until a later stop works', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		const kept = t.docker.containers.get(container);
		if (kept === undefined) throw new Error('no container');
		kept.slice = 'system.slice';
		// The stop times out once.
		t.docker.unstoppable.add(container);
		const deployer = t.restart();
		await deployer.reconcile();
		expect(t.logs.join('\n')).toContain(
			`stopping ${container}, which runs outside koi.slice: docker stop ${container} timed out`,
		);
		expect((await t.docker.inspect(container)).running).toBe(true);
		expect(t.lastRoutes()).toEqual([]);
		t.docker.unstoppable.delete(container);
		await deployer.stopOversized();
		// A visit does not route it while it runs outside the slice.
		await deployer.ensureRunning('hello-pr-7');
		expect(t.lastRoutes()).toEqual([]);
		expect(await t.docker.slice(container)).toBe('system.slice');
		// The watchdog's timer stops it, and the next visit starts it in the slice.
		await deployer.stopMisplaced();
		expect((await t.docker.inspect(container)).running).toBe(false);
		await deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts).toEqual([container]);
		expect(await t.docker.slice(container)).toBe('koi.slice');
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('a wake routes a container only in the slice', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		await t.deployer.sync();
		// Docker starts containers outside the slice.
		t.docker.startSlice = 'system.slice';
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.lastRoutes()).toEqual([]);
		expect((await t.docker.inspect(container)).running).toBe(false);
		expect(t.logs).toContain(
			`stopped ${container}, which ran outside koi.slice; its next visit starts it there`,
		);
		t.docker.startSlice = 'koi.slice';
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('a slow wake keeps the box awake while it waits for the preview to answer', async () => {
		const t = await setup();
		const base = request();
		if (base.recipe.kind !== 'repo') throw new Error('expected a repo recipe');
		const recipe = { ...base.recipe.recipe, healthTimeoutSeconds: 300 };
		await t.up(request({ recipe: { kind: 'repo', recipe } }));
		t.docker.stopAll();
		await t.deployer.sync();
		// Answers after about two and a half minutes of checks, one a second.
		let probes = 0;
		t.setHealthy(() => {
			probes += 1;
			return probes > 150;
		});
		const before = t.awakeCalls();
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.lastRoutes()).toHaveLength(1);
		// Once as the wake starts, then every 30 seconds of waiting.
		expect(t.awakeCalls() - before).toBeGreaterThanOrEqual(6);
	});

	test('keeps a preview outside the slice running while Caddy refuses routes without it', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		const kept = t.docker.containers.get(container);
		if (kept === undefined) throw new Error('no container');
		kept.slice = 'system.slice';
		const stops: string[] = [];
		t.docker.onStop = (name) => stops.push(name);
		const deployer = t.restart();
		t.rejectNextApply('caddy rejected the config: 400 bad');
		await expect(deployer.reconcile()).rejects.toThrow('caddy rejected');
		expect(stops).toEqual([]);
		expect((await t.docker.inspect(container)).running).toBe(true);
	});

	test("leaves a verification run's helpers alone, even when the image carries koi.preview", async () => {
		const t = await setup();
		await t.up(request());
		const run = 'r'.repeat(16);
		await t.docker.createNetwork({
			name: `koi-v-${run}`,
			bridge: 'kv0123456789ab',
			subnet: '10.213.0.0/28',
			gateway: '10.213.0.1',
			labels: { 'koi.run': run },
		});
		// The project chooses the image, and Docker copies its labels onto
		// the container. koid sets koi.preview to nothing over it, so the
		// helper is no preview: neither reconciled nor watched for disk use.
		t.docker.imageLabels.set('r', { 'koi.preview': 'hello-pr-7' });
		const recorder = `koi-verify-${run}-recorder`;
		await t.docker.createRecorder({
			name: recorder,
			image: 'r',
			network: `koi-v-${run}`,
			ip: '10.213.0.3',
			mac: '02:4b:0a:d5:00:03',
			runId: run,
			appHost: { name: 'a', ip: '10.213.0.2' },
			dns: '10.213.0.1',
			env: {},
		});
		expect(t.docker.containers.get(recorder)?.labels).toEqual({
			'koi.preview': '',
			'koi.role': 'recorder',
			'koi.run': run,
		});
		// Over the disk limit too, were it a preview.
		t.docker.diskBytes.set(recorder, 11 * 1024 ** 3);
		const deployer = t.restart();
		await deployer.reconcile();
		expect(t.docker.containers.has(recorder)).toBe(true);
		expect(await deployer.stopOversized()).toEqual([]);
		expect(t.docker.containers.get(recorder)?.running).toBe(false);
		expect(t.docker.events.filter((e) => e.includes(recorder))).toEqual([
			`created recorder ${recorder}`,
		]);
		// The preview is routed as before.
		expect(t.lastRoutes()).toHaveLength(1);
	});

	test('a preview whose image carries koi.role is still watched for disk use and reconciled', async () => {
		const t = await setup();
		await t.up(request());
		// A pull request's Dockerfile can LABEL koi.role. koid sets it to
		// nothing over that, so the container is a preview all the same.
		t.docker.imageLabels.set('x', { 'koi.role': 'verifier' });
		const orphan = 'koi-hello-pr-7-orphan';
		await t.docker.run({
			name: orphan,
			image: 'x',
			network: 'koi-previews',
			user: '1',
			env: {},
			labels: { 'koi.preview': 'hello-pr-7' },
		});
		expect(t.docker.containers.get(orphan)?.labels).toEqual({
			'koi.role': '',
			'koi.preview': 'hello-pr-7',
		});
		t.docker.diskBytes.set(orphan, 11 * 1024 ** 3);
		expect(await t.deployer.stopOversized()).toEqual([orphan]);
		await t.deployer.reconcile();
		expect(t.docker.containers.has(orphan)).toBe(false);
	});

	test('a preview an older koid made, with the koi.role its image set, is still watched for disk use and reconciled', async () => {
		const t = await setup();
		await t.up(request());
		// Before koid set koi.role to nothing on every preview, a label from
		// a pull request's Dockerfile reached the container as it was, and
		// so did koi.run. The name says what the container is; no label
		// takes it out of the watchdog's or the reconciler's sight.
		const orphan = `koi-hello-pr-7-${'a'.repeat(20)}`;
		await t.docker.run({
			name: orphan,
			image: 'x',
			network: 'koi-previews',
			user: '1',
			env: {},
			labels: { 'koi.preview': 'hello-pr-7' },
		});
		const container = t.docker.containers.get(orphan);
		if (container === undefined) throw new Error('no container');
		container.labels['koi.role'] = 'recorder';
		container.labels['koi.run'] = 'r'.repeat(16);
		t.docker.diskBytes.set(orphan, 11 * 1024 ** 3);
		expect(await t.deployer.stopOversized()).toEqual([orphan]);
		expect(container.running).toBe(false);
		await t.deployer.reconcile();
		expect(t.docker.containers.has(orphan)).toBe(false);
	});

	test('a helper whose koi.preview an image forged is no preview, nor is a container only named like one', async () => {
		const t = await setup();
		await t.up(request());
		const run = 'r'.repeat(16);
		await t.docker.createNetwork({
			name: `koi-v-${run}`,
			bridge: 'kv0123456789ab',
			subnet: '10.213.0.0/28',
			gateway: '10.213.0.1',
			labels: { 'koi.run': run },
		});
		const recorder = `koi-verify-${run}-recorder`;
		await t.docker.createRecorder({
			name: recorder,
			image: 'r',
			network: `koi-v-${run}`,
			ip: '10.213.0.3',
			mac: '02:4b:0a:d5:00:03',
			runId: run,
			appHost: { name: 'a', ip: '10.213.0.2' },
			dns: '10.213.0.1',
			env: {},
		});
		// As if koid had not set koi.preview to nothing over the image's:
		// the name alone keeps the helper out of reconcile and the watchdog.
		const helper = t.docker.containers.get(recorder);
		if (helper === undefined) throw new Error('no container');
		helper.labels['koi.preview'] = 'hello-pr-7';
		t.docker.diskBytes.set(recorder, 11 * 1024 ** 3);
		// A container made by hand under a helper's name, with a preview's
		// label and no run or role: not a preview here, and not a helper to
		// cleanup either (verification-network.ts, helperOf).
		const odd = `koi-verify-${run}-verifier`;
		await t.docker.run({
			name: odd,
			image: 'x',
			network: 'koi-previews',
			user: '1',
			env: {},
			labels: { 'koi.preview': 'hello-pr-7' },
		});
		t.docker.diskBytes.set(odd, 11 * 1024 ** 3);
		const deployer = t.restart();
		await deployer.reconcile();
		expect(t.docker.containers.has(recorder)).toBe(true);
		expect(t.docker.containers.has(odd)).toBe(true);
		expect(await deployer.stopOversized()).toEqual([]);
		expect(t.docker.containers.get(odd)?.running).toBe(true);
		expect(t.docker.events.filter((e) => e.includes(recorder))).toEqual([
			`created recorder ${recorder}`,
		]);
	});

	test('removes nothing until Caddy takes routes without it', async () => {
		const t = await setup();
		await t.up(request());
		await t.docker.run({
			name: 'koi-hello-pr-7-orphan',
			image: 'x',
			network: 'koi-previews',
			user: '1',
			env: {},
			labels: { 'koi.preview': 'hello-pr-7' },
		});
		t.rejectNextApply('caddy rejected the config: 400 bad');
		await expect(t.deployer.reconcile()).rejects.toThrow('caddy rejected');
		expect(t.docker.containers.has('koi-hello-pr-7-orphan')).toBe(true);
		await t.deployer.reconcile();
		expect(t.docker.containers.has('koi-hello-pr-7-orphan')).toBe(false);
	});

	test.each(['queued', 'building', 'starting'] as const)(
		'fails a %s request and removes containers and images no record uses',
		async (status) => {
			const t = await setup();
			await t.up(request());
			const record = await t.store.get('hello-pr-7');
			if (record === undefined) throw new Error('no record');
			await t.store.put({ ...record, status });
			await t.docker.run({
				name: 'koi-hello-pr-7-orphan',
				image: 'x',
				network: 'koi-previews',
				user: '1',
				env: {},
				labels: { 'koi.preview': 'hello-pr-7' },
			});
			t.docker.images.add('koi-preview/hello-pr-7:orphan');
			await t.deployer.reconcile();
			const after = await t.store.get('hello-pr-7');
			expect(after?.status).toBe('failed');
			expect(after?.error).toBe(
				'interrupted: the daemon restarted before this build finished; run koi up again',
			);
			expect(after?.deployment).toEqual(record.deployment);
			expect(t.docker.containers.has('koi-hello-pr-7-orphan')).toBe(false);
			expect(t.docker.images.has('koi-preview/hello-pr-7:orphan')).toBe(false);
			expect(t.docker.containers.has(record.deployment?.container ?? '')).toBe(true);
			expect(t.docker.images.has(record.deployment?.image ?? '')).toBe(true);
		},
	);
});

// The box stops, which stops every container, and starts again: a new koid
// takes its startup steps for previews in main.ts's order.
async function stopAndStart(t: Awaited<ReturnType<typeof setup>>) {
	t.docker.stopAll();
	const deployer = t.restart();
	await deployer.reconcile();
	const expired = await deployer.expire();
	await deployer.stopOversized();
	const started = await deployer.restore();
	return { deployer, expired, started };
}

describe('restore', () => {
	test('after the box stops and starts, a preview that served runs again with its deployment and login key', async () => {
		const t = await setup({ builtin: builtinRecipe({ loginKeyEnv: 'APP_LOGIN_KEY' }) });
		await t.up(request({ recipe: { kind: 'builtin', name: 'storefront' } }));
		const before = await t.store.get('hello-pr-7');
		const container = before?.deployment?.container ?? '';
		expect(before?.loginKey).toMatch(/^koi-[a-z0-9]{24}$/);
		const { deployer, started } = await stopAndStart(t);
		expect(started).toEqual(['hello-pr-7']);
		// The same container, started again, not a new one.
		expect(t.docker.starts).toEqual([container]);
		expect(t.docker.runs).toHaveLength(1);
		const after = await t.store.get('hello-pr-7');
		expect(after?.deployment).toEqual(before?.deployment);
		expect(after?.loginKey).toBe(before?.loginKey ?? '');
		expect(t.docker.containers.get(container)?.options?.env.APP_LOGIN_KEY).toBe(
			before?.loginKey ?? '',
		);
		const { ip } = await t.docker.inspect(container);
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: `${ip}:9000` }]);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
	});

	test('routes a preview it starts only once it answers, and a visit meanwhile shares the start', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		const deployer = t.restart();
		await deployer.reconcile();
		await deployer.expire();
		await deployer.stopOversized();
		const checking = t.hold('probe');
		const restoring = deployer.restore();
		await checking.reached;
		// Started, with an address, and not yet healthy.
		expect((await t.docker.inspect(container)).running).toBe(true);
		expect(t.lastRoutes()).toEqual([]);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'stopped' });
		const visit = deployer.ensureRunning('hello-pr-7');
		checking.release();
		await Promise.all([restoring, visit]);
		expect(t.docker.starts).toEqual([container]);
		expect(t.lastRoutes()).toHaveLength(1);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
	});

	test('a preview whose ttl passed while the box was off expires and does not come back', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.advance(8 * 86_400_000);
		const { deployer, expired, started } = await stopAndStart(t);
		expect(expired).toEqual(['hello-pr-7']);
		expect(started).toEqual([]);
		expect(t.docker.starts).toEqual([]);
		expect(t.docker.containers.has(container)).toBe(false);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('expired');
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'expired' });
		expect(t.lastRoutes()).toEqual([]);
	});

	test('does not start a preview past its ttl that expiry has not retired yet', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		const deployer = t.restart();
		await deployer.reconcile();
		await deployer.stopOversized();
		t.advance(8 * 86_400_000);
		expect(await deployer.restore()).toEqual([]);
		expect(t.docker.starts).toEqual([]);
		expect(t.lastRoutes()).toEqual([]);
	});

	test('a lease taken before the stop holds the same deployment after it', async () => {
		const t = await setup();
		await t.up(request());
		const { lease, deployment } = await t.deployer.acquireLease('hello-pr-7', 'ci', 3600);
		t.advance(15 * 60_000);
		const { deployer, started } = await stopAndStart(t);
		expect(started).toEqual(['hello-pr-7']);
		expect((await t.store.get('hello-pr-7'))?.lease).toEqual(lease);
		const leased = await deployer.leasedDeployment('hello-pr-7', lease.leaseId);
		expect(leased.deploymentId).toBe(deployment.deploymentId);
		// What the lease names runs, and visitors reach it.
		expect((await t.docker.inspect(leased.container)).running).toBe(true);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
		// The lease still refuses another holder and a build that would
		// replace its deployment.
		await expect(deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			`leased by ci until ${lease.expiresAt}`,
		);
		const second = request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) });
		t.addRequest(second);
		await expect(deployer.up(second.id)).rejects.toBeInstanceOf(LeaseError);
	});

	test('a preview koid stopped for disk use or after a failed start stays stopped, and one koi down removed stays gone', async () => {
		const t = await setup();
		await t.up(request());
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', label: 'other', pr: 8 }));
		await t.up(request({ id: 'cccccccccccccccc3', label: 'gone', pr: 9 }));
		const halted = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		const failed = (await t.store.get('other'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(halted, 11 * 1024 ** 3);
		expect(await t.deployer.stopOversized()).toEqual([halted]);
		expect(await t.deployer.down('gone')).toBe(true);
		// The box slept once already, and a visit to other could not start it.
		t.docker.stopAll();
		await t.deployer.sync();
		t.setHealthy(() => false);
		await t.deployer.ensureRunning('other');
		expect((await t.store.get('other'))?.error).toContain('the preview did not start');
		t.setHealthy(undefined);
		const runs = t.docker.runs.length;
		const { deployer, started } = await stopAndStart(t);
		expect(started).toEqual([]);
		expect(t.docker.starts).toEqual([failed]);
		expect(t.docker.runs).toHaveLength(runs);
		expect(t.lastRoutes()).toEqual([]);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'halted' });
		expect(await deployer.view('gone')).toEqual({ kind: 'unknown' });
		// A visit still tries the one whose start failed.
		await deployer.ensureRunning('other');
		expect(await deployer.view('other')).toEqual({ kind: 'running' });
	});

	test('after a koid restart, starts nothing that runs and answers', async () => {
		const t = await setup();
		await t.up(request());
		const routes = t.lastRoutes();
		const deployer = t.restart();
		await deployer.reconcile();
		await deployer.stopOversized();
		expect(await deployer.restore()).toEqual([]);
		expect(t.docker.starts).toEqual([]);
		expect(t.lastRoutes()).toEqual(routes);
	});

	test('starts one preview at a time, through its health check, and a visit starts one still waiting', async () => {
		const t = await setup();
		const labels = ['hello-pr-7', 'other', 'third'];
		await t.up(request());
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', label: 'other', pr: 8 }));
		await t.up(request({ id: 'cccccccccccccccc3', label: 'third', pr: 9 }));
		const labelOf = new Map<string, string>();
		for (const label of labels) {
			labelOf.set((await t.store.get(label))?.deployment?.container ?? '', label);
		}
		const started = () => t.docker.starts.map((c) => labelOf.get(c));
		t.docker.stopAll();
		const deployer = t.restart();
		await deployer.reconcile();
		await deployer.expire();
		await deployer.stopOversized();
		const checking = t.hold('probe');
		const restoring = deployer.restore();
		await checking.reached;
		const first = started()[0] ?? '';
		const [visited = '', last = ''] = labels.filter((l) => l !== first);
		// The first is in its health check, and the others have not started.
		// A visit to one of them starts it now and shares nothing.
		await deployer.ensureRunning(visited);
		expect(started()).toEqual([first, visited]);
		expect(await deployer.view(visited)).toEqual({ kind: 'running' });
		checking.release();
		expect(await restoring).toEqual([first, last].sort());
		expect(started()).toEqual([first, visited, last]);
		expect(t.lastRoutes()).toHaveLength(3);
	});

	test('when the first disk scan fails, starts the stopped previews after the next scan that succeeds', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		const deployer = t.restart();
		await deployer.reconcile();
		await deployer.expire();
		t.docker.diskUsageError = 'docker system df timed out';
		await expect(deployer.stopOversized()).rejects.toThrow('docker system df timed out');
		const restoring = deployer.restore();
		await Promise.race([restoring, Bun.sleep(20)]);
		expect(t.docker.starts).toEqual([]);
		// The five-minute timer's scan.
		t.docker.diskUsageError = undefined;
		await deployer.stopOversized();
		expect(await restoring).toEqual(['hello-pr-7']);
		expect(t.docker.starts).toEqual([container]);
		expect(await deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
	});

	test("restore's start judges a failed start under the lock, and a visit still retries it", async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		await t.deployer.sync();
		// A visit's start fails after restore read the record and before its
		// turn: the start restore asks for sees the failure under the lock.
		t.setHealthy(() => false);
		await t.deployer.ensureRunning('hello-pr-7');
		expect((await t.store.get('hello-pr-7'))?.error).toContain('the preview did not start');
		t.setHealthy(undefined);
		const starts = t.docker.starts.length;
		await t.deployer.ensureRunning('hello-pr-7', true);
		expect(t.docker.starts).toHaveLength(starts);
		expect(t.lastRoutes()).toEqual([]);
		await t.deployer.ensureRunning('hello-pr-7');
		expect(t.docker.starts.slice(starts)).toEqual([container]);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
	});

	test("a visit that joins restore's start still retries a preview whose last start failed", async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.stopAll();
		await t.deployer.sync();
		t.setHealthy(() => false);
		await t.deployer.ensureRunning('hello-pr-7');
		t.setHealthy(undefined);
		const starts = t.docker.starts.length;
		// restore's start is in progress when the visit asks.
		const restoring = t.deployer.ensureRunning('hello-pr-7', true);
		const visit = t.deployer.ensureRunning('hello-pr-7');
		await Promise.all([restoring, visit]);
		expect(t.docker.starts.slice(starts)).toEqual([container]);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
	});

	test('a Docker error reading the containers before a start is a failed start, not a routing one', async () => {
		const t = await setup();
		await t.up(request());
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', label: 'other', pr: 8 }));
		// hello-pr-7 stopped and its route gone; other runs and is routed, so
		// the sync before the start inspects it.
		const stopped = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		await t.docker.stop(stopped);
		await t.deployer.sync();
		const before = t.docker.onInspect;
		let inspections = 0;
		// The first inspection is start()'s own; the second is the sync's,
		// which reads other's container before the start.
		t.docker.onInspect = async () => {
			inspections += 1;
			if (inspections === 2) throw new Error('docker inspect: the daemon is not answering');
		};
		await t.deployer.ensureRunning('hello-pr-7').catch(() => {});
		t.docker.onInspect = before;
		expect((await t.store.get('hello-pr-7'))?.error).toContain(
			'the preview did not start: docker inspect: the daemon is not answering',
		);
		expect(t.docker.starts).toEqual([]);
	});

	test.each([
		['Caddy', (t: Awaited<ReturnType<typeof setup>>) => t.rejectNextApply('connection refused')],
		['the egress proxy', (t: Awaited<ReturnType<typeof setup>>) => t.rejectMaps(3)],
	])(
		'a start that %s failed before Docker ran it is tried again at the next boot',
		async (_, fail) => {
			const t = await setup({ proxy: true });
			await t.up(request());
			const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
			t.docker.stopAll();
			const deployer = t.restart();
			await deployer.reconcile();
			await deployer.expire();
			await deployer.stopOversized();
			// The sync before the start fails.
			fail(t);
			expect(await deployer.restore()).toEqual([]);
			expect(t.docker.starts).toEqual([]);
			expect((await t.store.get('hello-pr-7'))?.error).toBeUndefined();
			const { deployer: next, started } = await stopAndStart(t);
			expect(started).toEqual(['hello-pr-7']);
			expect(t.docker.starts).toEqual([container]);
			expect(await next.view('hello-pr-7')).toEqual({ kind: 'running' });
		},
	);
});

// Where the build log of a record's attempt is.
function logPath(stateDir: string, record: PreviewRecord | undefined): string {
	return join(stateDir, 'logs', 'hello-pr-7', `${record?.attempt}.build.log`);
}

// A build log that writes lines out only on flush or close, whose first
// flush waits at `flushing` until the test releases it.
function heldLog() {
	const flushing = new Gate();
	let held: string[] = [];
	const written: string[] = [];
	let first = true;
	const writeOut = () => {
		written.push(...held);
		held = [];
	};
	return {
		written,
		flushing,
		line(text: string) {
			held.push(text);
		},
		async flush() {
			if (first) {
				first = false;
				await flushing.pass();
			}
			writeOut();
		},
		async close() {
			writeOut();
		},
	};
}

describe('the egress proxy address map', () => {
	const A = 'hello-pr-7';
	const B = 'other-pr-8';
	const forB = (id = 'bbbbbbbbbbbbbbbb2') =>
		request({ id, label: B, project: 'other', repo: 'github.com/acme/other', pr: 8 });
	// The maps in the event log, from index `from` on.
	const mapsIn = (events: string[]) =>
		events
			.filter((e) => e.startsWith('map '))
			.map((e) => JSON.parse(e.slice(4)) as Record<string, string>);

	test('maps each routed container address to its preview', async () => {
		const t = await setup({ proxy: true });
		await t.up(request());
		const ip = t.lastRoutes()[0]?.upstream.split(':')[0] ?? '';
		expect(t.maps.at(-1)).toEqual({ [ip]: A });
	});

	test("a dead preview's address never maps to it once another preview's container has it", async () => {
		// The reviewer's scenario: A's container dies on its own (koid hears
		// nothing), and Docker gives its address to B's new container.
		const t = await setup({ proxy: true });
		t.docker.reuseAddresses = true;
		await t.up(request());
		const a = (await t.store.get(A))?.deployment?.container ?? '';
		expect(t.maps.at(-1)).toEqual({ '172.19.0.2': A });
		t.docker.kill(a);
		await t.up(forB());
		const b = (await t.store.get(B))?.deployment?.container ?? '';
		const ran = t.docker.events.findIndex((e) => e.startsWith(`ran ${b} `));
		expect(t.docker.events[ran]).toBe(`ran ${b} 172.19.0.2`);
		// The proxy took a map without A's address before B's container
		// started, and never one naming A for that address after.
		expect(mapsIn(t.docker.events.slice(0, ran)).at(-1)).toEqual({});
		for (const map of mapsIn(t.docker.events.slice(ran))) expect(map['172.19.0.2']).not.toBe(A);
		expect(t.maps.at(-1)).toEqual({ '172.19.0.2': B });
	});

	test('a container that dies between the sync and the start is taken out of the map at once', async () => {
		const t = await setup({ proxy: true });
		t.docker.reuseAddresses = true;
		await t.up(request());
		const a = (await t.store.get(A))?.deployment?.container ?? '';
		// A dies after the sync before B's start has told the proxy, just
		// before Docker gives B an address.
		t.docker.onStartBegin = (name) => {
			if (name !== a) t.docker.kill(a);
		};
		t.setHealthy((url) => {
			t.docker.events.push(`probe ${url}`);
			return true;
		});
		await t.up(forB());
		const b = (await t.store.get(B))?.deployment?.container ?? '';
		const ran = t.docker.events.findIndex((e) => e.startsWith(`ran ${b} `));
		expect(t.docker.events[ran]).toBe(`ran ${b} 172.19.0.2`);
		// The next thing after the start is a map without A, before any
		// health check of B.
		expect(t.docker.events[ran + 1]).toBe('map {}');
	});

	test('koid keeps a container whose address the proxy may still map, and frees it once the proxy confirms', async () => {
		const t = await setup({ proxy: true });
		await t.up(request());
		const a = (await t.store.get(A))?.deployment?.container ?? '';
		// Three tries, a second apart, all fail.
		t.rejectMaps(3);
		await expect(t.deployer.down(A)).rejects.toThrow(
			'the egress proxy did not take the preview addresses',
		);
		expect(t.docker.containers.has(a)).toBe(true);
		await t.deployer.down(A);
		expect(t.docker.containers.has(a)).toBe(false);
		const removed = t.docker.events.indexOf(`removed ${a}`);
		expect(mapsIn(t.docker.events.slice(0, removed)).at(-1)).toEqual({});
	});

	test('a map the proxy fails to take is sent again, up to three times', async () => {
		const t = await setup({ proxy: true });
		await t.up(request());
		const a = (await t.store.get(A))?.deployment?.container ?? '';
		t.rejectMaps(2);
		await t.deployer.down(A);
		expect(t.docker.containers.has(a)).toBe(false);
		expect(t.maps.at(-1)).toEqual({});
	});

	test('a container is not started while the proxy may still map a dead one', async () => {
		const t = await setup({ proxy: true });
		await t.up(request());
		t.docker.stopAll();
		t.rejectMaps(3);
		await t.deployer.ensureRunning(A);
		expect(t.docker.starts).toEqual([]);
		expect(t.logs).toContainEqual(expect.stringContaining('the egress proxy did not take'));
		// A failure of the proxy, not of the preview: the next boot tries it.
		expect((await t.store.get(A))?.error).toBeUndefined();
	});

	test('a sync inspects the containers, so one that died leaves the map', async () => {
		const t = await setup({ proxy: true });
		await t.up(request());
		t.docker.kill((await t.store.get(A))?.deployment?.container ?? '');
		await t.deployer.sync();
		expect(t.maps.at(-1)).toEqual({});
		expect(t.lastRoutes()).toEqual([]);
	});
});

describe('lease', () => {
	const HOUR = 3_600_000;

	test('takes a lease on the serving deployment and returns both', async () => {
		const t = await setup();
		await t.up(
			request({ merge: { head: 'b'.repeat(40), base: 'c'.repeat(40), baseBranch: 'main' } }),
		);
		const d = (await t.store.get('hello-pr-7'))?.deployment;
		const reply = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 3600);
		expect(reply.lease).toEqual({
			leaseId: expect.stringMatching(/^[a-z0-9]{20}$/),
			deploymentId: d?.deploymentId ?? '',
			holder: 'dev@laptop',
			acquiredAt: new Date(t.now()).toISOString(),
			expiresAt: new Date(t.now() + HOUR).toISOString(),
		});
		expect(reply.deployment).toEqual({
			label: 'hello-pr-7',
			deploymentId: d?.deploymentId ?? '',
			imageDigest: d?.imageDigest ?? '',
			commit: 'a'.repeat(40),
			merge: { head: 'b'.repeat(40), base: 'c'.repeat(40), baseBranch: 'main' },
		});
		// On the record, so it outlives koid.
		expect((await t.store.get('hello-pr-7'))?.lease).toEqual(reply.lease);
		// The preview still serves as before.
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
	});

	test('the lease starts when it is granted, not when it was asked for', async () => {
		const t = await setup();
		await t.up(request());
		const asked = t.now();
		// The route sync inside acquireLease takes 30 s on this run.
		const sync = t.deployer.sync.bind(t.deployer);
		t.deployer.sync = async () => {
			t.advance(30_000);
			return sync();
		};
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		expect(lease.acquiredAt).toBe(new Date(asked + 30_000).toISOString());
		expect(lease.expiresAt).toBe(new Date(asked + 90_000).toISOString());
		// A 60 s lease taken after a 30 s wait still has its full minute.
		const again = t.deployer.acquireLease('hello-pr-7', 'ci run 42', 60);
		await expect(again).rejects.toThrow('leased by dev@laptop');
	});

	test('refuses a second lease while the first holds, naming the holder and the expiry', async () => {
		const t = await setup();
		await t.up(request());
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 3600);
		const again = t.deployer.acquireLease('hello-pr-7', 'ci run 42', 60);
		await expect(again).rejects.toBeInstanceOf(LeaseError);
		await expect(again).rejects.toThrow(`leased by dev@laptop until ${lease.expiresAt}`);
		expect((await t.store.get('hello-pr-7'))?.lease).toEqual(lease);
	});

	test('a released lease frees the preview for the next holder', async () => {
		const t = await setup();
		await t.up(request());
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 3600);
		await t.deployer.releaseLease('hello-pr-7', lease.leaseId);
		expect((await t.store.get('hello-pr-7'))?.lease).toBeUndefined();
		const next = await t.deployer.acquireLease('hello-pr-7', 'ci run 42', 60);
		expect(next.lease.leaseId).not.toBe(lease.leaseId);
		expect(next.lease.holder).toBe('ci run 42');
	});

	test('release refuses a lease the preview does not hold, and a label without a record', async () => {
		const t = await setup();
		await t.up(request());
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 3600);
		await expect(t.deployer.releaseLease('hello-pr-7', 'x'.repeat(20))).rejects.toBeInstanceOf(
			NoSuchLeaseError,
		);
		await expect(t.deployer.releaseLease('nobody', lease.leaseId)).rejects.toBeInstanceOf(
			NoSuchPreviewError,
		);
		await expect(t.deployer.acquireLease('nobody', 'dev@laptop', 60)).rejects.toBeInstanceOf(
			NoSuchPreviewError,
		);
		// Still held.
		expect((await t.store.get('hello-pr-7'))?.lease).toEqual(lease);
	});

	test('an expired lease no longer holds, and the expiry sweep drops it from the record', async () => {
		const t = await setup();
		await t.up(request());
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 600);
		t.advance(599_000);
		await expect(t.deployer.acquireLease('hello-pr-7', 'ci', 60)).rejects.toThrow('leased by');
		t.advance(1_000);
		// Past its expiry it stays on the record until the sweep.
		expect((await t.store.get('hello-pr-7'))?.lease).toEqual(lease);
		expect(await t.deployer.expire()).toEqual([]);
		expect((await t.store.get('hello-pr-7'))?.lease).toBeUndefined();
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		// A new lease can be taken, swept or not.
		const next = await t.deployer.acquireLease('hello-pr-7', 'ci', 60);
		t.advance(61_000);
		const after = await t.deployer.acquireLease('hello-pr-7', 'ci again', 60);
		expect(after.lease.leaseId).not.toBe(next.lease.leaseId);
	});

	test('a renewal extends the lease in force, never past the cap, and revives no expired one', async () => {
		const t = await setup();
		await t.up(request());
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 600);
		t.advance(500_000);
		const renewed = await t.deployer.renewLease('hello-pr-7', lease.leaseId, 600);
		expect(renewed).toEqual({ ...lease, expiresAt: new Date(t.now() + 600_000).toISOString() });
		expect((await t.store.get('hello-pr-7'))?.lease).toEqual(renewed);
		// Shorter than what it has: nothing changes.
		expect(await t.deployer.renewLease('hello-pr-7', lease.leaseId, 10)).toEqual(renewed);
		// Never past two hours from when it was taken.
		const capped = await t.deployer.renewLease('hello-pr-7', lease.leaseId, 4 * HOUR);
		expect(capped.expiresAt).toBe(
			new Date(Date.parse(lease.acquiredAt) + LEASE_MAX_SECONDS * 1000).toISOString(),
		);
		// Another id, or a lease that has expired, is refused.
		await expect(t.deployer.renewLease('hello-pr-7', 'x'.repeat(20), 60)).rejects.toBeInstanceOf(
			NoSuchLeaseError,
		);
		t.advance(3 * HOUR);
		await expect(t.deployer.renewLease('hello-pr-7', lease.leaseId, 60)).rejects.toBeInstanceOf(
			NoSuchLeaseError,
		);
		await expect(t.deployer.renewLease('nobody', lease.leaseId, 60)).rejects.toBeInstanceOf(
			NoSuchPreviewError,
		);
	});

	test('names the leased deployment to a run while the lease holds, and refuses otherwise', async () => {
		const t = await setup();
		await t.up(request());
		const d = (await t.store.get('hello-pr-7'))?.deployment;
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'run', 600);
		expect(await t.deployer.leasedDeployment('hello-pr-7', lease.leaseId)).toEqual({
			container: d?.container ?? '',
			port: 8080,
			deploymentId: d?.deploymentId ?? '',
		});
		await expect(t.deployer.leasedDeployment('hello-pr-7', 'x'.repeat(20))).rejects.toBeInstanceOf(
			NoSuchLeaseError,
		);
		await expect(t.deployer.leasedDeployment('nobody', lease.leaseId)).rejects.toBeInstanceOf(
			NoSuchPreviewError,
		);
		// Stopped for disk use under the lease: the deployment no longer serves.
		await t.store.update('hello-pr-7', (r) =>
			r.deployment === undefined ? r : { ...r, deployment: { ...r.deployment, halted: 'disk' } },
		);
		await expect(t.deployer.leasedDeployment('hello-pr-7', lease.leaseId)).rejects.toThrow(
			'no longer serves the deployment the lease holds',
		);
		await t.store.update('hello-pr-7', (r) =>
			r.deployment === undefined ? r : { ...r, deployment: { ...r.deployment, halted: undefined } },
		);
		expect((await t.deployer.leasedDeployment('hello-pr-7', lease.leaseId)).port).toBe(8080);
		// Expired, it holds nothing.
		t.advance(600_001);
		await expect(t.deployer.leasedDeployment('hello-pr-7', lease.leaseId)).rejects.toBeInstanceOf(
			NoSuchLeaseError,
		);
	});

	test('refuses a lease when nothing serves', async () => {
		const t = await setup();
		t.docker.buildError = 'docker build exited 1';
		await t.up(request());
		expect((await t.store.get('hello-pr-7'))?.status).toBe('failed');
		await expect(t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			'hello-pr-7 has no serving deployment to lease',
		);
		// A deployment from before koid kept ids cannot be identified either.
		t.docker.buildError = undefined;
		await t.up(request());
		await t.store.update('hello-pr-7', (r) => {
			if (r.deployment === undefined) return r;
			const { deploymentId: _id, imageDigest: _digest, ...old } = r.deployment;
			return { ...r, deployment: old };
		});
		await expect(t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			'made before koid recorded deployment ids',
		);
		// A deployment stopped for disk use serves nothing.
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2' }));
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		t.docker.diskBytes.set(container, 11 * 1024 ** 3);
		expect(await t.deployer.stopOversized()).toEqual([container]);
		await expect(t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			'has no serving deployment',
		);
	});

	test('refuses a lease on a preview whose container is stopped, until a visit starts it', async () => {
		const t = await setup();
		await t.up(request());
		// The box slept and woke: every container is stopped and unrouted,
		// and the record still says running. A visit whose start fails
		// leaves it so.
		t.docker.stopAll();
		await t.deployer.sync();
		t.setHealthy(() => false);
		await t.deployer.ensureRunning('hello-pr-7');
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'stopped' });
		const refused = t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		await expect(refused).rejects.toBeInstanceOf(LeaseError);
		await expect(refused).rejects.toThrow(
			'hello-pr-7 is not running; open https://hello-pr-7.previews.example.net/ to start it, then run koi lease again',
		);
		expect((await t.store.get('hello-pr-7'))?.lease).toBeUndefined();
		// A visit that starts it makes it leasable, bound to the same deployment.
		t.setHealthy(undefined);
		await t.deployer.ensureRunning('hello-pr-7');
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
		const reply = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		expect(reply.deployment.deploymentId).toBe(
			(await t.store.get('hello-pr-7'))?.deployment?.deploymentId ?? '',
		);
	});

	test('refuses a lease on a container that runs but has no route', async () => {
		const t = await setup();
		await t.up(request());
		t.docker.stopAll();
		await t.deployer.sync();
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		// Started outside koid: Docker runs it, Caddy sends nobody to it.
		await t.docker.start(container);
		expect((await t.docker.inspect(container)).running).toBe(true);
		expect(t.lastRoutes()).toEqual([]);
		await expect(t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			'hello-pr-7 is not running',
		);
		expect((await t.store.get('hello-pr-7'))?.lease).toBeUndefined();
	});

	test('refuses a lease on a routed container that has exited since the last sync', async () => {
		const t = await setup();
		await t.up(request());
		const container = (await t.store.get('hello-pr-7'))?.deployment?.container ?? '';
		await t.docker.stop(container);
		expect(t.lastRoutes()).toHaveLength(1);
		await expect(t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			'hello-pr-7 is not running',
		);
		// Finding it stopped takes its route away, as a visit would.
		await eventually(() => t.lastRoutes().length === 0);
	});

	test('refuses a lease on a preview past its ttl', async () => {
		const t = await setup();
		await t.up(request());
		t.advance(8 * 86_400_000);
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'overdue' });
		await expect(t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			'hello-pr-7 is past its ttl and expires on its next visit; run koi up to deploy it again',
		);
	});

	test('refuses a lease while a build of the label is in progress', async () => {
		const t = await setup();
		await t.up(request());
		const gate = t.hold('probe');
		const second = request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) });
		t.addRequest(second);
		await t.deployer.up(second.id);
		await gate.reached;
		await expect(t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			'is building request bbbbbbbbbbbbbbbb2',
		);
		gate.release();
		await t.deployer.settled('hello-pr-7');
		// Once it has deployed, the lease binds to the new deployment.
		const reply = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		expect(reply.deployment.commit).toBe('b'.repeat(40));
	});

	test('a build request for a leased label is refused before anything is built', async () => {
		const t = await setup();
		await t.up(request());
		const before = await t.store.get('hello-pr-7');
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 3600);
		const second = request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) });
		const refused = t.up(second);
		await expect(refused).rejects.toBeInstanceOf(LeaseError);
		await expect(refused).rejects.toThrow(`leased by dev@laptop until ${lease.expiresAt}`);
		expect(t.docker.builds).toHaveLength(1);
		const after = await t.store.get('hello-pr-7');
		expect(after?.status).toBe('running');
		expect(after?.requestId).toBe(before?.requestId ?? '');
		expect(after?.deployment).toEqual(before?.deployment);
		// Sending the deployed request again is still nothing to do.
		expect(await t.up(request())).toEqual({ label: 'hello-pr-7', queued: false });
		// Once the lease has expired the build goes ahead, and drops the lease.
		t.advance(HOUR);
		await t.up(second);
		const replaced = await t.store.get('hello-pr-7');
		expect(replaced?.deployment?.commit).toBe('b'.repeat(40));
		expect(replaced?.lease).toBeUndefined();
	});

	test('down refuses a leased preview unless forced', async () => {
		const t = await setup();
		await t.up(request());
		const { lease } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 3600);
		const refused = t.deployer.down('hello-pr-7');
		await expect(refused).rejects.toBeInstanceOf(LeaseError);
		await expect(refused).rejects.toThrow(
			`leased by dev@laptop until ${lease.expiresAt}; run koi down hello-pr-7 --force`,
		);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(t.docker.containers.size).toBe(1);
		expect(await t.deployer.down('hello-pr-7', { force: true })).toBe(true);
		expect(await t.store.get('hello-pr-7')).toBeUndefined();
		expect(t.docker.containers.size).toBe(0);
		// An expired lease does not stand in the way.
		await t.up(request());
		await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		t.advance(61_000);
		expect(await t.deployer.down('hello-pr-7')).toBe(true);
	});

	test('a lease outlives a koid restart', async () => {
		const t = await setup();
		await t.up(request());
		const { lease, deployment } = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 3600);
		const deployer = t.restart();
		await deployer.reconcile();
		await expect(deployer.acquireLease('hello-pr-7', 'ci', 60)).rejects.toThrow(
			`leased by dev@laptop until ${lease.expiresAt}`,
		);
		const second = request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) });
		t.addRequest(second);
		await expect(deployer.up(second.id)).rejects.toBeInstanceOf(LeaseError);
		await deployer.releaseLease('hello-pr-7', lease.leaseId);
		const next = await deployer.acquireLease('hello-pr-7', 'ci', 60);
		expect(next.deployment).toEqual(deployment);
	});

	test('expiry of the preview takes its lease with its deployment', async () => {
		const t = await setup();
		await t.up(request());
		await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		t.advance(8 * 86_400_000);
		expect(await t.deployer.expire()).toEqual(['hello-pr-7']);
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('expired');
		expect(record?.lease).toBeUndefined();
		await expect(t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60)).rejects.toThrow(
			'has no serving deployment',
		);
	});

	test('refuses a lease while Caddy may serve a replacement the record does not name', async () => {
		const t = await setup();
		// The real applier against a fake Caddy admin API, so that the two
		// loads of one apply can part ways. `running` is the config Caddy
		// last accepted: what visitors reach.
		let running = '';
		let accepts = Number.POSITIVE_INFINITY;
		const loads: string[] = [];
		t.deps.caddy = caddyApplier({
			domain: 'previews.example.net',
			httpPort: 7777,
			logPort: 7778,
			file: join(await mkdtemp(join(tmpdir(), 'koid-lease-caddy-')), 'Caddyfile'),
			adminUrl: 'http://127.0.0.1:2019',
			fetch: (async (_url: URL, init: RequestInit) => {
				loads.push(String(init.body));
				if (accepts <= 0) return new Response('bad', { status: 502 });
				accepts -= 1;
				running = String(init.body);
				return new Response('', { status: 200 });
			}) as unknown as typeof fetch,
		});
		await t.up(request());
		const first = (await t.store.get('hello-pr-7'))?.deployment;
		expect(running).toContain('reverse_proxy 172.19.0.2:8080');
		// Caddy takes the cutover's first load and refuses every load after
		// it: the second load fails the cutover, and the sync that would put
		// the previous deployment back fails too.
		const before = loads.length;
		accepts = 1;
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) }));
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('failed');
		expect(record?.error).toContain('caddy rejected the config: 502');
		expect(record?.deployment).toEqual(first);
		expect(loads[before]).toContain('reverse_proxy 172.19.0.3:8080');
		// Visitors reach the replacement while the record names the previous
		// deployment, and both containers run.
		expect(running).toContain('reverse_proxy 172.19.0.3:8080');
		expect(t.docker.containers.has(first?.container ?? '')).toBe(true);
		expect(t.docker.containers.has('koi-hello-pr-7-bbbbbbbbbbbbbbbb2')).toBe(true);
		// koid's own view still says the previous deployment serves.
		expect(await t.deployer.view('hello-pr-7')).toEqual({ kind: 'running' });
		const refused = t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		await expect(refused).rejects.toBeInstanceOf(LeaseError);
		await expect(refused).rejects.toThrow(
			'the routes of hello-pr-7 are not settled: caddy rejected the config: 502 bad; what visitors reach may not be the recorded deployment',
		);
		expect((await t.store.get('hello-pr-7'))?.lease).toBeUndefined();
		// Caddy answers again. The lease's own sync puts the recorded
		// deployment back in front of visitors, and the lease names it.
		accepts = Number.POSITIVE_INFINITY;
		const reply = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		expect(reply.deployment.deploymentId).toBe(first?.deploymentId ?? '');
		expect(running).toContain('reverse_proxy 172.19.0.2:8080');
		expect(running).not.toContain('172.19.0.3');
	});

	test('a later sync settles the routes, and a lease then names what the record and Caddy agree on', async () => {
		const t = await setup();
		await t.up(request());
		const first = (await t.store.get('hello-pr-7'))?.deployment;
		// Caddy refuses the cutover (it may have taken it before failing),
		// the sync after the failure, and the sync the lease makes. The sync
		// before the container starts passes.
		t.rejectApplies(3, undefined, 1);
		const second = request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) });
		await t.up(second);
		expect((await t.store.get('hello-pr-7'))?.status).toBe('failed');
		expect((await t.store.get('hello-pr-7'))?.deployment).toEqual(first);
		expect(t.docker.containers.has('koi-hello-pr-7-bbbbbbbbbbbbbbbb2')).toBe(true);
		const refused = t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		await expect(refused).rejects.toBeInstanceOf(LeaseError);
		await expect(refused).rejects.toThrow('the routes of hello-pr-7 are not settled');
		expect((await t.store.get('hello-pr-7'))?.lease).toBeUndefined();
		// Caddy takes routes again, and a sync nothing to do with the lease
		// (the expiry sweep's, reconcile's, a visit's) settles them.
		await t.deployer.sync();
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.2:8080' }]);
		const reply = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		expect(reply.deployment.deploymentId).toBe(first?.deploymentId ?? '');
		expect(reply.deployment.commit).toBe('a'.repeat(40));
		expect((await t.store.get('hello-pr-7'))?.lease).toEqual(reply.lease);
		// The replacement is named only once a retry has deployed it.
		await t.deployer.releaseLease('hello-pr-7', reply.lease.leaseId);
		await t.up(second);
		const replaced = (await t.store.get('hello-pr-7'))?.deployment;
		expect(replaced?.commit).toBe('b'.repeat(40));
		expect(t.lastRoutes()).toEqual([{ label: 'hello-pr-7', upstream: '172.19.0.4:8080' }]);
		const again = await t.deployer.acquireLease('hello-pr-7', 'dev@laptop', 60);
		expect(again.deployment.deploymentId).toBe(replaced?.deploymentId ?? '');
		expect(again.deployment.commit).toBe('b'.repeat(40));
	});
});

describe('verification inputs', () => {
	const digestOf = (text: string) => `sha256:${createHash('sha256').update(text).digest('hex')}`;

	// A deployer with a snapshot hook: the build calls it with the extracted
	// source and the tarball before the cutover and the cleanup.
	async function withHook(
		hook: (input: { deploymentId: string; source: string; tarball: string }) => Promise<void>,
	) {
		const t = await setup();
		const { Deployer } = await import('../src/deployer.ts');
		const deployer = new Deployer({
			...t.deps,
			snapshotInputs: async (input) => {
				await hook({
					deploymentId: input.deploymentId,
					source: input.source,
					tarball: input.tarball,
				});
			},
		});
		return {
			t,
			async up() {
				const r = request();
				t.addRequest(r);
				await deployer.up(r.id);
				await deployer.settled(r.label);
				await deployer.published();
			},
		};
	}

	async function buildLog(stateDir: string): Promise<string> {
		const dir = join(stateDir, 'logs');
		const labels = await readdir(dir).catch(() => [] as string[]);
		for (const label of labels) {
			for (const name of await readdir(join(dir, label))) {
				if (name.endsWith('.build.log')) return readFile(join(dir, label, name), 'utf8');
			}
		}
		return '';
	}

	test('are kept from the build directory before it goes, under the deployment id', async () => {
		const seen: Array<{ deploymentId: string; source: string; tarball: string; existed: boolean }> =
			[];
		const h = await withHook(async (input) => {
			const existed = (await stat(input.source).catch(() => undefined)) !== undefined;
			seen.push({ ...input, existed });
		});
		await h.up();
		const record = await h.t.store.get('hello-pr-7');
		expect(seen).toHaveLength(1);
		expect(seen[0]?.deploymentId).toBe(record?.deployment?.deploymentId ?? '');
		expect(seen[0]?.existed).toBe(true);
		expect(seen[0]?.source).toBe(
			join(h.t.stateDir, 'builds', 'hello-pr-7', 'aaaaaaaaaaaaaaaa1', 'src'),
		);
		expect(seen[0]?.tarball).toBe(
			join(h.t.stateDir, 'builds', 'hello-pr-7', 'aaaaaaaaaaaaaaaa1', 'source.tar.gz'),
		);
		// The build directory went afterwards, as before.
		expect(await stat(seen[0]?.source ?? '').catch(() => undefined)).toBeUndefined();
		expect(record?.status).toBe('running');
	});

	test('are told the built-in recipe directory the build used, with its files as they were when the build started', async () => {
		const seen: Array<{ dir: string; files: Record<string, string> } | undefined> = [];
		const t = await setup({ builtin: builtinRecipe() });
		const { Deployer } = await import('../src/deployer.ts');
		const dir = join(t.root, 'recipes', 'storefront');
		const dockerfile = digestOf('FROM scratch\n');
		const recipeJson = digestOf(await readFile(join(dir, 'recipe.json'), 'utf8'));
		t.docker.onBuild = async () => {
			// The installed recipe is replaced while the build runs, as a
			// deploy of a newer koid does before it restarts this one.
			await writeFile(join(dir, 'Dockerfile'), 'FROM busybox\n');
		};
		const deployer = new Deployer({
			...t.deps,
			snapshotInputs: async (input) => {
				seen.push(input.recipe);
			},
		});
		const r = request({ recipe: { kind: 'builtin', name: 'storefront' } });
		t.addRequest(r);
		await deployer.up(r.id);
		await deployer.settled(r.label);
		const files = { Dockerfile: dockerfile, 'recipe.json': recipeJson };
		expect(seen).toEqual([{ dir, files }]);
		const repo = request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40) });
		t.addRequest(repo);
		await deployer.up(repo.id);
		await deployer.settled(repo.label);
		expect(seen).toEqual([{ dir, files }, undefined]);
	});

	test('replacing the installed recipe directory during the build changes nothing the build or the snapshot sees', async () => {
		const seen: Array<{ dir: string; files: Record<string, string> } | undefined> = [];
		const t = await setup({ builtin: builtinRecipe() });
		const { Deployer } = await import('../src/deployer.ts');
		const installed = join(t.root, 'recipes', 'storefront');
		const original = digestOf('FROM scratch\n');
		const recipeJson = digestOf(await readFile(join(installed, 'recipe.json'), 'utf8'));
		let read: { dockerfile: string; context: string[] } | undefined;
		t.docker.onBuild = async () => {
			// A deploy of a newer koid replaces the whole installed directory
			// while this build runs: new files, and the old Dockerfile gone.
			await rm(installed, { recursive: true, force: true });
			await mkdir(installed, { recursive: true });
			await writeFile(join(installed, 'Dockerfile'), 'FROM busybox\n');
			await writeFile(join(installed, 'setup.sh'), 'echo new\n');
			// What the builder reads now, from the paths it was given.
			const build = t.docker.builds[0];
			if (build === undefined) throw new Error('no build');
			read = {
				dockerfile: await readFile(build.dockerfile, 'utf8'),
				context: (await readdir(build.contexts?.recipe ?? '')).sort(),
			};
		};
		const deployer = new Deployer({
			...t.deps,
			snapshotInputs: async (input) => {
				seen.push(input.recipe);
			},
		});
		const r = request({ recipe: { kind: 'builtin', name: 'storefront' } });
		t.addRequest(r);
		await deployer.up(r.id);
		await deployer.settled(r.label);
		expect(read).toEqual({ dockerfile: 'FROM scratch\n', context: ['Dockerfile', 'recipe.json'] });
		expect(seen).toEqual([
			{ dir: installed, files: { Dockerfile: original, 'recipe.json': recipeJson } },
		]);
		expect((await t.store.get(r.label))?.status).toBe('running');
	});

	test('a recipe replaced after the request was accepted is built, run and recorded from the copy', async () => {
		const seen: Array<{ dir: string; files: Record<string, string> } | undefined> = [];
		const registered: string[] = [];
		// Containers started when each key was registered: none, if the key
		// is registered before it can reach one.
		const runsAt: number[] = [];
		const t = await setup({ builtin: builtinRecipe() });
		const { Deployer } = await import('../src/deployer.ts');
		const installed = join(t.root, 'recipes', 'storefront');
		const deployer = new Deployer({
			...t.deps,
			snapshotInputs: async (input) => {
				seen.push(input.recipe);
			},
			registerSecret: (value) => {
				registered.push(value);
				runsAt.push(t.docker.runs.length);
			},
		});
		// The build waits at its first keepAwake: accepted, not yet copying.
		const gate = t.hold('keepAwake');
		const r = request({ recipe: { kind: 'builtin', name: 'storefront' } });
		t.addRequest(r);
		await deployer.up(r.id);
		await gate.reached;
		// A deploy of a newer koid replaces the installed recipe meanwhile:
		// another port, an env, and a login key the old one did not have.
		const replaced = `${JSON.stringify(
			builtinRecipe({ port: 9100, env: { APP_MODE: 'preview' }, loginKeyEnv: 'APP_LOGIN_KEY' }),
		)}\n`;
		await writeFile(join(installed, 'recipe.json'), replaced);
		gate.release();
		await deployer.settled(r.label);
		const record = await t.store.get(r.label);
		expect(record?.status).toBe('running');
		// The deployment follows the copy, which is of the replaced recipe.
		expect(record?.deployment?.port).toBe(9100);
		expect(t.lastRoutes()[0]?.upstream).toEndWith(':9100');
		expect(record?.deployment?.env.APP_MODE).toBe('preview');
		// The key the copy asks for was made in the build, registered before
		// the container started, and the record keeps it.
		expect(record?.loginKey).toMatch(/^koi-[a-z0-9]{24}$/);
		expect(record?.deployment?.env.APP_LOGIN_KEY).toBe(record?.loginKey ?? '');
		expect(registered).toEqual([record?.loginKey ?? '']);
		expect(runsAt).toEqual([0]);
		// The snapshot digests the same bytes.
		expect(seen).toHaveLength(1);
		expect(seen[0]?.files['recipe.json']).toBe(digestOf(replaced));
	});

	test('plans the build from the copied recipe.json, not from the installed one', async () => {
		const seen: Array<{ dir: string; files: Record<string, string> } | undefined> = [];
		const t = await setup({ builtin: builtinRecipe() });
		const { Deployer } = await import('../src/deployer.ts');
		const installed = join(t.root, 'recipes', 'storefront');
		const copied = await readFile(join(installed, 'recipe.json'), 'utf8');
		let readFrom: string | undefined;
		const deployer = new Deployer({
			...t.deps,
			readRecipe: async (dir, name) => {
				// Between the copy and the read of it: the installed recipe
				// is replaced, with another port.
				readFrom = dir;
				await writeFile(
					join(installed, 'recipe.json'),
					`${JSON.stringify(builtinRecipe({ port: 9100 }))}\n`,
				);
				return t.deps.readRecipe(dir, name);
			},
			snapshotInputs: async (input) => {
				seen.push(input.recipe);
			},
		});
		const r = request({ recipe: { kind: 'builtin', name: 'storefront' } });
		t.addRequest(r);
		await deployer.up(r.id);
		await deployer.settled(r.label);
		expect(readFrom).toBe(join(t.stateDir, 'builds', r.label, r.id, 'recipe'));
		const record = await t.store.get(r.label);
		expect(record?.status).toBe('running');
		expect(record?.deployment?.port).toBe(9000);
		expect(t.lastRoutes()[0]?.upstream).toEndWith(':9000');
		expect(seen[0]?.files['recipe.json']).toBe(digestOf(copied));
	});

	test('a snapshot that fails is logged and does not fail the deploy', async () => {
		const h = await withHook(async () => {
			throw new Error('disk full');
		});
		await h.up();
		expect((await h.t.store.get('hello-pr-7'))?.status).toBe('running');
		const log = await buildLog(h.t.stateDir);
		expect(log).toContain('the verification inputs were not kept: disk full');
	});
});

// A built-in recipe as the box would install it, with its Dockerfile in
// the recipe directory.
function builtinRecipe(overrides: Record<string, unknown> = {}) {
	return RecipeSchema.parse({
		name: 'storefront',
		port: 9000,
		build: { kind: 'dockerfile', from: 'recipe', path: 'Dockerfile', context: '.' },
		...overrides,
	});
}

describe('login keys and the secret registry', () => {
	test('a key made for a new preview is registered before anything is built or started with it', async () => {
		const registered: string[] = [];
		// What the box had done when each key was registered: nothing, if
		// the key is registered before it can reach a container.
		const seenAt: Array<{ builds: number; runs: number; records: number }> = [];
		const t = await setup({ builtin: builtinRecipe({ loginKeyEnv: 'APP_LOGIN_KEY' }) });
		const { Deployer } = await import('../src/deployer.ts');
		const deployer = new Deployer({
			...t.deps,
			registerSecret: (value) => {
				registered.push(value);
				seenAt.push({
					builds: t.docker.builds.length,
					runs: t.docker.runs.length,
					records: t.store.list === undefined ? -1 : 0,
				});
			},
		});
		const r = request({ recipe: { kind: 'builtin', name: 'storefront' } });
		t.addRequest(r);
		await deployer.up(r.id);
		await deployer.settled(r.label);
		const record = await t.store.get(r.label);
		expect(record?.loginKey).toMatch(/^koi-[a-z0-9]{24}$/);
		expect(registered).toEqual([record?.loginKey ?? '']);
		expect(seenAt).toEqual([{ builds: 0, runs: 0, records: 0 }]);
		expect(record?.deployment?.env.APP_LOGIN_KEY).toBe(record?.loginKey ?? '');
		// A second build of the same preview keeps the key and registers
		// nothing new.
		const again = request({
			id: 'bbbbbbbbbbbbbbbb2',
			commit: 'b'.repeat(40),
			recipe: { kind: 'builtin', name: 'storefront' },
		});
		t.addRequest(again);
		await deployer.up(again.id);
		await deployer.settled(again.label);
		expect(registered).toHaveLength(1);
		expect((await t.store.get(r.label))?.loginKey).toBe(record?.loginKey ?? '');
	});
});
