import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readdir, readFile, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildAdapters } from '../src/adapters.ts';
import { loadConfig } from '../src/config.ts';
import { NoSuchUploadError, REQUEST_FILE, SOURCE_FILE, spoolLayout } from '../src/spool-uploads.ts';
import { request, setup } from './fakes.ts';

const DOMAIN = { KOI_DOMAIN: 'previews.example.net' };

// 62 characters each: 64 of them are more than an SSM parameter holds.
const long = (i: number) => `x${String(i).padStart(3, '0')}${'a'.repeat(58)}`;
const labels = (n: number) => Array.from({ length: n }, (_, i) => long(i));

function deps() {
	const logs: string[] = [];
	return { log: (m: string) => logs.push(m), logs };
}

// A committed entry as the upload API publishes it (upload-api.test.ts
// covers the API itself; the API here measures this machine's disk).
async function committed(readyDir: string, id: string, bytes: Uint8Array) {
	await mkdir(join(readyDir, id), { recursive: true });
	await writeFile(join(readyDir, id, REQUEST_FILE), JSON.stringify(request({ id })));
	await writeFile(join(readyDir, id, SOURCE_FILE), bytes);
}

describe('buildAdapters', () => {
	test('the AWS settings alone give S3 uploads, an SSM live list with its cap, and no spool', () => {
		const config = loadConfig({ ...DOMAIN, KOI_UPLOADS_BUCKET: 'bucket' });
		const adapters = buildAdapters(config, deps());
		expect(adapters.spool).toBeUndefined();
		expect(adapters.live.room(labels(63))).toEqual({ ok: true });
		expect(adapters.live.room(labels(64))).toEqual({
			ok: false,
			reason: 'it would pass the 4096 bytes its SSM parameter holds',
		});
	});

	test('the spool gives a reader over its ready directory, the upload API, and a file live list without a cap', async () => {
		const root = await mkdtemp(join(tmpdir(), 'koid-adapters-'));
		const config = loadConfig({
			...DOMAIN,
			KOI_UPLOADS: 'spool',
			KOI_SPOOL_DIR: join(root, 'uploads'),
			KOI_SPOOL_BUDGET_BYTES: '1048576',
			KOI_LIVE_FILE: join(root, 'live.json'),
		});
		const adapters = buildAdapters(config, deps());
		expect(adapters.spool).toBeDefined();
		await adapters.spool?.init();
		await expect(adapters.uploads.request('a'.repeat(20))).rejects.toBeInstanceOf(
			NoSuchUploadError,
		);
		// A claim through the reader is the API's: an entry that is not there
		// cannot be claimed.
		await expect(adapters.uploads.claim('a'.repeat(20))).rejects.toBeInstanceOf(NoSuchUploadError);
		expect(adapters.live.room(labels(500))).toEqual({ ok: true });
		await adapters.live.publish(['b', 'a']);
		expect(await readFile(join(root, 'live.json'), 'utf8')).toBe('["a","b"]\n');
	});

	test('the deployer claims an upload as it accepts the request, so cleanup leaves it until the build has the source', async () => {
		const root = await mkdtemp(join(tmpdir(), 'koid-adapters-'));
		const config = loadConfig({
			...DOMAIN,
			KOI_UPLOADS: 'spool',
			KOI_SPOOL_DIR: join(root, 'uploads'),
			KOI_LIVE_FILE: join(root, 'live.json'),
		});
		const adapters = buildAdapters(config, deps());
		const spool = adapters.spool;
		if (spool === undefined) throw new Error('no spool');
		const id = 'claimed0123456789abc';
		const bytes = Buffer.from('the source archive');
		const ready = spoolLayout(join(root, 'uploads')).ready;
		// Committed by an earlier koid: this one reads it in at startup.
		await committed(ready, id, bytes);
		await spool.init();
		// The real deployer over the real reader. Its build stops after it is
		// recorded as building and before it copies the source.
		const t = await setup({ uploads: adapters.uploads });
		const gate = t.hold('keepAwake');
		expect(await t.deployer.up(id)).toEqual({ label: 'hello-pr-7', queued: false });
		await gate.reached;
		// The entry is long past its day, and cleanup runs: it stays, claimed.
		const old = new Date(Date.now() - 2 * 24 * 60 * 60_000);
		await utimes(join(ready, id, REQUEST_FILE), old, old);
		await spool.cleanup();
		expect(await readdir(ready)).toEqual([id]);
		gate.release();
		await t.deployer.settled('hello-pr-7');
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(t.tarballSizes).toEqual([bytes.byteLength]);
		// The build has its copy, the claim is released, and the old entry goes.
		await spool.cleanup();
		expect(await readdir(ready)).toEqual([]);
	});

	test('S3 uploads with a file live list, when asked', async () => {
		const root = await mkdtemp(join(tmpdir(), 'koid-adapters-'));
		const config = loadConfig({
			...DOMAIN,
			KOI_UPLOADS_BUCKET: 'bucket',
			KOI_LIVE: 'file',
			KOI_LIVE_FILE: join(root, 'live.json'),
		});
		const adapters = buildAdapters(config, deps());
		expect(adapters.spool).toBeUndefined();
		expect(adapters.live.room(labels(64))).toEqual({ ok: true });
	});
});
