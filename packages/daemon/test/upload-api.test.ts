import { describe, expect, spyOn, test } from 'bun:test';
import { createHash } from 'node:crypto';
import type { PathLike, StatOptions } from 'node:fs';
import * as fsp from 'node:fs/promises';
import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	realpath,
	stat,
	utimes,
	writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { HostInfo, UpRequest } from '@koi/shared';
import { type ControlDeps, startControlServer } from '../src/control.ts';
import {
	MAX_REQUEST_BYTES,
	NoSuchUploadError,
	REQUEST_FILE,
	SOURCE_FILE,
	spoolLayout,
	spoolUploads,
} from '../src/spool-uploads.ts';
import { UploadApi, type UploadApiOptions } from '../src/upload-api.ts';
import {
	setup as deployerSetup,
	Gate,
	openingWith,
	overstatingSize,
	readingShort,
	request,
} from './fakes.ts';

const ID = 'abcdefghij0123456789';
const OTHER = 'b'.repeat(20);

function sha256(bytes: Uint8Array): string {
	return createHash('sha256').update(bytes).digest('hex');
}

// A source of `size` bytes that is not all one value, so a wrong slice has a
// different digest.
function source(size = 300_000): Buffer {
	const b = Buffer.alloc(size);
	for (let i = 0; i < size; i++) b[i] = (i * 7) & 0xff;
	return b;
}

// `bytes` in chunks of `size`, as a body streams in.
function chunked(bytes: Uint8Array, size = 64 * 1024): ReadableStream<Uint8Array> {
	let offset = 0;
	return new ReadableStream({
		pull(c) {
			if (offset >= bytes.byteLength) return c.close();
			c.enqueue(bytes.subarray(offset, offset + size));
			offset += size;
		},
	});
}

// A body that never ends; `pulled` counts the chunks taken from it.
function endless(size = 64 * 1024) {
	const state = { pulled: 0 };
	const stream = new ReadableStream<Uint8Array>({
		pull(c) {
			state.pulled += 1;
			c.enqueue(new Uint8Array(size));
		},
	});
	return { stream, state };
}

// `bytes` in chunks, as a body streams in, with each chunk's room taken
// from `disk` once the reader has written it: the reader writes a chunk
// before it asks for the next (no read-ahead, with the high-water mark at
// zero), so the disk shows what has landed when the next pull runs. Stops
// at `gate` once `pause` bytes have landed.
function landing(
	bytes: Uint8Array,
	disk: { free: number },
	gate: Gate,
	pause: number,
	size = 64 * 1024,
): ReadableStream<Uint8Array> {
	let offset = 0;
	let landed = 0;
	return new ReadableStream(
		{
			async pull(c) {
				disk.free -= offset - landed;
				landed = offset;
				if (landed === pause) await gate.pass();
				if (offset >= bytes.byteLength) return c.close();
				c.enqueue(bytes.subarray(offset, offset + size));
				offset = Math.min(offset + size, bytes.byteLength);
			},
		},
		{ highWaterMark: 0 },
	);
}

// An error as the filesystem raises it when the disk is full.
function enospc(): Error {
	return Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' });
}

// An error as the filesystem raises it when a sync or a removal fails.
function eio(): Error {
	return Object.assign(new Error('EIO: i/o error'), { code: 'EIO' });
}

// What the ledger says the spool holds and has promised, read off the
// refusal of a ticket for a source as large as the whole budget.
async function ledger(t: Awaited<ReturnType<typeof setup>>, budgetBytes = 10 * 1024 ** 2) {
	const res = await t.call(
		'POST',
		'',
		JSON.stringify({ ...ticketBody('z'.repeat(20), source(10)), sizeBytes: budgetBytes }),
	);
	expect(res.status).toBe(507);
	const { error } = (await res.json()) as { error: string };
	const used = /upload spool has (\d+) of its/.exec(error)?.[1];
	if (used === undefined) throw new Error(`not a budget refusal: ${error}`);
	return Number(used);
}

// The bytes of a committed entry's files, as they are on the disk.
async function entryOnDisk(t: Awaited<ReturnType<typeof setup>>, id: string): Promise<number> {
	const dir = join(t.layout.ready, id);
	return (await stat(join(dir, SOURCE_FILE))).size + (await stat(join(dir, REQUEST_FILE))).size;
}

// The sync of the ready directory, after the rename, runs `sync` in place
// of the real one, with the real one to hand. A second API over the same
// spool syncs the same directory, so the spy covers it too.
function syncingReady(
	t: Awaited<ReturnType<typeof setup>>,
	sync: (real: () => Promise<void>) => Promise<void>,
) {
	const original = fsp.open;
	return spyOn(fsp, 'open').mockImplementation(async (path, ...rest) => {
		const handle = await original(path, ...rest);
		if (path === t.layout.ready) {
			const real = handle.sync.bind(handle);
			spyOn(handle, 'sync').mockImplementation(() => sync(real));
		}
		return handle;
	});
}

// A body that sends `first` and then nothing, for ever.
function stalled(first: Uint8Array): ReadableStream<Uint8Array> {
	let sent = false;
	return new ReadableStream({
		pull(c) {
			if (sent) return new Promise<void>(() => {});
			sent = true;
			c.enqueue(first);
			return undefined;
		},
	});
}

type Body = string | Uint8Array | ReadableStream<Uint8Array> | undefined;

function requestFor(method: string, path: string, body: Body): Request {
	const init: Record<string, unknown> = { method };
	if (body !== undefined) {
		init.body = body;
		if (body instanceof ReadableStream) init.duplex = 'half';
	}
	return new Request(`http://koid/v1/uploads${path}`, init as RequestInit);
}

async function setup(overrides: Partial<UploadApiOptions> = {}) {
	// Resolved, so a path the API opens after realpath compares equal to
	// one built from it here.
	const root = await realpath(await mkdtemp(join(tmpdir(), 'koid-upload-')));
	// Real time, so entries written now age against it.
	let now = Date.now();
	const logs: string[] = [];
	const disk = { free: 100 * 1024 ** 3, size: 200 * 1024 ** 3 };
	const api = new UploadApi({
		spoolDir: root,
		budgetBytes: 10 * 1024 ** 2,
		log: (m) => logs.push(m),
		now: () => now,
		diskSpace: async () => ({ ...disk }),
		limits: { sourceTimeoutMs: 300 },
		...overrides,
	});
	await api.init();
	const layout = spoolLayout(root);
	const call = (method: string, path: string, body?: Body) =>
		api.handle(
			requestFor(method, path, body),
			path.split('/').filter((p) => p !== ''),
		);
	const bytes = source();
	const req = (overrides: Partial<UpRequest> = {}) =>
		request({ id: ID, createdAt: new Date(now).toISOString(), ...overrides });
	return {
		root,
		layout,
		api,
		call,
		logs,
		disk,
		bytes,
		req,
		advance(ms: number) {
			now += ms;
		},
		// A ticket for `bytes` under `id`, or for other bytes.
		async ticket(id = ID, data: Uint8Array = bytes): Promise<string> {
			const res = await call('POST', '', JSON.stringify(ticketBody(id, data)));
			expect(res.status).toBe(201);
			const { uploadId } = (await res.json()) as { uploadId: string };
			return uploadId;
		},
		async put(uploadId: string, data: Uint8Array = bytes): Promise<Response> {
			return call('PUT', `/${uploadId}/source`, chunked(data));
		},
		async commit(uploadId: string, r: UpRequest = req()): Promise<Response> {
			return call('POST', `/${uploadId}/commit`, JSON.stringify(r));
		},
		// The whole sequence, as the CLI will run it.
		async upload(id = ID, data: Uint8Array = bytes, r: UpRequest = req({ id })) {
			const uploadId = await this.ticket(id, data);
			expect((await this.put(uploadId, data)).status).toBe(200);
			const res = await this.commit(uploadId, r);
			expect(res.status).toBe(200);
			return uploadId;
		},
	};
}

const ticketBody = (id: string, bytes: Uint8Array) => ({
	requestId: id,
	sizeBytes: bytes.byteLength,
	sha256: sha256(bytes),
});

describe('POST /v1/uploads', () => {
	test('gives a random upload id that names nothing a caller chose, and reserves a directory', async () => {
		const t = await setup();
		const res = await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)));
		expect(res.status).toBe(201);
		const body = (await res.json()) as { uploadId: string; expiresAt: string };
		expect(body.uploadId).toMatch(/^[0-9a-f]{32}$/);
		expect(body.uploadId).not.toContain(ID);
		expect(Date.parse(body.expiresAt) - Date.now()).toBeGreaterThan(55 * 60_000);
		const dir = join(t.layout.incoming, body.uploadId);
		expect((await stat(dir)).mode & 0o777).toBe(0o700);
		expect(await readdir(dir)).toEqual([]);
		// Two tickets never share an id.
		expect(await t.ticket()).not.toBe(body.uploadId);
	});

	test('rejects a malformed body, id, size or digest with 400', async () => {
		const t = await setup();
		expect((await t.call('POST', '', '{')).status).toBe(400);
		expect((await t.call('POST', '', JSON.stringify({ requestId: ID }))).status).toBe(400);
		for (const bad of [
			{ ...ticketBody(ID, t.bytes), requestId: '../x' },
			{ ...ticketBody(ID, t.bytes), sizeBytes: 0 },
			{ ...ticketBody(ID, t.bytes), sizeBytes: 1.5 },
			{ ...ticketBody(ID, t.bytes), sha256: 'abc' },
			{ ...ticketBody(ID, t.bytes), sha256: sha256(t.bytes).toUpperCase() },
		]) {
			const res = await t.call('POST', '', JSON.stringify(bad));
			expect(res.status).toBe(400);
			expect(((await res.json()) as { error: string }).error).toBe('bad request');
		}
		expect(await readdir(t.layout.incoming)).toEqual([]);
	});

	test('refuses a declared size over 2 GiB with 413', async () => {
		const t = await setup();
		const res = await t.call(
			'POST',
			'',
			JSON.stringify({ ...ticketBody(ID, t.bytes), sizeBytes: 2 * 1024 ** 3 + 1 }),
		);
		expect(res.status).toBe(413);
		expect(await readdir(t.layout.incoming)).toEqual([]);
	});

	test('refuses an upload the budget cannot hold with 507, counting committed entries and open tickets', async () => {
		const t = await setup({ budgetBytes: 1024 ** 2 });
		const big = source(600 * 1024);
		const first = await t.ticket(ID, big);
		// The first ticket reserves its source and a request file (614400 +
		// 262144), which leaves no room for a second of the same size.
		const second = await t.call('POST', '', JSON.stringify(ticketBody(OTHER, big)));
		expect(second.status).toBe(507);
		expect(((await second.json()) as { error: string }).error).toMatch(
			/upload spool has 876544 of its 1048576 bytes in use or reserved/,
		);
		// Committed, the entry counts for what it is on disk: the source and
		// the request file, and the ticket reserves nothing more.
		expect((await t.put(first, big)).status).toBe(200);
		expect((await t.commit(first, t.req())).status).toBe(200);
		const requestBytes = (await stat(join(t.layout.ready, ID, REQUEST_FILE))).size;
		const again = await t.call('POST', '', JSON.stringify(ticketBody(OTHER, big)));
		expect(again.status).toBe(507);
		expect(((await again.json()) as { error: string }).error).toMatch(
			new RegExp(`upload spool has ${614400 + requestBytes} of its 1048576 bytes`),
		);
		// A small one fits beside it.
		expect((await t.call('POST', '', JSON.stringify(ticketBody(OTHER, source(1000))))).status).toBe(
			201,
		);
		// Once the entry expires, there is room again.
		t.advance(25 * 60 * 60_000);
		await t.api.cleanup();
		expect((await t.call('POST', '', JSON.stringify(ticketBody(OTHER, big)))).status).toBe(201);
	});

	test('a ticket reserves the most a request file can be along with its source', async () => {
		const short = await setup({ budgetBytes: 300_000 + MAX_REQUEST_BYTES - 1 });
		const res = await short.call('POST', '', JSON.stringify(ticketBody(ID, short.bytes)));
		expect(res.status).toBe(507);
		expect(await readdir(short.layout.incoming)).toEqual([]);
		const exact = await setup({ budgetBytes: 300_000 + MAX_REQUEST_BYTES });
		expect((await exact.call('POST', '', JSON.stringify(ticketBody(ID, exact.bytes)))).status).toBe(
			201,
		);
	});

	test('counts the ledger, not the disk: the budget tracks what was admitted and committed', async () => {
		const t = await setup({ budgetBytes: 2 * (300_000 + MAX_REQUEST_BYTES) });
		await t.upload();
		// A whole entry dropped into ready behind the API's back is not in
		// the ledger until the next startup, and takes nothing from the
		// budget.
		await mkdir(join(t.layout.ready, OTHER));
		await writeFile(join(t.layout.ready, OTHER, SOURCE_FILE), source(400_000));
		await writeFile(
			join(t.layout.ready, OTHER, REQUEST_FILE),
			JSON.stringify(t.req({ id: OTHER })),
		);
		expect(
			(await t.call('POST', '', JSON.stringify(ticketBody('c'.repeat(20), t.bytes)))).status,
		).toBe(201);
		// A new API over the same spool reads it in.
		const fresh = new UploadApi({
			spoolDir: t.root,
			budgetBytes: 2 * (300_000 + MAX_REQUEST_BYTES),
			log: () => {},
			diskSpace: async () => ({ ...t.disk }),
		});
		await fresh.init();
		const res = await fresh.handle(
			requestFor('POST', '', JSON.stringify(ticketBody('c'.repeat(20), t.bytes))),
			[],
		);
		expect(res.status).toBe(507);
	});

	test('refuses an upload that would take the disk under its reserve with 507', async () => {
		const t = await setup();
		// 10% of 200 GiB is 20 GiB; 20 GiB and a bit free leaves less than
		// that after the upload and its request file.
		t.disk.free = 20 * 1024 ** 3 + 1000;
		const res = await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)));
		expect(res.status).toBe(507);
		expect(((await res.json()) as { error: string }).error).toMatch(/keeps free/);
		t.disk.free = 20 * 1024 ** 3 + t.bytes.byteLength + MAX_REQUEST_BYTES - 1;
		expect((await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)))).status).toBe(507);
		t.disk.free = 20 * 1024 ** 3 + t.bytes.byteLength + MAX_REQUEST_BYTES;
		expect((await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)))).status).toBe(201);
	});

	test('keeps a tenth of a small disk free, and no more than 20 GiB of a large one', async () => {
		const edge = async (size: number, keep: number) => {
			const t = await setup();
			const upload = JSON.stringify(ticketBody(ID, t.bytes));
			t.disk.size = size;
			t.disk.free = keep + t.bytes.byteLength + MAX_REQUEST_BYTES - 1;
			expect((await t.call('POST', '', upload)).status).toBe(507);
			t.disk.free += 1;
			expect((await t.call('POST', '', upload)).status).toBe(201);
		};
		// 100 GiB: a tenth is 10 GiB.
		await edge(100 * 1024 ** 3, 10 * 1024 ** 3);
		// 2 TiB: a tenth would be 204.8 GiB; the cap keeps 20 GiB.
		await edge(2048 * 1024 ** 3, 20 * 1024 ** 3);
	});

	test('takes bytes promised to tickets under way off the free space: two tickets cannot both fit the reserve', async () => {
		const t = await setup();
		const reserve = 20 * 1024 ** 3;
		const each = t.bytes.byteLength + MAX_REQUEST_BYTES;
		const promised = async () => {
			const res = await t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)));
			expect(res.status).toBe(507);
			return ((await res.json()) as { error: string }).error;
		};
		// Room for one upload and its request file over the reserve, not two.
		t.disk.free = reserve + 2 * each - 1;
		const first = await t.ticket();
		expect(await promised()).toMatch(new RegExp(`${each} of them promised to uploads under way`));
		// Part of the first source has landed and the PUT waits: the
		// measurement shows those bytes and the ticket no longer promises
		// them, so the room is the same.
		const gate = new Gate();
		const put = t.call('PUT', `/${first}/source`, landing(t.bytes, t.disk, gate, 2 * 64 * 1024));
		await gate.reached;
		expect(t.disk.free).toBe(reserve + 2 * each - 1 - 2 * 64 * 1024);
		expect(await promised()).toMatch(
			new RegExp(`${each - 2 * 64 * 1024} of them promised to uploads under way`),
		);
		gate.release();
		expect((await put).status).toBe(200);
		// The whole source is on the disk; only its request file is still
		// promised, and the second still does not fit.
		expect(t.disk.free).toBe(reserve + 2 * each - 1 - t.bytes.byteLength);
		expect(await promised()).toMatch(
			new RegExp(`${MAX_REQUEST_BYTES} of them promised to uploads under way`),
		);
		// With one more byte of room it does.
		t.disk.free += 1;
		expect((await t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)))).status).toBe(201);
	});

	test('a source that lands while the disk is measured is counted once: promised bytes are counted first', async () => {
		// The admission measures the disk and waits inside the measurement;
		// the first source arrives whole meanwhile. Were the promised bytes
		// counted after, the measurement (taken before the source landed)
		// and the count (taken after) would both leave those bytes out.
		const gate = new Gate();
		let parked = false;
		const disk = { free: 0, size: 200 * 1024 ** 3 };
		const t = await setup({
			diskSpace: async () => {
				const measured = { ...disk };
				if (parked) await gate.pass();
				return measured;
			},
		});
		const reserve = 20 * 1024 ** 3;
		const each = t.bytes.byteLength + MAX_REQUEST_BYTES;
		disk.free = reserve + 2 * each - 1;
		const first = await t.ticket();
		parked = true;
		const admission = t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)));
		await gate.reached;
		expect((await t.put(first)).status).toBe(200);
		disk.free -= t.bytes.byteLength;
		gate.release();
		const res = await admission;
		expect(res.status).toBe(507);
		expect(((await res.json()) as { error: string }).error).toMatch(
			new RegExp(`${each} of them promised to uploads under way`),
		);
		// Measured now, the disk shows the source and the count credits it.
		parked = false;
		expect((await t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)))).status).toBe(507);
		disk.free += 1;
		expect((await t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)))).status).toBe(201);
	});

	test('a commit waits for an admission under way, so the two never count past the budget', async () => {
		// Budget for one upload of 300,000 bytes and its reservation, not
		// two. The ticket under commit holds its reservation until the commit
		// moves the entry and the ledger in one step, so an admission that
		// runs meanwhile sees the bytes either way.
		const budget = 600_000;
		const gate = new Gate();
		let parked = false;
		const disk = { free: 100 * 1024 ** 3, size: 200 * 1024 ** 3 };
		const t = await setup({
			budgetBytes: budget,
			diskSpace: async () => {
				if (parked) await gate.pass();
				return disk;
			},
		});
		const a = await t.ticket();
		expect((await t.put(a)).status).toBe(200);
		// An admission for another request stops inside the mutex, after it
		// has read the ledger.
		parked = true;
		const admission = t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)));
		await gate.reached;
		let committed = false;
		const commit = t.commit(a).then((res) => {
			committed = true;
			return res;
		});
		await Bun.sleep(20);
		expect(committed).toBe(false);
		gate.release();
		expect((await admission).status).toBe(507);
		expect((await commit).status).toBe(200);
		// The ledger holds one entry, under 301,000 bytes, and no reservation:
		// a small ticket fits.
		const res = await t.call('POST', '', JSON.stringify(ticketBody(OTHER, source(50))));
		expect(res.status).toBe(201);
	});

	test('answers 408 for ticket JSON that stalls, and 413 for JSON over 256 KiB', async () => {
		const t = await setup({ limits: { requestTimeoutMs: 200 } });
		const started = Date.now();
		const res = await t.call('POST', '', stalled(new TextEncoder().encode('{"requestId":')));
		expect(res.status).toBe(408);
		expect(((await res.json()) as { error: string }).error).toBe(
			'the request did not arrive within 0.2 seconds',
		);
		expect(Date.now() - started).toBeLessThan(2000);
		const body = endless();
		expect((await t.call('POST', '', body.stream)).status).toBe(413);
		expect(body.state.pulled).toBeLessThan(10);
		expect(await readdir(t.layout.incoming)).toEqual([]);
	});

	test('answers 507 when the disk is full as the ticket directory is made, and keeps no ticket', async () => {
		const t = await setup();
		const spy = spyOn(fsp, 'mkdir').mockRejectedValueOnce(enospc());
		try {
			const res = await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)));
			expect(res.status).toBe(507);
			expect(((await res.json()) as { error: string }).error).toBe('the disk is full');
		} finally {
			spy.mockRestore();
		}
		expect(await readdir(t.layout.incoming)).toEqual([]);
		// The reservation went with it: the full budget is there.
		const full = await setup({ budgetBytes: 300_000 + MAX_REQUEST_BYTES });
		const again = spyOn(fsp, 'mkdir').mockRejectedValueOnce(enospc());
		try {
			expect((await full.call('POST', '', JSON.stringify(ticketBody(ID, full.bytes)))).status).toBe(
				507,
			);
		} finally {
			again.mockRestore();
		}
		expect((await full.call('POST', '', JSON.stringify(ticketBody(ID, full.bytes)))).status).toBe(
			201,
		);
	});

	test('answers 200 committed for content already committed, and 409 for other content under the same id', async () => {
		const t = await setup();
		await t.upload();
		const same = await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)));
		expect(same.status).toBe(200);
		expect(await same.json()).toEqual({ committed: true, requestId: ID });
		const otherBytes = source(t.bytes.byteLength);
		otherBytes[0] = 255;
		const differentDigest = await t.call('POST', '', JSON.stringify(ticketBody(ID, otherBytes)));
		expect(differentDigest.status).toBe(409);
		const differentSize = await t.call('POST', '', JSON.stringify(ticketBody(ID, source(10))));
		expect(differentSize.status).toBe(409);
		expect(((await differentSize.json()) as { error: string }).error).toBe(
			`request ${ID} was already uploaded with different content`,
		);
		expect(await readdir(t.layout.incoming)).toEqual([]);
	});

	test('says content is committed only once the ready directory is synced: after a failed sync, and after a restart', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		await t.put(uploadId);
		// The sync fails with EIO, then with ENOSPC, then holds. The koid
		// that starts over the same spool syncs ready as it starts, and that
		// holds; its first sync for a ticket fails, then holds.
		const failures = [eio(), enospc(), undefined, undefined, eio()];
		let syncs = 0;
		const spy = syncingReady(t, async (real) => {
			syncs += 1;
			const failure = failures.shift();
			if (failure !== undefined) throw failure;
			await real();
		});
		const body = JSON.stringify(ticketBody(ID, t.bytes));
		try {
			expect((await t.commit(uploadId)).status).toBe(500);
			expect(syncs).toBe(1);
			// The entry is under ready but not durable. A ticket request for
			// the same content is not told it is committed: it syncs first,
			// and the sync fails again.
			const notYet = await t.call('POST', '', body);
			expect(notYet.status).toBe(507);
			expect(((await notYet.json()) as { error: string }).error).toBe(
				'the disk filled up before the commit was durable; try again',
			);
			expect(syncs).toBe(2);
			// The sync holds: committed. The ledger knows the entry durable
			// from here, so neither another ticket request nor a retry of the
			// commit syncs again.
			const same = await t.call('POST', '', body);
			expect(same.status).toBe(200);
			expect(await same.json()).toEqual({ committed: true, requestId: ID });
			expect(syncs).toBe(3);
			expect((await t.call('POST', '', body)).status).toBe(200);
			expect((await t.commit(uploadId)).status).toBe(200);
			expect(syncs).toBe(3);
			// A koid that starts over the same spool syncs ready as it starts,
			// but its ledger knows nothing of that sync or the earlier one:
			// the entry is acknowledged only once a sync for it has held.
			const restarted = new UploadApi({
				spoolDir: t.root,
				budgetBytes: 10 * 1024 ** 2,
				log: () => {},
				diskSpace: async () => ({ ...t.disk }),
			});
			await restarted.init();
			expect(syncs).toBe(4);
			const again = () => restarted.handle(requestFor('POST', '', body), []);
			const failed = await again();
			expect(failed.status).toBe(500);
			expect(((await failed.json()) as { error: string }).error).toBe(
				'the commit is on the disk but not durable yet: EIO: i/o error; try again',
			);
			expect(syncs).toBe(5);
			expect((await again()).status).toBe(200);
			expect(syncs).toBe(6);
			expect((await again()).status).toBe(200);
			expect(syncs).toBe(6);
		} finally {
			spy.mockRestore();
		}
		// None of this took a ticket or wrote anything.
		expect(await readdir(t.layout.incoming)).toEqual([]);
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		expect(await ledger(t)).toBe(await entryOnDisk(t, ID));
	});

	test('a ticket request after a commit whose sync failed is not told the content is committed until a sync holds', async () => {
		// The CLI's way out of a commit that answered 500 is to start over
		// with a ticket request for the same content. The entry is under
		// ready, the source compares the same, and no sync has held: the
		// request must sync before it says committed, and fail as the
		// commit did when that sync fails. The test above covers the 507
		// answer and a restart; this one pins the plain sequence.
		const t = await setup();
		const uploadId = await t.ticket();
		await t.put(uploadId);
		const failures = [eio(), eio()];
		let syncs = 0;
		const spy = syncingReady(t, async (real) => {
			syncs += 1;
			const failure = failures.shift();
			if (failure !== undefined) throw failure;
			await real();
		});
		const body = JSON.stringify(ticketBody(ID, t.bytes));
		try {
			expect((await t.commit(uploadId)).status).toBe(500);
			expect(syncs).toBe(1);
			const notYet = await t.call('POST', '', body);
			expect(notYet.status).toBe(500);
			expect(((await notYet.json()) as { error: string }).error).toBe(
				'the commit is on the disk but not durable yet: EIO: i/o error; try again',
			);
			expect(syncs).toBe(2);
			const same = await t.call('POST', '', body);
			expect(same.status).toBe(200);
			expect(await same.json()).toEqual({ committed: true, requestId: ID });
			expect(syncs).toBe(3);
		} finally {
			spy.mockRestore();
		}
		expect(await readdir(t.layout.incoming)).toEqual([]);
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		expect(await ledger(t)).toBe(await entryOnDisk(t, ID));
	});

	test('an entry without its request file is broken: not acknowledged, removed, and the id takes a new upload', async () => {
		const t = await setup();
		await t.upload();
		// A removal that failed part way leaves the source with no request
		// beside it. The reader refuses the entry, and so no build can use
		// it; were it acknowledged, the CLI would send nothing and `up`
		// would fail.
		await fsp.rm(join(t.layout.ready, ID, REQUEST_FILE));
		await expect(spoolUploads(t.root, t.api).request(ID)).rejects.toThrow(
			`upload ${ID} has no ${REQUEST_FILE}`,
		);
		const res = await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)));
		expect(res.status).toBe(201);
		expect(t.logs).toContain(
			`upload ${ID} is broken: upload ${ID} has no ${REQUEST_FILE}; removed`,
		);
		// The entry is gone and its bytes with it: the ledger holds this
		// ticket's reservation alone.
		expect(await ledger(t)).toBe(300_000 + MAX_REQUEST_BYTES);
		const { uploadId } = (await res.json()) as { uploadId: string };
		expect((await t.put(uploadId)).status).toBe(200);
		expect((await t.commit(uploadId)).status).toBe(200);
		expect(await spoolUploads(t.root, t.api).request(ID)).toEqual(t.req());
		expect(await ledger(t)).toBe(await entryOnDisk(t, ID));
	});

	test('reads the request and the source whole: a read that gives fewer bytes than asked for does not break the entry', async () => {
		const t = await setup();
		// Larger than one piece of the read loop, so the digest takes several.
		const big = source(1024 ** 2 + 12_345);
		await t.upload(ID, big);
		const body = JSON.stringify(ticketBody(ID, big));
		let requestReads = { reads: 0 };
		let sourceReads = { reads: 0 };
		const spy = openingWith((path, handle) => {
			if (path === join(t.layout.ready, ID, REQUEST_FILE)) requestReads = readingShort(handle, 10);
			if (path === join(t.layout.ready, ID, SOURCE_FILE)) sourceReads = readingShort(handle, 7777);
		});
		try {
			const same = await t.call('POST', '', body);
			expect(same.status).toBe(200);
			expect(await same.json()).toEqual({ committed: true, requestId: ID });
			expect(requestReads.reads).toBeGreaterThan(1);
			expect(sourceReads.reads).toBeGreaterThan(1);
			// Cleanup reads the entry the same way, at startup too.
			await t.api.cleanup();
			const fresh = new UploadApi({
				spoolDir: t.root,
				budgetBytes: 10 * 1024 ** 2,
				log: (m) => t.logs.push(m),
				diskSpace: async () => ({ ...t.disk }),
			});
			await fresh.init();
			expect((await fresh.handle(requestFor('POST', '', body), [])).status).toBe(200);
		} finally {
			spy.mockRestore();
		}
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		expect(t.logs.filter((m) => m.includes('broken'))).toEqual([]);
		expect(await ledger(t)).toBe(await entryOnDisk(t, ID));
	});

	test('a request file that ends short of its size is unreadable, not broken: refused, kept, and still counted after a restart', async () => {
		const t = await setup();
		await t.upload();
		const body = JSON.stringify(ticketBody(ID, t.bytes));
		const path = join(t.layout.ready, ID, REQUEST_FILE);
		const size = (await stat(path)).size;
		const spy = openingWith((opened, handle) => {
			if (opened === path) overstatingSize(handle);
		});
		try {
			// Not acknowledged, and not removed: as for any entry that cannot
			// be read, the id is answered as taken.
			expect((await t.call('POST', '', body)).status).toBe(409);
			expect(t.logs).toContain(
				`upload spool: ready/${ID}: ${REQUEST_FILE} of upload ${ID} ended after ${size} of ${size + 1} bytes`,
			);
			await t.api.cleanup();
			expect(await readdir(t.layout.ready)).toEqual([ID]);
			// A koid starting over the spool keeps it too, and its ledger
			// counts it: budget for the entry and one more upload of its
			// size, with no room for a second.
			const fresh = new UploadApi({
				spoolDir: t.root,
				budgetBytes: 2 * 300_000 + MAX_REQUEST_BYTES,
				log: (m) => t.logs.push(m),
				diskSpace: async () => ({ ...t.disk }),
			});
			await fresh.init();
			expect(await readdir(t.layout.ready)).toEqual([ID]);
			const other = requestFor('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)));
			expect((await fresh.handle(other, [])).status).toBe(507);
		} finally {
			spy.mockRestore();
		}
		expect(t.logs.filter((m) => m.includes('broken'))).toEqual([]);
		// Whole again, the content is acknowledged.
		expect((await t.call('POST', '', body)).status).toBe(200);
	});

	test('a source that ends short of its size fails the comparison and keeps the entry', async () => {
		const t = await setup();
		await t.upload();
		const path = join(t.layout.ready, ID, SOURCE_FILE);
		const spy = openingWith((opened, handle) => {
			if (opened === path) overstatingSize(handle);
		});
		try {
			// Declared at the size fstat now gives, so the digest is taken,
			// and the file ends before it is done.
			const declared = { ...ticketBody(ID, t.bytes), sizeBytes: t.bytes.byteLength + 1 };
			await expect(t.call('POST', '', JSON.stringify(declared))).rejects.toThrow(
				`${SOURCE_FILE} of upload ${ID} ended after ${t.bytes.byteLength} of ${t.bytes.byteLength + 1} bytes`,
			);
		} finally {
			spy.mockRestore();
		}
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		expect(t.logs.filter((m) => m.includes('broken'))).toEqual([]);
		expect((await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)))).status).toBe(200);
	});

	test('answers 404 for other methods and paths', async () => {
		const t = await setup();
		expect((await t.call('GET', '')).status).toBe(404);
		expect((await t.call('GET', `/${'0'.repeat(32)}/source`)).status).toBe(404);
		expect((await t.call('PUT', '/not-an-upload-id/source')).status).toBe(404);
		expect((await t.call('PUT', `/${'0'.repeat(32)}/elsewhere`)).status).toBe(404);
		expect((await t.call('PUT', `/${'0'.repeat(32)}`)).status).toBe(404);
	});
});

describe('PUT /v1/uploads/<upload-id>/source', () => {
	test('streams the archive to an exclusive file under incoming, and says what it got', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		const res = await t.put(uploadId);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ sizeBytes: t.bytes.byteLength, sha256: sha256(t.bytes) });
		const file = join(t.layout.incoming, uploadId, SOURCE_FILE);
		expect((await stat(file)).mode & 0o777).toBe(0o600);
		expect(Buffer.from(await readFile(file)).equals(t.bytes)).toBe(true);
		// Nothing is ready until the commit.
		expect(await readdir(t.layout.ready)).toEqual([]);
	});

	test('answers 404 for an unknown or expired ticket, and drops the expired one', async () => {
		const t = await setup();
		expect((await t.put('0'.repeat(32))).status).toBe(404);
		const uploadId = await t.ticket();
		t.advance(60 * 60_000);
		expect((await t.put(uploadId)).status).toBe(404);
		expect(await readdir(t.layout.incoming)).toEqual([]);
	});

	test('stops reading and answers 413 as soon as the body passes the declared size', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		const body = endless();
		const res = await t.call('PUT', `/${uploadId}/source`, body.stream);
		expect(res.status).toBe(413);
		expect(((await res.json()) as { error: string }).error).toBe(
			`the source is over its declared ${t.bytes.byteLength} bytes`,
		);
		// About five chunks of 64 KiB, not the endless rest.
		expect(body.state.pulled).toBeLessThan(10);
		expect(await readdir(join(t.layout.incoming, uploadId))).toEqual([]);
		// The ticket is still good: the right bytes go through.
		expect((await t.put(uploadId)).status).toBe(200);
	});

	test('answers 400 for a body that ends short, and takes a new attempt', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		const res = await t.put(uploadId, t.bytes.subarray(0, 1000));
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toBe(
			`the body ended after 1000 of ${t.bytes.byteLength} bytes`,
		);
		expect(await readdir(join(t.layout.incoming, uploadId))).toEqual([]);
		expect((await t.call('PUT', `/${uploadId}/source`)).status).toBe(400);
		expect((await t.put(uploadId)).status).toBe(200);
	});

	test('answers 422 for a body whose digest is not the one declared, keeping nothing of it', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		const wrong = source(t.bytes.byteLength);
		wrong[10] = 255;
		const res = await t.put(uploadId, wrong);
		expect(res.status).toBe(422);
		expect(((await res.json()) as { error: string }).error).toMatch(
			/digest is .* not the .* declared/,
		);
		expect(await readdir(join(t.layout.incoming, uploadId))).toEqual([]);
		// A commit now is refused: there is no source.
		expect((await t.commit(uploadId)).status).toBe(409);
		expect((await t.put(uploadId)).status).toBe(200);
	});

	test('answers 408 for a body that stalls past the time bound', async () => {
		const t = await setup({ limits: { sourceTimeoutMs: 200 } });
		const uploadId = await t.ticket();
		const started = Date.now();
		const res = await t.call('PUT', `/${uploadId}/source`, stalled(t.bytes.subarray(0, 1000)));
		expect(res.status).toBe(408);
		expect(((await res.json()) as { error: string }).error).toBe(
			'the source did not arrive within 0.2 seconds',
		);
		expect(Date.now() - started).toBeLessThan(2000);
		expect(await readdir(join(t.layout.incoming, uploadId))).toEqual([]);
		expect((await t.put(uploadId)).status).toBe(200);
	});

	test('answers 408 when every declared byte arrived but the body never ended', async () => {
		const t = await setup({ limits: { sourceTimeoutMs: 200 } });
		const uploadId = await t.ticket();
		const res = await t.call('PUT', `/${uploadId}/source`, stalled(t.bytes));
		expect(res.status).toBe(408);
		expect(await readdir(join(t.layout.incoming, uploadId))).toEqual([]);
		// Nothing of it was kept as received: a commit is refused, a PUT goes through.
		expect((await t.commit(uploadId)).status).toBe(409);
		expect((await t.put(uploadId)).status).toBe(200);
	});

	test('a ticket takes one source: a second PUT is a conflict', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		expect((await t.put(uploadId)).status).toBe(200);
		const res = await t.put(uploadId);
		expect(res.status).toBe(409);
		expect(((await res.json()) as { error: string }).error).toBe(
			'the source was already uploaded; commit it',
		);
		expect(
			Buffer.from(await readFile(join(t.layout.incoming, uploadId, SOURCE_FILE))).equals(t.bytes),
		).toBe(true);
	});
});

describe('POST /v1/uploads/<upload-id>/commit', () => {
	test('publishes the entry under ready with the request beside the source, and the spool reads it', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		await t.put(uploadId);
		const res = await t.commit(uploadId);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ requestId: ID, label: 'hello-pr-7' });
		expect(await readdir(t.layout.incoming)).toEqual([]);
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		expect((await readdir(join(t.layout.ready, ID))).sort()).toEqual([REQUEST_FILE, SOURCE_FILE]);
		expect((await stat(join(t.layout.ready, ID, REQUEST_FILE))).mode & 0o777).toBe(0o600);
		const uploads = spoolUploads(t.root, t.api);
		expect(await uploads.request(ID)).toEqual(t.req());
		const copy = join(t.root, 'copy.tar.gz');
		await uploads.downloadSource(ID, copy);
		expect(Buffer.from(await readFile(copy)).equals(t.bytes)).toBe(true);
		expect(t.logs).toEqual([`upload ${ID} committed for hello-pr-7`]);
	});

	test('a retried commit with the same request gets the same answer; another request is a conflict', async () => {
		const t = await setup();
		const uploadId = await t.upload();
		const again = await t.commit(uploadId);
		expect(again.status).toBe(200);
		expect(await again.json()).toEqual({ requestId: ID, label: 'hello-pr-7' });
		const other = await t.commit(uploadId, t.req({ branch: 'another' }));
		expect(other.status).toBe(409);
		expect(await spoolUploads(t.root, t.api).request(ID)).toEqual(t.req());
	});

	test('answers 404 for an unknown or expired ticket', async () => {
		const t = await setup();
		expect((await t.commit('0'.repeat(32))).status).toBe(404);
		const uploadId = await t.ticket();
		await t.put(uploadId);
		t.advance(60 * 60_000 + 1);
		expect((await t.commit(uploadId)).status).toBe(404);
		expect(await readdir(t.layout.incoming)).toEqual([]);
	});

	test('a ticket whose commit is still reading its JSON when the hour runs out keeps its reservation until the commit answers', async () => {
		// Budget for one upload. Were the ticket expired under the commit,
		// its reservation would go to another upload while its source is
		// still on the disk, and the commit would then publish it as well.
		const t = await setup({ budgetBytes: 300_000 + MAX_REQUEST_BYTES });
		const a = await t.ticket();
		expect((await t.put(a)).status).toBe(200);
		// The commit's JSON waits at the gate. The request is dated when it
		// arrives, so the hour that ran out on the ticket has not run out
		// on it.
		const gate = new Gate();
		const body = new ReadableStream<Uint8Array>(
			{
				async pull(c) {
					await gate.pass();
					c.enqueue(new TextEncoder().encode(JSON.stringify(t.req())));
					c.close();
				},
			},
			{ highWaterMark: 0 },
		);
		const commit = t.call('POST', `/${a}/commit`, body);
		await gate.reached;
		t.advance(60 * 60_000 + 1);
		// Expiry, asked for by another call on the ticket and by cleanup,
		// leaves the ticket, its directory and its reservation alone.
		expect((await t.put(a)).status).toBe(404);
		await t.api.cleanup();
		expect(await readdir(join(t.layout.incoming, a))).toEqual([SOURCE_FILE]);
		const other = await t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)));
		expect(other.status).toBe(507);
		expect(((await other.json()) as { error: string }).error).toMatch(
			new RegExp(`upload spool has ${300_000 + MAX_REQUEST_BYTES} of its`),
		);
		gate.release();
		const res = await commit;
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ requestId: ID, label: 'hello-pr-7' });
		expect(await readdir(t.layout.incoming)).toEqual([]);
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		// The ledger holds the entry and nothing for the ticket.
		expect(await ledger(t, 300_000 + MAX_REQUEST_BYTES)).toBe(await entryOnDisk(t, ID));
	});

	test('an expired ticket gives its budget back only once its bytes are off the disk', async () => {
		// Budget for one upload. The removal of the expired source stops at
		// the gate; an admission asked for meanwhile waits for it, so the
		// spool directory never holds both sources.
		const t = await setup({ budgetBytes: 300_000 + MAX_REQUEST_BYTES });
		const a = await t.ticket();
		expect((await t.put(a)).status).toBe(200);
		t.advance(60 * 60_000 + 1);
		const gate = new Gate();
		const dir = join(t.layout.incoming, a);
		const original = fsp.rm;
		const spy = spyOn(fsp, 'rm').mockImplementation(async (path, options) => {
			if (path === dir) await gate.pass();
			return original(path, options);
		});
		try {
			const expired = t.commit(a);
			await gate.reached;
			let admitted = false;
			const admission = t
				.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)))
				.then((res) => {
					admitted = true;
					return res;
				});
			await Bun.sleep(20);
			expect(admitted).toBe(false);
			expect(await readdir(dir)).toEqual([SOURCE_FILE]);
			gate.release();
			expect((await expired).status).toBe(404);
			expect((await admission).status).toBe(201);
		} finally {
			gate.release();
			spy.mockRestore();
		}
		expect(await readdir(t.layout.incoming)).toHaveLength(1);
		expect(await readdir(t.layout.incoming)).not.toContain(a);
	});

	test('refuses a commit before the source, with 409', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		const res = await t.commit(uploadId);
		expect(res.status).toBe(409);
		expect(((await res.json()) as { error: string }).error).toBe(
			'upload the source before committing',
		);
		expect(await readdir(t.layout.ready)).toEqual([]);
	});

	test('rejects a request that is malformed, too large, or names another id, with 400 or 413', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		await t.put(uploadId);
		expect((await t.call('POST', `/${uploadId}/commit`, '{')).status).toBe(400);
		expect(
			(await t.call('POST', `/${uploadId}/commit`, JSON.stringify({ version: 1 }))).status,
		).toBe(400);
		const mismatch = await t.commit(uploadId, t.req({ id: OTHER }));
		expect(mismatch.status).toBe(400);
		expect(((await mismatch.json()) as { error: string }).error).toBe(
			`the request names itself ${OTHER}; this upload is for ${ID}`,
		);
		const huge = JSON.stringify({ ...t.req(), branch: 'x'.repeat(256 * 1024) });
		expect((await t.call('POST', `/${uploadId}/commit`, huge)).status).toBe(413);
		expect(await readdir(t.layout.ready)).toEqual([]);
		// The ticket is unharmed.
		expect((await t.commit(uploadId)).status).toBe(200);
	});

	test('refuses a request that passes 256 KiB once its defaults are filled in, with 413', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		await t.put(uploadId);
		// A recipe with every default left out, padded in env so the text
		// sent is exactly the bound; parsing adds the defaults.
		const env: Record<string, string> = {};
		const r = {
			...t.req(),
			recipe: { kind: 'repo', recipe: { port: 8080, env, build: { kind: 'dockerfile' } } },
		};
		let i = 0;
		while (Buffer.byteLength(JSON.stringify(r)) + 4096 + 12 <= MAX_REQUEST_BYTES) {
			env[`PAD_${String(i++).padStart(3, '0')}`] = 'x'.repeat(4096);
		}
		env.LAST = '';
		env.LAST = 'x'.repeat(MAX_REQUEST_BYTES - Buffer.byteLength(JSON.stringify(r)));
		const text = JSON.stringify(r);
		expect(Buffer.byteLength(text)).toBe(MAX_REQUEST_BYTES);
		const res = await t.call('POST', `/${uploadId}/commit`, text);
		expect(res.status).toBe(413);
		expect(((await res.json()) as { error: string }).error).toMatch(
			/bytes once its defaults are filled in; koid keeps at most 262144/,
		);
		expect(await readdir(t.layout.ready)).toEqual([]);
		// The ticket is unharmed.
		expect((await t.commit(uploadId)).status).toBe(200);
	});

	test('answers 507 when the disk fills as the request is written, and takes the commit again', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		await t.put(uploadId);
		const spy = spyOn(fsp, 'open').mockRejectedValueOnce(enospc());
		try {
			const res = await t.commit(uploadId);
			expect(res.status).toBe(507);
			expect(((await res.json()) as { error: string }).error).toBe(
				'the disk filled up while the request was being written',
			);
		} finally {
			spy.mockRestore();
		}
		expect(await readdir(t.layout.ready)).toEqual([]);
		expect(
			Buffer.from(await readFile(join(t.layout.incoming, uploadId, SOURCE_FILE))).equals(t.bytes),
		).toBe(true);
		expect((await t.commit(uploadId)).status).toBe(200);
		expect(await readdir(t.layout.ready)).toEqual([ID]);
	});

	test('a commit is answered only once the ready directory is synced: a retry waits for a sync under way', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		await t.put(uploadId);
		// The sync stops at the gate. Were the reply cached before it, the
		// retry would answer 200 while the first commit still waits, and a
		// crash then could lose an upload the CLI saw acknowledged.
		const gate = new Gate();
		const spy = syncingReady(t, async (real) => {
			await gate.pass();
			await real();
		});
		try {
			let answered = 0;
			const count = (res: Response) => {
				answered += 1;
				return res;
			};
			const first = t.commit(uploadId).then(count);
			await gate.reached;
			// The entry is under ready; nothing has been answered.
			expect(await readdir(t.layout.ready)).toEqual([ID]);
			const retry = t.commit(uploadId).then(count);
			await Bun.sleep(20);
			expect(answered).toBe(0);
			gate.release();
			expect((await first).status).toBe(200);
			const res = await retry;
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ requestId: ID, label: 'hello-pr-7' });
		} finally {
			gate.release();
			spy.mockRestore();
		}
		expect(t.logs).toEqual([`upload ${ID} committed for hello-pr-7`]);
		expect(await ledger(t)).toBe(await entryOnDisk(t, ID));
	});

	test('a failed sync after the entry is published fails the commit, keeps the entry counted, and a retry syncs again before it is answered', async () => {
		const t = await setup();
		const uploadId = await t.ticket();
		await t.put(uploadId);
		// The sync fails with EIO, then with ENOSPC, then holds.
		const failures = [eio(), enospc()];
		let syncs = 0;
		const spy = syncingReady(t, async (real) => {
			syncs += 1;
			const failure = failures.shift();
			if (failure !== undefined) throw failure;
			await real();
		});
		try {
			const res = await t.commit(uploadId);
			expect(res.status).toBe(500);
			expect(((await res.json()) as { error: string }).error).toBe(
				'the commit is on the disk but not durable yet: EIO: i/o error; try again',
			);
			expect(t.logs).toEqual([
				`upload ${ID} committed for hello-pr-7`,
				`upload spool: syncing ready after ${ID} was published: EIO: i/o error`,
			]);
			// The entry is published: under ready, readable, and counted once
			// with no reservation beside it.
			expect(await readdir(t.layout.incoming)).toEqual([]);
			expect(await readdir(t.layout.ready)).toEqual([ID]);
			expect(await spoolUploads(t.root, t.api).request(ID)).toEqual(t.req());
			expect(await ledger(t)).toBe(await entryOnDisk(t, ID));
			// A retry with other content is a conflict, and syncs nothing.
			expect((await t.commit(uploadId, t.req({ branch: 'other' }))).status).toBe(409);
			expect(syncs).toBe(1);
			// A retry syncs again; the disk is full this time.
			const full = await t.commit(uploadId);
			expect(full.status).toBe(507);
			expect(((await full.json()) as { error: string }).error).toBe(
				'the disk filled up before the commit was durable; try again',
			);
			expect(syncs).toBe(2);
			expect(await ledger(t)).toBe(await entryOnDisk(t, ID));
			// The next retry's sync holds, and the commit is answered.
			const again = await t.commit(uploadId);
			expect(again.status).toBe(200);
			expect(await again.json()).toEqual({ requestId: ID, label: 'hello-pr-7' });
			expect(syncs).toBe(3);
			// From here the reply is cached: a retry syncs nothing more.
			expect((await t.commit(uploadId)).status).toBe(200);
			expect(syncs).toBe(3);
		} finally {
			spy.mockRestore();
		}
		expect(await ledger(t)).toBe(await entryOnDisk(t, ID));
	});

	test('answers 408 for commit JSON that stalls', async () => {
		const t = await setup({ limits: { requestTimeoutMs: 200 } });
		const uploadId = await t.ticket();
		await t.put(uploadId);
		const res = await t.call('POST', `/${uploadId}/commit`, stalled(new TextEncoder().encode('{')));
		expect(res.status).toBe(408);
		expect(await readdir(t.layout.ready)).toEqual([]);
		expect((await t.commit(uploadId)).status).toBe(200);
	});

	test('accepts a request created within the hour, and refuses one older or from the future', async () => {
		const t = await setup();
		const at = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();
		for (const [offset, status] of [
			[-59 * 60_000, 200],
			[4 * 60_000, 200],
			[-61 * 60_000, 400],
			[6 * 60_000, 400],
		] as const) {
			const id = `createdat${String(Math.abs(offset)).padStart(9, '0')}${status}`;
			const uploadId = await t.ticket(id);
			await t.put(uploadId);
			const res = await t.commit(uploadId, t.req({ id, createdAt: at(offset) }));
			expect([offset, res.status]).toEqual([offset, status]);
		}
	});

	test('two tickets for one id: the second commit of the same content gets the same answer', async () => {
		const t = await setup();
		const a = await t.ticket();
		const b = await t.ticket();
		await t.put(a);
		await t.put(b);
		expect((await t.commit(a)).status).toBe(200);
		const res = await t.commit(b);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ requestId: ID, label: 'hello-pr-7' });
		expect(await readdir(t.layout.incoming)).toEqual([]);
		expect(await readdir(t.layout.ready)).toEqual([ID]);
	});

	test('two tickets for one id with different content: the second commit is a conflict and leaves nothing', async () => {
		const t = await setup();
		const otherBytes = source(t.bytes.byteLength + 5);
		const a = await t.ticket(ID, t.bytes);
		const b = await t.ticket(ID, otherBytes);
		await t.put(a, t.bytes);
		await t.put(b, otherBytes);
		expect((await t.commit(a)).status).toBe(200);
		const res = await t.commit(b);
		expect(res.status).toBe(409);
		expect(await readdir(t.layout.incoming)).toEqual([]);
		// The first entry stands as it was.
		const copy = join(t.root, 'copy.tar.gz');
		await spoolUploads(t.root, t.api).downloadSource(ID, copy);
		expect(Buffer.from(await readFile(copy)).equals(t.bytes)).toBe(true);
		// The losing ticket is gone.
		expect((await t.commit(b)).status).toBe(404);
	});

	test('a commit whose source matches an entry but whose request differs is a conflict', async () => {
		const t = await setup();
		const a = await t.ticket();
		const b = await t.ticket();
		await t.put(a);
		await t.put(b);
		expect((await t.commit(a)).status).toBe(200);
		expect((await t.commit(b, t.req({ branch: 'other' }))).status).toBe(409);
	});
});

describe('cleanup', () => {
	test('drops tickets after an hour with what they received, and leaves younger ones', async () => {
		const t = await setup();
		const old = await t.ticket();
		await t.put(old);
		t.advance(30 * 60_000);
		const young = await t.ticket(OTHER);
		t.advance(30 * 60_000);
		await t.api.cleanup();
		expect(await readdir(t.layout.incoming)).toEqual([young]);
		expect((await t.commit(old)).status).toBe(404);
		expect((await t.put(young, t.bytes)).status).toBe(200);
	});

	test('an expired ticket whose directory could not be removed keeps its reservation until a later round removes it', async () => {
		// Budget for one upload. The removal of the expired source fails;
		// were the ticket dropped anyway, its budget would go to another
		// upload while its source is still on the disk.
		const t = await setup({ budgetBytes: 300_000 + MAX_REQUEST_BYTES });
		const a = await t.ticket();
		expect((await t.put(a)).status).toBe(200);
		t.advance(60 * 60_000 + 1);
		const dir = join(t.layout.incoming, a);
		const original = fsp.rm;
		const spy = spyOn(fsp, 'rm').mockImplementation(async (path, options) => {
			if (path === dir) throw eio();
			return original(path, options);
		});
		try {
			// Cleanup goes on past the failure, and says so.
			await t.api.cleanup();
			expect(t.logs).toEqual([
				`upload spool: removing expired upload ${a} for ${ID}: EIO: i/o error`,
			]);
			expect(await readdir(dir)).toEqual([SOURCE_FILE]);
			// The reservation stands: another upload does not fit.
			const refused = await t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)));
			expect(refused.status).toBe(507);
			expect(((await refused.json()) as { error: string }).error).toMatch(
				new RegExp(`upload spool has ${300_000 + MAX_REQUEST_BYTES} of its`),
			);
			// No request is served on the ticket, and each tries the removal
			// again.
			expect((await t.commit(a)).status).toBe(404);
			expect((await t.put(a)).status).toBe(404);
			expect(await readdir(dir)).toEqual([SOURCE_FILE]);
			// Nor once the clock goes back: the removal may have taken part
			// of the directory.
			t.advance(-(60 * 60_000 + 1));
			expect((await t.commit(a)).status).toBe(404);
			t.advance(60 * 60_000 + 1);
			expect(t.logs).toHaveLength(4);
		} finally {
			spy.mockRestore();
		}
		// The next round removes the directory, and the budget comes back
		// with it.
		await t.api.cleanup();
		expect(await readdir(t.layout.incoming)).toEqual([]);
		expect((await t.call('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes)))).status).toBe(201);
	});

	test('removes what is under incoming with no ticket, at startup too', async () => {
		const root = await mkdtemp(join(tmpdir(), 'koid-upload-'));
		const layout = spoolLayout(root);
		await mkdir(join(layout.incoming, 'f'.repeat(32)), { recursive: true });
		await writeFile(join(layout.incoming, 'f'.repeat(32), SOURCE_FILE), 'half an upload');
		await writeFile(join(layout.incoming, 'stray'), 'x');
		const api = new UploadApi({
			spoolDir: root,
			budgetBytes: 1024 ** 2,
			log: () => {},
		});
		await api.init();
		expect(await readdir(layout.incoming)).toEqual([]);
		expect(await readdir(layout.ready)).toEqual([]);
	});

	test('expires a ready entry after a day unless the deployer holds a claim on it', async () => {
		const t = await setup();
		await t.upload();
		await t.upload(OTHER, t.bytes, t.req({ id: OTHER, label: 'other', pr: 8 }));
		t.advance(23 * 60 * 60_000);
		await t.api.cleanup();
		expect((await readdir(t.layout.ready)).sort()).toEqual([ID, OTHER]);
		await t.api.claim(ID);
		t.advance(2 * 60 * 60_000);
		await t.api.cleanup();
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		expect(t.logs).toContain(`upload ${OTHER} expired`);
		await t.api.release(ID);
		await t.api.cleanup();
		expect(await readdir(t.layout.ready)).toEqual([]);
		// The ledger let the bytes go with the entries.
		const big = source(10 * 1024 ** 2 - MAX_REQUEST_BYTES);
		expect((await t.call('POST', '', JSON.stringify(ticketBody(OTHER, big)))).status).toBe(201);
	});

	test('a claim on an entry that is gone is a NoSuchUploadError, and a claim taken twice holds until both are released', async () => {
		const t = await setup();
		await expect(t.api.claim(ID)).rejects.toBeInstanceOf(NoSuchUploadError);
		// Releasing what is not claimed is nothing.
		await t.api.release(ID);
		await t.upload();
		await t.api.claim(ID);
		await t.api.claim(ID);
		t.advance(2 * 24 * 60 * 60_000);
		await t.api.release(ID);
		await t.api.cleanup();
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		await t.api.release(ID);
		await t.api.cleanup();
		expect(await readdir(t.layout.ready)).toEqual([]);
	});

	test('goes by the entry file time, so an old entry from a previous koid expires too', async () => {
		const t = await setup();
		await t.upload();
		const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60_000);
		await utimes(join(t.layout.ready, ID, REQUEST_FILE), twoDaysAgo, twoDaysAgo);
		await t.api.cleanup();
		expect(await readdir(t.layout.ready)).toEqual([]);
	});

	test('leaves a name under ready that is not a request id, and says so', async () => {
		const t = await setup();
		await mkdir(join(t.layout.ready, 'Not-A-Request'));
		await t.api.cleanup();
		expect(await readdir(t.layout.ready)).toEqual(['Not-A-Request']);
		expect(t.logs).toContain(
			'upload spool: Not-A-Request under ready is not a request id; leaving it',
		);
	});

	test('removes a broken entry whatever its age, unless the deployer holds a claim on it', async () => {
		const t = await setup();
		const third = 'c'.repeat(20);
		await t.upload();
		await t.upload(OTHER, t.bytes, t.req({ id: OTHER, label: 'other', pr: 8 }));
		await t.upload(third, t.bytes, t.req({ id: third, label: 'third', pr: 9 }));
		// Three ways an entry is broken: no request file, a request that is
		// not JSON, and a request for another id. The first is held by a
		// build that read the request before the file went.
		await fsp.rm(join(t.layout.ready, ID, REQUEST_FILE));
		await writeFile(join(t.layout.ready, OTHER, REQUEST_FILE), '{not json');
		await writeFile(join(t.layout.ready, third, REQUEST_FILE), JSON.stringify(t.req({ id: ID })));
		await t.api.claim(ID);
		await t.api.cleanup();
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		expect(t.logs).toContainEqual(
			expect.stringMatching(
				new RegExp(
					`^upload ${OTHER} is broken: ${REQUEST_FILE} of upload ${OTHER} is not a request: .+; removed$`,
				),
			),
		);
		expect(t.logs).toContain(
			`upload ${third} is broken: request ${third} names itself ${ID}; removed`,
		);
		// The held entry is not acknowledged, and not removed from under
		// the build either.
		const held = await t.call('POST', '', JSON.stringify(ticketBody(ID, t.bytes)));
		expect(held.status).toBe(409);
		expect(((await held.json()) as { error: string }).error).toBe(
			`request ${ID} has a broken upload that a build still holds; try again later`,
		);
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		// Once the claim is released, what is left of it goes.
		await t.api.release(ID);
		await t.api.cleanup();
		expect(await readdir(t.layout.ready)).toEqual([]);
		expect(t.logs).toContain(
			`upload ${ID} is broken: upload ${ID} has no ${REQUEST_FILE}; removed`,
		);
		// The ledger let the bytes go with the entries.
		expect(await ledger(t)).toBe(0);
	});
});

describe('startup', () => {
	test('syncs each spool directory it makes with its parent, and the root, its parent, incoming and ready at every start', async () => {
		// As /var/lib/koi/uploads on a box with no /var/lib/koi yet: two
		// directories to make above the spool's own. The root is resolved
		// so the paths the syncs open compare equal to it.
		const root = await realpath(await mkdtemp(join(tmpdir(), 'koid-fresh-')));
		const spoolDir = join(root, 'koi', 'uploads');
		const synced: string[] = [];
		const spy = openingWith((path, handle) => {
			const real = handle.sync.bind(handle);
			spyOn(handle, 'sync').mockImplementation(async () => {
				synced.push(path);
				await real();
			});
		});
		const start = () =>
			new UploadApi({ spoolDir, budgetBytes: 10 * 1024 ** 2, log: () => {} }).init();
		try {
			await start();
			// Each directory before its parent, up to the one that was there;
			// the four synced at every start are among them, once each.
			expect(synced).toEqual([
				join(spoolDir, 'incoming'),
				join(spoolDir, 'ready'),
				spoolDir,
				join(root, 'koi'),
				root,
			]);
			expect((await stat(spoolDir)).mode & 0o777).toBe(0o700);
			// Started again over the same spool, everything is there and
			// nothing is made. The root, the directory that names it, incoming
			// and ready are synced all the same: the koid that made them may
			// not have got this far.
			synced.length = 0;
			await start();
			expect(synced).toEqual([
				join(spoolDir, 'incoming'),
				join(spoolDir, 'ready'),
				spoolDir,
				join(root, 'koi'),
			]);
		} finally {
			spy.mockRestore();
		}
	});

	test('refuses to start the spool when an entry cannot be read into the ledger', async () => {
		// Budget for the committed entry and one more upload of that size,
		// with no room for a third. Were the entry's bytes left out of the
		// ledger, two more would be admitted.
		const budgetBytes = 2 * 300_000 + MAX_REQUEST_BYTES;
		const t = await setup({ budgetBytes });
		await t.upload();
		const sourcePath = join(t.layout.ready, ID, SOURCE_FILE);
		const original = fsp.lstat;
		// lstat is overloaded, so the replacement is asserted to its type.
		const spy = spyOn(fsp, 'lstat').mockImplementation((async (
			path: PathLike,
			options?: StatOptions,
		) => {
			if (path === sourcePath) throw eio();
			return original(path, options);
		}) as typeof fsp.lstat);
		const fresh = () =>
			new UploadApi({
				spoolDir: t.root,
				budgetBytes,
				log: () => {},
				diskSpace: async () => ({ ...t.disk }),
			});
		try {
			const err = await fresh()
				.init()
				.catch((e: unknown) => e);
			expect(err).toBeInstanceOf(Error);
			expect((err as Error).message).toBe(
				`upload spool: reading ${join(t.layout.ready, ID)} into the ledger: ${sourcePath}: EIO: i/o error`,
			);
		} finally {
			spy.mockRestore();
		}
		// The entry is untouched. With the disk readable again the ledger
		// counts it whole, and an upload of the same size does not fit.
		expect(await readdir(t.layout.ready)).toEqual([ID]);
		const api = fresh();
		await api.init();
		const res = await api.handle(
			requestFor('POST', '', JSON.stringify(ticketBody(OTHER, t.bytes))),
			[],
		);
		expect(res.status).toBe(507);
	});

	test('removes a broken entry a previous koid left, and the ledger does not count it', async () => {
		const t = await setup();
		await t.upload();
		await fsp.rm(join(t.layout.ready, ID, SOURCE_FILE));
		const logs: string[] = [];
		const fresh = new UploadApi({
			spoolDir: t.root,
			budgetBytes: 10 * 1024 ** 2,
			log: (m) => logs.push(m),
			diskSpace: async () => ({ ...t.disk }),
		});
		await fresh.init();
		expect(await readdir(t.layout.ready)).toEqual([]);
		expect(logs).toEqual([
			`upload spool: ready/${ID}: upload ${ID} has no ${SOURCE_FILE}`,
			`upload ${ID} is broken: upload ${ID} has no ${SOURCE_FILE}; removed`,
		]);
		// Nothing is committed under the id: a ticket request for the
		// content gets a ticket, not an acknowledgement.
		const res = await fresh.handle(
			requestFor('POST', '', JSON.stringify(ticketBody(ID, t.bytes))),
			[],
		);
		expect(res.status).toBe(201);
	});
});

// What this koid says of itself; the upload routes never read it.
const HOST: HostInfo = {
	protocol: 1,
	hostId: 'k'.repeat(20),
	domain: 'previews.example.com',
	address: { scheme: 'https', port: 443 },
	capabilities: {
		duplex: false,
		buildLogCursor: true,
		runtimeLogStream: false,
		artifactTransfer: false,
	},
};

// Through the control socket, as the CLI will reach it over SSH.
describe('over the control socket', () => {
	async function server(api: UploadApi | undefined, overrides: Partial<ControlDeps> = {}) {
		const dir = await mkdtemp(join(tmpdir(), 'koid-ctl-'));
		const socket = join(dir, 'control.sock');
		const deps: ControlDeps = {
			deployer: {
				up: async (id) => ({ label: `up-${id.slice(0, 4)}`, queued: false }),
				down: async () => false,
				// The upload routes never reach the lease ones.
				acquireLease: async () => {
					throw new Error('not expected');
				},
				releaseLease: async () => {
					throw new Error('not expected');
				},
			},
			store: { get: async () => undefined, list: async () => [] },
			docker: { logs: async () => '' },
			buildLogs: {
				read: async () => ({ next: 0, lines: [] }),
				tail: async () => '',
			},
			keepAwake: async () => {},
			describe: async () => HOST,
			uploadApi: api,
			...overrides,
		};
		const srv = await startControlServer(socket, deps);
		const call = (method: string, path: string, body?: Body) => {
			const init: Record<string, unknown> = { method, unix: socket };
			if (body !== undefined) {
				init.body = body;
				if (body instanceof ReadableStream) init.duplex = 'half';
			}
			return fetch(`http://koid${path}`, init as RequestInit);
		};
		return { call, stop: () => srv.stop(true) };
	}

	test('runs the whole sequence with a streamed body, then ctl up builds from the spool', async () => {
		const t = await setup();
		// The real deployer over the spool, as adapters.ts wires it, behind
		// the real /up route.
		const d = await deployerSetup({ uploads: spoolUploads(t.root, t.api) });
		const s = await server(t.api, { deployer: d.deployer });
		try {
			const bytes = source(3 * 1024 ** 2 + 123);
			// Nothing to build from yet: the route says so, as it did.
			const early = await s.call('POST', '/up', JSON.stringify({ requestId: ID }));
			expect(early.status).toBe(500);
			expect(((await early.json()) as { error: string }).error).toBe(`no upload for request ${ID}`);
			const created = await s.call('POST', '/v1/uploads', JSON.stringify(ticketBody(ID, bytes)));
			expect(created.status).toBe(201);
			const { uploadId } = (await created.json()) as { uploadId: string };
			const put = await s.call('PUT', `/v1/uploads/${uploadId}/source`, chunked(bytes, 100_000));
			expect(put.status).toBe(200);
			expect(await put.json()).toEqual({ sizeBytes: bytes.byteLength, sha256: sha256(bytes) });
			const committed = await s.call(
				'POST',
				`/v1/uploads/${uploadId}/commit`,
				JSON.stringify(t.req()),
			);
			expect(committed.status).toBe(200);
			const up = await s.call('POST', '/up', JSON.stringify({ requestId: ID }));
			expect(up.status).toBe(202);
			expect(await up.json()).toEqual({ label: 'hello-pr-7', queued: false });
			await d.deployer.settled('hello-pr-7');
			expect((await d.store.get('hello-pr-7'))?.status).toBe('running');
			// The build got the bytes that were uploaded.
			expect(d.tarballSizes).toEqual([bytes.byteLength]);
		} finally {
			s.stop();
		}
	});

	test('a JSON body that stalls is cut off by the handler, with the server idle timeout off', async () => {
		const t = await setup();
		const s = await server(t.api, { limits: { bodyTimeoutMs: 300 } });
		try {
			const started = Date.now();
			const res = await s.call('POST', '/up', stalled(new TextEncoder().encode('{"requestId":')));
			expect(res.status).toBe(408);
			expect(Date.now() - started).toBeLessThan(3000);
		} finally {
			s.stop();
		}
	});

	test('a body that takes longer than Bun idle timeout of ten seconds still arrives', async () => {
		// Bun closes a connection whose request has had no response for
		// its idle timeout, body bytes or not; startControlServer turns
		// that off when uploads are on. A regression here would cut off
		// every real upload.
		const t = await setup({ limits: { sourceTimeoutMs: 60_000 } });
		const s = await server(t.api);
		try {
			const bytes = source(12_000);
			const uploadId = await t.ticket(ID, bytes);
			let offset = 0;
			const slow = new ReadableStream<Uint8Array>({
				async pull(c) {
					if (offset >= bytes.byteLength) return c.close();
					await Bun.sleep(1000);
					c.enqueue(bytes.subarray(offset, offset + 1000));
					offset += 1000;
				},
			});
			const put = await s.call('PUT', `/v1/uploads/${uploadId}/source`, slow);
			expect(put.status).toBe(200);
		} finally {
			s.stop();
		}
	}, 30_000);

	test('without the spool, the route answers 404 and says where uploads go', async () => {
		const s = await server(undefined);
		try {
			const res = await s.call('POST', '/v1/uploads', JSON.stringify(ticketBody(ID, source(10))));
			expect(res.status).toBe(404);
			expect(((await res.json()) as { error: string }).error).toMatch(/reads them from S3/);
		} finally {
			s.stop();
		}
	});
});
