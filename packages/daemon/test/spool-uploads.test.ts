import { describe, expect, test } from 'bun:test';
import {
	link,
	mkdir,
	mkdtemp,
	readFile,
	stat,
	symlink,
	truncate,
	writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { UpRequest } from '@koi/shared';
import {
	BrokenUploadError,
	NoSuchUploadError,
	REQUEST_FILE,
	SOURCE_FILE,
	spoolLayout,
	spoolUploads,
} from '../src/spool-uploads.ts';
import { openingWith, overstatingSize, readingShort, request } from './fakes.ts';

const ID = 'abcdefghij0123456789';

// Claims are the upload API's business (upload-api.test.ts); the reader
// only passes them on.
const claims = {
	taken: [] as string[],
	async claim(id: string) {
		this.taken.push(`claim ${id}`);
	},
	async release(id: string) {
		this.taken.push(`release ${id}`);
	},
};

async function spool() {
	const root = await mkdtemp(join(tmpdir(), 'koid-spool-'));
	const layout = spoolLayout(root);
	await mkdir(layout.incoming, { recursive: true });
	await mkdir(layout.ready, { recursive: true });
	return { root, layout, uploads: spoolUploads(root, claims) };
}

// A committed entry as the upload API publishes it.
async function ready(
	dir: string,
	id: string,
	r: UpRequest | string = request({ id }),
	source: Uint8Array = Buffer.from('tarball'),
) {
	const entry = join(dir, id);
	await mkdir(entry, { recursive: true });
	await writeFile(join(entry, REQUEST_FILE), typeof r === 'string' ? r : JSON.stringify(r));
	await writeFile(join(entry, SOURCE_FILE), source);
	return entry;
}

describe('spoolUploads', () => {
	test('reads a committed request and copies its source', async () => {
		const s = await spool();
		const source = Buffer.alloc(300_000, 7);
		await ready(s.layout.ready, ID, request({ id: ID }), source);
		expect(await s.uploads.request(ID)).toEqual(request({ id: ID }));
		const file = join(s.root, 'build.tar.gz');
		await s.uploads.downloadSource(ID, file);
		expect(Buffer.from(await readFile(file)).equals(source)).toBe(true);
		// The copy is a file of its own.
		await writeFile(file, 'changed');
		expect(await readFile(join(s.layout.ready, ID, SOURCE_FILE), 'utf8')).not.toBe('changed');
	});

	test('passes claims and releases to the upload API', async () => {
		const s = await spool();
		claims.taken.length = 0;
		await s.uploads.claim(ID);
		await s.uploads.release(ID);
		expect(claims.taken).toEqual([`claim ${ID}`, `release ${ID}`]);
	});

	test('an id with no entry is a NoSuchUploadError', async () => {
		const s = await spool();
		const err = await s.uploads.request(ID).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(NoSuchUploadError);
		expect((err as Error).message).toBe(`no upload for request ${ID}`);
		await expect(s.uploads.downloadSource(ID, join(s.root, 'x'))).rejects.toBeInstanceOf(
			NoSuchUploadError,
		);
	});

	test('an upload still under incoming is not a request yet', async () => {
		const s = await spool();
		await ready(s.layout.incoming, 'a'.repeat(32), request({ id: ID }));
		await ready(s.layout.incoming, ID, request({ id: ID }));
		await expect(s.uploads.request(ID)).rejects.toBeInstanceOf(NoSuchUploadError);
	});

	test('refuses an id that is not a request id before touching the disk', async () => {
		const s = await spool();
		await expect(s.uploads.request('../etc')).rejects.toThrow();
		await expect(s.uploads.request('Not-An-Id')).rejects.toThrow();
	});

	test('refuses a request file that is a symlink', async () => {
		const s = await spool();
		const entry = join(s.layout.ready, ID);
		await mkdir(entry);
		await writeFile(join(s.root, 'elsewhere.json'), JSON.stringify(request({ id: ID })));
		await symlink(join(s.root, 'elsewhere.json'), join(entry, REQUEST_FILE));
		await writeFile(join(entry, SOURCE_FILE), 'tarball');
		await expect(s.uploads.request(ID)).rejects.toThrow(/request\.json of upload .* is a symlink/);
	});

	test('refuses a source that is a symlink', async () => {
		const s = await spool();
		const entry = join(s.layout.ready, ID);
		await mkdir(entry);
		await writeFile(join(entry, REQUEST_FILE), JSON.stringify(request({ id: ID })));
		await writeFile(join(s.root, 'secret.tar.gz'), 'tarball');
		await symlink(join(s.root, 'secret.tar.gz'), join(entry, SOURCE_FILE));
		await expect(s.uploads.downloadSource(ID, join(s.root, 'x'))).rejects.toThrow(
			/source\.tar\.gz of upload .* is a symlink/,
		);
	});

	test('refuses an entry directory that is a symlink', async () => {
		const s = await spool();
		const real = await ready(join(s.root, 'other'), ID);
		await symlink(real, join(s.layout.ready, ID));
		await expect(s.uploads.request(ID)).rejects.toThrow(/is not a directory/);
	});

	test('refuses a source that is a FIFO or has a second link', async () => {
		const s = await spool();
		const entry = join(s.layout.ready, ID);
		await mkdir(entry);
		await writeFile(join(entry, REQUEST_FILE), JSON.stringify(request({ id: ID })));
		expect(Bun.spawnSync(['mkfifo', join(entry, SOURCE_FILE)]).exitCode).toBe(0);
		await expect(s.uploads.downloadSource(ID, join(s.root, 'x'))).rejects.toThrow(
			/is not a regular file/,
		);
		const other = 'b'.repeat(20);
		await ready(s.layout.ready, other, request({ id: other }));
		await link(join(s.layout.ready, other, SOURCE_FILE), join(s.root, 'alias'));
		await expect(s.uploads.downloadSource(other, join(s.root, 'y'))).rejects.toThrow(/has 2 links/);
	});

	test('refuses a request over 256 KiB and a source over 2 GiB without reading them', async () => {
		const s = await spool();
		await ready(s.layout.ready, ID, `{"pad":"${'x'.repeat(256 * 1024)}"}`);
		await expect(s.uploads.request(ID)).rejects.toThrow(/request\.json .* is over 262144 bytes/);
		// A sparse file: the size is what counts, and it takes no disk.
		const other = 'b'.repeat(20);
		await ready(s.layout.ready, other, request({ id: other }));
		await truncate(join(s.layout.ready, other, SOURCE_FILE), 2 * 1024 ** 3 + 1);
		await expect(s.uploads.downloadSource(other, join(s.root, 'x'))).rejects.toThrow(
			/source\.tar\.gz .* is over 2147483648 bytes/,
		);
	});

	test('refuses a request that is empty, not JSON, not a request, or for another id', async () => {
		const s = await spool();
		await ready(s.layout.ready, ID, '{not json');
		await expect(s.uploads.request(ID)).rejects.toThrow();
		const empty = 'e'.repeat(20);
		await ready(s.layout.ready, empty, '');
		await expect(s.uploads.request(empty)).rejects.toThrow(/request\.json .* is empty/);
		const b = 'b'.repeat(20);
		await ready(s.layout.ready, b, '{"version":1}');
		await expect(s.uploads.request(b)).rejects.toThrow();
		const c = 'c'.repeat(20);
		await ready(s.layout.ready, c, request({ id: ID }));
		await expect(s.uploads.request(c)).rejects.toThrow(`request ${c} names itself ${ID}`);
	});

	test('an entry missing its source is damaged, not absent', async () => {
		const s = await spool();
		const entry = join(s.layout.ready, ID);
		await mkdir(entry);
		await writeFile(join(entry, REQUEST_FILE), JSON.stringify(request({ id: ID })));
		const err = await s.uploads.downloadSource(ID, join(s.root, 'x')).catch((e: unknown) => e);
		expect(err).not.toBeInstanceOf(NoSuchUploadError);
		expect((err as Error).message).toBe(`upload ${ID} has no ${SOURCE_FILE}`);
	});

	test('reads a request whole when a read gives fewer bytes than asked for', async () => {
		const s = await spool();
		await ready(s.layout.ready, ID);
		let reads = { reads: 0 };
		const spy = openingWith((path, handle) => {
			if (path === join(s.layout.ready, ID, REQUEST_FILE)) reads = readingShort(handle, 10);
		});
		try {
			expect(await s.uploads.request(ID)).toEqual(request({ id: ID }));
		} finally {
			spy.mockRestore();
		}
		expect(reads.reads).toBeGreaterThan(1);
	});

	test('a file that ends short of the size fstat gave is an error, not a broken entry', async () => {
		const s = await spool();
		await ready(s.layout.ready, ID);
		const entry = join(s.layout.ready, ID);
		const size = (await stat(join(entry, REQUEST_FILE))).size;
		const spy = openingWith((path, handle) => {
			if (path === join(entry, REQUEST_FILE) || path === join(entry, SOURCE_FILE)) {
				overstatingSize(handle);
			}
		});
		try {
			const err = await s.uploads.request(ID).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(Error);
			expect(err).not.toBeInstanceOf(BrokenUploadError);
			expect((err as Error).message).toBe(
				`${REQUEST_FILE} of upload ${ID} ended after ${size} of ${size + 1} bytes`,
			);
			// The copy of the source is checked the same way: a build must
			// not start from a short archive.
			await expect(s.uploads.downloadSource(ID, join(s.root, 'x'))).rejects.toThrow(
				`${SOURCE_FILE} of upload ${ID} gave 7 bytes, not the 8 it has`,
			);
		} finally {
			spy.mockRestore();
		}
		// Whole again, the entry reads as committed.
		expect(await s.uploads.request(ID)).toEqual(request({ id: ID }));
	});
});
