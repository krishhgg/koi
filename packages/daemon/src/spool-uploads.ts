import { constants, createWriteStream } from 'node:fs';
import { type FileHandle, lstat, open } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { RequestIdSchema, type UpRequest, UpRequestSchema } from '@koi/shared';
import type { Uploads } from './uploads.ts';

// The upload spool on the host, for a box the CLI reaches over SSH instead of
// through S3:
//
//   <spoolDir>/incoming/<upload-id>/   an upload under way (upload-api.ts)
//   <spoolDir>/ready/<request-id>/     a committed request: request.json and
//                                      source.tar.gz, never changed again
//
// This is the reader. It opens only committed entries, with the same limits
// as the S3 reader: a request of at most 256 KiB, a source of at most 2 GiB,
// copied to the build directory within ten minutes. The directory tree is
// the service user's own, mode 0700, with nothing mounted into it, so the
// checks here are against mistakes and against a file planted by a process
// running as that user, not against a hostile owner of the tree.
//
// One check is out of reach, and not faked: Bun and Node have no openat, so
// nothing pins the entry directory between the lstat that proves it is a
// directory and the open of a file inside it. A process that swapped it in
// that moment would have to run as koid's user, because only that user can
// rename inside a 0700 directory of its own, and such a process already
// controls koid itself. The lstat, O_NOFOLLOW and fstat checks stay for
// what they do catch.

export const MAX_SOURCE_BYTES = 2 * 1024 ** 3;
export const MAX_REQUEST_BYTES = 256 * 1024;
const DOWNLOAD_TIMEOUT_MS = 10 * 60_000;

export const REQUEST_FILE = 'request.json';
export const SOURCE_FILE = 'source.tar.gz';

export interface SpoolLayout {
	incoming: string;
	ready: string;
}

export function spoolLayout(spoolDir: string): SpoolLayout {
	return { incoming: join(spoolDir, 'incoming'), ready: join(spoolDir, 'ready') };
}

// Thrown for an entry that is not there, so a caller can tell "no such
// request" from a damaged one.
export class NoSuchUploadError extends Error {}

// Thrown for an entry that is there but not whole: a file of it is missing,
// or its request is empty, does not parse, or names another id. A commit
// publishes both files in one rename, so only a removal that failed part
// way leaves an entry like this. No build can use it and no commit of the
// id can take its place while it is there, so the upload API removes it
// (upload-api.ts). Any other failure is a plain error and the entry is left
// alone.
export class BrokenUploadError extends Error {}

// Opens one file of a committed entry for reading and proves what was
// opened is a plain file of at most `max` bytes. The open refuses to follow
// a symlink in the last path component (O_NOFOLLOW), the entry directory is
// checked not to be one first, and the checks on size and kind run on the
// open descriptor (fstat), so they describe the file that will be read and
// not another one that took its name in between. O_NONBLOCK keeps the open
// from waiting on a FIFO; a regular file ignores it. The entry directory
// itself is not pinned between the lstat and the open (no openat; see the
// note at the top).
export async function openReadyFile(
	readyDir: string,
	id: string,
	name: string,
	max: number,
): Promise<{ handle: FileHandle; size: number }> {
	const dir = join(readyDir, RequestIdSchema.parse(id));
	let entry: Awaited<ReturnType<typeof lstat>>;
	try {
		entry = await lstat(dir);
	} catch (err) {
		if (isCode(err, 'ENOENT')) throw new NoSuchUploadError(`no upload for request ${id}`);
		throw err;
	}
	if (!entry.isDirectory()) throw new Error(`upload ${id} is not a directory`);
	let handle: FileHandle;
	try {
		handle = await open(
			join(dir, name),
			constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY,
		);
	} catch (err) {
		if (isCode(err, 'ENOENT')) throw new BrokenUploadError(`upload ${id} has no ${name}`);
		if (isCode(err, 'ELOOP')) throw new Error(`${name} of upload ${id} is a symlink`);
		throw err;
	}
	try {
		const stat = await handle.stat();
		if (!stat.isFile()) throw new Error(`${name} of upload ${id} is not a regular file`);
		if (stat.nlink !== 1) throw new Error(`${name} of upload ${id} has ${stat.nlink} links`);
		if (stat.size > max) throw new Error(`${name} of upload ${id} is over ${max} bytes`);
		return { handle, size: stat.size };
	} catch (err) {
		await handle.close().catch(() => {});
		throw err;
	}
}

// A read of a regular file may give fewer bytes than asked for and still
// succeed, so one read is not the file. The readers of the request and of
// the source loop until the size fstat gave is in, this many bytes at a
// time.
const READ_PIECE_BYTES = 1024 ** 2;

// Reads the `size` bytes of an open file from its start, in order, handing
// each piece to `take` before the next is read. The piece is reused, so
// `take` copies what it keeps. `size` is what fstat gave for the open
// descriptor (openReadyFile). The end of the file before that is a plain
// error, not a BrokenUploadError: a committed file does not shrink on its
// own, so the disk misread it or a process running as the service user cut
// it, and the entry is left for a later look rather than removed.
export async function readWhole(
	handle: FileHandle,
	size: number,
	what: string,
	take: (piece: Buffer) => void,
): Promise<void> {
	const buffer = Buffer.alloc(Math.min(size, READ_PIECE_BYTES));
	let offset = 0;
	while (offset < size) {
		const length = Math.min(buffer.length, size - offset);
		const { bytesRead } = await handle.read(buffer, 0, length, offset);
		if (bytesRead === 0) throw new Error(`${what} ended after ${offset} of ${size} bytes`);
		take(buffer.subarray(0, bytesRead));
		offset += bytesRead;
	}
}

// The committed request of an entry, checked as the S3 reader checks it.
// The file is read whole before it is judged (readWhole): the JSON left by
// a short read would look like a broken entry and get it removed.
export async function readReadyRequest(readyDir: string, id: string): Promise<UpRequest> {
	const { handle, size } = await openReadyFile(readyDir, id, REQUEST_FILE, MAX_REQUEST_BYTES);
	let text: string;
	try {
		if (size === 0) throw new BrokenUploadError(`${REQUEST_FILE} of upload ${id} is empty`);
		const pieces: Buffer[] = [];
		await readWhole(handle, size, `${REQUEST_FILE} of upload ${id}`, (piece) => {
			pieces.push(Buffer.from(piece));
		});
		text = Buffer.concat(pieces).toString('utf8');
	} finally {
		await handle.close();
	}
	let request: UpRequest;
	try {
		request = UpRequestSchema.parse(JSON.parse(text));
	} catch (err) {
		throw new BrokenUploadError(
			`${REQUEST_FILE} of upload ${id} is not a request: ${err instanceof Error ? err.message : String(err)}`,
			{ cause: err },
		);
	}
	if (request.id !== id) {
		throw new BrokenUploadError(`request ${id} names itself ${request.id}`);
	}
	return request;
}

// The reader over `spoolDir`. Claims go to `claims`, the upload API's, whose
// cleanup leaves a claimed entry alone (upload-api.ts).
export function spoolUploads(
	spoolDir: string,
	claims: Pick<Uploads, 'claim' | 'release'>,
): Uploads {
	const { ready } = spoolLayout(spoolDir);
	return {
		request: (id) => readReadyRequest(ready, id),
		claim: (id) => claims.claim(id),
		release: (id) => claims.release(id),
		async downloadSource(id, file) {
			const { handle, size } = await openReadyFile(ready, id, SOURCE_FILE, MAX_SOURCE_BYTES);
			try {
				// A copy, not a link: the build directory gets a file of its own,
				// and the ready entry stays as it was committed.
				const copy = createWriteStream(file);
				await pipeline(handle.createReadStream({ autoClose: false }), copy, {
					signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
				});
				// The stream copies to the end of the file, wherever that is.
				// A build must not start from an archive short of the size
				// fstat gave (see readWhole), so the count is checked.
				if (copy.bytesWritten !== size) {
					throw new Error(
						`${SOURCE_FILE} of upload ${id} gave ${copy.bytesWritten} bytes, not the ${size} it has`,
					);
				}
			} finally {
				await handle.close().catch(() => {});
			}
		},
	};
}

export function isCode(err: unknown, code: string): boolean {
	return typeof err === 'object' && err !== null && 'code' in err && err.code === code;
}
