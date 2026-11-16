import { randomUUID } from 'node:crypto';
import {
	link,
	mkdir,
	open,
	realpath,
	rename,
	rm,
	stat,
	statfs,
	unlink,
	writeFile,
} from 'node:fs/promises';
import { join, sep } from 'node:path';
import { ExecError, exec, execOk } from './exec.ts';

// Joins a relative path to a root and proves the result is still inside it
// after symlinks are resolved. The schemas only check syntax; this is the check
// that a symlink in the pull request cannot point a Dockerfile or build
// context at /etc or the daemon's state. The path must exist.
export async function resolveInside(root: string, relative: string): Promise<string> {
	const realRoot = await realpath(root);
	let target: string;
	try {
		target = await realpath(join(realRoot, relative));
	} catch {
		throw new Error(`${JSON.stringify(relative)} does not exist in the source tree`);
	}
	if (target !== realRoot && !target.startsWith(realRoot + sep)) {
		throw new Error(`${JSON.stringify(relative)} resolves outside the source tree`);
	}
	return target;
}

export interface SourceLimits {
	// Total size of the members once unpacked.
	bytes: number;
	entries: number;
}

// What a pull request's source may unpack to. The tarball itself is at most
// 2 GB (uploads.ts), but gzip can expand that a thousandfold.
export const SOURCE_LIMITS: SourceLimits = { bytes: 4 * 1024 ** 3, entries: 200_000 };

// Unpacks a source tarball as the daemon's user, without restoring owners or
// permissions from the archive, after listing it and refusing it if it would
// unpack to more than `limits`. GNU tar refuses absolute and ".." member names.
export async function extractTarball(
	tarball: string,
	dir: string,
	limits: SourceLimits = SOURCE_LIMITS,
): Promise<void> {
	await checkTarball(tarball, limits);
	await mkdir(dir, { recursive: true });
	await execOk(
		[
			'tar',
			'-xzf',
			tarball,
			'-C',
			dir,
			'--no-same-owner',
			'--no-same-permissions',
			'--no-overwrite-dir',
		],
		{ timeoutMs: 10 * 60_000 },
	);
}

// Reads the archive's listing, stopping tar as soon as a limit is passed.
async function checkTarball(tarball: string, limits: SourceLimits): Promise<void> {
	const cmd = ['tar', '--numeric-owner', '-tvzf', tarball];
	const stop = new AbortController();
	let entries = 0;
	let bytes = 0;
	let refusal: string | undefined;
	const result = await exec(cmd, {
		timeoutMs: 10 * 60_000,
		signal: stop.signal,
		onLine(line, stream) {
			if (stream !== 'stdout' || refusal !== undefined) return;
			const size = tarMemberSize(line);
			entries += 1;
			bytes += size ?? 0;
			if (size === undefined) {
				refusal = `cannot read the archive listing at ${JSON.stringify(line.slice(0, 200))}`;
			} else if (entries > limits.entries) {
				refusal = `the source has more than ${limits.entries} files and directories`;
			} else if (bytes > limits.bytes) {
				refusal = `the source unpacks to more than ${mebibytes(limits.bytes)}`;
			}
			if (refusal !== undefined) stop.abort();
		},
	});
	if (refusal !== undefined) throw new Error(refusal);
	if (result.code !== 0 || result.timedOut) throw new ExecError(cmd, result);
}

// The size of one member in GNU tar's verbose listing with --numeric-owner:
//   -rw-r--r-- 1000/1000      1234 2026-10-06 12:00 docs/a file.md
// Owners are numbers, so the size is always the third field. Device files
// show "major,minor" there and take no space. Undefined if the line is not a
// member.
export function tarMemberSize(line: string): number | undefined {
	const fields = line.trim().split(/\s+/);
	const size = fields[2];
	if (fields.length < 6 || size === undefined || !/^[0-9]+\/[0-9]+$/.test(fields[1] ?? '')) {
		return undefined;
	}
	if (/^[0-9]+$/.test(size)) return Number(size);
	if (/^[0-9]+,[0-9]+$/.test(size)) return 0;
	return undefined;
}

function mebibytes(bytes: number): string {
	return `${Math.floor(bytes / 1024 ** 2)} MiB`;
}

// Replaces a file in one step: writes a temporary file beside it and renames
// that over it, so a reader sees the old text or the new, never half of one.
export async function writeFileAtomic(path: string, text: string, mode = 0o640): Promise<void> {
	const temp = `${path}.${randomUUID()}.tmp`;
	try {
		await writeFile(temp, text, { mode });
		await rename(temp, path);
	} catch (err) {
		await rm(temp, { force: true });
		throw err;
	}
}

// Creates `path` with `text`, or returns false when it already exists. The
// text goes to a temporary file first and is linked into place, which fails
// with EEXIST if another writer got there first. An exclusive open would be
// exclusive too, but the file would exist empty until its text was written,
// and the loser of the race could read it in that state. Where the
// filesystem has no hard links, the exclusive open is what there is, and the
// loser waits out the empty moment instead; see createByExclusiveOpen.
// `fs.link` is the real one unless a test injects a failure.
export async function createFileExclusive(
	path: string,
	text: string,
	mode = 0o640,
	fs: { link: typeof link } = { link },
): Promise<boolean> {
	const temp = `${path}.${randomUUID()}.tmp`;
	try {
		await writeFile(temp, text, { mode });
		try {
			await fs.link(temp, path);
			return true;
		} catch (err) {
			if (isCode(err, 'EEXIST')) return false;
			if (!isCode(err, 'EOPNOTSUPP') && !isCode(err, 'ENOTSUP') && !isCode(err, 'EPERM')) {
				throw err;
			}
		}
	} finally {
		await rm(temp, { force: true });
	}
	return createByExclusiveOpen(path, text, mode);
}

// How often, and how long apart, a reader looks again at a file that is
// still empty.
const EMPTY_FILE_RETRIES = 20;
const EMPTY_FILE_RETRY_MS = 50;

// Waits while `path` is there and empty, as it is between another writer's
// exclusive open and its write (see createByExclusiveOpen), looking a few
// times over about a second. Returns once the file has content or is gone.
// A file that stays empty is left to the caller to judge. Shared by the
// loser of that open and by any reader that may meet the file in that state.
export async function waitWhileEmpty(path: string): Promise<void> {
	for (let i = 0; i < EMPTY_FILE_RETRIES; i++) {
		if ((await stat(path).catch(() => undefined))?.size !== 0) return;
		await Bun.sleep(EMPTY_FILE_RETRY_MS);
	}
}

// createFileExclusive for a filesystem that rejects link(): the file is
// opened exclusively, written and synced. Between the open and the write it
// exists empty, so when the open finds the file there already, this waits
// until it has content before returning false. A process that dies or fails
// to write in that gap leaves the empty file behind for good; removeIfEmpty
// is how a reader clears it.
async function createByExclusiveOpen(path: string, text: string, mode: number): Promise<boolean> {
	let handle: Awaited<ReturnType<typeof open>>;
	try {
		handle = await open(path, 'wx', mode);
	} catch (err) {
		if (!isCode(err, 'EEXIST')) throw err;
		await waitWhileEmpty(path);
		return false;
	}
	try {
		await handle.writeFile(text);
		await handle.sync();
	} finally {
		await handle.close();
	}
	return true;
}

// Removes `path` if it is an empty file, and leaves it alone if it has
// content or is gone. For the file createByExclusiveOpen leaves when the
// process that opened it dies or fails to write: nothing was ever read from
// an empty file, so nothing is lost by removing it. True when the name is
// free afterwards.
//
// The size is read from an open descriptor right before the unlink, so a
// writer that filled the file a moment earlier keeps it. The unlink goes by
// name and cannot be made to depend on the size, so a writer can still land
// between the two. Its text went to the inode this descriptor holds open,
// so it is read back from there and put under the name again, and that
// writer keeps its file too. This assumes the text came from one write, as
// createFileExclusive makes it. `fs.unlink` is the real one unless a test
// injects a writer that lands just then.
export async function removeIfEmpty(
	path: string,
	fs: { unlink: typeof unlink } = { unlink },
): Promise<boolean> {
	let handle: Awaited<ReturnType<typeof open>>;
	try {
		handle = await open(path, 'r');
	} catch (err) {
		if (isCode(err, 'ENOENT')) return true;
		throw err;
	}
	try {
		if ((await handle.stat()).size !== 0) return false;
		try {
			await fs.unlink(path);
		} catch (err) {
			// Another reader of the same empty file got there first.
			if (!isCode(err, 'ENOENT')) throw err;
		}
		const after = await handle.stat();
		if (after.size === 0) return true;
		// False either way: the writer's text is back under the name, or a
		// third process created the file in the meantime and owns the name.
		await createFileExclusive(path, await handle.readFile('utf8'), after.mode & 0o777);
		return false;
	} finally {
		await handle.close();
	}
}

function isCode(err: unknown, code: string): boolean {
	return err instanceof Error && 'code' in err && err.code === code;
}

// What a build needs left free on the disk Docker keeps its data on: a tenth of it, up
// to 20 GiB. A build on a 2 TB disk does not need 200 GiB.
export function minFreeBytes(size: number): number {
	return Math.min(0.1 * size, 20 * 1024 ** 3);
}

// The space left to unprivileged users on the filesystem that holds `path`,
// and its size, in bytes.
export async function diskSpace(path: string): Promise<{ free: number; size: number }> {
	const s = await statfs(path);
	return { free: s.bavail * s.bsize, size: s.blocks * s.bsize };
}
