import { createHash } from 'node:crypto';
import { type BigIntStats, constants } from 'node:fs';
import { lstat, mkdtemp, open, readdir, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	commitObjectId,
	commitObjectTree,
	type DeploymentSource,
	type UpRequest,
} from '@koi/shared';
import { execOk } from './exec.ts';
import { extractTarball, SOURCE_LIMITS, type SourceLimits } from './fsutil.ts';

// What a build reads, computed from the directory koid unpacked its source
// tarball into, after tar has run and before the build does. The build reads
// that directory and nothing else of the upload, so these say what it read,
// however tar wrote it and whatever the request says.
//
// `digest` is exact: the SHA-256 of a listing of every entry under the
// directory, .koi-runtime/ included (see Walk for the format). Two builds
// with the same digest read the same paths, types, permission bits, bytes,
// symlink targets and hard links. Owners and times are left out. koid owns
// every file it unpacks, and two uploads of the same files carry different
// times.
//
// `tree` and `runtimeTree` are git's view of the same entries, the ids git
// gives them: a regular file is a blob of its bytes, mode 100755 when the
// owner may execute it and 100644 otherwise; a symlink is a blob of its
// target, mode 120000, never followed; a directory is a tree of what is
// under it, and one with no file under it is left out; a hard link is a
// file like any other. So a build of exactly a commit's files gives the id
// git rev-parse COMMIT^{tree} prints. git keeps less than a build reads
// (empty directories, permission bits but the owner's execute bit, hard
// links), so builds with one tree can differ, and only the digest tells
// them apart. `tree` leaves out .koi-runtime/, which no commit holds, and
// `runtimeTree` is its id.
//
// An entry git has no object for (a fifo, socket or device) is in the
// digest by type, path and mode, never opened, and there is then no tree:
// `noTree` says why. The walk opens nothing but regular files, reads at
// most `limits`, as unpacking does, and holds paths and ids, never a
// file's bytes. Any other failure throws, and the deployment records no
// source.

export interface SourceHashes {
	digest: string;
	tree?: string;
	runtimeTree?: string;
	// Why tree and runtimeTree are absent, for the build log.
	noTree?: string;
}

export interface WalkOptions {
	limits?: SourceLimits;
	signal?: AbortSignal;
}

// The directory koi up adds to every tarball for files of its own
// (RUNTIME_DIR in the CLI's git.ts), which no commit holds.
const RUNTIME_DIR = Buffer.from('.koi-runtime');

// How much of a file one read takes.
const READ_BYTES = 1024 * 1024;

// The source under `dir`, as a build of it reads it.
export async function hashSourceDir(dir: string, options: WalkOptions = {}): Promise<SourceHashes> {
	return new Walk(options.limits ?? SOURCE_LIMITS, options.signal).run(Buffer.from(dir));
}

// The source a tarball gives a build: unpacked as koid unpacks one
// (extractTarball) into a directory of its own, which is then walked and
// removed. For scripts/source-tree.ts and tests, so that they and koid
// cannot disagree.
export async function hashSourceTarball(
	tarball: string,
	options: WalkOptions = {},
): Promise<SourceHashes> {
	const work = await mkdtemp(join(tmpdir(), 'koi-source-'));
	try {
		const src = join(work, 'src');
		await extractTarball(tarball, src, options.limits);
		return await hashSourceDir(src, options);
	} finally {
		// The archive may have made directories its owner cannot write.
		await execOk(['chmod', '-R', 'u+rwX', work]).catch(() => {});
		await rm(work, { recursive: true, force: true });
	}
}

// What a build read (DeploymentSourceSchema): its hashes, and whether the
// project's tree is the one the request's commit object names, with that
// tree. koid takes the object only when it hashes to the request's commit,
// so the CLI can name no tree but that commit's; for one that does not, or
// none, or a source with no tree, there is no answer and no commitTree.
export function deploymentSourceOf(
	hashes: SourceHashes,
	request: Pick<UpRequest, 'commit' | 'commitObject'>,
): { source: DeploymentSource; commitTree?: string } {
	const { noTree: _, ...source } = hashes;
	const object =
		request.commitObject !== undefined ? Buffer.from(request.commitObject, 'base64') : undefined;
	const commitTree =
		object !== undefined && commitObjectId(object) === request.commit
			? commitObjectTree(object)
			: undefined;
	if (commitTree === undefined || source.tree === undefined) return { source };
	return { source: { ...source, matchesCommit: source.tree === commitTree }, commitTree };
}

// An entry of a directory, from its lstat.
interface Child {
	name: Buffer;
	// The name git sorts the entry by: a directory's with '/' after it.
	key: Buffer;
	stats: BigIntStats;
}

// What a git tree says of one name: its mode and object id.
interface GitBlob {
	mode: string;
	oid: Buffer;
}

// An entry of a git tree object.
interface GitEntry extends GitBlob {
	name: Buffer;
	key: Buffer;
}

const SLASH = Buffer.from('/');
const NUL = Buffer.from([0]);

// git's id of the empty tree.
const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

// One walk of a source directory, depth first, each directory's entries in
// git's order: by name as bytes, a directory's name read as ending in '/'.
// That order is also the order of the entries' paths as bytes, a
// directory's path written with its '/', so the digest's listing is sorted
// by path while the walk holds only the directories it is in.
//
// The listing the digest hashes is "koi-source-digest/1" and a NUL, then one
// record per entry under the directory (not the directory itself), in that
// order. A record is fields each ended by a NUL: the type, the path
// relative to the directory, then
//   file      mode, size in decimal, the SHA-256 of the bytes in hex
//   hardlink  the path of the first file in the listing with its inode
//   symlink   mode, the target's bytes
//   dir       mode (the path ends in '/')
//   fifo      mode
//   socket    mode
//   char      mode, the device number in decimal
//   block     mode, the device number in decimal
// where mode is the permission bits (st_mode & 07777) as four octal digits.
// Paths and targets are bytes and hold no NUL, and the type says how many
// fields follow, so one listing has one reading.
class Walk {
	private readonly digest = createHash('sha256').update('koi-source-digest/1\0');
	private readonly buffer = Buffer.allocUnsafe(READ_BYTES);
	// The first path, and the blob id, of each file with more than one name.
	// The first path of each inode with more than one name, and its entry in a
	// git tree (none for a type git has no object for).
	private readonly inodes = new Map<string, { path: Buffer; blob: GitBlob | undefined }>();
	private entries = 0;
	private bytes = 0;
	private noTree: string | undefined;
	private runtimeTree: Buffer | undefined;

	constructor(
		private readonly limits: SourceLimits,
		private readonly signal: AbortSignal | undefined,
	) {}

	async run(root: Buffer): Promise<SourceHashes> {
		const entries = await this.directory(root, Buffer.alloc(0));
		const digest = `sha256:${this.digest.digest('hex')}`;
		if (this.noTree !== undefined) return { digest, noTree: this.noTree };
		const runtimeTree = this.runtimeTree?.toString('hex');
		return {
			digest,
			tree: treeId(entries)?.toString('hex') ?? EMPTY_TREE,
			...(runtimeTree !== undefined ? { runtimeTree } : {}),
		};
	}

	// Walks the directory at `abs`, whose path in the listing is `rel` (empty
	// for the root, else ending in '/'), and returns its git tree entries.
	private async directory(abs: Buffer, rel: Buffer): Promise<GitEntry[]> {
		this.signal?.throwIfAborted();
		const names = await readdir(abs, { encoding: 'buffer' });
		this.entries += names.length;
		if (this.entries > this.limits.entries) {
			throw new Error(`the source has more than ${this.limits.entries} files and directories`);
		}
		const children: Child[] = [];
		for (const name of names) {
			const stats = await lstat(Buffer.concat([abs, SLASH, name]), { bigint: true });
			children.push({
				name,
				key: stats.isDirectory() ? Buffer.concat([name, SLASH]) : name,
				stats,
			});
		}
		children.sort((a, b) => Buffer.compare(a.key, b.key));
		const git: GitEntry[] = [];
		for (const { name, key, stats } of children) {
			this.signal?.throwIfAborted();
			const path = Buffer.concat([rel, key]);
			const entry = await this.entry(Buffer.concat([abs, SLASH, name]), path, stats);
			if (rel.length === 0 && name.equals(RUNTIME_DIR)) {
				if (stats.isDirectory()) this.runtimeTree = entry?.oid;
				else this.noTree ??= `${quoted(path)} is ${kind(stats)}, not a directory`;
				continue;
			}
			if (entry !== undefined) git.push({ name, key, ...entry });
		}
		return git;
	}

	// Writes the record of one entry and returns its mode and id in a git
	// tree, or undefined for a directory with no file under it and an entry
	// git has no object for.
	private async entry(abs: Buffer, path: Buffer, stats: BigIntStats): Promise<GitBlob | undefined> {
		const mode = (Number(stats.mode) & 0o7777).toString(8).padStart(4, '0');
		if (stats.isDirectory()) {
			this.record('dir', path, mode);
			const oid = treeId(await this.directory(abs, path));
			return oid !== undefined ? { mode: '40000', oid } : undefined;
		}
		// GNU tar links a second name to any type but a directory, a symlink
		// or a fifo included, so every one of them is recorded as a link to
		// the first name. In a git tree each name stays what that one is.
		const inode = stats.nlink > 1n ? `${stats.dev}:${stats.ino}` : undefined;
		const first = inode !== undefined ? this.inodes.get(inode) : undefined;
		if (first !== undefined) {
			this.record('hardlink', path, first.path);
			if (first.blob === undefined) {
				this.noTree ??= `${quoted(path)} is ${kind(stats)}, which git has no object for`;
			}
			return first.blob;
		}
		const blob = await this.leaf(abs, path, stats, mode);
		if (inode !== undefined) this.inodes.set(inode, { path, blob });
		return blob;
	}

	// Writes the record of a file, symlink or other entry that is not a
	// directory, seen under its first name.
	private async leaf(
		abs: Buffer,
		path: Buffer,
		stats: BigIntStats,
		mode: string,
	): Promise<GitBlob | undefined> {
		if (stats.isFile()) {
			const size = Number(stats.size);
			this.bytes += size;
			if (this.bytes > this.limits.bytes) {
				throw new Error(`the source unpacks to more than ${this.limits.bytes} bytes`);
			}
			const { oid, sha256 } = await this.file(abs, path, stats);
			this.record('file', path, mode, String(size), sha256);
			return { mode: (Number(stats.mode) & 0o100) !== 0 ? '100755' : '100644', oid };
		}
		if (stats.isSymbolicLink()) {
			const target = await readlink(abs, { encoding: 'buffer' });
			this.record('symlink', path, mode, target);
			const oid = createHash('sha1').update(`blob ${target.length}\0`).update(target).digest();
			return { mode: '120000', oid };
		}
		// Recorded without being opened: a fifo would block a read.
		const type = stats.isFIFO()
			? 'fifo'
			: stats.isSocket()
				? 'socket'
				: stats.isCharacterDevice()
					? 'char'
					: 'block';
		if (type === 'char' || type === 'block') this.record(type, path, mode, String(stats.rdev));
		else this.record(type, path, mode);
		this.noTree ??= `${quoted(path)} is ${kind(stats)}, which git has no object for`;
		return undefined;
	}

	// The blob id git gives a regular file's bytes, and their SHA-256, read
	// once. The open refuses anything but the file lstat saw.
	private async file(
		abs: Buffer,
		path: Buffer,
		stats: BigIntStats,
	): Promise<{ oid: Buffer; sha256: string }> {
		const handle = await open(
			abs,
			constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
		);
		try {
			const opened = await handle.stat({ bigint: true });
			if (!opened.isFile() || opened.ino !== stats.ino || opened.dev !== stats.dev) {
				throw new Error(`${quoted(path)} changed while koid read it`);
			}
			const git = createHash('sha1').update(`blob ${stats.size}\0`);
			const sha256 = createHash('sha256');
			let read = 0;
			for (;;) {
				this.signal?.throwIfAborted();
				const { bytesRead } = await handle.read(this.buffer, 0, READ_BYTES, read);
				if (bytesRead === 0) break;
				const bytes = this.buffer.subarray(0, bytesRead);
				git.update(bytes);
				sha256.update(bytes);
				read += bytesRead;
			}
			if (BigInt(read) !== stats.size) {
				throw new Error(`${quoted(path)} changed while koid read it`);
			}
			return { oid: git.digest(), sha256: sha256.digest('hex') };
		} finally {
			await handle.close();
		}
	}

	private record(type: string, ...fields: Array<string | Buffer>): void {
		this.digest.update(type).update(NUL);
		for (const field of fields) this.digest.update(field).update(NUL);
	}
}

// git's id of a tree holding `entries`, given in git's order, or undefined
// when there are none.
function treeId(entries: GitEntry[]): Buffer | undefined {
	if (entries.length === 0) return undefined;
	const body = Buffer.concat(
		entries.flatMap(({ name, mode, oid }) => [Buffer.from(`${mode} `), name, NUL, oid]),
	);
	return createHash('sha1').update(`tree ${body.length}\0`).update(body).digest();
}

function kind(stats: BigIntStats): string {
	if (stats.isFile()) return 'a file';
	if (stats.isSymbolicLink()) return 'a symlink';
	if (stats.isFIFO()) return 'a fifo';
	if (stats.isSocket()) return 'a socket';
	if (stats.isCharacterDevice()) return 'a character device';
	if (stats.isBlockDevice()) return 'a block device';
	return 'a directory';
}

function quoted(path: Buffer): string {
	return JSON.stringify(path.toString().replace(/\/$/, '').slice(0, 200));
}
