import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { createGunzip } from 'node:zlib';
import {
	commitObjectId,
	commitObjectTree,
	type DeploymentSource,
	type UpRequest,
} from '@koi/shared';
import { SOURCE_LIMITS, type SourceLimits } from './fsutil.ts';

// The git tree ids of a source tarball as koid received it: `tree` for the
// project's files, and `runtimeTree` for what koi added under .koi-runtime/,
// which git never holds. koid computes them from the bytes it builds from,
// so they say what the build read, whatever the request says.
//
// Each id is the one git gives the same bytes: a regular file is a blob of
// its bytes, mode 100755 when the owner may execute it and 100644
// otherwise, as git stores them; a symlink is a blob of its target, mode
// 120000; a directory is a tree of the files under it, and one with none
// is left out, as git leaves it out. So a tarball of exactly a commit's
// files gives the id git rev-parse COMMIT^{tree} prints, and anyone with
// the repository can check it without the tarball. What tar adds and git
// does not keep (owners, times, the gzip header, the order of entries)
// changes nothing.
//
// The bytes are hashed as they are, never as git would store them: a file
// git converts on checkout (eol=crlf, core.autocrlf, a filter such as LFS,
// ident) is in the tarball as checked out, and so is hashed. A tree with
// such a file, or with a submodule (an empty directory in the tarball, a
// commit in the commit's tree), never gives the commit's id. The id is
// then what git write-tree gives for the same files added with no
// attributes and no conversion.
//
// A hard link, which GNU tar writes for a second name of a file it packed
// already, is a copy of that file: tar unpacks it as a link to the same
// inode, so the bytes and mode are the file's.
//
// A tarball the id cannot describe exactly is refused with an Error that
// says why, rather than described as something it is not: an entry tar
// would unpack as anything but a file, symlink, hard link to a file or
// directory (devices, fifos, sparse files), a path given twice or that is
// both a file and a directory, a path GNU tar would unpack somewhere else
// than it reads ('..', an empty or '.' segment, a leading '/'), a PAX
// record that could change what an entry holds (a size, sparse maps), a
// symlink or directory with data, and anything after the end of the
// archive.
//
// The tarball streams through: memory holds the paths and their ids, never
// a file's bytes. It reads at most `limits`, as unpacking does.

export interface SourceTrees {
	tree: string;
	runtimeTree?: string;
}

// The directory koi up adds to every tarball for files of its own
// (RUNTIME_DIR in the CLI's git.ts), which no commit holds.
const RUNTIME_DIR = '.koi-runtime';

const BLOCK = 512;

// The longest path koid takes from a header, a PAX record or a GNU long
// name. Linux refuses longer ones, so tar could not unpack them anyway.
const MAX_PATH_BYTES = 4096;

// The most a PAX header or a GNU long name entry may hold.
const MAX_META_BYTES = 64 * 1024;

// PAX keys that change nothing git keeps: times, owners and their names, a
// comment (git archive writes the commit id as one), and how text is coded.
const IGNORED_PAX = new Set([
	'atime',
	'charset',
	'comment',
	'ctime',
	'gid',
	'gname',
	'hdrcharset',
	'mtime',
	'uid',
	'uname',
]);

type Tree = { kind: 'tree'; children: Map<string, Node> };
type Blob = { kind: 'blob'; mode: string; oid: Buffer };
type Node = Tree | Blob;

export async function sourceTrees(
	tarball: string,
	limits: SourceLimits = SOURCE_LIMITS,
): Promise<SourceTrees> {
	const reader = new TreeReader(limits);
	await pipeline(
		createReadStream(tarball),
		createGunzip(),
		async (chunks: AsyncIterable<Buffer>) => {
			for await (const chunk of chunks) reader.push(chunk);
		},
	);
	return reader.finish();
}

// What a build read (DeploymentSourceSchema): the tree ids of its tarball,
// and whether the project's tree is the one the request's commit object
// names, with that tree. koid takes the object only when it hashes to the
// request's commit, so the CLI can name no tree but that commit's; for one
// that does not, or none, there is no answer and no commitTree.
export function deploymentSourceOf(
	trees: SourceTrees,
	request: Pick<UpRequest, 'commit' | 'commitObject'>,
): { source: DeploymentSource; commitTree?: string } {
	const object =
		request.commitObject !== undefined ? Buffer.from(request.commitObject, 'base64') : undefined;
	const commitTree =
		object !== undefined && commitObjectId(object) === request.commit
			? commitObjectTree(object)
			: undefined;
	if (commitTree === undefined) return { source: { ...trees } };
	return { source: { ...trees, matchesCommit: trees.tree === commitTree }, commitTree };
}

// Reads a tar stream chunk by chunk and builds the tree of what it holds.
export class TreeReader {
	private readonly root: Tree = { kind: 'tree', children: new Map() };
	private readonly header = Buffer.alloc(BLOCK);
	private headerFill = 0;
	// Bytes of the current entry's data still to come, then of its padding.
	private remaining = 0;
	private padding = 0;
	// Where the current entry's data goes, and what happens once it is all
	// there.
	private sink: ((bytes: Buffer) => void) | undefined;
	private done: (() => void) | undefined;
	// Set by a PAX header or GNU long name for the entry after it.
	private nextPath: string | undefined;
	private nextLink: string | undefined;
	private ended = false;
	private entries = 0;
	private bytes = 0;

	constructor(private readonly limits: SourceLimits) {}

	push(chunk: Buffer): void {
		let at = 0;
		while (at < chunk.length) {
			if (this.ended) {
				if (chunk.subarray(at).some((b) => b !== 0))
					throw new Error('the archive has data after its end');
				return;
			}
			if (this.remaining > 0) {
				const n = Math.min(this.remaining, chunk.length - at);
				this.sink?.(chunk.subarray(at, at + n));
				at += n;
				this.remaining -= n;
				if (this.remaining === 0) this.endEntry();
				continue;
			}
			if (this.padding > 0) {
				const n = Math.min(this.padding, chunk.length - at);
				at += n;
				this.padding -= n;
				continue;
			}
			const n = Math.min(BLOCK - this.headerFill, chunk.length - at);
			chunk.copy(this.header, this.headerFill, at, at + n);
			this.headerFill += n;
			at += n;
			if (this.headerFill === BLOCK) {
				this.headerFill = 0;
				this.readHeader();
			}
		}
	}

	finish(): SourceTrees {
		if (!this.ended) throw new Error('the archive ends early');
		if (this.nextPath !== undefined || this.nextLink !== undefined) {
			throw new Error('the archive ends with a long name and no entry after it');
		}
		const runtime = this.root.children.get(RUNTIME_DIR);
		if (runtime?.kind === 'blob') throw new Error(`${RUNTIME_DIR} is a file, not a directory`);
		const children = new Map(this.root.children);
		children.delete(RUNTIME_DIR);
		const runtimeTree = runtime !== undefined ? treeId(runtime.children) : undefined;
		return {
			tree: (treeId(children) ?? EMPTY_TREE).toString('hex'),
			...(runtimeTree !== undefined ? { runtimeTree: runtimeTree.toString('hex') } : {}),
		};
	}

	private readHeader(): void {
		const header = this.header;
		if (header.every((b) => b === 0)) {
			// GNU tar stops at the first zero block; so does the id.
			this.ended = true;
			return;
		}
		if (octal(header.subarray(148, 156)) !== checksum(header)) {
			throw new Error('a tar header has a checksum that does not match');
		}
		const size = octal(header.subarray(124, 136));
		if (size === undefined) throw new Error('a tar header has no octal size');
		const type = String.fromCharCode(header[156] ?? 0);
		this.start(size);
		if (type === 'x' || type === 'g' || type === 'L' || type === 'K') {
			if (size > MAX_META_BYTES)
				throw new Error(`a tar ${type} header is over ${MAX_META_BYTES} bytes`);
			const parts: Buffer[] = [];
			this.sink = (bytes) => parts.push(Buffer.from(bytes));
			this.done = () => this.readMeta(type, Buffer.concat(parts));
		} else {
			this.readEntry(type, size, header);
		}
		if (this.remaining === 0) this.endEntry();
	}

	private start(size: number): void {
		this.remaining = size;
		this.padding = (BLOCK - (size % BLOCK)) % BLOCK;
		this.sink = undefined;
		this.done = undefined;
	}

	private endEntry(): void {
		const done = this.done;
		this.sink = undefined;
		this.done = undefined;
		done?.();
	}

	private readMeta(type: string, data: Buffer): void {
		if (type === 'L' || type === 'K') {
			// GNU's long name or link target, ended by a NUL.
			const end = data.indexOf(0);
			const value = bytesText(end === -1 ? data : data.subarray(0, end));
			if (type === 'L') this.nextPath = value;
			else this.nextLink = value;
			return;
		}
		const records = paxRecords(data);
		for (const [key, value] of records) {
			if (key === 'path' || key === 'linkpath') {
				if (type === 'g') throw new Error(`the archive has a global PAX ${key} record`);
				if (key === 'path') this.nextPath = value;
				else this.nextLink = value;
			} else if (!IGNORED_PAX.has(key)) {
				throw new Error(
					`the archive has a PAX record ${JSON.stringify(key.slice(0, 64))}, which koid does not read`,
				);
			}
		}
	}

	private readEntry(type: string, size: number, header: Buffer): void {
		this.entries += 1;
		if (this.entries > this.limits.entries) {
			throw new Error(`the source has more than ${this.limits.entries} files and directories`);
		}
		const raw = this.nextPath ?? headerName(header);
		const link = this.nextLink ?? field(header, 157, 257);
		this.nextPath = undefined;
		this.nextLink = undefined;
		const directory = type === '5';
		const path = entryPath(raw, directory);
		if (type === '0' || type === '\0' || type === '7') {
			this.bytes += size;
			if (this.bytes > this.limits.bytes) {
				throw new Error(`the source unpacks to more than ${this.limits.bytes} bytes`);
			}
			const mode = octal(header.subarray(100, 108));
			if (mode === undefined) throw new Error(`${quoted(path)} has no octal mode`);
			const hash = createHash('sha1').update(`blob ${size}\0`);
			this.sink = (bytes) => hash.update(bytes);
			this.done = () =>
				this.add(path, {
					kind: 'blob',
					mode: (mode & 0o100) !== 0 ? '100755' : '100644',
					oid: hash.digest(),
				});
			return;
		}
		if ((type === '1' || type === '2' || directory) && size !== 0) {
			throw new Error(`${quoted(path)} is ${KINDS[type]} with data`);
		}
		if (type === '1') {
			const target = this.find(entryPath(link, false));
			if (target?.kind !== 'blob' || target.mode === '120000') {
				throw new Error(
					`${quoted(path)} is a hard link to ${JSON.stringify(link.slice(0, 200))}, which is not a file before it in the archive`,
				);
			}
			this.add(path, target);
			return;
		}
		if (type === '2') {
			if (link === '') throw new Error(`the symlink ${quoted(path)} has no target`);
			const target = Buffer.from(link, 'latin1');
			const oid = createHash('sha1').update(`blob ${target.length}\0`).update(target).digest();
			this.add(path, { kind: 'blob', mode: '120000', oid });
			return;
		}
		if (directory) {
			this.addDirectory(path);
			return;
		}
		throw new Error(
			`${quoted(path)} is ${KINDS[type] ?? `an entry of tar type ${JSON.stringify(type)}`}`,
		);
	}

	private add(path: string[], blob: Blob): void {
		const name = path.at(-1) as string;
		const parent = this.addDirectory(path.slice(0, -1));
		if (parent.children.has(name)) throw new Error(`${quoted(path)} is in the archive twice`);
		parent.children.set(name, blob);
	}

	// What the archive has put at `path` so far.
	private find(path: string[]): Node | undefined {
		let node: Node | undefined = this.root;
		for (const name of path) node = node?.kind === 'tree' ? node.children.get(name) : undefined;
		return node;
	}

	private addDirectory(path: string[]): Tree {
		let node = this.root;
		for (const [i, name] of path.entries()) {
			const next = node.children.get(name);
			if (next?.kind === 'blob') {
				throw new Error(
					`${quoted(path.slice(0, i + 1))} is both a file and a directory in the archive`,
				);
			}
			if (next !== undefined) {
				node = next;
				continue;
			}
			const made: Node = { kind: 'tree', children: new Map() };
			node.children.set(name, made);
			node = made;
		}
		return node;
	}
}

const KINDS: Record<string, string> = {
	'1': 'a hard link',
	'2': 'a symlink',
	'3': 'a character device',
	'4': 'a block device',
	'5': 'a directory',
	'6': 'a fifo',
	S: 'a sparse file',
};

// git's id of the empty tree.
const EMPTY_TREE = Buffer.from('4b825dc642cb6eb9a060e54bf8d69288fbee4904', 'hex');

// git's id of a tree holding `children`, or undefined when no file is under
// it: entries sorted by name as bytes, a directory's name compared as if it
// ended in '/', as git sorts them.
function treeId(children: Map<string, Node>): Buffer | undefined {
	const entries: Array<{ name: string; mode: string; oid: Buffer; key: string }> = [];
	for (const [name, node] of children) {
		if (node.kind === 'blob') {
			entries.push({ name, mode: node.mode, oid: node.oid, key: name });
			continue;
		}
		const oid = treeId(node.children);
		if (oid !== undefined) entries.push({ name, mode: '40000', oid, key: `${name}/` });
	}
	if (entries.length === 0) return undefined;
	entries.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
	const body = Buffer.concat(
		entries.flatMap(({ name, mode, oid }) => [Buffer.from(`${mode} ${name}\0`, 'latin1'), oid]),
	);
	return createHash('sha1').update(`tree ${body.length}\0`).update(body).digest();
}

// A member name as the segments of the path tar unpacks it to. Names are
// bytes, kept one character per byte. A leading "./" is dropped, as tar
// drops it, and a directory's trailing '/'; a directory named "./" or "."
// is the one tar unpacks into, no segments. Anything else that tar would
// read as another path is refused.
function entryPath(raw: string, directory: boolean): string[] {
	if (raw.length > MAX_PATH_BYTES)
		throw new Error(`a path in the archive is over ${MAX_PATH_BYTES} bytes`);
	let name = raw.replace(/^(?:\.\/)+/, '');
	if (directory) name = name.replace(/\/$/, '');
	if (directory && (name === '' || name === '.') && raw !== '') return [];
	const segments = name.split('/');
	if (name === '' || segments.some((s) => s === '' || s === '.' || s === '..')) {
		throw new Error(
			`the archive has a member named ${JSON.stringify(raw.slice(0, 200))}, which is not a plain relative path`,
		);
	}
	return segments;
}

function quoted(path: string[]): string {
	return JSON.stringify(path.join('/').slice(0, 200));
}

// Bytes as a string of one character per byte, so that names compare and
// sort byte for byte and go back into a tree object unchanged.
function bytesText(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('latin1');
}

function field(header: Uint8Array, from: number, to: number): string {
	const bytes = header.subarray(from, to);
	const end = bytes.indexOf(0);
	return bytesText(end === -1 ? bytes : bytes.subarray(0, end));
}

// The name field, after the prefix field and a slash when the header is
// POSIX ustar's and has one. GNU's own format keeps other fields there.
function headerName(header: Uint8Array): string {
	const name = field(header, 0, 100);
	const posix = bytesText(header.subarray(257, 263)) === 'ustar\0';
	const prefix = posix ? field(header, 345, 500) : '';
	return prefix === '' ? name : `${prefix}/${name}`;
}

// The sum of a header's bytes, its checksum field counted as spaces.
function checksum(header: Uint8Array): number {
	let sum = 0;
	for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : (header[i] ?? 0);
	return sum;
}

// A numeric header field: octal digits, which may have spaces before them
// and NULs or spaces after. GNU's base-256 form, for numbers too large for
// the field, is undefined: no source file is that large.
function octal(field: Uint8Array): number | undefined {
	const text = bytesText(field)
		.replace(/^ +/, '')
		.replace(/[\0 ]+$/, '');
	return /^[0-7]{1,12}$/.test(text) ? Number.parseInt(text, 8) : undefined;
}

// PAX records, "LENGTH KEY=VALUE\n" with LENGTH in decimal counting the
// whole record, as [key, value] in order. Throws on a malformed one.
function paxRecords(data: Buffer): Array<[string, string]> {
	const text = bytesText(data);
	const records: Array<[string, string]> = [];
	let at = 0;
	while (at < text.length) {
		const length = /^[1-9][0-9]{0,8} /.exec(text.slice(at, at + 10))?.[0];
		const end = length === undefined ? -1 : at + Number.parseInt(length, 10);
		if (length === undefined || end > text.length || text[end - 1] !== '\n') {
			throw new Error('the archive has a malformed PAX record');
		}
		const record = text.slice(at + length.length, end - 1);
		const equals = record.indexOf('=');
		if (equals < 1) throw new Error('the archive has a malformed PAX record');
		records.push([record.slice(0, equals), record.slice(equals + 1)]);
		at = end;
	}
	return records;
}
