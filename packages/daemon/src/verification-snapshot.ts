import { createHash } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { type FileHandle, lstat, mkdir, open, readdir, rename, rm, stat } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import {
	canonicalDigest,
	type InputSnapshot,
	InputSnapshotSchema,
	KOI_DIR,
	loadVerifyConfig,
	MAX_VERIFY_FILE_BYTES,
	type UpRequest,
	type VerifyConfig,
	VerifyConfigError,
} from '@koi/shared';
import { fsyncDir, PENDING_INPUTS_PREFIX, syncTree, writeAtomic } from './verification-store.ts';

// The input snapshot (docs/verify.md, "Recorder and evidence"): what the
// deployer keeps of a build's verification inputs before it removes the
// build directory, so a plan made later reads the files the build had and
// nothing is ever taken from the running container. Bounded: .koi/ is
// measured before the loader opens anything in it (koiFiles, koiBytes),
// the loader's files at its limit, fixtures at 16 MiB each and 64 MiB
// together, the changed-file list at 1 MiB. Everything is copied by
// reading the file without following a symlink, written 0600 (0700 when the
// file is executable, since a point may run it by its path) under 0700
// directories into a pending directory, and the whole directory is renamed
// into place once snapshot.json, written last, is in it and every directory
// under it is synced (syncTree). A koid killed during the copy leaves that
// directory, and EvidenceStore.sweep removes it. A project without
// verification files gets a snapshot that says so. A built-in recipe is
// recorded by the digest of the files in the copy of its directory
// the build read, taken by the deployer before the build (hashRecipeDir), not
// by its name alone: the request names the recipe, the box supplies it,
// and a change to it must change the snapshot.

export const SNAPSHOT_LIMITS = {
	fixtureBytes: 16 * 1024 ** 2,
	totalBytes: 64 * 1024 ** 2,
	changedFilesBytes: 1024 ** 2,
	// What .koi/ may hold, counted before the loader reads any of it. The
	// loader bounds each file but holds every file it reads, so a tree of
	// thousands of point files would be in memory before the byte bound
	// above could apply.
	koiFiles: 2000,
	koiBytes: 64 * 1024 ** 2,
} as const;

// Where the CLI writes the changed-file list on every build.
export const CHANGED_FILES = '.koi-runtime/changed-files.txt';

// The tree's advisory required policy and proof records, under .koi/.
export const REQUIRED_POLICY = 'required.yaml';
export const PROOFS_DIR = 'proofs';
// The most proof files a snapshot copies; a project has one per required
// point revision, not hundreds.
export const MAX_PROOF_FILES = 200;

export interface SnapshotInput {
	deploymentId: string;
	request: UpRequest;
	// The extracted source tree the build used.
	source: string;
	// The source tarball as uploaded.
	tarball: string;
	// The built-in recipe the build used, when the request named one.
	// Required for a builtin request.
	recipe?: SnapshotRecipe | undefined;
}

// A built-in recipe as the build used it: its installed directory on the
// box, and the digest of each regular file in the copy of it the build
// read (deployer.ts). scripts/deploy-host.sh replaces the installed
// recipes before it restarts the old koid, so the build never reads the
// installed directory itself, and a hash of it could be of a newer recipe
// than the one built.
export interface SnapshotRecipe {
	dir: string;
	files: Record<string, string>;
}

export class SnapshotError extends Error {}

// Takes the snapshot into inputsDir(deploymentId). Throws if one exists.
export async function snapshotInputs(
	inputsDir: string,
	input: SnapshotInput,
	now: () => Date = () => new Date(),
): Promise<InputSnapshot> {
	const final = inputsDir;
	if ((await stat(final).catch(() => undefined)) !== undefined) {
		throw new SnapshotError(`inputs for deployment ${input.deploymentId} exist already`);
	}
	const parent = dirname(final);
	await mkdir(parent, { recursive: true, mode: 0o700 });
	const pending = join(parent, `${PENDING_INPUTS_PREFIX}${input.deploymentId}`);
	await rm(pending, { recursive: true, force: true });
	await mkdir(pending, { recursive: true, mode: 0o700 });
	try {
		const snapshot = await build(pending, input, now);
		await writeAtomic(
			join(pending, 'snapshot.json'),
			`${JSON.stringify(snapshot, null, '\t')}\n`,
			pending,
		);
		await rm(join(pending, 'snapshot.json.tmp'), { force: true });
		// Before the rename: from then on the snapshot counts as whole, and a
		// power cut must not leave snapshot.json without the files it names.
		await syncTree(pending);
		await rename(pending, final);
		await fsyncDir(parent);
		return snapshot;
	} catch (err) {
		await rm(pending, { recursive: true, force: true });
		throw err;
	}
}

async function build(
	pending: string,
	input: SnapshotInput,
	now: () => Date,
): Promise<InputSnapshot> {
	const { request } = input;
	const sourceDir = join(pending, 'source');
	await mkdir(sourceDir, { recursive: true, mode: 0o700 });
	const archive = await hashFile(input.tarball);
	let total = 0;
	// A path can be asked for twice: a fixture a step also names as a runner file
	// is both a loader file and a fixture. It is one file, so it counts once.
	const copied = new Map<string, { digest: string; size: number }>();
	const copy = async (relative: string, max: number): Promise<{ digest: string; size: number }> => {
		const known = copied.get(relative);
		if (known !== undefined) return known;
		const { bytes, executable } = await readFileNoFollow(
			join(input.source, relative),
			relative,
			max,
		);
		total += bytes.length;
		if (total > SNAPSHOT_LIMITS.totalBytes) {
			throw new SnapshotError(
				`the verification inputs are over ${SNAPSHOT_LIMITS.totalBytes} bytes together`,
			);
		}
		const target = join(sourceDir, relative);
		await mkdir(dirname(target), { recursive: true, mode: 0o700 });
		await writeAtomic(target, bytes, pending, executable ? 0o700 : 0o600);
		const result = { digest: sha256(bytes), size: bytes.length };
		copied.set(relative, result);
		return result;
	};

	let changedFiles: InputSnapshot['changedFiles'];
	const changedStat = await lstat(join(input.source, CHANGED_FILES)).catch(() => undefined);
	if (changedStat?.isFile()) {
		const copied = await copy(CHANGED_FILES, SNAPSHOT_LIMITS.changedFilesBytes);
		const text = await readNoFollow(
			join(sourceDir, CHANGED_FILES),
			CHANGED_FILES,
			SNAPSHOT_LIMITS.changedFilesBytes,
		);
		const count = new TextDecoder()
			.decode(text)
			.split('\n')
			.filter((line) => line.trim() !== '').length;
		changedFiles = { file: { path: CHANGED_FILES, ...copied }, count };
	}

	let verify: InputSnapshot['verify'] | undefined;
	let loaded: VerifyConfig | undefined;
	// Before the loader opens anything: what .koi/ holds, so a tree past the
	// bound is refused unread and the snapshot says so.
	const over = await koiOverBound(input.source);
	if (over !== undefined) {
		verify = { status: 'invalid', error: over };
	} else {
		try {
			loaded = await loadVerifyConfig(input.source);
		} catch (err) {
			if (!(err instanceof VerifyConfigError)) throw err;
			// No .koi/ or no manifest is a project without verification files;
			// anything else is a project whose files do not load.
			const missing =
				err.field === undefined &&
				err.message.endsWith(': not found') &&
				(err.file === `${KOI_DIR}/verify.yaml` || err.file === KOI_DIR);
			verify = missing
				? { status: 'absent' }
				: { status: 'invalid', error: err.message.slice(0, 2000) };
		}
	}
	if (loaded !== undefined) {
		// Every file the loader read, as it read it, within the loader's own
		// bound: the loader refused anything larger, so a larger file here
		// changed since.
		for (const path of Object.keys(loaded.digests).sort()) {
			await copy(path, MAX_VERIFY_FILE_BYTES);
		}
		const fixtures: Array<{ path: string; digest: string; size: number }> = [];
		const seen = new Set<string>();
		for (const point of loaded.points) {
			for (const fixture of point.point.requires?.fixtures ?? []) {
				const path = `${KOI_DIR}/${fixture}`;
				if (seen.has(path)) continue;
				seen.add(path);
				fixtures.push({ path, ...(await copy(path, SNAPSHOT_LIMITS.fixtureBytes)) });
			}
		}
		const other: Array<{ path: string; digest: string; size: number }> = [];
		for (const skill of loaded.manifest.skills) {
			const path = `${KOI_DIR}/${skill.path}`;
			if (seen.has(path) || path in loaded.digests) continue;
			seen.add(path);
			other.push({ path, ...(await copy(path, SNAPSHOT_LIMITS.fixtureBytes)) });
		}
		const koiYaml = `${KOI_DIR}/koi.yaml`;
		if ((await lstat(join(input.source, koiYaml)).catch(() => undefined))?.isFile()) {
			other.push({ path: koiYaml, ...(await copy(koiYaml, SNAPSHOT_LIMITS.fixtureBytes)) });
		}
		// The tree's own required policy and proof records, for the planner
		// to show. Advisory: a pull request cannot make its own checks
		// required, so these never decide readiness; the trusted source is
		// the protected base branch, which is later work.
		const required = `${KOI_DIR}/${REQUIRED_POLICY}`;
		if ((await lstat(join(input.source, required)).catch(() => undefined))?.isFile()) {
			other.push({ path: required, ...(await copy(required, MAX_VERIFY_FILE_BYTES)) });
		}
		for (const name of await proofFiles(join(input.source, KOI_DIR, PROOFS_DIR))) {
			const path = `${KOI_DIR}/${PROOFS_DIR}/${name}`;
			other.push({ path, ...(await copy(path, MAX_VERIFY_FILE_BYTES)) });
		}
		// The copy must load as the original did, with the same digests;
		// otherwise a file changed under the copy, and the snapshot is no
		// record of the build.
		const again = await loadVerifyConfig(sourceDir);
		if (JSON.stringify(sortKeys(again.digests)) !== JSON.stringify(sortKeys(loaded.digests))) {
			throw new SnapshotError('the verification files changed while they were copied');
		}
		verify = {
			status: 'present',
			digests: sortKeys(again.digests),
			points: again.points.map((p) => ({
				id: p.point.id,
				revision: p.point.revision,
				path: p.path,
			})),
			fixtures: fixtures.sort((a, b) => (a.path < b.path ? -1 : 1)),
			other: other.sort((a, b) => (a.path < b.path ? -1 : 1)),
		};
	}
	if (verify === undefined) throw new SnapshotError('no verification status');

	return InputSnapshotSchema.parse({
		version: 1,
		deploymentId: input.deploymentId,
		label: request.label,
		request: {
			id: request.id,
			repo: request.repo,
			commit: request.commit,
			branch: request.branch,
			...(request.pr !== undefined ? { pr: request.pr } : {}),
			...(request.merge !== undefined ? { merge: request.merge } : {}),
			dirty: request.dirty,
			createdAt: request.createdAt,
		},
		recipe: recipeIdentity(request, input.recipe),
		source: { archiveDigest: archive.digest, archiveBytes: archive.size },
		...(changedFiles !== undefined ? { changedFiles } : {}),
		verify,
		takenAt: now().toISOString(),
	});
}

// Why .koi/ under `source` is past SNAPSHOT_LIMITS.koiFiles or koiBytes,
// or undefined when it is within them or absent. Counts regular files and
// their sizes without following symlinks or opening anything; the loader
// judges symlinks and each file's size when it reads.
async function koiOverBound(source: string): Promise<string | undefined> {
	const root = join(source, KOI_DIR);
	if (!(await lstat(root).catch(() => undefined))?.isDirectory()) return undefined;
	let files = 0;
	let bytes = 0;
	const walk = async (dir: string): Promise<string | undefined> => {
		for (const entry of await readdir(dir, { withFileTypes: true })) {
			const path = join(dir, entry.name);
			if (entry.isDirectory()) {
				const over = await walk(path);
				if (over !== undefined) return over;
			} else if (entry.isFile()) {
				files += 1;
				bytes += (await lstat(path)).size;
				if (files > SNAPSHOT_LIMITS.koiFiles) {
					return `${KOI_DIR}/ holds more than ${SNAPSHOT_LIMITS.koiFiles} files; koi reads no more than that`;
				}
				if (bytes > SNAPSHOT_LIMITS.koiBytes) {
					return `${KOI_DIR}/ holds more than ${SNAPSHOT_LIMITS.koiBytes} bytes; koi reads no more than that`;
				}
			}
		}
		return undefined;
	};
	return walk(root);
}

// The proof records under `dir`, by name, sorted: regular YAML or JSON
// files only, refused past MAX_PROOF_FILES. Nothing is read here; the copy
// reads each without following a symlink.
export async function proofFiles(dir: string): Promise<string[]> {
	if (!(await lstat(dir).catch(() => undefined))?.isDirectory()) return [];
	const names: string[] = [];
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		if (!entry.isFile() || !/^[A-Za-z0-9][A-Za-z0-9._-]*\.(?:ya?ml|json)$/.test(entry.name))
			continue;
		names.push(entry.name);
	}
	if (names.length > MAX_PROOF_FILES) {
		throw new SnapshotError(
			`${KOI_DIR}/${PROOFS_DIR}/ holds ${names.length} files; koi reads at most ${MAX_PROOF_FILES}`,
		);
	}
	return names.sort();
}

// What the snapshot records of the recipe. A repo recipe is in the request,
// so its digest is over the request's copy. A built-in recipe is the
// daemon's own files, hashed by the deployer from the copy the build read
// (hashRecipeDir): the digest is over the name and those hashes.
function recipeIdentity(
	request: UpRequest,
	recipe: SnapshotRecipe | undefined,
): InputSnapshot['recipe'] {
	if (request.recipe.kind !== 'builtin') {
		return { kind: 'repo', digest: canonicalDigest(request.recipe) };
	}
	if (recipe === undefined) {
		throw new SnapshotError(
			`the built-in recipe ${request.recipe.name} has no file digests; the build did not hash its directory`,
		);
	}
	if (!('recipe.json' in recipe.files)) {
		throw new SnapshotError(`${recipe.dir} has no recipe.json`);
	}
	return {
		kind: 'builtin',
		name: request.recipe.name,
		digest: canonicalDigest({ name: request.recipe.name, files: recipe.files }),
		files: sortKeys(recipe.files),
	};
}

// The most a recipe file may be; a recipe directory holds a Dockerfile and
// scripts, nothing large.
const MAX_RECIPE_FILE_BYTES = 16 * 1024 ** 2;

// Every regular file under a built-in recipe's directory, by path relative
// to it with forward slashes, to its digest. The deployer calls it on the
// copy a build is about to read, so the digests are of those files and no
// others. Symlinks are refused: what they point to is not in the directory
// the daemon trusts.
export async function hashRecipeDir(root: string): Promise<Record<string, string>> {
	const files: Record<string, string> = {};
	const walk = async (dir: string): Promise<void> => {
		for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
			a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
		)) {
			const path = join(dir, entry.name);
			const name = relative(root, path).split('\\').join('/');
			if (entry.isDirectory()) await walk(path);
			else if (entry.isFile()) {
				files[name] = sha256(await readNoFollow(path, name, MAX_RECIPE_FILE_BYTES));
			} else throw new SnapshotError(`${name} in the recipe directory is not a regular file`);
		}
	};
	await walk(root);
	return sortKeys(files);
}

// The bytes of a regular file, opened without following a symlink in its
// last segment, read to `max` and refused past it.
export async function readNoFollow(path: string, name: string, max: number): Promise<Uint8Array> {
	return (await readFileNoFollow(path, name, max)).bytes;
}

// The same, and whether the file's mode lets anyone execute it. The mode comes
// from the descriptor the bytes were read through, so both describe one file.
export async function readFileNoFollow(
	path: string,
	name: string,
	max: number,
): Promise<{ bytes: Uint8Array; executable: boolean }> {
	let handle: FileHandle;
	try {
		handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
	} catch (err) {
		if ((err as { code?: string }).code === 'ELOOP') {
			throw new SnapshotError(`${name} is a symlink`);
		}
		throw new SnapshotError(`${name}: ${err instanceof Error ? err.message : String(err)}`);
	}
	try {
		const info = await handle.stat();
		if (!info.isFile()) throw new SnapshotError(`${name} is not a regular file`);
		if (info.size > max)
			throw new SnapshotError(`${name} is ${info.size} bytes; the most koi keeps is ${max}`);
		const chunks: Buffer[] = [];
		let length = 0;
		for (;;) {
			const buffer = Buffer.alloc(64 * 1024);
			const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
			if (bytesRead === 0) break;
			length += bytesRead;
			if (length > max)
				throw new SnapshotError(`${name} is over ${max} bytes; it grew while koi read it`);
			chunks.push(buffer.subarray(0, bytesRead));
		}
		return { bytes: Buffer.concat(chunks), executable: (info.mode & 0o111) !== 0 };
	} finally {
		await handle.close();
	}
}

function hashFile(path: string): Promise<{ digest: string; size: number }> {
	return new Promise((resolve, reject) => {
		const hash = createHash('sha256');
		let size = 0;
		createReadStream(path)
			.on('data', (chunk: Buffer | string) => {
				const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
				size += bytes.length;
				hash.update(bytes);
			})
			.on('error', reject)
			.on('end', () => resolve({ digest: `sha256:${hash.digest('hex')}`, size }));
	});
}

function sha256(bytes: Uint8Array): string {
	return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function sortKeys(record: Record<string, string>): Record<string, string> {
	return Object.fromEntries(
		Object.entries(record).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
	);
}
