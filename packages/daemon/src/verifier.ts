import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import {
	type Artifact,
	type ArtifactKind,
	DEFAULT_VERIFIER_IMAGE,
	helperName,
	INPUT_VOLUME_PARTS,
	INPUT_VOLUME_ROLE,
	type InputVolumePart,
	inputVolumeName,
	KOI_DIR,
	type Point,
	RECORDER_BROWSER_PORT,
	RUNNER_PROTOCOL_VERSION,
	type RunNetworkRecord,
	type RunnerAck,
	type RunnerEvent,
	RunnerEventSchema,
	SignedSupervisorLineSchema,
	type StepResult,
	type SupervisorLine,
	SupervisorLineSchema,
	stagingName,
} from '@koi/shared';
import supervisorSource from '../../../host/verifier/supervisor.py' with { type: 'text' };
import type { AttachedContainer, Docker, ExitState, Mount, VolumeMount } from './docker.ts';
import { type CallOptions, RecorderDeadlineError } from './recorder.ts';
import type { SecretRegistry } from './redact.ts';
import type { BodyPolicy } from './sanitize.ts';
import type { AssertionReport } from './verdict.ts';
import type { VerificationNetwork } from './verification-network.ts';
import { scrubFields } from './verification-sanitize.ts';
import { readFileNoFollow, SNAPSHOT_LIMITS } from './verification-snapshot.ts';
import { CapExceededError, clockReaches, type RunWriter } from './verification-store.ts';

// The verifier (docs/verify.md, "Writing a runner"): the container a
// point's commands run in, and koid's side of the runner protocol over its
// stdin and stdout. One verifier per point: created from the project's
// runner image, resolved to a digest and checked against the operator's
// allowlist; given the frozen inputs under /workspace and the point's
// fixtures under /fixtures, root-owned and read-only; started with koi's own
// supervisor (host/verifier/supervisor.py, embedded in koid) as its
// entrypoint, whatever the image's; attached without a TTY; and stopped and
// removed when the point ends or reaches its budget. Its output is read from
// the moment it starts, under bounds, whatever the handler is doing
// (OutputReader): a protocol event becomes an assertion report
// or a capture through the recorder, a line of the supervisor's is a
// diagnostic, and anything else is the runner's log. Nothing the runner
// prints is evidence; the recorder's artifacts are.
//
// How the inputs get in. Docker refuses `docker cp` into a container whose
// root is read-only, and the verifier's root must stay read-only, so nothing
// is ever copied into the verifier. Each point gets three Docker volumes,
// one each for /koi, /workspace and /fixtures, filled through a staging
// container made from the same image with the volumes mounted writable and a
// writable root of its own. It is on no network and never started: `docker
// cp` works on a created container, so no code of the image runs. It goes
// before the verifier is created, and the verifier mounts the same volumes
// read-only. Three volumes rather than one with subpaths, since volume
// subpaths need Docker 26. No host directory is involved at any step.

export const SUPERVISOR_PATH = '/koi/supervisor.py';
export const POINT_FILE = '/koi/point.json';
export const WORKSPACE = '/workspace';
export const FIXTURES_DIR = '/fixtures';
// Where each input volume is mounted, and so the top directory of its
// entries in the archive (pointInputs).
const INPUT_PATHS: Record<InputVolumePart, string> = {
	koi: '/koi',
	workspace: WORKSPACE,
	fixtures: FIXTURES_DIR,
};
// The one PATH a verifier gets, whatever the image set. The default image's
// python3 is in /usr/local/bin.
export const VERIFIER_PATH = '/usr/local/bin:/usr/bin:/bin';
export const SUPERVISOR_SOURCE: string = supervisorSource;
// How the supervisor is started: isolated mode ignores PYTHON* variables
// and does not put the script's directory on the import path.
export const SUPERVISOR_COMMAND = ['-I', SUPERVISOR_PATH, POINT_FILE];
export const SUPERVISOR_INTERPRETER = 'python3';

// The bounds on what koid reads from a verifier, from the design's runner
// protocol section. One rule covers them: each is counted as the output arrives,
// and koid never waits while it handles a line. Events over their rate, lines
// that are not protocol lines past their count, bytes past the total, and lines
// past what the queue may hold stop the verifier with runner_protocol_limit.
// Under them, every line is handled at full speed.
//
// There is no rate on bytes. The reader keeps up with a runner whatever it
// writes, so a wait on the handler's side would slow koid and nothing else, and
// a runner that had finished in time would run out of time on koid's account.
// The total, the queue and the cap on log lines kept already bound what a runner
// can make koid hold and write.
//
// queueBytes is the total, so a runner under the total reaches it only through
// the cost of each line (LINE_COST): 8 MiB of empty lines would be half a gigabyte
// of queue otherwise.
export const PROTOCOL_LIMITS = {
	lineBytes: 8 * 1024,
	bytesPerPoint: 8 * 1024 ** 2,
	queueBytes: 8 * 1024 ** 2,
	eventsPerSecond: 50,
	eventsBurst: 100,
	malformedPerPoint: 100,
	capturesPerPoint: 200,
	// Runner log lines kept as events per point; the rest are counted.
	logLinesPerPoint: 2000,
	// The body a runner's read keeps, scrubbed; a longer one is omitted.
	readBodyBytes: 64 * 1024,
} as const;

export type ProtocolLimits = { -readonly [K in keyof typeof PROTOCOL_LIMITS]: number };

// Seconds past the point's budget before koid stops the container itself:
// the supervisor's own SIGTERM grace, and time for its exit line.
const STOP_GRACE_SECONDS = 15;
// The least koid may go on handling what a verifier wrote after it exited, past
// the time the point had anyway. The runner has finished by then, so this is
// koid's time, and a point that reaches its end is blocked with a reason of its
// own and not point_timeout. It has to end, or a stuck capture would hold the
// point open. A recorder call gives up after 30 seconds of its own, so a slow one
// still leaves time for the lines behind it.
const HANDLING_MS = 60_000;
// How long a verifier may take to stop and go once its point has ended, before
// the point's account is settled without it and the run stops. Each Docker command
// in that has a timeout of its own, and all of them timing out would take over
// three minutes; the lease has only the teardown's two minutes past the run's
// deadline.
const CLEANUP_MS = 60_000;
// What a run gives a verifier past CLEANUP_MS before it stops waiting for it
// altogether, for the last records to be written (verifierStopBy).
const SETTLE_MS = 30_000;
// Why a run ends when a verifier did not.
export const VERIFIER_STUCK =
	'verifier_stuck: the verifier was still not gone well after its point ended, so the run stopped waiting for it';
// How long the output streams may stay silent, without ending, once the
// container has exited. What is left by then is unread, which fails the point.
const DRAIN_MS = 5_000;
// `docker start --attach` is up before the container is: how often koid looks,
// and how many times, before it gives up on the container running.
const RUNNING_POLL_MS = 100;
const RUNNING_POLLS = 300;
// The most of a runner's text one event keeps.
const MAX_TEXT = 2000;
// The most evidence references one assertion may cite.
const MAX_REFS = 100;
// stderr lines kept for the reason a verifier gave nothing.
const STDERR_TAIL = 5;
// What holding one line costs beyond its text, as OutputReader counts it: the
// queue's object and the string's header, measured at 60 to 115 bytes in Bun.
const LINE_COST = 128;

// -- Image policy --------------------------------------------------------------

// Environment names an image may declare. The supervisor passes its own
// allowlist (CHILD_ENV in supervisor.py) to the steps and nothing else, so
// an image's environment never reaches a runner; this check refuses an
// image that would have set something a runtime does not need, such as a
// proxy, before it is created at all.
export const IMAGE_ENV_ALLOWLIST: ReadonlySet<string> = new Set([
	'PATH',
	'HOME',
	'LANG',
	'LC_ALL',
	'TZ',
	'TMPDIR',
	'GPG_KEY',
	'PYTHON_VERSION',
	'PYTHON_SHA256',
	'PYTHONDONTWRITEBYTECODE',
	'PYTHONUNBUFFERED',
	'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD',
	'PLAYWRIGHT_BROWSERS_PATH',
	'NODE_VERSION',
	'NODE_ENV',
	'YARN_VERSION',
]);

// The names in an image's environment that are not on the allowlist.
export function imageEnvProblems(env: string[]): string[] {
	const names = env.map((entry) => entry.split('=')[0] ?? entry);
	return [...new Set(names.filter((name) => !IMAGE_ENV_ALLOWLIST.has(name)))].sort();
}

export interface ImagePolicy {
	// The id of the box's default verifier image (KOI_VERIFIER_IMAGE).
	defaultImageId: string;
	// References or digests a manifest may name besides it (KOI_VERIFIER_IMAGES).
	allowed: readonly string[];
}

export type ImageResolution = { ok: true; digest: string } | { ok: false; reason: string };

// How a reason from resolveRunnerImage starts. What follows can quote what Docker says of
// an image, so a plan keeps these as runtime text (Verification.makePlan).
export const IMAGE_REASONS = [
	'verifier_unavailable:',
	'image_missing:',
	'image_not_allowed:',
	'image_env_not_allowed:',
] as const;

// The runner image a manifest names, as the image on the box it resolves
// to, or why no point may run in it. koid never pulls: an image a pull
// request names is one the operator put on the box and on the allowlist,
// or the default. A mutable tag is a lookup input; the digest is what runs.
export async function resolveRunnerImage(
	docker: Pick<Docker, 'imageInfo'>,
	reference: string,
	policy: ImagePolicy,
): Promise<ImageResolution> {
	if (reference === DEFAULT_VERIFIER_IMAGE) {
		const info = await docker.imageInfo(policy.defaultImageId);
		if (info === undefined) {
			return {
				ok: false,
				reason: `verifier_unavailable: the default verifier image ${policy.defaultImageId} is not on the box`,
			};
		}
		const problems = imageEnvProblems(info.env);
		if (problems.length > 0) {
			return {
				ok: false,
				reason: `image_env_not_allowed: the default verifier image declares ${problems.join(', ')}`,
			};
		}
		return { ok: true, digest: info.id };
	}
	const info = await docker.imageInfo(reference);
	if (info === undefined) {
		return {
			ok: false,
			reason: `image_missing: ${reference} is not on the box; koid never pulls an image a pull request names`,
		};
	}
	let allowed = info.id === policy.defaultImageId || policy.allowed.includes(reference);
	if (!allowed) {
		for (const entry of policy.allowed) {
			if (entry.startsWith('sha256:')) {
				if (entry === info.id) allowed = true;
			} else if (entry.includes('@sha256:')) {
				// A pinned reference on the list: allowed when it names the same
				// image on the box.
				if ((await docker.imageInfo(entry))?.id === info.id) allowed = true;
			}
			if (allowed) break;
		}
	}
	if (!allowed) {
		return {
			ok: false,
			reason: `image_not_allowed: ${reference} (${info.id}) is not on this host's allowlist (KOI_VERIFIER_IMAGES)`,
		};
	}
	const problems = imageEnvProblems(info.env);
	if (problems.length > 0) {
		return {
			ok: false,
			reason: `image_env_not_allowed: ${reference} declares ${problems.join(', ')}, which a runner image may not set`,
		};
	}
	return { ok: true, digest: info.id };
}

// -- Environment ---------------------------------------------------------------

export interface VerifierEnvInput {
	runId: string;
	pointId: string;
	attempt: number;
	previewUrl: string;
	recorderIp: string;
	browserToken: string;
	// Fixture path under .koi/ to its path in the container.
	fixtures: Record<string, string>;
	timeoutSeconds: number;
	maxRequests: number;
	// Present only when policy grants it; no policy does yet.
	loginKey?: string | undefined;
}

// Exactly the verifier's environment, from the design's table: fixed
// runtime values, the point's identity and limits, where the app and the
// recorder are, and the fixtures. Nothing of the daemon's or the app's.
export function verifierEnv(input: VerifierEnvInput): Record<string, string> {
	return {
		PATH: VERIFIER_PATH,
		HOME: '/tmp/home',
		TMPDIR: '/tmp',
		LANG: 'C.UTF-8',
		TZ: 'UTC',
		KOI_PROTOCOL_VERSION: String(RUNNER_PROTOCOL_VERSION),
		KOI_RUN_ID: input.runId,
		KOI_POINT_ID: input.pointId,
		KOI_ATTEMPT: String(input.attempt),
		KOI_PREVIEW_URL: input.previewUrl,
		KOI_RECORDER_WS: `ws://${input.recorderIp}:${RECORDER_BROWSER_PORT}/${input.browserToken}`,
		KOI_FIXTURES: JSON.stringify(input.fixtures),
		KOI_TIMEOUT_SECONDS: String(input.timeoutSeconds),
		KOI_MAX_REQUESTS: String(input.maxRequests),
		...(input.loginKey !== undefined ? { KOI_LOGIN_KEY: input.loginKey } : {}),
	};
}

// -- The tar stream ------------------------------------------------------------

export interface TarEntry {
	// Relative, with forward slashes and no leading slash.
	path: string;
	type: 'file' | 'dir';
	mode: number;
	content?: Uint8Array;
}

const BLOCK = 512;
const encoder = new TextEncoder();

function octal(n: number, width: number): string {
	return `${n.toString(8).padStart(width - 1, '0')}\0`;
}

function put(block: Uint8Array, at: number, text: string, width: number): void {
	const bytes = encoder.encode(text);
	block.set(bytes.subarray(0, width), at);
}

function header(name: string, prefix: string, type: '0' | '5' | 'x', mode: number, size: number) {
	const block = new Uint8Array(BLOCK);
	put(block, 0, name, 100);
	put(block, 100, octal(mode, 8), 8);
	put(block, 108, octal(0, 8), 8);
	put(block, 116, octal(0, 8), 8);
	put(block, 124, octal(size, 12), 12);
	put(block, 136, octal(0, 12), 12);
	put(block, 148, '        ', 8);
	put(block, 156, type, 1);
	put(block, 257, 'ustar\0', 6);
	put(block, 263, '00', 2);
	put(block, 265, 'root', 32);
	put(block, 297, 'root', 32);
	put(block, 329, octal(0, 8), 8);
	put(block, 337, octal(0, 8), 8);
	put(block, 345, prefix, 155);
	let sum = 0;
	for (const b of block) sum += b;
	put(block, 148, `${sum.toString(8).padStart(6, '0')}\0 `, 8);
	return block;
}

function padded(content: Uint8Array): Uint8Array {
	const rest = content.length % BLOCK;
	if (rest === 0) return content;
	const out = new Uint8Array(content.length + BLOCK - rest);
	out.set(content);
	return out;
}

// A name as a ustar header holds it: whole when it fits, else split at a
// slash into prefix and name, else a PAX record carries it.
function nameFields(path: string): { name: string; prefix: string; pax?: string } {
	if (encoder.encode(path).length <= 100) return { name: path, prefix: '' };
	for (let i = path.length - 1; i > 0; i--) {
		if (path[i] !== '/') continue;
		const prefix = path.slice(0, i);
		const name = path.slice(i + 1);
		if (name !== '' && encoder.encode(prefix).length <= 155 && encoder.encode(name).length <= 100) {
			return { name, prefix };
		}
	}
	return { name: path.slice(0, 100), prefix: '', pax: path };
}

function paxRecord(key: string, value: string): Uint8Array {
	const body = ` ${key}=${value}\n`;
	let length = encoder.encode(body).length;
	for (;;) {
		const total = String(length).length + encoder.encode(body).length;
		if (total === length) break;
		length = total;
	}
	return encoder.encode(`${length}${body}`);
}

// A tar archive of the entries, in the order given, uid and gid 0, every
// time zero, so the same inputs make the same bytes. Each file's content
// is given; a directory has none. Docker extracts it at the staging
// container's root (Docker.copyIn), so each top directory lands in its
// volume.
export function tarball(entries: TarEntry[]): Uint8Array {
	const blocks: Uint8Array[] = [];
	for (const entry of entries) {
		if (entry.path.startsWith('/') || entry.path.includes('\\') || entry.path.includes('\0')) {
			throw new Error(`tar entry ${JSON.stringify(entry.path)} is not a relative path`);
		}
		if (entry.path.split('/').some((segment) => segment === '' || segment === '..')) {
			throw new Error(`tar entry ${JSON.stringify(entry.path)} has an empty or .. segment`);
		}
		const path = entry.type === 'dir' ? `${entry.path}/` : entry.path;
		const fields = nameFields(path);
		if (fields.pax !== undefined) {
			const record = paxRecord('path', fields.pax);
			blocks.push(header(`PaxHeader/${fields.name}`.slice(0, 100), '', 'x', 0o644, record.length));
			blocks.push(padded(record));
		}
		const content = entry.type === 'file' ? (entry.content ?? new Uint8Array(0)) : undefined;
		blocks.push(
			header(
				fields.name,
				fields.prefix,
				entry.type === 'dir' ? '5' : '0',
				entry.mode,
				content?.length ?? 0,
			),
		);
		if (content !== undefined && content.length > 0) blocks.push(padded(content));
	}
	blocks.push(new Uint8Array(BLOCK * 2));
	let size = 0;
	for (const b of blocks) size += b.length;
	const out = new Uint8Array(size);
	let at = 0;
	for (const b of blocks) {
		out.set(b, at);
		at += b.length;
	}
	return out;
}

// -- Inputs ----------------------------------------------------------------------

export interface PointInputs {
	// The input snapshot's source directory (verification-snapshot.ts).
	source: string;
	// The snapshot's fixture records, by path from the source root.
	fixtures: Array<{ path: string; digest: string }>;
	point: Point;
	runnerCommand: string[] | undefined;
	timeoutSeconds: number;
}

// What is wrong with a point's inputs, as the point's blocked reason.
export class InputsError extends Error {
	constructor(
		readonly code: string,
		detail: string,
	) {
		super(`${code}: ${detail}`);
	}
}

// The modes the verifier sees: root-owned, readable, not writable by anyone,
// so a runner cannot change its own inputs. A file keeps its executable bit,
// since a point's command may name a script by its path.
const DIR_MODE = 0o555;
const FILE_MODE = 0o444;
const EXECUTABLE_MODE = 0o555;

// What the verifier's input volumes hold: the supervisor and the point file
// under /koi, the whole snapshot under /workspace, and the point's fixtures
// under /fixtures, checked against the snapshot's digests. Each top
// directory is an entry even when empty, so its mode reaches the volume's
// root. Returns the archive, the fixture map KOI_FIXTURES carries, and the bytes
// of the unique input files, which is what SNAPSHOT_LIMITS.totalBytes holds.
//
// A fixture is a file of the snapshot, so it is in /workspace too. It counts once
// against the limit a deployment's snapshot already passed, or a valid snapshot
// could not run. What bounds the disk is then this: /workspace holds at most
// totalBytes, /fixtures holds only copies of its files, each once however often a
// point lists it, and /koi holds two small files. So the volumes and the archive
// in memory take at most twice totalBytes, plus tar's headers, and a run has one
// verifier at a time, whose volumes go before the next is filled.
export async function pointInputs(
	inputs: PointInputs,
): Promise<{ tar: Uint8Array; fixtures: Record<string, string>; bytes: number }> {
	const entries: TarEntry[] = [];
	const dirs = new Set<string>();
	const dir = (path: string) => {
		if (dirs.has(path)) return;
		const slash = path.lastIndexOf('/');
		if (slash > 0) dir(path.slice(0, slash));
		dirs.add(path);
		entries.push({ path, type: 'dir', mode: DIR_MODE });
	};
	const file = (path: string, content: Uint8Array, executable = false) => {
		dir(path.slice(0, path.lastIndexOf('/')));
		entries.push({ path, type: 'file', mode: executable ? EXECUTABLE_MODE : FILE_MODE, content });
	};
	let bytes = 0;
	const count = (n: number) => {
		bytes += n;
		if (bytes > SNAPSHOT_LIMITS.totalBytes) {
			throw new InputsError(
				'inputs_too_large',
				`the point's inputs are over ${SNAPSHOT_LIMITS.totalBytes} bytes together`,
			);
		}
	};

	const { point } = inputs;
	const pointFile = {
		version: RUNNER_PROTOCOL_VERSION,
		runner: inputs.runnerCommand ?? null,
		steps: {
			setup: point.setup?.command ?? null,
			run: point.run.command,
			cleanup: point.cleanup?.command ?? null,
		},
		timeoutSeconds: inputs.timeoutSeconds,
	};
	file(SUPERVISOR_PATH.slice(1), encoder.encode(SUPERVISOR_SOURCE));
	file(POINT_FILE.slice(1), encoder.encode(`${JSON.stringify(pointFile)}\n`));

	dir(WORKSPACE.slice(1));
	const read = new Map<string, { bytes: Uint8Array; executable: boolean }>();
	for (const relative of await listTree(inputs.source)) {
		const found = await readFileNoFollow(
			join(inputs.source, relative),
			relative,
			SNAPSHOT_LIMITS.fixtureBytes,
		);
		count(found.bytes.length);
		read.set(relative, found);
		file(`${WORKSPACE.slice(1)}/${relative}`, found.bytes, found.executable);
	}

	dir(FIXTURES_DIR.slice(1));
	const fixtures: Record<string, string> = {};
	for (const fixture of new Set(point.requires?.fixtures ?? [])) {
		const path = `${KOI_DIR}/${fixture}`;
		const recorded = inputs.fixtures.find((f) => f.path === path);
		const found = read.get(path);
		if (recorded === undefined || found === undefined) {
			throw new InputsError('fixture_missing', `${path} is not in the input snapshot`);
		}
		if (sha256(found.bytes) !== recorded.digest) {
			throw new InputsError(
				'fixture_mismatch',
				`${path} is not the file the input snapshot recorded`,
			);
		}
		file(`${FIXTURES_DIR.slice(1)}/${fixture}`, found.bytes, found.executable);
		fixtures[fixture] = `${FIXTURES_DIR}/${fixture}`;
	}
	return { tar: tarball(entries), fixtures, bytes };
}

// Every regular file under dir, by path relative to it, sorted. The
// snapshot holds no symlink; one found here is refused.
async function listTree(dir: string): Promise<string[]> {
	const files: string[] = [];
	const walk = async (relative: string): Promise<void> => {
		const entries = await readdir(join(dir, relative), { withFileTypes: true });
		for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
			const path = relative === '' ? entry.name : `${relative}/${entry.name}`;
			if (entry.isSymbolicLink()) {
				throw new InputsError('inputs_invalid', `${path} in the input snapshot is a symlink`);
			}
			if (entry.isDirectory()) await walk(path);
			else if (entry.isFile()) files.push(path);
		}
	};
	await walk('');
	return files;
}

function sha256(bytes: Uint8Array): string {
	return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

// The volumes of a run's verifier, by name and where each is mounted.
export function inputVolumes(runId: string): VolumeMount[] {
	return INPUT_VOLUME_PARTS.map((part) => ({
		name: inputVolumeName(runId, part),
		destination: INPUT_PATHS[part],
	}));
}

// Every way a verifier's mounts differ from its input volumes, read-only at
// their paths: a mount an image declared, one of the volumes writable or
// elsewhere, or one missing. Empty when they are what koid asked for.
export function mountProblems(mounts: Mount[], volumes: VolumeMount[]): string[] {
	const problems: string[] = [];
	const wanted = (m: Mount) =>
		m.type === 'volume' &&
		m.readOnly === true &&
		volumes.some((v) => v.name === m.name && v.destination === m.destination);
	const extra = mounts.filter((m) => !wanted(m));
	if (extra.length > 0) {
		problems.push(
			`has mounts koi did not ask for: ${extra.map((m) => `${m.type} at ${m.destination}`).join(', ')}`,
		);
	}
	const absent = volumes.filter(
		(v) => !mounts.some((m) => m.name === v.name && m.destination === v.destination && wanted(m)),
	);
	if (absent.length > 0) {
		problems.push(`lacks its input volumes at ${absent.map((v) => v.destination).join(', ')}`);
	}
	return problems;
}

// -- Reading the protocol ----------------------------------------------------

export type Classified =
	| { kind: 'event'; event: RunnerEvent }
	// Signed with the point's key, with the number it carried.
	| { kind: 'supervisor'; line: SupervisorLine; seq: number }
	| { kind: 'log'; text: string }
	// Not a protocol line, though it tried to be: counted, and recorded as
	// a fixed diagnostic, never as an event.
	| { kind: 'malformed'; reason: string };

const MAC_FIELD = ',"mac":"';

// Whether a line ends in the MAC the key gives the text before it, as
// supervisor.py signs it. koid checks the bytes it read, so no canonical form
// is needed on either side.
function signedWith(line: string, key: string): boolean {
	const at = line.lastIndexOf(MAC_FIELD);
	if (at < 0 || !line.endsWith('"}')) return false;
	const given = Buffer.from(line.slice(at + MAC_FIELD.length, -2));
	const expected = Buffer.from(createHmac('sha256', key).update(line.slice(0, at)).digest('hex'));
	return given.length === expected.length && timingSafeEqual(given, expected);
}

// One complete line of the verifier's stdout, as the protocol reads it. A
// line that does not start with a brace is the runner's log. A JSON object
// is a supervisor line, a runner event, or malformed: unknown type, unknown
// field, wrong shape. A line that says it is the supervisor's is believed only
// when signed with the point's key, which no runner holds (supervisor.py says
// why it cannot get it). Nothing is repaired.
export function classifyLine(text: string, key: string): Classified {
	const trimmed = text.replace(/\r$/, '');
	if (!trimmed.startsWith('{')) return { kind: 'log', text: trimmed };
	let data: unknown;
	try {
		data = JSON.parse(trimmed);
	} catch {
		return { kind: 'malformed', reason: 'a line that starts with a brace is not JSON' };
	}
	if (typeof data !== 'object' || data === null || Array.isArray(data)) {
		return { kind: 'malformed', reason: 'a JSON line that is not an object' };
	}
	if ('type' in data && data.type === 'supervisor') {
		if (!signedWith(trimmed, key)) {
			return { kind: 'malformed', reason: "a supervisor line without the point's signature" };
		}
		const signed = SignedSupervisorLineSchema.safeParse(data);
		const { seq, mac: _mac, ...fields } = signed.data ?? {};
		const line = SupervisorLineSchema.safeParse(fields);
		if (!line.success || seq === undefined) {
			return { kind: 'malformed', reason: 'a supervisor line of the wrong shape' };
		}
		return { kind: 'supervisor', line: line.data, seq };
	}
	const event = RunnerEventSchema.safeParse(data);
	if (!event.success) {
		const issue = event.error.issues[0];
		const field = issue?.path.map(String).join('.') ?? '';
		return {
			kind: 'malformed',
			reason: `an event the protocol does not read${field === '' ? '' : ` (${field})`}`,
		};
	}
	return { kind: 'event', event: event.data };
}

export type SplitLine = { text: string } | { discarded: true };

// Splits a byte stream into lines under a length bound. A line past the
// bound is discarded whole, from its first byte to its newline, and
// reported once; its content is never kept, since a cut could keep most of
// a secret. It holds at most the bound between calls, however long the line.
export class LineSplitter {
	private pending = '';
	private discarding = false;
	private readonly decoder = new TextDecoder();

	constructor(private readonly maxBytes: number) {}

	push(chunk: Uint8Array): SplitLine[] {
		const out: SplitLine[] = [];
		const text = this.decoder.decode(chunk, { stream: true });
		const parts = (this.pending + text).split('\n');
		this.pending = parts.pop() ?? '';
		for (const line of parts) {
			if (this.discarding) {
				this.discarding = false;
				continue;
			}
			if (Buffer.byteLength(line, 'utf8') > this.maxBytes) out.push({ discarded: true });
			else out.push({ text: line });
		}
		// Nothing of a discarded line is kept, or a line with no end would grow
		// here until the total stopped it.
		if (this.discarding) {
			this.pending = '';
		} else if (Buffer.byteLength(this.pending, 'utf8') > this.maxBytes) {
			this.discarding = true;
			this.pending = '';
			out.push({ discarded: true });
		}
		return out;
	}

	// The last line, without a newline, when the stream ends.
	end(): SplitLine[] {
		const tail = this.pending + this.decoder.decode();
		this.pending = '';
		if (this.discarding) {
			this.discarding = false;
			return [];
		}
		if (tail === '') return [];
		if (Buffer.byteLength(tail, 'utf8') > this.maxBytes) return [{ discarded: true }];
		return [{ text: tail }];
	}
}

// The bounds on one point's output: the total, a token bucket for events, and
// the count of lines that were not protocol lines. Over any of them the point
// stops. The reader counts all of them as the output arrives, so how long koid
// takes to handle a line changes none of them.
export class ProtocolBudget {
	private total = 0;
	private eventTokens: number;
	private lastEvents: number;
	private malformedCount = 0;
	readonly limits: ProtocolLimits;

	constructor(
		limits: Partial<ProtocolLimits>,
		private readonly now: () => number,
	) {
		this.limits = { ...PROTOCOL_LIMITS, ...limits };
		this.eventTokens = this.limits.eventsBurst;
		this.lastEvents = now();
	}

	get bytes(): number {
		return this.total;
	}

	get malformed(): number {
		return this.malformedCount;
	}

	// Counts `n` bytes read. Over the total, the reason the point must stop.
	countBytes(n: number): string | undefined {
		this.total += n;
		if (this.total <= this.limits.bytesPerPoint) return undefined;
		return `the runner wrote more than ${this.limits.bytesPerPoint} bytes`;
	}

	// Counts one event. Over the rate, the reason the point must stop.
	countEvent(): string | undefined {
		const at = this.now();
		this.eventTokens = Math.min(
			this.limits.eventsBurst,
			this.eventTokens + ((at - this.lastEvents) / 1000) * this.limits.eventsPerSecond,
		);
		this.lastEvents = at;
		this.eventTokens -= 1;
		if (this.eventTokens >= 0) return undefined;
		return `the runner sent more than ${this.limits.eventsPerSecond} events per second`;
	}

	// Counts one line that was not a protocol line. Over the count, the
	// reason the point must stop.
	countMalformed(): string | undefined {
		this.malformedCount += 1;
		if (this.malformedCount <= this.limits.malformedPerPoint) return undefined;
		return `the runner printed more than ${this.limits.malformedPerPoint} lines that look like protocol lines and are not`;
	}
}

export type OutputStream = 'stdout' | 'stderr';

// One thing read from a verifier, in the order read: a line of a stream, with
// the bytes it took, or a stream's end. `failed` is a stream that broke, not one
// that ended: what it held is unread.
export type OutputItem =
	| { kind: 'line'; stream: OutputStream; line: SplitLine; bytes: number }
	| { kind: 'end'; stream: OutputStream; failed: boolean };

// Reads a verifier's two output streams for as long as the attachment lasts,
// whatever the event handler is doing, and enforces the bounds on what it read.
//
// What bounds koid's memory is this loop and not the kernel pipe. Bun reads a
// spawned process's pipe into memory for as long as no reader holds the stream:
// a child can write gigabytes that way before anyone reads a byte. So the
// reader takes both streams in the same tick as the spawn (attach, then this
// constructor, with no await between them that lets the event loop read), and
// always has a read out from then on, so nothing waits in Bun. What it read
// is held in three places, and only these:
//
// - the queue, at most `queueBytes`, counting each line's UTF-8 length (which is
//   never less than its string takes in memory) plus LINE_COST. A line that would
//   pass the bound is not kept, and the point stops.
// - each stream's LineSplitter, at most `lineBytes` of an unfinished line.
// - the chunk in hand, which Bun sizes (under 1 MiB in practice) and which goes
//   as soon as it is split.
//
// Once the point stops, it goes on reading until the attachment ends and keeps
// nothing: `docker stop` can take 10 seconds, and a runner that ignores SIGTERM
// goes on writing through them.
export class OutputReader {
	// A queue in two stacks, so a long one costs no shifting: lines go on
	// `incoming`, and `outgoing` holds them reversed.
	private incoming: OutputItem[] = [];
	private outgoing: OutputItem[] = [];
	private readonly cancels: Array<() => Promise<void>> = [];
	private queued = 0;
	private peak = 0;
	private holding = true;
	private arrived: PromiseWithResolvers<void> | undefined;
	// When a stream last gave anything, on the clock given.
	lastReadAt = 0;

	constructor(
		attached: Pick<AttachedContainer, 'stdout' | 'stderr'>,
		private readonly budget: Pick<ProtocolBudget, 'countBytes' | 'limits'>,
		private readonly now: () => number,
		signal: AbortSignal,
		// A bound was passed. Called once, from the reading loop, however busy the
		// handler is, and nothing is kept after it.
		private readonly onLimit: (why: string) => void,
		// Counts one complete line as it arrives. Over a bound, why the point stops.
		private readonly countLine: (stream: OutputStream, line: SplitLine) => string | undefined,
	) {
		if (signal.aborted) this.holding = false;
		else signal.addEventListener('abort', () => this.stopHolding(), { once: true });
		void this.pump('stdout', attached.stdout);
		void this.pump('stderr', attached.stderr);
	}

	// The most this has held at once, as the bound counts it.
	get peakBytes(): number {
		return this.peak;
	}

	// The next item, or undefined when none is waiting.
	next(): OutputItem | undefined {
		if (this.outgoing.length === 0) {
			this.outgoing = this.incoming.reverse();
			this.incoming = [];
		}
		const item = this.outgoing.pop();
		if (item?.kind === 'line') this.queued -= item.bytes + LINE_COST;
		return item;
	}

	// Resolves when something is waiting that was not before.
	arrival(): Promise<void> {
		this.arrived ??= Promise.withResolvers<void>();
		return this.arrived.promise;
	}

	// From now on nothing read is kept. What is queued stays until drain().
	stopHolding(): void {
		this.holding = false;
	}

	// Everything still queued, which leaves the queue empty.
	drain(): OutputItem[] {
		const rest: OutputItem[] = [];
		for (let item = this.next(); item !== undefined; item = this.next()) rest.push(item);
		return rest;
	}

	// Lets go of the streams. Reading ends here even when a stream never does.
	close(): void {
		this.holding = false;
		for (const cancel of this.cancels) cancel().catch(() => {});
	}

	private async pump(stream: OutputStream, source: ReadableStream<Uint8Array>): Promise<void> {
		const reader = source.getReader();
		this.cancels.push(() => reader.cancel());
		const splitter = new LineSplitter(this.budget.limits.lineBytes);
		let failed = false;
		try {
			for (;;) {
				const { done, value } = await reader.read();
				if (done || value === undefined) break;
				this.lastReadAt = this.now();
				if (!this.holding) continue;
				const over = this.budget.countBytes(value.length);
				if (over !== undefined) this.limit(over);
				else for (const line of splitter.push(value)) this.hold(stream, line);
			}
		} catch {
			failed = true;
		}
		for (const line of splitter.end()) this.hold(stream, line);
		this.push({ kind: 'end', stream, failed });
	}

	private hold(stream: OutputStream, line: SplitLine): void {
		if (!this.holding) return;
		const over = this.countLine(stream, line);
		if (over !== undefined) {
			this.limit(over);
			return;
		}
		const bytes = 'text' in line ? Buffer.byteLength(line.text, 'utf8') + 1 : 0;
		const cost = bytes + LINE_COST;
		const { queueBytes } = this.budget.limits;
		if (this.queued + cost > queueBytes) {
			this.limit(`the runner's output outran koid: over ${queueBytes} bytes waited to be handled`);
			return;
		}
		this.queued += cost;
		this.peak = Math.max(this.peak, this.queued);
		this.push({ kind: 'line', stream, line, bytes });
	}

	private push(item: OutputItem): void {
		this.incoming.push(item);
		this.arrived?.resolve();
		this.arrived = undefined;
	}

	private limit(why: string): void {
		if (!this.holding) return;
		this.holding = false;
		this.onLimit(why);
	}
}

// The supervisor's exit code for its exit line, as supervisor.py computes
// it: the worst step. koid compares it with the container's exit code.
export function supervisorExitCode(line: Extract<SupervisorLine, { event: 'exit' }>): number {
	if (line.steps.length === 0) return line.status === 'failed' ? 3 : 4;
	let code = 0;
	for (const step of line.steps) {
		if (step.status === 'timeout') code = Math.max(code, 2);
		else if (step.status === 'failed') code = Math.max(code, 3);
		else if (step.status === 'signalled' || step.status === 'skipped' || (step.code ?? 0) !== 0) {
			code = Math.max(code, 1);
		}
	}
	return code;
}

// The latest a verifier's run should return: the last the watchdog can stop the
// point, which is a runner that exits at the end of its stop grace and whose
// output then takes all of koid's handling time, and then what its cleanup and
// its last records may take. The run's deadline ends everything sooner.
export function verifierStopBy(pointDeadline: number, deadline: number): number {
	const stopped = pointDeadline + STOP_GRACE_SECONDS * 1000 + HANDLING_MS;
	return Math.min(deadline, stopped) + CLEANUP_MS + SETTLE_MS;
}

// -- Running a point -------------------------------------------------------------

export interface VerifierDeps {
	docker: Pick<
		Docker,
		| 'createVerifier'
		| 'createVolume'
		| 'removeVolume'
		| 'createStaging'
		| 'remove'
		| 'mounts'
		| 'copyIn'
		| 'attach'
		| 'inspect'
		| 'stop'
		| 'exitState'
	>;
	network: Pick<VerificationNetwork, 'reapply'>;
	secrets: SecretRegistry;
	now: () => Date;
	sleep: (ms: number) => Promise<void>;
	log: (message: string) => void;
	// How often the watchdog looks at the budget and for a stop request, and
	// the longest the reader waits before it looks at the drain's limit.
	pollMs?: number | undefined;
	limits?: Partial<ProtocolLimits> | undefined;
}

// The recorder, as the point's captures and reads go through it
// (RecorderSession). The signal ends the call at the point's end.
export interface PointRecorder {
	capture(request: { kind: ArtifactKind; label: string }, options?: CallOptions): Promise<Artifact>;
	read(
		request: {
			path: string;
			method?: 'GET' | 'HEAD' | undefined;
			body: BodyPolicy;
		},
		options?: CallOptions,
	): Promise<Artifact>;
}

export interface PointExecution {
	runId: string;
	pointId: string;
	attempt: number;
	point: Point;
	runnerCommand: string[] | undefined;
	// The image by digest, resolved and allowed.
	image: string;
	record: RunNetworkRecord;
	browserToken: string;
	source: string;
	fixtures: Array<{ path: string; digest: string }>;
	// The point's budget as its reasons name it.
	timeoutSeconds: number;
	maxRequests: number;
	loginKey?: string | undefined;
	// When the point's budget ends, as epoch milliseconds. It started before the
	// recorder opened the point's context, so what is left here is less than
	// timeoutSeconds. The supervisor's budget and the watchdog both come from
	// this, so they end with the recorder's calls and not after them.
	pointDeadline: number;
	// When the run itself ends, in the same terms: the point stops at the earlier
	// of this and its own budget.
	deadline: number;
}

export interface PointRun {
	reports: AssertionReport[];
	// Capture and read labels to the artifact each gave, for the aliases a
	// runner may cite.
	artifacts: Record<string, string>;
	// The supervisor's last exit line, when it printed one.
	supervisor: Extract<SupervisorLine, { event: 'exit' }> | undefined;
	steps: StepResult[];
	exit: ExitState | undefined;
	stopped: 'exited' | 'timeout' | 'protocol-limit' | 'cancelled' | 'failed';
	// The stop and removal had not come back at the end of their time. What the
	// point saw still counts, and no other point can start: a run has one name for
	// its verifier.
	stuck: boolean;
	blocked: string | undefined;
	failures: string[];
	recovery: boolean;
	cleanup: 'succeeded' | 'failed' | 'not-run' | 'none';
	counts: {
		events: number;
		logLines: number;
		bytes: number;
		// The most koid held at once waiting to be handled (OutputReader).
		queuedBytes: number;
		malformed: number;
		captures: number;
	};
}

interface Control {
	// Why the point must stop now, or undefined to go on.
	stopRequested: () => string | undefined;
}

type Wake = { kind: 'output' } | { kind: 'exit' } | { kind: 'aborted' } | { kind: 'tick' };

export class VerifierRunner {
	constructor(private readonly deps: VerifierDeps) {}

	// Runs one point in a fresh verifier and returns what the host saw. The
	// container is stopped and removed whatever happened; a failure to
	// create or start it is a block with its reason, never an exception.
	async run(
		x: PointExecution,
		recorder: PointRecorder,
		writer: RunWriter,
		control: Control,
	): Promise<PointRun> {
		const { docker, log } = this.deps;
		const name = helperName(x.runId, 'verifier');
		const verifier = x.record.endpoints.find((e) => e.role === 'verifier');
		const recorderEndpoint = x.record.endpoints.find((e) => e.role === 'recorder');
		const ending = new AbortController();
		const { signal } = ending;
		const run = new PointState(this.deps, x, recorder, writer, signal);
		let result: PointRun;
		let attached: AttachedContainer | undefined;
		let output: OutputReader | undefined;
		// Armed before anything else: every Docker call of the preparation holds
		// this signal, so a cancel or the deadline ends one where it is, and the
		// teardown below removes what it left.
		const watch = this.watchdog(name, run, control, ending);
		// The watchdog looks when its timer says, and this looks now.
		const stopIfOver = () => {
			if (watch.look()) throw new BlockedError(run.blocked ?? 'the point was stopped');
		};
		try {
			if (verifier === undefined || recorderEndpoint === undefined) {
				throw new Error(`the run network of ${x.runId} lacks a helper endpoint`);
			}
			stopIfOver();
			// The placeholder the run network made, or the last point's, and
			// what the last point's inputs left. Docker's create leaves a volume
			// that exists as it is, so these must be gone before the next fill.
			await docker.remove(name, signal);
			await this.removeInputs(x.runId, signal);
			const inputs = await pointInputs({
				source: x.source,
				fixtures: x.fixtures,
				point: x.point,
				runnerCommand: x.runnerCommand,
				timeoutSeconds: x.timeoutSeconds,
			});
			const app = x.record.endpoints.find((e) => e.role === 'app');
			const volumes = await this.stageInputs(x, inputs.tar, signal);
			stopIfOver();
			const env = verifierEnv({
				runId: x.runId,
				pointId: x.pointId,
				attempt: x.attempt,
				previewUrl: `http://app.${x.runId}.invalid:${x.record.appPort}`,
				recorderIp: recorderEndpoint.ip,
				browserToken: x.browserToken,
				fixtures: inputs.fixtures,
				timeoutSeconds: Math.ceil(run.secondsLeft()),
				maxRequests: x.maxRequests,
				loginKey: x.loginKey,
			});
			await docker.createVerifier(
				{
					name,
					image: x.image,
					network: x.record.network,
					ip: verifier.ip,
					mac: verifier.mac,
					runId: x.runId,
					appHost: { name: `app.${x.runId}.invalid`, ip: app?.ip ?? '' },
					dns: x.record.gateway,
					env,
					entrypoint: SUPERVISOR_INTERPRETER,
					command: SUPERVISOR_COMMAND,
					workdir: WORKSPACE,
					volumes,
				},
				signal,
			);
			await run.event('host', 'verifier-created', {
				container: name,
				image: x.image,
				inputBytes: inputs.bytes,
			});
			const problems = mountProblems(await docker.mounts(name, signal), volumes);
			if (problems.length > 0) {
				throw new BlockedError(`image_mounts: ${name} ${problems.join('; ')}`);
			}
			stopIfOver();
			attached = await docker.attach(name);
			run.startedAt = this.deps.now().getTime();
			// Noted the moment it happens, whatever the handler is doing, so the
			// time koid then takes over the queue is not charged to the runner.
			attached.exited.then(
				(code) => run.exited(code),
				() => run.exited(125),
			);
			// In the same tick as the spawn: see OutputReader for why it matters.
			output = new OutputReader(
				attached,
				run.budget,
				() => this.deps.now().getTime(),
				signal,
				(why) => {
					run.overLimit(why);
					watch.stop();
				},
				(stream, line) => run.arrived(stream, line),
			);
			await run.event('host', 'verifier-started', { container: name });
			// A container that ended before it was seen running has nothing to
			// start: the streams and its exit say what happened.
			if (await this.untilRunning(name, x.record.network, attached, signal)) {
				// The container runs, so it has a bridge port now. The helper binds
				// a permit to that port only when it finds the container running,
				// so nothing short of its word on the port will do; a runner
				// released on the permits of a container still created would hold
				// a permit with no ingress match.
				//
				// The wait ends with the point: another run can hold the network's
				// lock, and the helper can be slow, and the watchdog reaches neither.
				// A reapply still queued for the lock when the signal fires is dropped.
				// One already at the helper finishes under the lock, ahead of the
				// teardown's revoke (VerificationNetwork.reapply says why).
				try {
					await untilAborted(
						this.deps.network.reapply(x.runId, { bound: ['verifier'], signal }),
						signal,
						`reapplying the permits of ${x.runId}`,
						log,
					);
				} catch (err) {
					throw new BlockedError(`network_reapply_failed: ${message(err)}`);
				}
				if (!signal.aborted) {
					// Measured here, the last thing before the steps can run. The
					// firewall and a slow start came out of the budget too.
					run.throwIfOutOfTime();
					await run.ack(attached, {
						version: RUNNER_PROTOCOL_VERSION,
						type: 'start',
						key: run.key,
						timeoutSeconds: run.secondsLeft(),
					});
				}
			}
			await this.follow(attached, output, run, signal);
		} catch (err) {
			if (err instanceof InputsError || err instanceof BlockedError) run.blocked ??= err.message;
			else run.blocked ??= `verifier_failed: ${this.scrub(message(err))}`;
			// A stop the watchdog already made is the truer account of the end.
			if (run.stopped === 'exited') run.stopped = 'failed';
			log(`run ${x.runId}, point ${x.pointId}: ${message(err)}`);
		} finally {
			// Before the stop: what a step says from here on is koid's stop killing
			// it, which says nothing about the app.
			output?.stopHolding();
			watch.disarm();
			// These have to work after the point has stopped, so no signal reaches
			// them, and a Docker that does not answer must not cost the point what it
			// already read. So the wait has an end here.
			const clock = clockReaches(
				this.deps.now().getTime() + CLEANUP_MS,
				() => this.deps.now().getTime(),
				this.deps.pollMs ?? 1_000,
			);
			run.stuck = await Promise.race([
				this.removeVerifier(name, run, attached, output).then(() => false),
				clock.at.then(() => true),
			]);
			clock.cancel();
			if (run.stuck) {
				log(`run ${x.runId}: its verifier has not gone, and the run's teardown tries again`);
				attached?.detach();
				output?.close();
			}
			await run
				.settle(output?.drain() ?? [], output?.peakBytes ?? 0)
				.catch((err: unknown) => log(`reading the verifier's last lines: ${message(err)}`));
			result = run.finish();
			await run
				.event('host', 'verifier-stopped', {
					how: run.stopped,
					...(run.exit !== undefined
						? {
								status: run.exit.status,
								exitCode: run.exit.exitCode,
								oomKilled: run.exit.oomKilled,
							}
						: {}),
				})
				.catch((err: unknown) => log(`recording the verifier's end: ${message(err)}`));
		}
		return result;
	}

	// Stops the verifier and removes it and its inputs. Never rejects: what fails
	// is logged, and the run's teardown tries again.
	private async removeVerifier(
		name: string,
		run: PointState,
		attached: AttachedContainer | undefined,
		output: OutputReader | undefined,
	): Promise<void> {
		const { docker, log } = this.deps;
		const { runId } = run.x;
		await docker
			.stop(name)
			.catch((err: unknown) => log(`stopping the verifier of ${runId}: ${message(err)}`));
		attached?.detach();
		output?.close();
		run.exit = await docker.exitState(name).catch(() => undefined);
		await docker
			.remove(name)
			.catch((err: unknown) => log(`removing the verifier of ${runId}: ${message(err)}`));
		await this.removeInputs(runId).catch((err: unknown) =>
			log(`removing the inputs of ${runId}: ${message(err)}; the run's teardown tries again`),
		);
	}

	// Fills the point's input volumes through a staging container and
	// removes it, so the volumes are mounted by nothing when the verifier
	// takes them. See the head of this file for why it goes this way.
	private async stageInputs(
		x: PointExecution,
		tar: Uint8Array,
		signal: AbortSignal,
	): Promise<VolumeMount[]> {
		const { docker } = this.deps;
		const volumes = inputVolumes(x.runId);
		const staging = stagingName(x.runId);
		for (const volume of volumes) {
			await docker.createVolume(
				volume.name,
				{ 'koi.role': INPUT_VOLUME_ROLE, 'koi.run': x.runId },
				signal,
			);
		}
		await docker.createStaging({ name: staging, image: x.image, runId: x.runId, volumes }, signal);
		await docker.copyIn(staging, tar, '/', signal);
		await docker.remove(staging, signal);
		return volumes;
	}

	// The staging container first: Docker refuses a volume a container still
	// mounts, and the verifier is gone by the time this is called. The teardown
	// passes no signal: it has to finish after the point has stopped.
	private async removeInputs(runId: string, signal?: AbortSignal): Promise<void> {
		const { docker } = this.deps;
		await docker.remove(stagingName(runId), signal);
		for (const volume of inputVolumes(runId)) await docker.removeVolume(volume.name, signal);
	}

	private scrub(text: string): string {
		return this.deps.secrets.redact(text).slice(0, MAX_TEXT);
	}

	// Stops the point at its budget, at the run's deadline, or on a stop
	// request, whatever the preparation or the handler is doing. The preparation
	// waits on Docker, and the handler on a capture, a read and an acknowledgment
	// for each line, so a limit either checked itself would wait behind all of
	// them. A timer does not: it ends the signal, which every such call holds, and
	// stops the container. Once the verifier has exited, the runner's time is over
	// and this watches koid's own on what it wrote (HANDLING_MS). The exit never
	// shortens what the point had. Returns that stop, for the reader's bounds, a
	// look that says whether the point is over, without waiting for the timer, and
	// the function that disarms it.
	private watchdog(
		name: string,
		run: PointState,
		control: Control,
		ending: AbortController,
	): { stop: () => void; look: () => boolean; disarm: () => void } {
		const { docker, log, now } = this.deps;
		const x = run.x;
		const pollMs = this.deps.pollMs ?? 1_000;
		// The grace is for the supervisor's SIGTERM and its exit line, so nothing
		// before the container starts gets any.
		const stopAt = () => {
			const own = x.pointDeadline + (run.startedAt === undefined ? 0 : STOP_GRACE_SECONDS * 1000);
			const end = run.exitedAt === undefined ? own : Math.max(own, run.exitedAt + HANDLING_MS);
			return Math.min(x.deadline, end);
		};
		let timer: ReturnType<typeof setTimeout> | undefined;
		const stop = () => {
			ending.abort();
			docker
				.stop(name)
				.catch((err: unknown) => log(`stopping the verifier of ${x.runId}: ${message(err)}`));
		};
		const look = () => {
			if (ending.signal.aborted) return true;
			const requested = control.stopRequested();
			if (requested !== undefined) {
				if (run.stopped === 'exited') run.stopped = 'cancelled';
				run.blocked ??= `cancelled: ${requested}`;
				stop();
				return true;
			}
			if (now().getTime() < stopAt()) return false;
			run.outOfTime();
			stop();
			return true;
		};
		const tick = () => {
			if (look()) return;
			timer = setTimeout(tick, Math.min(pollMs, Math.max(1, stopAt() - now().getTime())));
		};
		tick();
		return { stop, look, disarm: () => clearTimeout(timer) };
	}

	// Waits for the container to run: true once it does, false when it ended
	// first or the point's time ran out. A container that does neither within
	// the bound blocks the point.
	private async untilRunning(
		name: string,
		network: string,
		attached: AttachedContainer,
		signal: AbortSignal,
	): Promise<boolean> {
		const { docker, sleep } = this.deps;
		let ended = false;
		const end = () => {
			ended = true;
		};
		attached.exited.then(end, end);
		for (let i = 0; i < RUNNING_POLLS; i++) {
			if (signal.aborted) return false;
			let running: boolean;
			try {
				running = (await docker.inspect(name, network, signal)).running;
			} catch (err) {
				if (signal.aborted) return false;
				throw err;
			}
			if (running) return true;
			if (ended) return false;
			await sleep(RUNNING_POLL_MS);
		}
		throw new BlockedError(
			`verifier_not_running: ${name} was not running ${(RUNNING_POLLS * RUNNING_POLL_MS) / 1000} seconds after its start`,
		);
	}

	// Handles what the reader holds, in order, until the verifier has exited and
	// its streams have ended, the signal says the point is over, or a line stops
	// the point. Each turn handles one line, one stream's end or one tick, and never
	// waits on a rate. It may wait as long as a capture takes, and nothing depends
	// on it: the reader goes on reading, and counts the bounds, behind it. A line
	// taken here always counts. One still queued when the point stops goes to
	// settle().
	private async follow(
		attached: AttachedContainer,
		output: OutputReader,
		run: PointState,
		signal: AbortSignal,
	) {
		const { now } = this.deps;
		const pollMs = this.deps.pollMs ?? 1_000;
		const aborted = new Promise<Wake>((resolve) => {
			if (signal.aborted) resolve({ kind: 'aborted' });
			else signal.addEventListener('abort', () => resolve({ kind: 'aborted' }), { once: true });
		});
		const exit: Promise<Wake> = attached.exited.then(
			(): Wake => ({ kind: 'exit' }),
			(): Wake => ({ kind: 'exit' }),
		);
		const open = new Set<OutputStream>(['stdout', 'stderr']);
		// When koid last finished a line. The drain's limit is on the streams'
		// silence, so koid's own time on a slow capture does not count against them.
		let handledAt = 0;
		for (;;) {
			if (signal.aborted) return;
			const item = output.next();
			if (item?.kind === 'end') {
				open.delete(item.stream);
				if (item.failed) run.outputIncomplete(`reading the verifier's ${item.stream} failed`);
				continue;
			}
			if (item !== undefined) {
				const stop = await run.line(item.stream, item.line, attached);
				if (stop !== undefined) return;
				handledAt = now().getTime();
				continue;
			}
			let waitMs = pollMs;
			const waits: Array<Promise<Wake>> = [
				output.arrival().then((): Wake => ({ kind: 'output' })),
				aborted,
			];
			if (run.exitedAt === undefined) {
				waits.push(exit);
			} else {
				if (open.size === 0) return;
				const last = Math.max(run.exitedAt, handledAt, output.lastReadAt);
				const left = DRAIN_MS - (now().getTime() - last);
				if (left <= 0) {
					run.outputIncomplete('the output streams did not end after the verifier exited');
					return;
				}
				waitMs = Math.min(pollMs, left);
			}
			const wake = await race(waits, Math.max(1, waitMs));
			if (wake.kind === 'aborted') return;
		}
	}
}

class BlockedError extends Error {}

// What one point accumulates while its verifier runs.
class PointState {
	readonly budget: ProtocolBudget;
	readonly reports: AssertionReport[] = [];
	readonly artifacts: Record<string, string> = {};
	readonly labels = new Set<string>();
	readonly steps: StepResult[] = [];
	readonly failures: string[] = [];
	readonly stderrTail: string[] = [];
	supervisor: Extract<SupervisorLine, { event: 'exit' }> | undefined;
	// What signs the supervisor's lines. Goes to the supervisor in the start
	// line, and nowhere else.
	readonly key = randomBytes(32).toString('hex');
	// The number the next line of the supervisor's must carry.
	private nextSeq = 1;
	private readonly sequence: string[] = [];
	stopped: PointRun['stopped'] = 'exited';
	stuck = false;
	blocked: string | undefined;
	recovery = false;
	exit: ExitState | undefined;
	exitCode: number | undefined;
	startedAt: number | undefined;
	// When the attachment reported the container's end, on koid's clock.
	exitedAt: number | undefined;
	events = 0;
	logLines = 0;
	captures = 0;
	queuedBytes = 0;
	private readonly declared: Set<string>;

	constructor(
		private readonly deps: VerifierDeps,
		readonly x: PointExecution,
		private readonly recorder: PointRecorder,
		private readonly writer: RunWriter,
		private readonly signal: AbortSignal,
	) {
		this.budget = new ProtocolBudget(deps.limits ?? {}, () => deps.now().getTime());
		this.declared = new Set(x.point.assertions.map((a) => a.name));
	}

	private scrub(text: string, max = MAX_TEXT): string {
		return this.deps.secrets.redact(text).slice(0, max);
	}

	// The writer scrubs every event too. This scrubs first because of the cut: a
	// cut made first could leave most of a secret.
	async event(source: 'host' | 'runner', type: string, fields: Record<string, unknown>) {
		await this.writer.appendEvent({
			source,
			type,
			pointId: this.x.pointId,
			attempt: this.x.attempt,
			...scrubFields(this.deps.secrets, fields, MAX_TEXT),
		});
	}

	async ack(attached: AttachedContainer, ack: RunnerAck): Promise<void> {
		try {
			await attached.write(encoder.encode(`${JSON.stringify(ack)}\n`), { signal: this.signal });
		} catch (err) {
			// The container is gone or its stdin closed; the point's end will
			// say which.
			this.deps.log(`writing to the verifier of ${this.x.runId}: ${message(err)}`);
		}
	}

	// What the point has left of its budget, in seconds, on koid's clock.
	secondsLeft(): number {
		return (this.x.pointDeadline - this.deps.now().getTime()) / 1000;
	}

	// The container's end, as the attachment reported it.
	exited(code: number): void {
		this.exitCode = code;
		this.exitedAt = this.deps.now().getTime();
	}

	// The point's time ended before the runner did: it is blocked, and whatever
	// the runner reports after that does not count. Returns why it stops. A
	// verifier that exited first was in time, whatever is still queued: what ran
	// out is koid's own time on its output, and the reason must not read as the
	// runner's.
	outOfTime(): string {
		if (this.exitedAt !== undefined && this.stopped === 'exited') {
			const handling =
				'handling_timeout: the verifier exited in time, and koid ran out of time handling what it wrote';
			this.blocked ??= handling;
			return handling;
		}
		const before = this.startedAt === undefined ? 'its verifier started' : 'the runner ended';
		const why = `point_timeout: the point reached its budget of ${this.x.timeoutSeconds} seconds before ${before}`;
		if (this.stopped === 'exited') this.stopped = 'timeout';
		this.blocked ??= why;
		return why;
	}

	// Nothing left means nothing more is started: a step given no time could only
	// be stopped, and what it did until then would say nothing about the app.
	throwIfOutOfTime(): void {
		if (this.secondsLeft() <= 0) throw new BlockedError(this.outOfTime());
	}

	// A bound on the runner's output was passed.
	overLimit(why: string): void {
		if (this.stopped === 'exited') this.stopped = 'protocol-limit';
		this.failures.push(`runner_protocol_limit: ${why}`);
	}

	// Output koid did not read fails the point: what is unread could be the
	// step that failed, and a pass must rest on all of it.
	outputIncomplete(why: string): void {
		this.failures.push(`runner_output_incomplete: ${why}, so what it wrote was not all read`);
	}

	// One line as it arrives, on the reader's loop: every bound on lines is counted
	// here, so the time koid takes over the queue cannot change what they see. A
	// burst queued behind a long capture is not a burst the runner made, and a
	// flood behind one stops the point at once. Returns why the point must stop.
	arrived(stream: OutputStream, line: SplitLine): string | undefined {
		if ('discarded' in line) return this.budget.countMalformed();
		if (stream === 'stderr') return undefined;
		const read = classifyLine(line.text, this.key);
		if (read.kind === 'malformed') return this.budget.countMalformed();
		if (read.kind !== 'event') return undefined;
		const over = this.budget.countEvent();
		if (over !== undefined) return over;
		return this.misdirected(read.event) === undefined ? undefined : this.budget.countMalformed();
	}

	// Why an event the protocol reads is still not one this point can take.
	private misdirected(event: RunnerEvent): string | undefined {
		if (event.type !== 'assertion') return undefined;
		if (event.point !== this.x.pointId) {
			return `an assertion for point ${event.point}, not the active point`;
		}
		if (!this.declared.has(event.name)) {
			return `an assertion ${event.name} the point does not declare`;
		}
		return undefined;
	}

	// One line of a stream. Returns the reason the point must stop, if any.
	async line(
		stream: 'stdout' | 'stderr',
		line: { text: string } | { discarded: true },
		attached: AttachedContainer,
	): Promise<string | undefined> {
		if ('discarded' in line) {
			await this.diagnose(
				`a ${stream} line over ${this.budget.limits.lineBytes} bytes was discarded`,
			);
			return undefined;
		}
		if (stream === 'stderr') {
			this.stderrTail.push(this.scrub(line.text, 300));
			if (this.stderrTail.length > STDERR_TAIL) this.stderrTail.shift();
			await this.log('stderr', line.text);
			return undefined;
		}
		const classified = classifyLine(line.text, this.key);
		switch (classified.kind) {
			case 'log':
				await this.log('stdout', classified.text);
				return undefined;
			case 'malformed':
				await this.diagnose(classified.reason);
				return undefined;
			case 'supervisor':
				await this.supervisorLine(classified.line, classified.seq);
				return undefined;
			case 'event':
				this.events += 1;
				return this.handle(classified.event, attached);
		}
	}

	// What koid had read and not handled when the point stopped. Only the
	// supervisor's signed word counts by then: a step may have reported its
	// failure while koid waited on a capture, and that stands. A runner's events
	// are over, like everything else it says after the stop. A line counts once it
	// is taken in, so a failure to record one must not lose the lines behind it.
	async settle(rest: OutputItem[], queuedBytes: number): Promise<void> {
		this.queuedBytes = queuedBytes;
		for (const item of rest) {
			if (item.kind !== 'line' || item.stream !== 'stdout' || !('text' in item.line)) continue;
			const read = classifyLine(item.line.text, this.key);
			if (read.kind === 'supervisor' && read.seq === this.nextSeq) {
				await this.supervisorLine(read.line, read.seq).catch((err: unknown) =>
					this.deps.log(`recording a supervisor line of ${this.x.runId}: ${message(err)}`),
				);
			}
		}
	}

	private async log(stream: 'stdout' | 'stderr', text: string): Promise<void> {
		if (text === '') return;
		this.logLines += 1;
		if (this.logLines > this.budget.limits.logLinesPerPoint) {
			if (this.logLines === this.budget.limits.logLinesPerPoint + 1) {
				await this.event('host', 'runner-log-capped', {
					limit: this.budget.limits.logLinesPerPoint,
				});
			}
			return;
		}
		await this.event('runner', 'runner-log', { stream, text });
	}

	private async diagnose(reason: string): Promise<void> {
		await this.event('host', 'runner-protocol-diagnostic', { reason });
	}

	private async supervisorLine(line: SupervisorLine, seq: number): Promise<void> {
		// Signed, but out of its place: any process in the container can read
		// a line from the pipe and print it again. What it stole never counts
		// here, and the hole it left fails the point.
		if (seq !== this.nextSeq) {
			this.sequence.push(`line ${seq} came where line ${this.nextSeq} was due`);
			await this.event('host', 'runner-protocol-diagnostic', {
				reason: 'a supervisor line out of sequence',
			});
			return;
		}
		this.nextSeq += 1;
		if (this.supervisor !== undefined) {
			this.sequence.push(`a ${line.event} line came after the exit line`);
			return;
		}
		const { version: _v, type: _t, ...fields } = line;
		if (fields.event === 'step') {
			const { event: _e, ...step } = fields;
			this.steps.push(step);
			await this.event('host', 'supervisor-step', fields);
		} else if (line.event === 'exit') {
			this.supervisor = line;
			await this.event('host', 'supervisor-exit', {
				...fields,
				steps: JSON.stringify(line.steps),
			});
		} else {
			await this.event('host', 'supervisor-started', {});
		}
	}

	private async handle(
		event: RunnerEvent,
		attached: AttachedContainer,
	): Promise<string | undefined> {
		switch (event.type) {
			case 'assertion': {
				const wrong = this.misdirected(event);
				if (wrong !== undefined) {
					await this.diagnose(wrong);
					return undefined;
				}
				// As the runner sent it, until the point is judged. A reference must
				// still name its artifact whatever the registry has learned, or a
				// word someone registers would turn a pass into missing evidence.
				// What is kept of it goes through the run's sanitizer (runPoint).
				//
				// A report that cites too many counts as a failure of its assertion. Judged
				// on the references kept, it could hide a bad one past the cut. Dropped, it
				// could hide a failure, with a pass reported after it.
				const tooMany = event.evidence.length > MAX_REFS;
				const outcome = tooMany ? 'fail' : event.outcome;
				const evidence = tooMany ? [] : event.evidence;
				const detail = tooMany
					? `it cites ${event.evidence.length} references, over the ${MAX_REFS} allowed`
					: event.detail;
				// Kept before anything waits on the disk, so a stalled write cannot lose it.
				this.reports.push({
					name: event.name,
					outcome,
					evidence,
					...(detail !== undefined ? { detail } : {}),
				});
				if (tooMany) await this.diagnose(`the report of ${event.name}: ${detail}`);
				await this.event('runner', 'runner-assertion', {
					name: event.name,
					outcome,
					evidence,
					detail,
				});
				return;
			}
			case 'capture':
			case 'read': {
				const label = event.label;
				const what = event.type === 'capture' ? { kind: event.kind } : { path: event.path };
				await this.event('runner', `runner-${event.type}-requested`, { label, ...what });
				let status: 'ready' | 'failed';
				let artifact: string | undefined;
				let error: string | undefined;
				// A label that holds a registered word still makes its capture, or
				// that word would cost the point its evidence. It is the runner's
				// own text, and the records say it through the sanitizer.
				if (this.labels.has(label)) {
					status = 'failed';
					error = 'duplicate_label';
				} else if (this.captures >= this.budget.limits.capturesPerPoint) {
					status = 'failed';
					error = 'capture_limit';
				} else {
					this.labels.add(label);
					this.captures += 1;
					try {
						const options = { signal: this.signal };
						const entry =
							event.type === 'capture'
								? await this.recorder.capture({ kind: event.kind, label }, options)
								: await this.recorder.read(
										{
											path: event.path,
											method: event.method,
											body: { body: true, maxBodyBytes: this.budget.limits.readBodyBytes },
										},
										options,
									);
						if (entry.availability === 'available') {
							status = 'ready';
							artifact = entry.id;
							this.artifacts[label] = entry.id;
						} else {
							status = 'failed';
							error = entry.availability;
						}
					} catch (err) {
						// The recorder call ran out of the point's time. The refusal is
						// koid's, so what a runner reports on hearing of it says nothing
						// about the app. Reading stops here, as the watchdog's stop does.
						if (err instanceof RecorderDeadlineError) return this.outOfTime();
						status = 'failed';
						error = err instanceof CapExceededError ? 'cap_exceeded' : 'capture_failed';
						this.deps.log(`run ${this.x.runId}, ${event.type} ${label}: ${message(err)}`);
					}
				}
				const ack: RunnerAck =
					status === 'ready'
						? {
								version: RUNNER_PROTOCOL_VERSION,
								type: 'capture-result',
								label,
								status,
								artifact: artifact ?? '',
							}
						: {
								version: RUNNER_PROTOCOL_VERSION,
								type: 'capture-result',
								label,
								status,
								error: error ?? 'capture_failed',
							};
				await this.event('host', `runner-${event.type}-answered`, {
					label,
					status,
					artifact,
					error,
				});
				await this.ack(attached, ack);
				return undefined;
			}
			case 'note':
				await this.event('runner', 'runner-note', { text: event.text });
				return undefined;
			case 'phase':
				if (event.name === 'recovery' && event.state === 'start') this.recovery = true;
				await this.event('runner', 'runner-phase', { name: event.name, state: event.state });
				return undefined;
		}
	}

	// Every way the supervisor's account departs from what a real supervisor
	// prints for this point: its declared steps in order, each once, then an
	// exit line that repeats them and ends on the last.
	private sequenceProblems(exit: Extract<SupervisorLine, { event: 'exit' }>): string[] {
		const problems = [...this.sequence];
		const declared = [
			...(this.x.point.setup !== undefined ? ['setup'] : []),
			'run',
			...(this.x.point.cleanup !== undefined ? ['cleanup'] : []),
		];
		const printed = this.steps.map((s) => s.step);
		if (printed.join() !== declared.join()) {
			problems.push(
				`it printed steps ${printed.join(', ') || '(none)'}, and the point declares ${declared.join(', ')}`,
			);
		}
		const account = (steps: StepResult[]) =>
			JSON.stringify(
				steps.map((s) => [
					s.step,
					s.status,
					s.code,
					s.signal,
					s.seconds,
					s.reason,
					s.output_incomplete,
				]),
			);
		if (account(exit.steps) !== account(this.steps)) {
			problems.push('its exit line does not repeat its step lines');
		}
		const last = exit.steps.at(-1);
		if (exit.step !== last?.step || exit.status !== last?.status || exit.code !== last?.code) {
			problems.push('its exit line does not end on its last step');
		}
		return problems;
	}

	// What the host concludes once the container is gone: how the steps
	// ended, whether the supervisor's account and the exit code agree, and
	// what that fails or blocks.
	finish(): PointRun {
		const x = this.x;
		const steps = this.supervisor?.steps ?? this.steps;
		const step = (name: StepResult['step']) => steps.find((s) => s.step === name);
		const how = (s: StepResult): string =>
			s.status === 'exited'
				? `exited ${s.code ?? 0}`
				: s.status === 'signalled'
					? `was killed by signal ${s.signal ?? 0}`
					: s.status === 'timeout'
						? 'ran out of time'
						: s.status === 'failed'
							? `could not start${s.reason ? `: ${s.reason}` : ''}`
							: `was skipped${s.reason ? `: ${s.reason}` : ''}`;
		const ok = (s: StepResult | undefined) => s?.status === 'exited' && (s.code ?? 0) === 0;

		// The supervisor's signed word that it dropped part of a step's stdout.
		// It counts however the point ended, since what is gone could be the
		// failing assertion.
		const cut = [...this.steps, ...(this.supervisor?.steps ?? [])]
			.filter((s) => s.output_incomplete === true)
			.map((s) => s.step);
		for (const name of new Set(cut)) {
			this.outputIncomplete(`the supervisor stopped reading the ${name} step's stdout`);
		}

		// A step's signed failure counts however the point went on: a cleanup
		// that later ran out of time, a cancel or a limit takes nothing back.
		// Each of these came before koid stopped the container, since koid
		// handles no line after that, so none is a step koid's own stop killed.
		// A step stopped at the budget says nothing about the app, as with the
		// watchdog's own stop. A run skipped because of one is the same.
		const timedOut = steps.find((s) => s.status === 'timeout');
		const setup = step('setup');
		if (x.point.setup !== undefined && setup !== undefined && !ok(setup)) {
			if (setup.status !== 'timeout') {
				this.failures.push(`setup_failed: the setup step ${how(setup)}`);
			}
		}
		const run = step('run');
		if (run !== undefined && !ok(run) && run.status !== 'timeout') {
			if (run.status !== 'skipped' || timedOut === undefined) {
				this.failures.push(`runner_failed: the run step ${how(run)}`);
			}
		}

		if (this.stopped === 'exited') {
			if (this.exit?.oomKilled === true) {
				this.failures.push(
					'verifier_oom_killed: the verifier was killed for exceeding its memory limit',
				);
			}
			const code = this.exit?.exitCode ?? this.exitCode;
			if (this.supervisor === undefined) {
				if (code === 0) {
					this.failures.push(
						'supervisor_missing: the verifier exited 0 without the supervisor reporting how its steps ended',
					);
				} else {
					this.blocked ??= `verifier_failed: the verifier exited ${code ?? 'without a code'} before the supervisor reported${this.stderrTail.length > 0 ? `: ${this.stderrTail.join(' | ')}` : ''}`;
				}
			} else {
				for (const problem of this.sequenceProblems(this.supervisor)) {
					this.failures.push(`supervisor_sequence: ${problem}`);
				}
				if (code !== supervisorExitCode(this.supervisor)) {
					this.failures.push(
						`supervisor_mismatch: the supervisor's exit line implies exit code ${supervisorExitCode(this.supervisor)}, and the container exited ${code ?? 'without a code'}`,
					);
				}
			}
			if (timedOut !== undefined) {
				this.blocked ??= `point_timeout: the ${timedOut.step} step reached its share of the point's budget of ${x.timeoutSeconds} seconds`;
				this.stopped = 'timeout';
			}
		}

		let cleanup: PointRun['cleanup'];
		if (x.point.cleanup === undefined) cleanup = 'none';
		else {
			const c = step('cleanup');
			// A cleanup out of time did not finish, which is what the point's
			// block says; it reads as under the watchdog's stop.
			if (c === undefined || c.status === 'skipped' || c.status === 'timeout') cleanup = 'not-run';
			else cleanup = ok(c) ? 'succeeded' : 'failed';
		}

		return {
			reports: this.reports,
			artifacts: this.artifacts,
			supervisor: this.supervisor === undefined ? undefined : { ...this.supervisor, steps },
			steps,
			exit: this.exit,
			stopped: this.stopped,
			stuck: this.stuck,
			blocked: this.blocked,
			failures: this.failures,
			recovery: this.recovery,
			cleanup,
			counts: {
				events: this.events,
				logLines: this.logLines,
				bytes: this.budget.bytes,
				queuedBytes: this.queuedBytes,
				malformed: this.budget.malformed,
				captures: this.captures,
			},
		};
	}
}

// `work`, or undefined once the signal fires. The caller then goes on and `work`
// is left to end by itself, so it must be safe to leave. How it ended is logged.
async function untilAborted<T>(
	work: Promise<T>,
	signal: AbortSignal,
	what: string,
	log: (message: string) => void,
): Promise<T | undefined> {
	const aborted = new Promise<undefined>((resolve) => {
		if (signal.aborted) resolve(undefined);
		else signal.addEventListener('abort', () => resolve(undefined), { once: true });
	});
	const result = await Promise.race([work, aborted]);
	if (signal.aborted) {
		work.then(
			() => log(`${what}: finished after the point stopped waiting`),
			(err: unknown) => log(`${what}: ended after the point stopped waiting: ${message(err)}`),
		);
	}
	return result;
}

// The first of the promises to settle, or a tick after `ms`.
function race(waits: Promise<Wake>[], ms: number): Promise<Wake> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const tick = new Promise<Wake>((resolve) => {
		timer = setTimeout(() => resolve({ kind: 'tick' }), ms);
	});
	return Promise.race([...waits, tick]).finally(() => {
		if (timer !== undefined) clearTimeout(timer);
	});
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
