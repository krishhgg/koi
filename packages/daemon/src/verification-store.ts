import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import {
	type FileHandle,
	mkdir,
	open,
	readdir,
	readFile,
	rename,
	rm,
	stat,
} from 'node:fs/promises';
import { dirname, join } from 'node:path';
import {
	type Artifact,
	ArtifactIdSchema,
	type ArtifactKind,
	ArtifactSchema,
	type DeploymentIdentity,
	EVIDENCE_LIMITS,
	EVIDENCE_RETENTION,
	type EvidenceEvent,
	type EvidenceLimits,
	type EvidenceManifest,
	EvidenceManifestSchema,
	type EvidenceTombstone,
	EvidenceTombstoneSchema,
	MAX_EVENT_BYTES,
	PointIdSchema,
	type Redaction,
	type RunStatus,
	RunStatusSchema,
	VerifyIdSchema,
} from '@koi/shared';
import { diskSpace as statDiskSpace } from './fsutil.ts';
import type { EvidenceLookup, Integrity, ResolvedEvidence } from './verdict.ts';
import { type Sanitize, sanitizeRunData } from './verification-sanitize.ts';

// The evidence store (docs/verify.md, "Recorder and evidence"): what koid
// keeps of verification under <stateDir>/verification. koid is its only
// writer; no container sees these paths. Every directory is 0700 and every
// file 0600. A file is written whole into the run's .pending directory,
// fsynced and renamed into place, so a reader never sees half of one, and
// manifest.json goes last: a run directory without one is not a completed
// bundle. Artifact ids count up within a run and are never reused; the
// store derives a file's path from the id, the id never carries a path.
//
//   verification/
//     inputs/<deploymentId>/snapshot.json, source/   (verification-snapshot.ts)
//     inputs/.pending-<deploymentId>/                 a snapshot being copied
//     plans/<planId>/plan.json, planning.json         (verification.ts)
//     runs/<runId>/run.json, status.json, plan.json, execution.json,
//                  controller.json, events.ndjson,
//                  points/<pointId>/observations.json,
//                  artifacts/<artifactId>, result.json, report.md,
//                  manifest.json, .pending/

const DAY_MS = 86_400_000;

// The directory snapshotInputs copies a snapshot into, under inputs/. If koid
// is killed during the copy, nothing else ever removes it.
export const PENDING_INPUTS_PREFIX = '.pending-';

// How long such a directory must go unchanged before the sweep removes it. A
// snapshot copies 64 MiB at most and changes the directory with every file, so
// after an hour no koid can still be writing it.
const PENDING_INPUTS_MAX_AGE_MS = 60 * 60_000;

// The longest a run waits on one thing its disk has to do: a write and its sync,
// a read of one artifact. A disk that takes longer has stopped answering, as far
// as the run can tell, and the run stops waiting (RunWriter.onDisk). The run's
// teardown has 120 seconds, and this must leave most of them for the Docker
// commands behind it.
export const DISK_WAIT_MS = 60_000;

// Why a run ends when its disk stopped answering.
export const EVIDENCE_UNWRITABLE = 'evidence_unwritable';

// A run's disk did not answer in time. The run has no way to say how it went, so
// it ends interrupted, and what was still going is left to end by itself.
export class EvidenceStuckError extends Error {
	constructor(what: string) {
		super(
			`${EVIDENCE_UNWRITABLE}: the disk did not finish ${what} within ${DISK_WAIT_MS / 1000} seconds, so the evidence of this run could not be written`,
		);
		this.name = 'EvidenceStuckError';
	}
}

// A time on koid's clock: `at` resolves once it comes. This looks at the clock
// instead of arming one timer, so a clock that jumps is seen.
export function clockReaches(
	until: number,
	now: () => number,
	pollMs: number,
): { at: Promise<void>; cancel: () => void } {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const at = new Promise<void>((resolve) => {
		const look = () => {
			const left = until - now();
			if (left <= 0) resolve();
			else timer = setTimeout(look, Math.min(pollMs, left));
		};
		look();
	});
	return { at, cancel: () => clearTimeout(timer) };
}

export interface EvidenceStoreDeps {
	stateDir: string;
	now: () => Date;
	// Free space and size of the filesystem that holds the store.
	diskSpace?: (path: string) => Promise<{ free: number; size: number }>;
	limits?: Partial<EvidenceLimits>;
	log?: (message: string) => void;
	// Takes known secrets out of what a run writes when the run has no sanitizer
	// of its own (openRun). Problem details are built from labels and error
	// messages, which an application controls.
	scrub?: (text: string) => string;
	// How often a wait on the disk looks at the clock; tests shorten it.
	diskPollMs?: number;
}

// What a record holds that carries runtime text. Every such record reaches its file
// through this, and it takes the sanitizer as an argument so that no caller can skip it.
// It runs now and not when the record was built, so a secret learned since is out of
// what is written.
function recordText(record: unknown, sanitize: Sanitize): string {
	return jsonText(sanitize(record));
}

// A record as its file holds it. One with only project text and koid's own values comes
// here directly, as it is, so a digest over it holds.
function jsonText(record: unknown): string {
	return `${JSON.stringify(record, null, '\t')}\n`;
}

// The most problems a run's status holds (RunStatusSchema). The last entry
// within the bound is PROBLEMS_CAPPED, a fixed one that says later problems
// were not recorded, so a run with any number of problems still writes its
// status and finalizes, as incomplete.
export const MAX_PROBLEMS = 1000;
export const PROBLEMS_CAPPED = {
	code: 'problems_capped',
	detail: `the run has more than ${MAX_PROBLEMS} problems; the ones past this were not recorded`,
} as const;

// A cap was reached. The run records it and cannot pass.
export class CapExceededError extends Error {
	constructor(
		readonly cap: keyof EvidenceLimits | 'free-space',
		message: string,
	) {
		super(message);
	}
}

// The records a run directory may hold besides events and artifacts.
export type RunRecordName =
	| 'run.json'
	| 'plan.json'
	| 'execution.json'
	| 'result.json'
	| 'report.md'
	| 'controller.json';

export const RUN_RECORDS: readonly RunRecordName[] = [
	'run.json',
	'plan.json',
	'execution.json',
	'result.json',
	'report.md',
	'controller.json',
];

// Those that hold only project text and koid's own values (writeDeclared).
export type DeclaredRecordName = Extract<
	RunRecordName,
	'run.json' | 'plan.json' | 'execution.json'
>;

// Those that carry runtime text (writeRecord). The report has a way of its own
// (writeReport).
export type RuntimeRecordName = Extract<RunRecordName, 'result.json' | 'controller.json'>;

export class EvidenceStore {
	readonly root: string;
	readonly limits: EvidenceLimits;
	readonly now: () => Date;
	readonly log: (message: string) => void;
	readonly scrub: (text: string) => string;
	readonly diskPollMs: number;
	private readonly diskSpace: (path: string) => Promise<{ free: number; size: number }>;
	// The allowance of each run that is open, by run id. Admission counts
	// these against free space, so two runs admitted together cannot both
	// be promised the same bytes; a run gives its reservation back when it
	// finalizes or is abandoned.
	private readonly reservations = new Map<string, number>();

	constructor(deps: EvidenceStoreDeps) {
		this.root = join(deps.stateDir, 'verification');
		this.limits = { ...EVIDENCE_LIMITS, ...deps.limits };
		// The manifest schema holds EVIDENCE_LIMITS.artifactsPerRun entries at
		// most; a higher cap would let a run collect entries its manifest
		// cannot be written with.
		this.limits.artifactsPerRun = Math.min(
			this.limits.artifactsPerRun,
			EVIDENCE_LIMITS.artifactsPerRun,
		);
		this.now = deps.now;
		this.diskSpace = deps.diskSpace ?? statDiskSpace;
		this.log = deps.log ?? (() => {});
		this.scrub = deps.scrub ?? ((text) => text);
		this.diskPollMs = deps.diskPollMs ?? 1_000;
	}

	async init(): Promise<void> {
		for (const dir of ['', 'inputs', 'plans', 'runs']) {
			await mkdir(join(this.root, dir), { recursive: true, mode: 0o700 });
		}
		// A run or snapshot synced into one of these is only as durable as the
		// entry naming the directory itself.
		await syncTree(join(this.root, 'runs'), { depth: 0 });
		await syncTree(join(this.root, 'inputs'), { depth: 0 });
		await syncTree(join(this.root, 'plans'), { depth: 0 });
		await fsyncDir(this.root);
		await fsyncDir(dirname(this.root));
	}

	inputsDir(deploymentId: string): string {
		return join(this.root, 'inputs', VerifyIdSchema.parse(deploymentId));
	}

	planDir(planId: string): string {
		return join(this.root, 'plans', VerifyIdSchema.parse(planId));
	}

	runDir(runId: string): string {
		return join(this.root, 'runs', VerifyIdSchema.parse(runId));
	}

	// Bytes promised to runs that are open, other than `except`.
	reservedBytes(except?: string): number {
		let total = 0;
		for (const [runId, bytes] of this.reservations) if (runId !== except) total += bytes;
		return total;
	}

	// Gives a run's reservation back. finalize and abandon call this.
	release(runId: string): void {
		this.reservations.delete(runId);
	}

	// The reserve that must stay free: the larger of the fixed reserve and
	// the share of the filesystem, the share capped. What other open runs are
	// still promised is counted as used already, though it may not be on disk
	// yet.
	async checkSpace(forRun?: string): Promise<void> {
		const space = await this.diskSpace(this.root);
		const share = Math.min(this.limits.reserveShare * space.size, this.limits.reserveShareCap);
		const reserve = Math.max(this.limits.reserveBytes, share);
		const outstanding = this.reservedBytes(forRun);
		if (space.free - outstanding - this.limits.bytesPerRun < reserve) {
			const promised =
				outstanding > 0 ? `, ${gib(outstanding)} GiB of it promised to runs still open` : '';
			throw new CapExceededError(
				'free-space',
				`${gib(space.free)} GiB free on the evidence filesystem${promised}; a run needs ${gib(this.limits.bytesPerRun)} GiB over a reserve of ${gib(reserve)} GiB`,
			);
		}
	}

	// Starts a run's directory. The run id must be new: a finished run is
	// never reopened and a crashed one is swept, not resumed. The run's
	// allowance is reserved first and checked against free space before
	// anything is made, so a second run admitted meanwhile sees it.
	async openRun(
		runId: string,
		options: { deployment?: DeploymentIdentity; sanitize?: Sanitize } = {},
	): Promise<RunWriter> {
		const dir = this.runDir(runId);
		if (this.reservations.has(runId)) throw new Error(`run ${runId} is open already`);
		this.reservations.set(runId, this.limits.bytesPerRun);
		try {
			await this.checkSpace(runId);
			const existing = await stat(dir).catch(() => undefined);
			if (existing !== undefined) throw new Error(`run ${runId} already has a directory`);
			for (const sub of ['', '.pending', 'artifacts', 'points']) {
				await mkdir(join(dir, sub), { recursive: true, mode: 0o700 });
			}
			const sanitize =
				options.sanitize ?? ((record) => sanitizeRunData(record, { redact: this.scrub }));
			return await RunWriter.create(this, runId, dir, options.deployment, sanitize);
		} catch (err) {
			this.reservations.delete(runId);
			throw err;
		}
	}

	// Writes a record of a run with no writer open: recovery ends what the last koid left.
	async writeRecord(dir: string, name: string, record: unknown, sanitize: Sanitize): Promise<void> {
		const pending = join(dir, '.pending');
		await mkdir(pending, { recursive: true, mode: 0o700 });
		await writeAtomic(join(dir, name), recordText(record, sanitize), pending);
	}

	// Writes a record that has only project text and koid's own values, with no writer
	// open: a plan is made before any run, and recovery ends a run's run.json.
	async writeDeclared(dir: string, name: string, record: unknown): Promise<void> {
		const pending = join(dir, '.pending');
		await mkdir(pending, { recursive: true, mode: 0o700 });
		await writeAtomic(join(dir, name), jsonText(record), pending);
	}

	async readManifest(runId: string): Promise<EvidenceManifest | undefined> {
		return readJson(join(this.runDir(runId), 'manifest.json'), EvidenceManifestSchema);
	}

	async readStatus(runId: string): Promise<RunStatus | undefined> {
		return readJson(join(this.runDir(runId), 'status.json'), RunStatusSchema);
	}

	// Keeps a run's evidence for EVIDENCE_RETENTION.pinnedDays from now.
	// Retention is separate metadata: the manifest is never changed.
	async pin(runId: string, days = EVIDENCE_RETENTION.pinnedDays): Promise<string> {
		const dir = this.runDir(runId);
		if ((await this.readManifest(runId)) === undefined) {
			throw new Error(`run ${runId} has no manifest to pin`);
		}
		const pinnedUntil = new Date(this.now().getTime() + days * DAY_MS).toISOString();
		await writeAtomic(
			join(dir, 'retention.json'),
			`${JSON.stringify({ pinnedUntil }, null, '\t')}\n`,
			join(dir, '.pending'),
		);
		return pinnedUntil;
	}

	// Retention. A finalized run keeps its evidence until retainedUntil, or
	// its pin; then the evidence goes and a tombstone stays with the
	// manifest until tombstoneUntil; then the directory goes. A run that
	// never finalized goes whole after inputDays, as does an input snapshot
	// and a plan past its time. A snapshot a killed koid left half copied goes
	// after an hour.
	async sweep(): Promise<{
		expired: string[];
		removed: string[];
		inputs: string[];
		pendingInputs: string[];
		plans: string[];
	}> {
		const now = this.now().getTime();
		const expired: string[] = [];
		const removed: string[] = [];
		const inputs: string[] = [];
		const pendingInputs: string[] = [];
		const plans: string[] = [];
		for (const runId of await list(join(this.root, 'runs'))) {
			if (!VerifyIdSchema.safeParse(runId).success) continue;
			const dir = this.runDir(runId);
			try {
				const manifest = await this.readManifest(runId);
				if (manifest === undefined) {
					const status = await this.readStatus(runId);
					const since =
						status === undefined ? (await stat(dir)).mtimeMs : Date.parse(status.updatedAt);
					if (now - since >= EVIDENCE_RETENTION.inputDays * DAY_MS) {
						await rm(dir, { recursive: true, force: true });
						removed.push(runId);
					}
					continue;
				}
				if (now >= Date.parse(manifest.tombstoneUntil)) {
					await rm(dir, { recursive: true, force: true });
					removed.push(runId);
					continue;
				}
				const pin = await readJson(join(dir, 'retention.json'), undefined);
				const pinnedUntil =
					pin !== undefined && typeof pin === 'object' && pin !== null && 'pinnedUntil' in pin
						? Date.parse(String((pin as { pinnedUntil: unknown }).pinnedUntil))
						: Number.NaN;
				const until = Math.max(
					Date.parse(manifest.retainedUntil),
					Number.isNaN(pinnedUntil) ? 0 : pinnedUntil,
				);
				if (now >= until && (await this.expire(runId, dir, manifest))) expired.push(runId);
			} catch (err) {
				this.log(`sweeping run ${runId}: ${message(err)}`);
			}
		}
		// These names are not ids, so the retention loop below skips them.
		for (const name of await list(join(this.root, 'inputs'))) {
			if (!name.startsWith(PENDING_INPUTS_PREFIX)) continue;
			const dir = join(this.root, 'inputs', name);
			try {
				if (now - (await stat(dir)).mtimeMs >= PENDING_INPUTS_MAX_AGE_MS) {
					await rm(dir, { recursive: true, force: true });
					pendingInputs.push(name.slice(PENDING_INPUTS_PREFIX.length));
				}
			} catch (err) {
				this.log(`sweeping ${name}: ${message(err)}`);
			}
		}
		for (const deploymentId of await list(join(this.root, 'inputs'))) {
			if (!VerifyIdSchema.safeParse(deploymentId).success) continue;
			const dir = this.inputsDir(deploymentId);
			try {
				const snapshot = await readJson(join(dir, 'snapshot.json'), undefined);
				const taken =
					snapshot !== undefined &&
					typeof snapshot === 'object' &&
					snapshot !== null &&
					'takenAt' in snapshot
						? Date.parse(String((snapshot as { takenAt: unknown }).takenAt))
						: (await stat(dir)).mtimeMs;
				if (now - taken >= EVIDENCE_RETENTION.inputDays * DAY_MS) {
					await rm(dir, { recursive: true, force: true });
					inputs.push(deploymentId);
				}
			} catch (err) {
				this.log(`sweeping inputs ${deploymentId}: ${message(err)}`);
			}
		}
		for (const planId of await list(join(this.root, 'plans'))) {
			if (!VerifyIdSchema.safeParse(planId).success) continue;
			const dir = join(this.root, 'plans', planId);
			try {
				if (now - (await stat(dir)).mtimeMs >= EVIDENCE_RETENTION.manifestDays * DAY_MS) {
					await rm(dir, { recursive: true, force: true });
					plans.push(planId);
				}
			} catch (err) {
				this.log(`sweeping plan ${planId}: ${message(err)}`);
			}
		}
		return { expired, removed, inputs, pendingInputs, plans };
	}

	// Removes a run's evidence and leaves the manifest with a tombstone. The
	// tombstone goes first, so a crash between the two leaves nothing that
	// looks complete; and the removal is finished on a later sweep if the
	// crash came after the tombstone, so an interrupted expiry does not
	// leave evidence behind for 180 days. Returns whether anything was done.
	private async expire(runId: string, dir: string, manifest: EvidenceManifest): Promise<boolean> {
		const leftovers: string[] = [];
		for (const name of EXPIRED_NAMES) {
			if ((await stat(join(dir, name)).catch(() => undefined)) !== undefined) leftovers.push(name);
		}
		const hasTombstone =
			(await stat(join(dir, 'tombstone.json')).catch(() => undefined)) !== undefined;
		if (hasTombstone && leftovers.length === 0) return false;
		if (!hasTombstone) {
			const manifestBytes = await readFile(join(dir, 'manifest.json'));
			const tombstone: EvidenceTombstone = EvidenceTombstoneSchema.parse({
				version: 1,
				runId,
				expiredAt: this.now().toISOString(),
				manifestSha256: sha256(manifestBytes),
				tombstoneUntil: manifest.tombstoneUntil,
			});
			await mkdir(join(dir, '.pending'), { recursive: true, mode: 0o700 });
			await writeAtomic(
				join(dir, 'tombstone.json'),
				`${JSON.stringify(tombstone, null, '\t')}\n`,
				join(dir, '.pending'),
			);
		} else {
			this.log(`finishing the interrupted expiry of run ${runId}`);
		}
		for (const name of EXPIRED_NAMES) {
			await rm(join(dir, name), { recursive: true, force: true });
		}
		return true;
	}
}

// What expiry removes from a run directory: the evidence. The manifest,
// the status, the tombstone and controller.json stay for the manifest's
// lifetime (EVIDENCE_RETENTION.manifestDays): the status route reads the
// controller record for every run it knows, and a run whose evidence has
// gone must still answer with its verdict, while its artifacts answer 410.
const EXPIRED_NAMES = [
	'artifacts',
	'points',
	'events.ndjson',
	'.pending',
	...RUN_RECORDS.filter((name) => name !== 'controller.json'),
] as const;

// What a caller gives appendEvent: everything but the sequence number, and
// the time unless it has one.
// What the manifest says of a run besides what the writer knows.
export interface FinalizeFields {
	planId?: string;
	planDigest?: string;
	executionDigest?: string;
	limitations: string[];
}

export interface EventInput {
	source: EvidenceEvent['source'];
	type: string;
	pointId?: string | undefined;
	attempt?: number | undefined;
	at?: string | undefined;
	[field: string]: unknown;
}

interface ArtifactMeta {
	pointId: string;
	attempt: number;
	kind: ArtifactKind;
	mediaType: string;
	capturedAt: string;
	eventRange: { first: number; last: number };
	redaction: Redaction;
}

// One run's directory while the run goes. Everything it writes is final
// when its method returns; nothing is buffered.
export class RunWriter {
	readonly artifacts: Artifact[] = [];
	private eventCount = 0;
	// Bytes of events.ndjson that are whole lines, written and synced:
	// where the next append writes, and where a failed one is cut back to.
	private eventBytes = 0;
	private nextSeq = 1;
	// Appends run one at a time through this chain. One append checks and
	// takes its place under the event cap before the next looks, and a
	// failed one is cut out of the file before another writes after it.
	private appends: Promise<unknown> = Promise.resolve();
	private nextArtifact = 1;
	private artifactBytes = 0;
	// Bytes of the run's allowance held by artifacts still streaming in
	// (reserveBytes). The cap check counts them with artifactBytes, so two
	// streams each under the cap cannot together pass it.
	private bytesReserved = 0;
	private current: RunStatus;
	private finalized = false;
	// The first cap reached, after which nothing more is captured.
	private cap: CapExceededError | undefined;
	// Places in the manifest taken by entries about to be pushed: claimed
	// without an await between the claim and the push, so two writes that
	// stream at once cannot both take the last place (claimPlace).
	private claims = 0;
	// The disk did not answer in time (onDisk). Never cleared: what was going may
	// end at any time, and it must not change how the run ended.
	private gaveUp: EvidenceStuckError | undefined;
	// Rejects when the disk is given up on, for everything still waiting on it.
	private readonly givingUp = Promise.withResolvers<never>();

	private constructor(
		private readonly store: EvidenceStore,
		readonly runId: string,
		readonly dir: string,
		private readonly events: FileHandle,
		readonly deployment: DeploymentIdentity | undefined,
		// What everything this writer writes passes through, whichever method
		// writes it (verification-sanitize.ts).
		private readonly sanitize: Sanitize,
		status: RunStatus,
	) {
		this.current = status;
		// Nothing may be waiting when it rejects.
		this.givingUp.promise.catch(() => {});
	}

	static async create(
		store: EvidenceStore,
		runId: string,
		dir: string,
		deployment: DeploymentIdentity | undefined,
		sanitize: Sanitize,
	): Promise<RunWriter> {
		const at = store.now().toISOString();
		const status: RunStatus = RunStatusSchema.parse({
			version: 1,
			runId,
			state: 'running',
			evidence: 'collecting',
			startedAt: at,
			updatedAt: at,
			counts: { events: 0, artifacts: 0, bytes: 0 },
			problems: [],
		});
		const events = await open(join(dir, 'events.ndjson'), 'wx', 0o600);
		const writer = new RunWriter(store, runId, dir, events, deployment, sanitize, status);
		await writer.writeStatus();
		return writer;
	}

	get status(): RunStatus {
		return this.current;
	}

	// Whether a cap stopped capture; the message says which.
	get capped(): CapExceededError | undefined {
		return this.cap;
	}

	// Why this run gave up on its disk, once it has.
	get stuck(): EvidenceStuckError | undefined {
		return this.gaveUp;
	}

	private pending(): string {
		return join(this.dir, '.pending');
	}

	private assertOpen(): void {
		if (this.finalized) throw new Error(`run ${this.runId} is finalized`);
	}

	// Every wait of this run on its disk goes through here, so none outlasts
	// DISK_WAIT_MS. A wait that reaches it gives up on the disk for the whole run:
	// it and everything else waiting reject now, and from then on nothing starts,
	// so what stops the run never queues behind a write that does not come back. A
	// slow disk gets the limit for each thing it does, not for what waits in line.
	async onDisk<T>(what: string, work: () => Promise<T>): Promise<T> {
		if (this.gaveUp !== undefined) throw this.gaveUp;
		const now = () => this.store.now().getTime();
		const clock = clockReaches(now() + DISK_WAIT_MS, now, this.store.diskPollMs);
		const running = work();
		// It may reject once the wait is over, with nothing listening.
		running.catch(() => {});
		try {
			return await Promise.race([
				running,
				this.givingUp.promise,
				clock.at.then(() => {
					throw this.giveUp(what);
				}),
			]);
		} finally {
			clock.cancel();
		}
	}

	private giveUp(what: string): EvidenceStuckError {
		if (this.gaveUp === undefined) {
			const stuck = new EvidenceStuckError(what);
			this.gaveUp = stuck;
			this.store.log(`run ${this.runId}: ${stuck.message}`);
			// In memory only, since the disk is what stopped answering.
			this.noteProblem(EVIDENCE_UNWRITABLE, stuck.message);
			this.givingUp.reject(stuck);
		}
		return this.gaveUp;
	}

	// A file written whole, under the limit. A write still going when the run gives
	// up does not land: its bytes stay in .pending and the rename never happens.
	private writeWhole(what: string, path: string, content: string): Promise<void> {
		return this.onDisk(what, () =>
			writeAtomic(path, content, this.pending(), undefined, () => {
				if (this.gaveUp !== undefined) throw this.gaveUp;
			}),
		);
	}

	// Appends one event with the next host sequence number and the time.
	// An event over MAX_EVENT_BYTES is replaced by one that says so; the
	// event cap is a run problem. Appends wait for one another, so the cap
	// holds however many callers append at once.
	async appendEvent(event: EventInput): Promise<EvidenceEvent> {
		this.assertOpen();
		const turn = this.appends.then(() =>
			this.onDisk('writing an event', () => this.writeEvent(event)),
		);
		// The chain goes on whatever this append did; the caller gets the
		// result, or the error, from its own turn.
		this.appends = turn.catch(() => {});
		return turn;
	}

	// One append, with no other in progress. If the write or the sync fails
	// part way, the file is cut back to the last whole line, so a reader
	// still finds one JSON object per line, and the run records the loss.
	// The sequence number is taken only once the line is in, so the file's
	// numbers count up without a gap after a failure.
	private async writeEvent(event: EventInput): Promise<EvidenceEvent> {
		this.assertOpen();
		if (this.eventCount >= this.store.limits.eventsPerRun) {
			await this.reachCap(
				new CapExceededError(
					'eventsPerRun',
					`the run has ${this.eventCount} events, the most it may keep`,
				),
			);
		}
		const seq = this.nextSeq;
		const { at: given, ...rest } = event;
		let full: EvidenceEvent = this.sanitize({
			...rest,
			seq,
			at: given ?? this.store.now().toISOString(),
		});
		let line = `${JSON.stringify(full)}\n`;
		if (Buffer.byteLength(line) > MAX_EVENT_BYTES) {
			full = {
				seq,
				at: full.at,
				source: full.source,
				type: 'oversized-event',
				...(full.pointId !== undefined ? { pointId: full.pointId } : {}),
				...(full.attempt !== undefined ? { attempt: full.attempt } : {}),
				originalType: full.type,
			};
			line = `${JSON.stringify(full)}\n`;
		}
		const bytes = Buffer.from(line);
		try {
			// At the end of the whole lines, not at the handle's own position:
			// a cut leaves that position past the end of the file.
			await writeAll(this.events, bytes, this.eventBytes);
			await this.events.datasync();
		} catch (err) {
			await this.dropPartialEvent(seq, err);
			throw err;
		}
		this.nextSeq = seq + 1;
		this.eventCount += 1;
		this.eventBytes += bytes.length;
		this.current = { ...this.current, counts: { ...this.current.counts, events: this.eventCount } };
		// The event's content is gone, so the bundle no longer holds all that
		// was observed. The caller's cursor moves on as if it were kept.
		if (full.type === 'oversized-event') {
			await this.addProblem(
				'event_oversized',
				`an event of type ${String(full.originalType)} was too large to keep`,
			);
		}
		return full;
	}

	// Cuts a failed append out of events.ndjson, back to the last whole
	// line, and records that an event was lost. The evidence is incomplete
	// from here on either way; if the cut itself fails, the problem says so,
	// and the next append still writes at the last whole line.
	private async dropPartialEvent(seq: number, err: unknown): Promise<void> {
		let cut = '';
		try {
			await this.events.truncate(this.eventBytes);
			await this.events.datasync();
		} catch (truncation) {
			cut = `; the file could not be cut back to ${this.eventBytes} bytes: ${message(truncation)}`;
		}
		await this.addProblem(
			'event_write_failed',
			`event ${seq} was not written: ${message(err)}${cut}`,
		).catch((problem: unknown) =>
			this.store.log(
				`recording that event ${seq} of run ${this.runId} was lost: ${message(problem)}`,
			),
		);
	}

	// The next artifact id of a kind. Numbers count up across kinds within
	// the run, so no two artifacts of a run share a number.
	nextArtifactId(kind: ArtifactKind): string {
		return ArtifactIdSchema.parse(`recorder:${kind}:${this.nextArtifact++}`);
	}

	// Writes sanitized bytes as an artifact: into .pending, hashed as they
	// go, fsynced, its entry validated, and only then renamed into
	// artifacts/, the directory synced, and the entry returned. A cap
	// reached part way leaves no file and stops capture for the run. An
	// entry the manifest schema refuses (a redaction record past its bounds,
	// say) leaves no file either: the run gets a problem and the entry
	// returned is a failed one. A failure at the close, at the rename or after
	// it (the directory sync, say) removes the file, so the disk holds no more
	// artifact bytes than the run counts; a file that cannot be removed keeps its
	// bytes under the run's cap and is a run problem (removeUncounted).
	async writeArtifact(
		meta: ArtifactMeta,
		body: Uint8Array | AsyncIterable<Uint8Array>,
	): Promise<Artifact> {
		this.assertOpen();
		if (this.cap !== undefined) throw this.cap;
		await this.checkCount();
		const id = this.nextArtifactId(meta.kind);
		const temp = join(this.pending(), `${randomUUID()}.part`);
		const what = `writing ${id}`;
		const handle = await this.onDisk(what, () => open(temp, 'wx', 0o600));
		const hash = createHash('sha256');
		let size = 0;
		// What this write holds of the run's byte allowance (reserveBytes),
		// until its bytes are on the run's count (pushEntry) or gone with the
		// file. Every way out gives it back, unless the file could not be
		// removed: then its bytes are still on disk and the cap must count them.
		let held = 0;
		try {
			try {
				// A body given whole has a known size, reserved before a byte is
				// written. A stream's size is known only as it comes, so each
				// chunk is reserved before it is written.
				if (body instanceof Uint8Array) held = this.reserveBytes(id, held, body.length);
				const chunks = body instanceof Uint8Array ? [body] : body;
				for await (const chunk of chunks) {
					size += chunk.length;
					if (size > held) held = this.reserveBytes(id, held, size - held);
					hash.update(chunk);
					await this.onDisk(what, () => writeAll(handle, chunk));
				}
				await this.onDisk(what, () => handle.sync());
				// In here, not after the catch: a close can report a write error
				// the sync did not, and its file is on no count, like any other
				// failed write's. A second close in the catch does nothing.
				await this.onDisk(what, () => handle.close());
			} catch (err) {
				await this.onDisk(what, () => handle.close()).catch(() => {});
				// Held until the file is gone: given back sooner, an overlapping
				// write could take the allowance and then a failed removal would
				// leave the disk over the cap. Given back before the problem is
				// written, so a stream still going is not refused for bytes that
				// have left the disk. A file that cannot go keeps its bytes.
				if (await this.removeUncounted(id, temp, '.pending/', err)) this.bytesReserved -= held;
				held = 0;
				if (err instanceof CapExceededError) await this.reachCap(err);
				throw err;
			}
			// A place in the manifest, now that the body is in: another entry
			// may have joined the run while this one streamed, and the manifest
			// holds no more than the cap. Refused here, the file never reaches
			// artifacts/.
			const full = this.claimPlace();
			if (full !== undefined) {
				if (await this.removeUncounted(id, temp, '.pending/', full)) this.bytesReserved -= held;
				held = 0;
				await this.reachCap(full);
			}
			try {
				const parsed = ArtifactSchema.safeParse(
					this.entryFields(id, meta, size, `sha256:${hash.digest('hex')}`, 'available'),
				);
				if (!parsed.success) {
					const why = parsed.error.issues
						.map((i) => `${i.path.join('.')}: ${i.message}`)
						.join('; ')
						.slice(0, 500);
					if (!(await this.removeUncounted(id, temp, '.pending/', why))) held = 0;
					await this.addProblem(
						'artifact_invalid',
						`${id}: its entry is not a valid artifact: ${why}`,
					);
					return this.pushEntry(this.failedEntry(id, meta, why), 0);
				}
				const published = join(this.dir, 'artifacts', id);
				try {
					await this.onDisk(what, () => rename(temp, published));
				} catch (err) {
					// The file is still in .pending and on no count. It goes before
					// the finally below gives its bytes back, or the next write
					// could pass the cap with these bytes still on disk.
					if (!(await this.removeUncounted(id, temp, '.pending/', err))) held = 0;
					throw err;
				}
				try {
					await this.onDisk(what, () => fsyncDir(join(this.dir, 'artifacts')));
					return this.pushEntry(parsed.data, size);
				} catch (err) {
					// The file is in artifacts/ and on no count. Removed, the
					// directory holds what the run counts again. A file that
					// stays keeps the bytes this write reserved: the finally
					// below gives back nothing, so the cap still counts them.
					if (!(await this.removeUncounted(id, published, 'artifacts/', err))) held = 0;
					throw err;
				}
			} finally {
				this.claims -= 1;
			}
		} finally {
			// Synchronous with pushEntry, which counted the bytes kept: no
			// await between the two, so no check sees them twice. The bytes
			// of a file removed are nobody's.
			this.bytesReserved -= held;
		}
	}

	// Removes an artifact's file that will not reach the run's count, because
	// of `cause`, so the disk holds no more artifact bytes than the run
	// counts. True when the file is gone. When it cannot go it stays until
	// the sweep removes the run, and the run records it: the manifest will
	// not name it, so the evidence is incomplete, and the caller keeps its
	// bytes reserved so the run's cap counts them.
	private async removeUncounted(
		id: string,
		path: string,
		where: 'artifacts/' | '.pending/',
		cause: unknown,
	): Promise<boolean> {
		try {
			await this.onDisk(`removing ${id}`, () => rm(path, { force: true }));
			return true;
		} catch (err) {
			await this.addProblem(
				'artifact_orphaned',
				`${id}: its file is in ${where} but not on the run's count (${message(cause)}), and removing it failed: ${message(err)}`,
			).catch((problem: unknown) =>
				this.store.log(
					`recording that artifact ${id} of run ${this.runId} is orphaned: ${message(problem)}`,
				),
			);
			return false;
		}
	}

	// Takes `more` bytes of the run's allowance for an artifact on its way,
	// or says which cap refuses them. Synchronous: no await between the
	// check and the claim, so two streams cannot both be allowed the last
	// bytes. Returns what the write holds now.
	private reserveBytes(id: string, held: number, more: number): number {
		if (held + more > this.store.limits.bytesPerArtifact) {
			throw new CapExceededError(
				'bytesPerArtifact',
				`${id} is over ${this.store.limits.bytesPerArtifact} bytes, the most one artifact may be`,
			);
		}
		if (this.artifactBytes + this.bytesReserved + more > this.store.limits.bytesPerRun) {
			throw new CapExceededError(
				'bytesPerRun',
				`the run's artifacts would pass ${this.store.limits.bytesPerRun} bytes, the most a run may keep`,
			);
		}
		this.bytesReserved += more;
		return held + more;
	}

	// The entry for an artifact whose own entry the manifest schema refused.
	// It keeps only what cannot have been the problem: the media type the
	// recorder gave may be, so it is not kept.
	private failedEntry(id: string, meta: ArtifactMeta, why: string): Artifact {
		return ArtifactSchema.parse(
			this.entryFields(
				id,
				{
					...meta,
					mediaType: 'application/octet-stream',
					redaction: {
						status: 'failed',
						policyDigest: meta.redaction.policyDigest,
						removedFields: [],
						limitations: [`the artifact's entry was not valid: ${why}`.slice(0, 500)],
					},
				},
				0,
				sha256(new Uint8Array(0)),
				'failed',
			),
		);
	}

	// An entry for an artifact with no payload: withheld by policy, or
	// failed in capture or sanitization. It takes an id so a reference to
	// it resolves to the record of why there is nothing. It counts against
	// the run's artifact cap like any other entry.
	async recordArtifact(
		meta: Omit<ArtifactMeta, 'mediaType'> & { mediaType?: string },
	): Promise<Artifact> {
		this.assertOpen();
		if (meta.redaction.status === 'sanitized') {
			throw new Error('an artifact without bytes cannot be sanitized');
		}
		await this.checkCount();
		const full = this.claimPlace();
		if (full !== undefined) await this.reachCap(full);
		try {
			const entry = ArtifactSchema.parse(
				this.entryFields(
					this.nextArtifactId(meta.kind),
					{ ...meta, mediaType: meta.mediaType ?? 'application/octet-stream' },
					0,
					sha256(new Uint8Array(0)),
					meta.redaction.status,
				),
			);
			return this.pushEntry(entry, 0);
		} finally {
			this.claims -= 1;
		}
	}

	// The artifact count cap applies to every entry, withheld and failed
	// ones included: the manifest cannot hold more. Places already claimed
	// by entries on their way count as taken.
	private async checkCount(): Promise<void> {
		const full = this.countFull();
		if (full !== undefined) await this.reachCap(full);
	}

	// The cap, when the run's entries and the places claimed fill it.
	private countFull(): CapExceededError | undefined {
		if (this.artifacts.length + this.claims < this.store.limits.artifactsPerRun) return undefined;
		return new CapExceededError(
			'artifactsPerRun',
			`the run has ${this.artifacts.length} artifacts, the most it may keep`,
		);
	}

	// Takes a place for an entry about to be pushed, or says the run is full.
	// Synchronous: the caller pushes, or gives the place back, with no await
	// between a claim and the check another caller makes.
	private claimPlace(): CapExceededError | undefined {
		const full = this.countFull();
		if (full !== undefined) return full;
		this.claims += 1;
		return undefined;
	}

	private entryFields(
		id: string,
		meta: ArtifactMeta,
		size: number,
		digest: string,
		availability: Artifact['availability'],
	): Record<string, unknown> {
		return {
			id,
			runId: this.runId,
			pointId: PointIdSchema.parse(meta.pointId),
			attempt: meta.attempt,
			kind: meta.kind,
			mediaType: meta.mediaType,
			size,
			sha256: digest,
			origin: 'recorder',
			capturedAt: meta.capturedAt,
			eventRange: meta.eventRange,
			redaction: meta.redaction,
			availability,
			retainedUntil: this.retainedUntil(),
		};
	}

	// The one place entries join the run. Every caller holds a claimed
	// place; this holds the manifest's bound whatever path led here.
	private pushEntry(entry: Artifact, bytes: number): Artifact {
		if (this.artifacts.length >= this.store.limits.artifactsPerRun) {
			throw new CapExceededError(
				'artifactsPerRun',
				`the run has ${this.artifacts.length} artifacts, the most it may keep`,
			);
		}
		this.artifacts.push(entry);
		this.artifactBytes += bytes;
		this.current = {
			...this.current,
			counts: {
				...this.current.counts,
				artifacts: this.artifacts.length,
				bytes: this.artifactBytes,
			},
		};
		return entry;
	}

	// What the run holds for each of `refs`, checked on disk, as the verdict
	// takes it (resolveArtifacts over the entries so far). The entries are
	// the manifest's once the run finalizes.
	async resolveEvidence(refs: Iterable<string>): Promise<EvidenceLookup> {
		return resolveArtifacts(this.dir, this.artifacts, refs, (id, check) =>
			this.onDisk(`checking ${id}`, check),
		);
	}

	async writeObservations(pointId: string, data: unknown): Promise<void> {
		this.assertOpen();
		const dir = join(this.dir, 'points', PointIdSchema.parse(pointId));
		await this.onDisk(`making the directory of ${pointId}`, () =>
			mkdir(dir, { recursive: true, mode: 0o700 }),
		);
		await this.writeWhole(
			`writing the observations of ${pointId}`,
			join(dir, 'observations.json'),
			recordText(data, this.sanitize),
		);
	}

	async writeRecord(name: RuntimeRecordName, record: unknown): Promise<void> {
		this.assertOpen();
		await this.writeWhole(
			`writing ${name}`,
			join(this.dir, name),
			recordText(record, this.sanitize),
		);
	}

	async writeDeclared(name: DeclaredRecordName, record: unknown): Promise<void> {
		this.assertOpen();
		await this.writeWhole(`writing ${name}`, join(this.dir, name), jsonText(record));
	}

	// The report, rendered from what the sanitizer gives it. The finished text holds the
	// project's own words, which a scrub would mask, and the render escapes text, so a
	// scrub of the result could miss a secret. So the render takes the sanitizer.
	async writeReport(render: (clean: Sanitize) => string): Promise<void> {
		this.assertOpen();
		await this.writeWhole('writing report.md', join(this.dir, 'report.md'), render(this.sanitize));
	}

	// Records what keeps the run from passing. Evidence is incomplete from
	// here on, whatever else is captured. The status holds MAX_PROBLEMS: the
	// last place goes to PROBLEMS_CAPPED, and problems past it are not
	// recorded, so the status can always be written.
	async addProblem(code: string, detail: string): Promise<void> {
		this.assertOpen();
		if (!this.noteProblem(code, detail)) return;
		await this.writeStatus();
	}

	// The problem in the status in memory. False when the status has no more room.
	private noteProblem(code: string, detail: string): boolean {
		const problems = this.current.problems;
		if (problems.length >= MAX_PROBLEMS) return false;
		const at = this.store.now().toISOString();
		const entry =
			problems.length === MAX_PROBLEMS - 1
				? { ...PROBLEMS_CAPPED, at }
				: // Scrubbed before the cut, or a secret across the cut would survive.
					{ code, detail: this.sanitize(detail).slice(0, 2000), at };
		this.current = {
			...this.current,
			evidence: 'incomplete',
			problems: [...problems, entry],
		};
		return true;
	}

	async setState(state: 'running' | 'completed' | 'cancelled' | 'failed'): Promise<void> {
		this.assertOpen();
		const at = this.store.now().toISOString();
		const { finishedAt: _dropped, ...rest } = this.current;
		this.current = { ...rest, state, ...(state === 'running' ? {} : { finishedAt: at }) };
		await this.writeStatus();
	}

	private async reachCap(cap: CapExceededError): Promise<never> {
		if (this.cap === undefined) {
			this.cap = cap;
			await this.addProblem('cap_exceeded', cap.message);
		}
		throw cap;
	}

	private async writeStatus(): Promise<void> {
		this.current = RunStatusSchema.parse({
			...this.current,
			updatedAt: this.store.now().toISOString(),
		});
		await this.writeWhole(
			'writing status.json',
			join(this.dir, 'status.json'),
			recordText(this.current, this.sanitize),
		);
	}

	private retainedUntil(): string {
		return new Date(this.store.now().getTime() + EVIDENCE_RETENTION.runDays * DAY_MS).toISOString();
	}

	// Closes the run: a run still running is completed, the events file is
	// synced and closed, the status is written for the last time, and the
	// manifest goes in after everything it names is durable.
	async finalize(fields: FinalizeFields): Promise<EvidenceManifest> {
		this.assertOpen();
		if (this.current.state === 'running') await this.setState('completed');
		if (this.current.evidence === 'collecting') {
			this.current = {
				...this.current,
				evidence: this.current.problems.length === 0 ? 'complete' : 'incomplete',
			};
		}
		// An append still in its turn finishes, or is cut out, before the
		// file closes under it.
		await this.appends;
		await this.onDisk('syncing the events', () => this.events.datasync());
		await this.onDisk('closing the events', () => this.events.close());
		await this.writeStatus();
		const eventsBytes = await this.onDisk('reading the events', () =>
			readFile(join(this.dir, 'events.ndjson')),
		);
		const files: EvidenceManifest['files'] = {};
		for (const name of [...RUN_RECORDS, 'status.json'] as const) {
			const bytes = await this.onDisk(`reading ${name}`, () =>
				readFile(join(this.dir, name)).catch(() => undefined),
			);
			if (bytes !== undefined) files[name] = { sha256: sha256(bytes), bytes: bytes.length };
		}
		const finalizedAt = this.store.now();
		const manifest = EvidenceManifestSchema.parse(
			this.sanitize({
				version: 1,
				runId: this.runId,
				...(this.deployment !== undefined ? { deployment: this.deployment } : {}),
				...(fields.planId !== undefined ? { planId: fields.planId } : {}),
				...(fields.planDigest !== undefined ? { planDigest: fields.planDigest } : {}),
				...(fields.executionDigest !== undefined
					? { executionDigest: fields.executionDigest }
					: {}),
				status: this.current,
				artifacts: this.artifacts,
				events: { count: this.eventCount, bytes: eventsBytes.length, sha256: sha256(eventsBytes) },
				files,
				limitations: fields.limitations,
				finalizedAt: finalizedAt.toISOString(),
				retainedUntil: new Date(
					finalizedAt.getTime() + EVIDENCE_RETENTION.runDays * DAY_MS,
				).toISOString(),
				tombstoneUntil: new Date(
					finalizedAt.getTime() + EVIDENCE_RETENTION.manifestDays * DAY_MS,
				).toISOString(),
			}),
		);
		// The manifest says the bundle is whole, so every directory in it must
		// be durable first: writeAtomic syncs only the one that holds the file.
		await this.onDisk('syncing the run', () => syncTree(this.dir));
		// So must the run's own entry in runs/, or a power cut could lose the
		// whole bundle after finalize reported success. Both come before the
		// manifest, since a manifest on disk reads as a finished run.
		await this.onDisk('syncing the run', () => fsyncDir(dirname(this.dir)));
		const manifestPath = join(this.dir, 'manifest.json');
		if (this.gaveUp !== undefined) throw this.gaveUp;
		const landing = writeAtomic(
			manifestPath,
			`${JSON.stringify(manifest, null, '\t')}\n`,
			this.pending(),
			undefined,
			() => {
				if (this.gaveUp !== undefined) throw this.gaveUp;
			},
		);
		try {
			await this.onDisk('writing the manifest', () => landing);
		} catch (err) {
			// writeAtomic can fail after its rename, when it syncs the directory.
			// A manifest that may not survive must not read as a finished run. The
			// run may have stopped waiting with the rename still going, and a manifest
			// that lands after the run ended some other way would read as a finished
			// run, so this waits for the write to end, however long that takes.
			const removing = landing
				.catch(() => {})
				.then(() => rm(manifestPath, { force: true }))
				.catch((removal: unknown) => {
					this.store.log(
						`removing the manifest of run ${this.runId} after a failed write: ${String(removal)}`,
					);
				});
			await this.onDisk('removing the manifest', () => removing).catch(() => {});
			throw err;
		}
		this.finalized = true;
		this.store.release(this.runId);
		return manifest;
	}

	// For a run that stops without a manifest: closes the events file so
	// what was written is on disk, and gives the run's reservation back. The
	// directory stays as a partial bundle until the sweep removes it.
	async abandon(): Promise<void> {
		if (this.finalized) return;
		this.finalized = true;
		// An append queued behind this is refused as finalized; one in its
		// turn finishes first.
		await this.appends;
		// Under the limit like every wait: a run that stops must not wait here on a
		// disk that stopped answering. The file then closes when the disk answers.
		const closing = this.events
			.datasync()
			.catch(() => {})
			.then(() => this.events.close())
			.catch(() => {});
		await this.onDisk('closing the events', () => closing).catch(() => {});
		this.store.release(this.runId);
	}
}

// The evidence lookup the verdict rules take (verdict.ts, EvidenceLookup),
// over a run's artifact entries and its directory: each of `refs` that an
// entry names is resolved to what the entry says and what its bytes on
// disk say against it. A reference no entry names resolves to nothing.
// The check is made here, once, so the lookup itself is synchronous.
export async function resolveArtifacts(
	dir: string,
	entries: readonly Artifact[],
	refs: Iterable<string>,
	// How each file's check is waited on.
	waitFor: (id: string, check: () => Promise<Integrity>) => Promise<Integrity> = (_id, check) =>
		check(),
): Promise<EvidenceLookup> {
	const found = new Map<string, ResolvedEvidence>();
	for (const ref of new Set(refs)) {
		const entry = entries.find((a) => a.id === ref);
		if (entry === undefined) continue;
		found.set(ref, {
			kind: entry.kind,
			availability: entry.availability,
			redaction: entry.redaction.status,
			integrity: await waitFor(entry.id, () => artifactIntegrity(dir, entry)),
		});
	}
	return (ref) => found.get(ref);
}

// What an artifact's bytes on disk say against its entry: `verified` when
// the file is the entry's size and hashes to its digest, `corrupt` when it is
// not, is not a regular file or cannot be read, and `missing` when there is
// no file, or the entry never had one (withheld, failed, expired). The file
// is opened without following a symlink and read whole, since the digest is
// of the whole.
export async function artifactIntegrity(dir: string, entry: Artifact): Promise<Integrity> {
	if (entry.availability !== 'available') return 'missing';
	let handle: FileHandle;
	try {
		handle = await open(
			join(dir, 'artifacts', entry.id),
			constants.O_RDONLY | constants.O_NOFOLLOW,
		);
	} catch (err) {
		return isNotFound(err) ? 'missing' : 'corrupt';
	}
	try {
		const info = await handle.stat();
		if (!info.isFile() || info.size !== entry.size) return 'corrupt';
		const hash = createHash('sha256');
		const buffer = Buffer.alloc(64 * 1024);
		let total = 0;
		for (;;) {
			const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
			if (bytesRead === 0) break;
			hash.update(buffer.subarray(0, bytesRead));
			total += bytesRead;
		}
		if (total !== entry.size) return 'corrupt';
		return `sha256:${hash.digest('hex')}` === entry.sha256 ? 'verified' : 'corrupt';
	} catch {
		return 'corrupt';
	} finally {
		await handle.close().catch(() => {});
	}
}

// Writes every byte, however many calls the handle takes: a write may
// return short, and a short write accepted would be a truncated file with
// a hash of the whole. A write that makes no progress is an error. With a
// position, the bytes go there whatever the handle's own position is.
export async function writeAll(
	handle: Pick<FileHandle, 'write'>,
	bytes: Uint8Array,
	position?: number,
): Promise<void> {
	let at = 0;
	while (at < bytes.length) {
		const { bytesWritten } = await handle.write(
			bytes,
			at,
			bytes.length - at,
			position === undefined ? null : position + at,
		);
		if (bytesWritten <= 0)
			throw new Error(`a write of ${bytes.length - at} bytes made no progress`);
		at += bytesWritten;
	}
}

// Writes a file whole: a temporary in `pending`, fsynced, renamed over
// `path`, and the directory fsynced so the rename is durable too. A write
// that fails leaves nothing behind. `stillWanted` runs just before the rename and
// throws when the file must no longer land: the sync can take any time, and the
// caller may have stopped waiting by the time it comes back.
export async function writeAtomic(
	path: string,
	content: string | Uint8Array,
	pending: string,
	mode = 0o600,
	stillWanted?: () => void,
): Promise<void> {
	const temp = join(pending, `${randomUUID()}.tmp`);
	const handle = await open(temp, 'wx', mode);
	try {
		await writeAll(handle, typeof content === 'string' ? Buffer.from(content) : content);
		await handle.sync();
		stillWanted?.();
	} catch (err) {
		await handle.close().catch(() => {});
		await rm(temp, { force: true });
		throw err;
	}
	await handle.close();
	await rename(temp, path);
	await fsyncDir(join(path, '..'));
}

// Fsyncs `dir` and every directory under it, deepest first. writeAtomic syncs
// only the directory that holds the file it wrote, so nothing else makes a new
// directory's entry in its parent durable. This walks the tree, not a list of
// what was made, so a directory added later cannot be missed. isDirectory is
// false for a symlink, so a walk never leaves the tree. `depth: 0` syncs `dir`
// alone.
export async function syncTree(dir: string, options: { depth?: 0 } = {}): Promise<void> {
	if (options.depth !== 0) {
		for (const entry of await readdir(dir, { withFileTypes: true })) {
			if (entry.isDirectory()) await syncTree(join(dir, entry.name));
		}
	}
	await fsyncDir(dir);
}

export async function fsyncDir(dir: string): Promise<void> {
	const handle = await open(dir, 'r');
	try {
		await handle.sync();
	} finally {
		await handle.close();
	}
}

async function readJson<T>(
	path: string,
	schema: { parse(data: unknown): T } | undefined,
): Promise<T | undefined> {
	let text: string;
	try {
		text = await readFile(path, 'utf8');
	} catch (err) {
		if (isNotFound(err)) return undefined;
		throw err;
	}
	const data: unknown = JSON.parse(text);
	return schema === undefined ? (data as T) : schema.parse(data);
}

async function list(dir: string): Promise<string[]> {
	try {
		return (await readdir(dir)).sort();
	} catch (err) {
		if (isNotFound(err)) return [];
		throw err;
	}
}

function sha256(bytes: Uint8Array): string {
	return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function gib(bytes: number): string {
	return (bytes / 1024 ** 3).toFixed(1).replace(/\.0$/, '');
}

function isNotFound(err: unknown): boolean {
	return typeof err === 'object' && err !== null && 'code' in err && err.code === 'ENOENT';
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
