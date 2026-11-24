import { cp, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import {
	ContainerUserSchema,
	type Deployment,
	DeploymentSliceSchema,
	deploymentIdentity,
	IN_FLIGHT_STATUSES,
	LEASE_MAX_SECONDS,
	type Lease,
	type LeaseReply,
	MAX_DEPLOYMENT_SLICE_BYTES,
	MAX_SLICE_FILE_BYTES,
	NO_SUCH_LEASE,
	NO_SUCH_PREVIEW,
	numericUser,
	type PreviewRecord,
	type PreviewStatus,
	type Recipe,
	type RepoRecipe,
	randomId,
	type UpRequest,
} from '@koi/shared';
import type { BuildLog, BuildLogs } from './buildlog.ts';
import type { CaddyApplier, Route } from './caddy.ts';
import {
	BUILD_CACHE_LIMIT,
	BUILD_CACHE_LOW_DISK,
	type DiskUsage,
	type Docker,
	type RunOptions,
	readerName,
} from './docker.ts';
import { type Egress, egressEnv, egressFiles } from './egress-config.ts';
import { minFreeBytes } from './fsutil.ts';
import type { LiveList } from './live.ts';
import { KeyedLock, Mutex, Semaphore } from './lock.ts';
import type { LoadedRecipe } from './recipes.ts';
import { redact } from './redact.ts';
import type { PreviewStore } from './store.ts';
import type { Uploads } from './uploads.ts';
import { hashRecipeDir } from './verification-snapshot.ts';

export interface DeployerDeps {
	domain: string;
	network: string;
	// The systemd slice previews run in, when koid uses one.
	slice?: string | undefined;
	stateDir: string;
	store: PreviewStore;
	docker: Docker;
	uploads: Uploads;
	caddy: CaddyApplier;
	live: LiveList;
	buildLogs: Pick<BuildLogs, 'open'>;
	// A built-in recipe as installed on the box, for accepting a request
	// that names it.
	builtinRecipe: (name: string) => Promise<LoadedRecipe>;
	// The recipe.json in a directory, which must name `name`: the copy of a
	// built-in recipe's directory a build makes, whose settings the build
	// follows (copyRecipe).
	readRecipe: (dir: string, name: string) => Promise<Recipe>;
	keepAwake: () => Promise<void>;
	extract: (tarball: string, dir: string) => Promise<void>;
	resolveInside: (root: string, relative: string) => Promise<string>;
	// Free space and size, in bytes, of the filesystem Docker keeps its data on.
	diskSpace: () => Promise<{ free: number; size: number }>;
	// One health request: true when the preview answered with any status below 500.
	probe: (url: string) => Promise<boolean>;
	// Keeps a build's verification inputs before the build directory goes
	// (verification-snapshot.ts). Undefined: nothing is kept, and no run can
	// be planned for the deployment. recipe is the built-in recipe's
	// installed directory and the digest of each file in the copy of it the
	// build read, when the request named one.
	snapshotInputs?: (input: {
		deploymentId: string;
		request: UpRequest;
		source: string;
		tarball: string;
		recipe?: { dir: string; files: Record<string, string> } | undefined;
	}) => Promise<void>;
	// Told each secret the deployer makes (a preview's login key), before
	// the value is written anywhere or given to a container, so the
	// sanitizers know it from the start.
	registerSecret?: (value: string) => void;
	// The egress proxy previews use; undefined leaves them with no way out.
	egress?: Egress;
	// Tells the egress proxy which preview each container address runs, the
	// whole map each time, for its koi tokens (see previewAddresses).
	// Resolves once the proxy holds this map, or holds none at all; rejects
	// when that is not certain. Undefined without a proxy.
	previews?: (addresses: Record<string, string>) => Promise<void>;
	// Takes the visits counted since the last call, not yet on any record,
	// as [label, time] (Activity.drainVisits).
	drainVisits: () => Array<[string, number]>;
	now: () => Date;
	sleep: (ms: number) => Promise<void>;
	log: (message: string) => void;
}

// What the HTTP fallback needs to know about a label.
export type PreviewView =
	| { kind: 'unknown' }
	| { kind: 'expired' }
	// Past its ttl and not yet expired: the visit expires it.
	| { kind: 'overdue' }
	// Stopped for writing too much to its disk; only a new deployment helps.
	| { kind: 'halted' }
	| { kind: 'building' }
	| { kind: 'failed'; error: string }
	| { kind: 'stopped' }
	| { kind: 'running' };

export class OwnershipError extends Error {}

// koid cannot take another preview: the list of live previews, which wakes
// the box, has no room for its label (LiveList.room).
export class CapacityError extends Error {}

// A lease stands in the way, or none can be taken: another holder has the
// preview, a build of it is in progress, or nothing serves.
export class LeaseError extends Error {}

// The label has no record.
export class NoSuchPreviewError extends Error {}

// The preview holds no lease with that id.
export class NoSuchLeaseError extends Error {}

// The request asks for what its recipe does not do: koi up --keep for a
// recipe with no sliceFile.
export class UnsupportedRequestError extends Error {}

// A pull request label belongs to that pull request of that repo; a branch
// label to that exact branch. The label alone is not enough: an eight-letter
// digest keeps accidental collisions away but not a crafted one.
export function sameOwner(record: PreviewRecord, request: UpRequest): boolean {
	if (record.status === 'expired') return true;
	if (record.repo !== request.repo) return false;
	if (record.pr !== undefined || request.pr !== undefined) return record.pr === request.pr;
	return record.branch === request.branch;
}

// The numeric uid:gid a preview container runs as: the recipe's if it names
// one, else the image's USER if that is a numeric uid other than 0, else
// nobody. A user name is never trusted, because the image's /etc/passwd says
// what it means and the image comes from the pull request.
export function chooseUser(recipeUser: string | undefined, imageUser: string): string {
	if (recipeUser !== undefined) return ContainerUserSchema.parse(recipeUser);
	return numericUser(imageUser.trim()) ?? NOBODY;
}

const NOBODY = '65534:65534';

// What a request's recipe says about building and running it. up() derives
// one from the recipe as installed, to validate the request and shape the
// record it queues: its ttlDays, and whether a login key is made then. A
// build of a built-in recipe follows not that one but the plan it derives
// from its own copy of the recipe directory (copyRecipe), which the snapshot
// digests, so the deployment and the snapshot describe the same bytes.
interface Plan {
	request: UpRequest;
	port: number;
	healthPath: string;
	healthTimeoutSeconds: number;
	buildTimeoutMinutes: number;
	ttlDays: number;
	env: Record<string, string>;
	user: string | undefined;
	// Where the Dockerfile is: the source tree, or the built-in recipe's
	// directory, which the build gets as the named context "recipe" too.
	dockerfileRoot: 'source' | 'recipe';
	// A built-in recipe's name and installed directory, whatever its
	// Dockerfile builds from. The build copies the directory into its own
	// first and reads only the copy (copyRecipe).
	builtin: { name: string; dir: string } | undefined;
	loginKeyEnv: string | undefined;
	dockerfile: string;
	context: string;
	// Where a built-in recipe's build writes what it kept, in the image.
	sliceFile: string | undefined;
}

// The plan `recipe` gives `request`. A recipe the request brings builds from
// the source tree; a built-in one from where its build section says.
function planFrom(
	request: UpRequest,
	recipe: Recipe | RepoRecipe,
	builtin: { name: string; dir: string } | undefined,
): Plan {
	return {
		request,
		port: recipe.port,
		healthPath: recipe.healthPath,
		healthTimeoutSeconds: recipe.healthTimeoutSeconds,
		buildTimeoutMinutes: recipe.buildTimeoutMinutes,
		ttlDays: recipe.ttlDays,
		env: recipe.env,
		user: recipe.user,
		dockerfileRoot: builtin === undefined ? 'source' : recipe.build.from,
		dockerfile: recipe.build.path,
		context: recipe.build.context,
		builtin,
		loginKeyEnv: recipe.loginKeyEnv,
		sliceFile: builtin !== undefined && 'sliceFile' in recipe ? recipe.sliceFile : undefined,
	};
}

// Why a plan cannot take the request's --keep names, if it cannot: only a
// recipe that reports its slice takes them, so the caller can see what was
// kept.
function keepRefused(plan: Plan): string | undefined {
	if (plan.request.keep === undefined || plan.sliceFile !== undefined) return undefined;
	const recipe =
		plan.builtin === undefined ? "the repository's koi.yaml" : `the recipe ${plan.builtin.name}`;
	return `koi up --keep needs a recipe that reports its slice (a sliceFile in its recipe.json), and ${recipe} has none; run koi up without --keep`;
}

// Statuses of a request that koid has accepted and not yet finished.
const IN_FLIGHT = IN_FLIGHT_STATUSES;

// A preview container may write this much to its own filesystem and the
// volumes its image declares. Root filesystems stay writable (some apps
// install packages at run time) and Docker has no quota for either
// here, so the watchdog in main.ts enforces this after the fact.
export const DISK_LIMIT_BYTES = 10 * 1024 ** 3;

// Below this much of the disk free, a build trims the build cache first; below
// minFreeBytes after that, it is refused.
const wantFreeBytes = (size: number): number => 2 * minFreeBytes(size);

function gib(bytes: number): string {
	return (bytes / 1024 ** 3).toFixed(1).replace(/\.0$/, '');
}

// Starts the error a failed wake leaves on the record.
const WAKE_FAILED = 'the preview did not start: ';

// Whether a lease is in force at `now`. An expired one stays on the record
// until expire() sweeps it, and means nothing until then.
function leaseHolds(lease: Lease | undefined, now: number): lease is Lease {
	return lease !== undefined && Date.parse(lease.expiresAt) > now;
}

// The record without its lease, for a release or a sweep.
function withoutLease(r: PreviewRecord): PreviewRecord {
	const { lease: _released, ...rest } = r;
	return rest;
}

// Past its ttl since the last visit, or since the last change if nobody has
// visited. A request in flight is never overdue: its build will replace it.
// A preview expires ttlDays after it was last used: the later of its last
// visit and its last deploy. Counting from the visit alone would expire a
// preview redeployed after a quiet spell the moment it went up. `visited`
// is a visit not yet on the record, if any.
function overdue(r: PreviewRecord, now: number, visited = 0): boolean {
	if (r.status === 'expired' || IN_FLIGHT.has(r.status)) return false;
	const used = Math.max(
		visited,
		r.lastVisitAt === undefined ? 0 : Date.parse(r.lastVisitAt),
		r.deployment === undefined ? 0 : Date.parse(r.deployment.deployedAt),
		Date.parse(r.updatedAt),
	);
	return now - used >= r.ttlDays * 86_400_000;
}

// The latest visit in the chain of renewals that `visits` (in any order)
// make, starting from `from`, a visit not yet on the record, or else from
// when the record was last used. Each visit counts if it comes before the
// deadline the chain has reached so far, and moves that deadline; one after
// it does not count, since Caddy routes an overdue preview until expiry
// removes it and a visit then must not save it. Undefined when no visit
// counts and there is no `from`.
function chainEnd(
	r: PreviewRecord,
	from: number | undefined,
	visits: number[],
): number | undefined {
	if (r.status === 'expired') return undefined;
	let end = from;
	for (const at of [...visits].sort((a, b) => a - b)) {
		if (!overdue(r, at, end)) end = Math.max(end ?? at, at);
	}
	return end;
}

// The record with `end` as its last visit, when that is later than its own.
function withVisit(r: PreviewRecord, end: number | undefined): PreviewRecord {
	if (end === undefined || r.status === 'expired') return r;
	const when = new Date(end).toISOString();
	return r.lastVisitAt !== undefined && r.lastVisitAt >= when ? r : { ...r, lastVisitAt: when };
}

const INTERRUPTED =
	'interrupted: the daemon restarted before this build finished; run koi up again';

// A build whose attempt is no longer the label's latest: a newer koi up
// replaced it, koi down removed the preview, or the same request was
// accepted again after that.
class Superseded extends Error {}

// Caddy or the egress proxy did not take the routes a container start
// needs (startFresh). It says nothing about the preview, so start() does
// not record it as a failed start, which restore would skip at every later
// boot.
class RoutingFailed extends Error {}

function routingFailed(err: unknown): never {
	throw new RoutingFailed(message(err), { cause: err });
}

// Locks, outermost first:
// - buildQueue (per label) runs one build of a label at a time, in the order
//   the requests were accepted. It is held for the whole build, so it never
//   blocks anything but the next build of the same label.
// - builds (global) lets one build use the box at a time.
// - lifecycle (per label) is held briefly for every change that ties a record
//   to containers and routes: accepting a request, the cutover at the end of
//   a build, down, expiry, waking a stopped container, and the disk watchdog
//   stopping one. A build does its slow work without it, so visitors can
//   still wake the previous version.
// - routing (global) is held while routes are computed and applied, so two
//   route changes never interleave and an older snapshot never lands after a
//   newer one. Routes go to the egress proxy as a map of container address
//   to preview (its koi tokens work only from their own preview's address)
//   and to Caddy, in that order, each time. It is also held across every
//   start of a preview container (startFresh), from the sync before it to
//   the check after it, because Docker gives a stopped container's address
//   to the next container it starts.
// Publishing the live list has a mutex of its own and takes no other lock.
// Two more mutexes take only the store's locks, and may be taken under a
// lifecycle lock: visitWrites, held while visits are written, and admitting
// (global), held while up() checks that a new label still fits in the live
// list and records it, so two new labels cannot both take the last room.
// The store also serialises writes per label on its own.
//
// Only containers in `ready` are routed: those whose health check passed
// since this koid started or since they last started. A container being
// started, or one koid found running after a restart and has not checked,
// is not routed, however a sync interleaves with its check. The set changes
// only under `routing` (setReady), which a code path holding a lifecycle
// lock takes briefly, and a sync checks it after inspecting a container,
// just before routing it, so no change falls between the check and the
// route.
export class Deployer {
	private readonly buildQueue = new KeyedLock();
	private readonly builds = new Semaphore(1);
	private readonly lifecycle = new KeyedLock();
	private readonly admitting = new Mutex();
	private readonly starting = new Map<string, { task: Promise<void>; skipFailed: boolean }>();
	private readonly routing = new Mutex();
	private nextSync: Promise<void> | undefined;
	private readonly publishing = new Mutex();
	private readonly visitWrites = new Mutex();
	private nextPublish: Promise<void> | undefined;
	private upstreams: Route[] = [];
	// The address map the egress proxy last confirmed (tellProxy).
	private told: Record<string, string> = {};
	private readonly ready = new Set<string>();
	// Labels of records that have not expired, as of the last sync.
	private live = new Set<string>();
	// Containers the disk watchdog found over the limit. Visits do not start
	// them, whatever their record says, and the watchdog's run at startup
	// finds them again by their size.
	private readonly halted = new Set<string>();
	// Whether a disk watchdog run has measured every container since koid
	// started. Until one has, a visit does not start a stopped container:
	// it may be one koid stopped for disk use before a restart, whose record
	// could not say so.
	private diskChecked = false;
	// Settles when diskChecked becomes true. restore waits for it.
	private readonly diskMeasured = Promise.withResolvers<void>();
	// Running containers koid found outside the slice and has not managed to
	// stop yet. Nothing routes or wakes them, and the watchdog's timer tries
	// the stop again (stopMisplaced).
	private readonly misplaced = new Set<string>();
	// Visits taken from Activity whose write has not succeeded. Per label:
	// the end of their chain of renewals, checked against the record
	// (chainEnd), and visits not checked yet because the record could not be
	// read. Every decision on expiry counts the chain's end as a visit.
	// Changed only under visitWrites.
	private readonly renewals = new Map<string, number>();
	private readonly unchecked = new Map<string, number[]>();
	// The build of each label under way, for koi down to stop. buildQueue
	// runs one build of a label at a time, so a label has at most one. A
	// build leaves this at its cutover: what it does after that only tidies
	// up, and koi down removes the preview as it does any other.
	private readonly building = new Map<string, AbortController>();

	constructor(private readonly deps: DeployerDeps) {}

	// Accepts a request, records it as queued under a new attempt and starts
	// its build in the background. Throws before anything changes if the
	// request is unreadable, names an unknown recipe, targets a label that
	// belongs to another repo or ref, is gone from the upload store, or adds
	// a label the live list has no room for. The upload is claimed from the
	// acceptance until the build has copied its source, so the store cannot
	// drop it in between. Accepting the same request again while it builds,
	// or once it has deployed, changes nothing, so a retried koi up is safe.
	// Every other acceptance is a new attempt, with an id of its own on the
	// record: a request that failed builds again, and a build accepted
	// earlier for the same request id (before a koi down, say) cannot take
	// the record for its own.
	async up(id: string): Promise<{ label: string; queued: boolean }> {
		const request = await this.deps.uploads.request(id);
		const plan = await this.plan(request);
		const refused = keepRefused(plan);
		if (refused !== undefined) throw new UnsupportedRequestError(refused);
		const { label } = request;
		return this.lifecycle.run(label, async () => {
			const existing = await this.deps.store.get(label);
			if (existing?.deployment?.requestId === id) return { label, queued: false };
			if (existing?.requestId === id && IN_FLIGHT.has(existing.status)) {
				return { label, queued: existing.status === 'queued' };
			}
			if (existing !== undefined && !sameOwner(existing, request)) {
				const owner =
					existing.pr !== undefined ? `pull request ${existing.pr}` : `branch ${existing.branch}`;
				throw new OwnershipError(`${label} belongs to ${owner} of ${existing.repo}`);
			}
			// Before anything is queued or built: the build would replace the
			// deployment the lease holds. An expired lease does not count, and
			// queuedRecord drops it.
			const lease = existing?.lease;
			if (leaseHolds(lease, this.deps.now().getTime())) {
				throw new LeaseError(
					`${label} is leased by ${lease.holder} until ${lease.expiresAt}, and a build would replace the deployment the lease holds; run koi up again after it expires, or ask the holder to release it`,
				);
			}
			const attempt = randomId();
			// Before the record, so no accepted request ever lacks its claim;
			// the build releases it (see build), or this does if the request
			// is refused after all.
			await this.deps.uploads.claim(id);
			try {
				await this.admitting.run(async () => {
					if (existing === undefined || existing.status === 'expired') await this.checkRoom(label);
					await this.deps.store.upsert(label, (current) =>
						queuedRecord(current, request, attempt, plan.ttlDays, this.iso(), {
							wantsLoginKey: plan.loginKeyEnv !== undefined,
							newLoginKey: () => this.newSecret(newLoginKey()),
						}),
					);
				});
			} catch (err) {
				await this.deps.uploads
					.release(id)
					.catch((e: unknown) => this.deps.log(`releasing the upload of ${id}: ${message(e)}`));
				throw err;
			}
			const queued = this.buildQueue.busy(label) || this.builds.inUse > 0;
			// Queued while the lock is held, so builds start in acceptance order.
			void this.buildQueue
				.run(label, () => this.builds.run(() => this.build(plan, attempt)))
				.catch((err: unknown) => this.deps.log(`build ${id} for ${label}: ${message(err)}`));
			return { label, queued };
		});
	}

	// The plan of the recipe as it is when the request is accepted.
	private async plan(request: UpRequest): Promise<Plan> {
		if (request.recipe.kind === 'builtin') {
			const { name } = request.recipe;
			const { recipe, dir } = await this.deps.builtinRecipe(name);
			return planFrom(request, recipe, { name, dir });
		}
		return planFrom(request, request.recipe.recipe, undefined);
	}

	// Refuses a label the live list has no room for: once the box sleeps, a
	// preview missing from that list cannot wake it. The list knows its own
	// limit (an SSM parameter holds 4 KB; a file has none). Caller holds
	// `admitting`.
	private async checkRoom(label: string): Promise<void> {
		const live = (await this.records()).filter((r) => r.status !== 'expired').map((r) => r.label);
		const room = this.deps.live.room([...live, label]);
		if (room.ok) return;
		throw new CapacityError(
			`koi has ${live.length} live previews, and the list that lets a visit wake the box cannot take ${label} as well: ${room.reason}; remove a preview with koi down NAME and run koi up again`,
		);
	}

	private iso(): string {
		return this.deps.now().toISOString();
	}

	// A secret value just made: registered with the sanitizers before
	// anything is written or started with it.
	private newSecret(value: string): string {
		this.deps.registerSecret?.(value);
		return value;
	}

	// The app's own environment plus the egress proxy's settings and CA files.
	// Only the app's part is recorded on the deployment; the proxy settings
	// come from the daemon's config each time a container is created.
	private withEgress(
		env: Record<string, string>,
	): Pick<RunOptions, 'env'> & Partial<Pick<RunOptions, 'files'>> {
		const egress = this.deps.egress;
		if (egress === undefined) return { env };
		return { env: { ...env, ...egressEnv(egress) }, files: egressFiles(egress) };
	}

	// Whether `attempt` is still the label's latest.
	private async latest(label: string, attempt: string): Promise<boolean> {
		return (await this.deps.store.get(label))?.attempt === attempt;
	}

	// Records progress of the latest attempt; a superseded one writes nothing.
	private async setStatus(label: string, attempt: string, status: PreviewStatus): Promise<void> {
		await this.deps.store.update(label, (r) =>
			r.attempt === attempt ? { ...r, status, updatedAt: this.iso() } : r,
		);
	}

	// `accepted` is the plan up() made; a built-in recipe is built by the one
	// its copy gives (copyRecipe).
	private async build(accepted: Plan, attempt: string): Promise<void> {
		const { deps } = this;
		const { request } = accepted;
		const { label, id } = request;
		// Aborted when koi down removes the preview. The docker build and the
		// health check end at once; any other step runs to its end, and the
		// docker build, the health check or a read of the record (latest,
		// cutover) after it stops the build.
		const stop = new AbortController();
		const { signal } = stop;
		this.building.set(label, stop);
		// The claim up() took on the upload. Released once the source is
		// copied into the build directory, or when the attempt ends before
		// that, so the store may drop the entry. Every way out of this
		// function runs through the finally below, so no failure, the first
		// record read included, leaves the claim in place.
		let claimed = true;
		const releaseUpload = async () => {
			if (!claimed) return;
			claimed = false;
			await deps.uploads
				.release(id)
				.catch((err: unknown) => deps.log(`releasing the upload of ${id}: ${message(err)}`));
		};
		const work = join(deps.stateDir, 'builds', label, id);
		const src = join(work, 'src');
		const tarball = join(work, 'source.tar.gz');
		// Both names carry the whole request id, so only attempts of this
		// request use them, one at a time (buildQueue); removeEarlierAttempt
		// clears what an earlier one left.
		const image = `koi-preview/${label}:${id}`;
		const container = `koi-${label}-${id}`;
		const awake = setInterval(() => void deps.keepAwake(), 30_000);
		// Opened inside the try: if it cannot be, the request fails rather than
		// staying queued, where a retry of the same id would start nothing.
		let opened: BuildLog | undefined;
		// What this attempt may have created, for cleanup after a failure.
		let triedImage = false;
		let triedContainer = false;
		try {
			// A read that fails here is a failed build like any other: the
			// catch records it and the finally releases the claim.
			if (!(await this.latest(label, attempt))) {
				deps.log(`build ${id} for ${label}: superseded before it started`);
				return;
			}
			const log = await deps.buildLogs.open(label, attempt);
			opened = log;
			await this.setStatus(label, attempt, 'building');
			await deps.keepAwake();
			await this.makeRoom(log);
			await mkdir(work, { recursive: true });
			log.line(
				`request ${id}: ${request.repo} ${request.commit}${request.dirty ? ' (dirty)' : ''}${mergeNote(request)}`,
			);
			await deps.uploads.downloadSource(id, tarball);
			// The build has its own copy; the store may drop the entry now.
			await releaseUpload();
			await deps.extract(tarball, src);
			// A built-in recipe is built from a copy in this directory, never
			// from the installed one: scripts/deploy-host.sh replaces the
			// installed recipes before it restarts the old koid, so a build
			// that read them as they were replaced could mix two versions, and
			// a hash taken of them could be of a version the build did not
			// read. The copy comes first, and the plan the build follows is
			// read from the copy's recipe.json: the one up() made from the
			// installed file may be of a version replaced while the build
			// waited its turn, and the snapshot digests the copy, so the
			// deployment and the snapshot must describe the same bytes. The
			// Dockerfile and the "recipe" context are resolved inside the copy.
			// A copy that fails fails the build; a hash that fails (a symlink
			// in the recipe, say) loses the snapshot, not the deploy.
			const { plan, recipeCopy, recipe } = await this.copyRecipe(accepted, work, log);
			// The copy's recipe may have dropped its sliceFile since up()
			// accepted the request.
			const refused = keepRefused(plan);
			if (refused !== undefined) throw new Error(refused);
			// The copy, when the recipe brings its Dockerfile (planFrom sets
			// the root to the recipe only with a directory to copy).
			const recipeRoot = plan.dockerfileRoot === 'recipe' ? recipeCopy : undefined;
			const dockerfile = await deps.resolveInside(recipeRoot ?? src, plan.dockerfile);
			const context = await deps.resolveInside(src, plan.context);
			log.line(`building ${image}`);
			triedImage = true;
			await deps.docker.build({
				dockerfile,
				context,
				contexts: recipeRoot === undefined ? {} : { recipe: recipeRoot },
				...(request.keep !== undefined ? { buildArgs: { KOI_KEEP: request.keep.join(' ') } } : {}),
				tag: image,
				labels: { 'koi.preview': label, 'koi.request': id },
				timeoutMs: plan.buildTimeoutMinutes * 60_000,
				onLine: (line) => log.line(line),
				signal,
			});
			const user = chooseUser(plan.user, await deps.docker.imageUser(image));
			const imageDigest = await deps.docker.imageDigest(image);
			log.line(`image ${imageDigest}`);
			const slice =
				plan.sliceFile === undefined
					? undefined
					: await this.readSlice(image, plan.sliceFile, container, request, log);
			const loginKey = await this.loginKey(label, attempt, plan.loginKeyEnv);
			const env: Record<string, string> = {
				...plan.env,
				KOI_PREVIEW_LABEL: label,
				KOI_PREVIEW_URL: `https://${label}.${deps.domain}`,
				...(plan.loginKeyEnv !== undefined && loginKey !== undefined
					? { [plan.loginKeyEnv]: loginKey }
					: {}),
			};
			if (!(await this.latest(label, attempt))) {
				throw new Superseded('a newer request, or a retry of this one, replaced it');
			}
			await this.removeEarlierAttempt(container, log);
			log.line(`starting ${container} as ${user}`);
			// A new container: whatever a stopped one of that name was blocked
			// for does not apply.
			this.halted.delete(container);
			triedContainer = true;
			await this.startFresh(container, () =>
				deps.docker.run({
					name: container,
					image,
					network: deps.network,
					user,
					...this.withEgress(env),
					labels: { 'koi.preview': label, 'koi.request': id },
				}),
			);
			await this.setStatus(label, attempt, 'starting');
			await this.waitHealthy(
				container,
				plan.port,
				plan.healthPath,
				plan.healthTimeoutSeconds,
				signal,
			);
			// Before the cutover, and before the work directory goes: what a
			// verification run of this deployment will read. A failure here is
			// logged, not fatal: the deployment serves, and a run of it is
			// refused for want of inputs.
			if (deps.snapshotInputs !== undefined) {
				try {
					await deps.snapshotInputs({
						deploymentId: attempt,
						request,
						source: src,
						tarball,
						recipe,
					});
					log.line('kept the verification inputs');
				} catch (err) {
					log.line(`the verification inputs were not kept: ${message(err)}`);
				}
			}
			const deployment: Deployment = {
				requestId: id,
				deploymentId: attempt,
				imageDigest,
				commit: request.commit,
				...(request.merge !== undefined ? { merge: request.merge } : {}),
				image,
				container,
				port: plan.port,
				healthPath: plan.healthPath,
				healthTimeoutSeconds: plan.healthTimeoutSeconds,
				user,
				env,
				deployedAt: this.iso(),
				...(slice !== undefined ? { slice } : {}),
			};
			await this.lifecycle.run(label, async () => {
				await this.cutover(label, attempt, deployment, log, plan.loginKeyEnv !== undefined);
				// Deployed: koi down no longer has a build to stop.
				this.building.delete(label);
			});
			await deps.docker
				.pruneBuildCache(BUILD_CACHE_LIMIT)
				.catch((err: unknown) => deps.log(`pruning the build cache: ${message(err)}`));
		} catch (caught) {
			// A step koi down stopped fails with an error of its own (docker
			// buildx killed, say); the abort's reason says what happened.
			const err: unknown = signal.aborted ? signal.reason : caught;
			// Masked before the record keeps it: health-check failures carry
			// the container's own output.
			const reason = redact(message(err));
			const outcome = err instanceof Superseded ? `superseded: ${reason}` : `failed: ${reason}`;
			if (opened === undefined) {
				deps.log(`build ${id} for ${label}: ${outcome}`);
			} else {
				opened.line(outcome);
				// In the file before the record says the build failed: koi up stops
				// reading the log once it has read to the end after that.
				await opened
					.flush()
					.catch((e: unknown) => deps.log(`writing the build log of ${label}: ${message(e)}`));
			}
			if (!(err instanceof Superseded)) {
				// Only while the record is still this attempt's: a later one,
				// even of the same request, keeps its own status.
				await deps.store
					.update(label, (r) =>
						r.attempt === attempt
							? { ...r, status: 'failed', error: reason.slice(0, 2000), updatedAt: this.iso() }
							: r,
					)
					.catch((e: unknown) => deps.log(`recording that ${id} failed: ${message(e)}`));
			}
			await this.discard(
				triedContainer ? container : undefined,
				triedImage ? image : undefined,
			).catch((e: unknown) => deps.log(`sync after build ${id} for ${label}: ${message(e)}`));
		} finally {
			this.building.delete(label);
			await releaseUpload();
			clearInterval(awake);
			await opened
				?.close()
				.catch((err: unknown) => deps.log(`closing the build log of ${label}: ${message(err)}`));
			await rm(work, { recursive: true, force: true });
		}
	}

	// Copies a built-in recipe's installed directory into the build
	// directory, and gives the plan the build follows, read from the copy's
	// recipe.json, with the copy's path and, for the snapshot, the installed
	// directory and the digest of each file in the copy (none when the hash
	// fails). A request that brings its own recipe keeps the plan it was
	// accepted with, and nothing is copied.
	private async copyRecipe(
		accepted: Plan,
		work: string,
		log: BuildLog,
	): Promise<{
		plan: Plan;
		recipeCopy: string | undefined;
		recipe: { dir: string; files: Record<string, string> } | undefined;
	}> {
		const { builtin, request } = accepted;
		if (builtin === undefined) return { plan: accepted, recipeCopy: undefined, recipe: undefined };
		const recipeCopy = join(work, 'recipe');
		await cp(builtin.dir, recipeCopy, {
			recursive: true,
			dereference: false,
			errorOnExist: true,
			force: false,
		});
		const plan = planFrom(request, await this.deps.readRecipe(recipeCopy, builtin.name), builtin);
		try {
			return {
				plan,
				recipeCopy,
				recipe: { dir: builtin.dir, files: await hashRecipeDir(recipeCopy) },
			};
		} catch (err) {
			log.line(`the recipe's files were not hashed: ${message(err)}`);
			return { plan, recipeCopy, recipe: undefined };
		}
	}

	// What the build kept of the project: the JSON object the recipe's build
	// wrote to its sliceFile in the image, read before the container starts.
	// The build fails when the file is missing, unreadable, or not a JSON
	// object of at most MAX_DEPLOYMENT_SLICE_BYTES.
	private async readSlice(
		image: string,
		path: string,
		container: string,
		request: UpRequest,
		log: BuildLog,
	): Promise<Record<string, unknown>> {
		const what = `the recipe's sliceFile ${path}`;
		let text: string;
		try {
			text = await this.deps.docker.readImageFile({
				image,
				path,
				name: readerName(container),
				labels: { 'koi.preview': request.label, 'koi.request': request.id },
				maxBytes: MAX_SLICE_FILE_BYTES,
				log: (line) => this.deps.log(line),
			});
		} catch (err) {
			throw new Error(`${what}: ${message(err)}`);
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch (err) {
			throw new Error(`${what} is not JSON: ${message(err)}`);
		}
		const slice = DeploymentSliceSchema.safeParse(parsed);
		if (!slice.success) {
			throw new Error(
				`${what} is not a JSON object of at most ${MAX_DEPLOYMENT_SLICE_BYTES} bytes: ${slice.error.issues[0]?.message ?? 'invalid'}`,
			);
		}
		log.line(`read the slice from ${path}`);
		return slice.data;
	}

	// The record's login key, for a plan whose recipe names a variable to
	// carry it; none otherwise. up() makes the key when the installed recipe
	// names the variable, and the copy the build planned from may have
	// gained it since: then the key is made here, registered before it is
	// written, as up() does, and before any container sees it. An attempt
	// the record has left behind makes none.
	private async loginKey(
		label: string,
		attempt: string,
		loginKeyEnv: string | undefined,
	): Promise<string | undefined> {
		if (loginKeyEnv === undefined) return undefined;
		const record = await this.deps.store.update(label, (r) =>
			r.attempt === attempt && r.loginKey === undefined
				? { ...r, loginKey: this.newSecret(newLoginKey()), updatedAt: this.iso() }
				: r,
		);
		return record?.loginKey;
	}

	// Removes a container with this attempt's name, which an earlier attempt
	// of the same request left because Caddy refused the routes without it
	// (see discard), so that this attempt can create its own. As in discard,
	// it goes only once routes without it are applied. Throws, failing the
	// attempt, if a recorded deployment uses it or Caddy refuses again.
	private async removeEarlierAttempt(container: string, log: BuildLog): Promise<void> {
		const { deps } = this;
		if (!(await deps.docker.inspect(container, deps.network)).exists) return;
		if ((await this.records()).some((r) => r.deployment?.container === container)) {
			throw new Error(`${container} already exists, and a deployment uses it`);
		}
		log.line(`removing ${container}, left by an earlier attempt of this request`);
		try {
			await this.unroute({ containers: [container], images: [] });
		} catch (err) {
			throw new Error(
				`${container}, left by an earlier attempt of this request, stays until Caddy takes routes without it; run koi up again: ${message(err)}`,
			);
		}
	}

	// Makes room for a build on the disk Docker keeps its data on: under
	// wantFreeBytes free, trims the build cache to BUILD_CACHE_LOW_DISK, and
	// refuses the build if that leaves under minFreeBytes. Previews can still
	// fill the disk between two watchdog runs; this keeps a build from being
	// what does.
	private async makeRoom(log: BuildLog): Promise<void> {
		const { deps } = this;
		const before = await deps.diskSpace();
		if (before.free >= wantFreeBytes(before.size)) return;
		log.line(
			`${gib(before.free)} GiB of ${gib(before.size)} GiB free; trimming the build cache to ${BUILD_CACHE_LOW_DISK}`,
		);
		await deps.docker
			.pruneBuildCache(BUILD_CACHE_LOW_DISK)
			.catch((err: unknown) => log.line(`trimming the build cache: ${message(err)}`));
		const after = await deps.diskSpace();
		const need = minFreeBytes(after.size);
		if (after.free < need) {
			throw new Error(
				`the box is short of disk: ${gib(after.free)} GiB of ${gib(after.size)} GiB free after trimming the build cache, and a build needs ${gib(need)} GiB; remove previews with koi down and run koi up again`,
			);
		}
	}

	// Replaces what serves a label with a healthy new deployment. Caller holds
	// the label's lifecycle lock. The order means a failure at any step leaves
	// the record naming a container that exists:
	// 1. mark the new container ready and route to it; if Caddy refuses,
	//    nothing else changed and the previous deployment keeps serving, and
	//    discard takes the new one out of `ready` again. Caddy may have taken
	//    the routes before the apply failed (caddy.ts loads twice): then it
	//    serves the new container, while the record and `upstreams` keep the
	//    previous one, until the sync after the failure or a later one puts
	//    the previous deployment back. acquireLease syncs for that reason;
	// 2. write "ready" to the build log, then record the new deployment, still
	//    under the routing mutex, so no sync can read the old record in
	//    between and route back to the old one;
	// 3. sync, which also has the live list published;
	// 4. remove the previous container and image. The routes applied in 1
	//    no longer name it, and no sync after 2 can, so Docker may give its
	//    address to another preview.
	// A crash between 1 and 2 leaves the record on the previous deployment and
	// the new container unreferenced, which reconcile removes.
	// usesLoginKey: whether the new deployment's recipe has a loginKeyEnv. If
	// not, the record's login key goes with the deployment that used it.
	private async cutover(
		label: string,
		attempt: string,
		deployment: Deployment,
		log: BuildLog,
		usesLoginKey: boolean,
	): Promise<void> {
		const { deps } = this;
		const current = await deps.store.get(label);
		if (current === undefined) throw new Superseded('the preview was removed while it built');
		if (current.attempt !== attempt) {
			throw new Superseded(
				current.requestId === deployment.requestId
					? 'a retry of this request replaced it'
					: `request ${current.requestId} replaced it`,
			);
		}
		const previous = current.deployment;
		await this.routing.run(async () => {
			this.ready.add(deployment.container);
			const records = (await this.records()).map((r) =>
				r.label === label ? { ...r, deployment } : r,
			);
			const routes = await this.routesFor(records);
			if (!routes.some((r) => r.label === label)) {
				throw new Error(`${deployment.container} stopped before it could be routed`);
			}
			await this.applyRoutes(routes);
			// In the file before the record says running: koi up stops reading the
			// log once it has read to the end after that.
			log.line('ready');
			await log
				.flush()
				.catch((err: unknown) => deps.log(`writing the build log of ${label}: ${message(err)}`));
			await deps.store.update(label, (r) => {
				const { error: _cleared, loginKey, ...rest } = r;
				return {
					...rest,
					status: 'running',
					deployment,
					updatedAt: this.iso(),
					...(usesLoginKey && loginKey !== undefined ? { loginKey } : {}),
				};
			});
			if (previous !== undefined && previous.container !== deployment.container) {
				this.ready.delete(previous.container);
			}
		});
		// The new version is live; what follows only tidies up.
		await this.sync().catch((err: unknown) =>
			deps.log(`sync after deploying ${label}: ${message(err)}`),
		);
		if (previous !== undefined && previous.container !== deployment.container) {
			await this.removeAll(leftoversOf(previous));
		}
	}

	// Removes containers, then images, logging rather than failing: no record
	// names them, and reconcile removes whatever is left. The caller has
	// already taken the containers out of `ready`.
	private async removeAll({ containers, images }: Leftovers): Promise<void> {
		const { deps } = this;
		for (const c of containers) {
			await deps.docker
				.remove(c)
				.then(() => {
					this.halted.delete(c);
					this.misplaced.delete(c);
				})
				.catch((err: unknown) => deps.log(`removing ${c}: ${message(err)}`));
		}
		for (const image of images) {
			await deps.docker
				.removeImage(image)
				.catch((err: unknown) => deps.log(`removing ${image}: ${message(err)}`));
		}
	}

	// Removes what a failed or superseded attempt created, unless a recorded
	// deployment uses it. The sync goes first even though the attempt was
	// never recorded: Caddy may have taken a cutover it then reported as
	// failed, and so route the label to the attempt's container.
	private async discard(container: string | undefined, image: string | undefined): Promise<void> {
		const used = new Set(
			(await this.records()).flatMap((r) =>
				r.deployment === undefined ? [] : [r.deployment.container, r.deployment.image],
			),
		);
		await this.unroute({
			containers: container !== undefined && !used.has(container) ? [container] : [],
			images: image !== undefined && !used.has(image) ? [image] : [],
		});
	}

	// Syncs, then removes `leftovers`. The caller has already changed the
	// records so that none names them. A container is removed only once
	// routes without it have been applied: Docker can give a removed
	// container's address to another preview, and a route left behind would
	// send this label's visitors there. When the sync fails nothing is
	// removed and its error is thrown; reconcile, or a retried koi down,
	// removes them later.
	private async unroute(leftovers: Leftovers): Promise<void> {
		await this.syncWithout(leftovers.containers);
		await this.removeAll(leftovers);
	}

	// Applies routes that include none of `containers`, which are no longer
	// ready, so none of them can be routed again until a health check passes.
	// Throws the sync's error, after logging that they are kept.
	private async syncWithout(containers: string[]): Promise<void> {
		// Out of `ready` before the sync is asked for, so the run it joins
		// starts after the change.
		await this.setReady(containers, false);
		try {
			await this.sync();
		} catch (err) {
			if (containers.length > 0) {
				this.deps.log(
					`keeping ${containers.join(', ')} until Caddy takes routes without them: ${message(err)}`,
				);
			}
			throw err;
		}
	}

	// `signal`, when given, ends the wait with its reason.
	private async waitHealthy(
		container: string,
		port: number,
		path: string,
		timeoutSeconds: number,
		signal?: AbortSignal,
	) {
		const { deps } = this;
		const deadline = deps.now().getTime() + timeoutSeconds * 1000;
		// A slow start can outlast the idle limit, and nothing routes the
		// container yet to count as activity, so the wait itself keeps the box
		// awake.
		let awakeAt = deps.now().getTime();
		for (;;) {
			signal?.throwIfAborted();
			if (deps.now().getTime() - awakeAt >= 30_000) {
				awakeAt = deps.now().getTime();
				await deps.keepAwake();
			}
			const state = await deps.docker.inspect(container, deps.network);
			if (!state.running) {
				throw new Error(
					`the container stopped before it answered\n${await deps.docker.logs(container, 40)}`,
				);
			}
			if (state.ip !== undefined && (await deps.probe(`http://${state.ip}:${port}${path}`))) return;
			if (deps.now().getTime() >= deadline) {
				throw new Error(
					`no answer on port ${port} at ${path} after ${timeoutSeconds}s\n${await deps.docker.logs(container, 40)}`,
				);
			}
			await deps.sleep(1000);
		}
	}

	// Starts a stopped preview's container. Called when someone visits a
	// preview that is not routed, and by restore when koid starts. Runs under
	// the label's lifecycle lock, and visitors who ask while a start is in
	// progress share it. A preview past its ttl is expired instead. With
	// `skipFailed` (restore), a preview whose last start failed is left
	// stopped, judged under the lock from the record as it is then: a visit
	// that failed just before still leaves it for the next visit.
	ensureRunning(label: string, skipFailed = false): Promise<void> {
		const inFlight = this.starting.get(label);
		if (inFlight !== undefined) {
			// A visit that finds restore's start in progress waits for it, then
			// starts the preview itself: restore's start may have left it
			// stopped after a failed start, which a visit tries again. When
			// restore did start it, the visit's start finds it running.
			if (inFlight.skipFailed && !skipFailed) {
				const retry = () => this.ensureRunning(label);
				return inFlight.task.then(retry, retry);
			}
			return inFlight.task;
		}
		const task = this.lifecycle
			.run(label, () => this.start(label, skipFailed))
			.finally(() => this.starting.delete(label));
		this.starting.set(label, { task, skipFailed });
		return task;
	}

	// Caller holds the label's lifecycle lock.
	private async start(label: string, skipFailed = false): Promise<void> {
		const { deps } = this;
		const record = await deps.store.get(label);
		if (record === undefined || record.status === 'expired') return;
		if (skipFailed && record.error?.startsWith(WAKE_FAILED)) return;
		const now = deps.now().getTime();
		if (overdue(record, now)) {
			// A visit counted in time and not yet written renews it.
			await this.flushVisits();
			if (await this.retire(label, now)) return;
		}
		const d = record.deployment;
		if (
			d === undefined ||
			d.halted !== undefined ||
			this.halted.has(d.container) ||
			this.misplaced.has(d.container)
		) {
			return;
		}
		await deps.keepAwake();
		const state = await deps.docker.inspect(d.container, deps.network);
		// The watchdog's timer measures it again, and the next visit after
		// that starts it.
		if (state.exists && !state.running && !this.diskChecked) return;
		if (!state.running || !this.ready.has(d.container)) {
			// Not routed again until it answers, whatever an earlier check said.
			await this.setReady([d.container], false);
			try {
				if (!state.running && state.exists) {
					await this.startFresh(d.container, () => deps.docker.start(d.container));
				} else if (!state.exists) {
					await this.startFresh(d.container, () =>
						deps.docker.run({
							name: d.container,
							image: d.image,
							network: deps.network,
							user: d.user,
							...this.withEgress(d.env),
							labels: { 'koi.preview': label, 'koi.request': d.requestId },
						}),
					);
				}
				await this.waitHealthy(d.container, d.port, d.healthPath, d.healthTimeoutSeconds);
			} catch (err) {
				const reason = redact(`${WAKE_FAILED}${message(err)}`).slice(0, 2000);
				deps.log(`starting ${label}: ${message(err)}`);
				// Recorded only when Docker or the health check failed: restore
				// skips a preview whose start failed, and a routing failure
				// passes once Caddy or the egress proxy recovers. A record that
				// cannot be written (a full disk, say) must not keep the
				// container running, unrouted, below.
				if (!(err instanceof RoutingFailed)) {
					await deps.store
						.update(label, (r) =>
							r.deployment?.container === d.container
								? { ...r, error: reason, updatedAt: this.iso() }
								: r,
						)
						.catch((e: unknown) =>
							deps.log(`recording that ${label} did not start: ${message(e)}`),
						);
				}
				// Stopped rather than left running unrouted, once routes without
				// it are applied: Docker may give a stopped container's address
				// to another preview. No retry here: the next visit tries again.
				try {
					await this.syncWithout([d.container]);
					await deps.docker.stop(d.container);
				} catch (e) {
					deps.log(`stopping ${d.container}: ${message(e)}`);
				}
				return;
			}
			// Routed only in the slice. One outside it (kept running through
			// a Docker restart, or started there) is stopped instead, and its
			// next start puts it in the slice.
			if (!(await this.inSlice(d.container))) {
				await this.evict([d.container]).catch((err: unknown) =>
					deps.log(`taking ${d.container} out of the routes: ${message(err)}`),
				);
				return;
			}
			await this.setReady([d.container], true);
			await deps.store.update(label, (r) => {
				if (!r.error?.startsWith(WAKE_FAILED)) return r;
				const { error: _cleared, ...rest } = r;
				return rest;
			});
		}
		await this.sync();
	}

	// Starts every preview that serves and is not routed, each as a visit
	// would (ensureRunning), and resolves once every start has ended.
	// Returns the labels routed after their start. koid calls it at startup
	// without waiting: preview containers run with --restart no (docker.ts,
	// runArgs), so the box stopping leaves every one stopped, and without
	// this a preview started again only once a request reached koid.
	//
	// One start at a time, health check included: each container may use
	// the memory in CONTAINER_LIMITS (docker.ts), and several at their
	// start-up peak together can exceed the slice's memory ceiling, which
	// kills one that would have started alone. A visit does not wait its
	// preview's turn: it starts the preview at once, or shares a start
	// already in progress. Each preview's record is read again just before
	// its turn, so one that a visit started or failed to start meanwhile is
	// skipped.
	//
	// The record's own deployment starts, from its container or, if that is
	// gone, from its image with the recorded environment, so the URL, the
	// deployment a lease holds and the login key stay what they were. Each
	// container is routed only once it answers its health check, as on any
	// wake. Not started: a deployment halted for disk use, a preview whose
	// container did not start or answer last time (koid stopped it on
	// purpose; a visit still tries again), and a preview past its ttl, which
	// expire() at startup has already retired and start() would retire
	// rather than start. Call it after expire(). It first waits for a disk
	// watchdog run to measure the containers, the one at startup or, if that
	// failed, a later one on the timer: until one has, start() starts no
	// stopped container.
	async restore(): Promise<string[]> {
		await this.diskMeasured.promise;
		const restored: string[] = [];
		for (const { label } of await this.records()) {
			try {
				const r = await this.deps.store.get(label);
				const d = r?.deployment;
				if (
					r === undefined ||
					d === undefined ||
					d.halted !== undefined ||
					this.ready.has(d.container) ||
					r.error?.startsWith(WAKE_FAILED) ||
					this.lapsed(r, this.deps.now().getTime())
				) {
					continue;
				}
				await this.ensureRunning(label, true);
				if (this.ready.has(d.container)) restored.push(label);
			} catch (err) {
				this.deps.log(`starting ${label}: ${message(err)}`);
			}
		}
		return restored.sort();
	}

	async view(label: string): Promise<PreviewView> {
		const now = this.deps.now().getTime();
		let record = await this.deps.store.get(label);
		if (record !== undefined && overdue(record, now)) {
			// A visit counted in time and not yet written renews it.
			await this.flushVisits();
			record = await this.deps.store.get(label);
		}
		if (record === undefined) return { kind: 'unknown' };
		if (record.status === 'expired') return { kind: 'expired' };
		if (this.lapsed(record, now)) return { kind: 'overdue' };
		const d = record.deployment;
		if (d?.halted === 'disk' || (d !== undefined && this.halted.has(d.container))) {
			return { kind: 'halted' };
		}
		if (d !== undefined) {
			// A container Caddy does not route to cannot be reached, however
			// it is doing, so it counts as stopped and the visit wakes it.
			const route = this.upstreams.find((r) => r.label === label);
			if (route === undefined) return { kind: 'stopped' };
			// Routed, but it may have exited since the last sync. Then the
			// route goes, and the visit starts it again.
			const state = await this.deps.docker.inspect(d.container, this.deps.network);
			if (state.running && route.upstream === `${state.ip}:${d.port}`) return { kind: 'running' };
			void this.sync().catch((err: unknown) =>
				this.deps.log(`sync after ${d.container} stopped: ${message(err)}`),
			);
			return { kind: 'stopped' };
		}
		if (record.status === 'failed')
			return { kind: 'failed', error: record.error ?? 'the build failed' };
		return { kind: 'building' };
	}

	// Rebuilds Caddy's routes from the containers that are running and ready.
	// One run at a time: a call made while a run is in progress waits for the
	// next run, which reads the records only when it starts, so the last call
	// always applies the latest state. Calls that arrive before that next run
	// starts share it.
	//
	// Resolves once Caddy has taken the routes, and rejects only if it has
	// not. Each run then has the live list published apart from it, so a
	// caller waiting for routes without a container never waits on, or
	// fails with, the publication.
	sync(): Promise<void> {
		if (this.nextSync !== undefined) return this.nextSync;
		const run: Promise<void> = this.routing.run(async () => {
			if (this.nextSync === run) this.nextSync = undefined;
			try {
				await this.syncNow();
			} finally {
				void this.publishLive();
			}
		});
		this.nextSync = run;
		return run;
	}

	// Caller holds `routing`.
	private async syncNow(): Promise<void> {
		await this.applyRoutes(await this.currentRoutes());
	}

	// The routes the records call for, from Docker's view of the containers.
	// Caller holds `routing`.
	private async currentRoutes(): Promise<Route[]> {
		const records = await this.records();
		this.live = new Set(records.filter((r) => r.status !== 'expired').map((r) => r.label));
		return this.routesFor(records);
	}

	// Tells the egress proxy the address of every routed container and its
	// preview, then has Caddy route them. Throws, leaving `upstreams` as it
	// was, when either does not take them: a caller removing a container
	// then keeps it, so its address is not free while the proxy may still
	// map it to its preview. Caller holds `routing`.
	private async applyRoutes(routes: Route[]): Promise<void> {
		await this.tellProxy(routes);
		await this.deps.caddy.apply(routes);
		this.upstreams = routes;
	}

	// Sends the egress proxy the address map for `routes`, trying three
	// times a second apart. Caller holds `routing`.
	private async tellProxy(routes: Route[]): Promise<void> {
		const { previews } = this.deps;
		if (previews === undefined) return;
		const addresses = previewAddresses(routes);
		for (let attempt = 1; ; attempt++) {
			try {
				await previews(addresses);
				this.told = addresses;
				return;
			} catch (err) {
				if (attempt === 3) {
					throw new Error(`the egress proxy did not take the preview addresses: ${message(err)}`);
				}
				await this.deps.sleep(1000);
			}
		}
	}

	// Starts a preview container with `start` (docker run or docker start),
	// which gives it an address. Docker hands out an address as soon as a
	// container stops, and a container can die on its own: while the egress
	// proxy still maps that address to the dead container's preview, the new
	// container could use that preview's koi tokens. So, under `routing`, a
	// sync first takes dead containers out of the routes and the proxy's map,
	// and the proxy confirms, before the start. If the new container's
	// address is one the confirmed map still names, its holder died between
	// the two, and the map goes to the proxy again at once. When the proxy or
	// Caddy does not take the routes, this throws RoutingFailed; a Docker
	// error, reading the containers or starting this one, is thrown as it is.
	private async startFresh(container: string, start: () => Promise<void>): Promise<void> {
		await this.routing.run(async () => {
			const before = await this.currentRoutes();
			await this.applyRoutes(before).catch(routingFailed);
			await start();
			const { ip } = await this.deps.docker.inspect(container, this.deps.network);
			if (ip !== undefined && this.told[ip] !== undefined) {
				const after = await this.currentRoutes();
				await this.applyRoutes(after).catch(routingFailed);
			}
		});
	}

	// Publishes the labels allowed to wake the box, as of the last sync. One
	// run at a time, like sync: calls made while one runs share the next,
	// which reads the labels when it starts. A failure is logged, and the
	// next sync publishes again.
	private publishLive(): Promise<void> {
		if (this.nextPublish !== undefined) return this.nextPublish;
		const run: Promise<void> = this.publishing.run(async () => {
			if (this.nextPublish === run) this.nextPublish = undefined;
			try {
				await this.deps.live.publish([...this.live]);
			} catch (err) {
				this.deps.log(`publishing the live previews: ${message(err)}; the next sync tries again`);
			}
		});
		this.nextPublish = run;
		return run;
	}

	// Resolves once every publication of the live list started so far has
	// finished.
	published(): Promise<void> {
		return this.publishing.run(async () => undefined);
	}

	// Whether a request for this label is a visit to a preview: a label with
	// a record that has not expired, as of the last sync. Requests for
	// anything else (scanners, typos, expired previews) do not keep the box
	// awake.
	isLive(label: string): boolean {
		return this.live.has(label);
	}

	private records(): Promise<PreviewRecord[]> {
		return this.deps.store.list((file, err) => this.deps.log(`skipping ${file}: ${message(err)}`));
	}

	// A route for each record whose container is ready and running. A
	// container found stopped is no longer ready: it gets a new address when
	// it starts, and must pass a health check there first. Caller holds
	// `routing`.
	private async routesFor(records: PreviewRecord[]): Promise<Route[]> {
		const routes: Route[] = [];
		for (const r of records) {
			const d = r.deployment;
			if (d === undefined || r.status === 'expired' || !this.ready.has(d.container)) continue;
			const state = await this.deps.docker.inspect(d.container, this.deps.network);
			// Checked again now that the inspection is back, with nothing
			// awaited between the check and the route: the address may be a
			// restart's that has not answered yet.
			if (!this.ready.has(d.container)) continue;
			if (state.running && state.ip !== undefined) {
				routes.push({ label: r.label, upstream: `${state.ip}:${d.port}` });
			} else {
				this.ready.delete(d.container);
			}
		}
		return routes;
	}

	// Adds containers to `ready` or takes them out, under `routing`, so the
	// set never changes while a sync computes routes. A caller holding a
	// lifecycle lock may call this; one holding `routing` changes the set
	// directly.
	private async setReady(containers: string[], ready: boolean): Promise<void> {
		if (containers.length === 0) return;
		await this.routing.run(async () => {
			for (const c of containers) {
				if (ready) this.ready.add(c);
				else this.ready.delete(c);
			}
		});
	}

	// Resolves once every build queued for this label so far has finished.
	settled(label: string): Promise<void> {
		return this.buildQueue.run(label, async () => undefined);
	}

	// Container addresses currently routed, for the open-connection check.
	runningUpstreams(): Route[] {
		return this.upstreams;
	}

	// Removes the record first, then the routes, then the label's containers
	// and images, so a crash part way leaves only unreferenced containers,
	// which reconcile removes. If Caddy does not take the routes without the
	// preview, the containers stay and down throws. Running it again removes
	// them: whatever carries the label once its record is gone is left over,
	// from this or an earlier removal or expiry. A preview under a lease is
	// refused unless `force` is set: a run holds it.
	//
	// A build of the label under way is stopped (see build): it records and
	// routes nothing, removes what it made, and frees its slot. down does not
	// wait for that: the build may be in a step that ends on its own, and it
	// takes the lifecycle lock for its cutover. A build still queued finds
	// the record gone when its turn comes, and skips itself.
	async down(label: string, options: { force?: boolean } = {}): Promise<boolean> {
		return this.lifecycle.run(label, async () => {
			const { docker, store } = this.deps;
			const record = await store.get(label);
			const lease = record?.lease;
			if (options.force !== true && leaseHolds(lease, this.deps.now().getTime())) {
				throw new LeaseError(
					`${label} is leased by ${lease.holder} until ${lease.expiresAt}; run koi down ${label} --force to remove it anyway`,
				);
			}
			if (record !== undefined) await store.remove(label);
			// Once the record is gone, so that the build finds it gone at every
			// later step. What the build made goes with what is listed below,
			// or with the build's own discard if it made it after that.
			this.building.get(label)?.abort(new Superseded('koi down removed the preview'));
			const leftovers = leftoversOf(record?.deployment);
			for (const c of await docker.list()) {
				if (c.label === label) leftovers.containers.push(c.name);
			}
			for (const image of await docker.listImages()) {
				if (image.startsWith(`koi-preview/${label}:`)) leftovers.images.push(image);
			}
			leftovers.containers = [...new Set(leftovers.containers)];
			leftovers.images = [...new Set(leftovers.images)];
			const nothing = leftovers.containers.length === 0 && leftovers.images.length === 0;
			if (record === undefined && nothing) return false;
			try {
				await this.unroute(leftovers);
			} catch (err) {
				const kept = leftovers.containers.join(', ');
				throw new Error(
					kept === ''
						? `${label} is removed, but Caddy did not take the new routes: ${message(err)}`
						: `${label} is removed, but ${kept} stays until Caddy takes routes without it; run koi down again: ${message(err)}`,
				);
			}
			return true;
		});
	}

	// Takes a lease on the preview for `ttlSeconds`, bound to the deployment
	// serving it, and returns both. Refused while another lease holds, while
	// a build of the label is in progress (it would replace what serves as
	// soon as it is healthy), when nothing serves, when the routes are not
	// settled (below), and when what serves is not running and routed, since
	// a run could not reach it. Under the label's lifecycle lock, as up() is:
	// once this succeeds, no request is queued for the label until the lease
	// expires or is released, and a request queued before it was refused
	// here, so no cutover happens under a lease. Taking a lease counts as
	// using the preview (updatedAt), so it cannot expire under one.
	//
	// The lease names the record's deployment, so that must be what visitors
	// reach. A sync that succeeds makes it so: it applies the routes the
	// records call for, and resolves only once the egress proxy and Caddy
	// have taken them, so Caddy, `upstreams` and the record agree, and view()
	// then checks that the container runs at the routed address. Without
	// one, Caddy may run routes the last apply failed part way through (a
	// cutover whose first load Caddy took, see cutover), so a lease could
	// name a build visitors do not reach, and a later sync could switch what
	// they reach under the lease.
	async acquireLease(label: string, holder: string, ttlSeconds: number): Promise<LeaseReply> {
		return this.lifecycle.run(label, async () => {
			const now = this.deps.now();
			const record = await this.deps.store.get(label);
			if (record === undefined) throw new NoSuchPreviewError(NO_SUCH_PREVIEW);
			const held = record.lease;
			if (leaseHolds(held, now.getTime())) {
				throw new LeaseError(`${label} is leased by ${held.holder} until ${held.expiresAt}`);
			}
			if (IN_FLIGHT.has(record.status)) {
				throw new LeaseError(
					`${label} is building request ${record.requestId}, which will replace what serves; run koi lease again once it has finished`,
				);
			}
			const deployment = deploymentIdentity(record);
			if (deployment === undefined) {
				throw new LeaseError(
					record.deployment !== undefined && record.deployment.halted === undefined
						? `${label} serves a deployment made before koid recorded deployment ids; run koi up to replace it, then lease it`
						: `${label} has no serving deployment to lease`,
				);
			}
			// Routes settled: Caddy runs the routes koid computed from the
			// records, and `upstreams` holds them. Only a sync that succeeds
			// says so; one that fails leaves what visitors reach uncertain.
			try {
				await this.sync();
			} catch (err) {
				throw new LeaseError(
					`the routes of ${label} are not settled: ${message(err)}; what visitors reach may not be the recorded deployment, so run koi lease again once Caddy takes routes`,
				);
			}
			// The record says what was deployed, not what a visitor gets. After
			// the box wakes, or a start fails, the container is stopped or has
			// no route while the record still says running, and a lease on it
			// would hold a preview nobody can reach while refusing the build
			// that would replace it. view() is what the health check answers
			// from: running means the container runs and Caddy routes to it,
			// and after the sync above that route is the record's.
			const view = await this.view(label);
			if (view.kind === 'overdue') {
				throw new LeaseError(
					`${label} is past its ttl and expires on its next visit; run koi up to deploy it again, then lease it`,
				);
			}
			if (view.kind !== 'running') {
				throw new LeaseError(
					`${label} is not running; open https://${label}.${this.deps.domain}/ to start it, then run koi lease again`,
				);
			}
			// The sync and the view above can take a while; the lease starts
			// when it is granted, not when it was asked for, or a short lease
			// could be expired before it is saved.
			const granted = this.deps.now();
			const lease: Lease = {
				leaseId: randomId(),
				deploymentId: deployment.deploymentId,
				holder,
				acquiredAt: granted.toISOString(),
				expiresAt: new Date(granted.getTime() + ttlSeconds * 1000).toISOString(),
			};
			await this.deps.store.update(label, (r) => ({ ...r, lease, updatedAt: this.iso() }));
			return { lease, deployment };
		});
	}

	// The deployment a verification run attaches to: the one the lease with
	// this id holds, while it holds. A run calls this before it touches the
	// app's container (verification-network.ts), and again whenever it must
	// be sure the lease still stands. Throws when the preview has no record,
	// the lease is not the one in force, or what serves is no longer the
	// deployment the lease named.
	async leasedDeployment(
		label: string,
		leaseId: string,
	): Promise<{ container: string; port: number; deploymentId: string }> {
		const record = await this.deps.store.get(label);
		if (record === undefined) throw new NoSuchPreviewError(NO_SUCH_PREVIEW);
		const lease = record.lease;
		if (lease?.leaseId !== leaseId || !leaseHolds(lease, this.deps.now().getTime())) {
			throw new NoSuchLeaseError(NO_SUCH_LEASE);
		}
		const d = record.deployment;
		if (d === undefined || d.halted !== undefined || d.deploymentId !== lease.deploymentId) {
			throw new LeaseError(`${label} no longer serves the deployment the lease holds`);
		}
		return { container: d.container, port: d.port, deploymentId: d.deploymentId };
	}

	// Extends the lease with this id to `ttlSeconds` from now, and never past
	// LEASE_MAX_SECONDS from when it was taken, so a holder that keeps
	// renewing still gives the label back within the cap. A verification
	// run renews while it is legitimately still working on the app, within
	// its own budget (verification.ts). Throws when the preview has no
	// record, or the lease is not the one in force: an expired lease is not
	// revived, since another holder may have taken the label meanwhile.
	async renewLease(label: string, leaseId: string, ttlSeconds: number): Promise<Lease> {
		return this.lifecycle.run(label, async () => {
			const now = this.deps.now();
			const record = await this.deps.store.get(label);
			if (record === undefined) throw new NoSuchPreviewError(NO_SUCH_PREVIEW);
			const held = record.lease;
			if (held?.leaseId !== leaseId || !leaseHolds(held, now.getTime())) {
				throw new NoSuchLeaseError(NO_SUCH_LEASE);
			}
			const cap = Date.parse(held.acquiredAt) + LEASE_MAX_SECONDS * 1000;
			const until = Math.min(now.getTime() + ttlSeconds * 1000, cap);
			// Never shortened: a renewal asks for at least what it has.
			if (until <= Date.parse(held.expiresAt)) return held;
			const lease: Lease = { ...held, expiresAt: new Date(until).toISOString() };
			await this.deps.store.update(label, (r) =>
				r.lease?.leaseId === leaseId ? { ...r, lease, updatedAt: this.iso() } : r,
			);
			return lease;
		});
	}

	// Ends the lease with this id, expired or not. Throws when the preview
	// has no record, or holds no lease with that id.
	async releaseLease(label: string, leaseId: string): Promise<void> {
		await this.lifecycle.run(label, async () => {
			const record = await this.deps.store.get(label);
			if (record === undefined) throw new NoSuchPreviewError(NO_SUCH_PREVIEW);
			if (record.lease?.leaseId !== leaseId) throw new NoSuchLeaseError(NO_SUCH_LEASE);
			await this.deps.store.update(label, (r) =>
				r.lease?.leaseId === leaseId ? { ...withoutLease(r), updatedAt: this.iso() } : r,
			);
		});
	}

	// Expires every preview nobody has visited for its ttlDays, then syncs,
	// which also repairs routes and the live list if they drifted. The record
	// stays, marked expired, so the address can say so instead of "unknown".
	// Leases past their expiry go too: nothing reads them, but a record
	// should not carry a hold that no longer holds.
	async expire(): Promise<string[]> {
		const now = this.deps.now().getTime();
		// Visits counted by now and not yet written may renew a preview.
		await this.flushVisits();
		const expired: string[] = [];
		for (const r of await this.records()) {
			if (r.lease !== undefined && !leaseHolds(r.lease, now)) {
				await this.lifecycle
					.run(r.label, () =>
						this.deps.store.update(r.label, (current) =>
							current.lease === undefined || leaseHolds(current.lease, now)
								? current
								: withoutLease(current),
						),
					)
					.catch((err: unknown) =>
						this.deps.log(`dropping the expired lease on ${r.label}: ${message(err)}`),
					);
			}
			if (!overdue(r, now)) continue;
			try {
				if (await this.lifecycle.run(r.label, () => this.retire(r.label, now))) {
					expired.push(r.label);
				}
			} catch (err) {
				this.deps.log(`expiring ${r.label}: ${message(err)}; the next run tries again`);
			}
		}
		await this.sync();
		return expired;
	}

	// Marks the preview expired if it is still overdue when read under the
	// store's lock, counting visits that could not be written or checked yet,
	// then takes it out of the routes and removes its container and image.
	// If the record cannot be read, it throws and nothing changes. If Caddy
	// does not take the routes, the container stays for reconcile to remove.
	// Caller holds the label's lifecycle lock.
	private async retire(label: string, now: number): Promise<boolean> {
		const outcome: { retired: boolean; deployment?: Deployment } = { retired: false };
		await this.deps.store.update(label, (r) => {
			if (!this.lapsed(r, now, true)) return r;
			outcome.retired = true;
			if (r.deployment !== undefined) outcome.deployment = r.deployment;
			// A lease holds a deployment; with the deployment gone, so is it.
			const { deployment: _gone, error: _cleared, lease: _released, ...rest } = r;
			return { ...rest, status: 'expired', updatedAt: this.iso() };
		});
		if (outcome.retired) {
			await this.unroute(leftoversOf(outcome.deployment)).catch((err: unknown) =>
				this.deps.log(`expiring ${label}: ${message(err)}`),
			);
		}
		return outcome.retired;
	}

	// Stops every preview container whose writable layer and volumes together
	// are over the limit, and keeps it stopped. Each is taken out of the
	// routes first and stopped only once Caddy has taken routes without it,
	// under its label's lock so that no wake or cutover routes it in between.
	// Every one is blocked in memory as soon as the measurement is back, so
	// visits no longer start it, even if a step below fails for it. When a
	// record's deployment uses it, the deployment is then marked halted with
	// the reason in the record's error; the next koi up replaces it. The
	// block holds when the marker cannot be saved (the preview may have
	// filled the disk), and later runs try to save it again. Stopped
	// containers are measured too, so the run koid makes at startup blocks
	// one again after a restart; until a run has measured them, visits start
	// no stopped container. A container no record uses yet belongs to a
	// build in its health check, which fails when it stops. Returns the
	// containers stopped or blocked.
	async stopOversized(limitBytes = DISK_LIMIT_BYTES): Promise<string[]> {
		const { deps } = this;
		const over = (await deps.docker.diskUsage()).filter((c) => c.bytes > limitBytes);
		for (const c of over) this.halted.add(c.name);
		this.diskChecked = true;
		this.diskMeasured.resolve();
		const stopped: string[] = [];
		for (const c of over) {
			const reason = `stopped for disk use: its writable layer and volumes reached ${gib(c.bytes)} GiB, over the ${gib(limitBytes)} GiB limit`;
			try {
				if (await this.lifecycle.run(c.label, () => this.halt(c, reason))) {
					stopped.push(c.name);
					deps.log(`${c.name}: ${reason}`);
				}
			} catch (err) {
				deps.log(`stopping ${c.name} for disk use: ${message(err)}`);
			}
		}
		return stopped;
	}

	// Stops and blocks one container for stopOversized. False when there is
	// nothing to do: it is stopped, and no record uses it or its record says
	// it is halted. Caller holds the label's lifecycle lock.
	private async halt(c: DiskUsage, reason: string): Promise<boolean> {
		const { deps } = this;
		const record = await deps.store.get(c.label);
		const used = record?.deployment?.container === c.name;
		if (!c.running && (!used || record?.deployment?.halted === 'disk')) return false;
		await this.syncWithout([c.name]);
		await deps.docker.stop(c.name);
		if (!used) return true;
		await deps.store
			.update(c.label, (r) =>
				r.deployment?.container === c.name
					? {
							...r,
							error: reason,
							deployment: { ...r.deployment, halted: 'disk' },
							updatedAt: this.iso(),
						}
					: r,
			)
			.catch((err: unknown) =>
				deps.log(
					`recording that ${c.name} was stopped for disk use: ${message(err)}; visits still do not start it`,
				),
			);
		return true;
	}

	// Writes the visits counted so far to their records, with any an earlier
	// call could not write. Resolves once every one has been tried, those a
	// call before it took included: every decision on expiry calls this
	// first. When a label's write fails (a full disk, say), the end of the
	// chain of renewals its visits make stays pending, later visits extend
	// it, and the next call writes it; until then every decision on expiry
	// counts it as the last visit (lapsed). One call at a time.
	flushVisits(): Promise<void> {
		return this.visitWrites.run(async () => {
			for (const [label, at] of this.deps.drainVisits()) {
				this.unchecked.set(label, [...(this.unchecked.get(label) ?? []), at]);
			}
			for (const label of new Set([...this.renewals.keys(), ...this.unchecked.keys()])) {
				const visits = this.unchecked.get(label) ?? [];
				const chain: { read: boolean; end: number | undefined } = { read: false, end: undefined };
				try {
					await this.deps.store.update(label, (r) => {
						chain.read = true;
						chain.end = chainEnd(r, this.renewals.get(label), visits);
						return withVisit(r, chain.end);
					});
					this.renewals.delete(label);
					this.unchecked.delete(label);
				} catch (err) {
					// Checked against the record, the visits are in the chain;
					// unread, they wait to be checked.
					if (chain.read) {
						this.unchecked.delete(label);
						if (chain.end !== undefined) this.renewals.set(label, chain.end);
					}
					this.deps.log(`writing visits to ${label}: ${message(err)}; kept for the next try`);
				}
			}
		});
	}

	// Whether the record is overdue at `now`, counting the end of a chain of
	// visits not written yet as its last visit. Visits not yet checked
	// against the record, because reading it failed, are checked against `r`
	// when the caller read it under the label's lifecycle lock (retire).
	// Otherwise they keep the preview from lapsing until a flush or a retire
	// has checked them.
	private lapsed(r: PreviewRecord, now: number, locked = false): boolean {
		const unchecked = this.unchecked.get(r.label);
		if (unchecked !== undefined && !locked) return false;
		return overdue(r, now, chainEnd(r, this.renewals.get(r.label), unchecked ?? []));
	}

	// Writes visits to their records: for each label, the end of the chain
	// of renewals they make (chainEnd), so a visit after the preview's
	// deadline does not count, and a visit in time moves the deadline before
	// any later one is checked against it.
	async recordVisits(visits: Array<[string, number]>): Promise<void> {
		const byLabel = new Map<string, number[]>();
		for (const [label, at] of visits) byLabel.set(label, [...(byLabel.get(label) ?? []), at]);
		for (const [label, times] of byLabel) {
			await this.deps.store.update(label, (r) => withVisit(r, chainEnd(r, undefined, times)));
		}
	}

	// After a restart (or the box waking) nothing is mid-build: mark interrupted
	// attempts failed, check the containers that are still running, clear
	// build directories, route the ones that answered, and once Caddy has
	// taken those routes remove containers and images no record points at,
	// and stop the containers that run outside the slice. Starting the
	// stopped ones is restore()'s, later in startup.
	async reconcile(): Promise<void> {
		const { deps } = this;
		for (const r of await this.records()) {
			if (!IN_FLIGHT.has(r.status)) continue;
			await deps.store.update(r.label, (current) =>
				IN_FLIGHT.has(current.status)
					? { ...current, status: 'failed', error: INTERRUPTED, updatedAt: this.iso() }
					: current,
			);
		}
		const deployments = (await this.records()).flatMap((r) =>
			r.deployment === undefined ? [] : [r.deployment],
		);
		// Containers still running from before koid started serve again once
		// they answer; restore() starts and checks the rest. One that runs
		// outside the slice kept running through a Docker restart
		// (live-restore) where it was before; it is stopped below, and its
		// next start, by restore() or a visit, puts it in the slice.
		const outside: string[] = [];
		for (const d of deployments) {
			if (d.halted !== undefined) continue;
			const state = await deps.docker.inspect(d.container, deps.network);
			if (!state.running) continue;
			if (deps.slice !== undefined && (await deps.docker.slice(d.container)) !== deps.slice) {
				outside.push(d.container);
			} else if (
				state.ip !== undefined &&
				(await deps.probe(`http://${state.ip}:${d.port}${d.healthPath}`))
			) {
				await this.setReady([d.container], true);
			}
		}
		const containers = new Set(deployments.map((d) => d.container));
		const images = new Set(deployments.map((d) => d.image));
		const leftovers: Leftovers = {
			containers: (await deps.docker.list()).flatMap((c) =>
				containers.has(c.name) ? [] : [c.name],
			),
			images: (await deps.docker.listImages()).filter((image) => !images.has(image)),
		};
		await rm(join(deps.stateDir, 'builds'), { recursive: true, force: true });
		await this.unroute(leftovers);
		await this.evict(outside);
	}

	// Whether a running container runs in the slice, or koid uses none.
	private async inSlice(container: string): Promise<boolean> {
		const { slice, docker } = this.deps;
		return slice === undefined || (await docker.slice(container)) === slice;
	}

	// Stops running containers that are outside the slice, so that their
	// next start puts them in it. Each is blocked (misplaced) first, and
	// stopped only once Caddy has taken routes without it, as in unroute.
	// One whose stop fails stays blocked, out of the routes, for
	// stopMisplaced to try again. Throws, stopping none, when Caddy refuses
	// the routes. Caller holds the containers' lifecycle locks, or koid does
	// not serve yet.
	private async evict(containers: string[]): Promise<void> {
		const { deps } = this;
		if (containers.length === 0) return;
		for (const c of containers) this.misplaced.add(c);
		await this.syncWithout(containers);
		for (const c of containers) {
			try {
				await deps.docker.stop(c);
				this.misplaced.delete(c);
				deps.log(`stopped ${c}, which ran outside ${deps.slice}; its next visit starts it there`);
			} catch (err) {
				deps.log(
					`stopping ${c}, which runs outside ${deps.slice}: ${message(err)}; it stays out of the routes, and the watchdog tries again`,
				);
			}
		}
	}

	// Tries again to stop the containers evict could not. The watchdog's
	// timer calls it.
	async stopMisplaced(): Promise<void> {
		if (this.misplaced.size === 0) return;
		for (const r of await this.records()) {
			const c = r.deployment?.container;
			if (c === undefined || !this.misplaced.has(c)) continue;
			await this.lifecycle
				.run(r.label, async () => {
					const where = await this.deps.docker.slice(c);
					// Stopped, or moved, since.
					if (where === undefined || where === this.deps.slice) this.misplaced.delete(c);
					else await this.evict([c]);
				})
				.catch((err: unknown) => this.deps.log(`stopping ${c}: ${message(err)}`));
		}
	}
}

// Container address -> preview label, for every routed container: the map
// the egress proxy checks koi tokens against.
export function previewAddresses(routes: Route[]): Record<string, string> {
	return Object.fromEntries(
		routes.map((r) => [r.upstream.slice(0, r.upstream.lastIndexOf(':')), r.label]),
	);
}

// Containers and images that no record names, to remove once nothing routes
// to them.
interface Leftovers {
	containers: string[];
	images: string[];
}

function leftoversOf(d: Deployment | undefined): Leftovers {
	return d === undefined
		? { containers: [], images: [] }
		: { containers: [d.container], images: [d.image] };
}

// The record for a request koid has just accepted. A record that expired
// belonged to whoever had the label before, so nothing of it is kept.
// For the build log: what a merge commit holds, when the request's commit is
// GitHub's merge of a pull request into its base.
function mergeNote(request: UpRequest): string {
	const m = request.merge;
	if (m === undefined) return '';
	const what = request.pr !== undefined ? `#${request.pr}` : 'the pull request';
	return ` (${what} at ${m.head} merged into ${m.baseBranch ?? 'its base'} at ${m.base})`;
}

// A random login key: "koi-" and 24 lowercase letters and digits.
export function newLoginKey(): string {
	const abc = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return `koi-${Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => abc[b % 36]).join('')}`;
}

function queuedRecord(
	current: PreviewRecord | undefined,
	request: UpRequest,
	attempt: string,
	ttlDays: number,
	now: string,
	keys: { wantsLoginKey: boolean; newLoginKey: () => string },
): PreviewRecord {
	const kept = current?.status === 'expired' ? undefined : current;
	// One key per preview for its whole life, so a reviewer signed in to an
	// earlier build stays signed in; a new owner after expiry gets a new one.
	// A request without a login key keeps the one the record has: the running
	// deployment still uses it until this request's cuts over (cutover drops
	// it then), and a failed build leaves that deployment running.
	const loginKey = kept?.loginKey ?? (keys.wantsLoginKey ? keys.newLoginKey() : undefined);
	return {
		label: request.label,
		project: request.project,
		repo: request.repo,
		status: 'queued',
		commit: request.commit,
		branch: request.branch,
		...(request.pr !== undefined ? { pr: request.pr } : {}),
		...(request.merge !== undefined ? { merge: request.merge } : {}),
		dirty: request.dirty,
		requestId: request.id,
		attempt,
		ttlDays,
		createdAt: kept?.createdAt ?? now,
		updatedAt: now,
		...(kept?.lastVisitAt !== undefined ? { lastVisitAt: kept.lastVisitAt } : {}),
		...(loginKey !== undefined ? { loginKey } : {}),
		...(kept?.deployment !== undefined ? { deployment: kept.deployment } : {}),
	};
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
