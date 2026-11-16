import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import {
	ARTIFACT_CHUNK_BYTES,
	type Artifact,
	type ArtifactChunk,
	ArtifactChunkSchema,
	ArtifactIdSchema,
	BlockedPointSchema,
	type Completion,
	canonicalDigest,
	type DeploymentIdentity,
	deploymentIdentity,
	EVENTS_PAGE_MAX,
	type EvidenceEvent,
	EvidenceEventSchema,
	type EvidenceReply,
	EvidenceReplySchema,
	type ExecutionDescriptor,
	ExecutionDescriptorSchema,
	GlobWork,
	type GlobWorkOptions,
	type InputSnapshot,
	InputSnapshotSchema,
	KOI_DIR,
	LEASE_MAX_SECONDS,
	type LoadedPoint,
	loadVerifyConfig,
	NO_SUCH_PREVIEW,
	PLAN_LIMITS,
	PLAN_NOTE_MAX,
	type Plan,
	type PlanReply,
	PlanReplySchema,
	type PlanRequest,
	PlanSchema,
	type Point,
	type PointStatus,
	type ProofRecord,
	ProofRecordSchema,
	type RequiredPolicy,
	RequiredPolicySchema,
	RUN_LIMIT_CEILINGS,
	RUN_LIMIT_DEFAULTS,
	type Run,
	type RunAccepted,
	RunAcceptedSchema,
	type RunControllerRecord,
	RunControllerRecordSchema,
	type RunEventsPage,
	RunEventsPageSchema,
	type RunLimits,
	type RunOutcome,
	type RunRequest,
	RunSchema,
	type RunStatusReply,
	RunStatusReplySchema,
	RunStatusSchema,
	randomId,
	readVerifyFile,
	runLeaseHolder,
	TEARDOWN_ALLOWANCE_SECONDS,
	TEXT_MAX,
	TRUNCATED_NAME_MAX,
	TRUNCATED_NAMES_MAX,
	VERIFICATION_ENTRY_MAX_BYTES,
	VERIFICATION_REPLY_MAX_BYTES,
	type VerifyConfig,
	VerifyConfigError,
	VerifyIdSchema,
} from '@koi/shared';
import { fitJson } from './buildlog.ts';
import { type Deployer, LeaseError, NoSuchLeaseError, NoSuchPreviewError } from './deployer.ts';
import type { Docker } from './docker.ts';
import type { VerificationCapability } from './host.ts';
import { Mutex } from './lock.ts';
import {
	newRecorderTokens,
	type RecorderApi,
	RecorderDeadlineError,
	RecorderError,
	RecorderLostError,
	RecorderSession,
	type RunBudget,
	recorderEnv,
} from './recorder.ts';
import type { SecretRegistry } from './redact.ts';
import type { PreviewStore } from './store.ts';
import {
	type AssertionReport,
	judgePoint,
	judgeReadiness,
	judgeRun,
	type LostEvidence,
	type PointVerdict,
	type ReportInput,
	reasonText,
	renderReport,
	withLostEvidence,
} from './verdict.ts';
import { helperOf, runNetworkOf, type VerificationNetwork } from './verification-network.ts';
import { declaredCredential, type Sanitize, sanitizeRunData } from './verification-sanitize.ts';
import { PROOFS_DIR, proofFiles, REQUIRED_POLICY, readNoFollow } from './verification-snapshot.ts';
import {
	CapExceededError,
	clockReaches,
	DISK_WAIT_MS,
	EVIDENCE_UNWRITABLE,
	type EvidenceStore,
	EvidenceStuckError,
	MAX_PROBLEMS,
	type RunWriter,
} from './verification-store.ts';
import {
	IMAGE_REASONS,
	type ImageResolution,
	type PointRun,
	resolveRunnerImage,
	VERIFIER_STUCK,
	VerifierRunner,
	verifierStopBy,
} from './verifier.ts';

// The run controller (docs/verify.md, "Running a verification"): plans a
// verification of a deployment from its input snapshot, starts a run under
// the deployment's lease, runs each point in a verifier of its own against
// the recorder, judges the result by the verdict rules and writes the
// bundle. It is the only thing that allocates plan and run ids and the only
// writer of a run's records.
//
// A run plans, takes its lease, makes its network, starts the recorder,
// resolves the project's runner image under the operator's policy, and for
// each planned point opens a browser context in the recorder at `/`,
// creates a verifier from that image with the frozen inputs and runs the
// point's commands in it under the runner protocol (verifier.ts), then
// judges the point from the assertion events the runner reported and the
// artifacts the recorder captured. A point whose runner never reports an
// assertion is not-run; a verifier that cannot start blocks the point with
// the reason; a point that reaches its budget is blocked, never passed.

export class VerificationError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string,
		readonly retryable = false,
	) {
		super(message);
		this.name = 'VerificationError';
	}
}

export interface VerificationDeps {
	evidence: EvidenceStore;
	store: Pick<PreviewStore, 'get'>;
	deployer: Pick<Deployer, 'acquireLease' | 'renewLease' | 'releaseLease' | 'leasedDeployment'>;
	// Whether the box can verify, as startup found it (host.ts).
	capability: VerificationCapability;
	// The run networks, when the box can verify. `list` is for admission:
	// a preview whose last run still has a network takes no new run.
	network: Pick<VerificationNetwork, 'create' | 'destroy' | 'reapply' | 'list'> | undefined;
	// `listRun` and `networks` are for admission and for the teardown's
	// inspection: helpers and run networks of a run that outlived, or never
	// got, its record. `removeNetwork` is for the latter. The rest is the
	// verifier's (verifier.ts).
	docker: Pick<
		Docker,
		| 'start'
		| 'stop'
		| 'remove'
		| 'listRun'
		| 'networks'
		| 'removeNetwork'
		| 'createVerifier'
		| 'createVolume'
		| 'removeVolume'
		| 'createStaging'
		| 'mounts'
		| 'copyIn'
		| 'attach'
		| 'inspect'
		| 'exitState'
		| 'imageInfo'
	>;
	// KOI_RECORDER_IMAGE and KOI_RECORDER_SECCOMP (config.ts).
	recorderImage: string | undefined;
	recorderSeccomp: string | undefined;
	// Runner images a manifest may name besides the default
	// (KOI_VERIFIER_IMAGES).
	verifierImages: readonly string[];
	// How often the verifier's watchdog looks at the budget and for a stop
	// request; tests shorten it.
	verifierPollMs?: number | undefined;
	// The recorder's API for a URL; the HTTP one unless a test passes a fake.
	recorderApi?: ((baseUrl: string, token: string) => RecorderApi) | undefined;
	// How long the recorder may take to answer healthy.
	recorderHealthTimeoutMs?: number | undefined;
	secrets: SecretRegistry;
	// Refreshes the host activity stamp, so the box does not stop under a run.
	keepAwake?: (() => Promise<void>) | undefined;
	// How often, in milliseconds; KEEP_AWAKE_MS unless a test shortens it.
	keepAwakeMs?: number | undefined;
	// What the teardown may take, in milliseconds; the shared allowance
	// unless a test shortens it. The lease is always taken for the shared
	// one.
	teardownAllowanceMs?: number | undefined;
	// A test sets these: a plan's step budget, and a call each time matching gives the rest
	// of koid a turn.
	planGlobs?: Pick<GlobWorkOptions, 'budget' | 'onTurn'> | undefined;
	now: () => Date;
	sleep: (ms: number) => Promise<void>;
	log: (message: string) => void;
	randomId?: (() => string) | undefined;
}

// The path a point's first page opens at: the runner finds it in the
// browser already at the app.
const POINT_OPEN_PATH = '/';

// How a blocked point's reason starts when the box cannot verify. What follows is what
// Docker or the helper said at startup.
const UNAVAILABLE_REASON = 'verification_unavailable: ';

// What every plan says. These are koid's own words, so a word someone registered must not
// mask them. Any note after them is an error from reading a project's file.
const PLAN_NOTES = [
	'a run executes each point\'s setup, run and cleanup commands in a verifier made from the manifest\'s runner image, under the runner protocol (docs/verify.md, "Writing a runner"); agent actions (verify act), the pull request comment and proof verification are later work',
	'the required policy has no trusted source yet (the protected base branch is later work): a required.yaml in the tree is shown as advisory, and readiness is false for every run',
];

// The most problems a status reply carries; the count says how many there are.
const STATUS_PROBLEMS = 20;

// What the manifest's limitations say in every bundle.
const BUNDLE_LIMITATIONS = [
	'Text and declared secret fields were filtered. Pixels, encoded secrets, and unknown application data cannot be certified secret-free.',
	'Project text is kept as the project declared it. Text a run produced before koid learned a secret stays in these files until retention ends; replies mask it.',
];

// How often a run touches the host activity stamp and checks its lease.
const KEEP_AWAKE_MS = 5_000;

// A lease this close to its expiry is renewed, when the run's budget
// outlives it (keepLease).
const LEASE_RENEW_MARGIN_MS = 60_000;

// Why a run ends when its points were still not done well past its deadline.
const RUN_STUCK =
	'run_stuck: the run was still not done well after its time ended, so its teardown started without it';

// A phase of a run reached the end of its budget: before an operation was
// made, while it was pending, or by the time it came back. The run's own
// limit, not a failure: the points not reached are not-run.
class BudgetEndedError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'BudgetEndedError';
	}
}

// A verifier was still not done well past when its point had to end. The run
// stopped waiting for it, and it may still be going.
class VerifierStuckError extends Error {
	constructor() {
		super(VERIFIER_STUCK);
		this.name = 'VerifierStuckError';
	}
}

// The time a phase of a run may use (RunBudget, recorder.ts): its end, in
// deps.now() milliseconds, and a signal that fires at the end on the host
// clock, so a recorder call pending then is aborted. The controller also
// compares `until` with deps.now() before each operation, so a run sees
// its end on a test clock without waiting for the timer. A run has one
// budget for its points and then one for its teardown, and each point has one
// of its own inside the first.
class Budget implements RunBudget {
	private readonly aborter = new AbortController();
	private readonly timer: ReturnType<typeof setTimeout>;

	constructor(
		readonly until: number,
		now: number,
	) {
		this.timer = setTimeout(
			() => this.aborter.abort(new Error('the budget ended')),
			Math.max(0, until - now),
		);
	}

	get signal(): AbortSignal {
		return this.aborter.signal;
	}

	remaining(now: number): number {
		return Math.max(0, this.until - now);
	}

	ended(now: number): boolean {
		return now >= this.until || this.aborter.signal.aborted;
	}

	// Stops the timer. The signal stays as it is: a phase that is over does
	// not come back.
	close(): void {
		clearTimeout(this.timer);
	}
}

// What a plan said that is not in the strict Plan: everything the reply
// carries, persisted next to plan.json so pages and runs read it back.
type PlanRecord = Omit<PlanReply, 'next'>;

interface Inputs {
	snapshot: InputSnapshot;
	config: VerifyConfig;
	source: string;
	changed: string[];
}

interface ActiveRun {
	runId: string;
	writer: RunWriter;
	controller: RunControllerRecord;
	plan: Plan;
	planning: PlanRecord;
	inputs: Inputs;
	// The runner image, as start resolved it and found it to match the plan.
	image: ImageResolution;
	// What each judged point's observations.json says, so the last check of
	// its evidence can write the file again if it changes the verdict.
	observations: Map<string, PointObservations>;
	cancel: boolean;
	// The live record takes no more changes: the final records are being
	// written, or were. saveController writes nothing past it, and a cancel
	// that arrives past it is answered with the state the run ends in.
	closed: boolean;
	// One write of the controller's record at a time, with `closed` checked
	// inside: a live save still in flight cannot land after the final one.
	records: Mutex;
	// The manifest is on disk. A reader asks this and not the disk while the
	// run is active, since the record turns terminal before the lease goes.
	finalized: boolean;
	// finish() is done. An entry can outlive that only when its final record
	// could not be written (see finish), and it no longer holds its label.
	ended: boolean;
	// The time the current phase may use: the points' until the teardown
	// begins, then the teardown's.
	budget: Budget;
	done: Promise<void>;
}

// What a point's observations.json says besides its identity and verdict. The
// verifier's account is there when one ran. A field's name says how the sanitizer
// treats it, so what a runner chose is in fields that name it as such: `cited` and
// not `evidence`, which holds koid's artifact ids elsewhere, and a list and not a
// map keyed by a capture's label, since the sanitizer keeps a record's keys. The
// verifier takes a report only for a declared assertion and with one of the
// protocol's outcomes, so `assertion` and `outcome` stay as they are.
interface ObservedPoint {
	attempt: number;
	assertions: string[];
	asserted: Array<
		Omit<AssertionReport, 'name' | 'evidence'> & { assertion: string; cited: string[] }
	>;
	labels: Array<{ name: string; artifact: string }>;
	stopped?: PointRun['stopped'];
	steps?: PointRun['steps'];
	exit?: PointRun['exit'];
	cleanup?: PointRun['cleanup'];
	counts?: PointRun['counts'];
}

// A point's observations.json.
interface PointObservations extends ObservedPoint {
	version: 1;
	pointId: string;
	verdict: PointVerdict;
}

// What drive() hands finish(), filled in as the run goes: a throw part way
// still leaves what was made, so the teardown sees it.
interface Driven {
	// Set before the creation is asked for, not after it succeeds: it can
	// fail with its rollback failing too, or still be going once the run
	// stops waiting for it, and either way the teardown must deal with it.
	networkStarted: boolean;
	session: RecorderSession | undefined;
	completion: Completion | undefined;
	interruption: string | undefined;
	// The run stopped waiting for drive(), which may still be going. It starts
	// no more points.
	abandoned: boolean;
}

// How a point ended for the run: it is judged and the run goes on; the run
// cannot go on, with why; or the run's time ran out during it.
type PointEnd = { next: true } | { stop: string } | { deadline: true };

export class Verification {
	private readonly active = new Map<string, ActiveRun>();
	// Each idempotency key to the run it started. The run's record keeps the
	// key, and recover() fills this from the records at startup.
	private readonly accepted = new Map<string, RunAccepted>();
	private readonly verifier: VerifierRunner | undefined;
	// Each key whose first request is still being admitted, to that admission.
	// See start().
	private readonly admitting = new Map<string, Promise<RunAccepted>>();

	constructor(private readonly deps: VerificationDeps) {
		this.verifier =
			deps.network === undefined
				? undefined
				: new VerifierRunner({
						docker: deps.docker,
						network: deps.network,
						secrets: deps.secrets,
						now: deps.now,
						sleep: deps.sleep,
						log: deps.log,
						pollMs: deps.verifierPollMs,
					});
	}

	// The runner image the manifest names, resolved on this box under the
	// operator's policy, or why no point may run in it. Only when the box
	// can verify: without the default image there is nothing to resolve
	// against, and every point is blocked for that already.
	private async runnerImage(config: VerifyConfig): Promise<ImageResolution | undefined> {
		const capability = this.deps.capability;
		if (!capability.available) return undefined;
		return resolveRunnerImage(this.deps.docker, config.manifest.runner.image, {
			defaultImageId: capability.verifierImageId,
			allowed: this.deps.verifierImages,
		});
	}

	private id(): string {
		return (this.deps.randomId ?? randomId)();
	}

	private iso(): string {
		return this.deps.now().toISOString();
	}

	// The function a record with runtime text passes through to leave koid.
	private readonly clean: Sanitize = (record) =>
		sanitizeRunData(record, { redact: (text) => this.deps.secrets.redact(text) });

	// `make`, with its refusal scrubbed. A refusal is a reply too, and an error's text
	// is runtime text, whatever it quotes.
	private async answering<T>(make: () => Promise<T>): Promise<T> {
		try {
			return await make();
		} catch (err) {
			if (err instanceof VerificationError) err.message = this.deps.secrets.redact(err.message);
			throw err;
		}
	}

	// -- Plans ------------------------------------------------------------------

	async plan(request: PlanRequest): Promise<PlanReply> {
		return this.answering(() => this.makePlan(request));
	}

	private async makePlan(request: PlanRequest): Promise<PlanReply> {
		const record = await this.deps.store.get(request.label);
		if (record === undefined) throw new VerificationError(404, 'no_such_preview', NO_SUCH_PREVIEW);
		const deployment = deploymentIdentity(record);
		if (deployment === undefined) {
			throw new VerificationError(
				409,
				'no_deployment',
				`${request.label} has no serving deployment to plan against; run koi up first`,
			);
		}
		if (
			request.expectedDeploymentId !== undefined &&
			request.expectedDeploymentId !== deployment.deploymentId
		) {
			throw new VerificationError(
				409,
				'deployment_mismatch',
				`${request.label} serves deployment ${deployment.deploymentId}, not ${request.expectedDeploymentId}`,
			);
		}
		// A refusal and not a shorter list: a point left out without a word would make a run
		// look more covered than it is.
		const tooLarge = (why: string) =>
			new VerificationError(
				409,
				'plan_too_large',
				`${why}. koid made no plan and wrote nothing. Split the change or list fewer globs.`,
			);
		const work = new GlobWork({
			...this.deps.planGlobs,
			over: (budget) =>
				tooLarge(`matching the globs went past the ${budget} steps a plan may take`),
		});
		const inputs = await this.loadInputs(deployment.deploymentId, work);
		const { config, snapshot, changed } = inputs;
		// Before any glob of the plan runs, so a project over a limit costs koid nothing.
		const over = overPlanLimit(config, changed);
		if (over !== undefined) throw tooLarge(over);
		const declaredPolicy = await readAdvisoryPolicy(inputs.source);
		const proofs = await readProofs(inputs.source);
		// Before anything is said about the project's files or written. No registry here:
		// a word someone registered must not be able to stop a project from planning.
		const credential = await declaredCredential({
			config,
			policy: declaredPolicy.advisory,
			proofs: { records: proofs.records.values(), errors: proofs.errors },
		});
		if (credential !== undefined) {
			throw new VerificationError(
				409,
				'declared_credential',
				`what looks like a real credential is declared in ${KOI_DIR}/ at ${credential}. koid made no plan and wrote nothing. Take it out of the project's files and run koi up again.`,
			);
		}
		const profile = config.manifest.profiles[request.profile];
		if (profile === undefined) {
			throw new VerificationError(
				400,
				'no_such_profile',
				`${KOI_DIR}/verify.yaml has no profile ${request.profile}; it has ${Object.keys(config.manifest.profiles).join(', ') || 'none'}`,
			);
		}
		const byId = new Map(config.points.map((p) => [p.point.id, p]));

		// Selection: the profile's always list, then the points the change
		// selects, then the profile's includes; or the explicit subset.
		const selected = new Map<string, string>();
		const take = (id: string, why: string) => {
			if (!selected.has(id)) selected.set(id, why);
		};
		if (request.points !== undefined) {
			for (const id of request.points) {
				if (!byId.has(id)) {
					throw new VerificationError(400, 'no_such_point', `no point ${id} in the project`);
				}
				take(id, 'requested: named in the request');
			}
		} else {
			for (const id of profile.always) take(id, `always: listed by profile ${request.profile}`);
			if (profile.select === 'changed') {
				for (const loaded of config.points) {
					const { point } = loaded;
					if (point.select.always === true) {
						take(point.id, `select.always: taken by every run of profile ${request.profile}`);
						continue;
					}
					const match = await firstMatch(point.select.paths, changed, work);
					if (match === undefined) continue;
					take(point.id, changedWhy(match.file, match.glob));
				}
			}
			for (const id of profile.include) take(id, `include: listed by profile ${request.profile}`);
		}

		const uncovered = await uncoveredFiles(config, changed, work);
		// Docker's answer comes ahead of the scrub below, which nothing may wait behind.
		const image = await this.runnerImage(config);

		// All a plan holds that is not project text or koid's own: why the box cannot verify,
		// why its runner image cannot run, and an error from reading the policy or a proof,
		// which can name more than the file. Scrubbed here and not sooner, for two reasons.
		// The credential check above needs them as they were. And matching gives other work
		// turns, during which koid can learn a secret. From here to the digest there is no
		// await, so what the digest covers is what koid knew when it was made. The plan is
		// then written as it says.
		const policy = this.clean(declaredPolicy);
		const proofErrors = this.clean(proofs.errors);
		const capability = this.deps.capability;
		const unavailable = capability.available ? undefined : this.clean(capability.reason);
		const imageProblem = image?.ok === false ? this.clean(image.reason) : undefined;

		// Requirements against what this host gives.
		const fixtures = new Set(
			snapshot.verify.status === 'present' ? snapshot.verify.fixtures.map((f) => f.path) : [],
		);
		const imageDigest = image?.ok === true ? { runnerImageDigest: image.digest } : {};
		const points: Plan['points'] = [];
		const blocked: Plan['blocked'] = [];
		for (const [id, why] of selected) {
			const loaded = byId.get(id);
			if (loaded === undefined) continue;
			const reasons = this.blockedReasons(loaded, fixtures, unavailable, imageProblem);
			if (reasons.length > 0) {
				blocked.push({ id, reason: reasons.join('; ').slice(0, TEXT_MAX) });
				continue;
			}
			points.push({
				id,
				revision: loaded.point.revision,
				digest: config.digests[loaded.path] ?? '',
				runners: loaded.runners,
				why,
			});
		}

		const planId = this.id();
		// The digest is over what the plan says, and the plan is written as it says it, so
		// the digest holds whatever anyone registers later.
		const plan = PlanSchema.parse(
			withDigest({
				version: 1,
				planId,
				deployment,
				profile: request.profile,
				points,
				blocked,
				uncovered,
				...imageDigest,
			}),
		);
		const required = policy.advisory?.required ?? [];
		const isRequired = (id: string, revision: number) =>
			required.some((r) => r.id === id && r.revision === revision);
		const notes = [
			...PLAN_NOTES,
			...(policy.advisory?.error !== undefined
				? [`${KOI_DIR}/${REQUIRED_POLICY}: ${policy.advisory.error}`]
				: []),
			...proofErrors,
		]
			.slice(0, 20)
			// The schema's limit, here and not when the plan is read back: a
			// note over it would be written and then refused by planPage. The
			// whole error stays in policy.advisory.error.
			.map((note) => fitJson(note, PLAN_NOTE_MAX));
		const planning: PlanRecord = {
			version: 1,
			planId,
			planDigest: plan.planDigest,
			label: request.label,
			deployment,
			profile: request.profile,
			advisory:
				request.points !== undefined || snapshot.request.dirty || deployment.merge === undefined,
			counts: {
				selected: plan.points.length,
				blocked: plan.blocked.length,
				uncovered: plan.uncovered.length,
				required: required.length,
			},
			policy,
			limits: resolveLimits(config),
			runnerImage: config.manifest.runner.image,
			...imageDigest,
			originMode: 'private-app',
			notes,
			points: plan.points.map((p) => ({
				id: p.id,
				revision: p.revision,
				why: p.why,
				proof: proofs.records.has(`${p.id}@${p.revision}`) ? 'unverified' : 'none',
				required: isRequired(p.id, p.revision),
			})),
			blocked: plan.blocked,
			uncovered: plan.uncovered,
			createdAt: this.iso(),
		};
		const dir = this.deps.evidence.planDir(planId);
		await this.deps.evidence.writeDeclared(dir, 'plan.json', plan);
		await this.deps.evidence.writeDeclared(dir, 'planning.json', planning);
		return planPage(planning, undefined, this.clean);
	}

	// A page of a plan made earlier, from `after` (PlanCursorSchema).
	async planPage(planId: string, after: string | undefined): Promise<PlanReply> {
		const { planning } = await this.loadPlan(planId);
		return planPage(planning, after, this.clean);
	}

	private async loadPlan(planId: string): Promise<{ plan: Plan; planning: PlanRecord }> {
		const dir = this.deps.evidence.planDir(planId);
		const planText = await readFile(join(dir, 'plan.json'), 'utf8').catch(() => undefined);
		const planningText = await readFile(join(dir, 'planning.json'), 'utf8').catch(() => undefined);
		if (planText === undefined || planningText === undefined) {
			throw new VerificationError(404, 'no_such_plan', `no plan ${planId}`);
		}
		const plan = PlanSchema.parse(JSON.parse(planText));
		// The digest is checked on every read: a record that does not hash
		// to its own digest was not written whole.
		if (withDigest(plan).planDigest !== plan.planDigest) {
			throw new VerificationError(409, 'plan_corrupt', `plan ${planId} does not match its digest`);
		}
		const planning = PlanReplySchema.omit({ next: true }).parse(JSON.parse(planningText));
		return { plan, planning };
	}

	// Why a point cannot run on this host, or nothing. `unavailable` is why the box
	// cannot verify and `imageProblem` why its runner image cannot run, each scrubbed,
	// when that is so.
	private blockedReasons(
		loaded: LoadedPoint,
		fixtures: Set<string>,
		unavailable: string | undefined,
		imageProblem: string | undefined,
	): string[] {
		const reasons: string[] = [];
		const r = loaded.point.requires;
		if (unavailable !== undefined) reasons.push(`${UNAVAILABLE_REASON}${unavailable}`);
		if (imageProblem !== undefined) reasons.push(imageProblem);
		if (r?.provider !== undefined) {
			reasons.push(
				`capability_missing:provider:${r.provider}: provider request budgets are not available until the egress proxy counts them`,
			);
		}
		if (r?.network !== undefined) {
			reasons.push(
				`capability_missing:network:${r.network}: no named network policy exists on this host`,
			);
		}
		if (r?.services !== undefined && r.services.length > 0) {
			reasons.push(
				`capability_missing:services:${r.services.join(',')}: the host has no service policy to check them against`,
			);
		}
		for (const fixture of r?.fixtures ?? []) {
			const path = `${KOI_DIR}/${fixture}`;
			if (!fixtures.has(path))
				reasons.push(`fixture_missing: ${path} is not in the input snapshot`);
		}
		return reasons;
	}

	// The deployment's input snapshot, loaded and checked against itself.
	private async loadInputs(deploymentId: string, work?: GlobWork): Promise<Inputs> {
		const dir = this.deps.evidence.inputsDir(deploymentId);
		const text = await readFile(join(dir, 'snapshot.json'), 'utf8').catch(() => undefined);
		if (text === undefined) {
			throw new VerificationError(
				409,
				'inputs_missing',
				`the verification inputs of deployment ${deploymentId} were not kept; run koi up again to deploy with them`,
			);
		}
		const parsed = InputSnapshotSchema.safeParse(JSON.parse(text));
		if (!parsed.success) {
			throw new VerificationError(
				409,
				'inputs_invalid',
				`the input snapshot of deployment ${deploymentId} is not one koid can read`,
			);
		}
		const snapshot = parsed.data;
		if (snapshot.verify.status === 'absent') {
			throw new VerificationError(
				409,
				'verify_absent',
				`the project has no ${KOI_DIR}/verify.yaml; see docs/verify.md`,
			);
		}
		if (snapshot.verify.status === 'invalid') {
			throw new VerificationError(
				409,
				'verify_invalid',
				`the project's verification files do not load: ${snapshot.verify.error}`,
			);
		}
		const source = join(dir, 'source');
		let config: VerifyConfig;
		try {
			config = await loadVerifyConfig(source, { work });
		} catch (err) {
			if (!(err instanceof VerifyConfigError)) throw err;
			throw new VerificationError(
				409,
				'inputs_invalid',
				`the kept inputs do not load: ${err.message}`,
			);
		}
		const changedSince = (what: string) =>
			new VerificationError(
				409,
				'inputs_changed',
				`the kept inputs of deployment ${deploymentId} are not what the snapshot recorded: ${what}`,
			);
		if (!sameDigests(config.digests, snapshot.verify.digests)) {
			throw changedSince('the verification files the loader reads');
		}
		// Every other file the snapshot recorded a digest for is read back and
		// checked too: the fixtures a point requires, the skills, koi.yaml, the
		// advisory policy and the proof records, and the changed-file list.
		// The loader does not read these, so the check above says nothing
		// about them, and each one changes what a plan selects or shows: a
		// fixture decides whether a point is blocked, the policy which points
		// are required, a proof what the plan says is proven, the changed
		// files which points the change selects.
		for (const file of [...snapshot.verify.fixtures, ...snapshot.verify.other]) {
			await this.checkedFile(source, file, changedSince);
		}
		let changed: string[] = [];
		if (snapshot.changedFiles !== undefined) {
			const bytes = await this.checkedFile(source, snapshot.changedFiles.file, changedSince);
			// One file per line, its name kept as git wrote it: git allows a
			// leading or trailing space in a name, and a name trimmed here
			// would miss the glob that names it.
			changed = new TextDecoder()
				.decode(bytes)
				.split('\n')
				.filter((l) => l !== '');
		}
		return { snapshot, config, source, changed };
	}

	// A file of the snapshot read back without following a symlink, refused
	// unless its bytes are the size and digest the snapshot recorded.
	private async checkedFile(
		source: string,
		file: { path: string; digest: string; size: number },
		changedSince: (what: string) => VerificationError,
	): Promise<Uint8Array> {
		let bytes: Uint8Array;
		try {
			// A file past its recorded size has changed; the read need not go on.
			bytes = await readNoFollow(join(source, file.path), file.path, file.size);
		} catch (err) {
			throw changedSince(`${file.path}: ${message(err)}`);
		}
		if (bytes.length !== file.size || sha256(bytes) !== file.digest) {
			throw changedSince(`${file.path} does not hash to what was recorded`);
		}
		return bytes;
	}

	// -- Runs -------------------------------------------------------------------

	// A retry can arrive while the first request with its key is still loading
	// inputs or writing its first records, before `accepted` has the key. Run
	// as a second admission, it would find the first one's lease and be refused,
	// so it waits for that admission and gets its answer, acceptance or failure.
	async start(request: RunRequest): Promise<RunAccepted> {
		return this.answering(() => this.admission(request));
	}

	private async admission(request: RunRequest): Promise<RunAccepted> {
		const key = request.idempotencyKey;
		if (key === undefined) return this.admit(request);
		const known = this.accepted.get(key);
		if (known !== undefined) return known;
		const admitting = this.admitting.get(key);
		if (admitting !== undefined) return admitting;
		// Set with no await after the lookups, so two requests cannot both
		// miss. An acceptance is in `accepted` before the entry goes, and after a
		// failure a later retry finds the key free and starts again.
		const admission = this.admit(request).finally(() => {
			this.admitting.delete(key);
		});
		this.admitting.set(key, admission);
		return admission;
	}

	private async admit(request: RunRequest): Promise<RunAccepted> {
		const key = request.idempotencyKey;
		const { plan, planning } = await this.loadPlan(request.planId);
		if (plan.planDigest !== request.planDigest) {
			throw new VerificationError(
				409,
				'plan_stale',
				`plan ${request.planId} has digest ${plan.planDigest}, not ${request.planDigest}; plan again`,
			);
		}
		const capability = this.deps.capability;
		if (
			!capability.available ||
			this.deps.network === undefined ||
			this.deps.recorderImage === undefined
		) {
			throw new VerificationError(
				503,
				'verification_unavailable',
				`verification is unavailable on this box: ${capability.available ? 'no run networks' : capability.reason}`,
			);
		}
		if (plan.points.length + plan.blocked.length === 0) {
			throw new VerificationError(
				409,
				'empty_plan',
				`plan ${request.planId} selects no point; nothing to run`,
			);
		}
		// The inputs must still be what the plan was made from.
		const inputs = await this.loadInputs(plan.deployment.deploymentId);
		for (const planned of plan.points) {
			const loaded = inputs.config.points.find((p) => p.point.id === planned.id);
			if (loaded === undefined || inputs.config.digests[loaded.path] !== planned.digest) {
				throw new VerificationError(
					409,
					'plan_stale',
					`point ${planned.id} is not as plan ${request.planId} recorded it; plan again`,
				);
			}
		}
		// So must the runner image. The manifest names it by a reference an
		// operator can move, and what ran must be what the plan was made for. This
		// resolution is the run's: the verifiers are made from its digest, so a tag
		// moved after this check changes nothing.
		const image = (await this.runnerImage(inputs.config)) ?? {
			ok: false,
			reason: 'verifier_unavailable: no default verifier image',
		};
		const resolved = image.ok ? image.digest : undefined;
		if (resolved !== plan.runnerImageDigest) {
			throw new VerificationError(
				409,
				'inputs_changed',
				`the runner image ${planning.runnerImage} was ${plan.runnerImageDigest ?? 'not resolved'} when plan ${request.planId} was made and is ${image.ok ? image.digest : `not resolved now (${image.reason})`}; plan again`,
			);
		}
		const runId = this.id();
		const { label } = planning;
		const ttl = Math.min(
			planning.limits.runSeconds + TEARDOWN_ALLOWANCE_SECONDS,
			LEASE_MAX_SECONDS,
		);
		let leased: Awaited<ReturnType<Deployer['acquireLease']>>;
		try {
			leased = await this.deps.deployer.acquireLease(label, runLeaseHolder(runId), ttl);
		} catch (err) {
			if (err instanceof LeaseError) throw new VerificationError(409, 'lease_refused', err.message);
			if (err instanceof NoSuchPreviewError) {
				throw new VerificationError(404, 'no_such_preview', NO_SUCH_PREVIEW);
			}
			throw err;
		}
		const release = async () => {
			await this.deps.deployer
				.releaseLease(label, leased.lease.leaseId)
				.catch((err: unknown) => this.deps.log(`releasing the lease of ${runId}: ${message(err)}`));
		};
		if (!sameDeployment(leased.deployment, plan.deployment)) {
			await release();
			throw new VerificationError(
				409,
				'deployment_mismatch',
				`${label} serves deployment ${leased.deployment.deploymentId} (image ${leased.deployment.imageDigest}), and the plan is for ${plan.deployment.deploymentId} (image ${plan.deployment.imageDigest}); plan again`,
			);
		}
		// The lease alone does not prove the app is free: an earlier run's
		// lease may have expired while its teardown, or its last capture, was
		// still pending, and its helpers can still reach the app. Nothing of
		// an earlier run may exist on the preview before a new one starts.
		let busy: string | undefined;
		try {
			const { container } = await this.deps.deployer.leasedDeployment(label, leased.lease.leaseId);
			busy = await this.leftoversOn(label, container);
		} catch (err) {
			await release();
			throw err;
		}
		if (busy !== undefined) {
			await release();
			throw new VerificationError(
				409,
				'preview_busy',
				`${label} cannot take a run yet: ${busy}; try again once it is gone`,
				true,
			);
		}
		let writer: RunWriter;
		try {
			writer = await this.deps.evidence.openRun(runId, {
				deployment: plan.deployment,
				sanitize: this.clean,
			});
		} catch (err) {
			await release();
			if (err instanceof CapExceededError) {
				throw new VerificationError(507, 'evidence_capacity', err.message, true);
			}
			throw err;
		}
		const startedAt = this.iso();
		const run: Run = RunSchema.parse({
			version: 1,
			runId,
			planId: plan.planId,
			deployment: plan.deployment,
			planDigest: plan.planDigest,
			state: 'running',
			startedAt,
		});
		const controller: RunControllerRecord = RunControllerRecordSchema.parse({
			version: 1,
			runId,
			planId: plan.planId,
			planDigest: plan.planDigest,
			...(key !== undefined ? { idempotencyKey: key } : {}),
			label,
			deployment: plan.deployment,
			profile: plan.profile,
			advisory: planning.advisory,
			state: 'running',
			cancelRequested: false,
			points: [
				...plan.points.map((p) => ({ id: p.id, state: 'pending', evidence: [] })),
				...plan.blocked.map((p) => ({
					id: p.id,
					state: 'done',
					outcome: 'blocked',
					reason: p.reason,
					evidence: [],
				})),
			],
			uncovered: plan.uncovered,
			policy: planning.policy,
			limits: planning.limits,
			lease: { leaseId: leased.lease.leaseId, expiresAt: leased.lease.expiresAt },
			readiness: { eligibleForMergeGate: false, reasons: ['the run is not finished'] },
			freshness: 'unknown',
			cleanup: 'unknown',
			startedAt,
			updatedAt: startedAt,
		});
		const startedAtMs = Date.parse(startedAt);
		const active: ActiveRun = {
			runId,
			writer,
			controller,
			plan,
			planning,
			inputs,
			image,
			observations: new Map(),
			cancel: false,
			closed: false,
			records: new Mutex(),
			finalized: false,
			ended: false,
			// The points' time runs from the start; the teardown gets its own.
			budget: new Budget(startedAtMs + planning.limits.runSeconds * 1000, startedAtMs),
			done: Promise.resolve(),
		};
		try {
			await writer.writeDeclared('run.json', run);
			await writer.writeDeclared('plan.json', plan);
			await this.saveController(active);
		} catch (err) {
			active.budget.close();
			await writer.abandon();
			await release();
			throw err;
		}
		this.active.set(runId, active);
		const accepted = acceptanceOf(controller);
		if (key !== undefined) this.accepted.set(key, accepted);
		active.done = this.execute(active).catch((err: unknown) =>
			this.deps.log(`run ${runId}: ${message(err)}`),
		);
		return accepted;
	}

	// Resolves once the run has finished, for callers that wait on it.
	async settled(runId: string): Promise<void> {
		await this.active.get(runId)?.done;
	}

	// What an earlier run left on the preview that could still touch the
	// app, or undefined when nothing did: a run of the label still
	// finishing here, a run network record naming the app's container, a
	// run network the container is still attached to, or a helper of a run
	// of the label. The startup cleanup removes leftovers of a koid that
	// died; this is for the ones of a run under this koid whose teardown is
	// not done, or failed and left the network in `destroying`.
	private async leftoversOn(label: string, container: string): Promise<string | undefined> {
		for (const run of this.active.values()) {
			if (run.controller.label === label && !run.ended) {
				return `run ${run.runId} is still finishing`;
			}
		}
		const network = this.deps.network;
		const records = network === undefined ? [] : await network.list();
		const held = records.find((r) => r.appContainer === container);
		if (held !== undefined) {
			return `run ${held.runId} still has its run network (${held.state})`;
		}
		for (const n of await this.deps.docker.networks()) {
			const runId = runNetworkOf(n);
			if (runId !== undefined && n.containers.includes(container)) {
				return `the app is still attached to the run network of ${runId}`;
			}
		}
		// Every helper is checked by its run's label, whether or not its run
		// has a network record: a record names the app container its run
		// bound to, and once the preview is redeployed under another
		// container that record says nothing about the new one, while the
		// helper can still reach the app.
		for (const c of await this.deps.docker.listRun()) {
			const helper = helperOf(c);
			if (helper === undefined) continue;
			const controller = await this.readController(helper.runId).catch(() => undefined);
			if (controller?.label === label) {
				return `${helper.name}, the ${helper.role} of run ${helper.runId}, still exists`;
			}
		}
		return undefined;
	}

	// What a run left on the box, or undefined when nothing: its network
	// record in any state, a helper of it, or its run network. A creation
	// that failed and whose rollback failed too leaves the first two; a
	// crash between steps could leave the others without a record.
	private async leftoversOfRun(runId: string, signal: AbortSignal): Promise<string | undefined> {
		const { network, docker } = this.deps;
		if (network === undefined) return undefined;
		const record = (await network.list()).find((r) => r.runId === runId);
		if (record !== undefined) return `its run network record (${record.state})`;
		for (const c of await docker.listRun(signal)) {
			const helper = helperOf(c);
			if (helper?.runId === runId) return `${helper.name}, its ${helper.role}`;
		}
		const net = (await docker.networks(signal)).find((n) => runNetworkOf(n) === runId);
		if (net !== undefined) return `its run network ${net.name}`;
		return undefined;
	}

	// Takes down what the run left, and fails when anything is still there
	// after. Once a creation began (`started`) this always goes through the
	// network's lock, even when nothing shows yet: the creation may still be
	// going after the run stopped waiting for it, and the lock puts this
	// behind it and its rollback. Otherwise it goes only when something
	// shows, so a run that never reached its network does not wait on a lock
	// another run holds. A record's own teardown removes the helpers, the
	// network and the record; without a record they go by name.
	private async removeLeftovers(
		runId: string,
		started: boolean,
		signal: AbortSignal,
	): Promise<void> {
		const { network, docker } = this.deps;
		if (network === undefined) return;
		if (!started && (await this.leftoversOfRun(runId, signal)) === undefined) return;
		if (!(await network.destroy(runId, { signal }))) {
			for (const c of await docker.listRun(signal)) {
				const helper = helperOf(c);
				if (helper?.runId === runId) await docker.remove(helper.name, signal);
			}
			for (const n of await docker.networks(signal)) {
				if (runNetworkOf(n) === runId) await docker.removeNetwork(n.name, signal);
			}
		}
		const left = await this.leftoversOfRun(runId, signal);
		if (left !== undefined) throw new Error(`${left} still exists`);
	}

	// The record stays the one object the run mutates; the schema checks it
	// on the way out and never replaces it, so no update is lost to a copy.
	// Nothing is written once the run is closed, and the check is made
	// under the run's record lock, so a save that was queued before the
	// close lands before the final record and none lands after it.
	private saveController(active: ActiveRun): Promise<void> {
		return active.records.run(async () => {
			if (active.closed) return;
			await this.writeController(active);
		});
	}

	private async writeController(active: ActiveRun): Promise<void> {
		active.controller.updatedAt = this.iso();
		const valid = RunControllerRecordSchema.parse(this.clean(active.controller));
		await active.writer.writeRecord('controller.json', valid);
	}

	// A failure the run has no named stop for, as a problem on the run: the
	// reader of the status learns of it, whether or not the disk takes the
	// write (addProblem keeps it in memory first).
	private async recordFailure(active: ActiveRun, err: unknown): Promise<void> {
		this.deps.log(`run ${active.runId}: ${message(err)}`);
		await active.writer
			.addProblem('run_failed', `the run stopped before its teardown: ${message(err)}`)
			.catch((e: unknown) =>
				this.deps.log(`run ${active.runId}: recording the failure: ${message(e)}`),
			);
	}

	// The run, from the lease to the bundle. Whatever happens, finish() runs
	// once: it tears down, judges, writes and releases. Nothing drive()
	// throws, a failed write of the deadline marks included, gets past this
	// without the teardown: the failure is recorded as a problem and the run
	// finishes as interrupted. The activity stamp and the lease are kept up
	// for as long as any of it goes on.
	private async execute(active: ActiveRun): Promise<void> {
		const deps = this.deps;
		const awake = setInterval(() => {
			void deps.keepAwake?.().catch(() => {});
			void this.keepLease(active).catch((err: unknown) =>
				deps.log(`run ${active.runId}: renewing the lease: ${message(err)}`),
			);
		}, deps.keepAwakeMs ?? KEEP_AWAKE_MS);
		const driven: Driven = {
			networkStarted: false,
			session: undefined,
			completion: undefined,
			interruption: undefined,
			abandoned: false,
		};
		try {
			try {
				await this.driveInTime(active, driven);
			} catch (err) {
				await this.recordFailure(active, err);
				driven.interruption ??= `${codeOf(err)}: ${message(err)}`;
				driven.completion = active.cancel ? 'cancelled' : 'interrupted';
			}
			await this.finish(active, driven);
		} finally {
			clearInterval(awake);
			active.budget.close();
		}
	}

	// drive(), for as long as anything in it may rightly take. Every wait in it has
	// an end of its own: the verifier's (verifierStopBy) and then the disk's. Past all
	// of those the run's teardown starts anyway, since it must start whatever
	// drive() is doing: the network and the helpers cannot stay up behind a wait
	// nobody thought of. What drive() does when it comes back changes nothing, as the
	// record is frozen by then (recordVerdict, markNotRun).
	private async driveInTime(active: ActiveRun, driven: Driven): Promise<void> {
		const { deps } = this;
		const { until } = active.budget;
		const clock = clockReaches(
			verifierStopBy(until, until) + 2 * DISK_WAIT_MS,
			() => deps.now().getTime(),
			deps.evidence.diskPollMs,
		);
		const driving = this.drive(active, driven);
		const stuck = await Promise.race([
			driving.then(() => false),
			clock.at.then(() => true),
		]).finally(clock.cancel);
		if (!stuck) return;
		driving.then(
			() => deps.log(`run ${active.runId}: its points ended after the run stopped waiting`),
			(err: unknown) =>
				deps.log(`run ${active.runId}: its points failed after that: ${message(err)}`),
		);
		driven.abandoned = true;
		driven.interruption ??= RUN_STUCK;
		driven.completion = 'interrupted';
	}

	// A call that waits on the preview store, while the run goes or stops. The store
	// may be on the disk that stopped answering, and neither the next step of a run
	// nor its teardown may wait on it without a limit.
	private async timed<T>(what: string, work: Promise<T>): Promise<T> {
		const { deps } = this;
		const clock = clockReaches(
			deps.now().getTime() + DISK_WAIT_MS,
			() => deps.now().getTime(),
			deps.evidence.diskPollMs,
		);
		let late = false;
		try {
			return await Promise.race([
				work,
				clock.at.then(() => {
					late = true;
					throw new Error(`${what} did not finish within ${DISK_WAIT_MS / 1000} seconds`);
				}),
			]);
		} finally {
			clock.cancel();
			if (late) {
				work.then(
					() => deps.log(`${what}: finished after the run stopped waiting`),
					(err: unknown) =>
						deps.log(`${what}: failed after the run stopped waiting: ${message(err)}`),
				);
			}
		}
	}

	// `make`, under the budget of the run's current phase: the call gets
	// the budget's signal, and the run stops waiting at the budget's end,
	// so a lock wait or a Docker command cannot hold the run past its
	// lease. An end reached before, during or by the time the call comes
	// back is the run's deadline (BudgetEndedError). Work that goes on
	// after the run stopped waiting is logged when it ends; the teardown
	// inspects what it left (leftoversOfRun).
	private async bounded<T>(
		active: ActiveRun,
		what: string,
		make: (signal: AbortSignal) => Promise<T>,
	): Promise<T> {
		const deps = this.deps;
		const begun = deps.now().getTime();
		if (active.budget.ended(begun)) throw new BudgetEndedError(`${what}: the run's time is up`);
		let result: T;
		try {
			result = await within(
				make(active.budget.signal),
				active.budget.remaining(begun),
				what,
				deps.log,
			);
		} catch (err) {
			if (active.budget.ended(deps.now().getTime())) {
				throw new BudgetEndedError(`${what}: the run's time ran out: ${message(err)}`);
			}
			throw err;
		}
		if (active.budget.ended(deps.now().getTime())) {
			throw new BudgetEndedError(`${what}: the run's time ran out during it`);
		}
		return result;
	}

	// The points: the network, the recorder, and each point in turn, until
	// the plan is done, the run is cancelled, its time is up, or it cannot
	// go on. Fills in `driven` for finish() as it goes.
	private async drive(active: ActiveRun, driven: Driven): Promise<void> {
		const { writer, controller, plan, inputs, image, runId } = active;
		const { label } = controller;
		const deps = this.deps;
		const network = deps.network;
		let deadline = false;
		try {
			if (network === undefined || deps.recorderImage === undefined) {
				throw new VerificationError(503, 'verification_unavailable', 'no run networks');
			}
			await writer.appendEvent({
				source: 'host',
				type: 'run-started',
				planId: plan.planId,
				planDigest: plan.planDigest,
			});
			const leased = await this.timed(
				'reading the lease',
				deps.deployer.leasedDeployment(label, controller.lease.leaseId),
			);
			const tokens = newRecorderTokens();
			// The verifier gets the browser token in its environment and may
			// print it; neither token may reach an event or a log.
			deps.secrets.add(tokens.control);
			deps.secrets.add(tokens.browser);
			// The image every point's verifier is made from. Unresolved, the plan
			// took no point and no verifier starts; the run network still needs its
			// third endpoint, so the placeholder comes from the default image.
			if (!image.ok) {
				await writer.appendEvent({
					source: 'host',
					type: 'runner-image-blocked',
					reason: image.reason,
				});
			}
			const defaultImage = deps.capability.available
				? deps.capability.verifierImageId
				: deps.recorderImage;
			// The setup is under the run's budget like the points: the wait
			// for the network lock, the network and the recorder's start.
			driven.networkStarted = true;
			const record = await this.bounded(active, `making the run network of ${runId}`, (signal) =>
				network.create(
					{
						runId,
						appContainer: leased.container,
						appPort: leased.port,
						recorderImage: deps.recorderImage as string,
						verifierImage: image.ok ? image.digest : defaultImage,
						recorderEnv: recorderEnv(tokens),
						seccompProfile: deps.recorderSeccomp,
					},
					{ signal },
				),
			);
			// Handed over as soon as it exists: a budget that ends just as the
			// start returns still needs the session's stop and last read.
			const session = await this.bounded(active, `starting the recorder of ${runId}`, async () => {
				driven.session = await RecorderSession.start(
					{
						docker: deps.docker,
						network,
						...(deps.recorderApi !== undefined ? { api: deps.recorderApi } : {}),
						secrets: deps.secrets,
						now: deps.now,
						sleep: deps.sleep,
						log: deps.log,
					},
					{
						record,
						tokens,
						run: writer,
						budget: active.budget,
						...(deps.recorderHealthTimeoutMs !== undefined
							? { healthTimeoutMs: deps.recorderHealthTimeoutMs }
							: {}),
					},
				);
				return driven.session;
			});
			const descriptor = this.descriptor(active, session, image);
			await writer.writeDeclared('execution.json', descriptor);
			controller.executionDigest = descriptor.executionDigest;
			await this.saveController(active);
			const run = { session, tokens, record, image };

			for (const planned of plan.points) {
				if (active.cancel || driven.abandoned) break;
				if (active.budget.ended(deps.now().getTime())) {
					deadline = true;
					break;
				}
				// The lease must still hold, and be kept ahead of the point.
				try {
					await this.timed('renewing the lease', this.keepLease(active));
					await this.timed(
						'reading the lease',
						deps.deployer.leasedDeployment(label, controller.lease.leaseId),
					);
				} catch (err) {
					driven.interruption = `lease_lost: ${message(err)}`;
					break;
				}
				const ended = await this.runPoint(active, run, planned, inputs);
				if ('deadline' in ended) {
					deadline = true;
					break;
				}
				if ('stop' in ended) {
					driven.interruption = ended.stop;
					break;
				}
			}
		} catch (err) {
			if (err instanceof RecorderDeadlineError || err instanceof BudgetEndedError) {
				deadline = true;
			} else {
				driven.interruption = `${codeOf(err)}: ${message(err)}`;
				driven.completion = 'interrupted';
				// A failed write says so here. The named stops say so already:
				// the recorder's start records its own, a lost lease is its code.
				if (codeOf(err) === 'run_failed') await this.recordFailure(active, err);
			}
		}
		if (deadline) await this.markNotRun(active);
		if (active.cancel) driven.completion = 'cancelled';
		else if (driven.interruption !== undefined) driven.completion = 'interrupted';
	}

	// The points not yet done when the run's time ran out are not-run, with
	// the deadline as their reason. The run is still evaluated: its time is
	// its own limit, not a failure of capture.
	private async markNotRun(active: ActiveRun): Promise<void> {
		const { controller, planning, writer } = active;
		if (active.closed) return;
		for (const p of controller.points) {
			if (p.state === 'done') continue;
			p.state = 'done';
			p.outcome = 'not-run';
			p.reason = `run_deadline: the run reached its limit of ${planning.limits.runSeconds} seconds before this point`;
		}
		await writer
			.appendEvent({ source: 'host', type: 'run-deadline' })
			.catch((err: unknown) => this.deps.log(`run ${active.runId}: ${message(err)}`));
		await this.saveController(active);
	}

	// Keeps the lease ahead of the run's budget: a lease about to expire
	// while the current phase still has time is renewed to the phase's end.
	// A run asks for no more than its own budget, the points' time and then
	// the teardown allowance, so a renewal cannot hold the label past what
	// the plan's limits allow. A renewal that is refused means the lease is
	// gone; the caller treats that as a lost lease.
	private async keepLease(active: ActiveRun): Promise<void> {
		if (active.closed) return;
		const { controller } = active;
		const now = this.deps.now().getTime();
		const expires = Date.parse(controller.lease.expiresAt);
		const until = active.budget.until;
		if (until <= expires || expires - now > LEASE_RENEW_MARGIN_MS) return;
		const lease = await this.deps.deployer.renewLease(
			controller.label,
			controller.lease.leaseId,
			Math.ceil((until - now) / 1000),
		);
		if (lease.expiresAt === controller.lease.expiresAt) return;
		controller.lease.expiresAt = lease.expiresAt;
		await this.saveController(active);
		this.deps.log(
			`run ${active.runId}: lease on ${controller.label} renewed to ${lease.expiresAt}`,
		);
	}

	// One point: its context opened in the recorder, its verifier created,
	// started and followed to its end, the point judged from what the
	// runner reported against what the recorder holds. Says whether the run
	// goes on, cannot (the recorder is gone), or ran out of time during it.
	// The recorder calls run under the point's own budget. A point that
	// reaches it is blocked (point_timeout) and the run goes on; the context
	// is closed under the run's budget, since the point's has ended by then.
	// A point with more budget than the run has left ends at the run's
	// deadline instead, with the rules for that.
	private async runPoint(
		active: ActiveRun,
		run: {
			session: RecorderSession;
			tokens: { browser: string };
			record: Awaited<ReturnType<VerificationNetwork['create']>>;
			image: ImageResolution;
		},
		planned: Plan['points'][number],
		inputs: Inputs,
	): Promise<PointEnd> {
		const { writer, controller, planning } = active;
		const { session } = run;
		const status = controller.points.find((p) => p.id === planned.id);
		const loaded = inputs.config.points.find((p) => p.point.id === planned.id);
		if (status === undefined || loaded === undefined) return { next: true };
		status.state = 'running';
		await this.saveController(active);
		const attempt = 1;
		let stop: string | undefined;
		let result: PointRun | undefined;
		let blocked: string | undefined;
		let deadline = false;
		let timedOut: string | undefined;
		const begun = this.deps.now().getTime();
		const seconds = pointBudgetSeconds(
			loaded.point,
			planning.limits,
			active.budget.remaining(begun),
		);
		// The formula works in whole seconds. A point cut short by what the run
		// has left ends with the run, so its end is the run's deadline and not
		// a point_timeout a fraction of a second before it.
		const end = begun + seconds * 1000;
		const budget = new Budget(active.budget.until - end < 1000 ? active.budget.until : end, begun);
		session.budget = {
			until: budget.until,
			signal: AbortSignal.any([budget.signal, active.budget.signal]),
			of: 'point',
		};
		try {
			await session.openPoint(planned.id, attempt, POINT_OPEN_PATH);
			if (!run.image.ok) {
				blocked = run.image.reason;
			} else if (this.verifier === undefined) {
				blocked = 'verifier_unavailable: no run networks';
			} else {
				const running = this.verifier.run(
					{
						runId: active.runId,
						pointId: planned.id,
						attempt,
						point: loaded.point,
						runnerCommand: inputs.config.manifest.runner.command,
						image: run.image.digest,
						record: run.record,
						browserToken: run.tokens.browser,
						source: inputs.source,
						fixtures:
							inputs.snapshot.verify.status === 'present' ? inputs.snapshot.verify.fixtures : [],
						timeoutSeconds: seconds,
						maxRequests: pointRequests(loaded.point, planning.limits),
						pointDeadline: budget.until,
						deadline: active.budget.until,
					},
					session,
					writer,
					{
						// A disk given up on by any write stops the point now: the run can
						// keep nothing it does from here.
						stopRequested: () => (active.cancel ? 'the run was cancelled' : writer.stuck?.message),
					},
				);
				result = await this.verifierEnd(
					active,
					running,
					verifierStopBy(budget.until, active.budget.until),
				);
				if (result.stuck) stop = VERIFIER_STUCK;
			}
		} catch (err) {
			// The session records a capture it could not keep as a problem on
			// the run; a recorder that no longer answers ends the run; and the
			// run's time running out ends the points. A recorder that refuses an
			// open because it holds a context koid could not close would refuse
			// every later point too, so that ends the run as well, rather than
			// blocking each of them with nothing captured.
			if (err instanceof VerifierStuckError) {
				blocked = VERIFIER_STUCK;
				stop = VERIFIER_STUCK;
			} else if (err instanceof RecorderDeadlineError) {
				const now = this.deps.now().getTime();
				if (budget.until >= active.budget.until || active.budget.ended(now)) deadline = true;
				else timedOut = `point_timeout: the point reached its budget of ${seconds} seconds`;
			} else {
				if (err instanceof RecorderLostError) {
					stop = `recorder_lost: ${err.message}`;
				} else if (
					err instanceof RecorderError &&
					(err.status >= 500 || err.code === 'context_open')
				) {
					stop = `recorder_unavailable: ${err.message}`;
				} else if (err instanceof CapExceededError) {
					stop = `cap_exceeded: ${err.message}`;
				} else {
					this.deps.log(`run ${active.runId}, point ${planned.id}: ${message(err)}`);
				}
				blocked ??= `${codeOf(err)}: ${message(err)}`;
			}
		} finally {
			budget.close();
			session.budget = active.budget;
			// The verifier stops at the run's end on its own and returns; the
			// run's budget has ended then as much as when a recorder call was
			// refused. Past the deadline the point's context stays open for
			// the teardown, which has time of its own; a close now would be
			// refused by the budget that just ended.
			if (active.budget.ended(this.deps.now().getTime())) deadline = true;
			if (!deadline) {
				await session
					.closePoint()
					.catch((err: unknown) => this.deps.log(`closing point ${planned.id}: ${message(err)}`));
			}
		}
		// A loss the session absorbed, in a drain or a capture, still ends
		// the run: what the recorder saw since is not in the run.
		if (stop === undefined && session.lost !== undefined) stop = `recorder_lost: ${session.lost}`;
		// The disk stopped answering. What the point cites cannot be checked and no
		// record can say how it went, so a pass is not believed, and a failure the
		// runner or the host reported stands. The point is judged in memory, and the
		// run stops here.
		const settleStuck = (stuck: Error): { stop: string } => {
			const lost = stuck.message;
			this.settleVerdict(
				active,
				status,
				this.clean(
					judgePoint({
						id: status.id,
						assertions: loaded.point.assertions.map((a) => ({
							name: a.name,
							evidence: a.evidence,
						})),
						reports: (result?.reports ?? []).filter((r) => r.outcome === 'fail'),
						resolve: () => undefined,
						blocked: lost,
						cleanup: result?.cleanup === 'failed' ? 'failed' : 'none',
						failures: result?.failures ?? [],
					}),
				),
			);
			return { stop: lost };
		};
		if (writer.stuck !== undefined) return settleStuck(writer.stuck);
		// An assertion may cite a capture by its label; the alias resolves to
		// the artifact the capture gave, within this point and attempt.
		const labels = result?.artifacts ?? {};
		const reports: AssertionReport[] = (result?.reports ?? []).map((r) => ({
			...r,
			evidence: r.evidence.map((ref) =>
				ref.startsWith('capture:') ? (labels[ref.slice('capture:'.length)] ?? ref) : ref,
			),
		}));
		// The judge below sees these as the runner sent them. Everything from here on
		// is kept and shown: the controller's record, the observations and the reasons
		// a pull request comment quotes. A reference or a reason can hold what a runner
		// or an error printed, so it goes through the sanitizer, which keeps a typed
		// record's field names: the verdict and the record below read them.
		const { clean } = this;
		const observed: ObservedPoint = clean({
			attempt,
			assertions: loaded.point.assertions.map((a) => a.name),
			asserted: reports.map(({ name, evidence, ...report }) => ({
				assertion: name,
				...report,
				cited: evidence,
			})),
			labels: Object.entries(labels).map(([name, artifact]) => ({ name, artifact })),
			...(result !== undefined
				? {
						stopped: result.stopped,
						steps: result.steps,
						exit: result.exit,
						cleanup: result.cleanup,
						counts: result.counts,
					}
				: {}),
		});
		if (deadline && result === undefined && blocked === undefined) {
			// The run's time ran out before the verifier ran, and that outranks
			// the point's own limit: nothing was observed.
			const reason = `run_deadline: the run reached its limit of ${planning.limits.runSeconds} seconds during this point`;
			await this.recordVerdict(active, status, observed, {
				id: planned.id,
				outcome: 'not-run',
				reasons: [reason],
				evidence: [],
			});
			return { deadline: true };
		}
		const hostBlocked = blocked ?? timedOut ?? result?.blocked;
		// The disk can stop answering during either wait below, and what the runner
		// reported must still count. Past this the verdict is set before anything is
		// written (recordVerdict).
		let resolve: Awaited<ReturnType<RunWriter['resolveEvidence']>>;
		let lost: LostEvidence[];
		// What the point may be judged on is checked on disk against its entry
		// before the judge sees it: what it captured, in this attempt. A
		// reference to anything else resolves to nothing, so a report cannot
		// borrow another point's capture. A withheld or failed entry never had
		// a file, so nothing of it can be lost; the judge reads its availability.
		// A file that fails the check is a problem on the run, fails the point
		// and is no evidence of it. finish() checks all of it again.
		const own = writer.artifacts.filter((a) => a.pointId === planned.id && a.attempt === attempt);
		const captured = own.filter((a) => a.availability === 'available').map((a) => a.id);
		try {
			if (hostBlocked !== undefined) {
				await writer.appendEvent({
					source: 'host',
					type: 'point-blocked',
					pointId: planned.id,
					attempt,
					// Through the sanitizer as a reason, which cuts it after the scrub: the
					// writer cuts no event, and one too long to keep costs the run its
					// evidence.
					reason: clean({ reason: hostBlocked }).reason,
				});
			}
			resolve = await writer.resolveEvidence(own.map((a) => a.id));
			lost = await this.lostEvidence(writer, resolve, captured);
		} catch (err) {
			if (writer.stuck === undefined) throw err;
			return settleStuck(writer.stuck);
		}
		const verdict = clean(
			withLostEvidence(
				judgePoint({
					id: planned.id,
					assertions: loaded.point.assertions.map((a) => ({ name: a.name, evidence: a.evidence })),
					reports,
					resolve,
					blocked: hostBlocked,
					cleanup: result?.cleanup ?? (loaded.point.cleanup === undefined ? 'none' : 'not-run'),
					recovery: result?.recovery ?? false,
					failures: result?.failures ?? [],
					hostEvidence: captured,
				}),
				lost,
			),
		);
		await this.recordVerdict(active, status, observed, verdict);
		if (deadline) return { deadline: true };
		return stop === undefined ? { next: true } : { stop };
	}

	// The verifier's end, or VerifierStuckError past `until`. Its own watchdog ends
	// every wait in it with the point, it gives up on Docker by itself, and the writer
	// gives up on the disk (RunWriter.onDisk), so this is for what is left: a wait no
	// signal reaches. What the point read is gone with it, so the point is blocked.
	// The verifier may still be going, under the one name a run has for it, so no
	// later point can start.
	private async verifierEnd(
		active: ActiveRun,
		running: Promise<PointRun>,
		until: number,
	): Promise<PointRun> {
		const { deps } = this;
		const clock = clockReaches(until, () => deps.now().getTime(), deps.verifierPollMs ?? 1_000);
		const ended = await Promise.race([running, clock.at]).finally(clock.cancel);
		if (ended !== undefined) return ended;
		running.then(
			() => deps.log(`run ${active.runId}: its verifier ended after the run stopped waiting`),
			(err: unknown) =>
				deps.log(`run ${active.runId}: its verifier failed after that: ${message(err)}`),
		);
		throw new VerifierStuckError();
	}

	// Which of `refs` no longer match their entries on disk. Each one becomes
	// a problem on the run, so the run cannot call its evidence complete.
	private async lostEvidence(
		writer: RunWriter,
		resolve: Awaited<ReturnType<RunWriter['resolveEvidence']>>,
		refs: string[],
	): Promise<LostEvidence[]> {
		const lost: LostEvidence[] = [];
		for (const ref of refs) {
			const integrity = resolve(ref)?.integrity ?? 'missing';
			if (integrity === 'verified') continue;
			lost.push({ ref, integrity });
			await writer.addProblem(
				`artifact_${integrity}`,
				integrity === 'corrupt'
					? `${ref}: the file on disk is not the size and sha256 its entry records`
					: `${ref}: its file is no longer on disk`,
			);
		}
		return lost;
	}

	// A point's verdict, into its status. Nothing past the freeze, since the run
	// stopped waiting for what comes back that late.
	private settleVerdict(active: ActiveRun, status: PointStatus, verdict: PointVerdict): void {
		if (active.closed) return;
		status.state = 'done';
		status.outcome = verdict.outcome;
		if (verdict.reasons.length > 0) status.reason = reasonText(verdict.reasons);
		else delete status.reason;
		status.evidence = verdict.evidence;
	}

	// A point's verdict, into its status and its observations.
	private async recordVerdict(
		active: ActiveRun,
		status: PointStatus,
		observed: ObservedPoint,
		verdict: PointVerdict,
	): Promise<void> {
		if (active.closed) return;
		this.settleVerdict(active, status, verdict);
		const observations: PointObservations = {
			version: 1,
			pointId: status.id,
			...observed,
			verdict,
		};
		active.observations.set(status.id, observations);
		await active.writer.writeObservations(status.id, observations);
		await this.saveController(active);
	}

	// Every artifact a point still cites, checked against the disk once more
	// before the run is judged. Each point's check ran as that point ended, and
	// a file can change any time after that; a verdict saved from then would
	// call such a run evaluated with its evidence complete. A file that fails
	// here is a problem on the run and fails its point, as it would have then.
	// The live record is frozen by now, so these changes reach the disk with
	// the final record; only the observations are written here.
	private async recheckEvidence(active: ActiveRun): Promise<void> {
		const { writer, controller } = active;
		const refs = controller.points.flatMap((p) => p.evidence);
		const lost = await this.lostEvidence(writer, await writer.resolveEvidence(refs), refs);
		for (const p of controller.points) {
			const own = lost.filter((l) => p.evidence.includes(l.ref));
			if (own.length === 0 || p.outcome === undefined) continue;
			const verdict = this.clean(
				withLostEvidence(
					{
						id: p.id,
						outcome: p.outcome,
						reasons: p.reason === undefined ? [] : [p.reason],
						evidence: p.evidence,
					},
					own,
				),
			);
			p.outcome = verdict.outcome;
			p.reason = reasonText(verdict.reasons);
			p.evidence = verdict.evidence;
			const observations = active.observations.get(p.id);
			if (observations !== undefined) {
				const judged = { ...observations, verdict };
				active.observations.set(p.id, judged);
				await writer.writeObservations(p.id, judged);
			}
		}
	}

	// Project text and koid's own values only, written as they are, so the digest holds.
	// The recorder's versions are the one thing it reports here, read once before any
	// page opens, and the schema holds each to a version's form.
	private descriptor(
		active: ActiveRun,
		session: RecorderSession,
		image: ImageResolution,
	): ExecutionDescriptor {
		const { planning, plan, runId } = active;
		const capability = this.deps.capability;
		const recorderImage = this.deps.recorderImage ?? 'unknown';
		const capabilities = [...session.capabilities].filter(
			(c): c is 'raw-cdp' | 'login-key' => c === 'raw-cdp' || c === 'login-key',
		);
		return ExecutionDescriptorSchema.parse(
			withExecutionDigest({
				version: 1,
				runId,
				planId: plan.planId,
				runnerImage: {
					reference: planning.runnerImage,
					...(image.ok ? { digest: image.digest } : {}),
				},
				recorderImage: {
					reference: recorderImage,
					digest: capability.available ? capability.recorderImageId : recorderImage,
				},
				browser: { name: 'chromium', version: session.health.browser.version },
				playwright: session.health.playwright,
				policy: { source: 'none', digest: canonicalDigest({ version: 1, required: [] }) },
				proofs: [],
				originMode: 'private-app',
				origin: session.health.origin,
				limits: {
					...planning.limits,
					artifactBytes: this.deps.evidence.limits.bytesPerArtifact,
					runBytes: this.deps.evidence.limits.bytesPerRun,
					artifacts: this.deps.evidence.limits.artifactsPerRun,
					events: this.deps.evidence.limits.eventsPerRun,
				},
				capabilities,
			}),
		);
	}

	// Teardown, judgement, records, the manifest, and the lease, in that
	// order: the lease goes only once nothing of the run is on the box. The
	// teardown has the allowance the lease was taken with, and nothing in
	// it waits longer; it inspects what the run made, whether or not the
	// setup succeeded, and takes it down. Judgement starts by freezing the
	// live record, which settles any cancel, and checking the evidence again,
	// since either can change how the run ended. The run's record says it is
	// finished only once the manifest is in: until then a reader sees it
	// running, so a status read never shows an evaluated run that is not
	// finalized. A bundle whose manifest could not be written is
	// `finalize-failed`, incomplete, whatever was judged; one whose
	// finalize-failed record could not be written either stays in `active`,
	// so its status stays the truth until koid restarts. A disk that stopped
	// answering takes the same way out from wherever the run has got to, with the
	// teardown done first and the lease released last: nothing here waits on the
	// disk past RunWriter.onDisk.
	private async finish(active: ActiveRun, driven: Driven): Promise<void> {
		const { writer, controller, plan, planning, runId } = active;
		const { session } = driven;
		const { label } = controller;
		const deps = this.deps;
		let completion = driven.completion;
		let { interruption } = driven;
		// Cast so it is not narrowed to 'succeeded': failedTeardown changes it
		// from a closure, which the compiler does not see.
		let cleanup = 'succeeded' as RunControllerRecord['cleanup'];
		// The teardown's own time, from now; the lease is kept ahead of it.
		const startedTeardown = deps.now().getTime();
		active.budget.close();
		active.budget = new Budget(
			startedTeardown + (deps.teardownAllowanceMs ?? TEARDOWN_ALLOWANCE_SECONDS * 1000),
			startedTeardown,
		);
		if (session !== undefined) session.budget = active.budget;
		await this.timed('renewing the lease', this.keepLease(active)).catch((err: unknown) =>
			deps.log(`run ${runId}: renewing the lease for the teardown: ${message(err)}`),
		);
		// A teardown step that did not finish, or did not finish in time,
		// leaves the run on the box as far as koid knows: the cleanup is
		// failed and the lease stays, so no new run is admitted on the app
		// while the step may still be going.
		const failedTeardown = async (err: unknown) => {
			cleanup = 'failed';
			await writer
				.addProblem('teardown_failed', message(err))
				.catch((e: unknown) => deps.log(`recording a failed teardown: ${message(e)}`));
			interruption ??= `teardown_failed: ${message(err)}`;
			completion = 'interrupted';
		};
		let recordSaved = true;
		try {
			if (session !== undefined) {
				try {
					await within(
						session.stop(),
						active.budget.remaining(deps.now().getTime()),
						`stopping the recorder of ${runId}`,
						deps.log,
					);
				} catch (err) {
					await failedTeardown(err);
				}
				// A loss the session absorbed in its last drain, after the
				// last point was judged, still means events of the run were
				// never read.
				if (completion === undefined && session.lost !== undefined) {
					interruption = `recorder_lost: ${session.lost}`;
					completion = 'interrupted';
				}
			}
			// Whatever the setup got to, what the run left goes before the
			// lease does. The network's teardown runs root-owned steps that
			// cannot be aborted; past the allowance the run stops waiting.
			try {
				await within(
					this.removeLeftovers(runId, driven.networkStarted, active.budget.signal),
					active.budget.remaining(deps.now().getTime()),
					`taking down the run network of ${runId}`,
					deps.log,
				);
			} catch (err) {
				await failedTeardown(err);
			}
			// The disk stopped answering, whenever that was: the final record below
			// cannot be written, and no judgement stands without one.
			if (writer.stuck !== undefined) throw writer.stuck;
			// The identity at the end must be the one the run began with.
			if (completion === undefined) {
				try {
					await this.timed(
						'reading the lease',
						deps.deployer.leasedDeployment(label, controller.lease.leaseId),
					);
				} catch (err) {
					interruption = `identity_unverified: ${message(err)}`;
					completion = 'interrupted';
				}
			}
			// From here the live record is frozen: a save queued before this
			// lands first, none lands after, and a cancel that arrives now is
			// answered once the run has ended.
			await active.records.run(async () => {
				active.closed = true;
			});
			if (driven.abandoned) endRunningPoints(controller, RUN_STUCK);
			// A cancel accepted up to this point was answered as running with
			// cancelRequested, so the run must end as cancelled, whenever it
			// arrived. A failed teardown outranks it, as it outranks a cancel
			// made during the points: the lease stays and an operator must look.
			if (active.cancel && cleanup !== 'failed') completion = 'cancelled';
			await this.recheckEvidence(active);
			if (completion === undefined) {
				completion = writer.status.evidence === 'incomplete' ? 'capture-error' : 'evaluated';
			}
			const ended = completion;
			const freshness = await this.timed('reading the preview', this.freshness(controller)).catch(
				(): RunControllerRecord['freshness'] => 'unknown',
			);
			const finishedAt = this.iso();
			const state = ended === 'cancelled' ? 'cancelled' : 'completed';
			// The final records, from the live record as it is now. Each is written once:
			// what koid learns after this stays out of replies, and the files stay as the
			// manifest hashes them.
			const verdicts: PointVerdict[] = controller.points
				.filter((p) => p.state === 'done' && p.outcome !== undefined)
				.map((p) => ({
					id: p.id,
					outcome: p.outcome as PointVerdict['outcome'],
					reasons: p.reason === undefined ? [] : [p.reason],
					evidence: p.evidence,
				}));
			const { uncovered } = controller;
			const run = judgeRun({ runId, completion: ended, points: verdicts, uncovered });
			const outcome: RunOutcome = run.outcome;
			const readiness = judgeReadiness({
				outcome,
				completion: ended,
				policy: {
					source: planning.policy.source,
					required:
						planning.policy.source === 'base-branch'
							? (planning.policy.advisory?.required ?? [])
							: [],
				},
				planned: plan.points.map((p) => ({ id: p.id, revision: p.revision })),
				points: verdicts,
				proofs: [],
				freshness,
				uncovered,
				cleanup,
				advisory: planning.advisory,
			});
			const terminal: Partial<RunControllerRecord> = {
				state,
				completion: ended,
				outcome,
				...(interruption !== undefined ? { interruption } : {}),
				readiness,
				freshness,
				cleanup,
				finishedAt,
				updatedAt: finishedAt,
			};
			const final: RunControllerRecord = RunControllerRecordSchema.parse(
				this.clean({ ...controller, ...terminal }),
			);
			if (run.result !== null) await writer.writeRecord('result.json', run.result);
			const limitations = [...BUNDLE_LIMITATIONS, ...(session?.limitations ?? [])].slice(0, 50);
			// One record, scrubbed as the file is written. `final` was made before the writes
			// above, and koid may have learned a secret during them.
			await writer.writeReport((clean) => {
				const report = clean({
					input: this.reportInput(active, final, session),
					problems: writer.status.problems,
					limitations,
				});
				return renderReport(report.input, {
					problems: report.problems,
					limitations: report.limitations,
					reasons: report.input.points.map((p) => ({
						id: p.id,
						reasons: p.reason === undefined ? [] : [p.reason],
					})),
				});
			});
			await writer.writeRecord('controller.json', final);
			await writer.writeDeclared(
				'run.json',
				RunSchema.parse({
					version: 1,
					runId,
					planId: plan.planId,
					deployment: plan.deployment,
					planDigest: plan.planDigest,
					state,
					startedAt: controller.startedAt,
					finishedAt,
				}),
			);
			await writer.setState(
				ended === 'cancelled' ? 'cancelled' : ended === 'interrupted' ? 'failed' : 'completed',
			);
			await writer.finalize({
				planId: plan.planId,
				planDigest: plan.planDigest,
				...(controller.executionDigest !== undefined
					? { executionDigest: controller.executionDigest }
					: {}),
				limitations,
			});
			// Only now is the run finished for a reader. The manifest is in, so
			// the status read during the lease's release below is the final one.
			active.finalized = true;
			Object.assign(controller, terminal);
			deps.log(
				`run ${runId} of ${label}: ${ended}, ${outcome}${interruption === undefined ? '' : ` (${interruption})`}`,
			);
		} catch (err) {
			deps.log(`run ${runId}: finishing: ${message(err)}`);
			// Without a manifest nothing of the run counts, whatever was
			// judged: the record says so, on disk and in memory. A disk that
			// stopped answering outranks all else, a cancel too: it is what ended
			// the run, and this is all a reader will learn of why.
			const at = this.iso();
			const { stuck } = writer;
			const stateNow = () => (stuck === undefined && active.cancel ? 'cancelled' : 'completed');
			controller.state = stateNow();
			controller.completion = stuck === undefined ? 'finalize-failed' : 'interrupted';
			controller.outcome = 'incomplete';
			controller.interruption = stuck?.message ?? `finalize_failed: ${message(err)}`;
			controller.readiness = {
				eligibleForMergeGate: false,
				reasons: [
					stuck === undefined
						? 'the run was not finalized: its manifest was not written'
						: 'the run was interrupted: its evidence could not be written',
				],
			};
			if (stuck !== undefined) endRunningPoints(controller, stuck.message);
			controller.cleanup = cleanup;
			controller.finishedAt ??= at;
			await writer
				.addProblem('finalize_failed', `the bundle was not finalized: ${message(err)}`)
				.catch((e: unknown) =>
					deps.log(`run ${runId}: recording the failed finalize: ${message(e)}`),
				);
			// The final record, whatever `closed` says: this is the one write
			// that must land.
			recordSaved = await active.records
				.run(async () => {
					active.closed = true;
					// Again, now that it is frozen: a cancel may have come in the
					// wait for this lock.
					controller.state = stateNow();
					await this.writeController(active);
				})
				.then(
					() => true,
					(e: unknown) => {
						deps.log(`run ${runId}: recording the failed finalize: ${message(e)}`);
						return false;
					},
				);
			await writer.abandon().catch(() => {});
		}
		if (cleanup === 'succeeded') {
			await this.timed(
				'releasing the lease',
				deps.deployer.releaseLease(label, controller.lease.leaseId),
			).catch((err: unknown) => deps.log(`releasing the lease of ${runId}: ${message(err)}`));
		} else {
			deps.log(
				`run ${runId}: teardown ${cleanup}; the lease on ${label} stays until it expires at ${controller.lease.expiresAt}`,
			);
		}
		active.ended = true;
		// With its final record not on disk, this entry is the only place that
		// holds how the run ended; dropped, a reader would get the earlier
		// record, which says running or claims a verdict. It stays until koid
		// restarts and recovery settles the record. It takes a run that passed
		// its first writes and then lost the disk, so these stay few, and
		// evicting one would bring back the stale read this entry prevents.
		if (recordSaved) this.active.delete(runId);
		else {
			deps.log(
				`run ${runId}: its final record is not on disk; its state is kept in memory until koid restarts`,
			);
		}
	}

	private reportInput(
		active: ActiveRun,
		controller: RunControllerRecord,
		session: RecorderSession | undefined,
	): ReportInput {
		const { plan, planning } = active;
		const deployment = plan.deployment;
		return {
			runId: active.runId,
			outcome: controller.outcome ?? 'incomplete',
			readiness: controller.readiness,
			commit: deployment.commit,
			head: deployment.merge?.head,
			baseBranch: deployment.merge?.baseBranch,
			base: deployment.merge?.base,
			deploymentId: deployment.deploymentId,
			imageDigest: deployment.imageDigest,
			planDigest: plan.planDigest,
			executionDigest: controller.executionDigest,
			freshness: controller.freshness,
			checkedAt: controller.finishedAt ?? this.iso(),
			origin: session?.health.origin,
			points: controller.points.map((p) => ({
				id: p.id,
				outcome: p.outcome,
				reason: p.reason,
				evidence: p.evidence,
			})),
			exclusions: [],
			uncovered: controller.uncovered,
			recoveries: [],
			completion: controller.completion,
			interruption: controller.interruption,
			cleanup: controller.cleanup,
			evidenceLink: undefined,
			retainedUntil: undefined,
			unavailable: active.writer.artifacts
				.filter((a) => a.availability !== 'available')
				.map((a) => `${a.id} (${a.availability})`),
			label: controller.label,
			profile: planning.profile,
		};
	}

	// Whether the deployment the run bound to still serves the label.
	private async freshness(
		controller: Pick<RunControllerRecord, 'label' | 'deployment'>,
	): Promise<RunControllerRecord['freshness']> {
		let record: Awaited<ReturnType<PreviewStore['get']>>;
		try {
			record = await this.deps.store.get(controller.label);
		} catch {
			return 'unknown';
		}
		if (record === undefined) return 'stale';
		const now = deploymentIdentity(record);
		return now !== undefined && sameDeployment(now, controller.deployment) ? 'current' : 'stale';
	}

	// -- Reads ------------------------------------------------------------------

	private async readController(runId: string): Promise<RunControllerRecord | undefined> {
		const text = await readFile(
			join(this.deps.evidence.runDir(runId), 'controller.json'),
			'utf8',
		).catch(() => undefined);
		if (text === undefined) return undefined;
		return RunControllerRecordSchema.parse(JSON.parse(text));
	}

	// A run as every reply reads it: through the sanitizer, with the secrets known now, so
	// no reply can say more than this. A read writes nothing: a record is written once, and
	// what it holds from before koid learned a secret is masked here, on the way out.
	private async readRun(runId: string) {
		VerifyIdSchema.parse(runId);
		const { evidence } = this.deps;
		const live = this.active.get(runId);
		const controller = live?.controller ?? (await this.readController(runId));
		if (controller === undefined)
			throw new VerificationError(404, 'no_such_run', `no run ${runId}`);
		const manifest =
			live === undefined || live.finalized ? await evidence.readManifest(runId) : undefined;
		const status = live !== undefined ? live.writer.status : await evidence.readStatus(runId);
		return {
			controller: this.clean(controller),
			status: this.clean(status),
			manifest: this.clean(manifest),
		};
	}

	async status(runId: string, after = 0): Promise<RunStatusReply> {
		const { controller: stored, status, manifest } = await this.readRun(runId);
		const finalized = manifest !== undefined;
		// A record that says the run ended is believed only with the manifest
		// that ends a run, or when koid wrote it as the end of a run that has
		// none. Any other such record is the end of a run whose finalize did
		// not complete, however it came to be on disk, and is reported as that.
		const distrusted = stored.state !== 'running' && !finalized && !endsWithoutManifest(stored);
		const controller: RunControllerRecord = distrusted
			? {
					...stored,
					completion: 'finalize-failed',
					outcome: 'incomplete',
					interruption: stored.interruption ?? 'finalize_failed: the manifest was not written',
					readiness: {
						eligibleForMergeGate: false,
						reasons: ['the run was not finalized: its manifest was not written'],
					},
				}
			: stored;
		const freshness = await this.freshness(controller);
		const problems = status?.problems ?? [];
		const base: Omit<RunStatusReply, 'points' | 'next'> = {
			version: 1,
			runId,
			planId: controller.planId,
			planDigest: controller.planDigest,
			...(controller.executionDigest !== undefined
				? { executionDigest: controller.executionDigest }
				: {}),
			label: controller.label,
			deployment: controller.deployment,
			profile: controller.profile,
			advisory: controller.advisory,
			state: controller.state,
			...(controller.completion !== undefined ? { completion: controller.completion } : {}),
			...(controller.outcome !== undefined ? { outcome: controller.outcome } : {}),
			...(controller.interruption !== undefined ? { interruption: controller.interruption } : {}),
			cancelRequested: controller.cancelRequested,
			readiness: controller.readiness,
			freshness,
			evidence: distrusted ? 'incomplete' : (status?.evidence ?? 'incomplete'),
			finalized,
			cleanup: controller.cleanup,
			limits: controller.limits,
			leaseExpiresAt: controller.lease.expiresAt,
			progress: {
				total: controller.points.length,
				done: controller.points.filter((p) => p.state === 'done').length,
			},
			problems: problems.slice(0, STATUS_PROBLEMS),
			problemCount: problems.length,
			startedAt: controller.startedAt,
			...(controller.finishedAt !== undefined ? { finishedAt: controller.finishedAt } : {}),
		};
		// The unpaged parts, cut until a page of points has room; then the
		// page, each point cut to an entry's size.
		const trimmed = cutToFit({ ...base, points: [], next: 0 }, STATUS_CUTS);
		const { page, next, truncated } = fit(
			controller.points,
			after,
			budgetFor(trimmed.reply),
			'points',
			cutPoint,
		);
		const { next: _measured, ...rest } = trimmed.reply;
		return this.measured(
			RunStatusReplySchema.parse({
				...rest,
				points: page,
				...(next !== undefined ? { next } : {}),
				...marked([...trimmed.truncated, ...truncated]),
			}),
			'status',
		);
	}

	// A reply as it goes out: it is measured against the bound it was built
	// under, and one over it, which the cuts should make impossible, is
	// logged so the cuts can be fixed.
	private measured<T>(reply: T, what: string): T {
		const size = jsonBytes(reply);
		if (size > VERIFICATION_REPLY_MAX_BYTES) {
			this.deps.log(
				`a ${what} reply is ${size} bytes, over the bound of ${VERIFICATION_REPLY_MAX_BYTES}`,
			);
		}
		return reply;
	}

	async events(runId: string, after = 0, limit = EVENTS_PAGE_MAX): Promise<RunEventsPage> {
		await this.readRun(runId);
		const path = join(this.deps.evidence.runDir(runId), 'events.ndjson');
		if ((await stat(path).catch(() => undefined)) === undefined) {
			throw new VerificationError(
				410,
				'evidence_expired',
				`the events of run ${runId} are no longer kept`,
			);
		}
		const base = {
			version: 1 as const,
			runId,
			events: [] as EvidenceEvent[],
			next: 0,
			more: false,
		};
		// An event line is at most MAX_EVENT_BYTES (the writer replaces a
		// longer one), well under the bound less the reply around it, so a
		// page always holds at least the next event whole.
		const budget = budgetFor(base);
		const max = Math.max(1, Math.min(limit, EVENTS_PAGE_MAX));
		const events: EvidenceEvent[] = [];
		const truncated: string[] = [];
		let used = 0;
		let more = false;
		let next = after;
		await readLines(path, (line) => {
			let event: EvidenceEvent;
			try {
				const parsed = EvidenceEventSchema.safeParse(JSON.parse(line));
				if (!parsed.success) return true;
				event = this.clean(parsed.data);
			} catch {
				return true;
			}
			if (event.seq <= after) return true;
			const size = jsonBytes(event) + 1;
			if (events.length >= max || (events.length > 0 && used + size > budget)) {
				more = true;
				return false;
			}
			if (events.length === 0 && size > budget) {
				// Not possible for a line the writer accepted; if a line is
				// over the bound anyway, the page skips it and says so, rather
				// than send a reply SSM would cut.
				truncated.push(`events[${event.seq}]`);
				next = event.seq;
				return true;
			}
			events.push(event);
			used += size;
			next = event.seq;
			return true;
		});
		return this.measured(
			RunEventsPageSchema.parse({ ...base, events, next, more, ...marked(truncated) }),
			'events',
		);
	}

	async evidence(runId: string, after = 0): Promise<EvidenceReply> {
		const { manifest, status } = await this.readRun(runId);
		const dir = this.deps.evidence.runDir(runId);
		if (status === undefined) {
			throw new VerificationError(404, 'no_such_run', `run ${runId} has no status`);
		}
		const expired = (await stat(join(dir, 'tombstone.json')).catch(() => undefined)) !== undefined;
		const base: Omit<EvidenceReply, 'artifacts' | 'next'> = {
			version: 1,
			runId,
			finalized: manifest !== undefined,
			expired,
			status: manifest?.status ?? status,
			...(manifest !== undefined
				? {
						retention: {
							retainedUntil: manifest.retainedUntil,
							tombstoneUntil: manifest.tombstoneUntil,
						},
						events: manifest.events,
					}
				: {}),
			limitations: manifest?.limitations ?? [],
			artifactCount: manifest?.artifacts.length ?? status.counts.artifacts,
		};
		const artifacts = expired ? [] : (manifest?.artifacts ?? []);
		const trimmed = cutToFit({ ...base, artifacts: [], next: 0 }, EVIDENCE_CUTS);
		const { page, next, truncated } = fit(
			artifacts,
			after,
			budgetFor(trimmed.reply),
			'artifacts',
			cutArtifact,
		);
		const { next: _measured, ...rest } = trimmed.reply;
		return this.measured(
			EvidenceReplySchema.parse({
				...rest,
				artifacts: page,
				...(next !== undefined ? { next } : {}),
				...marked([...trimmed.truncated, ...truncated]),
			}),
			'evidence',
		);
	}

	async artifact(
		runId: string,
		artifactId: string,
		offset = 0,
		length = ARTIFACT_CHUNK_BYTES,
	): Promise<ArtifactChunk> {
		const { manifest } = await this.readRun(runId);
		const id = ArtifactIdSchema.parse(artifactId);
		if (manifest === undefined) {
			throw new VerificationError(
				409,
				'not_finalized',
				`run ${runId} is not finalized; its artifacts are not readable yet`,
				true,
			);
		}
		const entry = manifest.artifacts.find((a) => a.id === id);
		if (entry === undefined) {
			throw new VerificationError(404, 'no_such_artifact', `run ${runId} has no artifact ${id}`);
		}
		const dir = this.deps.evidence.runDir(runId);
		if ((await stat(join(dir, 'tombstone.json')).catch(() => undefined)) !== undefined) {
			throw new VerificationError(
				410,
				'evidence_expired',
				`the evidence of run ${runId} has expired`,
			);
		}
		if (entry.availability !== 'available') {
			throw new VerificationError(
				409,
				'artifact_unavailable',
				`${id} is ${entry.availability}: ${entry.redaction.limitations[0] ?? 'no bytes were kept'}`,
			);
		}
		if (offset > entry.size) {
			throw new VerificationError(400, 'bad_offset', `${id} is ${entry.size} bytes`);
		}
		const want = Math.max(0, Math.min(length, ARTIFACT_CHUNK_BYTES, entry.size - offset));
		const handle = await open(
			join(dir, 'artifacts', id),
			constants.O_RDONLY | constants.O_NOFOLLOW,
		);
		let bytes: Buffer;
		try {
			const info = await handle.stat();
			if (!info.isFile() || info.size !== entry.size) {
				throw new VerificationError(
					500,
					'artifact_corrupt',
					`${id} on disk is not the ${entry.size}-byte file the manifest records`,
				);
			}
			bytes = Buffer.alloc(want);
			let at = 0;
			while (at < want) {
				const { bytesRead } = await handle.read(bytes, at, want - at, offset + at);
				if (bytesRead === 0) break;
				at += bytesRead;
			}
			bytes = bytes.subarray(0, at);
		} finally {
			await handle.close();
		}
		const end = offset + bytes.length;
		const truncated = end < entry.size;
		// The entry came through the sanitizer with the manifest. The bytes are what its
		// capture's sanitizer left, and they hash to the entry.
		return ArtifactChunkSchema.parse({
			version: 1,
			runId,
			artifact: id,
			kind: entry.kind,
			mediaType: entry.mediaType,
			size: entry.size,
			sha256: entry.sha256,
			offset,
			length: bytes.length,
			dataBase64: bytes.toString('base64'),
			...(truncated ? { next: end } : {}),
			truncated,
			...(truncated
				? {
						note: `${entry.size - end} bytes follow this chunk; an export over SSM reads chunks up to its ceiling, and a larger artifact needs the channel (C2)`,
					}
				: {}),
		});
	}

	async cancel(runId: string): Promise<RunStatusReply> {
		const active = this.active.get(runId);
		if (active === undefined) {
			// Finished or never started: the status says which.
			return this.status(runId);
		}
		if (active.closed) {
			// The final records are being written: a cancel changes nothing
			// now, and is answered with the state the run ends in.
			await active.done;
			return this.status(runId);
		}
		if (!active.cancel) {
			active.cancel = true;
			active.controller.cancelRequested = true;
			await active.writer
				.appendEvent({ source: 'host', type: 'cancel-requested' })
				.catch((err: unknown) => this.deps.log(`recording a cancel: ${message(err)}`));
			await this.saveController(active).catch((err: unknown) =>
				this.deps.log(`saving a cancel: ${message(err)}`),
			);
		}
		return this.status(runId);
	}

	// -- Restart ----------------------------------------------------------------

	// At startup, before the control socket listens: every run left running
	// by the last koid is marked interrupted, outcome incomplete, and never
	// becomes passed. Its network and helpers were removed by the startup
	// cleanup (verification-network.ts); its lease is released only when
	// that cleanup is known to have run, else it stays until it expires. A
	// run the last koid judged but whose manifest it did not write is
	// treated the same: a bundle without a manifest counts for nothing, so
	// it becomes finalize-failed, outcome incomplete, and keeps the points
	// it had judged. Every run's idempotency key is loaded back, finished runs
	// included. Returns the runs recovered.
	async recover(options: { releaseLeases: boolean }): Promise<string[]> {
		const recovered: string[] = [];
		const runs = join(this.deps.evidence.root, 'runs');
		let names: string[];
		try {
			names = await readdir(runs);
		} catch (err) {
			if (isNotFound(err)) return [];
			throw err;
		}
		for (const runId of names.sort()) {
			if (!VerifyIdSchema.safeParse(runId).success) continue;
			try {
				const controller = await this.readController(runId);
				if (controller === undefined) continue;
				// Every keyed run, finished or not: a retry of its request gets
				// the first acceptance back and starts nothing.
				if (controller.idempotencyKey !== undefined) {
					this.accepted.set(controller.idempotencyKey, acceptanceOf(controller));
				}
				const running = controller.state === 'running';
				// A run an earlier start recovered has no manifest either, and
				// is left as it is: its interruption names the restart.
				const unfinalized =
					!running &&
					!endsWithoutManifest(controller) &&
					(await this.deps.evidence.readManifest(runId)) === undefined;
				if (!running && !unfinalized) continue;
				const at = this.iso();
				const dir = this.deps.evidence.runDir(runId);
				const detail = running
					? 'koid_restarted: koid restarted while the run was running'
					: 'koid_restarted: koid restarted before the run was finalized; its manifest was not written';
				const updated = RunControllerRecordSchema.parse(
					this.clean({
						...controller,
						state: running ? 'completed' : controller.state,
						completion: running ? 'interrupted' : 'finalize-failed',
						outcome: 'incomplete',
						interruption: detail,
						points: controller.points.map((p) =>
							p.state === 'running' ? { ...p, state: 'pending' } : p,
						),
						readiness: {
							eligibleForMergeGate: false,
							reasons: [
								running
									? 'the run was interrupted: koid restarted'
									: 'the run was not finalized: its manifest was not written',
							],
						},
						cleanup: running
							? options.releaseLeases
								? 'succeeded'
								: 'unknown'
							: controller.cleanup,
						finishedAt: controller.finishedAt ?? at,
						updatedAt: at,
					}),
				);
				const { evidence } = this.deps;
				await evidence.writeRecord(dir, 'controller.json', updated, this.clean);
				const status = await evidence.readStatus(runId);
				if (status !== undefined) {
					const problems = status.problems.slice(0, MAX_PROBLEMS - 1);
					const code = running ? 'koid_restarted' : 'finalize_failed';
					await evidence.writeRecord(
						dir,
						'status.json',
						RunStatusSchema.parse({
							...status,
							state: status.state === 'running' ? 'failed' : status.state,
							evidence: 'incomplete',
							finishedAt: status.finishedAt ?? at,
							updatedAt: at,
							problems: [...problems, { code, detail, at }],
						}),
						this.clean,
					);
				}
				const runText = await readFile(join(dir, 'run.json'), 'utf8').catch(() => undefined);
				if (runText !== undefined) {
					const run = RunSchema.safeParse(JSON.parse(runText));
					if (run.success && run.data.state === 'running') {
						await evidence.writeDeclared(
							dir,
							'run.json',
							RunSchema.parse({ ...run.data, state: 'completed', finishedAt: at }),
						);
					}
				}
				// The lease is released only once the helpers are known gone,
				// and only when it is still this run's.
				const leaseKnownGone = updated.cleanup === 'succeeded' && options.releaseLeases;
				if (leaseKnownGone) {
					const record = await this.deps.store.get(controller.label);
					const lease = record?.lease;
					if (
						lease !== undefined &&
						lease.leaseId === controller.lease.leaseId &&
						lease.holder === runLeaseHolder(runId)
					) {
						await this.deps.deployer
							.releaseLease(controller.label, lease.leaseId)
							.catch((err: unknown) => {
								if (!(err instanceof NoSuchLeaseError)) {
									this.deps.log(`releasing the lease of interrupted run ${runId}: ${message(err)}`);
								}
							});
					}
				} else {
					this.deps.log(
						`run ${runId}: the lease on ${controller.label} stays until it expires at ${controller.lease.expiresAt}; teardown was not proved`,
					);
				}
				recovered.push(runId);
			} catch (err) {
				this.deps.log(`recovering run ${runId}: ${message(err)}`);
			}
		}
		if (recovered.length > 0) {
			this.deps.log(`marked ${recovered.join(', ')} incomplete after restart`);
		}
		return recovered;
	}
}

// -- Ending a point the run stopped waiting for ---------------------------------

// A point the run was still in when it stopped waiting has no verdict and never
// will. It is blocked, with why: a record in which a point of a finished run is
// still running would read as though something were still going.
function endRunningPoints(record: RunControllerRecord, reason: string): void {
	for (const point of record.points) {
		if (point.state !== 'running') continue;
		point.state = 'done';
		point.outcome = 'blocked';
		point.reason = reason;
	}
}

// -- Plan helpers --------------------------------------------------------------

// The limits of a run of this manifest: the manifest's budgets under the
// host ceilings, with the defaults where it names none. A point's own
// budget applies at run time (pointBudgetSeconds).
export function resolveLimits(config: VerifyConfig): RunLimits {
	const budgets = config.manifest.budgets;
	const runSeconds = Math.min(
		budgets?.timeoutSeconds ?? RUN_LIMIT_DEFAULTS.runSeconds,
		RUN_LIMIT_CEILINGS.runSeconds,
	);
	const runRequests = Math.min(
		budgets?.maxRequests ?? RUN_LIMIT_DEFAULTS.runRequests,
		RUN_LIMIT_CEILINGS.runRequests,
	);
	return {
		runSeconds,
		pointSeconds: Math.min(
			budgets?.timeoutSeconds ?? RUN_LIMIT_DEFAULTS.pointSeconds,
			RUN_LIMIT_CEILINGS.pointSeconds,
			runSeconds,
		),
		runRequests,
		pointRequests: Math.min(
			budgets?.maxRequests ?? RUN_LIMIT_DEFAULTS.pointRequests,
			RUN_LIMIT_CEILINGS.pointRequests,
			runRequests,
		),
	};
}

// A point's time budget, the one formula for it: its own, or the plan's point
// limit when it names none, under the host's ceiling and the time the run has
// left. The plan's limit is the default and no ceiling: a point may ask for
// more than the manifest's value. At least a second, so a point at the run's
// end still gets a verifier and a reason.
export function pointBudgetSeconds(
	point: Pick<Point, 'budgets'>,
	limits: RunLimits,
	remainingMs: number,
): number {
	return Math.max(
		1,
		Math.min(
			point.budgets?.timeoutSeconds ?? limits.pointSeconds,
			RUN_LIMIT_CEILINGS.pointSeconds,
			Math.floor(Math.max(0, remainingMs) / 1000),
		),
	);
}

// A point's request budget, by the same formula, under the run's.
export function pointRequests(point: Pick<Point, 'budgets'>, limits: RunLimits): number {
	return Math.min(
		point.budgets?.maxRequests ?? limits.pointRequests,
		RUN_LIMIT_CEILINGS.pointRequests,
		limits.runRequests,
	);
}

// Why this project's globs and these changed files are more than a plan takes, or undefined
// (PLAN_LIMITS).
function overPlanLimit(config: VerifyConfig, changed: string[]): string | undefined {
	if (changed.length > PLAN_LIMITS.changedFiles) {
		return `${changed.length} files changed, and a plan takes at most ${PLAN_LIMITS.changedFiles}`;
	}
	const longest = changed.reduce((most, file) => Math.max(most, file.length), 0);
	if (longest > PLAN_LIMITS.changedNameChars) {
		return `a changed file's name is ${longest} characters, and a plan takes at most ${PLAN_LIMITS.changedNameChars}`;
	}
	const globs = config.points.reduce((sum, p) => sum + p.point.select.paths.length, 0);
	if (globs > PLAN_LIMITS.globs) {
		return `the points list ${globs} select.paths globs, and a plan takes at most ${PLAN_LIMITS.globs}`;
	}
	return undefined;
}

// The first changed file one of the globs matches, with the glob.
async function firstMatch(
	globs: string[],
	changed: string[],
	work: GlobWork,
): Promise<{ glob: string; file: string } | undefined> {
	// With no file to match, no match would give koid a turn between the compiles.
	if (changed.length === 0) return undefined;
	for (const glob of globs) {
		const compiled = work.compile(glob);
		for (const file of changed) {
			const hit = work.match(compiled, file);
			if (typeof hit === 'boolean' ? hit : await hit) return { glob, file };
		}
	}
	return undefined;
}

// The note on why a changed file selected a point. Both names come from the
// project and neither has a limit of its own, so together they can pass what a
// Plan may hold, and a plan that fails its schema would fail for a valid
// project. When they do not fit, each name is cut and still shows; a name that
// needs less than its half gives the rest to the other.
function changedWhy(file: string, glob: string): string {
	const before = 'changed: ';
	const between = ' matches ';
	const whole = `${before}${file}${between}${glob}`;
	if (whole.length <= TEXT_MAX) return whole;
	const room = TEXT_MAX - before.length - between.length;
	const forGlob = Math.max(Math.floor(room / 2), room - file.length);
	const forFile = room - Math.min(glob.length, forGlob);
	return `${before}${cutMiddle(file, forFile)}${between}${cutMiddle(glob, forGlob)}`;
}

// `text` in at most `max` UTF-16 units, the measure TextSchema uses, with its
// middle replaced by a marker: a path's directories and its file name both tell
// the reader something. A surrogate pair at either edge goes whole, so the
// result stays well-formed text.
function cutMiddle(text: string, max: number): string {
	if (text.length <= max) return text;
	const marker = ' [cut by koid] ';
	const room = max - marker.length;
	let head = Math.ceil(room / 2);
	let tail = text.length - Math.floor(room / 2);
	const unit = text.charCodeAt(head - 1);
	if (unit >= 0xd800 && unit <= 0xdbff) head -= 1;
	const next = text.charCodeAt(tail);
	if (next >= 0xdc00 && next <= 0xdfff) tail += 1;
	return `${text.slice(0, head)}${marker}${text.slice(tail)}`;
}

// The most uncovered paths a plan lists by name; past that, a count.
const UNCOVERED_MAX = 100;

// Changed files no point's select.paths match, koi's own directories
// aside, bounded.
async function uncoveredFiles(
	config: VerifyConfig,
	changed: string[],
	work: GlobWork,
): Promise<string[]> {
	let uncovered = changed.filter(
		(file) => !file.startsWith(`${KOI_DIR}/`) && !file.startsWith('.koi-runtime/'),
	);
	// One glob at a time, so only one compiled glob is in memory: 5,000 of them could be
	// over a gigabyte.
	for (const glob of config.points.flatMap((p) => p.point.select.paths)) {
		if (uncovered.length === 0) break;
		const compiled = work.compile(glob);
		const still: string[] = [];
		for (const file of uncovered) {
			const hit = work.match(compiled, file);
			if (!(typeof hit === 'boolean' ? hit : await hit)) still.push(file);
		}
		uncovered = still;
	}
	// A name can be longer than a plan holds, and a plan that fails its schema would fail
	// for a valid project.
	const listed = uncovered.slice(0, UNCOVERED_MAX).map((file) => cutMiddle(file, TEXT_MAX));
	if (uncovered.length > UNCOVERED_MAX) {
		listed.push(`and ${uncovered.length - UNCOVERED_MAX} more files`);
	}
	return listed;
}

// The tree's own required.yaml, as advisory. The trusted source is the
// protected base branch, which is later work, so `source` is none.
async function readAdvisoryPolicy(source: string): Promise<PlanReply['policy']> {
	const path = `${KOI_DIR}/${REQUIRED_POLICY}`;
	const file = join(source, KOI_DIR, REQUIRED_POLICY);
	if ((await stat(file).catch(() => undefined)) === undefined) return { source: 'none' };
	try {
		const bytes = await readVerifyFile(file, path);
		const data: unknown = Bun.YAML.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
		const parsed = RequiredPolicySchema.safeParse(data);
		if (!parsed.success) {
			const issue = parsed.error.issues[0];
			return {
				source: 'none',
				advisory: {
					path,
					required: [],
					error: `${issue?.path.join('.') || 'the file'}: ${issue?.message ?? 'invalid'}`.slice(
						0,
						TEXT_MAX,
					),
				},
			};
		}
		const policy: RequiredPolicy = parsed.data;
		return { source: 'none', advisory: { path, required: policy.required } };
	} catch (err) {
		return {
			source: 'none',
			advisory: { path, required: [], error: message(err).slice(0, TEXT_MAX) },
		};
	}
}

// The proof records under .koi/proofs/, by point id and revision, with what
// could not be read. Each is a claim: koid does not resolve the runs it
// names.
async function readProofs(
	source: string,
): Promise<{ records: Map<string, ProofRecord>; errors: string[] }> {
	const records = new Map<string, ProofRecord>();
	const errors: string[] = [];
	const dir = join(source, KOI_DIR, PROOFS_DIR);
	let names: string[];
	try {
		names = await proofFiles(dir);
	} catch (err) {
		return { records, errors: [message(err)] };
	}
	for (const name of names) {
		const path = `${KOI_DIR}/${PROOFS_DIR}/${name}`;
		try {
			const bytes = await readVerifyFile(join(dir, name), path);
			const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
			const data: unknown = name.endsWith('.json') ? JSON.parse(text) : Bun.YAML.parse(text);
			const parsed = ProofRecordSchema.safeParse(data);
			if (!parsed.success) {
				const issue = parsed.error.issues[0];
				errors.push(
					`${path}: ${issue?.path.join('.') || 'the file'}: ${issue?.message ?? 'invalid'}`,
				);
				continue;
			}
			records.set(`${parsed.data.pointId}@${parsed.data.revision}`, parsed.data);
		} catch (err) {
			errors.push(`${path}: ${message(err)}`);
		}
	}
	return { records, errors };
}

// A plan reply page from `after`: the three lists in order, as many entries
// as fit, and the cursor of the rest. The unpaged parts (the notes, the
// advisory policy) are cut first when they leave no room for a page.
function planPage(planning: PlanRecord, after: string | undefined, clean: Sanitize): PlanReply {
	const lists = [
		['points', planning.points],
		['blocked', planning.blocked],
		['uncovered', planning.uncovered],
	] as const;
	const start = after === undefined ? { list: 'points', index: 0 } : parseCursor(after);
	// The plan's runtime text, scrubbed again: koid may have learned a secret since it was
	// written. Project text and koid's own words stay as the plan says them.
	const base: PlanReply = {
		...planning,
		policy: clean(planning.policy),
		notes: planning.notes.map((note) =>
			PLAN_NOTES.includes(note) ? note : fitJson(clean(note), PLAN_NOTE_MAX),
		),
		points: [],
		blocked: [],
		uncovered: [],
	};
	const trimmed = cutToFit({ ...base, next: 'uncovered:0000000' }, PLAN_CUTS);
	const budget = budgetFor(trimmed.reply);
	const truncated = [...trimmed.truncated];
	const out: Record<string, unknown[]> = { points: [], blocked: [], uncovered: [] };
	let used = 0;
	let next: string | undefined;
	let began = false;
	let any = false;
	outer: for (const [name, items] of lists) {
		if (!began && name !== start.list) continue;
		const from = began ? 0 : start.index;
		began = true;
		for (let i = from; i < items.length; i++) {
			const cut = cutPlanEntry(name, name === 'blocked' ? blockedNow(items[i], clean) : items[i]);
			truncated.push(...cut.truncated);
			const size = jsonBytes(cut.item) + 1;
			if (any && used + size > budget) {
				next = `${name}:${i}`;
				break outer;
			}
			if (!any && size > budget) {
				// Not possible for an entry cut to its size; if one is over
				// the budget anyway, the page skips it and says so.
				truncated.push(`${name}[${i}]`);
				continue;
			}
			out[name]?.push(cut.item);
			used += size;
			any = true;
		}
	}
	const { next: _dropped, ...rest } = trimmed.reply;
	return PlanReplySchema.parse({
		...rest,
		points: out.points,
		blocked: out.blocked,
		uncovered: out.uncovered,
		...(next !== undefined ? { next } : {}),
		...marked(truncated),
	});
}

// A blocked entry as a reply may say it now. Only a reason that quotes the box or what Docker
// says of the runner image holds runtime text. Any other names only what the project declared,
// and stays as it is.
function blockedNow(item: unknown, clean: Sanitize): unknown {
	const { reason } = BlockedPointSchema.parse(item);
	const quotesTheBox = [UNAVAILABLE_REASON, ...IMAGE_REASONS].some((start) =>
		reason.startsWith(start),
	);
	return quotesTheBox ? clean(item) : item;
}

// A plan's entry cut to an entry's size: its free text shortened.
function cutPlanEntry(
	list: 'points' | 'blocked' | 'uncovered',
	item: unknown,
): { item: unknown; truncated: string[] } {
	if (jsonBytes(item) <= VERIFICATION_ENTRY_MAX_BYTES) return { item, truncated: [] };
	if (list === 'uncovered' && typeof item === 'string') {
		return { item: fitJson(item, ENTRY_TEXT_BYTES), truncated: ['uncovered'] };
	}
	const entry = item as { id: string; why?: string; reason?: string };
	if (list === 'points' && entry.why !== undefined) {
		return {
			item: { ...entry, why: fitJson(entry.why, ENTRY_TEXT_BYTES) },
			truncated: [`points[${entry.id}].why`],
		};
	}
	if (list === 'blocked' && entry.reason !== undefined) {
		return {
			item: { ...entry, reason: fitJson(entry.reason, ENTRY_TEXT_BYTES) },
			truncated: [`blocked[${entry.id}].reason`],
		};
	}
	return { item, truncated: [] };
}

function parseCursor(cursor: string): { list: string; index: number } {
	const [list = 'points', index = '0'] = cursor.split(':');
	return { list, index: Number(index) };
}

// -- Records and bytes ---------------------------------------------------------

function withDigest(plan: Omit<Plan, 'planDigest'> & { planDigest?: string }): Plan {
	const { planDigest: _given, ...rest } = plan;
	return { ...rest, planDigest: canonicalDigest(rest) } as Plan;
}

function withExecutionDigest(
	descriptor: Omit<ExecutionDescriptor, 'executionDigest'>,
): ExecutionDescriptor {
	return { ...descriptor, executionDigest: canonicalDigest(descriptor) };
}

export function sameDeployment(a: DeploymentIdentity, b: DeploymentIdentity): boolean {
	return (
		a.label === b.label &&
		a.deploymentId === b.deploymentId &&
		a.imageDigest === b.imageDigest &&
		a.commit === b.commit &&
		a.merge?.head === b.merge?.head &&
		a.merge?.base === b.merge?.base &&
		a.merge?.baseBranch === b.merge?.baseBranch
	);
}

// What start() answers for a run, from its record, so a restart rebuilds the
// same reply. The lease's expiry is the latest the record holds, which a
// renewal may have moved past the first answer's.
function acceptanceOf(controller: RunControllerRecord): RunAccepted {
	return RunAcceptedSchema.parse({
		version: 1,
		runId: controller.runId,
		planId: controller.planId,
		planDigest: controller.planDigest,
		deployment: controller.deployment,
		state: 'running',
		leaseExpiresAt: controller.lease.expiresAt,
		limits: controller.limits,
		startedAt: controller.startedAt,
	});
}

// Whether koid wrote this record as the end of a run that has no manifest: a
// finalize that failed, or a restart (`recover`). Those are the truth about
// the run. Any other terminal record without a manifest is not.
function endsWithoutManifest(controller: RunControllerRecord): boolean {
	return (
		controller.completion === 'finalize-failed' ||
		controller.interruption?.startsWith('koid_restarted:') === true ||
		controller.interruption?.startsWith(`${EVIDENCE_UNWRITABLE}:`) === true
	);
}

function sameDigests(a: Record<string, string>, b: Record<string, string>): boolean {
	const keys = Object.keys(a).sort();
	if (keys.length !== Object.keys(b).length) return false;
	return keys.every((k) => a[k] === b[k]);
}

function sha256(bytes: Uint8Array): string {
	return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function jsonBytes(value: unknown): number {
	return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

// -- Bounded replies ------------------------------------------------------------
//
// Every reply is measured once built and stays under
// VERIFICATION_REPLY_MAX_BYTES, since SSM cuts what is longer. A reply's
// paged list is sized by `fit` against what the rest of the reply leaves;
// the rest, the unpaged lists and the free text, is cut first by `cutToFit`
// until a page has room for at least one entry; and each entry of a page
// is cut to VERIFICATION_ENTRY_MAX_BYTES by its cutter. What was cut is
// named in `truncated`, so a reader knows the list or the text is not
// whole; the records on disk are not touched.

// The room every reply keeps for its `truncated` names, at their largest:
// TRUNCATED_NAMES_MAX names of TRUNCATED_NAME_MAX bytes, quoted and joined.
const TRUNCATED_RESERVE_BYTES = TRUNCATED_NAMES_MAX * (TRUNCATED_NAME_MAX + 3) + 32;
// What a reply's unpaged parts may take: the bound less the room for the
// names, an entry, and the commas and cursor around a page.
const BASE_MAX_BYTES =
	VERIFICATION_REPLY_MAX_BYTES - TRUNCATED_RESERVE_BYTES - VERIFICATION_ENTRY_MAX_BYTES - 64;
// What free text in an entry or a list is cut to.
const ENTRY_TEXT_BYTES = 512;

// One cut of a reply's unpaged parts: what it is called, and the reply
// with that part cut.
type Cut<T> = [name: string, apply: (reply: T) => T];

// `reply`, with its cuts applied in order until it fits BASE_MAX_BYTES,
// and the names of the cuts applied.
function cutToFit<T>(reply: T, cuts: Array<Cut<T>>): { reply: T; truncated: string[] } {
	let current = reply;
	const truncated: string[] = [];
	for (const [name, apply] of cuts) {
		if (jsonBytes(current) <= BASE_MAX_BYTES) break;
		const next = apply(current);
		if (jsonBytes(next) === jsonBytes(current)) continue;
		current = next;
		if (!truncated.includes(name)) truncated.push(name);
	}
	return { reply: current, truncated };
}

// The `truncated` field for what was cut, within the room reserved for it.
function marked(truncated: string[]): { truncated?: string[] } {
	if (truncated.length === 0) return {};
	const names = [...new Set(truncated.map((name) => fitJson(name, TRUNCATED_NAME_MAX + 2)))];
	return { truncated: names.slice(0, TRUNCATED_NAMES_MAX) };
}

type StatusBase = Omit<RunStatusReply, 'next'> & { next: number };

const STATUS_CUTS: Array<Cut<StatusBase>> = [
	[
		'readiness.reasons',
		(r) => ({ ...r, readiness: { ...r.readiness, reasons: r.readiness.reasons.slice(0, 10) } }),
	],
	['problems', (r) => ({ ...r, problems: r.problems.map(cutProblem) })],
	['problems', (r) => ({ ...r, problems: r.problems.slice(0, 5) })],
	[
		'interruption',
		(r) =>
			r.interruption === undefined
				? r
				: { ...r, interruption: fitJson(r.interruption, ENTRY_TEXT_BYTES) },
	],
	['problems', (r) => ({ ...r, problems: [] })],
	['readiness.reasons', (r) => ({ ...r, readiness: { ...r.readiness, reasons: [] } })],
];

type EvidenceBase = Omit<EvidenceReply, 'next'> & { next: number };

const EVIDENCE_CUTS: Array<Cut<EvidenceBase>> = [
	[
		'status.problems',
		(r) => ({ ...r, status: { ...r.status, problems: r.status.problems.slice(0, 20) } }),
	],
	['limitations', (r) => ({ ...r, limitations: r.limitations.slice(0, 10) })],
	[
		'status.problems',
		(r) => ({
			...r,
			status: { ...r.status, problems: r.status.problems.slice(0, 5).map(cutProblem) },
		}),
	],
	['status.problems', (r) => ({ ...r, status: { ...r.status, problems: [] } })],
	['limitations', (r) => ({ ...r, limitations: [] })],
];

const PLAN_CUTS: Array<Cut<PlanReply>> = [
	['notes', (r) => ({ ...r, notes: r.notes.slice(0, 5).map((n) => fitJson(n, ENTRY_TEXT_BYTES)) })],
	['policy.advisory.required', (r) => cutRequired(r, 50)],
	[
		'policy.advisory.error',
		(r) =>
			r.policy.advisory?.error === undefined
				? r
				: {
						...r,
						policy: {
							...r.policy,
							advisory: {
								...r.policy.advisory,
								error: fitJson(r.policy.advisory.error, ENTRY_TEXT_BYTES),
							},
						},
					},
	],
	['notes', (r) => ({ ...r, notes: [] })],
	['policy.advisory.required', (r) => cutRequired(r, 0)],
];

function cutRequired(r: PlanReply, keep: number): PlanReply {
	const advisory = r.policy.advisory;
	if (advisory === undefined || advisory.required.length <= keep) return r;
	return {
		...r,
		policy: { ...r.policy, advisory: { ...advisory, required: advisory.required.slice(0, keep) } },
	};
}

function cutProblem<P extends { detail: string }>(p: P): P {
	return { ...p, detail: fitJson(p.detail, ENTRY_TEXT_BYTES) };
}

// A point's entry cut to an entry's size: its reason shortened, then its
// evidence list.
function cutPoint(p: PointStatus): { item: PointStatus; truncated: string[] } {
	if (jsonBytes(p) <= VERIFICATION_ENTRY_MAX_BYTES) return { item: p, truncated: [] };
	const truncated: string[] = [];
	let item = p;
	if (item.reason !== undefined && jsonBytes(item.reason) > ENTRY_TEXT_BYTES) {
		item = { ...item, reason: fitJson(item.reason, ENTRY_TEXT_BYTES) };
		truncated.push(`points[${p.id}].reason`);
	}
	if (jsonBytes(item) > VERIFICATION_ENTRY_MAX_BYTES) {
		item = { ...item, evidence: item.evidence.slice(0, 50) };
		truncated.push(`points[${p.id}].evidence`);
	}
	return { item, truncated };
}

// An artifact's entry cut to an entry's size: the fields its redaction
// removed, then its limitations, which are the only parts without a small
// bound of their own.
function cutArtifact(a: Artifact): { item: Artifact; truncated: string[] } {
	if (jsonBytes(a) <= VERIFICATION_ENTRY_MAX_BYTES) return { item: a, truncated: [] };
	const truncated: string[] = [];
	let item: Artifact = {
		...a,
		redaction: { ...a.redaction, removedFields: a.redaction.removedFields.slice(0, 20) },
	};
	if (item.redaction.removedFields.length !== a.redaction.removedFields.length) {
		truncated.push(`artifacts[${a.id}].redaction.removedFields`);
	}
	if (jsonBytes(item) > VERIFICATION_ENTRY_MAX_BYTES) {
		item = {
			...item,
			redaction: {
				...item.redaction,
				limitations: item.redaction.limitations.slice(0, 5).map((l) => fitJson(l, 200)),
			},
		};
		truncated.push(`artifacts[${a.id}].redaction.limitations`);
	}
	if (jsonBytes(item) > VERIFICATION_ENTRY_MAX_BYTES) {
		item = { ...item, redaction: { ...item.redaction, removedFields: [], limitations: [] } };
	}
	return { item, truncated };
}

// How many bytes a reply's list may take: the bound less the reply around
// it and the room for the names of what was cut.
function budgetFor(replyWithEmptyLists: unknown): number {
	return (
		VERIFICATION_REPLY_MAX_BYTES - TRUNCATED_RESERVE_BYTES - jsonBytes(replyWithEmptyLists) - 16
	);
}

// As many of `items` from `after` as fit in `budget`, each cut to an
// entry's size by `cut`, and the index of the rest. An entry that does not
// fit on its own, which the cut should make impossible, is skipped and
// named, so a page always moves on and never goes over the bound.
function fit<T>(
	items: T[],
	after: number,
	budget: number,
	list: string,
	cut: (item: T) => { item: T; truncated: string[] },
): { page: T[]; next: number | undefined; truncated: string[] } {
	const page: T[] = [];
	const truncated: string[] = [];
	let used = 0;
	for (let i = Math.max(0, after); i < items.length; i++) {
		const entry = cut(items[i] as T);
		const size = jsonBytes(entry.item) + 1;
		if (page.length > 0 && used + size > budget) return { page, next: i, truncated };
		if (page.length === 0 && size > budget) {
			truncated.push(`${list}[${i}]`);
			continue;
		}
		truncated.push(...entry.truncated);
		page.push(entry.item);
		used += size;
	}
	return { page, next: undefined, truncated };
}

// Calls `onLine` for each complete line of the file, in order, until it
// returns false. A last line without a newline is still being written and
// is left for the next read.
async function readLines(path: string, onLine: (line: string) => boolean): Promise<void> {
	const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
	try {
		const decoder = new TextDecoder();
		const buffer = Buffer.alloc(64 * 1024);
		let partial = '';
		for (;;) {
			const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
			if (bytesRead === 0) return;
			const lines = (
				partial + decoder.decode(buffer.subarray(0, bytesRead), { stream: true })
			).split('\n');
			partial = lines.pop() ?? '';
			for (const line of lines) {
				if (line === '') continue;
				if (!onLine(line)) return;
			}
		}
	} finally {
		await handle.close();
	}
}

// `promise`, unless it takes longer than `ms`: then an error naming `what`,
// and the promise's own end is logged when it comes, since the work it
// stands for cannot be stopped.
async function within<T>(
	promise: Promise<T>,
	ms: number,
	what: string,
	log: (message: string) => void,
): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	let timedOut = false;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			timedOut = true;
			reject(new Error(`${what} did not finish within ${Math.round(ms / 1000)} seconds`));
		}, ms);
	});
	try {
		return await Promise.race([promise, timeout]);
	} finally {
		clearTimeout(timer);
		if (timedOut) {
			promise.then(
				() => log(`${what}: finished after the run stopped waiting`),
				(late: unknown) => log(`${what}: failed after the run stopped waiting: ${message(late)}`),
			);
		}
	}
}

function codeOf(err: unknown): string {
	if (err instanceof VerificationError) return err.code;
	if (err instanceof RecorderLostError) return 'recorder_lost';
	if (err instanceof RecorderError) return err.code === 'error' ? 'recorder_error' : err.code;
	if (err instanceof CapExceededError) return 'cap_exceeded';
	if (err instanceof EvidenceStuckError) return EVIDENCE_UNWRITABLE;
	if (err instanceof LeaseError || err instanceof NoSuchLeaseError) return 'lease_lost';
	return 'run_failed';
}

function isNotFound(err: unknown): boolean {
	return typeof err === 'object' && err !== null && 'code' in err && err.code === 'ENOENT';
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
