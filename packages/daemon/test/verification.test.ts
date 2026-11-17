import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import {
	type FileHandle,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	stat,
	writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	type Artifact,
	canonicalDigest,
	type DeploymentIdentity,
	deploymentIdentity,
	EvidenceEventSchema,
	type EvidenceManifest,
	EvidenceManifestSchema,
	ExecutionDescriptorSchema,
	helperName,
	LEASE_MAX_SECONDS,
	type Lease,
	PLAN_LIMITS,
	PLAN_NOTE_MAX,
	type PlanReply,
	PlanSchema,
	type Point,
	type PreviewRecord,
	type RecorderCapture,
	type RecorderEventsPage,
	type RecorderHealth,
	ResultSchema,
	RUN_LIMIT_CEILINGS,
	type RunControllerRecord,
	RunControllerRecordSchema,
	type RunNetworkDescriptor,
	RunSchema,
	type RunStatus,
	type RunStatusReply,
	RunStatusSchema,
	runLeaseHolder,
	runNetworkName,
	TEXT_MAX,
	VERIFICATION_REPLY_MAX_BYTES,
	type VerifyAttestation,
} from '@koi/shared';
import type { Box, CtlResult } from '../../cli/src/box.ts';
import { exportEvidence, formatStatus } from '../../cli/src/verify.ts';
import { LeaseError, NoSuchLeaseError } from '../src/deployer.ts';
import type { VerificationCapability } from '../src/host.ts';
import {
	type CallOptions,
	type CaptureRequest,
	httpRecorder,
	type ReadRequest,
	type RecorderApi,
	RecorderError,
} from '../src/recorder.ts';
import { SecretRegistry, secretForms } from '../src/redact.ts';
import {
	pointBudgetSeconds,
	pointRequests,
	resolveLimits,
	Verification,
	type VerificationDeps,
	VerificationError,
} from '../src/verification.ts';
import { VerificationNetwork, type VerifyNetHelper } from '../src/verification-network.ts';
import { snapshotInputs } from '../src/verification-snapshot.ts';
import {
	DISK_WAIT_MS,
	EvidenceStore,
	type RunWriter,
	writeAtomic,
} from '../src/verification-store.ts';
import {
	declaredSteps,
	eventually,
	FakeDocker,
	type FakeVerifier,
	Gate,
	request,
	supervisorExit,
	supervisorLine,
	type VerifierScript,
} from './fakes.ts';
import { PNG_STRIPPED } from './png.ts';

const LABEL = 'hello-pr-7';
const DEPLOYMENT = 'd'.repeat(20);
const APP = `koi-${LABEL}-aaaaaaaaaaaaaaaa1`;
const IMAGE = `sha256:${'1'.repeat(64)}`;
const RECORDER_IMAGE = `sha256:${'5'.repeat(64)}`;
const VERIFIER_IMAGE = `sha256:${'6'.repeat(64)}`;
// What the manifest's runner image resolves to on the box.
const CURL_IMAGE = `sha256:${'7'.repeat(64)}`;
// What it resolves to after the tag moves.
const OTHER_IMAGE = `sha256:${'9'.repeat(64)}`;
const AT = '2026-10-06T12:00:00.000Z';
const sha = (bytes: Uint8Array | string) =>
	`sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const MANIFEST = `version: 1
points:
  - points/*.yaml
profiles:
  pr:
    always: [hello.home]
    select: changed
  matrix:
    include: [app.llm]
runner:
  image: curlimages/curl:8.11.1
budgets:
  timeoutSeconds: 600
`;

const POINTS: Record<string, string> = {
	'home.yaml': `id: hello.home
revision: 2
claim: The home page says hello.
select:
  paths: [Dockerfile]
run:
  command: [sh, .koi/runners/home.sh]
cleanup:
  command: [sh, .koi/runners/home.sh]
assertions:
  - name: home-says-hello
    description: GET / answers 200.
    evidence: [http-response]
`,
	'search.yaml': `id: app.search
revision: 1
claim: Search finds what was saved.
select:
  paths: ['src/search/**']
run:
  command: [sh, .koi/runners/home.sh]
assertions:
  - name: finds
    description: The result lists the saved item.
    evidence: [screenshot]
`,
	'always.yaml': `id: app.always
revision: 3
claim: The app starts.
select:
  always: true
  paths: ['src/boot/**']
run:
  command: [sh, .koi/runners/home.sh]
assertions:
  - name: boots
    description: The app answers.
    evidence: [http-response]
`,
	'llm.yaml': `id: app.llm
revision: 1
claim: The model answers.
select:
  paths: ['src/llm/**']
requires:
  provider: anthropic
  services: [chat]
  network: dns
  fixtures: [fixtures/probe.txt]
run:
  command: [sh, .koi/runners/home.sh]
assertions:
  - name: answers
    description: An answer comes back.
    evidence: [http-response]
`,
};

const REQUIRED = `version: 1
required:
  - id: hello.home
    revision: 2
  - id: app.always
    revision: 3
`;

const PROOF = `pointId: hello.home
revision: 2
mutation:
  kind: ref
  digest: sha256:${'a'.repeat(64)}
failingRunId: ${'f'.repeat(20)}
passingRunId: ${'p'.repeat(20)}
provenAt: ${AT}
`;

function attestation(pool: string): VerifyAttestation {
	return {
		policy: 2,
		pool,
		ipv4: { chains: true, jump: true, defaults: true, permits: true, problems: [] },
		ipv6: { defaults: true, problems: [] },
		bridge: { guard: true, pins: true, problems: [] },
		sysctl: {
			br_netfilter: true,
			bridge_nf_call_iptables: true,
			bridge_nf_call_ip6tables: true,
			bridge_nf_filter_vlan_tagged: true,
		},
		runs: [],
	};
}

class FakeHelper implements VerifyNetHelper {
	runs = new Set<string>();
	revokeError: string | undefined;
	// The revoke error is for the next revoke only, when set.
	revokeOnce = false;
	constructor(
		private readonly pool: string,
		private readonly events: string[],
	) {}
	async apply(descriptor: RunNetworkDescriptor) {
		this.runs.add(descriptor.runId);
		this.events.push(`apply ${descriptor.runId}`);
	}
	async revoke(runId: string) {
		if (this.revokeError !== undefined) {
			const error = this.revokeError;
			if (this.revokeOnce) this.revokeError = undefined;
			throw new Error(error);
		}
		this.runs.delete(runId);
		this.events.push(`revoke ${runId}`);
	}
	async attest() {
		const ports = { app: 'vethapp', recorder: 'vethrec', verifier: 'vethver' };
		return {
			...attestation(this.pool),
			runs: [...this.runs],
			ports: Object.fromEntries([...this.runs].map((run) => [run, ports])),
		};
	}
}

// A request to a recorder that never answers: pending until its signal ends
// it, and then failing as the HTTP client's does.
function hangUntilAborted(signal: AbortSignal | undefined): Promise<never> {
	return new Promise((_, reject) => {
		signal?.addEventListener('abort', () =>
			reject(new RecorderError(0, 'unreachable', 'the recorder did not answer: aborted')),
		);
	});
}

// The recorder's control API in memory, for one run at a time.
class FakeRecorder implements RecorderApi {
	calls: string[] = [];
	healthy = true;
	// Waits here on each capture, when set.
	captureGate: Gate | undefined;
	// The point whose captures, or whose open, never answer.
	hangCapturesOf: string | undefined;
	hangOpenOf: string | undefined;
	private pointOpen: string | undefined;
	captureError: Error | undefined;
	// Runs as each context opens, and as each closes; the close is awaited.
	onOpen: ((pointId: string) => void) | undefined;
	onClose: (() => unknown) | undefined;
	// The address an open answers with, when set.
	openUrl: string | undefined;
	// What the recorder has seen, for koid's next read of its events (say).
	private feed: RecorderEventsPage['events'] = [];
	// Fails every events read with this, when set, from the read numbered
	// `eventsFailFrom` on (the first read is 1).
	eventsError: Error | undefined;
	eventsFailFrom = 1;
	eventsCalls = 0;
	ariaText = 'heading "hello from koi"\n';
	// Screenshots that are not PNGs, which the sanitizer withholds.
	badPng = false;
	// The signal each capture was given, so a test can see it is bounded.
	signals: AbortSignal[] = [];
	held = new Map<string, Uint8Array>();
	private next = 1;
	constructor(readonly runId: string) {}
	async health(): Promise<RecorderHealth> {
		this.calls.push('health');
		if (!this.healthy) return { ok: false, reason: 'the browser did not start: no display' };
		return {
			ok: true,
			runId: this.runId,
			origin: `http://app.${this.runId}.invalid:8080`,
			browser: { name: 'chromium', version: '142.0.7444.52' },
			playwright: '1.64.1',
			contexts: 0,
			captures: { count: 0, bytes: 0 },
			events: { next: 1, dropped: 0 },
		};
	}
	async openContext(
		r: { pointId: string; attempt: number; open?: string | undefined },
		options?: CallOptions,
	) {
		this.calls.push(`open ${r.pointId} ${r.attempt} ${r.open ?? ''}`);
		this.onOpen?.(r.pointId);
		if (this.hangOpenOf === r.pointId) await hangUntilAborted(options?.signal);
		this.pointOpen = r.pointId;
		return {
			contextId: 'x1',
			pageId: 'p1',
			url: this.openUrl ?? `http://app.${this.runId}.invalid:8080/`,
		};
	}
	async closeContext(contextId: string) {
		this.calls.push(`close ${contextId}`);
		await this.onClose?.();
	}
	async capture(
		contextId: string,
		r: CaptureRequest,
		options?: CallOptions,
	): Promise<RecorderCapture> {
		this.calls.push(`capture ${contextId} ${r.kind} ${r.label}`);
		if (options?.signal !== undefined) this.signals.push(options.signal);
		if (this.hangCapturesOf === this.pointOpen) await hangUntilAborted(options?.signal);
		await this.captureGate?.pass();
		if (this.captureError !== undefined) throw this.captureError;
		const bytes =
			r.kind === 'screenshot'
				? this.badPng
					? new TextEncoder().encode('not a png')
					: PNG_STRIPPED
				: new TextEncoder().encode(this.ariaText);
		const captureId = `c${this.next++}`;
		this.held.set(captureId, bytes);
		return {
			captureId,
			kind: r.kind,
			mediaType: r.kind === 'screenshot' ? 'image/png' : 'text/plain; charset=utf-8',
			size: bytes.length,
			sha256: sha(bytes),
			pageId: 'p1',
			eventRange: { first: 1, last: 1 },
			capturedAt: AT,
		};
	}
	// A state read of the app's home page: what the recorder writes for one.
	async read(contextId: string, r: ReadRequest): Promise<RecorderCapture> {
		this.calls.push(`read ${contextId} ${r.method} ${r.path}`);
		if (this.captureError !== undefined) throw this.captureError;
		const body = '<h1>hello from koi</h1>';
		const bytes = new TextEncoder().encode(
			JSON.stringify({
				request: { method: r.method, url: `http://app.${this.runId}.invalid:8080${r.path}` },
				response: {
					status: 200,
					headers: { 'content-type': 'text/html' },
					bodyBase64: Buffer.from(body).toString('base64'),
					bodyBytes: body.length,
					truncated: false,
				},
				startedAt: AT,
				endedAt: AT,
			}),
		);
		const captureId = `c${this.next++}`;
		this.held.set(captureId, bytes);
		return {
			captureId,
			kind: 'http-response',
			mediaType: 'application/json',
			size: bytes.length,
			sha256: sha(bytes),
			eventRange: { first: 1, last: 1 },
			capturedAt: AT,
		};
	}
	async bytes(captureId: string) {
		const bytes = this.held.get(captureId);
		if (bytes === undefined) throw new Error(`no capture ${captureId}`);
		return new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(bytes);
				controller.close();
			},
		});
	}
	async acknowledge(captureId: string) {
		this.calls.push(`ack ${captureId}`);
		this.held.delete(captureId);
	}
	async events(
		after: number,
		_limit?: number,
		_options?: CallOptions,
	): Promise<RecorderEventsPage> {
		this.eventsCalls += 1;
		if (this.eventsError !== undefined && this.eventsCalls >= this.eventsFailFrom) {
			throw this.eventsError;
		}
		const events = this.feed.filter((e) => e.seq > after);
		return { events, next: events.at(-1)?.seq ?? after, dropped: 0 };
	}
	// One event for koid's next read, as a page or the recorder said it.
	say(type: string, fields: Record<string, unknown>) {
		this.feed.push({ seq: this.feed.length + 1, at: AT, type, ...fields });
	}
}

// A capture or a read through the protocol, as a runner does it: the event
// out, the acknowledgment back; the artifact, or undefined when it failed.
async function ask(
	v: FakeVerifier,
	event: Record<string, unknown>,
	label: string,
): Promise<string | undefined> {
	v.out(JSON.stringify({ ...event, label }));
	for (;;) {
		const ack = JSON.parse(await v.nextLine()) as {
			type: string;
			label: string;
			status: string;
			artifact?: string;
		};
		if (ack.type === 'capture-result' && ack.label === label) {
			return ack.status === 'ready' ? ack.artifact : undefined;
		}
	}
}

// A runner that waits for start, takes a screenshot, an aria snapshot and
// a state read of /, and reports each of the point's assertions with the
// outcome given (pass by default) citing the artifacts it got.
function runner(
	assertions: Record<string, string[]>,
	outcome: (point: string, name: string) => string = () => 'pass',
	detail: (name: string) => string = (name) => `${name} as the runner saw it`,
): VerifierScript {
	return async (v) => {
		await v.nextLine();
		v.out(supervisorLine({ event: 'started' }));
		const point = v.env.KOI_POINT_ID ?? '';
		const evidence: string[] = [];
		for (const [event, label] of [
			[{ type: 'capture', kind: 'screenshot' }, 'shot'],
			[{ type: 'capture', kind: 'aria' }, 'tree'],
			[{ type: 'read', path: '/' }, 'state'],
		] as const) {
			const artifact = await ask(v, event, label);
			if (artifact !== undefined) evidence.push(artifact);
		}
		for (const name of assertions[point] ?? []) {
			v.out(
				JSON.stringify({
					type: 'assertion',
					point,
					name,
					outcome: outcome(point, name),
					evidence,
					detail: detail(name),
				}),
			);
		}
		// Every step the point file declares exited 0, as the supervisor
		// would report them.
		for (const line of supervisorExit(declaredSteps(v))) v.out(line);
		return 0;
	};
}

// The assertion names each point file declares, by point id.
function declared(files: Record<string, string>): Record<string, string[]> {
	const out: Record<string, string[]> = {};
	for (const text of Object.values(files)) {
		const point = Bun.YAML.parse(text) as { id: string; assertions: Array<{ name: string }> };
		out[point.id] = point.assertions.map((a) => a.name);
	}
	return out;
}

interface SetupOptions {
	available?: boolean;
	changed?: string[];
	files?: Record<string, string>;
	manifest?: string;
	merge?: boolean;
	baseBranch?: string;
	dirty?: boolean;
	// What the startup check said, when verification is not available.
	unavailableReason?: string;
	planGlobs?: VerificationDeps['planGlobs'];
	// KOI_VERIFIER_IMAGES.
	allowed?: string[];
	// References on the box besides the usual ones, each naming the curl image.
	boxImages?: string[];
	// Files written into the source tree besides the usual ones.
	extra?: Record<string, string>;
	// The most the fake deployer leases for, as a box with a short cap would.
	leaseCapSeconds?: number;
	keepAwakeMs?: number;
	// Real time, as the controller's teardown timer runs on the host clock.
	teardownAllowanceMs?: number;
	// How often a wait on the disk looks at the clock, for a test that moves it
	// with a write held. The default keeps a jump from reading as a stuck disk.
	diskPollMs?: number;
}

async function setup(options: SetupOptions = {}) {
	const root = await mkdtemp(join(tmpdir(), 'koid-verification-'));
	const stateDir = join(root, 'state');
	await mkdir(stateDir, { recursive: true });
	let clock = Date.parse(AT);
	const now = () => new Date(clock);
	const evidence = new EvidenceStore({
		stateDir,
		now,
		diskSpace: async () => ({ free: 60 * 1024 ** 3, size: 80 * 1024 ** 3 }),
		...(options.diskPollMs !== undefined ? { diskPollMs: options.diskPollMs } : {}),
	});
	await evidence.init();

	// The source tree as the build had it, snapshotted as the deployer does.
	const src = join(root, 'src');
	for (const dir of ['points', 'runners', 'fixtures', 'proofs']) {
		await mkdir(join(src, '.koi', dir), { recursive: true });
	}
	await writeFile(join(src, 'Dockerfile'), 'FROM scratch\n');
	await writeFile(join(src, '.koi/verify.yaml'), options.manifest ?? MANIFEST);
	for (const [name, text] of Object.entries(options.files ?? POINTS)) {
		await writeFile(join(src, '.koi/points', name), text);
	}
	await writeFile(join(src, '.koi/runners/home.sh'), 'curl "$KOI_PREVIEW_URL"\n');
	await writeFile(join(src, '.koi/fixtures/probe.txt'), 'probe');
	await writeFile(join(src, '.koi/required.yaml'), REQUIRED);
	await writeFile(join(src, '.koi/proofs/hello.home.yaml'), PROOF);
	for (const [name, text] of Object.entries(options.extra ?? {})) {
		await mkdir(join(src, name, '..'), { recursive: true });
		await writeFile(join(src, name), text);
	}
	await mkdir(join(src, '.koi-runtime'), { recursive: true });
	const changed = options.changed ?? ['Dockerfile', 'src/search/index.ts', 'README.md'];
	await writeFile(join(src, '.koi-runtime/changed-files.txt'), `${changed.join('\n')}\n`);
	const tarball = join(root, 'source.tar.gz');
	await writeFile(tarball, 'tarball');
	const upRequest = request({
		label: LABEL,
		commit: 'c'.repeat(40),
		dirty: options.dirty ?? false,
		...(options.merge === false
			? {}
			: {
					merge: {
						head: '1'.repeat(40),
						base: '2'.repeat(40),
						baseBranch: options.baseBranch ?? 'main',
					},
				}),
	});
	await snapshotInputs(evidence.inputsDir(DEPLOYMENT), {
		deploymentId: DEPLOYMENT,
		request: upRequest,
		source: src,
		tarball,
	});

	// The preview, serving the deployment the snapshot is of.
	const record: PreviewRecord = {
		label: LABEL,
		project: 'hello',
		repo: 'github.com/acme/hello',
		status: 'running',
		commit: upRequest.commit,
		branch: upRequest.branch,
		pr: 7,
		...(upRequest.merge !== undefined ? { merge: upRequest.merge } : {}),
		dirty: upRequest.dirty,
		requestId: upRequest.id,
		attempt: DEPLOYMENT,
		ttlDays: 7,
		createdAt: AT,
		updatedAt: AT,
		deployment: {
			requestId: upRequest.id,
			deploymentId: DEPLOYMENT,
			imageDigest: IMAGE,
			commit: upRequest.commit,
			...(upRequest.merge !== undefined ? { merge: upRequest.merge } : {}),
			image: 'koi-preview/hello:1',
			container: APP,
			port: 8080,
			healthPath: '/',
			healthTimeoutSeconds: 5,
			user: '65534:65534',
			env: {},
			deployedAt: AT,
		},
	};
	const identity = deploymentIdentity(record) as DeploymentIdentity;
	const store = {
		get: async (label: string) => (label === LABEL ? structuredClone(record) : undefined),
	};

	// The deployer's lease side, over the record.
	const calls: string[] = [];
	const deployer = {
		served: undefined as DeploymentIdentity | undefined,
		leaseError: undefined as string | undefined,
		lost: false,
		async acquireLease(label: string, holder: string, ttlSeconds: number) {
			calls.push(`lease ${label} ${holder} ${ttlSeconds}`);
			if (this.leaseError !== undefined) throw new LeaseError(this.leaseError);
			const ttl = Math.min(ttlSeconds, options.leaseCapSeconds ?? ttlSeconds);
			const lease: Lease = {
				leaseId: 'l'.repeat(20),
				deploymentId: DEPLOYMENT,
				holder,
				acquiredAt: now().toISOString(),
				expiresAt: new Date(clock + ttl * 1000).toISOString(),
			};
			record.lease = lease;
			return { lease, deployment: this.served ?? identity };
		},
		async renewLease(label: string, leaseId: string, ttlSeconds: number) {
			calls.push(`renew ${label} ${leaseId} ${ttlSeconds}`);
			const held = record.lease;
			if (this.lost || held?.leaseId !== leaseId || Date.parse(held.expiresAt) <= clock) {
				throw new NoSuchLeaseError('no such lease');
			}
			const cap = Date.parse(held.acquiredAt) + LEASE_MAX_SECONDS * 1000;
			const until = Math.min(clock + ttlSeconds * 1000, cap);
			if (until <= Date.parse(held.expiresAt)) return held;
			const lease: Lease = { ...held, expiresAt: new Date(until).toISOString() };
			record.lease = lease;
			return lease;
		},
		async releaseLease(label: string, leaseId: string) {
			calls.push(`release ${label} ${leaseId}`);
			if (record.lease?.leaseId !== leaseId) throw new NoSuchLeaseError('no such lease');
			delete record.lease;
		},
		async leasedDeployment(_label: string, leaseId: string) {
			if (this.lost || record.lease?.leaseId !== leaseId)
				throw new NoSuchLeaseError('no such lease');
			// The container the record names: a redeploy changes it.
			return {
				container: record.deployment?.container ?? APP,
				port: 8080,
				deploymentId: DEPLOYMENT,
			};
		},
	};

	// Docker, the firewall helper and the run networks, as the network tests
	// have them, with the app running on the preview network.
	const docker = new FakeDocker();
	await docker.run({
		name: APP,
		image: 'koi-preview/hello:1',
		network: 'koi-previews',
		user: '65534:65534',
		env: {},
		labels: { 'koi.preview': LABEL, 'koi.request': upRequest.id },
	});
	const pool = '10.213.0.0/26';
	const helper = new FakeHelper(pool, docker.events);
	const logs: string[] = [];
	const network = new VerificationNetwork({
		docker,
		helper,
		pool,
		previewNetwork: 'koi-previews',
		stateDir,
		slice: 'koi.slice',
		linkExists: async () => false,
		now,
		log: (m) => logs.push(m),
	});
	const capability: VerificationCapability =
		options.available === false
			? { available: false, reason: options.unavailableReason ?? 'KOI_VERIFY_POOL is not set' }
			: {
					available: true,
					attestation: attestation(pool),
					recorderImageId: RECORDER_IMAGE,
					verifierImageId: VERIFIER_IMAGE,
				};
	// The images on the box: the default verifier, and the manifest's
	// runner image, which the operator allowed.
	docker.imageInfos.set(VERIFIER_IMAGE, { id: VERIFIER_IMAGE, env: ['PATH=/usr/local/bin'] });
	docker.imageInfos.set('curlimages/curl:8.11.1', { id: CURL_IMAGE, env: ['PATH=/usr/bin'] });
	for (const reference of options.boxImages ?? []) {
		docker.imageInfos.set(reference, { id: CURL_IMAGE, env: ['PATH=/usr/bin'] });
	}
	docker.verifierScript = runner(declared(options.files ?? POINTS));
	const recorders = new Map<string, FakeRecorder>();
	let awake = 0;
	// What status said at the moment each run's finalize began, a hook that
	// runs then, and ways to make writes fail, as a full disk would: the
	// finalize alone, or every write of a record, an event or the status
	// (`writes`), from now or from the event named in `writesFrom`. A
	// problem or a state change still takes effect in memory before its
	// write fails, as the real writer's does.
	const atFinalize: Array<{ runId: string; state: string; finalized: boolean }> = [];
	const failing = {
		finalize: undefined as Error | undefined,
		writes: undefined as Error | undefined,
		writesFrom: undefined as string | undefined,
		// The disk takes writes again once a problem of this code is recorded.
		writesUntilProblem: undefined as string | undefined,
	};
	let onFinalize: ((runId: string) => void | Promise<void>) | undefined;
	// Runs as each record of a run is about to be written, with its name.
	let onWrite: ((name: string, runId: string) => void | Promise<void>) | undefined;
	// Runs as a run checks its evidence against the disk.
	let onResolve: (() => void | Promise<void>) | undefined;
	const writers: RunWriter[] = [];
	const openRun = evidence.openRun.bind(evidence);
	evidence.openRun = async (runId, options) => {
		const writer: RunWriter = await openRun(runId, options);
		writers.push(writer);
		const resolveEvidence = writer.resolveEvidence.bind(writer);
		writer.resolveEvidence = async (refs) => {
			await onResolve?.();
			return resolveEvidence(refs);
		};
		const finalize = writer.finalize.bind(writer);
		writer.finalize = async (fields) => {
			const status = await verification.status(runId);
			atFinalize.push({ runId, state: status.state, finalized: status.finalized });
			await onFinalize?.(runId);
			if (failing.finalize !== undefined) throw failing.finalize;
			if (failing.writes !== undefined) throw failing.writes;
			return finalize(fields);
		};
		const writeRecord = writer.writeRecord.bind(writer);
		writer.writeRecord = async (name, text) => {
			await onWrite?.(name, runId);
			if (failing.writes !== undefined) throw failing.writes;
			return writeRecord(name, text);
		};
		const writeDeclared = writer.writeDeclared.bind(writer);
		writer.writeDeclared = async (name, record) => {
			await onWrite?.(name, runId);
			if (failing.writes !== undefined) throw failing.writes;
			return writeDeclared(name, record);
		};
		const writeReport = writer.writeReport.bind(writer);
		writer.writeReport = async (render) => {
			await onWrite?.('report.md', runId);
			if (failing.writes !== undefined) throw failing.writes;
			return writeReport(render);
		};
		const writeObservations = writer.writeObservations.bind(writer);
		writer.writeObservations = async (pointId, data) => {
			if (failing.writes !== undefined) throw failing.writes;
			return writeObservations(pointId, data);
		};
		const appendEvent = writer.appendEvent.bind(writer);
		writer.appendEvent = async (event) => {
			if (failing.writesFrom !== undefined && event.type === failing.writesFrom) {
				failing.writes = new Error('ENOSPC: no space left on device');
			}
			if (failing.writes !== undefined) throw failing.writes;
			return appendEvent(event);
		};
		const writeArtifact = writer.writeArtifact.bind(writer);
		writer.writeArtifact = async (meta, body) => {
			if (failing.writes !== undefined) throw failing.writes;
			return writeArtifact(meta, body);
		};
		const addProblem = writer.addProblem.bind(writer);
		writer.addProblem = async (code, detail) => {
			await addProblem(code, detail);
			const error = failing.writes;
			if (error === undefined) return;
			if (failing.writesUntilProblem === code) {
				failing.writes = undefined;
				failing.writesFrom = undefined;
			}
			throw error;
		};
		const setState = writer.setState.bind(writer);
		writer.setState = async (state) => {
			await setState(state);
			if (failing.writes !== undefined) throw failing.writes;
		};
		return writer;
	};
	const deps: VerificationDeps = {
		evidence,
		store,
		deployer,
		capability,
		network: capability.available ? network : undefined,
		docker,
		recorderImage: capability.available ? RECORDER_IMAGE : undefined,
		recorderSeccomp: '/etc/koi/seccomp.json',
		verifierImages: options.allowed ?? ['curlimages/curl:8.11.1'],
		verifierPollMs: 5,
		recorderApi: (baseUrl) => {
			// The recorder of the run whose network holds this address.
			const ip = new URL(baseUrl).hostname;
			const run = docker.helpers.find((h) => h.role === 'recorder' && h.options.ip === ip);
			const runId = run?.options.runId ?? 'unknown';
			let recorder = recorders.get(runId);
			if (recorder === undefined) {
				recorder = new FakeRecorder(runId);
				recorders.set(runId, recorder);
			}
			return recorder;
		},
		recorderHealthTimeoutMs: 3_000,
		secrets: new SecretRegistry(),
		keepAwake: async () => {
			awake += 1;
		},
		keepAwakeMs: options.keepAwakeMs,
		teardownAllowanceMs: options.teardownAllowanceMs,
		planGlobs: options.planGlobs,
		now,
		sleep: async (ms) => {
			clock += ms;
		},
		log: (m) => logs.push(m),
	};
	const verification = new Verification(deps);
	return {
		root,
		stateDir,
		evidence,
		verification,
		// A new koid over the same state, as a restart makes.
		restarted: () => new Verification(deps),
		secrets: deps.secrets,
		record,
		identity,
		deployer,
		calls,
		docker,
		helper,
		network,
		logs,
		recorders,
		atFinalize,
		failing,
		// Runs as a run's finalize begins, with the run id.
		finalizing(hook: (runId: string) => void | Promise<void>) {
			onFinalize = hook;
		},
		writing(hook: (name: string, runId: string) => void | Promise<void>) {
			onWrite = hook;
		},
		resolving(hook: () => void | Promise<void>) {
			onResolve = hook;
		},
		// From now on each sync of the events file of the latest run waits at the
		// gate, as a disk that stopped answering holds it.
		latestWriter: () => writers.at(-1) as RunWriter,
		stallEvents(gate: Gate) {
			const events = (writers.at(-1) as unknown as { events: FileHandle }).events;
			const real = events.datasync.bind(events);
			events.datasync = async () => {
				await gate.pass();
				return real();
			};
		},
		// The next check of what a point cites waits on the gate.
		stallChecks(gate: Gate) {
			const writer = writers.at(-1) as unknown as {
				resolveEvidence: RunWriter['resolveEvidence'];
				onDisk: RunWriter['onDisk'];
			};
			const real = writer.resolveEvidence.bind(writer);
			writer.resolveEvidence = async (refs) => {
				await writer.onDisk('checking an artifact', () => gate.pass());
				return real(refs);
			};
		},
		// The recorder a run will get, made ahead of the run so a test can
		// shape it. Recorder run ids are not known before start, so this
		// hooks the factory instead.
		prepareRecorder(shape: (r: FakeRecorder) => void) {
			const original = recorders.set.bind(recorders);
			recorders.set = (id, r) => {
				shape(r);
				return original(id, r);
			};
		},
		advance(ms: number) {
			clock += ms;
		},
		now: () => clock,
		awake: () => awake,
		async plan(profile = 'pr', more: Partial<Parameters<Verification['plan']>[0]> = {}) {
			return verification.plan({ version: 1, label: LABEL, profile, ...more });
		},
		async run(plan: PlanReply) {
			const accepted = await verification.start({
				version: 1,
				planId: plan.planId,
				planDigest: plan.planDigest,
				mode: 'runner',
			});
			return accepted;
		},
		async runToEnd(profile = 'pr') {
			const plan = await verification.plan({ version: 1, label: LABEL, profile });
			const accepted = await this.run(plan);
			await verification.settled(accepted.runId);
			return { plan, accepted, status: await verification.status(accepted.runId) };
		},
	};
}

async function refusal(promise: Promise<unknown>): Promise<VerificationError> {
	try {
		await promise;
	} catch (err) {
		if (err instanceof VerificationError) return err;
		throw err;
	}
	throw new Error('expected a refusal');
}

describe('planning', () => {
	test('a script the manifest names in runner.command is in every planned point and its verifier', async () => {
		const wrapper = '.koi/runners/wrapper.py';
		const t = await setup({
			manifest: MANIFEST.replace(
				'image: curlimages/curl:8.11.1',
				`image: curlimages/curl:8.11.1\n  command: [python3, ${wrapper}]`,
			),
			extra: { [wrapper]: 'print("wrapped")\n' },
		});
		const planned = await t.plan();
		const plan = PlanSchema.parse(
			JSON.parse(await readFile(join(t.evidence.planDir(planned.planId), 'plan.json'), 'utf8')),
		);
		expect(plan.points.length).toBeGreaterThan(0);
		for (const point of plan.points) {
			expect(point.runners.map((r) => r.path)).toContain(wrapper);
		}
		const accepted = await t.run(planned);
		await t.verification.settled(accepted.runId);
		expect(t.docker.verifiers.length).toBeGreaterThan(0);
		for (const verifier of t.docker.verifiers) {
			expect(verifier.files.has(`workspace/${wrapper}`)).toBe(true);
		}
	});

	test('selects the profile points, the changed points and the includes, and says why', async () => {
		const t = await setup();
		const plan = await t.plan();
		expect(plan.version).toBe(1);
		expect(plan.label).toBe(LABEL);
		expect(plan.deployment).toEqual(t.identity);
		expect(plan.advisory).toBe(false);
		// Points come in the loader's order: by file name under points/.
		expect(plan.points.map((p) => [p.id, p.why])).toEqual([
			['hello.home', 'always: listed by profile pr'],
			['app.always', 'select.always: taken by every run of profile pr'],
			['app.search', 'changed: src/search/index.ts matches src/search/**'],
		]);
		// app.llm is not selected by the change; the matrix profile includes it.
		const matrix = await t.plan('matrix');
		expect(matrix.points).toEqual([]);
		expect(matrix.blocked.map((b) => b.id)).toEqual(['app.llm']);
		expect(plan.counts).toEqual({ selected: 3, blocked: 0, uncovered: 1, required: 2 });
		expect(plan.uncovered).toEqual(['README.md']);
		expect(plan.limits).toEqual({
			runSeconds: 600,
			pointSeconds: 600,
			runRequests: 50,
			pointRequests: 20,
		});
		expect(plan.runnerImage).toBe('curlimages/curl:8.11.1');
		expect(plan.next).toBeUndefined();
	});

	test('blocks a point whose requirements the host cannot meet, with every reason', async () => {
		const t = await setup();
		const plan = await t.plan('matrix');
		const blocked = plan.blocked[0];
		expect(blocked?.id).toBe('app.llm');
		expect(blocked?.reason).toContain('capability_missing:provider:anthropic');
		expect(blocked?.reason).toContain('capability_missing:network:dns');
		expect(blocked?.reason).toContain('capability_missing:services:chat');
		expect(blocked?.reason).not.toContain('fixture_missing');
	});

	test('blocks every point when verification is unavailable on the box', async () => {
		const t = await setup({ available: false });
		const plan = await t.plan();
		expect(plan.points).toEqual([]);
		expect(plan.blocked.map((b) => b.id)).toEqual(['hello.home', 'app.always', 'app.search']);
		expect(plan.blocked[0]?.reason).toBe('verification_unavailable: KOI_VERIFY_POOL is not set');
	});

	describe('runtime text that reaches a plan', () => {
		const VALUE = 'private-value-1234';
		const filesOf = async (t: Awaited<ReturnType<typeof setup>>, planId: string) => {
			const dir = t.evidence.planDir(planId);
			return {
				plan: await readFile(join(dir, 'plan.json'), 'utf8'),
				planning: await readFile(join(dir, 'planning.json'), 'utf8'),
			};
		};
		// The digest over the plan on disk, and the read koid makes of it.
		const expectDigestHolds = async (t: Awaited<ReturnType<typeof setup>>, plan: PlanReply) => {
			const { plan: text } = await filesOf(t, plan.planId);
			const { planDigest, ...rest } = PlanSchema.parse(JSON.parse(text));
			expect(planDigest).toBe(plan.planDigest);
			expect(canonicalDigest(rest)).toBe(planDigest);
			await t.verification.planPage(plan.planId, undefined);
		};

		test('why the box cannot verify is scrubbed as it enters, before the digest', async () => {
			const t = await setup({
				available: false,
				unavailableReason: `docker: no such network ${VALUE}`,
			});
			t.secrets.add(VALUE);
			const plan = await t.plan();
			expect(plan.blocked[0]?.reason).toBe(
				'verification_unavailable: docker: no such network [redacted]',
			);
			const files = await filesOf(t, plan.planId);
			expect(files.plan).not.toContain(VALUE);
			expect(files.planning).not.toContain(VALUE);
			expect(JSON.stringify(plan)).not.toContain(VALUE);
			await expectDigestHolds(t, plan);
			expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);
			// A refusal for what it says, and not because the plan does not hold together.
			const err = await refusal(t.run(plan));
			expect(err.code).toBe('verification_unavailable');
			expect(err.message).not.toContain(VALUE);
		});

		test('learned while matching: scrubbed from every plan record, since the scrub comes last', async () => {
			const POLICY_ERROR = `version: 1\nrequired: []\n${VALUE}: 1\n`;
			const PROOF_ERROR = `${PROOF}${VALUE}: 1\n`;
			let turns = 0;
			const t = await setup({
				available: false,
				unavailableReason: `docker: no such network ${VALUE}`,
				extra: { '.koi/required.yaml': POLICY_ERROR, '.koi/proofs/broken.yaml': PROOF_ERROR },
				changed: Array.from({ length: 3000 }, (_, i) => `src/f${i}.ts`),
				planGlobs: {
					onTurn: () => {
						// During a yield inside matching, which is the point: koid knew nothing of the
						// value when matching began.
						turns += 1;
						if (turns === 1) t.secrets.add(VALUE);
					},
				},
				files: {
					...POINTS,
					'search.yaml': (POINTS['search.yaml'] as string).replace(
						"paths: ['src/search/**']",
						`paths: [${Array.from({ length: 100 }, (_, i) => `'g${i}/**'`).join(', ')}]`,
					),
				},
			});
			const plan = await t.plan();
			expect(turns).toBeGreaterThan(0);
			expect(JSON.stringify(plan)).not.toContain(VALUE);
			expect(plan.blocked[0]?.reason).toBe(
				'verification_unavailable: docker: no such network [redacted]',
			);
			expect(plan.notes.join('\n')).toContain('[redacted]');
			const files = await filesOf(t, plan.planId);
			expect(files.plan).not.toContain(VALUE);
			expect(files.planning).not.toContain(VALUE);
			await expectDigestHolds(t, plan);
			expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);
		});

		test('learned after the plan: every reply masks it, and the plan stays as written', async () => {
			const t = await setup({
				available: false,
				unavailableReason: `docker: no such network ${VALUE}`,
			});
			const plan = await t.plan();
			expect(plan.blocked[0]?.reason).toContain(VALUE);
			t.secrets.add(VALUE);
			const page = await t.verification.planPage(plan.planId, undefined);
			expect(JSON.stringify(page)).not.toContain(VALUE);
			expect(page.blocked[0]?.reason).toContain('[redacted]');
			expect(page.planDigest).toBe(plan.planDigest);
			// A record is written once, so its digest is still over these bytes.
			expect((await filesOf(t, plan.planId)).plan).toContain(VALUE);
			await expectDigestHolds(t, plan);
		});

		test.each<[string, Record<string, string>]>([
			['the required policy', { '.koi/required.yaml': `version: 1\nrequired: []\n${VALUE}: 1\n` }],
			['a proof record', { '.koi/proofs/broken.yaml': `${PROOF}${VALUE}: 1\n` }],
		])('an error from reading %s is scrubbed, on disk and in the reply', async (_what, extra) => {
			const before = await setup({ extra });
			expect(JSON.stringify(await before.plan())).toContain(VALUE);

			const t = await setup({ extra });
			t.secrets.add(VALUE);
			const plan = await t.plan();
			expect(JSON.stringify(plan)).not.toContain(VALUE);
			expect(plan.notes.join('\n')).toContain('[redacted]');
			const files = await filesOf(t, plan.planId);
			expect(files.plan).not.toContain(VALUE);
			expect(files.planning).not.toContain(VALUE);
			await expectDigestHolds(t, plan);
			expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);
		});

		test('an error learned after the plan is masked in the reply, at the size a note may be', async () => {
			// A mask is longer than this value, so a note at its limit would grow past the schema.
			const short = 'privat12';
			const t = await setup({
				extra: { '.koi/proofs/broken.yaml': `${PROOF}${short.repeat(100)}: 1\n` },
			});
			const plan = await t.plan();
			expect(plan.notes.some((note) => note.includes(short))).toBe(true);
			t.secrets.add(short);
			const page = await t.verification.planPage(plan.planId, undefined);
			expect(JSON.stringify(page)).not.toContain(short);
			for (const note of page.notes) expect(note.length).toBeLessThanOrEqual(PLAN_NOTE_MAX);
		});

		test("a registered word changes neither koid's notes nor a reason that names what is declared", async () => {
			const t = await setup();
			const plan = await t.plan('matrix');
			t.secrets.add('aria snapshot');
			t.secrets.add('capability_missing');
			expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);

			const registered = await setup();
			registered.secrets.add('aria snapshot');
			registered.secrets.add('capability_missing');
			const planned = await registered.plan('matrix');
			expect(planned.notes).toEqual(plan.notes);
			expect(planned.blocked).toEqual(plan.blocked);
		});
	});

	describe('planning limits', () => {
		const withGlobs = (globs: string[]) => ({
			...POINTS,
			'search.yaml': (POINTS['search.yaml'] as string).replace(
				"paths: ['src/search/**']",
				`paths: [${globs.map((g) => `'${g}'`).join(', ')}]`,
			),
		});
		const names = (count: number) => Array.from({ length: count }, (_, i) => `src/f${i}.ts`);
		const globs = (count: number) => Array.from({ length: count }, (_, i) => `g${i}/**`);
		const expectNothingWritten = async (t: Awaited<ReturnType<typeof setup>>) => {
			expect(await readdir(join(t.stateDir, 'verification', 'plans'))).toEqual([]);
		};

		test('10,000 changed files by 10,000 globs end at once with a refusal', async () => {
			const t = await setup({ changed: names(10_000), files: withGlobs(globs(10_000)) });
			const started = performance.now();
			const err = await refusal(t.plan());
			// Run through, this is about 20 seconds with nothing else able to answer.
			expect(performance.now() - started).toBeLessThan(2000);
			expect([err.status, err.code, err.retryable]).toEqual([409, 'plan_too_large', false]);
			expect(err.message).toContain('select.paths globs');
			expect(err.message).toContain(String(PLAN_LIMITS.globs));
			await expectNothingWritten(t);
		});

		test.each<[string, () => SetupOptions, string]>([
			[
				'too many changed files',
				() => ({ changed: names(PLAN_LIMITS.changedFiles + 1) }),
				`${PLAN_LIMITS.changedFiles + 1} files changed`,
			],
			[
				'a changed name too long',
				() => ({ changed: ['a'.repeat(PLAN_LIMITS.changedNameChars + 1)] }),
				`name is ${PLAN_LIMITS.changedNameChars + 1} characters`,
			],
			[
				'too many globs',
				() => ({ files: withGlobs(globs(PLAN_LIMITS.globs + 1)) }),
				'select.paths globs',
			],
		])('%s: refused, whatever the profile selects', async (_what, options, says) => {
			const t = await setup(options());
			for (const profile of ['pr', 'matrix']) {
				const err = await refusal(t.plan(profile));
				expect(err.code).toBe('plan_too_large');
				expect(err.message).toContain(says);
			}
			await expectNothingWritten(t);
		});

		test('past its step budget a plan is refused, writes nothing, and leaves no point out', async () => {
			const t = await setup({
				changed: names(200),
				files: withGlobs(globs(50)),
				// The loader takes its share of this too. A plan this size takes many more.
				planGlobs: { budget: 10_000 },
			});
			const err = await refusal(t.plan());
			expect([err.status, err.code, err.retryable]).toEqual([409, 'plan_too_large', false]);
			expect(err.message).toContain('went past the 10000 steps a plan may take');
			expect(err.message).toContain('wrote nothing');
			await expectNothingWritten(t);
		});

		test('the same plan and the same budget get the same answer, as it counts no time', async () => {
			const options = () => ({ changed: names(200), files: withGlobs(globs(50)) });
			const large = await setup({ ...options(), planGlobs: { budget: 1_000_000 } });
			const plan = await large.plan();
			expect(plan.points.map((p) => p.id)).toContain('app.always');
			for (const _ of [1, 2]) {
				const small = await setup({ ...options(), planGlobs: { budget: 10_000 } });
				expect((await refusal(small.plan())).code).toBe('plan_too_large');
			}
		});

		test('loading the point globs counts toward the budget', async () => {
			// Enough for no plan at all, so the loader is what runs it out.
			const t = await setup({ planGlobs: { budget: 5 } });
			const err = await refusal(t.plan());
			expect(err.code).toBe('plan_too_large');
			await expectNothingWritten(t);
		});

		test('a real workspace selector loads and selects', async () => {
			const selector =
				'{apps,packages}/{web,api,cli,shared}/**/*.{ts,tsx,js,jsx,mjs,cjs,json,yaml,yml,css,scss,html,md,mdx,toml}';
			const t = await setup({
				changed: ['packages/web/src/deep/a.tsx', 'libs/web/a.ts', 'apps/api/a.py'],
				files: withGlobs([selector]),
			});
			const plan = await t.plan();
			expect(plan.points.find((p) => p.id === 'app.search')?.why).toBe(
				`changed: packages/web/src/deep/a.tsx matches ${selector}`,
			);
			expect(plan.uncovered).toEqual(['libs/web/a.ts', 'apps/api/a.py']);
		});

		test('a glob that once passed the schema and matched wrongly is now refused at load', async () => {
			// Bun.Glob read the `}` in `[a}]` as closing the group and answered false, so a file
			// that should select this point landed in `uncovered`, with a plan and no refusal.
			const group = `{[a},${Array(9).fill('a'.repeat(20)).join(',')}}`;
			const t = await setup({
				changed: [`${'a'.repeat(100)}b`],
				files: withGlobs([`${group.repeat(5)}b`]),
			});
			const err = await refusal(t.plan());
			expect(err.code).toBe('verify_invalid');
			expect(err.message).toContain('.koi/points/search.yaml');
			expect(err.message).toContain('[ is not supported');
			await expectNothingWritten(t);
		});

		test('koid goes on answering during a large plan that is allowed, and the plan is whole', async () => {
			const changed = names(3000);
			const last = changed.at(-1) as string;
			let turns = 0;
			const t = await setup({
				changed,
				files: withGlobs([...globs(2500), last]),
				planGlobs: {
					onTurn: () => {
						turns += 1;
					},
				},
			});
			let planning = true;
			let answers = 0;
			let longestPause = 0;
			let at = performance.now();
			const others = (async () => {
				while (planning) {
					// What a route of koid does: a read, and an answer.
					const err = await refusal(t.verification.planPage('n'.repeat(20), undefined));
					expect(err.code).toBe('no_such_plan');
					answers += 1;
					await new Promise((resolve) => setTimeout(resolve, 1));
					const now = performance.now();
					longestPause = Math.max(longestPause, now - at);
					at = now;
				}
			})();
			const started = performance.now();
			const plan = await t.plan();
			const took = performance.now() - started;
			planning = false;
			await others;
			expect(answers).toBeGreaterThan(5);
			// Counted, so it cannot depend on how fast the box is.
			expect(turns).toBeGreaterThan(50);
			// With no yield the one pause would be the whole of the matching.
			expect(longestPause).toBeLessThan(took / 2);
			// The last glob on the last file: found, so nothing was cut short.
			expect(plan.points.map((p) => p.id)).toContain('app.search');
			expect(plan.points.find((p) => p.id === 'app.search')?.why).toBe(
				`changed: ${last} matches ${last}`,
			);
			expect(plan.uncovered.at(-1)).toBe(`and ${changed.length - 101} more files`);
		}, 30_000);
	});

	test('shows the advisory policy, marks required points and attaches proof status', async () => {
		const t = await setup();
		const plan = await t.plan();
		expect(plan.policy).toEqual({
			source: 'none',
			advisory: {
				path: '.koi/required.yaml',
				required: [
					{ id: 'hello.home', revision: 2 },
					{ id: 'app.always', revision: 3 },
				],
			},
		});
		expect(plan.points.map((p) => [p.id, p.required, p.proof])).toEqual([
			['hello.home', true, 'unverified'],
			['app.always', true, 'none'],
			['app.search', false, 'none'],
		]);
		expect(plan.notes[0]).toContain(
			'agent actions (verify act), the pull request comment and proof verification are later work',
		);
		expect(plan.notes[1]).toContain('required policy has no trusted source yet');
	});

	test('persists a Plan that validates, with its digest, and pages it back', async () => {
		const t = await setup();
		const plan = await t.plan();
		const dir = t.evidence.planDir(plan.planId);
		const stored = PlanSchema.parse(JSON.parse(await readFile(join(dir, 'plan.json'), 'utf8')));
		expect(stored.planDigest).toBe(plan.planDigest);
		expect(stored.points.map((p) => p.id)).toEqual(['hello.home', 'app.always', 'app.search']);
		expect(stored.points[0]?.runners).toEqual([
			{ path: '.koi/runners/home.sh', digest: sha('curl "$KOI_PREVIEW_URL"\n') },
		]);
		const page = await t.verification.planPage(plan.planId, 'blocked:0');
		expect(page.points).toEqual([]);
		expect(page.uncovered).toEqual(['README.md']);
		expect((await stat(join(dir, 'planning.json'))).mode & 0o777).toBe(0o600);
	});

	test('a plan with more than a reply holds is paged under the bound', async () => {
		const changed = Array.from({ length: 150 }, (_, i) => `src/other/${'x'.repeat(150)}/${i}.ts`);
		const t = await setup({ changed: ['Dockerfile', ...changed] });
		const first = await t.plan();
		expect(Buffer.byteLength(JSON.stringify(first))).toBeLessThanOrEqual(
			VERIFICATION_REPLY_MAX_BYTES,
		);
		expect(first.next).toMatch(/^uncovered:[0-9]+$/);
		const all = [...first.uncovered];
		let next = first.next;
		while (next !== undefined) {
			const page = await t.verification.planPage(first.planId, next);
			expect(Buffer.byteLength(JSON.stringify(page))).toBeLessThanOrEqual(
				VERIFICATION_REPLY_MAX_BYTES,
			);
			all.push(...page.uncovered);
			next = page.next;
		}
		// Bounded: 100 named, and the count of the rest.
		expect(all).toHaveLength(101);
		expect(all.at(-1)).toBe('and 50 more files');
		expect(first.counts.uncovered).toBe(101);
	});

	describe('a why note over what a plan may hold', () => {
		// A nested name of about 1,100 UTF-16 units, made of `unit`, that a point
		// selects by naming it exactly.
		const longName = (unit: string, end: string) => {
			const segment = unit.repeat(Math.ceil(100 / unit.length));
			return `src/${Array.from({ length: 11 }, () => segment).join('/')}/${end}`;
		};
		const pointFor = (paths: string[]) => `id: app.long
revision: 1
claim: The long name is covered.
select:
  paths:
${paths.map((path) => `    - ${JSON.stringify(path)}`).join('\n')}
run:
  command: [sh, .koi/runners/home.sh]
assertions:
  - name: holds
    description: The app answers.
    evidence: [http-response]
`;
		const planFor = async (file: string, paths: string[]) => {
			const t = await setup({
				changed: [file],
				files: { ...POINTS, 'long.yaml': pointFor(paths) },
			});
			const plan = await t.plan();
			const stored = PlanSchema.parse(
				JSON.parse(await readFile(join(t.evidence.planDir(plan.planId), 'plan.json'), 'utf8')),
			);
			const why = stored.points.find((p) => p.id === 'app.long')?.why ?? '';
			return { t, plan, why };
		};

		test('a long name and an equally long exact path still plan and run, and the note says both', async () => {
			const file = longName('a', 'first-end.ts');
			expect(file.length).toBeGreaterThan(1_100);
			const { t, plan, why } = await planFor(file, [file]);
			expect(why.length).toBeLessThanOrEqual(TEXT_MAX);
			expect(why).toStartWith('changed: src/aaa');
			expect(why).toContain('first-end.ts matches src/aaa');
			expect(why).toEndWith('first-end.ts');
			expect(why).toContain('[cut by koid]');
			expect(plan.points.find((p) => p.id === 'app.long')?.why).toBe(why);
			const accepted = await t.run(plan);
			await t.verification.settled(accepted.runId);
			expect((await t.verification.status(accepted.runId)).finalized).toBe(true);
		});

		test('multibyte names are cut by the units the schema counts, and no pair is split', async () => {
			// Emoji take two units and four bytes each, so a cut by bytes would
			// keep half of what fits, and a careless cut would split a pair.
			for (const unit of ['😀', 'é', 'a😀']) {
				const file = longName(unit, `${unit}end.ts`);
				const { plan, why } = await planFor(file, [file]);
				expect(why.length).toBeLessThanOrEqual(TEXT_MAX);
				// Every unit the schema allows is used, less the marker edges.
				expect(why.length).toBeGreaterThan(TEXT_MAX - 4);
				expect(why.isWellFormed()).toBe(true);
				expect(why).toEndWith(`${unit}end.ts`);
				expect(why).toContain(`${unit}end.ts matches `);
				// The reply takes the note or says it cut it, and it still parses.
				const shown = plan.points.find((p) => p.id === 'app.long')?.why ?? '';
				expect(shown === why || plan.truncated?.includes('points[app.long].why')).toBe(true);
			}
		});

		test('a short path keeps its whole name and gives the rest to the long one', async () => {
			const file = `src/${'b'.repeat(3_000)}/end.ts`;
			const { why } = await planFor(file, ['src/*/end.ts']);
			expect(why.length).toBe(TEXT_MAX);
			expect(why).toEndWith('/end.ts matches src/*/end.ts');
			const glob = `src/${'c'.repeat(3_000)}/**`;
			const short = await planFor(`src/${'c'.repeat(3_000)}/x.ts`, [glob]);
			expect(short.why.length).toBeLessThanOrEqual(TEXT_MAX);
			expect(short.why).toContain('/x.ts matches src/ccc');
			expect(short.why).toEndWith('/**');
		});

		test('a note that fits is left as it was', async () => {
			const file = longName('a', 'x.ts');
			const { why } = await planFor(file, ['src/**']);
			expect(why).toBe(`changed: ${file} matches src/**`);
		});
	});

	test('a snapshot file that changed since it was taken refuses the plan and the run, whichever it is', async () => {
		const files: Array<[string, string]> = [
			['.koi/fixtures/probe.txt', 'probe!'],
			['.koi/required.yaml', REQUIRED.replace('revision: 2', 'revision: 3')],
			['.koi/proofs/hello.home.yaml', PROOF.replace('revision: 2', 'revision: 3')],
			['.koi-runtime/changed-files.txt', 'Dockerfile\nsrc/other.ts\n'],
		];
		for (const [path, text] of files) {
			const t = await setup();
			const plan = await t.plan();
			const file = join(t.evidence.inputsDir(DEPLOYMENT), 'source', path);
			await writeFile(file, text);
			const planned = await refusal(t.plan());
			expect([planned.status, planned.code]).toEqual([409, 'inputs_changed']);
			expect(planned.message).toContain(path);
			const ran = await refusal(t.run(plan));
			expect(ran.code).toBe('inputs_changed');
			expect(t.calls).toEqual([]);
		}
		// Same bytes, so the same plan: a rewrite that changes nothing passes.
		const same = await setup();
		await writeFile(
			join(same.evidence.inputsDir(DEPLOYMENT), 'source/.koi/fixtures/probe.txt'),
			'probe',
		);
		expect((await same.plan()).counts.selected).toBe(3);
	});

	test('a changed file is matched by its name as git wrote it, spaces included', async () => {
		// A leading space is part of the name: the file is not under src/search/,
		// and trimming it would select a point the change does not touch.
		const t = await setup({ changed: ['Dockerfile', ' src/search/odd.ts', 'src/search/a b.ts '] });
		const plan = await t.plan();
		expect(plan.points.map((p) => [p.id, p.why])).toEqual([
			['hello.home', 'always: listed by profile pr'],
			['app.always', 'select.always: taken by every run of profile pr'],
			['app.search', 'changed: src/search/a b.ts  matches src/search/**'],
		]);
		expect(plan.uncovered).toEqual([' src/search/odd.ts']);
	});

	test('an explicit subset is advisory and must name points that exist', async () => {
		const t = await setup();
		const plan = await t.plan('pr', { points: ['app.search'] });
		expect(plan.advisory).toBe(true);
		expect(plan.points.map((p) => [p.id, p.why])).toEqual([
			['app.search', 'requested: named in the request'],
		]);
		const err = await refusal(t.plan('pr', { points: ['app.nope'] }));
		expect([err.status, err.code]).toEqual([400, 'no_such_point']);
	});

	test('a dirty tree or a build without a pull request context plans as advisory', async () => {
		expect((await (await setup({ dirty: true })).plan()).advisory).toBe(true);
		expect((await (await setup({ merge: false })).plan()).advisory).toBe(true);
	});

	test('refuses an unknown preview, profile, or deployment, and missing inputs', async () => {
		const t = await setup();
		const unknown = await refusal(
			t.verification.plan({ version: 1, label: 'nobody-pr-1', profile: 'pr' }),
		);
		expect([unknown.status, unknown.code]).toEqual([404, 'no_such_preview']);
		const profile = await refusal(t.plan('nightly'));
		expect([profile.status, profile.code]).toEqual([400, 'no_such_profile']);
		expect(profile.message).toContain('it has pr, matrix');
		const other = await refusal(t.plan('pr', { expectedDeploymentId: 'e'.repeat(20) }));
		expect([other.status, other.code]).toEqual([409, 'deployment_mismatch']);
		// A deployment whose inputs were not kept.
		t.record.deployment = {
			...(t.record.deployment as NonNullable<PreviewRecord['deployment']>),
			deploymentId: 'e'.repeat(20),
		};
		const inputs = await refusal(t.plan());
		expect([inputs.status, inputs.code]).toEqual([409, 'inputs_missing']);
		delete t.record.deployment;
		const none = await refusal(t.plan());
		expect([none.status, none.code]).toEqual([409, 'no_deployment']);
	});

	test('a long error in the policy file is cut to fit a note, and the plan reads back', async () => {
		// The schema refuses the key by name, so the error quotes all of it.
		const key = 'k'.repeat(900);
		const t = await setup({
			extra: { '.koi/required.yaml': `version: 1\nrequired: []\n${key}: true\n` },
		});
		const plan = await t.plan();
		const error = plan.policy.advisory?.error;
		expect(error).toContain(key);
		const note = plan.notes.find((n) => n.startsWith('.koi/required.yaml: '));
		expect(note).toBeDefined();
		expect(note).toEndWith(' [cut by koid]');
		expect(plan.notes.every((n) => n.length <= PLAN_NOTE_MAX)).toBe(true);
		// The whole error stays in the policy, and the record reads back.
		expect((error as string).length).toBeGreaterThan(PLAN_NOTE_MAX);
		expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);
		const accepted = await t.run(plan);
		await t.verification.settled(accepted.runId);
		expect((await t.verification.status(accepted.runId)).finalized).toBe(true);
	});

	test('limits come from the manifest under the host ceilings, with defaults', async () => {
		const t = await setup({
			manifest: MANIFEST.replace(
				'  timeoutSeconds: 600\n',
				'  timeoutSeconds: 3600\n  maxRequests: 500\n',
			),
		});
		const plan = await t.plan();
		expect(plan.limits).toEqual({
			runSeconds: 3600,
			pointSeconds: 900,
			runRequests: 200,
			pointRequests: 50,
		});
		const bare = await setup({
			manifest: MANIFEST.replace('budgets:\n  timeoutSeconds: 600\n', ''),
		});
		expect((await bare.plan()).limits).toEqual({
			runSeconds: 900,
			pointSeconds: 300,
			runRequests: 50,
			pointRequests: 20,
		});
		expect(resolveLimits({ manifest: { budgets: { timeoutSeconds: 100 } } } as never)).toEqual({
			runSeconds: 100,
			pointSeconds: 100,
			runRequests: 50,
			pointRequests: 20,
		});
	});

	test("a point's budget is its own, or the plan's point limit, under the host's ceiling", () => {
		const limits = { runSeconds: 900, pointSeconds: 300, runRequests: 50, pointRequests: 20 };
		const left = 3_600_000;
		expect(pointBudgetSeconds({}, limits, left)).toBe(300);
		expect(pointBudgetSeconds({ budgets: { timeoutSeconds: 1 } }, limits, left)).toBe(1);
		// More than the manifest's value is allowed, more than the host's is not.
		expect(pointBudgetSeconds({ budgets: { timeoutSeconds: 600 } }, limits, left)).toBe(600);
		expect(pointBudgetSeconds({ budgets: { timeoutSeconds: 3600 } }, limits, left)).toBe(900);
	});
});

describe('running', () => {
	test('takes the lease, runs each point in a verifier, judges it from its reports, and finalizes', async () => {
		const t = await setup();
		const { plan, accepted, status } = await t.runToEnd();
		const { runId } = accepted;
		expect(accepted.state).toBe('running');
		expect(accepted.planId).toBe(plan.planId);
		expect(accepted.limits.runSeconds).toBe(600);
		// The lease: held by the run, for the run's limit and the allowance.
		expect(t.calls[0]).toBe(`lease ${LABEL} ${runLeaseHolder(runId)} 720`);
		expect(t.calls.at(-1)).toBe(`release ${LABEL} ${'l'.repeat(20)}`);
		expect(t.record.lease).toBeUndefined();

		expect(status.state).toBe('completed');
		expect(status.completion).toBe('evaluated');
		expect(status.outcome).toBe('passed');
		expect(status.finalized).toBe(true);
		expect(status.evidence).toBe('complete');
		expect(status.cleanup).toBe('succeeded');
		expect(status.freshness).toBe('current');
		expect(status.readiness.eligibleForMergeGate).toBe(false);
		expect(status.readiness.reasons).toContain(
			'no required policy from the protected base branch (advisory rollout)',
		);
		expect(status.progress).toEqual({ total: 3, done: 3 });
		expect(status.points.map((p) => [p.id, p.state, p.outcome, p.reason, p.evidence])).toEqual([
			[
				'hello.home',
				'done',
				'pass',
				undefined,
				['recorder:screenshot:1', 'recorder:aria:2', 'recorder:http-response:3'],
			],
			[
				'app.always',
				'done',
				'pass',
				undefined,
				['recorder:screenshot:4', 'recorder:aria:5', 'recorder:http-response:6'],
			],
			[
				'app.search',
				'done',
				'pass',
				undefined,
				['recorder:screenshot:7', 'recorder:aria:8', 'recorder:http-response:9'],
			],
		]);
		expect(status.problems).toEqual([]);

		// What the recorder was asked, per point: open at /, two captures and
		// a read, close.
		const recorder = t.recorders.get(runId);
		expect(recorder?.calls.filter((c) => c.startsWith('open '))).toEqual([
			'open hello.home 1 /',
			'open app.always 1 /',
			'open app.search 1 /',
		]);
		expect(recorder?.calls.filter((c) => c.startsWith('capture '))).toHaveLength(6);
		expect(recorder?.calls.filter((c) => c.startsWith('read '))).toEqual([
			'read x1 GET /',
			'read x1 GET /',
			'read x1 GET /',
		]);

		// Each point got a verifier of its own from the allowed runner image,
		// with the point's identity, the frozen inputs and the supervisor.
		expect(t.docker.verifiers.map((v) => v.env.KOI_POINT_ID)).toEqual([
			'hello.home',
			'app.always',
			'app.search',
		]);
		const first = t.docker.verifiers[0] as FakeVerifier;
		expect(first.options.image).toBe(CURL_IMAGE);
		expect(first.options.entrypoint).toBe('python3');
		expect(first.options.command).toEqual(['-I', '/koi/supervisor.py', '/koi/point.json']);
		expect(first.options.workdir).toBe('/workspace');
		expect(first.env.KOI_RUN_ID).toBe(runId);
		expect(first.env.KOI_PREVIEW_URL).toBe(`http://app.${runId}.invalid:8080`);
		expect(first.env.KOI_RECORDER_WS).toMatch(/^ws:\/\/10\.213\.0\.3:4317\/[0-9a-f]{64}$/);
		expect(first.env.KOI_TIMEOUT_SECONDS).toBe('600');
		expect(first.files.get('koi/supervisor.py')?.content).toContain('def main(');
		expect(JSON.parse(first.files.get('koi/point.json')?.content ?? '')).toEqual({
			version: 1,
			runner: null,
			steps: {
				setup: null,
				run: ['sh', '.koi/runners/home.sh'],
				cleanup: ['sh', '.koi/runners/home.sh'],
			},
			timeoutSeconds: 600,
		});
		expect(first.files.get('workspace/.koi/runners/home.sh')?.content).toBe(
			'curl "$KOI_PREVIEW_URL"\n',
		);
		expect(first.files.get('workspace/.koi/points/home.yaml')?.mode).toBe(0o444);
		expect(first.files.get('workspace/.koi')?.mode).toBe(0o555);

		// The bundle: run, plan, execution, controller, result, report, manifest.
		const dir = t.evidence.runDir(runId);
		const run = RunSchema.parse(JSON.parse(await readFile(join(dir, 'run.json'), 'utf8')));
		expect([run.state, run.planId, run.planDigest]).toEqual([
			'completed',
			plan.planId,
			plan.planDigest,
		]);
		expect(run.finishedAt).toBeDefined();
		const result = ResultSchema.parse(JSON.parse(await readFile(join(dir, 'result.json'), 'utf8')));
		expect(result.outcome).toBe('passed');
		expect(result.points.map((p) => p.outcome)).toEqual(['pass', 'pass', 'pass']);
		expect(result.uncovered).toEqual(['README.md']);
		const execution = ExecutionDescriptorSchema.parse(
			JSON.parse(await readFile(join(dir, 'execution.json'), 'utf8')),
		);
		expect(execution.runnerImage).toEqual({
			reference: 'curlimages/curl:8.11.1',
			digest: CURL_IMAGE,
		});
		expect(execution.recorderImage.digest).toBe(RECORDER_IMAGE);
		expect(execution.browser.version).toBe('142.0.7444.52');
		expect(execution.origin).toBe(`http://app.${runId}.invalid:8080`);
		expect(execution.policy.source).toBe('none');
		expect(status.executionDigest).toBe(execution.executionDigest);
		const controller = RunControllerRecordSchema.parse(
			JSON.parse(await readFile(join(dir, 'controller.json'), 'utf8')),
		);
		expect(controller.completion).toBe('evaluated');
		expect(controller.lease.leaseId).toBe('l'.repeat(20));
		const report = await readFile(join(dir, 'report.md'), 'utf8');
		expect(report).toStartWith(`<!-- koi-verification:${runId} -->\n## koi verification: passed\n`);
		expect(report).toContain(
			'| hello.home | pass | - | recorder:screenshot:1, recorder:aria:2, recorder:http-response:3 |',
		);
		const observations = JSON.parse(
			await readFile(join(dir, 'points/hello.home/observations.json'), 'utf8'),
		) as { asserted: unknown[]; steps: unknown[]; cleanup: string; verdict: { outcome: string } };
		expect(observations.asserted).toEqual([
			{
				assertion: 'home-says-hello',
				outcome: 'pass',
				cited: ['recorder:screenshot:1', 'recorder:aria:2', 'recorder:http-response:3'],
				detail: 'home-says-hello as the runner saw it',
			},
		]);
		expect(observations.cleanup).toBe('succeeded');
		expect(observations.steps.map((s) => (s as { step: string }).step)).toEqual(['run', 'cleanup']);
		expect(observations.verdict.outcome).toBe('pass');
		const manifest = EvidenceManifestSchema.parse(
			JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')),
		);
		expect(manifest.planDigest).toBe(plan.planDigest);
		expect(manifest.executionDigest).toBe(execution.executionDigest);
		expect(Object.keys(manifest.files).sort()).toEqual([
			'controller.json',
			'execution.json',
			'plan.json',
			'report.md',
			'result.json',
			'run.json',
			'status.json',
		]);
		expect(manifest.artifacts).toHaveLength(9);
		expect(manifest.status.state).toBe('completed');

		// The events: the runner's assertions and captures, host-sequenced,
		// and never the browser token.
		const events = await t.verification.events(runId, 0, 200);
		const types = events.events.map((e) => e.type);
		expect(types).toContain('verifier-created');
		expect(types).toContain('verifier-started');
		expect(types).toContain('runner-capture-requested');
		expect(types).toContain('runner-capture-answered');
		expect(types).toContain('runner-read-answered');
		expect(types).toContain('runner-assertion');
		expect(types).toContain('supervisor-exit');
		expect(types).toContain('verifier-stopped');
		const token = first.env.KOI_RECORDER_WS?.split('/').at(-1) ?? 'none';
		expect(await readFile(join(dir, 'events.ndjson'), 'utf8')).not.toContain(token);

		// Each point's verifier was created, started, stopped and removed; the
		// network and the recorder went last, in order.
		const verifier = `koi-verify-${runId}-verifier`;
		expect(t.docker.events.filter((e) => e.startsWith(`started ${verifier}`))).toHaveLength(3);
		expect(t.docker.events.filter((e) => e === `removed ${verifier}`)).toHaveLength(4);
		expect(t.docker.events.filter((e) => e === `apply ${runId}`)).toHaveLength(5);
		expect(t.docker.events.at(-1)).toBe(`removed network koi-v-${runId}`);
		expect(t.docker.events.indexOf(`revoke ${runId}`)).toBeGreaterThan(
			t.docker.events.indexOf(`stopped koi-verify-${runId}-recorder`),
		);
		expect(await t.network.record(runId)).toBeUndefined();
	});

	test('touches the activity stamp while the run goes', async () => {
		const t = await setup({ keepAwakeMs: 1 });
		const gate = new Gate();
		t.prepareRecorder((r) => {
			r.captureGate = gate;
		});
		const plan = await t.plan();
		const accepted = await t.run(plan);
		await gate.reached;
		// Real time, since the interval runs on the host clock.
		await Bun.sleep(30);
		expect(t.awake()).toBeGreaterThan(0);
		const recorder = t.recorders.get(accepted.runId);
		if (recorder !== undefined) recorder.captureGate = undefined;
		gate.release();
		await t.verification.settled(accepted.runId);
		// The lease outlives the run's budget, so no tick renewed it.
		expect(t.calls.filter((c) => c.startsWith('renew'))).toEqual([]);
	});

	test('status says running until the manifest is in', async () => {
		const t = await setup();
		const { accepted } = await t.runToEnd();
		// At the moment the bundle was being finalized, after the run had
		// been judged, a reader still saw it running: no status ever shows a
		// judged run that is not finalized.
		expect(t.atFinalize).toEqual([{ runId: accepted.runId, state: 'running', finalized: false }]);
	});

	test("a failing assertion fails the point and the run, with the runner's detail", async () => {
		const t = await setup();
		t.docker.verifierScript = runner(declared(POINTS), (point) =>
			point === 'app.search' ? 'fail' : 'pass',
		);
		const { status } = await t.runToEnd();
		expect(status.completion).toBe('evaluated');
		expect(status.outcome).toBe('failed');
		expect(status.points.map((p) => [p.id, p.outcome])).toEqual([
			['hello.home', 'pass'],
			['app.always', 'pass'],
			['app.search', 'fail'],
		]);
		expect(status.points[2]?.reason).toBe('finds failed: finds as the runner saw it');
		// A failed point keeps the evidence the run holds for it.
		expect(status.points[2]?.evidence).toEqual([
			'recorder:screenshot:7',
			'recorder:aria:8',
			'recorder:http-response:9',
		]);
	});

	test('a runner that never reports an assertion leaves the point not-run, and the run incomplete', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(supervisorLine({ event: 'started' }));
			v.out('the runner printed a log line and nothing else');
			// Every declared step ran and exited 0; only the assertion is missing.
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const { accepted, status } = await t.runToEnd();
		expect(status.outcome).toBe('incomplete');
		expect(status.points.map((p) => p.outcome)).toEqual(['not-run', 'not-run', 'not-run']);
		expect(status.points[0]?.reason).toBe('not_run: no terminal event for home-says-hello');
		const events = await t.verification.events(accepted.runId, 0, 200);
		expect(events.events.filter((e) => e.type === 'runner-log').map((e) => e.text)).toContain(
			'the runner printed a log line and nothing else',
		);
	});

	test('a runner image outside the allowlist blocks every point, at plan time and at run time', async () => {
		const t = await setup({ allowed: [] });
		const plan = await t.plan();
		expect(plan.points).toEqual([]);
		expect(plan.blocked.map((b) => b.id)).toEqual(['hello.home', 'app.always', 'app.search']);
		expect(plan.blocked[0]?.reason).toBe(
			`image_not_allowed: curlimages/curl:8.11.1 (${CURL_IMAGE}) is not on this host's allowlist (KOI_VERIFIER_IMAGES)`,
		);
		// A plan that took no point can still run: each point is blocked with
		// the plan's reason, and no verifier starts.
		const accepted = await t.run(plan);
		await t.verification.settled(accepted.runId);
		const status = await t.verification.status(accepted.runId);
		expect(status.completion).toBe('evaluated');
		expect(status.outcome).toBe('incomplete');
		expect(status.points.map((p) => p.outcome)).toEqual(['blocked', 'blocked', 'blocked']);
		expect(status.points[0]?.reason).toStartWith('image_not_allowed: curlimages/curl:8.11.1');
		expect(t.docker.verifiers).toEqual([]);
		const execution = ExecutionDescriptorSchema.parse(
			JSON.parse(await readFile(join(t.evidence.runDir(accepted.runId), 'execution.json'), 'utf8')),
		);
		expect(execution.runnerImage).toEqual({ reference: 'curlimages/curl:8.11.1' });
	});

	test('a plan keeps the digest its runner image resolved to, inside what its digest covers', async () => {
		const t = await setup();
		const plan = await t.plan();
		expect(plan.runnerImageDigest).toBe(CURL_IMAGE);
		const dir = t.evidence.planDir(plan.planId);
		const stored = PlanSchema.parse(JSON.parse(await readFile(join(dir, 'plan.json'), 'utf8')));
		expect(stored.runnerImageDigest).toBe(CURL_IMAGE);
		const { planDigest, ...rest } = stored;
		expect(planDigest).toBe(canonicalDigest(rest));
		// The digest of the record as it stands is what a reader checks, so a
		// digest changed on disk is a corrupt plan and no way around a new one.
		await writeFile(
			join(dir, 'plan.json'),
			JSON.stringify({ ...stored, runnerImageDigest: OTHER_IMAGE }),
		);
		const err = await refusal(t.run(plan));
		expect([err.status, err.code]).toEqual([409, 'plan_corrupt']);
	});

	test('a tag that moved since the plan refuses the run; the image must not change under a plan', async () => {
		const t = await setup();
		const plan = await t.plan();
		expect(plan.runnerImageDigest).toBe(CURL_IMAGE);
		// The allowed tag now names another image.
		t.docker.imageInfos.set('curlimages/curl:8.11.1', { id: OTHER_IMAGE, env: ['PATH=/usr/bin'] });
		const err = await refusal(t.run(plan));
		expect([err.status, err.code]).toEqual([409, 'inputs_changed']);
		expect(err.message).toContain(CURL_IMAGE);
		expect(err.message).toContain(OTHER_IMAGE);
		// Refused before anything was taken or made.
		expect(t.calls).toEqual([]);
		expect(t.docker.verifiers).toEqual([]);
		// A new plan records the new image, and runs in it.
		const again = await t.plan();
		expect(again.runnerImageDigest).toBe(OTHER_IMAGE);
		const accepted = await t.run(again);
		await t.verification.settled(accepted.runId);
		expect(t.docker.verifiers[0]?.options.image).toBe(OTHER_IMAGE);
	});

	test('an image gone from the box or the allowlist since the plan refuses the run too', async () => {
		const gone = await setup();
		const made = await gone.plan();
		expect(made.points).toHaveLength(3);
		gone.docker.imageInfos.delete('curlimages/curl:8.11.1');
		const missing = await refusal(gone.run(made));
		expect(missing.code).toBe('inputs_changed');
		expect(missing.message).toContain('image_missing');
		expect(gone.calls).toEqual([]);
		// The other way too: a plan made while the image was refused is not a
		// plan for the image that has since been allowed.
		const refused = await setup({ allowed: [] });
		const blocked = await refused.plan();
		expect(blocked.runnerImageDigest).toBeUndefined();
		refused.docker.imageInfos.set('curlimages/curl:8.11.1', {
			id: VERIFIER_IMAGE,
			env: ['PATH=/usr/bin'],
		});
		const allowed = await refusal(refused.run(blocked));
		expect(allowed.code).toBe('inputs_changed');
	});

	test("a tag that moves once the run has started changes nothing: each verifier uses the start's digest", async () => {
		const t = await setup();
		const plan = await t.plan();
		t.prepareRecorder((r) => {
			r.onOpen = () => {
				t.docker.imageInfos.set('curlimages/curl:8.11.1', { id: OTHER_IMAGE, env: [] });
			};
		});
		const accepted = await t.run(plan);
		await t.verification.settled(accepted.runId);
		expect(t.docker.verifiers.map((v) => v.options.image)).toEqual([
			CURL_IMAGE,
			CURL_IMAGE,
			CURL_IMAGE,
		]);
		const execution = ExecutionDescriptorSchema.parse(
			JSON.parse(await readFile(join(t.evidence.runDir(accepted.runId), 'execution.json'), 'utf8')),
		);
		expect(execution.runnerImage.digest).toBe(CURL_IMAGE);
	});

	test('the default image is always allowed, by its name in the manifest', async () => {
		const t = await setup({
			allowed: [],
			manifest: MANIFEST.replace('image: curlimages/curl:8.11.1', 'image: koi-verifier'),
		});
		const { status } = await t.runToEnd();
		expect(status.outcome).toBe('passed');
		expect(t.docker.verifiers[0]?.options.image).toBe(VERIFIER_IMAGE);
	});

	test('a verifier that cannot start blocks the point with the reason, and the run goes on', async () => {
		const t = await setup();
		t.docker.attachError = 'docker start exited 125: no such image';
		const { status } = await t.runToEnd();
		expect(status.completion).toBe('evaluated');
		expect(status.points.map((p) => p.outcome)).toEqual(['blocked', 'pass', 'pass']);
		expect(status.points[0]?.reason).toBe(
			'verifier_failed: docker start exited 125: no such image',
		);
	});

	test('a point that reaches its budget is stopped and blocked, never passed', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(supervisorLine({ event: 'started' }));
			if (v.env.KOI_POINT_ID === 'hello.home') {
				// The runner hangs; the clock passes the point's budget.
				t.advance(620_000);
				await v.stopped;
				return 137;
			}
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const { status } = await t.runToEnd();
		expect(status.points[0]?.outcome).toBe('blocked');
		expect(status.points[0]?.reason).toBe(
			'point_timeout: the point reached its budget of 600 seconds before the runner ended',
		);
		// The run's own deadline passed with it, so the rest are not run.
		expect(status.points.map((p) => p.outcome)).toEqual(['blocked', 'not-run', 'not-run']);
		expect(t.docker.verifiers[0]?.detached).toBe(true);
	});

	describe('a word someone registers as a key', () => {
		// The keys page takes any value, and every value goes into the one registry,
		// so one request reaches every run on the host. None of this may change how a
		// point ended or leave a run that cannot be read.
		const PROFILE = 'nightly-check';
		const MASK = '[redacted]';
		const FAILURE = `expected the assertion to show evidence of a heading on ${PROFILE}`;
		const manifest = `version: 1
points:
  - points/*.yaml
profiles:
  ${PROFILE}:
    always: [hello.home, app.search]
runner:
  image: curlimages/curl:8.11.1
budgets:
  timeoutSeconds: 600
`;
		const onePassOneFail = runner(
			declared(POINTS),
			(point) => (point === 'app.search' ? 'fail' : 'pass'),
			(name) => (name === 'finds' ? FAILURE : `${name} as the runner saw it`),
		);
		const start = async () => {
			const t = await setup({ manifest });
			t.docker.verifierScript = onePassOneFail;
			return t;
		};
		// Registers `word` before the plan, or at the first capture of the first point.
		const runWith = async (word: string, when: 'before' | 'during') => {
			const t = await start();
			if (when === 'before') t.secrets.add(word);
			const plan = await t.plan(PROFILE);
			const gate = new Gate();
			if (when === 'during') {
				t.prepareRecorder((r) => {
					r.captureGate = gate;
				});
			}
			const { runId } = await t.run(plan);
			if (when === 'during') {
				await gate.reached;
				t.secrets.add(word);
				const recorder = t.recorders.get(runId);
				if (recorder !== undefined) recorder.captureGate = undefined;
				gate.release();
			}
			await t.verification.settled(runId);
			return { t, runId, plan };
		};

		// What holds whichever word was registered: how each point ended, on every
		// record and reply that says so, and that each can still be read.
		const expectRightAndReadable = async (t: Awaited<ReturnType<typeof setup>>, runId: string) => {
			const status = await t.verification.status(runId);
			expect(status.finalized).toBe(true);
			expect(status.completion).toBe('evaluated');
			expect(status.outcome).toBe('failed');
			expect(status.problemCount).toBe(0);
			const ended = Object.fromEntries(status.points.map((p) => [p.id, p.outcome]));
			expect(ended).toEqual({ 'hello.home': 'pass', 'app.search': 'fail' });
			expect(status.points[0]?.evidence.length).toBeGreaterThan(0);

			const dir = t.evidence.runDir(runId);
			const read = (name: string) => readFile(join(dir, name), 'utf8');
			const controller = RunControllerRecordSchema.parse(JSON.parse(await read('controller.json')));
			expect(controller.outcome).toBe('failed');
			expect(controller.points.map((p) => p.outcome)).toEqual(['pass', 'fail']);
			const result = ResultSchema.parse(JSON.parse(await read('result.json')));
			expect(result.outcome).toBe('failed');
			expect(result.points.map((p) => p.outcome)).toEqual(['pass', 'fail']);
			const manifest = EvidenceManifestSchema.parse(JSON.parse(await read('manifest.json')));
			expect(manifest.status.evidence).toBe('complete');
			expect(manifest.artifacts.every((a) => a.availability === 'available')).toBe(true);
			ExecutionDescriptorSchema.parse(JSON.parse(await read('execution.json')));
			const report = await read('report.md');
			expect(report).toContain('## koi verification: failed');
			expect(report).toContain('| hello.home | pass |');
			expect(report).toContain('| app.search | fail |');
			// A failing assertion reads as failed in its own observations, by field.
			const failing = JSON.parse(await read('points/app.search/observations.json'));
			expect(failing.asserted.map((r: { outcome: string }) => r.outcome)).toEqual(['fail']);
			expect(failing.verdict.outcome).toBe('fail');
			const passing = JSON.parse(await read('points/hello.home/observations.json'));
			expect(passing.verdict.outcome).toBe('pass');
			expect(passing.verdict.evidence.length).toBeGreaterThan(0);

			// The replies read back through their own schemas, and so does every event.
			formatStatus(status);
			const events = await t.verification.events(runId);
			expect(events.events.length).toBeGreaterThan(0);
			for (const line of (await read('events.ndjson')).split('\n').filter((l) => l !== '')) {
				EvidenceEventSchema.parse(JSON.parse(line));
			}
			const evidence = await t.verification.evidence(runId);
			expect(evidence.artifacts.length).toBe(manifest.artifacts.length);
			const first = manifest.artifacts[0];
			if (first !== undefined) await t.verification.artifact(runId, first.id);
			return { status, controller, result, report, failing, events };
		};

		for (const word of ['outcome', 'pass', 'fail', 'pointId', 'steps', 'blocked']) {
			for (const when of ['before', 'during'] as const) {
				test(`${word} ${when} a run: too short to register, so nothing changes`, async () => {
					const { t, runId } = await runWith(word, when);
					expect(t.secrets.count).toBeLessThanOrEqual(2);
					const { status } = await expectRightAndReadable(t, runId);
					expect(status.points[1]?.reason).toContain(FAILURE);
				});
			}
		}

		for (const word of ['evidence', 'assertion', PROFILE, 'expected']) {
			for (const when of ['before', 'during'] as const) {
				test(`${word} ${when} a run: masked in free text, and the run stays right`, async () => {
					const { t, runId } = await runWith(word, when);
					const { status, controller, result, report, failing, events } =
						await expectRightAndReadable(t, runId);
					const free = [
						status.points[1]?.reason,
						controller.points[1]?.reason,
						result.points[1]?.reason,
						failing.asserted[0]?.detail,
						failing.verdict.reasons.join(' '),
					];
					for (const text of free) {
						expect(text).toContain(MASK);
						expect(text).not.toContain(word);
					}
					expect(report).toContain('app.search');
					expect(report).not.toContain(FAILURE);
					// The assertion came after the word was known. Its event says the
					// word in no value, and a field's name may be masked there.
					const event = events.events.find(
						(e) => e.type === 'runner-assertion' && e.pointId === 'app.search',
					);
					expect(event?.outcome).toBe('fail');
					expect(event?.detail).toContain(MASK);
					expect(JSON.stringify(event?.detail)).not.toContain(word);
				});
			}
		}

		test('a word that is part of an artifact id leaves the reference naming the artifact', async () => {
			for (const word of ['screenshot', 'recorder', 'http-response']) {
				for (const when of ['before', 'during'] as const) {
					const { t, runId } = await runWith(word, when);
					const { status, failing } = await expectRightAndReadable(t, runId);
					expect(status.points[0]?.evidence).toContain('recorder:http-response:3');
					// What the runner cited is its own text, and is masked as text.
					expect(JSON.stringify(failing.asserted[0]?.cited)).not.toContain(word);
				}
			}
		}, 30_000);

		test('a word that is a fixed value of a record stays that value', async () => {
			for (const word of ['chromium', 'complete', 'evaluated', 'completed', 'succeeded']) {
				for (const when of ['before', 'during'] as const) {
					const { t, runId } = await runWith(word, when);
					const { status } = await expectRightAndReadable(t, runId);
					expect(status.cleanup).toBe('succeeded');
				}
			}
		}, 30_000);

		test('a word in an assertion or a capture label takes nothing from the point', async () => {
			const t = await setup({ manifest });
			// The word is in the label and the assertion's name. A label refused for
			// it would leave the assertion with nothing to cite, and the point would
			// fail for what someone typed on the keys page.
			const label = 'evidence-shot';
			const files = declared(POINTS);
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(supervisorLine({ event: 'started' }));
				const point = v.env.KOI_POINT_ID ?? '';
				await ask(v, { type: 'capture', kind: 'screenshot' }, label);
				const read = await ask(v, { type: 'read', path: '/' }, 'state');
				for (const name of files[point] ?? []) {
					v.out(
						JSON.stringify({
							type: 'assertion',
							point,
							name,
							outcome: 'pass',
							evidence: [`capture:${label}`, read],
						}),
					);
				}
				for (const line of supervisorExit(declaredSteps(v))) v.out(line);
				return 0;
			};
			t.secrets.add('evidence');
			t.secrets.add('home-says-hello');
			const plan = await t.plan(PROFILE);
			const { runId } = await t.run(plan);
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expect(status.points.map((p) => p.outcome)).toEqual(['pass', 'pass']);
			expect(status.outcome).toBe('passed');
			const dir = t.evidence.runDir(runId);
			const text = await readFile(join(dir, 'points/hello.home/observations.json'), 'utf8');
			const observations = JSON.parse(text);
			expect(observations.labels[0]).toEqual({
				name: `${MASK}-shot`,
				artifact: 'recorder:screenshot:1',
			});
			// A declared name is project text, whoever repeats it. A label is the runner's.
			expect(observations.assertions).toEqual(['home-says-hello']);
			expect(observations.asserted[0].assertion).toBe('home-says-hello');
			expect(observations.verdict.outcome).toBe('pass');
			expect(text).not.toContain(label);
		});

		test('a secret learned after a report stays in its observations, and the run ends as it would', async () => {
			const t = await start();
			const secret = 'cited-later-value';
			t.docker.verifierScript = runner(
				declared(POINTS),
				(point) => (point === 'app.search' ? 'fail' : 'pass'),
				() => `saw ${secret}`,
			);
			const plan = await t.plan(PROFILE);
			t.finalizing(() => {
				t.secrets.add(secret);
			});
			const { runId } = await t.run(plan);
			await t.verification.settled(runId);
			const dir = t.evidence.runDir(runId);
			// A record is written once: this one was on disk before koid knew.
			const text = await readFile(join(dir, 'points/app.search/observations.json'), 'utf8');
			expect(JSON.parse(text).asserted[0].detail).toBe(`saw ${secret}`);
			const status = await t.verification.status(runId);
			expect(status.points.map((p) => p.outcome)).toEqual(['pass', 'fail']);
			expect(status.outcome).toBe('failed');
			// No reply says it.
			expect(status.points[1]?.reason).toContain(`saw ${MASK}`);
			expect(JSON.stringify(status)).not.toContain(secret);
		});
	});

	test('a secret a runner cited as evidence or a reason reaches no record of the run', async () => {
		const t = await setup();
		let token = '';
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			token = (v.env.KOI_RECORDER_WS ?? '').split('/').at(-1) ?? '';
			const point = v.env.KOI_POINT_ID ?? '';
			if (point === 'hello.home') {
				v.out(`{"type":"capture","kind":"screenshot","label":"${token}"}`);
				await v.nextLine();
				v.out(
					JSON.stringify({
						type: 'assertion',
						point,
						name: 'home-says-hello',
						outcome: 'pass',
						evidence: [token, `capture:${token}`],
						detail: `saw ${token}`,
					}),
				);
			}
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const { accepted, status } = await t.runToEnd();
		expect(token).toMatch(/^[0-9a-f]{64}$/);
		expect(status.points[0]?.outcome).toBe('fail');
		expect(status.points[0]?.reason).toContain('[redacted]');
		expect(status.points[0]?.reason).not.toContain(token);
		const dir = t.evidence.runDir(accepted.runId);
		for (const file of ['points/hello.home/observations.json', 'controller.json', 'report.md']) {
			const text = await readFile(join(dir, file), 'utf8');
			expect([file, text.includes(token)]).toEqual([file, false]);
		}
		const observations = JSON.parse(
			await readFile(join(dir, 'points/hello.home/observations.json'), 'utf8'),
		) as {
			asserted: Array<{ cited: string[] }>;
			labels: Array<{ name: string; artifact: string }>;
			verdict: { reasons: string[] };
		};
		// The label still made its capture, and the alias reached it.
		expect(observations.asserted[0]?.cited).toEqual(['[redacted]', 'recorder:screenshot:1']);
		expect(observations.labels).toEqual([
			{ name: '[redacted]', artifact: 'recorder:screenshot:1' },
		]);
		expect(observations.verdict.reasons.join(' ')).toContain('references [redacted]');
	});

	test('a step the supervisor stopped at its share blocks the point, and the run goes on', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(supervisorLine({ event: 'started' }));
			if (v.env.KOI_POINT_ID === 'hello.home') {
				const steps = declaredSteps(v).map((s) =>
					s.step === 'run' ? { step: 'run', status: 'timeout', seconds: 270 } : s,
				);
				for (const line of supervisorExit(steps)) v.out(line);
				return 2;
			}
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const { status } = await t.runToEnd();
		expect(status.points[0]?.outcome).toBe('blocked');
		expect(status.points[0]?.reason).toStartWith('point_timeout: the run step reached its share');
		expect(status.points[1]?.state).toBe('done');
	});

	test('a plan with blocked points judges them blocked with the plan reason, without opening them', async () => {
		const t = await setup();
		const { accepted, status } = await t.runToEnd('matrix');
		expect(status.points).toEqual([
			{
				id: 'app.llm',
				state: 'done',
				outcome: 'blocked',
				reason: expect.stringContaining('capability_missing:provider:anthropic'),
				evidence: [],
			},
		]);
		expect(status.completion).toBe('evaluated');
		expect(status.outcome).toBe('incomplete');
		expect(t.recorders.get(accepted.runId)?.calls.filter((c) => c.startsWith('open '))).toEqual([]);
	});

	test('refuses a run when the lease serves another deployment, and gives the lease back', async () => {
		const t = await setup();
		const plan = await t.plan();
		t.deployer.served = { ...t.identity, deploymentId: 'e'.repeat(20) };
		const err = await refusal(t.run(plan));
		expect([err.status, err.code]).toEqual([409, 'deployment_mismatch']);
		expect(err.message).toContain(`serves deployment ${'e'.repeat(20)}`);
		expect(t.calls).toEqual([
			expect.stringMatching(/^lease hello-pr-7 verify:[a-z0-9]{20} 720$/),
			`release ${LABEL} ${'l'.repeat(20)}`,
		]);
		expect(t.record.lease).toBeUndefined();
	});

	test('refuses a stale plan, a refused lease, an unknown plan and an unavailable box', async () => {
		const t = await setup();
		const plan = await t.plan();
		const stale = await refusal(
			t.verification.start({
				version: 1,
				planId: plan.planId,
				planDigest: `sha256:${'0'.repeat(64)}`,
				mode: 'runner',
			}),
		);
		expect([stale.status, stale.code]).toEqual([409, 'plan_stale']);
		const unknown = await refusal(
			t.verification.start({
				version: 1,
				planId: 'z'.repeat(20),
				planDigest: plan.planDigest,
				mode: 'runner',
			}),
		);
		expect([unknown.status, unknown.code]).toEqual([404, 'no_such_plan']);
		t.deployer.leaseError = 'hello-pr-7 is leased by dev@laptop until later';
		const leased = await refusal(t.run(plan));
		expect([leased.status, leased.code]).toEqual([409, 'lease_refused']);
		expect(t.calls.filter((c) => c.startsWith('release'))).toEqual([]);
		const off = await setup({ available: false });
		const offPlan = await off.plan();
		const unavailable = await refusal(off.run(offPlan));
		expect([unavailable.status, unavailable.code]).toEqual([503, 'verification_unavailable']);
		expect(off.calls).toEqual([]);
	});

	test('a plan whose inputs changed since is stale', async () => {
		const t = await setup();
		const plan = await t.plan();
		const point = join(t.evidence.inputsDir(DEPLOYMENT), 'source/.koi/points/home.yaml');
		await writeFile(point, (await readFile(point, 'utf8')).replace('revision: 2', 'revision: 3'));
		const err = await refusal(t.run(plan));
		// The snapshot's own digests no longer match either, which is found first.
		expect(err.status).toBe(409);
		expect(['plan_stale', 'inputs_changed']).toContain(err.code);
	});

	test('the same idempotency key returns the run first started', async () => {
		const t = await setup();
		const plan = await t.plan();
		const body = {
			version: 1 as const,
			planId: plan.planId,
			planDigest: plan.planDigest,
			mode: 'runner' as const,
			idempotencyKey: 'ci-run-42',
		};
		const first = await t.verification.start(body);
		const again = await t.verification.start(body);
		expect(again).toEqual(first);
		await t.verification.settled(first.runId);
		expect(t.calls.filter((c) => c.startsWith('lease '))).toHaveLength(1);
	});

	describe('requests that share an idempotency key', () => {
		const keyed = (plan: PlanReply, idempotencyKey: string) => ({
			version: 1 as const,
			planId: plan.planId,
			planDigest: plan.planDigest,
			mode: 'runner' as const,
			idempotencyKey,
		});
		const leases = (t: Awaited<ReturnType<typeof setup>>) =>
			t.calls.filter((c) => c.startsWith('lease '));
		// Holds each lease at the gate, and refuses a second one as the real
		// deployer does while the first stands.
		const gatedLease = (t: Awaited<ReturnType<typeof setup>>, gate: Gate) => {
			const acquire = t.deployer.acquireLease.bind(t.deployer);
			let held = false;
			t.deployer.acquireLease = async (label, holder, ttlSeconds) => {
				if (held) throw new LeaseError(`${label} is leased`);
				held = true;
				await gate.pass();
				return acquire(label, holder, ttlSeconds).catch((err: unknown) => {
					held = false;
					throw err;
				});
			};
		};

		test('a retry while the first is still being admitted gets its acceptance', async () => {
			const t = await setup();
			const plan = await t.plan();
			const body = keyed(plan, 'ci-run-42');
			const gate = new Gate();
			gatedLease(t, gate);
			const first = t.verification.start(body);
			const concurrent = t.verification.start(body);
			await gate.reached;
			// The first has passed its lookup and awaits, and `accepted` has no key.
			const late = t.verification.start(body);
			gate.release();
			const accepted = await first;
			expect(await concurrent).toEqual(accepted);
			expect(await late).toEqual(accepted);
			await t.verification.settled(accepted.runId);
			expect(leases(t)).toHaveLength(1);
			// Once admitted, the key answers from `accepted` as before.
			expect(await t.verification.start(body)).toEqual(accepted);
			expect(leases(t)).toHaveLength(1);
		});

		test('a first attempt that fails frees its key for a later retry', async () => {
			const t = await setup();
			const plan = await t.plan();
			const body = keyed(plan, 'ci-run-42');
			const gate = new Gate();
			gatedLease(t, gate);
			t.deployer.leaseError = 'hello-pr-7 is leased by dev@laptop until later';
			const first = refusal(t.verification.start(body));
			const waiting = refusal(t.verification.start(body));
			await gate.reached;
			gate.release();
			const failure = await first;
			expect([failure.status, failure.code]).toEqual([409, 'lease_refused']);
			// The one attempt's answer: the retry made no attempt of its own.
			expect(await waiting).toBe(failure);
			expect(leases(t)).toHaveLength(1);
			t.deployer.leaseError = undefined;
			const accepted = await t.verification.start(body);
			expect(leases(t)).toHaveLength(2);
			await t.verification.settled(accepted.runId);
			expect((await t.verification.status(accepted.runId)).finalized).toBe(true);
			expect(await t.verification.start(body)).toEqual(accepted);
			expect(leases(t)).toHaveLength(2);
		});

		test('a first attempt whose first records fail also frees its key', async () => {
			const t = await setup();
			const plan = await t.plan();
			const body = keyed(plan, 'ci-run-42');
			t.failing.writes = new Error('ENOSPC: no space left on device');
			const attempts = [t.verification.start(body), t.verification.start(body)];
			const [first, retry] = await Promise.allSettled(attempts);
			expect(first?.status).toBe('rejected');
			expect(retry?.status).toBe('rejected');
			expect(leases(t)).toHaveLength(1);
			expect(t.calls.filter((c) => c.startsWith('release'))).toHaveLength(1);
			t.failing.writes = undefined;
			const accepted = await t.verification.start(body);
			expect(leases(t)).toHaveLength(2);
			await t.verification.settled(accepted.runId);
			expect((await t.verification.status(accepted.runId)).finalized).toBe(true);
		});

		test('requests with another key or none do not wait for it', async () => {
			const t = await setup();
			const plan = await t.plan();
			const gate = new Gate();
			gatedLease(t, gate);
			const first = t.verification.start(keyed(plan, 'ci-run-42'));
			await gate.reached;
			// Each goes on to its own admission while the first holds the gate.
			const other = await refusal(t.verification.start(keyed(plan, 'ci-run-43')));
			expect([other.status, other.code]).toEqual([409, 'lease_refused']);
			const none = await refusal(t.run(plan));
			expect([none.status, none.code]).toEqual([409, 'lease_refused']);
			gate.release();
			const accepted = await first;
			await t.verification.settled(accepted.runId);
			expect(await t.verification.start(keyed(plan, 'ci-run-42'))).toEqual(accepted);
		});
	});

	describe('what the registry can touch', () => {
		// Every reply a reader can get about a run, as text, whichever route it asks: every
		// page of the status and the events, the evidence, each artifact's bytes, a cancel,
		// and the plan's page.
		const replies = async (api: Verification, runId: string, planId: string) => {
			const out: string[] = [];
			const status = await api.status(runId);
			out.push(JSON.stringify(status), formatStatus(status));
			for (let i = 0; i < status.points.length; i++) {
				out.push(JSON.stringify(await api.status(runId, i)));
			}
			const events = await api.events(runId);
			out.push(JSON.stringify(events));
			const evidence = await api.evidence(runId);
			out.push(JSON.stringify(evidence));
			for (const a of evidence.artifacts.filter((x) => x.availability === 'available')) {
				const chunk = await api.artifact(runId, a.id);
				out.push(JSON.stringify(chunk), Buffer.from(chunk.dataBase64, 'base64').toString());
			}
			out.push(JSON.stringify(await api.cancel(runId)));
			out.push(JSON.stringify(await api.planPage(planId, undefined)));
			return out;
		};

		// The files under a run's folder that hold the value, in any of the forms the
		// registry replaces, or under a name that does.
		const holders = async (t: Awaited<ReturnType<typeof setup>>, runId: string, value: string) => {
			const forms = secretForms(value);
			const dir = t.evidence.runDir(runId);
			const found: string[] = [];
			for (const name of await readdir(dir, { recursive: true })) {
				if (forms.some((form) => name.includes(form))) found.push(name);
				if (!(await stat(join(dir, name))).isFile()) continue;
				const bytes = await readFile(join(dir, name));
				if (forms.some((form) => bytes.includes(form))) found.push(name);
			}
			return found.sort();
		};

		const expectNoReplyHolds = async (
			api: Verification,
			runId: string,
			planId: string,
			value: string,
		) => {
			const forms = secretForms(value);
			for (const reply of await replies(api, runId, planId)) {
				for (const form of forms) expect(reply).not.toContain(form);
			}
		};

		// A run that stops inside its first capture, with what came before it on disk.
		const heldAtCapture = async (t: Awaited<ReturnType<typeof setup>>, plan: PlanReply) => {
			const gate = new Gate();
			t.prepareRecorder((r) => {
				r.captureGate = gate;
			});
			const accepted = await t.run(plan);
			await gate.reached;
			return {
				runId: accepted.runId,
				release: async () => {
					const recorder = t.recorders.get(accepted.runId);
					if (recorder !== undefined) recorder.captureGate = undefined;
					gate.release();
					await t.verification.settled(accepted.runId);
				},
			};
		};

		const recordsOf = async (t: Awaited<ReturnType<typeof setup>>, runId: string) => {
			const dir = t.evidence.runDir(runId);
			const read = (name: string) => readFile(join(dir, name), 'utf8');
			return {
				controller: RunControllerRecordSchema.parse(JSON.parse(await read('controller.json'))),
				manifest: EvidenceManifestSchema.parse(JSON.parse(await read('manifest.json'))),
				result: await read('result.json')
					.then((text) => ResultSchema.parse(JSON.parse(text)))
					.catch(() => undefined),
				report: await read('report.md').catch(() => ''),
				events: await read('events.ndjson'),
			};
		};

		// Each file the manifest names is the bytes it hashed, and so are the events.
		const expectDigestsHold = async (t: Awaited<ReturnType<typeof setup>>, runId: string) => {
			const dir = t.evidence.runDir(runId);
			const { manifest } = await recordsOf(t, runId);
			for (const [name, entry] of Object.entries(manifest.files)) {
				const bytes = await readFile(join(dir, name));
				expect({ name, sha256: entry.sha256, bytes: entry.bytes }).toEqual({
					name,
					sha256: sha(bytes),
					bytes: bytes.length,
				});
			}
			expect(manifest.events.sha256).toBe(sha(await readFile(join(dir, 'events.ndjson'))));
		};

		// The plan and the descriptor each hash to the digest they carry.
		const expectOwnDigests = async (t: Awaited<ReturnType<typeof setup>>, runId: string) => {
			const dir = t.evidence.runDir(runId);
			const plan = PlanSchema.parse(JSON.parse(await readFile(join(dir, 'plan.json'), 'utf8')));
			const { planDigest, ...planRest } = plan;
			expect(canonicalDigest(planRest)).toBe(planDigest);
			const execution = ExecutionDescriptorSchema.parse(
				JSON.parse(await readFile(join(dir, 'execution.json'), 'utf8')),
			);
			const { executionDigest, ...executionRest } = execution;
			expect(canonicalDigest(executionRest)).toBe(executionDigest);
			return { plan, execution };
		};

		const box = (t: Awaited<ReturnType<typeof setup>>): Box => ({
			upload: async () => {},
			ensureAwake: async () => {},
			ctl: async (args): Promise<CtlResult> => {
				const [, what, runId = '', a, b, c] = args;
				const answer = async () => {
					switch (what) {
						case 'status':
							return t.verification.status(runId, a === undefined ? 0 : Number(a));
						case 'evidence':
							return t.verification.evidence(runId, a === undefined ? 0 : Number(a));
						case 'events':
							return t.verification.events(runId, Number(a), Number(b));
						default:
							return t.verification.artifact(runId, a as string, Number(b), Number(c));
					}
				};
				return { code: 0, stdout: JSON.stringify(await answer()), stderr: '' };
			},
		});

		const exported = async (t: Awaited<ReturnType<typeof setup>>, runId: string) => {
			const out = join(t.root, `export-${t.now()}-${Math.random()}`);
			const report = await exportEvidence(runId, out, {
				box: box(t),
				domain: 'previews.example.net',
				progress: () => {},
				probe: async () => ({ status: 200 }),
				sleep: async () => {},
				now: () => new Date(t.now()),
			});
			return { out, report };
		};

		// The project of the next tests: a profile long enough to register, and a page
		// that says the word. Its points are the usual ones.
		const PROFILE = 'pr-checks';
		const project = (): SetupOptions => ({
			manifest: MANIFEST.replace('pr:\n', `${PROFILE}:\n`),
			changed: ['Dockerfile', 'src/search/index.ts', 'docs/redacted.md', 'README.md'],
		});
		const pageSays = (t: Awaited<ReturnType<typeof setup>>, text: string) =>
			t.prepareRecorder((r) => {
				r.onOpen = (pointId) => {
					// As the real recorder does: its event names the point koid told it.
					r.say('context-opened', { contextId: 'x1', pointId, attempt: 1 });
					r.say('console', { level: 'log', text: `the page said ${text}` });
				};
			});

		// What a run decides, whatever anyone registered.
		const decided = (status: RunStatusReply) => ({
			state: status.state,
			completion: status.completion,
			outcome: status.outcome,
			evidence: status.evidence,
			finalized: status.finalized,
			eligible: status.readiness.eligibleForMergeGate,
			points: status.points.map((p) => [p.id, p.state, p.outcome, p.evidence]),
		});

		describe.each<[string, string, 'masked' | 'not registered']>([
			['a directory of runner paths', '.koi/runners', 'masked'],
			['the browser name', 'chromium', 'masked'],
			['the word in the mask', 'redacted', 'not registered'],
			['the mask', '[redacted]', 'not registered'],
			['a point id', 'hello.home', 'masked'],
			['the profile', PROFILE, 'masked'],
			['a declared assertion name', 'home-says-hello', 'masked'],
			['a common word in an error', 'unexpectedly', 'masked'],
		])('registering %s (%s)', (_what, word, effect) => {
			test.each(['before the plan', 'after the plan'])(
				'%s: it plans and runs, ids and digests hold, and only runtime text changes',
				async (when) => {
					const base = await setup(project());
					pageSays(base, word);
					const expected = await base.runToEnd(PROFILE);

					const t = await setup(project());
					pageSays(t, word);
					if (when === 'before the plan') t.secrets.add(word);
					const plan = await t.plan(PROFILE);
					if (when === 'after the plan') t.secrets.add(word);

					// The plan says what the project declares, whatever is registered.
					const { planId: _a, planDigest: _b, createdAt: _c, ...planned } = plan;
					const { planId: _d, planDigest: _e, createdAt: _f, ...baseline } = expected.plan;
					expect(planned).toEqual(baseline);
					expect(plan.profile).toBe(PROFILE);
					expect(plan.uncovered).toEqual(['docs/redacted.md', 'README.md']);
					expect(plan.points[0]?.id).toBe('hello.home');
					expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);

					const accepted = await t.run(plan);
					await t.verification.settled(accepted.runId);
					const status = await t.verification.status(accepted.runId);

					// A registered word can mask text, and cannot change an outcome.
					expect(decided(status)).toEqual(decided(expected.status));
					expect(status.finalized).toBe(true);
					expect(status.profile).toBe(PROFILE);
					expect(status.completion).toBe('evaluated');
					// Being registered blocks no point: each was opened.
					const calls = t.recorders.get(accepted.runId)?.calls ?? [];
					expect(calls.filter((c) => c.startsWith('open '))).toEqual(
						status.points.map((p) => `open ${p.id} 1 /`),
					);

					// The plan is written as it was made, and both digests hold.
					const { plan: stored, execution } = await expectOwnDigests(t, accepted.runId);
					expect(stored.planDigest).toBe(plan.planDigest);
					expect(stored.points[0]?.runners[0]?.path).toBe('.koi/runners/home.sh');
					expect(execution.browser.name).toBe('chromium');
					expect(execution.runnerImage.reference).toBe('curlimages/curl:8.11.1');
					expect(status.executionDigest).toBe(execution.executionDigest);
					await expectDigestsHold(t, accepted.runId);

					// Project text in the run's records stays as the project declared it.
					const { controller, result, report } = await recordsOf(t, accepted.runId);
					expect(controller.profile).toBe(PROFILE);
					expect(controller.points.map((p) => p.id)).toEqual(status.points.map((p) => p.id));
					expect(controller.uncovered).toEqual(['docs/redacted.md', 'README.md']);
					expect(controller.policy.advisory?.path).toBe('.koi/required.yaml');
					expect(result?.points[0]?.id).toBe('hello.home');
					expect(result?.uncovered).toEqual(['docs/redacted.md', 'README.md']);
					expect(report).toContain('| hello.home | pass |');
					expect(report).toContain(`--profile ${PROFILE}`);
					expect(report).toContain('docs/redacted.md');
					const observations = JSON.parse(
						await readFile(
							join(t.evidence.runDir(accepted.runId), 'points/hello.home/observations.json'),
							'utf8',
						),
					);
					expect(observations.pointId).toBe('hello.home');
					expect(observations.assertions).toEqual(['home-says-hello']);

					// An export of a normal run is complete, and it is the bytes on disk.
					const { out, report: exportReport } = await exported(t, accepted.runId);
					expect(exportReport.missing).toEqual([]);
					expect(exportReport.complete).toBe(true);
					expect(await readFile(join(out, 'events.ndjson'))).toEqual(
						await readFile(join(t.evidence.runDir(accepted.runId), 'events.ndjson')),
					);

					// Runtime text is masked, on disk and in a reply. Its envelope still names
					// the point: the recorder's copy of the id goes nowhere.
					const page = await t.verification.events(accepted.runId);
					const said = page.events.filter((e) => e.type === 'console').map((e) => e.text);
					const expectedText =
						effect === 'masked' ? 'the page said [redacted]' : `the page said ${word}`;
					expect(said.length).toBe(status.points.length);
					expect(new Set(said)).toEqual(new Set([expectedText]));
					const opened = page.events.filter((e) => e.type === 'context-opened');
					expect(opened.map((e) => e.pointId)).toEqual(status.points.map((p) => p.id));
					const lines = (await recordsOf(t, accepted.runId)).events.trimEnd().split('\n');
					for (const line of lines) {
						expect(JSON.stringify(EvidenceEventSchema.parse(JSON.parse(line)))).toBe(line);
					}
					const onDisk = lines.map((l) => JSON.parse(l)).filter((e) => e.type === 'console');
					expect(new Set(onDisk.map((e) => e.text))).toEqual(new Set([expectedText]));
				},
			);
		});

		test('a common word in an error is masked there, and the run decides what it would have', async () => {
			const word = 'unexpectedly';
			const failing = (t: Awaited<ReturnType<typeof setup>>) =>
				t.prepareRecorder((r) => {
					r.captureError = new RecorderError(500, 'capture_failed', `crashed ${word} in the page`);
				});
			const base = await setup(project());
			failing(base);
			const expected = await base.runToEnd(PROFILE);

			const t = await setup(project());
			failing(t);
			t.secrets.add(word);
			const { accepted, status } = await t.runToEnd(PROFILE);
			expect(decided(status)).toEqual(decided(expected.status));
			expect(status.completion).toBe('capture-error');
			expect(status.problems.map((p) => p.code)).toContain('capture_failed');
			const detail = status.problems.find((p) => p.code === 'capture_failed')?.detail;
			expect(detail).toContain('crashed [redacted] in the page');
			expect(await holders(t, accepted.runId, word)).toEqual([]);
			await expectDigestsHold(t, accepted.runId);
		});

		test('a required point that did not pass is still not passed, whatever is registered', async () => {
			const t = await setup();
			const plan = await t.plan();
			// The base branch as a policy source does not exist yet, so the plan's record
			// is set to what it will say. One required id is in no plan at all.
			const path = join(t.evidence.planDir(plan.planId), 'planning.json');
			const planning = JSON.parse(await readFile(path, 'utf8'));
			planning.policy = {
				source: 'base-branch',
				advisory: {
					path: '.koi/required.yaml',
					required: [
						{ id: 'hello.home', revision: 2 },
						{ id: 'app.always', revision: 3 },
						{ id: 'absent.point', revision: 1 },
					],
				},
			};
			await writeFile(path, JSON.stringify(planning));
			t.secrets.add('hello.home');
			t.secrets.add('absent.point');
			t.docker.verifierScript = runner(declared(POINTS), (point) =>
				point === 'hello.home' ? 'blocked' : 'pass',
			);
			const accepted = await t.run(plan);
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			// The point ran: being registered no longer blocks it, and its runner did.
			expect(t.recorders.get(accepted.runId)?.calls).toContain('open hello.home 1 /');
			expect(status.points[0]?.id).toBe('hello.home');
			expect(status.points[0]?.outcome).toBe('blocked');
			expect(status.outcome).toBe('incomplete');
			const { reasons, eligibleForMergeGate } = status.readiness;
			expect(eligibleForMergeGate).toBe(false);
			// Judged on the real ids and then masked, as the reasons are runtime text.
			expect(reasons).toContain('required point [redacted] is blocked');
			expect(reasons).toContain('required point [redacted] has no proof at revision 2');
			expect(reasons).toContain('required point app.always has no proof at revision 3');
			expect(reasons).toContain('required point [redacted] was not in the plan');
			// The record still names each required point, so nothing is lost as unjudged.
			const { controller, report } = await recordsOf(t, accepted.runId);
			expect(controller.policy.advisory?.required.map((r) => r.id)).toEqual([
				'hello.home',
				'app.always',
				'absent.point',
			]);
			expect(report).toContain('required point &#91;redacted&#93; is blocked');
		});

		test("a value registered that only a record's own words hold does not break the run", async () => {
			// The keys page registers what a caller sends, so an app can register these.
			const t = await setup();
			const plan = await t.plan();
			for (const value of [
				'evaluated',
				'completed',
				'incomplete',
				'succeeded',
				'recorder',
				'chromium',
				'sanitized',
				'available',
				'point-opened',
				'image/png',
				'text/plain; charset=utf-8',
				'hello.home',
				'.koi/required.yaml',
				plan.planDigest,
				t.identity.imageDigest,
				t.identity.commit,
				t.identity.label,
				'main',
				AT,
			]) {
				t.secrets.add(value);
			}
			const accepted = await t.run(plan);
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.finalized).toBe(true);
			expect(status.completion).toBe('evaluated');
			expect(status.planDigest).toBe(plan.planDigest);
			expect(status.startedAt).toBe(AT);
			const evidence = await t.verification.evidence(accepted.runId);
			expect(evidence.artifacts.length).toBeGreaterThan(0);
			expect(evidence.artifacts[0]?.origin).toBe('recorder');
			expect(evidence.artifacts[0]?.mediaType).toBe('image/png');
			const events = await t.verification.events(accepted.runId);
			expect(events.events.some((e) => e.type === 'point-opened')).toBe(true);
			await expectDigestsHold(t, accepted.runId);
			const { report } = await exported(t, accepted.runId);
			expect(report.complete).toBe(true);
		});

		test('no page or recorder chooses the value of a fixed field, whatever it calls its own', async () => {
			// A value that fills every name a record keeps as it is, and the event's envelope.
			const value = 'Zq81xW0pLmN4vT7yRs2K';
			const fixedNames = [
				'assertion',
				'assertions',
				'baseBranch',
				'id',
				'path',
				'pointId',
				'profile',
				'uncovered',
				'artifact',
				'commit',
				'base',
				'deploymentId',
				'executionDigest',
				'head',
				'idempotencyKey',
				'imageDigest',
				'label',
				'leaseId',
				'planDigest',
				'planId',
				'policyDigest',
				'runId',
				'sha256',
				'capturedAt',
				'checkedAt',
				'expiresAt',
				'finalizedAt',
				'finishedAt',
				'retainedUntil',
				'startedAt',
				'tombstoneUntil',
				'updatedAt',
				'availability',
				'cleanup',
				'code',
				'completion',
				'evidence',
				'freshness',
				'kind',
				'mediaType',
				'origin',
				'outcome',
				'source',
				'state',
				'status',
				'stopped',
				'attempt',
				'at',
				'seq',
				'type',
			];
			const t = await setup();
			t.secrets.add(value);
			t.prepareRecorder((r) => {
				r.openUrl = `http://app.invalid/${value}`;
				r.onOpen = () => {
					const fields = Object.fromEntries(fixedNames.map((name) => [name, value]));
					const { seq: _seq, at: _at, type: _type, ...rest } = fields;
					r.say('console', { ...rest, [value]: value, nested: { ...rest } });
				};
			});
			const { accepted, plan } = await t.runToEnd();
			// Scrubbed wherever it went. A fixed field that took it would still hold it.
			expect(await holders(t, accepted.runId, value)).toEqual([]);
			await expectNoReplyHolds(t.verification, accepted.runId, plan.planId, value);
			// The envelope is koid's: the point it opened, and the source it read from.
			const { events } = await t.verification.events(accepted.runId);
			const said = events.filter((e) => e.type === 'console');
			expect(said.map((e) => [e.source, e.pointId, e.attempt])[0]).toEqual([
				'recorder',
				'hello.home',
				1,
			]);
			expect(said[0]?.label).toBe('[redacted]');
			expect(said[0]?.['[redacted]']).toBe('[redacted]');
			await expectDigestsHold(t, accepted.runId);
		});

		describe('the search for a runtime secret, by when koid learns it', () => {
			// A value no pattern finds, so only the registry can mask it.
			const LEAK = 'Zq81xW0pLmN4vT7yRs2K';

			// A run where a page, an event, an error and an interruption all say LEAK: the page
			// prints it, the point-opened event carries it in its URL, the first capture's
			// error quotes it, and the lease is lost in words that hold it. The second capture
			// waits on `gate`, so what came before it is on disk by then.
			const saying = (t: Awaited<ReturnType<typeof setup>>) => {
				const gate = new Gate();
				let held = true;
				t.prepareRecorder((r) => {
					r.openUrl = `http://app.invalid/?ref=${LEAK}`;
					r.onOpen = () => r.say('console', { text: `the page printed ${LEAK}` });
					const capture = r.capture.bind(r);
					let captures = 0;
					r.capture = async (contextId, request, options) => {
						captures += 1;
						if (captures === 1) {
							throw new RecorderError(500, 'capture_failed', `the page crashed on ${LEAK}`);
						}
						if (captures === 2 && held) await gate.pass();
						return capture(contextId, request, options);
					};
				});
				const { leasedDeployment } = t.deployer;
				let looks = 0;
				t.deployer.leasedDeployment = async function (label: string, leaseId: string) {
					looks += 1;
					// At admission, as the run starts, before the first point, then the next point.
					if (looks === 4) throw new NoSuchLeaseError(`the lease went with ${LEAK}`);
					return leasedDeployment.call(this, label, leaseId);
				};
				return {
					gate,
					open: () => {
						held = false;
						gate.release();
					},
				};
			};

			const expectAllSaid = async (t: Awaited<ReturnType<typeof setup>>, runId: string) => {
				const status = await t.verification.status(runId);
				expect(status.interruption).toContain('lease_lost: the lease went with [redacted]');
				expect(status.problems.find((p) => p.code === 'capture_failed')?.detail).toContain(
					'the page crashed on [redacted]',
				);
				const { events } = await t.verification.events(runId);
				expect(events.find((e) => e.type === 'console')?.text).toBe('the page printed [redacted]');
				expect(events.find((e) => e.type === 'point-opened')?.url).toBe(
					'http://app.invalid/?ref=[redacted]',
				);
				expect(events.find((e) => e.type === 'capture-failed')?.reason).toContain('[redacted]');
			};

			test('with no secret known, it is said everywhere: the search finds what it looks for', async () => {
				const t = await setup();
				const { open } = saying(t);
				open();
				const { accepted } = await t.runToEnd();
				const found = await holders(t, accepted.runId, LEAK);
				expect(found).toContain('events.ndjson');
				expect(found).toContain('controller.json');
				expect(found).toContain('status.json');
				expect(found).toContain('manifest.json');
			});

			test('learned before the run: no file and no reply holds it', async () => {
				const t = await setup();
				const plan = await t.plan();
				const { open } = saying(t);
				t.secrets.add(LEAK);
				open();
				const accepted = await t.run(plan);
				await t.verification.settled(accepted.runId);
				expect(await holders(t, accepted.runId, LEAK)).toEqual([]);
				await expectNoReplyHolds(t.verification, accepted.runId, plan.planId, LEAK);
				await expectAllSaid(t, accepted.runId);
				await expectDigestsHold(t, accepted.runId);
				// Nothing differs from what the manifest hashed, so the events export as they are.
				const { report } = await exported(t, accepted.runId);
				expect(report.missing.filter((m) => m.startsWith('events'))).toEqual([]);
			});

			test('learned during a capture: only what was written before it holds it, and no reply does', async () => {
				const t = await setup();
				const plan = await t.plan();
				const { gate, open } = saying(t);
				const accepted = await t.run(plan);
				await gate.reached;
				t.secrets.add(LEAK);
				// A reply made now, with the run still going, masks what the disk holds.
				const live = await t.verification.status(accepted.runId);
				expect(live.state).toBe('running');
				expect(JSON.stringify(live)).not.toContain(LEAK);
				const before = await holders(t, accepted.runId, LEAK);
				expect(before).toContain('events.ndjson');
				expect(before).toContain('status.json');
				open();
				await t.verification.settled(accepted.runId);
				// The events were appended before koid knew, and an event is never rewritten.
				// status.json is written again as it changes, and that write scrubs it.
				expect(await holders(t, accepted.runId, LEAK)).toEqual(['events.ndjson']);
				await expectNoReplyHolds(t.verification, accepted.runId, plan.planId, LEAK);
				await expectAllSaid(t, accepted.runId);
				await expectDigestsHold(t, accepted.runId);
				// The reply's events are not the bytes on disk, and the export says so.
				const { report } = await exported(t, accepted.runId);
				expect(report.complete).toBe(false);
				expect(report.missing.join('\n')).toContain('events: the ');
				expect(report.missing.join('\n')).toContain('and the manifest says sha256:');
			});

			test('learned during finalization: the records already written hold it, the manifest does not, and no reply does', async () => {
				const t = await setup();
				const plan = await t.plan();
				const { open } = saying(t);
				open();
				t.finalizing(async (runId) => {
					t.secrets.add(LEAK);
					const live = await t.verification.status(runId);
					expect(JSON.stringify(live)).not.toContain(LEAK);
				});
				const accepted = await t.run(plan);
				await t.verification.settled(accepted.runId);
				const status = await t.verification.status(accepted.runId);
				expect(status.finalized).toBe(true);
				// Written once and left: controller.json, the report and the events. status.json
				// and the manifest are written after, so they are scrubbed.
				expect(await holders(t, accepted.runId, LEAK)).toEqual([
					'controller.json',
					'events.ndjson',
					'report.md',
				]);
				await expectNoReplyHolds(t.verification, accepted.runId, plan.planId, LEAK);
				await expectAllSaid(t, accepted.runId);
				// Nothing was rewritten, so every digest is over the bytes on disk.
				await expectDigestsHold(t, accepted.runId);
				const { report } = await exported(t, accepted.runId);
				expect(report.complete).toBe(false);
				expect(report.missing.join('\n')).toContain('and the manifest says sha256:');
			});

			test('learned as a record is about to be written: that record does not hold it', async () => {
				const t = await setup();
				const plan = await t.plan();
				const { open } = saying(t);
				open();
				t.writing((name) => {
					if (name === 'report.md') t.secrets.add(LEAK);
				});
				const accepted = await t.run(plan);
				await t.verification.settled(accepted.runId);
				expect(await holders(t, accepted.runId, LEAK)).toEqual(['events.ndjson']);
				await expectDigestsHold(t, accepted.runId);
				await expectNoReplyHolds(t.verification, accepted.runId, plan.planId, LEAK);
			});

			test('learned as result.json is written: no part of the report holds it', async () => {
				// A service name only the registry can mask, in a reason the run carries.
				const word = 'zq81xw0plmn4vt7yrs2k';
				const t = await setup({
					files: {
						...POINTS,
						'llm.yaml': (POINTS['llm.yaml'] as string).replace(
							'services: [chat]',
							`services: [${word}]`,
						),
					},
				});
				const plan = await t.plan('matrix');
				expect(plan.blocked[0]?.reason).toContain(word);
				t.writing((name) => {
					if (name === 'result.json') t.secrets.add(word);
				});
				const accepted = await t.run(plan);
				await t.verification.settled(accepted.runId);
				const { report, result } = await recordsOf(t, accepted.runId);
				// Written before it was learned, so this one shows the test's timing is right.
				expect(result).toBeDefined();
				expect(report).not.toContain(word);
				const reasons = report.slice(report.indexOf('## Point reasons'));
				expect(reasons).toContain('- app.llm: ');
				expect(reasons).toContain('capability_missing:services:&#91;redacted&#93;');
			});

			test('learned through recovery: the records recovery ends are scrubbed, the events stay, and no reply holds it', async () => {
				const t = await setup();
				const plan = await t.plan();
				const { gate, open } = saying(t);
				const accepted = await t.run(plan);
				await gate.reached;
				// As a crash leaves it: a point open, and its files written before koid knew.
				t.secrets.add(LEAK);
				const before = await holders(t, accepted.runId, LEAK);
				expect(before).toContain('events.ndjson');
				expect(before).toContain('status.json');
				const next = t.restarted();
				expect(await next.recover({ releaseLeases: false })).toEqual([accepted.runId]);
				expect(await holders(t, accepted.runId, LEAK)).toEqual(['events.ndjson']);
				const status = await next.status(accepted.runId);
				expect(status.completion).toBe('interrupted');
				expect(status.outcome).toBe('incomplete');
				expect(status.finalized).toBe(false);
				expect(status.problems.find((p) => p.code === 'capture_failed')?.detail).toContain(
					'[redacted]',
				);
				await expectNoReplyHolds(next, accepted.runId, plan.planId, LEAK);
				const { events } = await next.events(accepted.runId);
				expect(events.find((e) => e.type === 'console')?.text).toBe('the page printed [redacted]');
				open();
				await t.verification.settled(accepted.runId).catch(() => {});
			});

			test('learned once the bundle is finalized: the bundle stays as hashed, and no reply holds it', async () => {
				const t = await setup();
				const plan = await t.plan();
				const { open } = saying(t);
				open();
				const accepted = await t.run(plan);
				await t.verification.settled(accepted.runId);
				const manifest = await t.evidence.readManifest(accepted.runId);
				const found = await holders(t, accepted.runId, LEAK);
				expect(found).toContain('manifest.json');
				const dir = t.evidence.runDir(accepted.runId);
				const before = await readFile(join(dir, 'controller.json'), 'utf8');
				t.secrets.add(LEAK);
				// Ask a new koid too: nothing it holds in memory helps it.
				for (const api of [t.verification, t.restarted()]) {
					await expectNoReplyHolds(api, accepted.runId, plan.planId, LEAK);
					expect((await api.status(accepted.runId)).finalized).toBe(true);
				}
				// Every file as it was, which is the documented limit until retention ends.
				expect(await holders(t, accepted.runId, LEAK)).toEqual(found);
				expect(await readFile(join(dir, 'controller.json'), 'utf8')).toBe(before);
				expect(await t.evidence.readManifest(accepted.runId)).toEqual(manifest);
				await expectDigestsHold(t, accepted.runId);
			});
		});

		test('an artifact keeps its bytes when koid learns a secret after the capture, and its reply returns them', async () => {
			// The one reply that is not masked: its bytes must hash to the manifest.
			const leak = 'Zq81xW0pLmN4vT7yRs2K';
			const t = await setup();
			t.prepareRecorder((r) => {
				r.ariaText = `heading "${leak}"\n`;
			});
			const { accepted } = await t.runToEnd();
			t.secrets.add(leak);
			const evidence = await t.verification.evidence(accepted.runId);
			const aria = evidence.artifacts.find((a) => a.kind === 'aria' && a.pointId === 'hello.home');
			const chunk = await t.verification.artifact(accepted.runId, aria?.id as string);
			const bytes = Buffer.from(chunk.dataBase64, 'base64');
			expect(bytes.toString()).toContain(leak);
			expect(sha(bytes)).toBe(chunk.sha256);
			expect(chunk.sha256).toBe(aria?.sha256 as string);
			const { report } = await exported(t, accepted.runId);
			expect(report.artifacts.every((a) => a.verified)).toBe(true);
		});

		describe('a read', () => {
			test('of a run with no manifest writes nothing, and masks what it returns', async () => {
				const t = await setup();
				const plan = await t.plan();
				const { runId, release } = await heldAtCapture(t, plan);
				const next = t.restarted();
				expect(await next.recover({ releaseLeases: false })).toEqual([runId]);
				const dir = t.evidence.runDir(runId);
				const before = await readFile(join(dir, 'controller.json'), 'utf8');
				const statusBefore = await readFile(join(dir, 'status.json'), 'utf8');
				// A word the record holds in its runtime text.
				t.secrets.add('koid_restarted');
				const status = await next.status(runId);
				expect(status.interruption).toContain('[redacted]');
				expect(status.points[2]?.id).toBe('app.search');
				expect(await readFile(join(dir, 'controller.json'), 'utf8')).toBe(before);
				expect(await readFile(join(dir, 'status.json'), 'utf8')).toBe(statusBefore);
				await release();
			});

			test('of a live run writes nothing either, and costs the reader nothing when the disk is full', async () => {
				const t = await setup();
				const plan = await t.plan();
				const { runId, release } = await heldAtCapture(t, plan);
				const dir = t.evidence.runDir(runId);
				const before = await readFile(join(dir, 'controller.json'), 'utf8');
				t.secrets.add('app.search');
				t.failing.writes = new Error('ENOSPC: no space left on device');
				const live = await t.verification.status(runId);
				expect(live.points[2]?.id).toBe('app.search');
				expect(await readFile(join(dir, 'controller.json'), 'utf8')).toBe(before);
				t.failing.writes = undefined;
				await release();
				expect(await t.evidence.readManifest(runId)).toBeDefined();
			});

			test('of a plan page answers as ever, whatever koid learns, and a run of it still runs', async () => {
				const t = await setup();
				const plan = await t.plan();
				// In a point id, a changed file's name and the plan's text.
				expect(plan.uncovered).toEqual(['README.md']);
				t.secrets.add('README.md');
				t.secrets.add('hello.home');
				expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);
				const accepted = await t.run(plan);
				await t.verification.settled(accepted.runId);
				const status = await t.verification.status(accepted.runId);
				expect(status.finalized).toBe(true);
				expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);
				const dir = t.evidence.runDir(accepted.runId);
				expect((await stat(join(dir, 'plan.json'))).isFile()).toBe(true);
				const { manifest } = await recordsOf(t, accepted.runId);
				expect(manifest.files['plan.json']).toBeDefined();
			});

			test('a plan that never was still answers no_such_plan', async () => {
				const t = await setup();
				const page = await refusal(t.verification.planPage('n'.repeat(20), undefined));
				expect([page.status, page.code]).toEqual([404, 'no_such_plan']);
			});
		});

		test('a retried request gets its acceptance as it was, whatever koid learned', async () => {
			const t = await setup({ baseBranch: 'release-candidate' });
			const plan = await t.plan();
			const ask = () =>
				t.verification.start({
					version: 1,
					planId: plan.planId,
					planDigest: plan.planDigest,
					mode: 'runner',
					idempotencyKey: 'retry-key-1',
				});
			const first = await ask();
			t.secrets.add('release-candidate');
			const again = await ask();
			expect(again).toEqual(first);
			expect(again.deployment.merge?.baseBranch).toBe('release-candidate');
			await t.verification.settled(first.runId);
			// A base branch is compared as it is, so the deployment is still this one.
			expect((await t.verification.status(first.runId)).freshness).toBe('current');
		});

		test('a run the last koid left comes back with its ids and its other records as written', async () => {
			const t = await setup();
			const plan = await t.plan();
			const runId = 'q'.repeat(20);
			const writer = await t.evidence.openRun(runId, { deployment: t.identity });
			const lease = await t.deployer.acquireLease(LABEL, runLeaseHolder(runId), 720);
			const secret = 'private-value-1234';
			const reason = `the recorder said ${secret}`;
			await writer.addProblem('capture_failed', `aria ${secret}: failed`);
			await writer.writeReport(() => `# stale, naming ${secret}\n`);
			await writer.writeRecord('result.json', { reason: secret });
			await writer.writeObservations('hello.home', { reason: secret });
			await writer.writeRecord(
				'controller.json',
				RunControllerRecordSchema.parse({
					version: 1,
					runId,
					planId: plan.planId,
					planDigest: plan.planDigest,
					label: LABEL,
					deployment: t.identity,
					profile: 'pr',
					advisory: false,
					state: 'running',
					cancelRequested: false,
					points: [
						{ id: 'hello.home', state: 'done', outcome: 'blocked', reason, evidence: [] },
						{ id: 'app.always', state: 'running', evidence: [] },
					],
					uncovered: ['docs/private-value-1234.md'],
					policy: { source: 'none', advisory: { path: 'x', required: [], error: secret } },
					limits: plan.limits,
					lease: { leaseId: lease.lease.leaseId, expiresAt: lease.lease.expiresAt },
					readiness: { eligibleForMergeGate: false, reasons: [`waiting on ${secret}`] },
					freshness: 'unknown',
					cleanup: 'unknown',
					startedAt: AT,
					updatedAt: AT,
				}),
			);
			await writer.abandon();
			t.secrets.add(secret);
			const next = t.restarted();
			expect(await next.recover({ releaseLeases: true })).toEqual([runId]);
			const status = await next.status(runId);
			expect(status.points.map((p) => [p.id, p.state, p.outcome])).toEqual([
				['hello.home', 'done', 'blocked'],
				['app.always', 'pending', undefined],
			]);
			expect(status.points[0]?.reason).toBe('the recorder said [redacted]');
			const dir = t.evidence.runDir(runId);
			const stored = RunControllerRecordSchema.parse(
				JSON.parse(await readFile(join(dir, 'controller.json'), 'utf8')),
			);
			// Recovery wrote this one, as it must, and the write scrubbed its runtime text.
			expect(stored.points[0]?.reason).toBe('the recorder said [redacted]');
			expect(stored.policy.advisory?.error).toBe('[redacted]');
			expect(stored.readiness.reasons.join()).not.toContain(secret);
			// A changed file's name is project text: it stays as the pull request has it.
			expect(stored.uncovered).toEqual(['docs/private-value-1234.md']);
			// It wrote no other record for what it learned: they stay until retention ends.
			expect(await readFile(join(dir, 'report.md'), 'utf8')).toContain(secret);
			expect(await holders(t, runId, secret)).toEqual([
				'controller.json',
				'points/hello.home/observations.json',
				'report.md',
				'result.json',
			]);
			// A later koid finds nothing to do, and the record stays as it was left.
			const third = t.restarted();
			expect(await third.recover({ releaseLeases: true })).toEqual([]);
			expect((await third.status(runId)).points[1]?.id).toBe('app.always');
		});

		describe('a passing point and a failing one, whatever is registered', () => {
			const FAILURE = 'expected the heading to show';
			// Each word is also what the runner says, so each reading shows whether it was masked.
			const saying = (word: string) =>
				runner(
					declared(POINTS),
					(point) => (point === 'app.search' ? 'fail' : 'pass'),
					(name) => `${name === 'finds' ? FAILURE : 'it shows'} as ${word} says`,
				);
			const ids = ['hello.home', 'app.always', 'app.search'];

			describe.each<[string, string, boolean]>([
				['a word of the records', 'evidence', true],
				['another word of the records', 'assertion', true],
				["the passing point's id", 'hello.home', true],
				["the failing point's id", 'app.search', true],
				['the profile', PROFILE, true],
				['a declared assertion name', 'home-says-hello', true],
				['a part of an artifact id', 'screenshot', true],
				['the other part of an artifact id', 'recorder', true],
				['the browser name', 'chromium', true],
				['the word in the mask, which the registry ignores', 'redacted', false],
				['a common word in the failure text', 'expected', true],
			])('registering %s (%s)', (_what, word, masked) => {
				test.each(['before', 'during'] as const)('%s the run', async (when) => {
					const base = await setup(project());
					base.docker.verifierScript = saying(word);
					const expected = await base.runToEnd(PROFILE);

					const t = await setup(project());
					t.docker.verifierScript = saying(word);
					if (when === 'before') t.secrets.add(word);
					const plan = await t.plan(PROFILE);
					const gate = new Gate();
					if (when === 'during') {
						t.prepareRecorder((r) => {
							r.captureGate = gate;
						});
					}
					const { runId } = await t.run(plan);
					if (when === 'during') {
						// The first capture of the first point, so every report comes after it.
						await gate.reached;
						t.secrets.add(word);
						const recorder = t.recorders.get(runId);
						if (recorder !== undefined) recorder.captureGate = undefined;
						gate.release();
					}
					await t.verification.settled(runId);
					const status = await t.verification.status(runId);

					// Outcomes stay right, and every point ran with a verifier of its own.
					expect(decided(status)).toEqual(decided(expected.status));
					expect(status.points.map((p) => [p.id, p.outcome])).toEqual([
						['hello.home', 'pass'],
						['app.always', 'pass'],
						['app.search', 'fail'],
					]);
					expect(status.completion).toBe('evaluated');
					expect(status.outcome).toBe('failed');
					expect(status.finalized).toBe(true);
					expect(status.problemCount).toBe(0);
					expect(t.docker.verifiers.map((v) => v.env.KOI_POINT_ID)).toEqual(ids);
					expect(status.points[0]?.evidence).toEqual([
						'recorder:screenshot:1',
						'recorder:aria:2',
						'recorder:http-response:3',
					]);

					// The run stays readable: every record through its schema, and the digests hold.
					const { plan: stored, execution } = await expectOwnDigests(t, runId);
					expect(stored.planDigest).toBe(plan.planDigest);
					expect(status.executionDigest).toBe(execution.executionDigest);
					await expectDigestsHold(t, runId);
					const { controller, result, report, events } = await recordsOf(t, runId);
					for (const line of events.trimEnd().split('\n')) {
						EvidenceEventSchema.parse(JSON.parse(line));
					}
					await replies(t.verification, runId, plan.planId);
					if (when === 'before') {
						expect((await exported(t, runId)).report.complete).toBe(true);
					}

					// Project text and koid's own values stay as they are.
					const observed = async (id: string) =>
						JSON.parse(
							await readFile(
								join(t.evidence.runDir(runId), `points/${id}/observations.json`),
								'utf8',
							),
						);
					const passing = await observed('hello.home');
					const failing = await observed('app.search');
					expect(status.profile).toBe(PROFILE);
					expect(controller.profile).toBe(PROFILE);
					expect(controller.points.map((p) => p.id)).toEqual(ids);
					expect(result?.points.map((p) => p.id)).toEqual(ids);
					expect(execution.browser.name).toBe('chromium');
					expect(execution.runnerImage.reference).toBe('curlimages/curl:8.11.1');
					expect(stored.points[0]?.runners[0]?.path).toBe('.koi/runners/home.sh');
					expect(report).toContain('| hello.home | pass |');
					expect(report).toContain(`--profile ${PROFILE}`);
					expect(passing.pointId).toBe('hello.home');
					expect(passing.assertions).toEqual(['home-says-hello']);
					expect(passing.asserted[0].assertion).toBe('home-says-hello');
					expect(passing.labels[0]).toEqual({ name: 'shot', artifact: 'recorder:screenshot:1' });
					expect(passing.verdict.evidence).toEqual(status.points[0]?.evidence);
					const { events: pages } = await t.verification.events(runId);
					expect(pages.find((e) => e.type === 'point-opened')?.pointId).toBe('hello.home');

					// Runtime text is masked, and only that.
					const assertion = pages.find(
						(e) => e.type === 'runner-assertion' && e.pointId === 'app.search',
					);
					const said = [
						status.points[2]?.reason,
						controller.points[2]?.reason,
						result?.points[2]?.reason,
						failing.asserted[0].detail,
						failing.verdict.reasons.join(' '),
						assertion?.detail as string,
					];
					for (const text of said) {
						if (masked) {
							expect(text).toContain('[redacted] says');
							expect(text).not.toContain(word);
						} else {
							expect(text).toContain(`as ${word} says`);
						}
					}
					expect(report).toContain('## Point reasons');
					if (masked)
						expect(report.slice(report.indexOf('## Point reasons'))).not.toContain(`as ${word}`);

					// A failing assertion never reads as passed, in any of them.
					expect(
						failing.asserted.map((r: { assertion: string; outcome: string }) => [
							r.assertion,
							r.outcome,
						]),
					).toEqual([['finds', 'fail']]);
					expect(failing.verdict.outcome).toBe('fail');
					expect(assertion?.outcome).toBe('fail');
					expect(controller.outcome).toBe('failed');
					expect(result?.outcome).toBe('failed');
					expect(result?.points[2]?.outcome).toBe('fail');
					expect(report).toContain('## koi verification: failed');
					expect(report).toContain('| app.search | fail |');
					expect(report).not.toContain('| app.search | pass');
					expect(formatStatus(status)).toContain('  app.search  fail');
					expect(formatStatus(status)).not.toContain('  app.search  pass');
				});
			});
		});

		test('a runner that names a known secret in each thing it can say leaves it in no file and no reply', async () => {
			// Shaped as a slug, so the protocol reads it as a name and a label. No pattern finds it.
			const secret = 'zq81xw0plmn4vt7yrs2k';
			const t = await setup(project());
			t.secrets.add(secret);
			const assertions = declared(POINTS);
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(supervisorLine({ event: 'started' }));
				const point = v.env.KOI_POINT_ID ?? '';
				v.out(`a log line that says ${secret}`);
				v.err(`a stderr line that says ${secret}`);
				v.out(JSON.stringify({ type: 'note', text: `a note that says ${secret}` }));
				v.out(
					JSON.stringify({ type: 'assertion', point, name: secret, outcome: 'pass', evidence: [] }),
				);
				await ask(v, { type: 'capture', kind: 'screenshot' }, secret);
				const tree = await ask(v, { type: 'capture', kind: 'aria' }, 'tree');
				const state = await ask(v, { type: 'read', path: `/?q=${secret}` }, `read-${secret}`);
				for (const name of assertions[point] ?? []) {
					v.out(
						JSON.stringify({
							type: 'assertion',
							point,
							name,
							outcome: 'pass',
							// The label's alias reaches its capture. A reference to nothing fails the
							// point it is in.
							evidence: [
								`capture:${secret}`,
								tree,
								state,
								...(point === 'app.search' ? [secret] : []),
							],
							detail: `a detail that says ${secret}`,
						}),
					);
				}
				for (const line of supervisorExit(declaredSteps(v))) v.out(line);
				return 0;
			};
			const { accepted, plan, status } = await t.runToEnd(PROFILE);
			const { runId } = accepted;

			// It was all read, and said with the value masked.
			expect(status.points.map((p) => [p.id, p.outcome])).toEqual([
				['hello.home', 'pass'],
				['app.always', 'pass'],
				['app.search', 'fail'],
			]);
			expect(status.points[2]?.reason).toContain('references [redacted]');
			const { events } = await t.verification.events(runId);
			const texts = events.map((e) => JSON.stringify(e)).join('\n');
			for (const line of [
				'a log line that says [redacted]',
				'a stderr line that says [redacted]',
				'a note that says [redacted]',
				'an assertion [redacted] the point does not declare',
				'a detail that says [redacted]',
			]) {
				expect(texts).toContain(line);
			}
			const observations = JSON.parse(
				await readFile(
					join(t.evidence.runDir(runId), 'points/app.search/observations.json'),
					'utf8',
				),
			);
			expect(observations.labels[0]).toEqual({
				name: '[redacted]',
				artifact: expect.stringMatching(/^recorder:screenshot:/),
			});
			expect(observations.asserted[0].cited.at(-1)).toBe('[redacted]');
			expect(observations.asserted[0].detail).toBe('a detail that says [redacted]');

			expect(await holders(t, runId, secret)).toEqual([]);
			await expectNoReplyHolds(t.verification, runId, plan.planId, secret);
			await expectDigestsHold(t, runId);
		});

		describe('a runner image that cannot run', () => {
			// Docker's list of what an image sets. The image is the operator's, and its text is
			// still what Docker says.
			const declaring = (t: Awaited<ReturnType<typeof setup>>, name: string) =>
				t.docker.imageInfos.set('curlimages/curl:8.11.1', {
					id: CURL_IMAGE,
					env: ['PATH=/usr/bin', `${name}=1`],
				});
			const NAME = 'ZQ81XW0PLMN4VT7Y';

			test('is said with what koid knows masked, before the digest and in every reply', async () => {
				const t = await setup();
				declaring(t, NAME);
				t.secrets.add(NAME);
				const plan = await t.plan();
				expect(plan.points).toEqual([]);
				const reason = plan.blocked[0]?.reason;
				expect(reason).toStartWith('image_env_not_allowed: curlimages/curl:8.11.1 declares ');
				expect(reason).toContain('[redacted]');
				const stored = await readFile(join(t.evidence.planDir(plan.planId), 'plan.json'), 'utf8');
				expect(stored).not.toContain(NAME);
				expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);
			});

			test('learned after the plan: the plan stays as its digest says, and a reply masks it', async () => {
				const t = await setup();
				declaring(t, NAME);
				const plan = await t.plan();
				expect(plan.blocked[0]?.reason).toContain(NAME);
				t.secrets.add(NAME);
				const page = await t.verification.planPage(plan.planId, undefined);
				expect(JSON.stringify(page)).not.toContain(NAME);
				expect(page.blocked.map((b) => b.id)).toEqual(plan.blocked.map((b) => b.id));
				expect(page.planDigest).toBe(plan.planDigest);
				const accepted = await t.run(plan);
				await t.verification.settled(accepted.runId);
				const { plan: stored } = await expectOwnDigests(t, accepted.runId);
				expect(stored.planDigest).toBe(plan.planDigest);
				expect(stored.blocked[0]?.reason).toContain(NAME);
				const status = await t.verification.status(accepted.runId);
				expect(status.points[0]?.outcome).toBe('blocked');
				expect(JSON.stringify(status)).not.toContain(NAME);
			});
		});

		describe('what the recorder says of itself', () => {
			test.each([
				['a sentence', 'see token=abc123 for details'],
				['a line break', '142.0\nforged'],
				['too long a value', 'a'.repeat(101)],
			])(
				'as a version, %s stops the run before execution.json is written',
				async (_what, version) => {
					const t = await setup();
					t.prepareRecorder((r) => {
						const health = r.health.bind(r);
						r.health = async () => {
							const answer = await health();
							return answer.ok ? { ...answer, browser: { ...answer.browser, version } } : answer;
						};
					});
					const { accepted, status } = await t.runToEnd();
					expect(status.completion).toBe('interrupted');
					expect(status.outcome).toBe('incomplete');
					expect(status.interruption).toStartWith('run_failed: ');
					const dir = t.evidence.runDir(accepted.runId);
					expect(await stat(join(dir, 'execution.json')).catch(() => undefined)).toBeUndefined();
					expect(t.docker.verifiers).toEqual([]);
				},
			);

			test('an origin that is not the address koid gave it stops the run the same way', async () => {
				const t = await setup();
				t.prepareRecorder((r) => {
					const health = r.health.bind(r);
					r.health = async () => {
						const answer = await health();
						return answer.ok ? { ...answer, origin: 'http://app.invalid/?said=something' } : answer;
					};
				});
				const { accepted, status } = await t.runToEnd();
				expect(status.completion).toBe('interrupted');
				expect(status.interruption).toContain('recorder_mismatch');
				expect(status.problems.map((p) => p.code)).toContain('recorder_mismatch');
				const dir = t.evidence.runDir(accepted.runId);
				expect(await stat(join(dir, 'execution.json')).catch(() => undefined)).toBeUndefined();
				expect(await holders(t, accepted.runId, 'said=something')).toEqual([]);
			});

			test('a version that fits is written as it came, whatever is registered, and masked in its event', async () => {
				const t = await setup();
				t.secrets.add('142.0.7444.52');
				const { accepted, status } = await t.runToEnd();
				expect(status.completion).toBe('evaluated');
				const { execution } = await expectOwnDigests(t, accepted.runId);
				expect(execution.browser.version).toBe('142.0.7444.52');
				const { events } = await t.verification.events(accepted.runId);
				expect(events.find((e) => e.type === 'recorder-ready')?.browser).toBe('[redacted]');
			});
		});

		describe('what a hostile runner says, on its way to a terminal', () => {
			// Erases the screen, writes to the clipboard, starts a section of the report, and
			// turns the text around.
			const HOSTILE = 'bad\x1b[2J\x1b]52;c;QUJD\x07\n## forged section\r\u2028\u202e\x9b1m end';
			const CONTROL = /[\p{Cc}\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;

			const runIt = async () => {
				const t = await setup();
				const script = runner(
					declared(POINTS),
					() => 'fail',
					() => HOSTILE,
				);
				t.docker.verifierScript = async (v) => {
					v.out(JSON.stringify({ type: 'note', text: HOSTILE }));
					return script(v);
				};
				return { t, ...(await t.runToEnd()) };
			};

			const expectSafe = (text: string) => {
				for (const line of text.split('\n')) {
					expect(line).not.toMatch(CONTROL);
					expect(line).not.toStartWith('## forged');
				}
			};

			test('koi verify status shows each control character as an escape', async () => {
				const { status } = await runIt();
				// It reached the reply as the runner sent it: --json is for a program.
				expect(status.points[0]?.reason).toContain(HOSTILE);
				const text = formatStatus(status);
				expectSafe(text);
				expect(text).toContain('bad\\x1b[2J\\x1b]52;c;QUJD\\x07\\x0a## forged section\\x0d');
				expect(text).toContain('\\u2028\\u202e\\x9b1m end');
			});

			test('report.md shows them the same way', async () => {
				const { t, accepted } = await runIt();
				const { report } = await recordsOf(t, accepted.runId);
				expectSafe(report);
				expect(report).toContain('\\x1b');
				expect(report).toContain('\\x0a');
			});

			test('a note stays in the events, which a program reads, and neither of those shows it', async () => {
				const t = await setup();
				const script = runner(declared(POINTS));
				t.docker.verifierScript = async (v) => {
					v.out(JSON.stringify({ type: 'note', text: HOSTILE }));
					return script(v);
				};
				const { accepted, status } = await t.runToEnd();
				const { events } = await t.verification.events(accepted.runId);
				expect(events.find((e) => e.type === 'runner-note')?.text).toBe(HOSTILE);
				const { report } = await recordsOf(t, accepted.runId);
				for (const text of [report, formatStatus(status)]) {
					expectSafe(text);
					expect(text).not.toContain('forged');
				}
			});
		});

		describe('the events an export gets', () => {
			test('are the bytes the manifest hashed, so a real run exports complete', async () => {
				const t = await setup();
				const { accepted } = await t.runToEnd();
				const { out, report } = await exported(t, accepted.runId);
				expect(report.missing).toEqual([]);
				expect(report.complete).toBe(true);
				const dir = t.evidence.runDir(accepted.runId);
				expect(await readFile(join(out, 'events.ndjson'))).toEqual(
					await readFile(join(dir, 'events.ndjson')),
				);
			});

			test('a line replaced by a copy of another keeps the count, and is not complete', async () => {
				const t = await setup();
				const { accepted } = await t.runToEnd();
				const path = join(t.evidence.runDir(accepted.runId), 'events.ndjson');
				const lines = (await readFile(path, 'utf8')).trimEnd().split('\n');
				lines[4] = lines[3] as string;
				await writeFile(path, `${lines.join('\n')}\n`);
				const { report } = await exported(t, accepted.runId);
				expect(report.events.count).toBe(lines.length);
				expect(report.complete).toBe(false);
				expect(report.missing).toEqual(['events: sequence 4 comes after 4']);
			});

			test('a line changed in place keeps the sequence, and is not complete', async () => {
				const t = await setup();
				const { accepted } = await t.runToEnd();
				const path = join(t.evidence.runDir(accepted.runId), 'events.ndjson');
				const text = await readFile(path, 'utf8');
				await writeFile(path, text.replace('point-opened', 'point-closed'));
				const { report } = await exported(t, accepted.runId);
				expect(report.complete).toBe(false);
				expect(report.missing).toHaveLength(1);
				expect(report.missing[0]).toContain('and the manifest says sha256:');
			});

			test('a word learned after the events were written makes the reply differ, and the export says so', async () => {
				const t = await setup();
				t.prepareRecorder((r) => {
					r.onOpen = () => r.say('console', { text: 'the page said late-word-1234' });
				});
				const { accepted } = await t.runToEnd();
				expect((await exported(t, accepted.runId)).report.complete).toBe(true);
				t.secrets.add('late-word-1234');
				const { out, report } = await exported(t, accepted.runId);
				expect(report.complete).toBe(false);
				expect(report.missing).toHaveLength(1);
				expect(report.missing[0]).toContain('and the manifest says sha256:');
				// The export holds the masked events, and the store still holds what was hashed.
				expect(await readFile(join(out, 'events.ndjson'), 'utf8')).not.toContain('late-word-1234');
				await expectDigestsHold(t, accepted.runId);
			});

			test('a word that is not in any event changes nothing an export sees', async () => {
				const t = await setup();
				const { accepted } = await t.runToEnd();
				t.secrets.add('a-word-in-no-event');
				expect((await exported(t, accepted.runId)).report.complete).toBe(true);
			});
		});
	});

	describe('a credential declared in the project', () => {
		const KEY = `sk-proj-${'AbCdEf0123456789'.repeat(2)}`;

		// Nothing is written: no plan, no run.
		const expectNothingWritten = async (t: Awaited<ReturnType<typeof setup>>) => {
			const root = join(t.stateDir, 'verification');
			expect(await readdir(join(root, 'plans'))).toEqual([]);
			expect(await readdir(join(root, 'runs'))).toEqual([]);
		};

		test.each<[string, SetupOptions, string]>([
			[
				'the runner image',
				{ manifest: MANIFEST.replace('curlimages/curl:8.11.1', `ghcr.io/acme/${KEY}:1`) },
				'.koi/verify.yaml, field runner.image',
			],
			[
				'the runner command',
				{ manifest: `${MANIFEST.replace('runner:\n', `runner:\n  command: [run, ${KEY}]\n`)}` },
				'.koi/verify.yaml, field runner.command[1]',
			],
			[
				'a profile name, by its position',
				{ manifest: MANIFEST.replace('matrix:', `${'koi-a1b2c3d4a1b2c3d4a1b2c3d4'}:`) },
				'.koi/verify.yaml, field profiles[1].name',
			],
			[
				"a point's claim",
				{
					files: {
						...POINTS,
						'search.yaml': (POINTS['search.yaml'] as string).replace(
							'claim: Search finds what was saved.',
							`claim: Uses ${KEY}.`,
						),
					},
				},
				'point 4 of 4, counting the point files in the sorted order of their paths, field claim',
			],
			[
				"a point's command",
				{
					files: {
						...POINTS,
						'home.yaml': (POINTS['home.yaml'] as string).replace(
							'run:\n  command: [sh, .koi/runners/home.sh]',
							`run:\n  command: [sh, .koi/runners/home.sh, "--api-key=${KEY}"]`,
						),
					},
				},
				'point 2 of 4, counting the point files in the sorted order of their paths, field run.command[2]',
			],
			[
				"a point's path glob",
				{
					files: {
						...POINTS,
						'search.yaml': (POINTS['search.yaml'] as string).replace(
							"paths: ['src/search/**']",
							`paths: ['src/${KEY}/**']`,
						),
					},
				},
				'point 4 of 4, counting the point files in the sorted order of their paths, field select.paths[0]',
			],
			[
				"an assertion's description",
				{
					files: {
						...POINTS,
						'home.yaml': (POINTS['home.yaml'] as string).replace(
							'description: GET / answers 200.',
							`description: 'token: ${KEY}'`,
						),
					},
				},
				'point 2 of 4, counting the point files in the sorted order of their paths, field assertions[0].description',
			],
			[
				"a point's own file name, which it leaves out of the answer",
				{
					files: {
						...POINTS,
						[`${KEY}.yaml`]: (POINTS['search.yaml'] as string).replace('app.search', 'app.other'),
					},
				},
				'point 5 of 5, counting the point files in the sorted order of their paths, field path',
			],
			[
				'a required id',
				{
					extra: {
						'.koi/required.yaml':
							'version: 1\nrequired:\n  - id: koi-a1b2c3d4a1b2c3d4a1b2c3d4\n    revision: 1\n',
					},
				},
				'the required policy, field required[0].id',
			],
		])('in %s refuses the plan and writes nothing', async (_what, options, where) => {
			const t = await setup(options);
			const err = await refusal(t.plan());
			expect([err.status, err.code, err.retryable]).toEqual([409, 'declared_credential', false]);
			expect(err.message).toContain(where);
			expect(err.message).not.toContain(KEY);
			expect(err.message).not.toContain(KEY.slice(0, 16));
			expect(err.message).not.toContain('koi-a1b2c3d4');
			await expectNothingWritten(t);
		});

		test('in a point not selected refuses too: the file is in the project either way', async () => {
			const t = await setup({
				changed: ['Dockerfile'],
				files: {
					...POINTS,
					'llm.yaml': (POINTS['llm.yaml'] as string).replace(
						'claim: The model answers.',
						`claim: Uses ${KEY}.`,
					),
				},
			});
			const err = await refusal(t.plan());
			expect(err.code).toBe('declared_credential');
			expect(err.message).toContain(
				'point 3 of 4, counting the point files in the sorted order of their paths, field claim',
			);
			await expectNothingWritten(t);
		});

		test('in a claim, and in a file name a prefix hides from the patterns: the refusal quotes neither', async () => {
			const login = 'koi-a1b2c3d4a1b2c3d4a1b2c3d4';
			const t = await setup({
				files: {
					...POINTS,
					[`prefix${login}.yaml`]: (POINTS['search.yaml'] as string)
						.replace('app.search', 'app.other')
						.replace('Search finds what was saved.', `Uses ${login}.`),
				},
			});
			const err = await refusal(t.plan());
			expect(err.code).toBe('declared_credential');
			expect(err.message).toContain(
				'point 4 of 5, counting the point files in the sorted order of their paths, field claim',
			);
			expect(err.message).not.toContain(login);
			expect(err.message).not.toContain('prefix');
			expect(err.message).not.toContain('.koi/points');
			await expectNothingWritten(t);
		});

		test('an image tag that only reads like an assignment plans; a key in the reference does not', async () => {
			const image = (reference: string) =>
				setup({ manifest: MANIFEST.replace('curlimages/curl:8.11.1', reference) });
			const reference = 'ghcr.io/acme/token:DevelopmentBuild20261103';
			const plan = await (await image(reference)).plan();
			expect(plan.runnerImage).toBe(reference);
			const err = await refusal((await image('ghcr.io/acme/token:AKIAIOSFODNN7EXAMPLE')).plan());
			expect(err.code).toBe('declared_credential');
			expect(err.message).toContain('.koi/verify.yaml, field runner.image');
		});

		test('in a broken policy file, whose error would quote it, refuses too', async () => {
			const t = await setup({
				extra: { '.koi/required.yaml': `version: 1\nrequired: []\n${KEY}: 1\n` },
			});
			const err = await refusal(t.plan());
			expect(err.code).toBe('declared_credential');
			expect(err.message).toContain('the required policy, field error');
			expect(err.message).not.toContain(KEY);
			await expectNothingWritten(t);
		});

		test('what a normal project declares does not trip it', async () => {
			const digest = 'e'.repeat(64);
			const commit = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
			const manifest = MANIFEST.replace(
				'curlimages/curl:8.11.1',
				`ghcr.io/acme/token-runner@sha256:${digest}`,
			)
				.replace('matrix:', 'sk-learn-regression-checks:')
				.replace('runner:\n', 'runner:\n  command: [run, "--token=$KOI_TOKEN"]\n');
			const t = await setup({
				manifest,
				files: {
					...POINTS,
					'home.yaml': (POINTS['home.yaml'] as string)
						.replace('claim: The home page says hello.', `claim: Commit ${commit} saves the token.`)
						.replace(
							'paths: [Dockerfile]',
							'paths: [Dockerfile, src/auth/token.ts, docs/secret/**]',
						)
						.replace(
							'run:\n  command: [sh, .koi/runners/home.sh]',
							`run:\n  command: [sh, .koi/runners/home.sh, "Authorization: Bearer $TOKEN", "--pin=${commit}", "sha256:${digest}"]`,
						),
					'xai.yaml': (POINTS['search.yaml'] as string).replace(
						'id: app.search',
						'id: xai-chat-completes-a-long-request',
					),
				},
			});
			const plan = await t.plan();
			expect(plan.runnerImage).toBe(`ghcr.io/acme/token-runner@sha256:${digest}`);
			const accepted = await t.run(plan);
			await t.verification.settled(accepted.runId);
			expect((await t.verification.status(accepted.runId)).finalized).toBe(true);
		});

		test("a changed file name is not checked: it is the pull request's own, and stays as it is", async () => {
			const t = await setup({ changed: ['Dockerfile', `docs/${KEY}.md`] });
			const plan = await t.plan();
			expect(plan.uncovered).toEqual([`docs/${KEY}.md`]);
			const accepted = await t.run(plan);
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.finalized).toBe(true);
			const { uncovered } = RunControllerRecordSchema.parse(
				JSON.parse(
					await readFile(join(t.evidence.runDir(accepted.runId), 'controller.json'), 'utf8'),
				),
			);
			expect(uncovered).toEqual([`docs/${KEY}.md`]);
		});

		test('a word someone registered is no credential, so it cannot stop a plan', async () => {
			const t = await setup();
			for (const word of ['hello.home', 'home-says-hello', '.koi/runners', 'curlimages/curl']) {
				t.secrets.add(word);
			}
			expect((await t.plan()).points[0]?.id).toBe('hello.home');
		});
	});

	test('a long changed file name is cut in the middle, and the plan holds it', async () => {
		const name = `${'x'.repeat(TEXT_MAX)}.md`;
		const t = await setup({ changed: ['Dockerfile', name] });
		const plan = await t.plan();
		expect(plan.uncovered[0]).toHaveLength(TEXT_MAX);
		expect(plan.uncovered[0]).toContain('[cut by koid]');
		expect(plan.uncovered[0]).toEndWith('.md');
		const accepted = await t.run(plan);
		await t.verification.settled(accepted.runId);
		expect((await t.verification.status(accepted.runId)).finalized).toBe(true);
	});

	test('a blocked reason over what a plan holds is cut, and the plan reads back', async () => {
		const services = Array.from({ length: 80 }, (_, i) => `service-with-a-long-name-${i}`);
		const t = await setup({
			files: {
				...POINTS,
				'llm.yaml': (POINTS['llm.yaml'] as string).replace(
					'services: [chat]',
					`services: [${services.join(', ')}]`,
				),
			},
		});
		const plan = await t.plan('matrix');
		expect(plan.blocked[0]?.reason).toHaveLength(TEXT_MAX);
		expect(await t.verification.planPage(plan.planId, undefined)).toEqual(plan);
	});

	test('a refusal is scrubbed like any error, with what the project named in it', async () => {
		const t = await setup({
			manifest: MANIFEST.replace('matrix:', 'privatetoken:'),
		});
		t.secrets.add('privatetoken');
		const err = await refusal(t.plan('nightly'));
		expect(err.code).toBe('no_such_profile');
		expect(err.message).toContain('it has pr, [redacted]');
	});

	describe('a firewall reapply that does not come back', () => {
		// Holds the third apply. The network's own and the recorder's come first, so
		// this is the first verifier's reapply unless a test asks for another first.
		const holdingThirdApply = (t: Awaited<ReturnType<typeof setup>>) => {
			const gate = new Gate();
			const apply = t.helper.apply.bind(t.helper);
			let applies = 0;
			t.helper.apply = async (descriptor) => {
				applies += 1;
				if (applies === 3) await gate.pass();
				return apply(descriptor);
			};
			return { gate, applies: () => applies };
		};
		const verifierGone = (t: Awaited<ReturnType<typeof setup>>) =>
			eventually(() => t.docker.verifiers[0]?.detached === true);

		test('a cancel ends the wait: cleanup runs, the run ends, the point is blocked, and the revoke comes after the apply', async () => {
			const t = await setup();
			const { gate } = holdingThirdApply(t);
			const plan = await t.plan();
			const accepted = await t.run(plan);
			await gate.reached;
			await t.verification.cancel(accepted.runId);
			// The helper still holds on, and the verifier has gone all the same.
			await verifierGone(t);
			expect(t.docker.containers.has(helperName(accepted.runId, 'verifier'))).toBe(false);
			expect(t.docker.verifiers[0]?.key).toBeUndefined();
			gate.release();
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.state).toBe('cancelled');
			expect(status.points[0]?.outcome).toBe('blocked');
			expect(status.points[0]?.reason).toBe('cancelled: the run was cancelled');
			expect(status.cleanup).toBe('succeeded');
			expect(status.finalized).toBe(true);
			const { events } = t.docker;
			expect(events.indexOf(`revoke ${accepted.runId}`)).toBeGreaterThan(
				events.lastIndexOf(`apply ${accepted.runId}`),
			);
			expect(t.helper.runs.has(accepted.runId)).toBe(false);
		});

		test('at the deadline, one still queued behind another change is dropped, and the helper hears nothing of it', async () => {
			const t = await setup();
			const { gate, applies } = holdingThirdApply(t);
			t.docker.verifierScript = async (v) => {
				// Another change takes the network's lock first, as another run's can.
				void t.network.reapply(v.env.KOI_RUN_ID ?? '').catch(() => {});
				await gate.reached;
				t.advance(610_000);
				await v.stopped;
				return 137;
			};
			const plan = await t.plan();
			const accepted = await t.run(plan);
			await verifierGone(t);
			gate.release();
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.points.map((p) => p.outcome)).toEqual(['blocked', 'not-run', 'not-run']);
			expect(status.points[0]?.reason).toStartWith('point_timeout: ');
			expect(status.cleanup).toBe('succeeded');
			expect(status.finalized).toBe(true);
			// The network's, the recorder's and the other change's.
			expect(applies()).toBe(3);
			expect(t.helper.runs.has(accepted.runId)).toBe(false);
		});

		test('one that never comes back holds neither the point nor the run', async () => {
			const t = await setup({ teardownAllowanceMs: 200 });
			const { gate } = holdingThirdApply(t);
			const plan = await t.plan();
			const accepted = await t.run(plan);
			await gate.reached;
			await t.verification.cancel(accepted.runId);
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.points[0]?.outcome).toBe('blocked');
			expect(status.points[0]?.reason).toBe('cancelled: the run was cancelled');
			expect(t.docker.containers.has(helperName(accepted.runId, 'verifier'))).toBe(false);
			// The lock is still held, so the teardown could not finish, and says so.
			expect(status.cleanup).toBe('failed');
			expect(status.interruption).toStartWith('teardown_failed: ');
			expect(status.finalized).toBe(true);
			gate.release();
		});
	});

	describe('a verifier that does not end', () => {
		const onePointSecond = {
			files: { ...POINTS, 'home.yaml': `${POINTS['home.yaml']}budgets:\n  timeoutSeconds: 1\n` },
		};
		// The stop of its cleanup never comes back. No signal reaches that.
		const holdingStop = (t: Awaited<ReturnType<typeof setup>>) => {
			const gate = new Gate();
			t.docker.onStop = async (name) => {
				if (name.endsWith('-verifier')) await gate.pass();
			};
			return gate;
		};
		// A wait in the verifier that its signal does not end. The real command
		// takes the signal, so this stands for one that does not.
		const holdingCopy = (t: Awaited<ReturnType<typeof setup>>) => {
			const gate = new Gate();
			t.docker.copyIn = async () => {
				await gate.pass();
				throw new Error('it came back in the end');
			};
			return gate;
		};
		const firstPointDone = async (t: Awaited<ReturnType<typeof setup>>, runId: string) =>
			(await t.verification.status(runId)).points[0]?.state === 'done';

		test('a stop that never comes back ends the run after a grace, and the point is judged on what it read', async () => {
			const t = await setup();
			const gate = holdingStop(t);
			t.docker.verifierScript = runner(declared(POINTS), () => 'fail');
			const plan = await t.plan();
			const accepted = await t.run(plan);
			await gate.reached;
			// Short of the grace, and the run still waits.
			t.advance(50_000);
			await Bun.sleep(20);
			expect(await firstPointDone(t, accepted.runId)).toBe(false);
			t.advance(11_000);
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.points[0]?.outcome).toBe('fail');
			expect(status.completion).toBe('interrupted');
			expect(status.interruption).toStartWith('verifier_stuck: ');
			// Its name is still in use, so no other point started.
			expect(t.docker.verifiers).toHaveLength(1);
			expect(t.docker.verifiers[0]?.detached).toBe(true);
			expect(status.points[1]?.state).toBe('pending');
			expect(status.cleanup).toBe('succeeded');
			expect(status.finalized).toBe(true);
			gate.release();
		});

		test('a cancel does not wait out the point for a stop that never comes back', async () => {
			const t = await setup();
			const gate = holdingStop(t);
			// The watchdog's stop comes first, and the one that removes the verifier second.
			// Its limit starts just before that, after real writes to the disk, and this clock
			// moves only when told. Moved any sooner, the limit would start after it and
			// never be reached.
			const held = t.docker.onStop;
			let stops = 0;
			t.docker.onStop = (name) => {
				if (name.endsWith('-verifier')) stops += 1;
				return held?.(name);
			};
			t.docker.verifierScript = async (v) => {
				await v.stopped;
				return 137;
			};
			const plan = await t.plan();
			const accepted = await t.run(plan);
			await eventually(() => t.docker.verifiers.length === 1);
			await t.verification.cancel(accepted.runId);
			await eventually(() => stops === 2);
			t.advance(61_000);
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.state).toBe('cancelled');
			expect(status.points[0]?.outcome).toBe('blocked');
			expect(status.points[0]?.reason).toBe('cancelled: the run was cancelled');
			expect(status.finalized).toBe(true);
			gate.release();
		});

		test('a wait no signal ends is left past its point and a grace: the point is blocked and the run stops there', async () => {
			const t = await setup(onePointSecond);
			const gate = holdingCopy(t);
			const plan = await t.plan();
			const accepted = await t.run(plan);
			await gate.reached;
			// A second of budget, 15 of grace, 60 of handling, 60 and 30 for its end.
			t.advance(160_000);
			await Bun.sleep(20);
			expect(await firstPointDone(t, accepted.runId)).toBe(false);
			t.advance(7_000);
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.points[0]?.outcome).toBe('blocked');
			expect(status.points[0]?.reason).toStartWith('verifier_stuck: ');
			expect(status.completion).toBe('interrupted');
			expect(status.interruption).toStartWith('verifier_stuck: ');
			expect(status.points[1]?.state).toBe('pending');
			expect(status.finalized).toBe(true);
			expect(status.cleanup).toBe('succeeded');

			// It ends in the end, and what it does then touches none of the records.
			const events = join(t.evidence.runDir(accepted.runId), 'events.ndjson');
			const before = await readFile(events, 'utf8');
			gate.release();
			await eventually(() => t.logs.join('\n').includes('ended after the run stopped waiting'));
			expect(await readFile(events, 'utf8')).toBe(before);
		});

		test("past the run's deadline and a grace, the point is blocked and the rest are not-run", async () => {
			const t = await setup();
			const gate = holdingCopy(t);
			const plan = await t.plan();
			const accepted = await t.run(plan);
			await gate.reached;
			t.advance(691_000);
			await t.verification.settled(accepted.runId);
			const status = await t.verification.status(accepted.runId);
			expect(status.points.map((p) => p.outcome)).toEqual(['blocked', 'not-run', 'not-run']);
			expect(status.points[0]?.reason).toStartWith('verifier_stuck: ');
			expect(status.finalized).toBe(true);
			expect(status.cleanup).toBe('succeeded');
			gate.release();
		});
	});

	test('a report citing too many references fails its point, even with a pass after it', async () => {
		const report = (outcome: string, count: number) =>
			JSON.stringify({
				type: 'assertion',
				point: 'hello.home',
				name: 'home-says-hello',
				outcome,
				evidence: Array.from({ length: count }, () => 'capture:shot'),
			});
		for (const first of ['pass', 'fail']) {
			const t = await setup();
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(report(first, 101));
				v.out(report('pass', 0));
				for (const line of supervisorExit(declaredSteps(v))) v.out(line);
				return 0;
			};
			const { runId } = await t.run(await t.plan());
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expect(status.points.find((p) => p.id === 'hello.home')?.outcome).toBe('fail');
			expect(status.outcome).not.toBe('pass');
		}
	});

	describe('a disk that stops answering', () => {
		// A runner that holds its point open, its first line stalling the events.
		const stallingRunner =
			(t: Awaited<ReturnType<typeof setup>>, gate: Gate, before?: (v: FakeVerifier) => void) =>
			async (v: FakeVerifier) => {
				await v.nextLine();
				before?.(v);
				t.stallEvents(gate);
				v.out('the line that does not get written');
				await v.stopped;
				return 137;
			};
		const startStalled = async (
			gate: Gate,
			before?: (v: FakeVerifier) => void,
		): Promise<{ t: Awaited<ReturnType<typeof setup>>; runId: string }> => {
			const t = await setup({ diskPollMs: 5 });
			t.docker.verifierScript = stallingRunner(t, gate, before);
			const { runId } = await t.run(await t.plan());
			await gate.reached;
			return { t, runId };
		};
		const expectTornDown = async (t: Awaited<ReturnType<typeof setup>>, runId: string) => {
			expect(t.record.lease).toBeUndefined();
			expect(t.calls.some((c) => c.startsWith('release '))).toBe(true);
			expect(await t.network.record(runId)).toBeUndefined();
			expect(await t.docker.listRun()).toEqual([]);
			expect(t.docker.events.at(-1)).toBe(`removed network koi-v-${runId}`);
		};
		const expectEndsInterrupted = (status: Awaited<ReturnType<Verification['status']>>) => {
			expect(status.state).toBe('completed');
			expect(status.completion).toBe('interrupted');
			expect(status.outcome).toBe('incomplete');
			expect(status.interruption).toStartWith('evidence_unwritable: ');
			expect(status.interruption).toContain('could not be written');
			expect(status.finalized).toBe(false);
			expect(status.evidence).toBe('incomplete');
			expect(status.cleanup).toBe('succeeded');
			expect(status.readiness.eligibleForMergeGate).toBe(false);
		};
		// When the writes come back, they change nothing a reader can see, on this
		// koid or the next.
		const expectLateWritesChangeNothing = async (
			t: Awaited<ReturnType<typeof setup>>,
			runId: string,
			gate: Gate,
		) => {
			const dir = t.evidence.runDir(runId);
			const before = await t.verification.status(runId);
			const controller = await readFile(join(dir, 'controller.json'), 'utf8');
			gate.release();
			await Bun.sleep(40);
			expect(await t.verification.status(runId)).toEqual(before);
			expect(await readFile(join(dir, 'controller.json'), 'utf8')).toBe(controller);
			expect(await stat(join(dir, 'manifest.json')).catch(() => undefined)).toBeUndefined();
			const next = t.restarted();
			expect(await next.recover({ releaseLeases: false })).toEqual([runId]);
			const after = await next.status(runId);
			expect(after.outcome).toBe('incomplete');
			expect(after.finalized).toBe(false);
			expect(after.points.some((p) => p.outcome === 'pass')).toBe(false);
		};

		test('with the deadline passed, the teardown runs and the run ends interrupted', async () => {
			const gate = new Gate();
			const { t, runId } = await startStalled(gate);
			// Past the deadline and the verifier's own outer limit.
			t.advance(700_000);
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expectEndsInterrupted(status);
			await expectTornDown(t, runId);
			expect(status.points[0]?.state).toBe('done');
			expect(status.points[0]?.outcome).toBe('blocked');
			expect(status.points[0]?.reason).toContain('evidence_unwritable: ');
			expect(t.docker.verifiers[0]?.detached).toBe(true);
			await expectLateWritesChangeNothing(t, runId, gate);
		});

		test('with the deadline not yet passed, the teardown runs and the run ends interrupted', async () => {
			const gate = new Gate();
			const { t, runId } = await startStalled(gate);
			// Short of the limit on one write, the run still waits.
			t.advance(DISK_WAIT_MS - 1_000);
			await Bun.sleep(30);
			expect((await t.verification.status(runId)).state).toBe('running');
			t.advance(2_000);
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expectEndsInterrupted(status);
			await expectTornDown(t, runId);
			expect(status.points[0]?.outcome).toBe('blocked');
			// The run stopped there: the rest never started, and the run's time had not ended.
			expect(status.points[1]?.state).toBe('pending');
			expect(t.docker.verifiers).toHaveLength(1);
			expect(t.now()).toBeLessThan(Date.parse(status.startedAt) + 600_000);
			await expectLateWritesChangeNothing(t, runId, gate);
		});

		test('a failure stands when the disk stops during the check of what the point cites', async () => {
			for (const [outcome, ended] of [
				['pass', 'blocked'],
				['fail', 'fail'],
			] as const) {
				const gate = new Gate();
				const t = await setup({ diskPollMs: 5 });
				t.docker.verifierScript = async (v) => {
					await v.nextLine();
					t.stallChecks(gate);
					v.out(
						JSON.stringify({
							type: 'assertion',
							point: 'hello.home',
							name: 'home-says-hello',
							outcome,
							evidence: [],
						}),
					);
					for (const line of supervisorExit(declaredSteps(v))) v.out(line);
					return 0;
				};
				const { runId } = await t.run(await t.plan());
				await gate.reached;
				t.advance(DISK_WAIT_MS + 1_000);
				await t.verification.settled(runId);
				const status = await t.verification.status(runId);
				expectEndsInterrupted(status);
				expect(status.points[0]?.outcome).toBe(ended);
				gate.release();
			}
		});

		test('a pass reported before the stall is not believed, and a failure stands', async () => {
			const assertion = (outcome: string) => (v: FakeVerifier) =>
				v.out(
					JSON.stringify({
						type: 'assertion',
						point: 'hello.home',
						name: 'home-says-hello',
						outcome,
						evidence: [],
					}),
				);
			for (const [outcome, ended] of [
				['pass', 'blocked'],
				['fail', 'fail'],
			] as const) {
				const gate = new Gate();
				const { t, runId } = await startStalled(gate, assertion(outcome));
				t.advance(DISK_WAIT_MS + 1_000);
				await t.verification.settled(runId);
				const status = await t.verification.status(runId);
				expectEndsInterrupted(status);
				expect(status.points[0]?.outcome).toBe(ended);
				gate.release();
			}
		});

		test('a write the runner did not make stops its point too, however quiet it is', async () => {
			const t = await setup({ diskPollMs: 5 });
			const gate = new Gate();
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				await v.stopped;
				return 137;
			};
			const { runId } = await t.run(await t.plan());
			await eventually(() => t.docker.verifiers.length === 1);
			await eventually(() => t.docker.events.some((e) => e.includes('verifier')));
			t.stallEvents(gate);
			const lost = t
				.latestWriter()
				.appendEvent({ source: 'host', type: 'held' })
				.catch(() => {});
			await gate.reached;
			t.advance(DISK_WAIT_MS + 1_000);
			await lost;
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expectEndsInterrupted(status);
			expect(status.points[0]?.outcome).toBe('blocked');
			await expectTornDown(t, runId);
			gate.release();
		});

		test('it outranks a cancel, since it is what ended the run', async () => {
			const gate = new Gate();
			const { t, runId } = await startStalled(gate);
			const cancelling = t.verification.cancel(runId);
			t.advance(DISK_WAIT_MS + 1_000);
			await cancelling;
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expectEndsInterrupted(status);
			expect(status.cancelRequested).toBe(true);
			await expectTornDown(t, runId);
			gate.release();
		});

		test('during finalization, the lease still goes and no manifest lands', async () => {
			const t = await setup({ diskPollMs: 5 });
			const gate = new Gate();
			t.finalizing(() => {
				t.stallEvents(gate);
				// The stall is what the seal waits on; the clock passes the limit once it does.
				gate.reached.then(() => t.advance(DISK_WAIT_MS + 1_000));
			});
			const { runId } = await t.run(await t.plan());
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expectEndsInterrupted(status);
			await expectTornDown(t, runId);
			// Every point had ended, and its outcome stays. The run still counts for nothing.
			expect(status.points.every((p) => p.state === 'done')).toBe(true);
			gate.release();
			await Bun.sleep(40);
			expect(
				await stat(join(t.evidence.runDir(runId), 'manifest.json')).catch(() => undefined),
			).toBeUndefined();
			expect((await t.verification.status(runId)).outcome).toBe('incomplete');
		});

		test('a preview store that does not answer does not hold the end of the run', async () => {
			const t = await setup({ diskPollMs: 5 });
			const gate = new Gate();
			t.deployer.releaseLease = async () => {
				await gate.pass();
			};
			const { runId } = await t.run(await t.plan());
			await gate.reached;
			t.advance(DISK_WAIT_MS + 1_000);
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expect(status.finalized).toBe(true);
			expect(status.state).toBe('completed');
			gate.release();
		});

		test('a wait nothing else ends cannot hold the teardown back, and changes nothing when it ends', async () => {
			const t = await setup({ diskPollMs: 5 });
			const gate = new Gate();
			// Once: the run's last check of its evidence must get an answer.
			let held = false;
			t.resolving(async () => {
				if (held) return;
				held = true;
				await gate.pass();
			});
			const { runId } = await t.run(await t.plan());
			await gate.reached;
			// Short of the deadline, the 90 seconds a verifier may take past it and two
			// disk waits, the run still waits.
			t.advance(600_000 + 90_000 + 2 * DISK_WAIT_MS - 1_000);
			await Bun.sleep(30);
			expect((await t.verification.status(runId)).state).toBe('running');
			t.advance(2_000);
			await t.verification.settled(runId);
			const status = await t.verification.status(runId);
			expect(status.completion).toBe('interrupted');
			expect(status.interruption).toStartWith('run_stuck: ');
			expect(status.outcome).toBe('incomplete');
			expect(status.finalized).toBe(true);
			expect(status.points[0]?.state).toBe('done');
			expect(status.points[0]?.outcome).toBe('blocked');
			await expectTornDown(t, runId);
			gate.release();
			await Bun.sleep(40);
			expect((await t.verification.status(runId)).points).toEqual(status.points);
			expect(t.docker.verifiers).toHaveLength(1);
		});
	});

	test("a cancel during the first point's staging ends the copy, and nothing of the point stays", async () => {
		const t = await setup();
		const gate = new Gate();
		t.docker.copyGate = gate;
		const plan = await t.plan();
		const accepted = await t.run(plan);
		await gate.reached;
		await t.verification.cancel(accepted.runId);
		// The gate never opens: only the point's signal can end this copy.
		await t.verification.settled(accepted.runId);
		const status = await t.verification.status(accepted.runId);
		expect(status.state).toBe('cancelled');
		expect(t.docker.verifiers).toEqual([]);
		expect(t.docker.volumes.size).toBe(0);
		expect([...t.docker.containers.keys()].filter((n) => n.includes('staging'))).toEqual([]);
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
	});

	test('a cancel ends the run after the point in progress, as cancelled with no Result', async () => {
		const t = await setup();
		const gate = new Gate();
		t.prepareRecorder((r) => {
			r.captureGate = gate;
		});
		const plan = await t.plan();
		const accepted = await t.run(plan);
		await gate.reached;
		const asked = await t.verification.cancel(accepted.runId);
		expect(asked.cancelRequested).toBe(true);
		expect(asked.state).toBe('running');
		const recorder = t.recorders.get(accepted.runId);
		if (recorder !== undefined) recorder.captureGate = undefined;
		gate.release();
		await t.verification.settled(accepted.runId);
		const status = await t.verification.status(accepted.runId);
		expect(status.state).toBe('cancelled');
		expect(status.completion).toBe('cancelled');
		expect(status.outcome).toBe('incomplete');
		expect(status.points.map((p) => [p.id, p.state])).toEqual([
			['hello.home', 'done'],
			['app.always', 'pending'],
			['app.search', 'pending'],
		]);
		const dir = t.evidence.runDir(accepted.runId);
		expect(await stat(join(dir, 'result.json')).catch(() => undefined)).toBeUndefined();
		const manifest = EvidenceManifestSchema.parse(
			JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')),
		);
		expect(manifest.status.state).toBe('cancelled');
		expect(t.record.lease).toBeUndefined();
		// A cancel of a finished run just reports it.
		expect((await t.verification.cancel(accepted.runId)).state).toBe('cancelled');
	});

	test('a lost lease interrupts the run before the next point', async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			r.onOpen = () => {
				t.deployer.lost = true;
			};
		});
		const { status } = await t.runToEnd();
		expect(status.state).toBe('completed');
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toStartWith('lease_lost:');
		expect(status.outcome).toBe('incomplete');
		expect(status.points.map((p) => p.state)).toEqual(['done', 'pending', 'pending']);
		// The lease is not ours to release.
		expect(t.calls.filter((c) => c.startsWith('release'))).toHaveLength(1);
	});

	test('the run deadline ends the point in progress and leaves the rest not-run, with the Result incomplete', async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			r.onOpen = () => t.advance(700_000);
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('evaluated');
		expect(status.outcome).toBe('incomplete');
		// The time ran out while the first point was opening: its next call
		// to the recorder was refused, and nothing of it was captured.
		expect(status.points.map((p) => [p.id, p.outcome, p.evidence])).toEqual([
			['hello.home', 'not-run', []],
			['app.always', 'not-run', []],
			['app.search', 'not-run', []],
		]);
		expect(status.points[0]?.reason).toContain('run_deadline');
		expect(status.points[0]?.reason).toContain('during this point');
		expect(status.points[1]?.reason).toContain('before this point');
		const recorder = t.recorders.get(accepted.runId);
		expect(recorder?.calls.filter((c) => c.startsWith('capture '))).toEqual([]);
		// The teardown had time of its own: the point was closed and the
		// recorder stopped, the network removed and the lease released.
		expect(recorder?.calls).toContain('close x1');
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
		expect(t.record.lease).toBeUndefined();
		// The deadline is the run's own limit, not a capture error.
		expect(status.evidence).toBe('complete');
	});

	test("every recorder call carries the run's budget as its signal", async () => {
		const t = await setup();
		const { accepted } = await t.runToEnd();
		const recorder = t.recorders.get(accepted.runId);
		expect(recorder?.signals).toHaveLength(6);
		expect(recorder?.signals.every((s) => !s.aborted)).toBe(true);
	});

	// The first point's file with a budget of its own.
	const withPointBudget = (seconds: number): Record<string, string> => ({
		...POINTS,
		'home.yaml': `${POINTS['home.yaml']}budgets:\n  timeoutSeconds: ${seconds}\n`,
	});

	test('a one-second point with a hanging capture is blocked at its budget, and the run goes on', async () => {
		// Real time: the point's end is a host timer, and the run has 600 seconds.
		const t = await setup({ files: withPointBudget(1) });
		t.prepareRecorder((r) => {
			r.hangCapturesOf = 'hello.home';
		});
		// Only the point's budget can end the hanging capture: the test's own
		// timeout is far under the run's limit.
		const { accepted, status } = await t.runToEnd();
		const reason =
			'point_timeout: the point reached its budget of 1 seconds before the runner ended';
		expect(status.points.map((p) => [p.id, p.outcome, p.reason])).toEqual([
			['hello.home', 'blocked', reason],
			['app.always', 'pass', undefined],
			['app.search', 'pass', undefined],
		]);
		expect(status.points[0]?.evidence).toEqual([]);
		expect(status.points[1]?.evidence).toEqual([
			'recorder:screenshot:2',
			'recorder:aria:3',
			'recorder:http-response:4',
		]);
		// The limit is the point's own and no capture error, and the entry for
		// the capture it cut says whose time ran out.
		expect([status.completion, status.outcome, status.evidence]).toEqual([
			'evaluated',
			'incomplete',
			'complete',
		]);
		expect(status.problems).toEqual([]);
		const evidence = await t.verification.evidence(accepted.runId);
		expect(evidence.artifacts[0]?.availability).toBe('failed');
		expect(evidence.artifacts[0]?.redaction.limitations[0]).toBe(
			"the capture was not made: capturing: the point's time ran out during the call",
		);
		// The context closed under the run's budget, so the next point opened.
		const recorder = t.recorders.get(accepted.runId);
		expect(recorder?.calls.filter((c) => c.startsWith('close '))).toHaveLength(3);
		expect(recorder?.signals[0]?.aborted).toBe(true);
		expect(recorder?.signals.slice(1).every((s) => !s.aborted)).toBe(true);
		const events = await t.verification.events(accepted.runId);
		expect(events.events.find((e) => e.type === 'point-blocked')?.reason).toBe(reason);
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
		expect(t.record.lease).toBeUndefined();
	});

	test('a run step that already failed stands when the cleanup then reaches the point budget', async () => {
		// Real time, as above. The point is a fail, and the budget stays among its
		// reasons, since the cleanup did not finish either.
		const t = await setup({ files: withPointBudget(1) });
		t.prepareRecorder((r) => {
			r.hangCapturesOf = 'hello.home';
		});
		const usual = t.docker.verifierScript;
		t.docker.verifierScript = async (v) => {
			if (v.env.KOI_POINT_ID !== 'hello.home') return (usual as VerifierScript)(v);
			await v.nextLine();
			v.out(supervisorLine({ event: 'started' }));
			v.out(
				supervisorLine({ event: 'step', step: 'run', status: 'exited', code: 1, seconds: 0.1 }),
			);
			v.out('{"type":"capture","kind":"screenshot","label":"from-cleanup"}');
			await v.stopped;
			return 137;
		};
		const { status } = await t.runToEnd();
		expect(status.points[0]?.outcome).toBe('fail');
		expect(status.points[0]?.reason).toContain('runner_failed: the run step exited 1');
		expect(status.points[0]?.reason).toContain(
			'point_timeout: the point reached its budget of 1 seconds before the runner ended',
		);
	}, 30_000);

	test('a slow open leaves the verifier what the point has left, on one deadline', async () => {
		const t = await setup({ files: withPointBudget(100) });
		let opens = 0;
		t.prepareRecorder((r) => {
			r.onOpen = () => {
				opens += 1;
				if (opens === 1) t.advance(40_000);
			};
		});
		const told = new Map<string, unknown>();
		t.docker.verifierScript = async (v) => {
			const start = JSON.parse(await v.nextLine()) as { timeoutSeconds: unknown };
			told.set(v.env.KOI_POINT_ID ?? '', [start.timeoutSeconds, v.env.KOI_TIMEOUT_SECONDS]);
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		await t.runToEnd();
		expect(told.get('hello.home')).toEqual([60, '60']);
		// The next point's budget is its own, from its own start, under what the
		// run has left: the 40 seconds came off the run's 600 too.
		expect(told.get('app.always')).toEqual([560, '560']);
	});

	test('an open that used all of the budget starts no verifier for the point', async () => {
		const t = await setup({ files: withPointBudget(100) });
		let opens = 0;
		t.prepareRecorder((r) => {
			r.onOpen = () => {
				opens += 1;
				if (opens === 1) t.advance(100_000);
			};
		});
		const { status } = await t.runToEnd();
		expect(status.points[0]?.outcome).toBe('blocked');
		expect(status.points[0]?.reason).toContain('point_timeout: ');
		expect(t.docker.verifiers.map((v) => v.env.KOI_POINT_ID)).not.toContain('hello.home');
		expect(status.points[1]?.outcome).toBe('pass');
	});

	test("a point that names no budget stops at the plan's point limit, and each point gets its own", async () => {
		const t = await setup({ manifest: MANIFEST.replace('budgets:\n  timeoutSeconds: 600\n', '') });
		let opens = 0;
		t.prepareRecorder((r) => {
			// Two points take most of the point limit and go on; together they
			// are past it. The third is past it on its own.
			r.onOpen = () => {
				opens += 1;
				t.advance(opens === 3 ? 301_000 : 200_000);
			};
		});
		const { status } = await t.runToEnd();
		expect(status.points.map((p) => [p.outcome, p.reason])).toEqual([
			['pass', undefined],
			['pass', undefined],
			['blocked', 'point_timeout: the point reached its budget of 300 seconds'],
		]);
		expect(status.completion).toBe('evaluated');
		expect(status.problems).toEqual([]);
	});

	test('a point with more budget than the run has left ends with the run, under the same formula', async () => {
		// Real time: the run's second ends both, and the run's limit is the one
		// that counts. The verifier was running by then, so the point is
		// blocked, and the runner is told the same second.
		const t = await setup({
			manifest: MANIFEST.replace('timeoutSeconds: 600', 'timeoutSeconds: 1'),
			files: withPointBudget(600),
		});
		t.prepareRecorder((r) => {
			r.hangCapturesOf = 'hello.home';
		});
		const { status } = await t.runToEnd();
		expect(status.points.map((p) => p.outcome)).toEqual(['blocked', 'not-run', 'not-run']);
		expect(status.points[0]?.reason).toBe(
			'point_timeout: the point reached its budget of 1 seconds before the runner ended',
		);
		expect(status.points[1]?.reason).toContain('run_deadline');
		expect(t.docker.verifiers[0]?.env.KOI_TIMEOUT_SECONDS).toBe('1');
		expect(status.completion).toBe('evaluated');
		expect(status.problems).toEqual([]);
	});

	test('a recorder still holding a context koid could not name ends the run, not each later point', async () => {
		// The first open never answers, and the recorder keeps its context and
		// refuses the next open, as it does while one stands.
		const t = await setup({ files: withPointBudget(1) });
		t.prepareRecorder((r) => {
			r.hangOpenOf = 'hello.home';
			const open = r.openContext.bind(r);
			r.openContext = async (request, options) => {
				if (request.pointId !== 'hello.home') {
					r.calls.push(`refused ${request.pointId}`);
					throw new RecorderError(409, 'context_open', 'a context is open already; close it first');
				}
				return open(request, options);
			};
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.points.map((p) => [p.id, p.state, p.outcome])).toEqual([
			['hello.home', 'done', 'blocked'],
			['app.always', 'done', 'blocked'],
			['app.search', 'pending', undefined],
		]);
		expect(status.points[0]?.reason).toBe(
			'point_timeout: the point reached its budget of 1 seconds',
		);
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toBe(
			'recorder_unavailable: a context is open already; close it first',
		);
		expect(t.recorders.get(accepted.runId)?.calls).toContain('refused app.always');
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
	});

	test('a lease shorter than the run is renewed before each point, within the budget', async () => {
		// The box caps leases at 30 seconds; the run has 600.
		const t = await setup({ leaseCapSeconds: 30 });
		const { accepted, status } = await t.runToEnd();
		expect(t.calls[0]).toBe(`lease ${LABEL} ${runLeaseHolder(accepted.runId)} 720`);
		// Within the renewal margin from the start: renewed to the points'
		// deadline before the first point, never past the run's own budget.
		const renewals = t.calls.filter((c) => c.startsWith('renew '));
		expect(renewals[0]).toBe(`renew ${LABEL} ${'l'.repeat(20)} 600`);
		expect(status.completion).toBe('evaluated');
		expect(status.cleanup).toBe('succeeded');
		expect(t.record.lease).toBeUndefined();
		expect(t.logs.some((l) => l.includes('lease on hello-pr-7 renewed'))).toBe(true);
	});

	test('a recorder that stops answering interrupts the run as recorder_lost, not capture-error', async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			r.captureError = new RecorderError(
				0,
				'unreachable',
				'the recorder did not answer: connection refused',
			);
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toStartWith(
			'recorder_lost: capturing: the recorder did not answer',
		);
		expect(status.outcome).toBe('incomplete');
		// The capture it did not make is a failed entry with a problem, so the
		// bundle says what is missing; the run still finalizes and tears down.
		expect(status.problems.map((p) => p.code)).toContain('capture_failed');
		expect(status.points.map((p) => p.state)).toEqual(['done', 'pending', 'pending']);
		expect(status.finalized).toBe(true);
		expect(status.cleanup).toBe('succeeded');
		expect(await t.network.record(accepted.runId)).toBeUndefined();
	});

	test('refuses a run while an earlier run of the preview still has its network or is still finishing', async () => {
		// A teardown that failed leaves the network in `destroying` and keeps
		// the lease; once the lease is gone, the leftovers still refuse a run.
		const t = await setup();
		t.helper.revokeError = 'iptables is busy';
		const first = await t.runToEnd();
		expect(first.status.cleanup).toBe('failed');
		t.advance(3_600_000);
		const plan = await t.plan();
		const err = await refusal(t.run(plan));
		expect([err.status, err.code, err.retryable]).toEqual([409, 'preview_busy', true]);
		expect(err.message).toContain(
			`run ${first.accepted.runId} still has its run network (destroying)`,
		);
		// The lease taken for the refused run was given back.
		expect(t.calls.at(-1)).toBe(`release ${LABEL} ${'l'.repeat(20)}`);
		expect(t.record.lease).toBeUndefined();

		// A run still finishing on the label refuses the next one too.
		const u = await setup();
		const gate = new Gate();
		u.prepareRecorder((r) => {
			r.captureGate = gate;
		});
		const running = await u.run(await u.plan());
		await gate.reached;
		const again = await refusal(u.run(await u.plan()));
		expect(again.code).toBe('preview_busy');
		expect(again.message).toContain(`run ${running.runId} is still finishing`);
		const recorder = u.recorders.get(running.runId);
		if (recorder !== undefined) recorder.captureGate = undefined;
		gate.release();
		await u.verification.settled(running.runId);
	});

	test('a bundle whose manifest cannot be written is finalize-failed and incomplete, whatever was judged', async () => {
		const t = await setup();
		const gate = new Gate();
		t.prepareRecorder((r) => {
			r.captureGate = gate;
		});
		const plan = await t.plan();
		const accepted = await t.run(plan);
		await gate.reached;
		t.failing.finalize = new Error('ENOSPC: no space left on device');
		const dir = t.evidence.runDir(accepted.runId);
		const recorder = t.recorders.get(accepted.runId);
		if (recorder !== undefined) recorder.captureGate = undefined;
		gate.release();
		await t.verification.settled(accepted.runId);
		const status = await t.verification.status(accepted.runId);
		expect(status.state).toBe('completed');
		expect(status.completion).toBe('finalize-failed');
		expect(status.outcome).toBe('incomplete');
		expect(status.interruption).toStartWith('finalize_failed:');
		expect(status.finalized).toBe(false);
		expect(status.evidence).toBe('incomplete');
		expect(status.problems.map((p) => p.code)).toContain('finalize_failed');
		expect(status.readiness.eligibleForMergeGate).toBe(false);
		// The points keep what was judged; the teardown was done, so the
		// lease is released.
		expect(status.points.map((p) => p.outcome)).toEqual(['pass', 'pass', 'pass']);
		expect(status.cleanup).toBe('succeeded');
		expect(t.record.lease).toBeUndefined();
		const stored = RunControllerRecordSchema.parse(
			JSON.parse(await readFile(join(dir, 'controller.json'), 'utf8')),
		);
		expect(stored.completion).toBe('finalize-failed');
		expect(stored.interruption).toContain('ENOSPC');
		expect(await stat(join(dir, 'manifest.json')).catch(() => undefined)).toBeUndefined();
		// A restart leaves it as it is: it is already incomplete.
		expect(await t.verification.recover({ releaseLeases: true })).toEqual([]);
	});

	test('a capture that failed makes the completion capture-error with no Result', async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			r.captureError = new Error('the browser hung');
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('capture-error');
		expect(status.outcome).toBe('incomplete');
		expect(status.evidence).toBe('incomplete');
		expect(status.problems.map((p) => p.code)).toContain('capture_failed');
		// The runner got failed acknowledgments and cited nothing; its pass
		// lacks the declared evidence.
		expect(status.points[0]?.outcome).toBe('fail');
		expect(status.points[0]?.reason).toBe(
			'missing_evidence: home-says-hello has no available http-response evidence',
		);
		expect(status.points[0]?.evidence).toEqual([]);
		const dir = t.evidence.runDir(accepted.runId);
		expect(await stat(join(dir, 'result.json')).catch(() => undefined)).toBeUndefined();
		expect(await stat(join(dir, 'manifest.json')).catch(() => undefined)).toBeDefined();
	});

	test('a recorder that does not start interrupts the run, tears down and releases', async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			r.healthy = false;
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toStartWith('recorder_unavailable:');
		expect(status.cleanup).toBe('succeeded');
		expect(await t.network.record(accepted.runId)).toBeUndefined();
		expect(t.record.lease).toBeUndefined();
	});

	test('a teardown that fails keeps the lease and reports the cleanup', async () => {
		const t = await setup();
		t.helper.revokeError = 'iptables is busy';
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toStartWith('teardown_failed:');
		expect(status.cleanup).toBe('failed');
		expect(status.readiness.reasons).toContain('cleanup failed');
		expect(t.calls.filter((c) => c.startsWith('release'))).toEqual([]);
		expect(t.record.lease?.holder).toBe(runLeaseHolder(accepted.runId));
		expect((await t.network.record(accepted.runId))?.state).toBe('destroying');
	});

	test('a write that fails at the deadline still tears the run down, ends it and records the failure', async () => {
		const t = await setup();
		// The time runs out as the first point closes, and every write fails
		// from the deadline event on: the save of the not-run marks is the
		// first to fail, outside any point.
		t.prepareRecorder((r) => {
			r.onClose = () => t.advance(700_000);
		});
		t.failing.writesFrom = 'run-deadline';
		const { accepted, status } = await t.runToEnd();
		expect(status.state).toBe('completed');
		expect(status.completion).toBe('finalize-failed');
		expect(status.outcome).toBe('incomplete');
		expect(status.points.map((p) => [p.state, p.outcome])).toEqual([
			['done', 'pass'],
			['done', 'not-run'],
			['done', 'not-run'],
		]);
		expect(status.problems.map((p) => p.code)).toEqual(
			expect.arrayContaining(['run_failed', 'finalize_failed']),
		);
		expect(status.problems.find((p) => p.code === 'run_failed')?.detail).toContain('ENOSPC');
		// The teardown ran all the same, and the lease went: nothing of the
		// run is on the box.
		expect(status.cleanup).toBe('succeeded');
		expect(t.record.lease).toBeUndefined();
		expect(await t.network.record(accepted.runId)).toBeUndefined();
		expect(t.docker.events.at(-1)).toBe(`removed network koi-v-${accepted.runId}`);
		// The run is over for admission too: once the disk takes writes
		// again, the label takes a new run.
		t.failing.writes = undefined;
		t.failing.writesFrom = undefined;
		const next = await t.run(await t.plan());
		expect(next.state).toBe('running');
		await t.verification.settled(next.runId);
	});

	test('a write that fails once at the deadline interrupts the run, and the bundle still finalizes', async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			r.onClose = () => t.advance(700_000);
		});
		// The disk is full from the deadline until the failure is recorded.
		t.failing.writesFrom = 'run-deadline';
		t.failing.writesUntilProblem = 'run_failed';
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toStartWith('run_failed: ENOSPC');
		expect(status.outcome).toBe('incomplete');
		expect(status.finalized).toBe(true);
		expect(status.problems.map((p) => p.code)).toContain('run_failed');
		expect(status.problems.find((p) => p.code === 'run_failed')?.detail).toContain('ENOSPC');
		expect(status.points.map((p) => p.outcome)).toEqual(['pass', 'not-run', 'not-run']);
		expect(status.cleanup).toBe('succeeded');
		expect(t.record.lease).toBeUndefined();
		expect(await t.network.record(accepted.runId)).toBeUndefined();
	});

	test("a setup that outlives the run's budget is torn down, and every point is not-run", async () => {
		const t = await setup();
		// The time runs out while the run network is being made.
		t.docker.onInspect = async () => t.advance(700_000);
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('evaluated');
		expect(status.outcome).toBe('incomplete');
		expect(status.points.map((p) => [p.outcome, p.reason?.startsWith('run_deadline')])).toEqual([
			['not-run', true],
			['not-run', true],
			['not-run', true],
		]);
		expect(status.executionDigest).toBeUndefined();
		// Nothing of the setup remains: the network went, no recorder was
		// started, the lease is released.
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
		expect(t.record.lease).toBeUndefined();
		expect(await t.network.record(accepted.runId)).toBeUndefined();
		expect(t.docker.events.filter((e) => e.startsWith('started '))).toEqual([]);
		expect(t.docker.events).toContain(`created network koi-v-${accepted.runId}`);
		expect(t.docker.events.at(-1)).toBe(`removed network koi-v-${accepted.runId}`);
		// The creation was given the run's budget as its signal.
		expect(t.docker.networkSignals).toHaveLength(1);
		expect(t.docker.networkSignals[0]).toBeInstanceOf(AbortSignal);
	});

	test("a recorder start that outlives the run's budget is rolled back, and is not a recorder failure", async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			const health = r.health.bind(r);
			r.health = async () => {
				t.advance(700_000);
				return health();
			};
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('evaluated');
		expect(status.outcome).toBe('incomplete');
		expect(status.problems).toEqual([]);
		expect(status.points.map((p) => p.reason?.startsWith('run_deadline'))).toEqual([
			true,
			true,
			true,
		]);
		expect(status.executionDigest).toBeUndefined();
		expect(status.cleanup).toBe('succeeded');
		expect(t.docker.events).toContain(`stopped koi-verify-${accepted.runId}-recorder`);
		expect(await t.network.record(accepted.runId)).toBeUndefined();
		expect(t.docker.networksMade.size).toBe(0);
		expect(t.record.lease).toBeUndefined();
	});

	test("a run waiting for the network lock stops at its budget's end, and its creation is never made", async () => {
		// A second of budget, in real time: the wait ends on the host's clock.
		const t = await setup({
			manifest: MANIFEST.replace('timeoutSeconds: 600', 'timeoutSeconds: 1'),
		});
		// Another run's creation holds the network lock at its first Docker call.
		const gate = new Gate();
		t.docker.onInspect = () => gate.pass();
		const other = t.network
			.create({
				runId: 'z'.repeat(20),
				appContainer: 'koi-other-app',
				appPort: 8080,
				recorderImage: RECORDER_IMAGE,
				verifierImage: RECORDER_IMAGE,
			})
			.catch(() => undefined);
		await gate.reached;
		const accepted = await t.run(await t.plan());
		// The points end as not-run while the lock is still held.
		for (;;) {
			const seen = await t.verification.status(accepted.runId);
			if (seen.progress.done === seen.progress.total) break;
			await Bun.sleep(25);
		}
		// The teardown waits behind the creation it might have to undo, and
		// the lease holds until it has. The pause gives a teardown that did
		// not wait the time to finish, so the check below would see it.
		await Bun.sleep(200);
		const waiting = await t.verification.status(accepted.runId);
		expect(waiting.state).toBe('running');
		expect(waiting.points.map((p) => p.outcome)).toEqual(['not-run', 'not-run', 'not-run']);
		expect(t.calls.filter((c) => c.startsWith('release'))).toEqual([]);
		expect(t.record.lease?.holder).toBe(runLeaseHolder(accepted.runId));
		gate.release();
		await other;
		await t.verification.settled(accepted.runId);
		const status = await t.verification.status(accepted.runId);
		expect(status.completion).toBe('evaluated');
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
		expect(t.record.lease).toBeUndefined();
		expect(t.docker.events).not.toContain(`created network koi-v-${accepted.runId}`);
		expect(await t.network.record(accepted.runId)).toBeUndefined();
		expect(
			t.logs.some((l) =>
				l.includes(
					`making the run network of ${accepted.runId}: failed after the run stopped waiting: the budget ended`,
				),
			),
		).toBe(true);
	});

	test('a recorder whose stop outlives the teardown allowance fails the cleanup and keeps the lease', async () => {
		// Real time: the allowance is a host timer.
		const t = await setup({ teardownAllowanceMs: 50 });
		t.docker.onStop = (name) =>
			name.endsWith('-recorder') ? new Promise<void>(() => {}) : undefined;
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toStartWith(
			`teardown_failed: stopping the recorder of ${accepted.runId} did not finish within`,
		);
		expect(status.cleanup).toBe('failed');
		expect(status.problems.map((p) => p.code)).toContain('teardown_failed');
		expect(t.calls.filter((c) => c.startsWith('release'))).toEqual([]);
		expect(t.record.lease?.holder).toBe(runLeaseHolder(accepted.runId));
		// The docker stop had the teardown's signal, which the allowance ended.
		expect(t.docker.stopSignals.at(-1)?.aborted).toBe(true);
	});

	test('a cancel that arrives while the bundle is finalized changes nothing and is answered with the final state', async () => {
		const t = await setup();
		let asked: Promise<RunStatusReply> | undefined;
		t.finalizing((runId) => {
			asked = t.verification.cancel(runId);
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('evaluated');
		expect(status.cancelRequested).toBe(false);
		const answer = await (asked as Promise<RunStatusReply>);
		expect([answer.state, answer.completion, answer.cancelRequested, answer.finalized]).toEqual([
			'completed',
			'evaluated',
			false,
			true,
		]);
		// The record on disk is the final one, as the manifest hashed it.
		const dir = t.evidence.runDir(accepted.runId);
		const bytes = await readFile(join(dir, 'controller.json'));
		const manifest = EvidenceManifestSchema.parse(
			JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')),
		);
		expect(manifest.files['controller.json']).toEqual({ sha256: sha(bytes), bytes: bytes.length });
		expect(RunControllerRecordSchema.parse(JSON.parse(bytes.toString())).cancelRequested).toBe(
			false,
		);
	});

	// A cancel asked for as the recorder's container stops, in the teardown:
	// the points are judged and nothing is frozen yet.
	const cancelDuringTeardown = (t: Awaited<ReturnType<typeof setup>>) => {
		const answers: RunStatusReply[] = [];
		t.docker.onStop = async (name) => {
			if (!name.endsWith('-recorder') || answers.length > 0) return;
			const runId = name.slice('koi-verify-'.length, -'-recorder'.length);
			answers.push(await t.verification.cancel(runId));
		};
		return answers;
	};

	test('a cancel that arrives during the teardown ends the run as cancelled, with no Result', async () => {
		const t = await setup();
		const answers = cancelDuringTeardown(t);
		const { accepted, status } = await t.runToEnd();
		// The answer said the cancel was taken, and the run keeps to it.
		expect([answers[0]?.state, answers[0]?.cancelRequested]).toEqual(['running', true]);
		expect([status.state, status.completion, status.outcome, status.cancelRequested]).toEqual([
			'cancelled',
			'cancelled',
			'incomplete',
			true,
		]);
		expect(status.finalized).toBe(true);
		expect(status.cleanup).toBe('succeeded');
		expect(status.points.map((p) => p.outcome)).toEqual(['pass', 'pass', 'pass']);
		expect(t.record.lease).toBeUndefined();
		// Every record says the same, the one the manifest hashed included.
		const dir = t.evidence.runDir(accepted.runId);
		expect(await stat(join(dir, 'result.json')).catch(() => undefined)).toBeUndefined();
		const stored = RunControllerRecordSchema.parse(
			JSON.parse(await readFile(join(dir, 'controller.json'), 'utf8')),
		);
		expect([stored.state, stored.completion]).toEqual(['cancelled', 'cancelled']);
		expect(RunSchema.parse(JSON.parse(await readFile(join(dir, 'run.json'), 'utf8'))).state).toBe(
			'cancelled',
		);
		const manifest = EvidenceManifestSchema.parse(
			JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')),
		);
		expect(manifest.status.state).toBe('cancelled');
	});

	test('a cancel during a teardown that fails ends the run interrupted, and keeps the lease', async () => {
		const t = await setup();
		cancelDuringTeardown(t);
		t.helper.revokeError = 'iptables is busy';
		const { accepted, status } = await t.runToEnd();
		expect([status.state, status.completion, status.cancelRequested]).toEqual([
			'completed',
			'interrupted',
			true,
		]);
		expect(status.interruption).toStartWith('teardown_failed:');
		expect(status.cleanup).toBe('failed');
		expect(t.record.lease?.holder).toBe(runLeaseHolder(accepted.runId));
	});

	test('a cancel during the teardown of a run whose manifest then fails keeps the cancelled state', async () => {
		const t = await setup();
		cancelDuringTeardown(t);
		t.failing.finalize = new Error('ENOSPC: no space left on device');
		const { status } = await t.runToEnd();
		expect([status.state, status.completion, status.outcome, status.cancelRequested]).toEqual([
			'cancelled',
			'finalize-failed',
			'incomplete',
			true,
		]);
	});

	test('what a failed creation left is taken down by the teardown, and the lease stays when that fails too', async () => {
		// The recorder is created with a mount koi did not ask for, so the
		// creation fails once the helper exists; its rollback fails at the
		// revoke and leaves the record destroying with the helper in place.
		const t = await setup();
		t.docker.helperMounts = [{ type: 'volume', destination: '/data' }];
		t.helper.revokeError = 'iptables is busy';
		t.helper.revokeOnce = true;
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toContain('mounts koi did not ask for');
		// The teardown found the record and the helper, and took them down.
		expect(status.cleanup).toBe('succeeded');
		expect(await t.network.record(accepted.runId)).toBeUndefined();
		expect(t.docker.containers.has(`koi-verify-${accepted.runId}-recorder`)).toBe(false);
		expect(t.docker.networksMade.size).toBe(0);
		expect(t.record.lease).toBeUndefined();

		// When the second attempt fails as well, nothing is released.
		const u = await setup();
		u.docker.helperMounts = [{ type: 'volume', destination: '/data' }];
		u.helper.revokeError = 'iptables is busy';
		const again = await u.runToEnd();
		expect(again.status.completion).toBe('interrupted');
		expect(again.status.interruption).toContain('mounts koi did not ask for');
		expect(again.status.cleanup).toBe('failed');
		expect(again.status.problems.map((p) => p.code)).toContain('teardown_failed');
		expect((await u.network.record(again.accepted.runId))?.state).toBe('destroying');
		expect(u.docker.containers.has(`koi-verify-${again.accepted.runId}-recorder`)).toBe(true);
		expect(u.calls.filter((c) => c.startsWith('release'))).toEqual([]);
		expect(u.record.lease?.holder).toBe(runLeaseHolder(again.accepted.runId));
	});

	test('helpers and a network the run left without a record are found, and the lease waits for them', async () => {
		// A creation that dies part way, with no record: only what is on
		// Docker says the run was here.
		const leaveHelper = (t: Awaited<ReturnType<typeof setup>>, stuck: boolean) => {
			t.network.create = async ({ runId }) => {
				const network = runNetworkName(runId);
				const name = helperName(runId, 'recorder');
				await t.docker.createNetwork({
					name: network,
					bridge: 'koi-v-left',
					subnet: '10.213.0.0/28',
					gateway: '10.213.0.1',
					labels: { 'koi.run': runId },
				});
				await t.docker.createRecorder({
					name,
					image: RECORDER_IMAGE,
					network,
					ip: '10.213.0.3',
					mac: '02:00:0a:d5:00:03',
					runId,
					appHost: { name: `app.${runId}.invalid`, ip: '10.213.0.2' },
					dns: '10.213.0.1',
					env: {},
				});
				if (stuck) t.docker.unremovable.add(name);
				throw new Error('the box went away part way');
			};
		};
		const t = await setup();
		leaveHelper(t, false);
		const { accepted, status } = await t.runToEnd();
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toContain('the box went away part way');
		expect(status.problems.map((p) => p.code)).toEqual(['run_failed']);
		expect(status.cleanup).toBe('succeeded');
		expect(t.docker.containers.has(helperName(accepted.runId, 'recorder'))).toBe(false);
		expect(t.docker.networksMade.size).toBe(0);
		expect(t.record.lease).toBeUndefined();

		// When the helper cannot be removed, nothing is released.
		const u = await setup();
		leaveHelper(u, true);
		const again = await u.runToEnd();
		expect(again.status.cleanup).toBe('failed');
		expect(again.status.problems.map((p) => p.code)).toContain('teardown_failed');
		expect(u.docker.containers.has(helperName(again.accepted.runId, 'recorder'))).toBe(true);
		expect(u.calls.filter((c) => c.startsWith('release'))).toEqual([]);
		expect(u.record.lease?.holder).toBe(runLeaseHolder(again.accepted.runId));
	});

	test('a run that never reached its network does not wait on the lock another run holds', async () => {
		const t = await setup();
		const gate = new Gate();
		t.docker.onInspect = () => gate.pass();
		const other = t.network
			.create({
				runId: 'z'.repeat(20),
				appContainer: 'koi-other-app',
				appPort: 8080,
				recorderImage: RECORDER_IMAGE,
				verifierImage: RECORDER_IMAGE,
			})
			.catch(() => undefined);
		await gate.reached;
		// The lease is good for the admission and gone by the time the run
		// begins, so the run stops before it asks for a network.
		const leased = t.deployer.leasedDeployment.bind(t.deployer);
		let asked = 0;
		t.deployer.leasedDeployment = async (label, leaseId) => {
			asked += 1;
			if (asked === 2) throw new NoSuchLeaseError('no such lease');
			return leased(label, leaseId);
		};
		// Settles with the lock still held.
		const { status } = await t.runToEnd();
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toStartWith('lease_lost:');
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
		expect(t.record.lease).toBeUndefined();
		gate.release();
		await other;
	});

	test('a run whose every write fails is finalize-failed in memory, not what its stale record says', async () => {
		const t = await setup();
		const gate = new Gate();
		t.prepareRecorder((r) => {
			r.captureGate = gate;
		});
		const plan = await t.plan();
		const accepted = await t.run(plan);
		await gate.reached;
		t.failing.writes = new Error('ENOSPC: no space left on device');
		const recorder = t.recorders.get(accepted.runId);
		if (recorder !== undefined) recorder.captureGate = undefined;
		gate.release();
		await t.verification.settled(accepted.runId);
		const status = await t.verification.status(accepted.runId);
		expect(status.state).toBe('completed');
		expect(status.completion).toBe('finalize-failed');
		expect(status.outcome).toBe('incomplete');
		expect(status.finalized).toBe(false);
		expect(status.evidence).toBe('incomplete');
		expect(status.interruption).toStartWith('finalize_failed:');
		expect(status.problems.map((p) => p.code)).toContain('finalize_failed');
		expect(status.readiness.eligibleForMergeGate).toBe(false);
		expect(status.cleanup).toBe('succeeded');
		expect(t.record.lease).toBeUndefined();
		// The record on disk is the last that could be written, a running
		// run; no reader is shown it.
		const dir = t.evidence.runDir(accepted.runId);
		const stored = RunControllerRecordSchema.parse(
			JSON.parse(await readFile(join(dir, 'controller.json'), 'utf8')),
		);
		expect(stored.state).toBe('running');
		expect(await stat(join(dir, 'manifest.json')).catch(() => undefined)).toBeUndefined();
		const evidence = await t.verification.evidence(accepted.runId);
		expect(evidence.finalized).toBe(false);
		expect(evidence.status.evidence).toBe('incomplete');
		expect((await t.verification.cancel(accepted.runId)).completion).toBe('finalize-failed');
		expect(t.logs.some((l) => l.includes('kept in memory until koid restarts'))).toBe(true);
	});

	test('a terminal record already on disk is not what a reader gets when the finalize and its fallback both fail', async () => {
		const t = await setup();
		// The disk fills as the manifest is written: the terminal record went
		// in just before, and the finalize-failed record cannot replace it.
		t.finalizing(() => {
			t.failing.writes = new Error('ENOSPC: no space left on device');
		});
		const { accepted, status } = await t.runToEnd();
		const dir = t.evidence.runDir(accepted.runId);
		const stored = RunControllerRecordSchema.parse(
			JSON.parse(await readFile(join(dir, 'controller.json'), 'utf8')),
		);
		expect([stored.state, stored.completion]).toEqual(['completed', 'evaluated']);
		expect(status.completion).toBe('finalize-failed');
		expect(status.outcome).toBe('incomplete');
		expect(status.finalized).toBe(false);
		expect(status.evidence).toBe('incomplete');
		expect(status.interruption).toStartWith('finalize_failed: ENOSPC');
		expect(status.readiness.eligibleForMergeGate).toBe(false);
		// The label is free: the run is over, its lease went, and only its
		// record could not be written.
		expect(t.record.lease).toBeUndefined();
		t.failing.writes = undefined;
		t.finalizing(() => {});
		const next = await t.run(await t.plan());
		await t.verification.settled(next.runId);
		expect((await t.verification.status(next.runId)).finalized).toBe(true);
		// The new run changes nothing for the old one.
		expect((await t.verification.status(accepted.runId)).completion).toBe('finalize-failed');
	});

	test('a status read while the lease is released is the final one, not a failed finalize', async () => {
		const t = await setup();
		let runId = '';
		t.finalizing((id) => {
			runId = id;
		});
		const release = t.deployer.releaseLease.bind(t.deployer);
		let during: RunStatusReply | undefined;
		let evidenceFinalized: boolean | undefined;
		t.deployer.releaseLease = async (label, leaseId) => {
			during = await t.verification.status(runId);
			evidenceFinalized = (await t.verification.evidence(runId)).finalized;
			return release(label, leaseId);
		};
		const { status } = await t.runToEnd();
		expect(status.completion).toBe('evaluated');
		expect(status.finalized).toBe(true);
		expect(during).toEqual(status);
		expect(evidenceFinalized).toBe(true);
	});

	test('a record that says the run ended, without the manifest that ends one, is reported as finalize-failed', async () => {
		const t = await setup();
		const { accepted } = await t.runToEnd();
		const dir = t.evidence.runDir(accepted.runId);
		// However the record came to say evaluated with no manifest beside
		// it, the run is not finished.
		await rm(join(dir, 'manifest.json'));
		const status = await t.verification.status(accepted.runId);
		expect([
			status.state,
			status.completion,
			status.outcome,
			status.finalized,
			status.evidence,
		]).toEqual(['completed', 'finalize-failed', 'incomplete', false, 'incomplete']);
		expect(status.interruption).toBe('finalize_failed: the manifest was not written');
		expect(status.readiness).toEqual({
			eligibleForMergeGate: false,
			reasons: ['the run was not finalized: its manifest was not written'],
		});
	});

	test("a recorder lost in the teardown's last read of its events interrupts the run as recorder_lost", async () => {
		const t = await setup();
		let closes = 0;
		t.prepareRecorder((r) => {
			r.onClose = () => {
				// After the last point's close and its drain: the recorder stops
				// answering before the teardown reads its events one last time.
				if (++closes === 3) {
					r.eventsError = new RecorderError(0, 'unreachable', 'the recorder did not answer: reset');
					r.eventsFailFrom = r.eventsCalls + 2;
				}
			};
		});
		const { status } = await t.runToEnd();
		expect(status.points.map((p) => p.outcome)).toEqual(['pass', 'pass', 'pass']);
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toStartWith(
			'recorder_lost: reading events: the recorder did not answer: reset',
		);
		expect(status.outcome).toBe('incomplete');
		expect(status.problems.map((p) => p.code)).toContain('observation_gap');
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
	});

	test("a connection that drops after the headers of the teardown's last read is recorder_lost too", async () => {
		const t = await setup();
		// The real client over a reply whose body fails, as a dropped socket's does.
		const dropped = httpRecorder(
			'http://10.0.0.2:4318',
			'token',
			(async () =>
				new Response(
					new ReadableStream<Uint8Array>({
						start(controller) {
							controller.error(new Error('socket hang up'));
						},
					}),
					{ status: 200 },
				)) as unknown as typeof fetch,
		);
		let closes = 0;
		let readsSince = 0;
		t.prepareRecorder((r) => {
			const events = r.events.bind(r);
			r.onClose = () => {
				closes += 1;
			};
			// Past the last close: its own drain, then the teardown's.
			r.events = async (after, limit, options) => {
				if (closes === 3 && ++readsSince === 2) {
					return dropped.events(after, limit ?? 500, options);
				}
				return events(after);
			};
		});
		const { status } = await t.runToEnd();
		expect(status.points.map((p) => p.outcome)).toEqual(['pass', 'pass', 'pass']);
		expect(status.completion).toBe('interrupted');
		expect(status.interruption).toBe(
			'recorder_lost: reading events: the recorder stopped sending: socket hang up',
		);
		expect(status.outcome).toBe('incomplete');
		expect(status.problems.map((p) => p.code)).toContain('observation_gap');
		expect(status.cleanup).toBe('succeeded');
		expect(status.finalized).toBe(true);
	});

	test('a helper of an earlier run refuses a new run after a redeploy, whatever its network record names', async () => {
		const t = await setup();
		t.helper.revokeError = 'iptables is busy';
		// A run of blocked points never replaces the placeholder verifier, so
		// the helper outlives the failed teardown.
		const first = await t.runToEnd('matrix');
		expect(first.status.cleanup).toBe('failed');
		t.helper.revokeError = undefined;
		// The preview is redeployed under another container. The old record
		// names the old one; the helper is still there and can reach the app.
		const replacement = `koi-${LABEL}-bbbbbbbbbbbbbbbb2`;
		await t.docker.run({
			name: replacement,
			image: 'koi-preview/hello:2',
			network: 'koi-previews',
			user: '65534:65534',
			env: {},
			labels: { 'koi.preview': LABEL, 'koi.request': 'bbbbbbbbbbbbbbbb2' },
		});
		(t.record.deployment as NonNullable<PreviewRecord['deployment']>).container = replacement;
		t.advance(3_600_000);
		const err = await refusal(t.run(await t.plan()));
		expect([err.status, err.code, err.retryable]).toEqual([409, 'preview_busy', true]);
		expect(err.message).toContain(
			`koi-verify-${first.accepted.runId}-verifier, the verifier of run ${first.accepted.runId}, still exists`,
		);
		expect(t.record.lease).toBeUndefined();
	});

	test('an artifact tampered with on disk is a problem on the run and no evidence of the point', async () => {
		const t = await setup();
		let tampered = false;
		t.prepareRecorder((r) => {
			// As the first point closes, its screenshot is on disk and not yet
			// judged: its bytes are replaced.
			r.onClose = async () => {
				if (tampered) return;
				tampered = true;
				await writeFile(
					join(t.evidence.runDir(r.runId), 'artifacts', 'recorder:screenshot:1'),
					PNG_STRIPPED.subarray(0, PNG_STRIPPED.length - 1),
				);
			};
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.points[0]?.evidence).toEqual(['recorder:aria:2', 'recorder:http-response:3']);
		expect(status.points[0]?.outcome).toBe('fail');
		expect(status.points[0]?.reason).toStartWith('corrupt_evidence: recorder:screenshot:1,');
		expect(status.points[1]?.evidence).toEqual([
			'recorder:screenshot:4',
			'recorder:aria:5',
			'recorder:http-response:6',
		]);
		expect(status.points[1]?.outcome).toBe('pass');
		const problem = status.problems.find((p) => p.code === 'artifact_corrupt');
		expect(problem?.detail).toBe(
			'recorder:screenshot:1: the file on disk is not the size and sha256 its entry records',
		);
		expect(status.completion).toBe('capture-error');
		expect(status.evidence).toBe('incomplete');
		// The entry stays in the manifest as the capture was made; the
		// bytes beside it are not it.
		const manifest = EvidenceManifestSchema.parse(
			JSON.parse(await readFile(join(t.evidence.runDir(accepted.runId), 'manifest.json'), 'utf8')),
		);
		expect(manifest.artifacts).toHaveLength(9);
	});

	test('an artifact gone from disk is a problem on the run and no evidence of the point', async () => {
		const t = await setup();
		let removed = false;
		t.prepareRecorder((r) => {
			r.onClose = async () => {
				if (removed) return;
				removed = true;
				await rm(join(t.evidence.runDir(r.runId), 'artifacts', 'recorder:aria:2'));
			};
		});
		const { status } = await t.runToEnd();
		expect(status.points[0]?.evidence).toEqual([
			'recorder:screenshot:1',
			'recorder:http-response:3',
		]);
		expect(status.points[0]?.outcome).toBe('fail');
		expect(status.points[0]?.reason).toStartWith('missing_evidence: recorder:aria:2,');
		const problem = status.problems.find((p) => p.code === 'artifact_missing');
		expect(problem?.detail).toBe('recorder:aria:2: its file is no longer on disk');
		expect(status.completion).toBe('capture-error');
	});

	test('a file that changes after its own point was judged fails that point at the final check', async () => {
		const t = await setup();
		let closes = 0;
		t.prepareRecorder((r) => {
			r.onClose = async () => {
				// As the third point closes, the first two are judged and saved.
				if (++closes !== 3) return;
				const artifacts = join(t.evidence.runDir(r.runId), 'artifacts');
				await writeFile(join(artifacts, 'recorder:screenshot:1'), PNG_STRIPPED.subarray(1));
				await rm(join(artifacts, 'recorder:aria:5'));
			};
		});
		const { accepted, status } = await t.runToEnd();
		expect(status.points.map((p) => [p.id, p.outcome, p.evidence])).toEqual([
			['hello.home', 'fail', ['recorder:aria:2', 'recorder:http-response:3']],
			['app.always', 'fail', ['recorder:screenshot:4', 'recorder:http-response:6']],
			[
				'app.search',
				'pass',
				['recorder:screenshot:7', 'recorder:aria:8', 'recorder:http-response:9'],
			],
		]);
		expect(status.points[0]?.reason).toBe(
			'corrupt_evidence: recorder:screenshot:1, whose bytes do not hash to the manifest',
		);
		expect(status.points[1]?.reason).toBe(
			'missing_evidence: recorder:aria:5, whose bytes are not on disk',
		);
		expect(status.points[2]?.reason).toBeUndefined();
		expect(status.problems.map((p) => p.code)).toEqual(['artifact_corrupt', 'artifact_missing']);
		expect([status.completion, status.outcome, status.evidence]).toEqual([
			'capture-error',
			'incomplete',
			'incomplete',
		]);
		expect(status.finalized).toBe(true);
		// Every record of the run says so.
		const dir = t.evidence.runDir(accepted.runId);
		expect(await stat(join(dir, 'result.json')).catch(() => undefined)).toBeUndefined();
		const stored = RunControllerRecordSchema.parse(
			JSON.parse(await readFile(join(dir, 'controller.json'), 'utf8')),
		);
		expect(stored.points[0]?.outcome).toBe('fail');
		const observed = JSON.parse(
			await readFile(join(dir, 'points/hello.home/observations.json'), 'utf8'),
		) as { verdict: { outcome: string; evidence: string[] }; assertions: string[] };
		expect(observed.verdict.outcome).toBe('fail');
		expect(observed.verdict.evidence).toEqual(['recorder:aria:2', 'recorder:http-response:3']);
		expect(observed.assertions).toEqual(['home-says-hello']);
		expect(await readFile(join(dir, 'report.md'), 'utf8')).toContain('| hello.home | fail |');
		const manifest = EvidenceManifestSchema.parse(
			JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')),
		);
		expect(manifest.status.evidence).toBe('incomplete');
	});

	test('the final check comes after the teardown, and whatever else ended the run', async () => {
		const t = await setup();
		let done = false;
		t.docker.onStop = async (name) => {
			if (done || !name.endsWith('-recorder')) return;
			done = true;
			const runId = name.slice('koi-verify-'.length, -'-recorder'.length);
			await t.verification.cancel(runId);
			await writeFile(
				join(t.evidence.runDir(runId), 'artifacts', 'recorder:aria:8'),
				'heading "not what was captured"\n',
			);
		};
		const { status } = await t.runToEnd();
		expect(status.completion).toBe('cancelled');
		expect(status.points[2]?.outcome).toBe('fail');
		expect(status.points[2]?.evidence).toEqual([
			'recorder:screenshot:7',
			'recorder:http-response:9',
		]);
		expect(status.problems.map((p) => p.code)).toEqual(['artifact_corrupt']);
		expect(status.evidence).toBe('incomplete');
	});

	test('a capture that changes as the run reaches its deadline fails the point, not only not-run', async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			const capture = r.capture.bind(r);
			let captures = 0;
			r.capture = async (contextId, request, options) => {
				if (++captures === 2) {
					await rm(join(t.evidence.runDir(r.runId), 'artifacts', 'recorder:screenshot:1'));
					t.advance(610_000);
				}
				return capture(contextId, request, options);
			};
		});
		const { status } = await t.runToEnd();
		expect(status.points[0]?.outcome).toBe('fail');
		expect(status.points[0]?.evidence).toEqual([]);
		expect(status.points[0]?.reason).toStartWith('missing_evidence: recorder:screenshot:1,');
		expect(status.points[0]?.reason).toContain('point_timeout');
		expect(status.points.slice(1).map((p) => p.outcome)).toEqual(['not-run', 'not-run']);
	});

	test('status reports stale once another deployment serves the label', async () => {
		const t = await setup();
		const { accepted } = await t.runToEnd();
		t.record.deployment = {
			...(t.record.deployment as NonNullable<PreviewRecord['deployment']>),
			deploymentId: 'e'.repeat(20),
		};
		expect((await t.verification.status(accepted.runId)).freshness).toBe('stale');
		delete t.record.deployment;
		expect((await t.verification.status(accepted.runId)).freshness).toBe('stale');
	});

	test('once its evidence has expired, a run still answers its status and verdict, and its artifacts 410', async () => {
		const t = await setup();
		const { accepted } = await t.runToEnd();
		t.advance(31 * 86_400_000);
		expect((await t.evidence.sweep()).expired).toEqual([accepted.runId]);
		const status = await t.verification.status(accepted.runId);
		expect([status.state, status.completion, status.outcome, status.finalized]).toEqual([
			'completed',
			'evaluated',
			'passed',
			true,
		]);
		const evidence = await t.verification.evidence(accepted.runId);
		expect(evidence.expired).toBe(true);
		expect(evidence.artifacts).toEqual([]);
		// Three points, each a screenshot, an aria snapshot and a state read.
		expect(evidence.artifactCount).toBe(9);
		const gone = await refusal(t.verification.artifact(accepted.runId, 'recorder:screenshot:1'));
		expect([gone.status, gone.code]).toEqual([410, 'evidence_expired']);
		const events = await refusal(t.verification.events(accepted.runId));
		expect([events.status, events.code]).toEqual([410, 'evidence_expired']);
	});

	test('status, events, evidence and artifacts refuse an unknown run', async () => {
		const t = await setup();
		for (const read of [
			() => t.verification.status('z'.repeat(20)),
			() => t.verification.events('z'.repeat(20)),
			() => t.verification.evidence('z'.repeat(20)),
			() => t.verification.artifact('z'.repeat(20), 'recorder:screenshot:1'),
		]) {
			const err = await refusal(read());
			expect([err.status, err.code]).toEqual([404, 'no_such_run']);
		}
	});
});

describe('reading a run', () => {
	test('events page by sequence and by count, under the bound', async () => {
		const t = await setup();
		const { accepted } = await t.runToEnd();
		const first = await t.verification.events(accepted.runId, 0, 3);
		expect(first.events.map((e) => e.seq)).toEqual([1, 2, 3]);
		expect(first.events[0]?.type).toBe('run-started');
		expect(first.next).toBe(3);
		expect(first.more).toBe(true);
		const rest = await t.verification.events(accepted.runId, first.next);
		expect(rest.events[0]?.seq).toBe(4);
		expect(rest.more).toBe(false);
		expect(rest.events.map((e) => e.type)).toContain('runner-assertion');
		expect(rest.events.at(-1)?.type).toBe('recorder-stopped');
		expect(Buffer.byteLength(JSON.stringify(rest))).toBeLessThanOrEqual(
			VERIFICATION_REPLY_MAX_BYTES,
		);
		const past = await t.verification.events(accepted.runId, 10_000);
		expect(past).toEqual({
			version: 1,
			runId: accepted.runId,
			events: [],
			next: 10_000,
			more: false,
		});
	});

	test('evidence gives the manifest and pages the artifacts', async () => {
		const t = await setup();
		const { accepted } = await t.runToEnd();
		const evidence = await t.verification.evidence(accepted.runId);
		expect(evidence.finalized).toBe(true);
		expect(evidence.expired).toBe(false);
		expect(evidence.artifactCount).toBe(9);
		expect(evidence.artifacts.map((a) => a.id)).toEqual([
			'recorder:screenshot:1',
			'recorder:aria:2',
			'recorder:http-response:3',
			'recorder:screenshot:4',
			'recorder:aria:5',
			'recorder:http-response:6',
			'recorder:screenshot:7',
			'recorder:aria:8',
			'recorder:http-response:9',
		]);
		expect(evidence.retention?.retainedUntil).toBeDefined();
		expect(evidence.events?.count).toBeGreaterThan(0);
		expect(evidence.limitations[0]).toContain('cannot be certified secret-free');
		const second = await t.verification.evidence(accepted.runId, 7);
		expect(second.artifacts.map((a) => a.id)).toEqual([
			'recorder:aria:8',
			'recorder:http-response:9',
		]);
	});

	test('evidence before finalization says so, with the status and no artifacts', async () => {
		const t = await setup();
		const gate = new Gate();
		t.prepareRecorder((r) => {
			r.captureGate = gate;
		});
		const plan = await t.plan();
		const accepted = await t.run(plan);
		await gate.reached;
		const evidence = await t.verification.evidence(accepted.runId);
		expect(evidence.finalized).toBe(false);
		expect(evidence.status.state).toBe('running');
		expect(evidence.artifacts).toEqual([]);
		const err = await refusal(t.verification.artifact(accepted.runId, 'recorder:screenshot:1'));
		expect([err.status, err.code, err.retryable]).toEqual([409, 'not_finalized', true]);
		const recorder = t.recorders.get(accepted.runId);
		if (recorder !== undefined) recorder.captureGate = undefined;
		gate.release();
		await t.verification.settled(accepted.runId);
	});

	test('an artifact comes back in bounded chunks that reassemble to the manifest hash', async () => {
		const t = await setup();
		const line = `${'x'.repeat(99)}\n`;
		t.prepareRecorder((r) => {
			r.ariaText = line.repeat(200);
		});
		const { accepted } = await t.runToEnd();
		const entry = (await t.verification.evidence(accepted.runId)).artifacts.find(
			(a) => a.id === 'recorder:aria:2',
		);
		expect(entry?.size).toBe(20_000);
		const first = await t.verification.artifact(accepted.runId, 'recorder:aria:2');
		expect(first.offset).toBe(0);
		expect(first.length).toBe(6 * 1024);
		expect(first.next).toBe(6 * 1024);
		expect(first.truncated).toBe(true);
		expect(first.note).toContain('needs the channel (C2)');
		expect(Buffer.byteLength(JSON.stringify(first))).toBeLessThanOrEqual(
			VERIFICATION_REPLY_MAX_BYTES,
		);
		const hash = createHash('sha256');
		let offset: number | undefined = 0;
		let chunks = 0;
		while (offset !== undefined) {
			const chunk = await t.verification.artifact(
				accepted.runId,
				'recorder:aria:2',
				offset,
				100_000,
			);
			expect(chunk.length).toBeLessThanOrEqual(6 * 1024);
			hash.update(Buffer.from(chunk.dataBase64, 'base64'));
			offset = chunk.next;
			chunks += 1;
		}
		expect(chunks).toBe(4);
		expect(`sha256:${hash.digest('hex')}`).toBe(entry?.sha256 as string);
		const last = await t.verification.artifact(accepted.runId, 'recorder:aria:2', 20_000);
		expect([last.length, last.truncated, last.next]).toEqual([0, false, undefined]);
		const past = await refusal(t.verification.artifact(accepted.runId, 'recorder:aria:2', 20_001));
		expect(past.code).toBe('bad_offset');
		const missing = await refusal(t.verification.artifact(accepted.runId, 'recorder:aria:99'));
		expect([missing.status, missing.code]).toEqual([404, 'no_such_artifact']);
	});

	test('a withheld artifact has no bytes to read, and the point keeps only what was kept', async () => {
		const t = await setup();
		t.prepareRecorder((r) => {
			r.badPng = true;
		});
		const { accepted, status } = await t.runToEnd();
		// Withheld is not a problem on the run: the evidence is complete and
		// the point simply has less of it. The runner's screenshot came back
		// failed, so it cited the rest.
		expect(status.completion).toBe('evaluated');
		expect(status.points[0]?.outcome).toBe('pass');
		expect(status.points[0]?.evidence).toEqual(['recorder:aria:2', 'recorder:http-response:3']);
		const entry = (await t.verification.evidence(accepted.runId)).artifacts[0];
		expect(entry?.availability).toBe('withheld');
		const err = await refusal(t.verification.artifact(accepted.runId, 'recorder:screenshot:1'));
		expect([err.status, err.code]).toEqual([409, 'artifact_unavailable']);
		expect(err.message).toContain('withheld');
	});

	test('status pages the points under the bound', async () => {
		const files: Record<string, string> = {};
		for (let i = 0; i < 60; i++) {
			files[`p${i}.yaml`] = POINTS['always.yaml']?.replace('id: app.always', `id: app.p${i}`) ?? '';
		}
		const t = await setup({
			files,
			manifest: MANIFEST.replace('always: [hello.home]', 'always: []').replace(
				'include: [app.llm]',
				'include: []',
			),
		});
		const plan = await t.plan();
		expect(plan.points).toHaveLength(60);
		// Every point fails with a long reason, so the points outgrow a reply.
		t.docker.verifierScript = runner(
			declared(files),
			() => 'fail',
			(name) => `${name}: ${'the page said something else '.repeat(20)}`,
		);
		const accepted = await t.run(plan);
		await t.verification.settled(accepted.runId);
		const first = await t.verification.status(accepted.runId);
		expect(Buffer.byteLength(JSON.stringify(first))).toBeLessThanOrEqual(
			VERIFICATION_REPLY_MAX_BYTES,
		);
		expect(first.next).toBeGreaterThan(0);
		expect(first.progress).toEqual({ total: 60, done: 60 });
		const all = [...first.points];
		let next = first.next;
		while (next !== undefined) {
			const page = await t.verification.status(accepted.runId, next);
			all.push(...page.points);
			next = page.next;
		}
		expect(all).toHaveLength(60);
	}, 30_000);
});

describe('bounded replies', () => {
	const STORED = 'q'.repeat(20);
	// A character JSON escapes to six bytes, so a string of 2000 of them is
	// 12 KiB once serialized: the worst a bounded field can be.
	const C1 = '\u0001';
	const bytes = (value: unknown) => Buffer.byteLength(JSON.stringify(value));

	// A finished run written to disk as the controller would leave it, with
	// whatever the test makes as large as the schemas allow.
	async function stored(
		t: Awaited<ReturnType<typeof setup>>,
		shape: {
			points?: RunControllerRecord['points'];
			readinessReasons?: string[];
			interruption?: string;
			problems?: RunStatus['problems'];
			artifacts?: Artifact[];
			limitations?: string[];
		},
	) {
		const plan = await t.plan();
		const dir = t.evidence.runDir(STORED);
		const pending = join(dir, '.pending');
		await mkdir(pending, { recursive: true, mode: 0o700 });
		const problems = shape.problems ?? [];
		const controller: RunControllerRecord = RunControllerRecordSchema.parse({
			version: 1,
			runId: STORED,
			planId: plan.planId,
			planDigest: plan.planDigest,
			label: LABEL,
			deployment: t.identity,
			profile: 'pr',
			advisory: false,
			state: 'completed',
			completion: 'interrupted',
			outcome: 'incomplete',
			...(shape.interruption !== undefined ? { interruption: shape.interruption } : {}),
			cancelRequested: false,
			points: shape.points ?? [],
			uncovered: [],
			policy: { source: 'none' },
			limits: plan.limits,
			lease: { leaseId: 'l'.repeat(20), expiresAt: AT },
			readiness: { eligibleForMergeGate: false, reasons: shape.readinessReasons ?? [] },
			freshness: 'current',
			cleanup: 'succeeded',
			startedAt: AT,
			finishedAt: AT,
			updatedAt: AT,
		});
		const status: RunStatus = RunStatusSchema.parse({
			version: 1,
			runId: STORED,
			state: 'completed',
			evidence: problems.length === 0 ? 'complete' : 'incomplete',
			startedAt: AT,
			updatedAt: AT,
			finishedAt: AT,
			counts: { events: 0, artifacts: shape.artifacts?.length ?? 0, bytes: 0 },
			problems,
		});
		const manifest: EvidenceManifest = EvidenceManifestSchema.parse({
			version: 1,
			runId: STORED,
			status,
			artifacts: shape.artifacts ?? [],
			events: { count: 0, bytes: 0, sha256: sha('') },
			files: {},
			limitations: shape.limitations ?? [],
			finalizedAt: AT,
			retainedUntil: AT,
			tombstoneUntil: AT,
		});
		const json = (v: unknown) => `${JSON.stringify(v)}\n`;
		await writeAtomic(join(dir, 'controller.json'), json(controller), pending);
		await writeAtomic(join(dir, 'status.json'), json(status), pending);
		await writeAtomic(join(dir, 'manifest.json'), json(manifest), pending);
		return dir;
	}

	test('status stays under the bound with every field at its largest, and pages every point', async () => {
		const t = await setup();
		const points: RunControllerRecord['points'] = Array.from({ length: 40 }, (_, i) => ({
			id: `app.p${i}`,
			state: 'done',
			outcome: 'fail',
			reason: C1.repeat(2000),
			evidence: Array.from({ length: 200 }, (_, j) => `recorder:http-response:${j + 1}`),
		}));
		await stored(t, {
			points,
			readinessReasons: Array.from({ length: 50 }, () => 'r'.repeat(500)),
			interruption: C1.repeat(2000),
			problems: Array.from({ length: 1000 }, () => ({
				code: 'capture_failed',
				detail: C1.repeat(2000),
				at: AT,
			})),
		});
		const first = await t.verification.status(STORED);
		expect(bytes(first)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
		expect(first.problemCount).toBe(1000);
		expect(first.truncated).toEqual(
			expect.arrayContaining(['readiness.reasons', 'problems', 'interruption']),
		);
		expect(first.truncated).toContain('points[app.p0].reason');
		expect(first.points.length).toBeGreaterThan(0);
		const all = [...first.points];
		let next = first.next;
		let pages = 1;
		while (next !== undefined) {
			const page = await t.verification.status(STORED, next);
			expect(bytes(page)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
			expect(page.next === undefined || page.next > next).toBe(true);
			all.push(...page.points);
			next = page.next;
			pages += 1;
		}
		expect(all.map((p) => p.id)).toEqual(points.map((p) => p.id));
		expect(pages).toBeGreaterThan(1);
		// The records on disk are whole; only the reply was cut.
		const onDisk = RunControllerRecordSchema.parse(
			JSON.parse(await readFile(join(t.evidence.runDir(STORED), 'controller.json'), 'utf8')),
		);
		expect(onDisk.points[0]?.reason).toBe(C1.repeat(2000));
	});

	test('evidence stays under the bound with the largest status, limitations and entries, and pages every artifact', async () => {
		const t = await setup();
		const artifacts: Artifact[] = Array.from({ length: 30 }, (_, i) => ({
			id: `recorder:aria:${i + 1}`,
			runId: STORED,
			pointId: 'app.p',
			attempt: 1,
			kind: 'aria',
			mediaType: 'text/plain',
			size: 0,
			sha256: sha(''),
			origin: 'recorder',
			capturedAt: AT,
			eventRange: { first: 1, last: 1 },
			redaction: {
				status: 'sanitized',
				policyDigest: sha('policy'),
				removedFields: Array.from({ length: 1000 }, (_, j) => `field-${j}-${'f'.repeat(190)}`),
				limitations: Array.from({ length: 50 }, () => 'l'.repeat(500)),
			},
			availability: 'available',
			retainedUntil: AT,
		}));
		await stored(t, {
			artifacts,
			limitations: Array.from({ length: 50 }, () => 'm'.repeat(500)),
			problems: Array.from({ length: 1000 }, () => ({
				code: 'capture_failed',
				detail: C1.repeat(2000),
				at: AT,
			})),
		});
		const first = await t.verification.evidence(STORED);
		expect(bytes(first)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
		expect(first.artifactCount).toBe(30);
		expect(first.truncated).toEqual(expect.arrayContaining(['status.problems', 'limitations']));
		expect(first.truncated).toContain('artifacts[recorder:aria:1].redaction.removedFields');
		const all = [...first.artifacts];
		let next = first.next;
		while (next !== undefined) {
			const page = await t.verification.evidence(STORED, next);
			expect(bytes(page)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
			expect(page.next === undefined || page.next > next).toBe(true);
			all.push(...page.artifacts);
			next = page.next;
		}
		expect(all.map((a) => a.id)).toEqual(artifacts.map((a) => a.id));
		// An entry keeps its identity, hash and availability whole.
		expect(all[0]).toMatchObject({
			id: 'recorder:aria:1',
			sha256: sha(''),
			availability: 'available',
		});
	});

	test('events of the largest size page under the bound, one at a time', async () => {
		const t = await setup();
		const dir = await stored(t, {});
		const lines = Array.from({ length: 5 }, (_, i) =>
			JSON.stringify({ seq: i + 1, at: AT, source: 'host', type: 'big', text: 'x'.repeat(12_000) }),
		);
		await writeFile(join(dir, 'events.ndjson'), `${lines.join('\n')}\n`);
		const seen: number[] = [];
		let after = 0;
		for (;;) {
			const page = await t.verification.events(STORED, after);
			expect(bytes(page)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
			expect(page.events).toHaveLength(1);
			seen.push(...page.events.map((e) => e.seq));
			if (!page.more) break;
			expect(page.next).toBeGreaterThan(after);
			after = page.next;
		}
		expect(seen).toEqual([1, 2, 3, 4, 5]);
	});

	test('a plan with the largest advisory policy and uncovered names stays under the bound', async () => {
		const required = [
			'version: 1',
			'required:',
			...Array.from({ length: 3000 }, (_, i) => `  - id: app.point-${i}\n    revision: 1`),
		].join('\n');
		const changed = [
			'Dockerfile',
			...Array.from({ length: 20 }, (_, i) => `${C1.repeat(1999)}${i}`),
		];
		const t = await setup({ extra: { '.koi/required.yaml': required }, changed });
		const first = await t.plan();
		expect(bytes(first)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
		expect(first.counts.required).toBe(3000);
		expect(first.truncated).toContain('policy.advisory.required');
		expect(first.truncated).toContain('uncovered');
		const all = [...first.uncovered];
		let next = first.next;
		while (next !== undefined) {
			const page = await t.verification.planPage(first.planId, next);
			expect(bytes(page)).toBeLessThanOrEqual(VERIFICATION_REPLY_MAX_BYTES);
			all.push(...page.uncovered);
			next = page.next;
		}
		expect(all).toHaveLength(20);
		expect(all.every((u) => u.endsWith(' [cut by koid]'))).toBe(true);
	});
});

describe('restart', () => {
	test('a keyed request retried after a restart gets the first acceptance and starts nothing', async () => {
		const t = await setup();
		const plan = await t.plan();
		const body = {
			version: 1 as const,
			planId: plan.planId,
			planDigest: plan.planDigest,
			mode: 'runner' as const,
			idempotencyKey: 'ci-run-42',
		};
		const first = await t.verification.start(body);
		await t.verification.settled(first.runId);
		// A finished run counts too: the retry may come long after it. It needs
		// no recovery, and its key is still loaded.
		const next = t.restarted();
		expect(await next.recover({ releaseLeases: true })).toEqual([]);
		expect(await next.start(body)).toEqual(first);
		expect(t.calls.filter((c) => c.startsWith('lease '))).toHaveLength(1);
		// The key stays out of the status a reader gets.
		expect(JSON.stringify(await next.status(first.runId))).not.toContain('ci-run-42');
		// Another key starts a run of its own.
		const other = await next.start({ ...body, idempotencyKey: 'ci-run-43' });
		expect(other.runId).not.toBe(first.runId);
		await next.settled(other.runId);
		expect(t.calls.filter((c) => c.startsWith('lease '))).toHaveLength(2);
	});

	test('a keyed run the last koid left running is found by its key, and stays interrupted', async () => {
		const t = await setup();
		const plan = await t.plan();
		const runId = 'q'.repeat(20);
		const writer = await t.evidence.openRun(runId, { deployment: t.identity });
		const lease = await t.deployer.acquireLease(LABEL, runLeaseHolder(runId), 720);
		const controller = RunControllerRecordSchema.parse({
			version: 1,
			runId,
			planId: plan.planId,
			planDigest: plan.planDigest,
			idempotencyKey: 'ci-run-42',
			label: LABEL,
			deployment: t.identity,
			profile: 'pr',
			advisory: false,
			state: 'running',
			cancelRequested: false,
			points: [{ id: 'hello.home', state: 'running', evidence: [] }],
			uncovered: [],
			policy: { source: 'none' },
			limits: plan.limits,
			lease: { leaseId: lease.lease.leaseId, expiresAt: lease.lease.expiresAt },
			readiness: { eligibleForMergeGate: false, reasons: [] },
			freshness: 'unknown',
			cleanup: 'unknown',
			startedAt: AT,
			updatedAt: AT,
		});
		await writer.writeRecord('controller.json', controller);
		await writer.abandon();
		const leases = t.calls.filter((c) => c.startsWith('lease ')).length;

		const next = t.restarted();
		expect(await next.recover({ releaseLeases: true })).toEqual([runId]);
		const again = await next.start({
			version: 1,
			planId: plan.planId,
			planDigest: plan.planDigest,
			mode: 'runner',
			idempotencyKey: 'ci-run-42',
		});
		expect(again).toEqual({
			version: 1,
			runId,
			planId: plan.planId,
			planDigest: plan.planDigest,
			deployment: t.identity,
			state: 'running',
			leaseExpiresAt: lease.lease.expiresAt,
			limits: plan.limits,
			startedAt: AT,
		});
		expect(t.calls.filter((c) => c.startsWith('lease '))).toHaveLength(leases);
		// The acceptance is what it was; the status says how the run ended.
		expect((await next.status(runId)).completion).toBe('interrupted');
		// The rewritten record keeps the key, so a second restart finds it too.
		const stored = RunControllerRecordSchema.parse(
			JSON.parse(await readFile(join(t.evidence.runDir(runId), 'controller.json'), 'utf8')),
		);
		expect(stored.idempotencyKey).toBe('ci-run-42');
		const third = t.restarted();
		await third.recover({ releaseLeases: true });
		expect(
			(
				await third.start({
					version: 1,
					planId: plan.planId,
					planDigest: plan.planDigest,
					mode: 'runner',
					idempotencyKey: 'ci-run-42',
				})
			).runId,
		).toBe(runId);
	});

	test('marks a run the last koid judged but did not finalize as finalize-failed, and leaves it so after', async () => {
		const t = await setup();
		const plan = await t.plan();
		const runId = 'q'.repeat(20);
		const writer = await t.evidence.openRun(runId, { deployment: t.identity });
		const lease = await t.deployer.acquireLease(LABEL, runLeaseHolder(runId), 720);
		// As a crash between the terminal records and the manifest leaves it:
		// evaluated and passed on disk, with no manifest.
		const controller = RunControllerRecordSchema.parse({
			version: 1,
			runId,
			planId: plan.planId,
			planDigest: plan.planDigest,
			label: LABEL,
			deployment: t.identity,
			profile: 'pr',
			advisory: false,
			state: 'completed',
			completion: 'evaluated',
			outcome: 'passed',
			cancelRequested: false,
			points: [{ id: 'hello.home', state: 'done', outcome: 'pass', evidence: [] }],
			uncovered: [],
			policy: { source: 'none' },
			limits: plan.limits,
			lease: { leaseId: lease.lease.leaseId, expiresAt: lease.lease.expiresAt },
			readiness: { eligibleForMergeGate: false, reasons: [] },
			freshness: 'current',
			cleanup: 'succeeded',
			startedAt: AT,
			finishedAt: AT,
			updatedAt: AT,
		});
		await writer.writeRecord('controller.json', controller);
		await writer.setState('completed');
		await writer.abandon();

		expect(await t.verification.recover({ releaseLeases: true })).toEqual([runId]);
		const status = await t.verification.status(runId);
		expect(status.state).toBe('completed');
		expect(status.completion).toBe('finalize-failed');
		expect(status.outcome).toBe('incomplete');
		expect(status.interruption).toContain('before the run was finalized');
		expect(status.finalized).toBe(false);
		expect(status.evidence).toBe('incomplete');
		expect(status.problems.map((p) => p.code)).toEqual(['finalize_failed']);
		expect(status.readiness.eligibleForMergeGate).toBe(false);
		expect(status.points.map((p) => [p.id, p.outcome])).toEqual([['hello.home', 'pass']]);
		// The teardown was done before the records were written, so the
		// lease goes once the startup cleanup is known to have run.
		expect(t.record.lease).toBeUndefined();
		expect(await t.verification.recover({ releaseLeases: true })).toEqual([]);
	});

	test('marks a run left running as interrupted, never passed, and releases its lease', async () => {
		const t = await setup();
		// A run as a crash leaves it: records written, no manifest, the lease held.
		const plan = await t.plan();
		const runId = 'q'.repeat(20);
		const writer = await t.evidence.openRun(runId, { deployment: t.identity });
		const lease = await t.deployer.acquireLease(LABEL, runLeaseHolder(runId), 720);
		const controller = RunControllerRecordSchema.parse({
			version: 1,
			runId,
			planId: plan.planId,
			planDigest: plan.planDigest,
			label: LABEL,
			deployment: t.identity,
			profile: 'pr',
			advisory: false,
			state: 'running',
			cancelRequested: false,
			points: [
				{ id: 'hello.home', state: 'done', outcome: 'pass', evidence: [] },
				{ id: 'app.search', state: 'running', evidence: [] },
			],
			uncovered: [],
			policy: { source: 'none' },
			limits: plan.limits,
			lease: { leaseId: lease.lease.leaseId, expiresAt: lease.lease.expiresAt },
			readiness: { eligibleForMergeGate: false, reasons: [] },
			freshness: 'unknown',
			cleanup: 'unknown',
			startedAt: AT,
			updatedAt: AT,
		});
		await writer.writeRecord('controller.json', controller);
		await writer.writeDeclared('run.json', {
			version: 1,
			runId,
			planId: plan.planId,
			deployment: t.identity,
			planDigest: plan.planDigest,
			state: 'running',
			startedAt: AT,
		});
		await writer.abandon();

		expect(await t.verification.recover({ releaseLeases: true })).toEqual([runId]);
		const status = await t.verification.status(runId);
		expect(status.state).toBe('completed');
		expect(status.completion).toBe('interrupted');
		expect(status.outcome).toBe('incomplete');
		expect(status.interruption).toStartWith('koid_restarted');
		expect(status.finalized).toBe(false);
		expect(status.evidence).toBe('incomplete');
		expect(status.readiness.eligibleForMergeGate).toBe(false);
		expect(status.points.map((p) => [p.id, p.state, p.outcome])).toEqual([
			['hello.home', 'done', 'pass'],
			['app.search', 'pending', undefined],
		]);
		const dir = t.evidence.runDir(runId);
		const stored = RunStatusSchema.parse(
			JSON.parse(await readFile(join(dir, 'status.json'), 'utf8')),
		);
		expect(stored.state).toBe('failed');
		expect(stored.problems.map((p) => p.code)).toEqual(['koid_restarted']);
		const run = RunSchema.parse(JSON.parse(await readFile(join(dir, 'run.json'), 'utf8')));
		expect(run.state).toBe('completed');
		expect(t.record.lease).toBeUndefined();
		expect(t.calls.at(-1)).toBe(`release ${LABEL} ${lease.lease.leaseId}`);
		// A second start finds nothing to recover.
		expect(await t.verification.recover({ releaseLeases: true })).toEqual([]);
	});

	test("leaves the lease when the cleanup was not proved, and a lease that is not the run's", async () => {
		const t = await setup();
		const plan = await t.plan();
		const runId = 'q'.repeat(20);
		const writer = await t.evidence.openRun(runId, { deployment: t.identity });
		const lease = await t.deployer.acquireLease(LABEL, 'dev@laptop', 720);
		await writer.writeRecord(
			'controller.json',
			RunControllerRecordSchema.parse({
				version: 1,
				runId,
				planId: plan.planId,
				planDigest: plan.planDigest,
				label: LABEL,
				deployment: t.identity,
				profile: 'pr',
				advisory: false,
				state: 'running',
				cancelRequested: false,
				points: [],
				uncovered: [],
				policy: { source: 'none' },
				limits: plan.limits,
				lease: { leaseId: lease.lease.leaseId, expiresAt: lease.lease.expiresAt },
				readiness: { eligibleForMergeGate: false, reasons: [] },
				freshness: 'unknown',
				cleanup: 'unknown',
				startedAt: AT,
				updatedAt: AT,
			}),
		);
		await writer.abandon();
		expect(await t.verification.recover({ releaseLeases: false })).toEqual([runId]);
		expect(t.record.lease?.leaseId).toBe(lease.lease.leaseId);
		expect((await t.verification.status(runId)).cleanup).toBe('unknown');
		// Released only when the holder is the run.
		const again = await setup();
		const other = await again.plan();
		const writer2 = await again.evidence.openRun(runId, { deployment: again.identity });
		const held = await again.deployer.acquireLease(LABEL, 'dev@laptop', 720);
		await writer2.writeRecord(
			'controller.json',
			RunControllerRecordSchema.parse({
				version: 1,
				runId,
				planId: other.planId,
				planDigest: other.planDigest,
				label: LABEL,
				deployment: again.identity,
				profile: 'pr',
				advisory: false,
				state: 'running',
				cancelRequested: false,
				points: [],
				uncovered: [],
				policy: { source: 'none' },
				limits: other.limits,
				lease: { leaseId: held.lease.leaseId, expiresAt: held.lease.expiresAt },
				readiness: { eligibleForMergeGate: false, reasons: [] },
				freshness: 'unknown',
				cleanup: 'unknown',
				startedAt: AT,
				updatedAt: AT,
			}),
		);
		await writer2.abandon();
		await again.verification.recover({ releaseLeases: true });
		expect(again.record.lease?.holder).toBe('dev@laptop');
	});
});

describe('point budgets', () => {
	const limits = { runSeconds: 900, pointSeconds: 300, runRequests: 50, pointRequests: 20 };
	const at = (budgets?: Point['budgets']) =>
		({ id: 'a.b', ...(budgets !== undefined ? { budgets } : {}) }) as Point;

	test("a point's own time is under the host ceiling and the time left, not the default", () => {
		// Asks for more than the default, with the run's time to spare.
		expect(pointBudgetSeconds(at({ timeoutSeconds: 600 }), limits, 900_000)).toBe(600);
		// The default applies only to a point that names none.
		expect(pointBudgetSeconds(at(), limits, 900_000)).toBe(300);
		expect(pointBudgetSeconds(at({ timeoutSeconds: 60 }), limits, 900_000)).toBe(60);
		// The host's ceiling and the time left still bound it.
		expect(
			pointBudgetSeconds(at({ timeoutSeconds: 1200 }), { ...limits, runSeconds: 3600 }, 3_600_000),
		).toBe(RUN_LIMIT_CEILINGS.pointSeconds);
		expect(pointBudgetSeconds(at({ timeoutSeconds: 600 }), limits, 120_500)).toBe(120);
		expect(pointBudgetSeconds(at({ timeoutSeconds: 600 }), limits, 0)).toBe(1);
	});

	test("a point's own requests go by the same formula", () => {
		expect(pointRequests(at({ maxRequests: 40 }), limits)).toBe(40);
		expect(pointRequests(at(), limits)).toBe(20);
		expect(pointRequests(at({ maxRequests: 60 }), { ...limits, runRequests: 200 })).toBe(
			RUN_LIMIT_CEILINGS.pointRequests,
		);
		expect(pointRequests(at({ maxRequests: 40 }), { ...limits, runRequests: 30 })).toBe(30);
	});
});
