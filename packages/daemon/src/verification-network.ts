import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import {
	type EndpointRole,
	helperName,
	INPUT_VOLUME_PARTS,
	INPUT_VOLUME_ROLE,
	inputVolumeName,
	type KoidContainerRole,
	parseHelperName,
	parseInputVolumeName,
	parseRunNetworkName,
	type RunNetworkDescriptor,
	RunNetworkDescriptorSchema,
	type RunNetworkEndpoint,
	type RunNetworkRecord,
	RunNetworkRecordSchema,
	runNetworkName,
	stagingName,
	VERIFY_POLICY_VERSION,
	type VerifyAttestation,
	VerifyAttestationSchema,
	VerifyIdSchema,
	VerifyPoolSchema,
} from '@koi/shared';
import type { Docker, LabelledContainer, LabelledVolume, NetworkInfo } from './docker.ts';
import { ExecError, type ExecOptions, type ExecResult, exec, WHOLE_OUTPUT } from './exec.ts';
import { writeFileAtomic } from './fsutil.ts';
import { Mutex } from './lock.ts';

// The private network of one verification run (docs/verify.md, "Run
// network"): a bridge of its own with a /28 from the operator's reserved
// pool, the serving app attached to it as a second interface, and two
// containers koi owns, the recorder and the verifier, created but not
// started. The firewall permits between them come from the root-owned
// helper (host/verify/koi_verify_net.py), which koid runs through sudo.
//
// Each network has a record on disk from before Docker is asked for
// anything until after the helper has revoked its permits and the network
// is gone, so its subnet is never reused while any connection state or rule
// of the old run could still exist, and startup finds what a crash left.
// Nothing here starts a container or keeps a run going: that is the run's
// job, in a later change.

// The root-owned helper, through sudo. Tests use a fake.
export interface VerifyNetHelper {
	apply(descriptor: RunNetworkDescriptor): Promise<void>;
	revoke(runId: string): Promise<void>;
	attest(): Promise<VerifyAttestation>;
}

type Run = (cmd: string[], options?: ExecOptions) => Promise<ExecResult>;

// `sudo -n <path> apply|revoke|attest`. The sudoers rule provisioning
// installs names exactly this path (host/cloud-init.sh); -n fails instead
// of waiting for a password.
export function sudoHelper(path: string, run: Run = exec): VerifyNetHelper {
	const call = async (args: string[], stdin?: string): Promise<string> => {
		const cmd = ['sudo', '-n', path, ...args];
		const r = await run(cmd, {
			timeoutMs: 60_000,
			maxBytes: WHOLE_OUTPUT,
			...(stdin !== undefined ? { stdin } : {}),
		});
		if (r.code !== 0 || r.timedOut) throw new ExecError(cmd, r);
		return r.stdout;
	};
	return {
		async apply(descriptor) {
			await call(['apply'], `${JSON.stringify(descriptor)}\n`);
		},
		async revoke(runId) {
			await call(['revoke', VerifyIdSchema.parse(runId)]);
		},
		async attest() {
			return parseAttestation(await call(['attest']));
		},
	};
}

// What `koi-verify-net attest` printed, checked against its schema.
export function parseAttestation(text: string): VerifyAttestation {
	let data: unknown;
	try {
		data = JSON.parse(text);
	} catch {
		throw new Error('koi-verify-net attest printed something other than JSON');
	}
	const result = VerifyAttestationSchema.safeParse(data);
	if (!result.success) {
		const fields = result.error.issues.map(
			(i) => `${i.path.join('.') || 'the output'}: ${i.message}`,
		);
		throw new Error(`koi-verify-net attest printed what koid cannot read: ${fields.join('; ')}`);
	}
	return result.data;
}

// Every way the attestation says the host is not ready for verification;
// empty when it is. Shared by the host check and by create(), which checks
// again once the run's permits are in.
export function attestationProblems(attestation: VerifyAttestation, pool: string): string[] {
	const problems: string[] = [];
	if (attestation.policy !== VERIFY_POLICY_VERSION) {
		problems.push(
			`the helper installs policy version ${attestation.policy}, and koid expects ${VERIFY_POLICY_VERSION}`,
		);
	}
	if (attestation.pool !== pool) {
		problems.push(
			`the helper's pool is ${attestation.pool ?? 'not set'} and KOI_VERIFY_POOL is ${pool}; both come from /etc/koi/verify/env`,
		);
	}
	const ipv4 = attestation.ipv4;
	if (!ipv4.chains || !ipv4.jump || !ipv4.defaults || !ipv4.permits) {
		problems.push(...ipv4.problems);
		if (ipv4.problems.length === 0) problems.push('the KOI-VERIFY chains are not in place');
	}
	if (!attestation.ipv6.defaults) {
		problems.push(...attestation.ipv6.problems);
		if (attestation.ipv6.problems.length === 0)
			problems.push('the IPv6 denies for kv+ are not in place');
	}
	if (!attestation.sysctl.br_netfilter) problems.push('br_netfilter is not loaded');
	else {
		if (!attestation.sysctl.bridge_nf_call_iptables) {
			problems.push('net.bridge.bridge-nf-call-iptables is not 1');
		}
		if (!attestation.sysctl.bridge_nf_call_ip6tables) {
			problems.push('net.bridge.bridge-nf-call-ip6tables is not 1');
		}
	}
	return problems;
}

// --- Names and addresses ---------------------------------------------------------

export { helperName, runNetworkName };

// A run's helper or staging container, from a container's name and labels,
// or undefined for anything else. A container is one only when koid named
// it as one, its labels say the same run and role, and koi.preview holds
// nothing: a preview's image can set any label, including koi.run and
// koi.role, but its name is koid's and never a helper's, and koid creates a
// helper or staging container with koi.preview set to nothing over whatever
// its image carries (docker.ts, helperArgs and stagingArgs), so a value there
// is not koid's doing. Cleanup removes nothing it is not sure of. The
// reconciler and the watchdog, which must keep every preview in sight, go by
// the name alone (docker.ts, isPreview).
export function helperOf(
	container: LabelledContainer,
): { name: string; runId: string; role: KoidContainerRole } | undefined {
	const named = parseHelperName(container.name);
	if (named === undefined) return undefined;
	const { labels } = container;
	if ((labels['koi.preview'] ?? '') !== '') return undefined;
	if (labels['koi.role'] !== named.role) return undefined;
	if (labels['koi.run'] !== named.runId) return undefined;
	if (!VerifyIdSchema.safeParse(named.runId).success) return undefined;
	return { name: container.name, ...named };
}

// The run an input volume belongs to, when koid named it as one and its
// labels say the same run, or undefined. An image can declare a volume, but
// not name one, so the name is the part only koid can have set.
export function inputVolumeOf(volume: LabelledVolume): { name: string; runId: string } | undefined {
	const named = parseInputVolumeName(volume.name);
	if (named === undefined) return undefined;
	if (volume.labels['koi.role'] !== INPUT_VOLUME_ROLE) return undefined;
	if (volume.labels['koi.run'] !== named.runId) return undefined;
	if (!VerifyIdSchema.safeParse(named.runId).success) return undefined;
	return { name: volume.name, runId: named.runId };
}

// The run a network belongs to, when koid named it as a run network and its
// label says the same run, or undefined.
export function runNetworkOf(network: NetworkInfo): string | undefined {
	const runId = parseRunNetworkName(network.name);
	if (runId === undefined || network.run !== runId) return undefined;
	return VerifyIdSchema.safeParse(runId).success ? runId : undefined;
}

// The private application name both helpers resolve to the app's address on
// the run network. .invalid never resolves anywhere else.
export function privateHost(runId: string): string {
	return `app.${runId}.invalid`;
}

// kv and twelve hex digits from the run id. A truncated hash can collide,
// so create() checks the name against existing bridges and tries the next
// attempt on a clash.
export function bridgeName(runId: string, attempt = 0): string {
	return `kv${createHash('sha256').update(`${runId}:${attempt}`).digest('hex').slice(0, 12)}`;
}

function parseCidr(cidr: string): { base: number; prefix: number } {
	const [address = '', prefix = ''] = cidr.split('/');
	const base = address.split('.').reduce((n, octet) => n * 256 + Number(octet), 0);
	return { base, prefix: Number(prefix) };
}

function formatAddress(n: number): string {
	return [24, 16, 8, 0].map((shift) => Math.floor(n / 2 ** shift) % 256).join('.');
}

// Every /28 in the pool, lowest first.
export function subnetsOf(pool: string): string[] {
	const { base, prefix } = parseCidr(VerifyPoolSchema.parse(pool));
	const count = 2 ** (28 - prefix);
	return Array.from({ length: count }, (_, i) => `${formatAddress(base + i * 16)}/28`);
}

// The lowest /28 of the pool that overlaps nothing in `used` (networks of
// any size), or undefined when the pool is full.
export function allocateSubnet(pool: string, used: Iterable<string>): string | undefined {
	const taken = [...used].map(parseCidr);
	return subnetsOf(pool).find((candidate) => {
		const c = parseCidr(candidate);
		return !taken.some((t) => {
			const prefix = Math.min(c.prefix, t.prefix);
			const size = 2 ** (32 - prefix);
			return Math.floor(c.base / size) === Math.floor(t.base / size);
		});
	});
}

// The fixed addresses in a run's /28: the gateway, then app, recorder and
// verifier.
export function addressesOf(subnet: string): Record<'gateway' | EndpointRole, string> {
	const { base } = parseCidr(subnet);
	return {
		gateway: formatAddress(base + 1),
		app: formatAddress(base + 2),
		recorder: formatAddress(base + 3),
		verifier: formatAddress(base + 4),
	};
}

// The MAC a helper is created with: locally administered, unicast, 02:4b
// ("k") and the address's four bytes, so a helper's MAC is recognisable.
// Docker picks the app's: 02:42 and the address's bytes before Docker 28,
// random since. A random one could match a helper's, and the root-owned
// helper refuses a descriptor in which two endpoints share a MAC.
export function helperMac(ip: string): string {
	const bytes = ip.split('.').map((o) => Number(o).toString(16).padStart(2, '0'));
	return ['02', '4b', ...bytes].join(':');
}

// Every way the network Docker made differs from the record; empty when it
// is the run network as asked.
export function runNetworkProblems(
	network: NetworkInfo | undefined,
	record: Pick<RunNetworkRecord, 'network' | 'bridge' | 'subnet' | 'runId'>,
): string[] {
	if (network === undefined) return [`network ${record.network} does not exist`];
	const problems: string[] = [];
	if (network.driver !== 'bridge') problems.push(`uses the ${network.driver} driver, not bridge`);
	if (!network.internal) problems.push('is not internal');
	if (network.ipv6) problems.push('has IPv6 enabled');
	if (!network.icc) problems.push('lets its containers reach each other (enable_icc is not false)');
	if (network.bridge !== record.bridge) {
		problems.push(`has bridge ${network.bridge ?? '(automatic)'}, not ${record.bridge}`);
	}
	if (network.subnets.join(' ') !== record.subnet) {
		problems.push(`has subnets ${network.subnets.join(' ') || '(none)'}, not ${record.subnet}`);
	}
	if (network.run !== record.runId) problems.push(`is not labelled koi.run=${record.runId}`);
	return problems.map((p) => `network ${record.network} ${p}`);
}

// --- The networks ---------------------------------------------------------------------

export interface VerificationNetworkDeps {
	docker: Docker;
	helper: VerifyNetHelper;
	// KOI_VERIFY_POOL.
	pool: string;
	// The preview network, where the app keeps its address.
	previewNetwork: string;
	stateDir: string;
	slice?: string | undefined;
	// Whether a host interface of that name exists, for the bridge collision
	// check. `ip link show` needs no privilege.
	linkExists?: (name: string) => Promise<boolean>;
	now: () => Date;
	log: (message: string) => void;
}

// What a change of a run's network may be given besides its request: the
// signal of the run's budget. A change whose signal fired while it waited
// for the lock is not made, and a Docker call pending when it fires is
// ended. The helper's steps go on whatever the signal says (docker.ts).
export interface ChangeOptions {
	signal?: AbortSignal | undefined;
}

export interface RunNetworkRequest {
	runId: string;
	// The serving app's container and port, from the run's lease
	// (Deployer.leasedDeployment).
	appContainer: string;
	appPort: number;
	// Images by digest, approved outside this module.
	recorderImage: string;
	verifierImage: string;
	verifierCommand?: string[] | undefined;
	seccompProfile?: string | undefined;
	// The recorder's own settings over the common ones: the run's two
	// tokens (recorder.ts). The verifier never gets them.
	recorderEnv?: Record<string, string> | undefined;
}

async function ipLinkExists(name: string): Promise<boolean> {
	const r = await exec(['ip', '-o', 'link', 'show', 'dev', name], { timeoutMs: 15_000 });
	return r.code === 0;
}

interface RecordsOnDisk {
	records: RunNetworkRecord[];
	unreadable: Array<{ name: string; reason: string }>;
}

// A record from its file's text. The error is one line, since it can end up
// in the reason verification is unavailable.
function parseRecord(text: string): RunNetworkRecord {
	const result = RunNetworkRecordSchema.safeParse(JSON.parse(text));
	if (result.success) return result.data;
	const fields = result.error.issues.map((i) => `${i.path.join('.') || 'the file'}: ${i.message}`);
	throw new Error(fields.join('; '));
}

export class VerificationNetwork {
	// One change at a time: allocation reads every record and must not
	// interleave with another allocation or a teardown.
	private readonly changes = new Mutex();

	constructor(private readonly deps: VerificationNetworkDeps) {}

	private dir(): string {
		return join(this.deps.stateDir, 'verification', 'networks');
	}

	private path(runId: string): string {
		return join(this.dir(), `${VerifyIdSchema.parse(runId)}.json`);
	}

	// Every record on disk, and every file that could not be read or parsed
	// with the reason. One bad file does not stop the others being read.
	private async readRecords(): Promise<RecordsOnDisk> {
		const found: RecordsOnDisk = { records: [], unreadable: [] };
		let names: string[];
		try {
			names = await readdir(this.dir());
		} catch (err) {
			if (isNotFound(err)) return found;
			throw err;
		}
		for (const name of names.sort()) {
			if (!name.endsWith('.json')) continue;
			try {
				found.records.push(parseRecord(await readFile(join(this.dir(), name), 'utf8')));
			} catch (err) {
				found.unreadable.push({ name, reason: message(err) });
			}
		}
		return found;
	}

	// The records that can be read. A file that cannot is logged and skipped,
	// so it does not stop create() and destroy() for other runs. Its subnet
	// is then not known to be held, so cleanupOrphans() counts it as a
	// failure, which makes verification unavailable from the next start
	// until the operator has looked at it.
	async list(): Promise<RunNetworkRecord[]> {
		const { records, unreadable } = await this.readRecords();
		for (const { name, reason } of unreadable) {
			this.deps.log(`skipping run network record ${name}: ${reason}`);
		}
		return records;
	}

	private async save(record: RunNetworkRecord): Promise<RunNetworkRecord> {
		const valid = RunNetworkRecordSchema.parse(record);
		await mkdir(this.dir(), { recursive: true, mode: 0o700 });
		await writeFileAtomic(this.path(valid.runId), `${JSON.stringify(valid, null, '\t')}\n`, 0o600);
		return valid;
	}

	// Makes the run's network around the serving app and its two helpers,
	// installs the permits and checks the attestation. Whatever fails, the
	// network, the helpers and the app's extra attachment are taken down
	// again before the error is thrown; the record then goes too, so the
	// subnet is free. The app's own preview address, which the lease, Caddy
	// and the egress proxy's map all rest on, is checked unchanged. The
	// rollback takes no signal: a creation the budget ended is still taken
	// down whole, and a rollback that fails leaves the record in
	// `destroying` for the run's teardown and the next start.
	async create(request: RunNetworkRequest, options: ChangeOptions = {}): Promise<RunNetworkRecord> {
		const { signal } = options;
		return this.changes.run(async () => {
			const runId = VerifyIdSchema.parse(request.runId);
			const records = await this.list();
			if (records.some((r) => r.runId === runId)) {
				throw new Error(`run ${runId} already has a network`);
			}
			const networks = await this.deps.docker.networks(signal);
			const subnet = allocateSubnet(this.deps.pool, [
				...records.map((r) => r.subnet),
				...networks.flatMap((n) => n.subnets),
			]);
			if (subnet === undefined) {
				throw new Error(
					`the verification pool ${this.deps.pool} has no free /28: ${records.length} run networks hold one each`,
				);
			}
			const bridge = await this.freeBridge(runId, records, networks);
			const addresses = addressesOf(subnet);
			const record = await this.save({
				version: 1,
				runId,
				network: runNetworkName(runId),
				bridge,
				subnet,
				gateway: addresses.gateway,
				appContainer: request.appContainer,
				appPort: request.appPort,
				state: 'creating',
				endpoints: [],
				createdAt: this.deps.now().toISOString(),
			});
			try {
				return await this.build(record, request, addresses, signal);
			} catch (err) {
				await this.teardown(record).catch((e: unknown) =>
					this.deps.log(
						`taking down the run network of ${runId} after a failure: ${message(e)}; kept for the next start`,
					),
				);
				throw new Error(`making the run network of ${runId}: ${message(err)}`);
			}
		}, signal);
	}

	// A bridge name no network, record or host interface uses.
	private async freeBridge(
		runId: string,
		records: RunNetworkRecord[],
		networks: NetworkInfo[],
	): Promise<string> {
		const linkExists = this.deps.linkExists ?? ipLinkExists;
		for (let attempt = 0; attempt < 16; attempt++) {
			const name = bridgeName(runId, attempt);
			if (records.some((r) => r.bridge === name)) continue;
			if (networks.some((n) => n.bridge === name)) continue;
			if (await linkExists(name)) continue;
			return name;
		}
		throw new Error(`no free bridge name for run ${runId}`);
	}

	private async build(
		initial: RunNetworkRecord,
		request: RunNetworkRequest,
		addresses: ReturnType<typeof addressesOf>,
		signal: AbortSignal | undefined,
	): Promise<RunNetworkRecord> {
		const { docker, helper, previewNetwork } = this.deps;
		let record = initial;
		const { runId, network, appContainer } = record;
		const before = await docker.inspect(appContainer, previewNetwork, signal);
		if (!before.running || before.ip === undefined) {
			throw new Error(`${appContainer} is not running on ${previewNetwork}`);
		}
		await docker.createNetwork(
			{
				name: network,
				bridge: record.bridge,
				subnet: record.subnet,
				gateway: record.gateway,
				labels: { 'koi.run': runId },
			},
			signal,
		);
		const made = (await docker.networks(signal)).find((n) => n.name === network);
		const problems = runNetworkProblems(made, record);
		if (problems.length > 0) throw new Error(problems.join('; '));
		// A second interface; the preview one stays as it was.
		await docker.connect(network, appContainer, addresses.app, signal);
		const app = await docker.endpoint(appContainer, network, signal);
		if (app?.ip !== addresses.app || app.mac === undefined) {
			throw new Error(
				`${appContainer} got ${app?.ip ?? 'no address'} on ${network}, not ${addresses.app}`,
			);
		}
		const after = await docker.inspect(appContainer, previewNetwork, signal);
		if (!after.running || after.ip !== before.ip) {
			throw new Error(
				`${appContainer} is ${after.running ? `at ${after.ip ?? 'no address'}` : 'stopped'} on ${previewNetwork}, where it was at ${before.ip}`,
			);
		}
		const endpoints: RunNetworkEndpoint[] = [
			{ role: 'app', container: appContainer, ip: app.ip, mac: app.mac },
		];
		const appHost = { name: privateHost(runId), ip: addresses.app };
		const env = {
			KOI_RUN_ID: runId,
			KOI_PREVIEW_URL: `http://${appHost.name}:${record.appPort}`,
		};
		for (const role of ['recorder', 'verifier'] as const) {
			const name = helperName(runId, role);
			const ip = addresses[role];
			const mac = helperMac(ip);
			const common = { name, network, ip, mac, runId, appHost, dns: addresses.gateway, env };
			if (role === 'recorder') {
				await docker.createRecorder(
					{
						...common,
						env: { ...env, ...(request.recorderEnv ?? {}) },
						image: request.recorderImage,
						seccompProfile: request.seccompProfile,
					},
					signal,
				);
			} else {
				await docker.createVerifier(
					{
						...common,
						image: request.verifierImage,
						command: request.verifierCommand,
					},
					signal,
				);
			}
			const made = await docker.endpoint(name, network, signal);
			if (made?.ip !== ip) {
				throw new Error(`${name} got ${made?.ip ?? 'no address'} on ${network}, not ${ip}`);
			}
			if (made.mac !== undefined && made.mac !== mac) {
				throw new Error(`${name} got MAC ${made.mac} on ${network}, not ${mac}`);
			}
			// An image may declare a volume, which would give the helper a
			// writable place koi did not ask for.
			const mounts = await docker.mounts(name, signal);
			if (mounts.length > 0) {
				throw new Error(
					`${name} has mounts koi did not ask for: ${mounts.map((m) => `${m.type} at ${m.destination}`).join(', ')}`,
				);
			}
			endpoints.push({ role, container: name, ip, mac });
		}
		record = await this.save({ ...record, endpoints });
		const descriptor: RunNetworkDescriptor = RunNetworkDescriptorSchema.parse({
			version: 1,
			runId,
			bridge: record.bridge,
			subnet: record.subnet,
			appPort: record.appPort,
			endpoints,
		});
		await helper.apply(descriptor);
		// The permits are in; the host must still be as the host check found
		// it, and the helper must count the run.
		const attestation = await helper.attest();
		const bad = attestationProblems(attestation, this.deps.pool);
		if (!attestation.runs.includes(runId)) bad.push(`the helper does not list run ${runId}`);
		if (bad.length > 0) throw new Error(`after apply, ${bad.join('; ')}`);
		return this.save({ ...record, state: 'ready' });
	}

	// The record of a run's network, or undefined when it has none.
	async record(runId: string): Promise<RunNetworkRecord | undefined> {
		return (await this.list()).find((r) => r.runId === VerifyIdSchema.parse(runId));
	}

	// Installs the run's permits again. The helper binds a permit to a
	// container's bridge port only once the container runs, so this is
	// called after the recorder starts and after each verifier does; the
	// helper replaces the run's generation, and the attestation must list the
	// run afterwards. Each role in `bound` must have a bridge port in the
	// attestation: a container that stopped running since the caller looked
	// comes back from the helper with none, and its permits have no ingress
	// match.
	//
	// The signal is for a caller that may stop waiting, and it stops this from
	// asking the helper for anything from then on. It does not reach the helper
	// call under way. A SIGKILL to sudo does not reach the root helper, and it would
	// free the lock with an apply still going, so the run's revoke could get in first
	// and the apply would leave permits for a run that is gone. So the call keeps the
	// lock until it ends, the teardown's revoke stays behind it, and a reapply that
	// gets the lock after the teardown finds no record and changes nothing.
	async reapply(
		runId: string,
		options: ChangeOptions & { bound?: readonly EndpointRole[] } = {},
	): Promise<void> {
		return this.changes.run(async () => {
			const record = await this.record(runId);
			if (record === undefined) throw new Error(`run ${runId} has no network`);
			if (record.state !== 'ready') {
				throw new Error(`the run network of ${runId} is ${record.state}, not ready`);
			}
			const descriptor: RunNetworkDescriptor = RunNetworkDescriptorSchema.parse({
				version: 1,
				runId: record.runId,
				bridge: record.bridge,
				subnet: record.subnet,
				appPort: record.appPort,
				endpoints: record.endpoints,
			});
			options.signal?.throwIfAborted();
			await this.deps.helper.apply(descriptor);
			options.signal?.throwIfAborted();
			const attestation = await this.deps.helper.attest();
			const bad = attestationProblems(attestation, this.deps.pool);
			if (!attestation.runs.includes(record.runId)) {
				bad.push(`the helper does not list run ${record.runId}`);
			}
			const ports = attestation.ports?.[record.runId];
			for (const role of options.bound ?? []) {
				if (typeof ports?.[role] !== 'string') {
					bad.push(`the helper has not bound the ${role}'s permits to a bridge port`);
				}
			}
			if (bad.length > 0) throw new Error(`after apply, ${bad.join('; ')}`);
		}, options.signal);
	}

	// Takes a run's network down. False when there is no record of it. A
	// step the signal ends fails like any other: the record stays in
	// `destroying` for the next attempt.
	async destroy(runId: string, options: ChangeOptions = {}): Promise<boolean> {
		return this.changes.run(async () => {
			const record = (await this.list()).find((r) => r.runId === VerifyIdSchema.parse(runId));
			if (record === undefined) return false;
			try {
				await this.teardown(record, options.signal);
			} catch (err) {
				throw new Error(`taking down the run network of ${runId}: ${message(err)}`);
			}
			return true;
		}, options.signal);
	}

	// The reverse of build: revoke the permits (the helper also drops the
	// run's connection state), take the app off the run network and nothing
	// else of it, remove the helpers, the staging container and the input
	// volumes, remove the network, and only then release the subnet by
	// removing the record. The containers go first because Docker refuses to
	// remove a volume a container still mounts, even one never started. A
	// step that fails leaves the record in `destroying`, with the subnet held,
	// for the next start to try again, and the error names the step.
	//
	// The record's new state is written beside these steps and not ahead of them. A
	// disk that stopped answering must not keep a run's permits alive, and nothing
	// after this depends on that write: the next start cleans up a record in any
	// state. The record goes only once the write has ended, or the write could land
	// after it and bring it back.
	private async teardown(record: RunNetworkRecord, signal?: AbortSignal): Promise<void> {
		const { docker, helper } = this.deps;
		const marking =
			record.state === 'destroying'
				? Promise.resolve()
				: this.save({ ...record, state: 'destroying' }).then(
						() => {},
						(err: unknown) =>
							this.deps.log(`marking the run network of ${record.runId}: ${message(err)}`),
					);
		try {
			await step('revoking its permits', () => helper.revoke(record.runId));
			await step(`taking ${record.appContainer} off ${record.network}`, () =>
				docker.disconnect(record.network, record.appContainer, signal),
			);
			for (const role of ['recorder', 'verifier'] as const) {
				const name = helperName(record.runId, role);
				await step(`removing ${name}`, () => docker.remove(name, signal));
			}
			const staging = stagingName(record.runId);
			await step(`removing ${staging}`, () => docker.remove(staging, signal));
			for (const part of INPUT_VOLUME_PARTS) {
				const volume = inputVolumeName(record.runId, part);
				await step(`removing volume ${volume}`, () => docker.removeVolume(volume, signal));
			}
			await step(`removing network ${record.network}`, () =>
				docker.removeNetwork(record.network, signal),
			);
		} finally {
			await marking;
		}
		await step('removing its record', () => rm(this.path(record.runId), { force: true }));
	}

	// At startup: every recorded network goes, since no run outlives koid,
	// and so do helpers, staging containers, input volumes and run networks
	// that no record names (a crash before the record was written). Only
	// what koid named as one of these and labelled as the same run counts
	// (helperOf, inputVolumeOf, runNetworkOf); anything else that carries
	// koi.run is left where it is and logged. Returns the run ids cleaned
	// up. What could not be cleaned
	// is logged and tried again next start. Every run and orphan is
	// attempted first; then the failures are thrown as one error naming
	// each run and the step that failed. The capability check turns that
	// into a reason verification is unavailable. A leftover holds permits
	// and a subnet, and a start that reported ready over it would hide
	// that.
	//
	// A record that cannot be read or parsed is such a failure too. Without
	// it, nothing here knows the run: what the run left in Docker still goes
	// as an orphan, and its permits go with the helper's list below. The file
	// stays, because koid cannot tell which subnet it held, so verification
	// stays unavailable until the operator has looked at it and removed it.
	async cleanupOrphans(): Promise<string[]> {
		return this.changes.run(async () => {
			const { docker, helper, log } = this.deps;
			const cleaned: string[] = [];
			const failed: string[] = [];
			// Runs named in `failed`, which the helper's list below does not
			// try a second time.
			const failedRuns = new Set<string>();
			const { records, unreadable } = await this.readRecords();
			for (const { name, reason } of unreadable) {
				const path = join(this.dir(), name);
				log(`cannot read run network record ${path}: ${reason}; kept for the operator`);
				failed.push(`cannot read run network record ${path}: ${reason}; look at it and remove it`);
			}
			for (const record of records) {
				try {
					await this.teardown(record);
					cleaned.push(record.runId);
				} catch (err) {
					log(
						`removing the run network of ${record.runId}: ${message(err)}; kept for the next start`,
					);
					failed.push(`run ${record.runId}, ${message(err)}`);
					failedRuns.add(record.runId);
				}
			}
			const known = new Set(records.map((r) => r.runId));
			const helpers: Array<{ name: string; runId: string }> = [];
			for (const container of await docker.listRun()) {
				const found = helperOf(container);
				if (found === undefined) {
					log(
						`leaving container ${container.name}, labelled koi.run=${JSON.stringify(container.labels['koi.run'] ?? '')}: not a helper koid made`,
					);
				} else helpers.push(found);
			}
			const volumes: Array<{ name: string; runId: string }> = [];
			for (const volume of await docker.listRunVolumes()) {
				const found = inputVolumeOf(volume);
				if (found === undefined) {
					log(
						`leaving volume ${volume.name}, labelled koi.run=${JSON.stringify(volume.labels['koi.run'] ?? '')}: not an input volume koid made`,
					);
				} else volumes.push(found);
			}
			const networks: Array<NetworkInfo & { runId: string }> = [];
			for (const network of await docker.networks()) {
				if (network.run === undefined) continue;
				const runId = runNetworkOf(network);
				if (runId === undefined) {
					log(
						`leaving network ${network.name}, labelled koi.run=${JSON.stringify(network.run)}: not a run network koid made`,
					);
				} else networks.push({ ...network, runId });
			}
			const orphans = new Set(
				[...helpers, ...volumes, ...networks].map((o) => o.runId).filter((id) => !known.has(id)),
			);
			for (const runId of orphans) {
				try {
					await step('revoking its permits', () => helper.revoke(runId));
					for (const n of networks.filter((n) => n.runId === runId)) {
						for (const c of n.containers) {
							await step(`taking ${c} off ${n.name}`, () => docker.disconnect(n.name, c));
						}
					}
					for (const h of helpers.filter((h) => h.runId === runId)) {
						await step(`removing ${h.name}`, () => docker.remove(h.name));
					}
					// After the containers: Docker refuses a volume one still mounts.
					for (const v of volumes.filter((v) => v.runId === runId)) {
						await step(`removing volume ${v.name}`, () => docker.removeVolume(v.name));
					}
					for (const n of networks.filter((n) => n.runId === runId)) {
						await step(`removing network ${n.name}`, () => docker.removeNetwork(n.name));
					}
					cleaned.push(runId);
				} catch (err) {
					log(`removing what run ${runId} left: ${message(err)}; tried again next start`);
					failed.push(`run ${runId}, ${message(err)}`);
					failedRuns.add(runId);
				}
			}
			// Logged here rather than by the caller, so a pass that also
			// failed somewhere still says what went.
			if (cleaned.length > 0) log(`removed the run networks of ${cleaned.join(', ')}`);
			// The helper lists every run it holds state for, whatever koid knows.
			// A run can be on that list with nothing else left to find it by: its
			// record could not be read, or its Docker objects are gone. No run
			// outlives koid, so any such run gets a revoke.
			let held: string[] = [];
			try {
				held = (await helper.attest()).runs;
			} catch (err) {
				log(`asking the helper which runs it holds: ${message(err)}; tried again next start`);
				failed.push(`asking the helper which runs it holds: ${message(err)}`);
			}
			for (const runId of held) {
				if (failedRuns.has(runId)) continue;
				try {
					await step('revoking its permits', () => helper.revoke(runId));
					log(`revoked run ${runId}, which the helper held and koid had no record of`);
					if (!cleaned.includes(runId)) cleaned.push(runId);
				} catch (err) {
					log(`run ${runId}, held by the helper: ${message(err)}; tried again next start`);
					failed.push(`run ${runId}, ${message(err)}`);
				}
			}
			if (failed.length > 0) throw new Error(failed.join('; '));
			return cleaned;
		});
	}
}

function isNotFound(err: unknown): boolean {
	return typeof err === 'object' && err !== null && 'code' in err && err.code === 'ENOENT';
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

// One step of taking a network down. A failure names the step, so the log
// and the readiness reason say what was left and which step failed.
async function step<T>(what: string, run: () => Promise<T>): Promise<T> {
	try {
		return await run();
	} catch (err) {
		throw new Error(`${what}: ${message(err)}`);
	}
}
