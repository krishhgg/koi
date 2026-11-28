import { spyOn } from 'bun:test';
import { createHash, createHmac } from 'node:crypto';
import * as fsp from 'node:fs/promises';
import { type FileHandle, mkdir, mkdtemp, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Recipe, UpRequest } from '@koi/shared';
import { Activity } from '../src/activity.ts';
import { BuildLogs, type LogFile, type LogFiles } from '../src/buildlog.ts';
import type { Route } from '../src/caddy.ts';
import { Deployer, type DeployerDeps } from '../src/deployer.ts';
import {
	type AttachedContainer,
	type BuildOptions,
	type ContainerState,
	type Docker,
	type ExitState,
	type ImageFileOptions,
	type ImageInfo,
	isPreview,
	type Mount,
	type NetworkEndpoint,
	type NetworkInfo,
	type NetworkOptions,
	type RecorderOptions,
	type RunOptions,
	type StagingOptions,
	type VerifierOptions,
} from '../src/docker.ts';
import type { Egress } from '../src/egress-config.ts';
import { resolveInside } from '../src/fsutil.ts';
import { ssmRoom } from '../src/live.ts';
import { readRecipe } from '../src/recipes.ts';
import { PreviewStore } from '../src/store.ts';
import type { Uploads } from '../src/uploads.ts';

type FakeFile = { type: 'file' | 'dir'; mode: number; content: string };

interface FakeContainer {
	// A preview's options; a verification helper has none.
	options?: RunOptions;
	labels: Record<string, string>;
	running: boolean;
	ip?: string;
	// The systemd slice it runs in.
	slice: string;
	// Attachments to networks other than the preview network, by network name.
	attachments: Map<string, NetworkEndpoint>;
	// Volume and bind mounts, as an image's VOLUME would give.
	mounts: Array<{ type: string; destination: string }>;
	// Created with --read-only, as both helpers are: docker cp into the
	// root filesystem is refused.
	readOnly: boolean;
	// Named volumes mounted into it, writable or not.
	volumes: Array<{ name: string; destination: string; readOnly: boolean }>;
	// What docker cp put into the root filesystem, by path.
	files: Map<string, FakeFile>;
}

interface FakeVolume {
	labels: Record<string, string>;
	// Its contents, by path relative to the volume's root; '' is the root.
	files: Map<string, FakeFile>;
}

interface FakeNetwork {
	options: NetworkOptions;
	info: NetworkInfo;
}

// A verifier as a test's script drives it once koid attaches: what it was
// created with, what koid copied in, its output streams, and the lines koid
// writes to its stdin.
export interface FakeVerifier {
	name: string;
	env: Record<string, string>;
	options: VerifierOptions;
	// What the container sees at its paths: the root filesystem's copied
	// files and the mounted volumes' contents, by path without the leading
	// slash (koi/supervisor.py, workspace/koi.yaml, fixtures/...).
	files: Map<string, FakeFile>;
	// Writes a line, or raw bytes, to the container's stdout or stderr.
	out(text: string): void;
	err(text: string): void;
	write(bytes: Uint8Array): void;
	// The next line koid wrote to stdin, as it arrives.
	nextLine(): Promise<string>;
	// Resolves once koid stops the container.
	stopped: Promise<void>;
	// Whether koid ended the attachment.
	detached: boolean;
	// The key in koid's start line, once it came.
	key: string | undefined;
	// Leaves the output streams open past the script's end, as a client that
	// never reports their end would.
	keepOutputOpen: boolean;
	// Breaks stdout, as a client that dies mid-stream would.
	failOutput(): void;
	// End the streams left open by hand.
	closeOutput(): void;
	closeErrors(): void;
}

// What a started verifier does: given the container, prints what a runner
// would and returns the exit code. The default waits for start and reports
// a run step that exited 0 with no assertion.
export type VerifierScript = (verifier: FakeVerifier) => Promise<number>;

// A supervisor line signed as supervisor.py signs it, with the key and number
// given.
export function signedSupervisorLine(
	key: string,
	seq: number,
	fields: Record<string, unknown>,
): string {
	const head = JSON.stringify({ version: 1, type: 'supervisor', seq, ...fields }).slice(0, -1);
	return `${head},"mac":"${createHmac('sha256', key).update(head).digest('hex')}"}`;
}

const TO_SIGN = '{"sign-as-the-supervisor":';

// A supervisor line for a script to print with v.out, which signs it with
// the key koid sent and the next number, as the real supervisor does. A
// script that means to forge one prints its own line.
export function supervisorLine(fields: Record<string, unknown>): string {
	return `${TO_SIGN}${JSON.stringify(fields)}}`;
}

// The supervisor's lines for steps that all exited 0, from `steps`.
export function supervisorExit(
	steps: Array<Record<string, unknown>> = [{ step: 'run', status: 'exited', code: 0 }],
): string[] {
	const last = steps.at(-1) ?? { step: 'run', status: 'exited', code: 0 };
	return [
		...steps.map((step) => supervisorLine({ event: 'step', ...step })),
		supervisorLine({
			event: 'exit',
			step: last.step,
			status: last.status,
			...(last.code !== undefined ? { code: last.code } : {}),
			steps,
		}),
	];
}

// The steps a verifier's point file declares, each as a step that exited 0.
export function declaredSteps(v: FakeVerifier): Array<Record<string, unknown>> {
	const pointFile = JSON.parse(v.files.get('koi/point.json')?.content ?? '{}') as {
		steps?: Record<string, unknown>;
	};
	return ['setup', 'run', 'cleanup']
		.filter((step) => pointFile.steps?.[step] != null)
		.map((step) => ({ step, status: 'exited', code: 0 }));
}

export const defaultVerifierScript: VerifierScript = async (v) => {
	await v.nextLine();
	v.out(supervisorLine({ event: 'started' }));
	for (const line of supervisorExit(declaredSteps(v))) v.out(line);
	return 0;
};

// The entries of a ustar archive as verifier.ts writes one: name, type,
// mode and content as text. PAX path records are applied.
export function tarEntries(tar: Uint8Array): Map<string, FakeFile> {
	const out = new Map<string, FakeFile>();
	const text = (at: number, length: number) =>
		new TextDecoder().decode(tar.subarray(at, at + length)).replace(/\0.*$/s, '');
	let at = 0;
	let paxPath: string | undefined;
	while (at + 512 <= tar.length) {
		const name = text(at, 100);
		if (name === '') break;
		const mode = Number.parseInt(text(at + 100, 8), 8);
		const size = Number.parseInt(text(at + 124, 12), 8);
		const type = text(at + 156, 1);
		const prefix = text(at + 345, 155);
		const content = new TextDecoder().decode(tar.subarray(at + 512, at + 512 + size));
		at += 512 + Math.ceil(size / 512) * 512;
		if (type === 'x') {
			const match = /^\d+ path=(.*)\n$/s.exec(content);
			paxPath = match?.[1];
			continue;
		}
		const full = paxPath ?? (prefix === '' ? name : `${prefix}/${name}`);
		paxPath = undefined;
		out.set(full.replace(/\/$/, ''), {
			type: type === '5' ? 'dir' : 'file',
			mode,
			content,
		});
	}
	return out;
}

// Docker in memory: containers get addresses on start and lose them on stop.
export class FakeDocker implements Docker {
	containers = new Map<string, FakeContainer>();
	// Networks made through createNetwork, by name.
	networksMade = new Map<string, FakeNetwork>();
	// Networks the box has besides those, as the preview networks are.
	otherNetworks: NetworkInfo[] = [];
	// The recorder and verifier options koid created helpers with, in order.
	helpers: Array<{ role: 'recorder' | 'verifier'; options: RecorderOptions | VerifierOptions }> =
		[];
	// Mounts every helper created from now on gets, as from an image's VOLUME.
	helperMounts: Array<{ type: string; destination: string }> = [];
	// Images on the box by reference, for imageInfo, besides the built ones.
	imageInfos = new Map<string, ImageInfo>();
	// Named volumes, by name.
	volumes = new Map<string, FakeVolume>();
	// The staging containers koid created, in order.
	stagings: StagingOptions[] = [];
	// What a verifier does once koid attaches to it.
	verifierScript: VerifierScript | undefined;
	// The verifiers koid attached to, in order.
	verifiers: FakeVerifier[] = [];
	// An attached container is running only after this many inspects, as
	// a container Docker is still starting; 0 means at once.
	runningAfterInspects = 0;
	private readonly starting = new Map<string, number>();
	// Past this many lines a verifier's stdin is full, as when the runner
	// reads nothing: a write then waits for its signal.
	stdinLines: number | undefined;
	// How containers ended, by name, for exitState; a script's exit code
	// is recorded here when it returns.
	exits = new Map<string, ExitState>();
	// Fails the next attach with this message.
	attachError: string | undefined;
	// Each copyIn waits here until the gate opens or its signal ends it, as a
	// `docker cp` in progress does.
	copyGate: Gate | undefined;
	// The signals createVolume, createStaging and copyIn were given, in order.
	prepareSignals: Array<AbortSignal | undefined> = [];
	// Labels an image carries, by image: as Docker does, a container made
	// from it gets them, under the labels koid sets.
	imageLabels = new Map<string, Record<string, string>>();
	// Fails the next createNetwork with this message.
	createNetworkError: string | undefined;
	// What endpoint() reports as a created helper's MAC: Docker's record of
	// the one asked for, or nothing until it starts.
	reportHelperMac = true;
	images = new Set<string>();
	// Each image's id. Docker's is a hash of the image configuration, so a
	// cached rebuild of the same input keeps it, and a build whose labels
	// differ gets another. Every fake build has the same layers (extract
	// writes one Dockerfile), so the labels, which carry the request id, are
	// the whole identity here.
	digests = new Map<string, string>();
	builds: BuildOptions[] = [];
	// Files in every built image, by absolute path, for readImageFile.
	imageFiles = new Map<string, string>();
	// What readImageFile was asked for, in order.
	imageFileReads: ImageFileOptions[] = [];
	runs: RunOptions[] = [];
	starts: string[] = [];
	imageUserValue = '';
	buildError: string | undefined;
	// The cache sizes builds were trimmed to, in order.
	prunes: string[] = [];
	pruneError: string | undefined;
	onPrune: (() => void) | undefined;
	// Disk use (writable layer and volumes) of containers, by name.
	diskBytes = new Map<string, number>();
	// diskUsage fails with this, when set.
	diskUsageError: string | undefined;
	// Containers that docker stop fails for.
	unstoppable = new Set<string>();
	// Containers that docker rm fails for.
	unremovable = new Set<string>();
	// Containers that docker network disconnect fails for.
	undisconnectable = new Set<string>();
	// Containers that exit right after starting.
	crashing = new Set<string>();
	// Runs at the start of every inspect, before it reads the container.
	onInspect: (() => Promise<void>) | undefined;
	// Runs during a build, before it succeeds: what the box does meanwhile.
	onBuild: (() => Promise<void>) | undefined;
	// Runs as each stop begins, with the container's name, and is awaited:
	// one that never resolves is a docker stop that hangs.
	onStop: ((name: string) => unknown) | undefined;
	// The signal each createNetwork was given, in order.
	networkSignals: Array<AbortSignal | undefined> = [];
	// The signal each stop was given, in order.
	stopSignals: Array<AbortSignal | undefined> = [];
	// The slice a container runs in once it starts, as Docker's default.
	startSlice = 'koi.slice';
	// What every container's log says; by default, which container it is.
	containerLogs: string | undefined;
	// Lines every build prints after its first.
	buildOutput: string[] = [];
	private nextIp = 2;
	// Give each start the lowest free address, as Docker does, instead of
	// a new one each time.
	reuseAddresses = false;
	// Runs as each run or start begins, before the container gets its address.
	onStartBegin: ((name: string) => void) | undefined;
	// What happened, in order: "ran NAME IP", "started NAME IP", "stopped
	// NAME", "removed NAME". Tests add their own entries (setup's proxy adds
	// "map {...}").
	events: string[] = [];

	private address(): string {
		if (!this.reuseAddresses) return `172.19.0.${this.nextIp++}`;
		const used = new Set([...this.containers.values()].flatMap((c) => (c.ip ? [c.ip] : [])));
		for (let n = 2; ; n++) if (!used.has(`172.19.0.${n}`)) return `172.19.0.${n}`;
	}

	// A container that dies on its own, as by the memory limit: Docker frees
	// its address at once, and koid hears of it only from Docker.
	kill(name: string) {
		const c = this.containers.get(name);
		if (c === undefined) return;
		c.running = false;
		delete c.ip;
		this.events.push(`died ${name}`);
	}

	async build(o: BuildOptions) {
		this.builds.push(o);
		// The build's signal ends it at once, as it kills docker buildx,
		// whatever onBuild is waiting for.
		await new Promise<void>((resolve, reject) => {
			const end = () => reject(new Error('docker buildx exited 137'));
			if (o.signal?.aborted) {
				end();
				return;
			}
			o.signal?.addEventListener('abort', end, { once: true });
			Promise.resolve(this.onBuild?.()).then(resolve, reject);
		});
		o.onLine('step 1/1');
		for (const line of this.buildOutput) o.onLine(line);
		if (this.buildError !== undefined) throw new Error(this.buildError);
		this.images.add(o.tag);
		this.digests.set(
			o.tag,
			`sha256:${createHash('sha256').update(JSON.stringify(o.labels)).digest('hex')}`,
		);
	}
	async pruneBuildCache(maxUsedSpace: string) {
		this.prunes.push(maxUsedSpace);
		if (this.pruneError !== undefined) throw new Error(this.pruneError);
		this.onPrune?.();
	}
	async imageUser() {
		return this.imageUserValue;
	}
	async readImageFile(o: ImageFileOptions) {
		this.imageFileReads.push(o);
		if (!this.images.has(o.image)) throw new Error(`no such image ${o.image}`);
		const text = this.imageFiles.get(o.path);
		if (text === undefined) throw new Error(`cannot read ${o.path} from the image: no such file`);
		if (new TextEncoder().encode(text).length > o.maxBytes) {
			throw new Error(`cannot read ${o.path} from the image: it is more than ${o.maxBytes} bytes`);
		}
		return text;
	}
	async imageDigest(image: string) {
		const digest = this.digests.get(image);
		if (digest === undefined) throw new Error(`no such image ${image}`);
		return digest;
	}
	async run(o: RunOptions) {
		if (this.containers.has(o.name)) throw new Error(`container ${o.name} already exists`);
		this.runs.push(o);
		this.onStartBegin?.(o.name);
		const ip = this.address();
		this.containers.set(o.name, {
			options: o,
			// As runArgs: koi.role set to nothing, over the image's.
			labels: { ...this.imageLabels.get(o.image), 'koi.role': '', ...o.labels },
			running: true,
			ip,
			slice: this.startSlice,
			attachments: new Map(),
			mounts: [],
			readOnly: false,
			volumes: [],
			files: new Map(),
		});
		this.events.push(`ran ${o.name} ${ip}`);
	}
	async start(name: string) {
		const c = this.containers.get(name);
		if (c === undefined) throw new Error(`no such container ${name}`);
		this.starts.push(name);
		this.onStartBegin?.(name);
		c.running = true;
		c.slice = this.startSlice;
		c.ip = this.address();
		this.events.push(`started ${name} ${c.ip}`);
	}
	private readonly stopWaiters = new Map<string, () => void>();
	async stop(name: string, signal?: AbortSignal) {
		this.stopSignals.push(signal);
		await this.onStop?.(name);
		if (this.unstoppable.has(name)) throw new Error(`docker stop ${name} timed out`);
		const c = this.containers.get(name);
		if (c === undefined) return;
		if (!c.running) return;
		c.running = false;
		delete c.ip;
		this.events.push(`stopped ${name}`);
		this.stopWaiters.get(name)?.();
	}
	async remove(name: string, _signal?: AbortSignal) {
		if (this.unremovable.has(name)) throw new Error(`docker rm ${name} exited 1`);
		const c = this.containers.get(name);
		if (c === undefined) return;
		this.exits.delete(name);
		for (const network of c.attachments.keys()) {
			this.networksMade
				.get(network)
				?.info.containers.splice(
					this.networksMade.get(network)?.info.containers.indexOf(name) ?? 0,
					1,
				);
		}
		this.containers.delete(name);
		this.events.push(`removed ${name}`);
	}
	async removeImage(image: string) {
		this.images.delete(image);
		this.digests.delete(image);
	}
	async inspect(name: string): Promise<ContainerState> {
		await this.onInspect?.();
		const c = this.containers.get(name);
		if (c === undefined) return { exists: false, running: false };
		if (this.crashing.has(name)) {
			c.running = false;
			delete c.ip;
		}
		const left = this.starting.get(name);
		if (left !== undefined) {
			if (left <= 1) {
				this.starting.delete(name);
				c.running = true;
				c.ip = this.address();
				this.events.push(`running ${name}`);
			} else this.starting.set(name, left - 1);
		}
		return c.running && c.ip
			? { exists: true, running: true, ip: c.ip }
			: { exists: true, running: false };
	}
	async slice(name: string) {
		const c = this.containers.get(name);
		return c?.running ? c.slice : undefined;
	}
	async logs(name: string) {
		return this.containerLogs ?? `logs of ${name}`;
	}
	// As the real one: only previews, by name and koi.preview (isPreview).
	async list() {
		return [...this.containers.entries()]
			.filter(([name, c]) => isPreview(name, c.labels['koi.preview']))
			.map(([name, c]) => ({ name, label: c.labels['koi.preview'] ?? '' }));
	}
	async listImages() {
		return [...this.images];
	}
	// As the real one: only previews, by name and koi.preview (isPreview).
	async diskUsage() {
		if (this.diskUsageError !== undefined) throw new Error(this.diskUsageError);
		return [...this.containers.entries()]
			.filter(([name, c]) => isPreview(name, c.labels['koi.preview']))
			.map(([name, c]) => ({
				name,
				label: c.labels['koi.preview'] ?? '',
				bytes: this.diskBytes.get(name) ?? 0,
				running: c.running,
			}));
	}
	async createNetwork(o: NetworkOptions, signal?: AbortSignal) {
		this.networkSignals.push(signal);
		if (this.createNetworkError !== undefined) {
			const error = this.createNetworkError;
			this.createNetworkError = undefined;
			throw new Error(error);
		}
		if (this.networksMade.has(o.name)) throw new Error(`network ${o.name} already exists`);
		const run = o.labels['koi.run'];
		this.networksMade.set(o.name, {
			options: o,
			info: {
				id: `net-${o.name}`,
				name: o.name,
				driver: 'bridge',
				internal: true,
				ipv6: false,
				icc: true,
				bridge: o.bridge,
				subnets: [o.subnet],
				...(run !== undefined ? { run } : {}),
				containers: [],
			},
		});
		this.events.push(`created network ${o.name}`);
	}
	async removeNetwork(name: string) {
		const n = this.networksMade.get(name);
		if (n === undefined) return;
		if (n.info.containers.length > 0) {
			throw new Error(`network ${name} has active endpoints: ${n.info.containers.join(', ')}`);
		}
		this.networksMade.delete(name);
		this.events.push(`removed network ${name}`);
	}
	async networks() {
		return [...this.otherNetworks, ...[...this.networksMade.values()].map((n) => n.info)];
	}
	async connect(network: string, container: string, ip: string) {
		const n = this.networksMade.get(network);
		if (n === undefined) throw new Error(`network ${network} not found`);
		const c = this.containers.get(container);
		if (c === undefined) throw new Error(`no such container ${container}`);
		if (c.attachments.has(network)) {
			throw new Error(`${container} is already attached to ${network}`);
		}
		c.attachments.set(network, { ip, mac: dockerMac(ip), endpointId: `ep-${container}` });
		n.info.containers.push(container);
		this.events.push(`connected ${container} to ${network} at ${ip}`);
	}
	async disconnect(network: string, container: string) {
		if (this.undisconnectable.has(container)) {
			throw new Error(`docker network disconnect exited 1: ${container} is busy`);
		}
		const c = this.containers.get(container);
		if (c === undefined || !c.attachments.delete(network)) return;
		const n = this.networksMade.get(network);
		if (n !== undefined) n.info.containers = n.info.containers.filter((x) => x !== container);
		this.events.push(`disconnected ${container} from ${network}`);
	}
	private createHelper(role: 'recorder' | 'verifier', o: RecorderOptions | VerifierOptions) {
		if (this.containers.has(o.name)) throw new Error(`container ${o.name} already exists`);
		const n = this.networksMade.get(o.network);
		if (n === undefined) throw new Error(`network ${o.network} not found`);
		const volumes = 'volumes' in o ? (o.volumes ?? []) : [];
		for (const v of volumes) {
			if (!this.volumes.has(v.name)) throw new Error(`no such volume ${v.name}`);
		}
		this.helpers.push({ role, options: o });
		const attachments = new Map<string, NetworkEndpoint>();
		attachments.set(o.network, { ip: o.ip, ...(this.reportHelperMac ? { mac: o.mac } : {}) });
		this.containers.set(o.name, {
			// As helperArgs: koi.preview set to nothing, over the image's.
			labels: {
				...this.imageLabels.get(o.image),
				'koi.preview': '',
				'koi.role': role,
				'koi.run': o.runId,
			},
			running: false,
			slice: this.startSlice,
			attachments,
			mounts: [...this.helperMounts],
			readOnly: true,
			volumes: volumes.map((v) => ({ ...v, readOnly: true })),
			files: new Map(),
		});
		n.info.containers.push(o.name);
		this.events.push(`created ${role} ${o.name}`);
	}
	async createRecorder(o: RecorderOptions) {
		this.createHelper('recorder', o);
	}
	async createVerifier(o: VerifierOptions, _signal?: AbortSignal) {
		this.createHelper('verifier', o);
	}
	async createVolume(name: string, labels: Record<string, string>, signal?: AbortSignal) {
		this.prepareSignals.push(signal);
		// As Docker: a volume that exists is left as it is.
		if (this.volumes.has(name)) return;
		this.volumes.set(name, { labels: { ...labels }, files: new Map() });
		this.events.push(`created volume ${name}`);
	}
	async removeVolume(name: string, _signal?: AbortSignal) {
		if (!this.volumes.has(name)) return;
		for (const [container, c] of this.containers) {
			if (c.volumes.some((v) => v.name === name)) {
				throw new Error(`docker volume rm exited 1: volume ${name} is in use by ${container}`);
			}
		}
		this.volumes.delete(name);
		this.events.push(`removed volume ${name}`);
	}
	async listRunVolumes() {
		return [...this.volumes.entries()]
			.filter(([, v]) => v.labels['koi.run'] !== undefined)
			.map(([name, v]) => ({ name, labels: { ...v.labels } }));
	}
	async createStaging(o: StagingOptions, signal?: AbortSignal) {
		this.prepareSignals.push(signal);
		if (this.containers.has(o.name)) throw new Error(`container ${o.name} already exists`);
		for (const v of o.volumes) {
			if (!this.volumes.has(v.name)) throw new Error(`no such volume ${v.name}`);
		}
		this.stagings.push(o);
		this.containers.set(o.name, {
			labels: {
				...this.imageLabels.get(o.image),
				'koi.preview': '',
				'koi.role': 'staging',
				'koi.run': o.runId,
			},
			running: false,
			slice: this.startSlice,
			attachments: new Map(),
			mounts: [],
			readOnly: false,
			volumes: o.volumes.map((v) => ({ ...v, readOnly: false })),
			files: new Map(),
		});
		this.events.push(`created staging ${o.name}`);
	}
	async imageInfo(image: string): Promise<ImageInfo | undefined> {
		const known = this.imageInfos.get(image);
		if (known !== undefined) return known;
		const id = this.digests.get(image);
		return id === undefined ? undefined : { id, env: [] };
	}
	// As Docker extracts an archive. The refusal looks at the destination
	// alone, as the daemon's does: a path on the root filesystem of a
	// read-only container, or in a read-only volume, takes nothing, even when
	// every entry would land in a writable volume. Then each entry lands in
	// the volume mounted at its path when one is, else in the root filesystem.
	async copyIn(container: string, tar: Uint8Array, destination: string, signal?: AbortSignal) {
		this.prepareSignals.push(signal);
		if (this.copyGate !== undefined) {
			const gate = this.copyGate;
			await new Promise<void>((resolve, reject) => {
				const end = () => reject(new Error('docker cp exited 137'));
				if (signal?.aborted) end();
				signal?.addEventListener('abort', end, { once: true });
				gate.pass().then(resolve, reject);
			});
		}
		const c = this.containers.get(container);
		if (c === undefined) throw new Error(`no such container ${container}`);
		if (c.running) throw new Error(`${container} is running`);
		const mountAt = (path: string) =>
			c.volumes.find((v) => path === v.destination || path.startsWith(`${v.destination}/`));
		const readOnlyVolume =
			'docker cp exited 1: Error response from daemon: mounted volume is marked read-only';
		const base = destination.replace(/\/+$/, '');
		const target = mountAt(base === '' ? '/' : base);
		if (target === undefined && c.readOnly) {
			throw new Error(
				'docker cp exited 1: Error response from daemon: container rootfs is marked read-only',
			);
		}
		if (target?.readOnly) throw new Error(readOnlyVolume);
		for (const [path, entry] of tarEntries(tar)) {
			const full = `${base}/${path}`;
			const mount = mountAt(full);
			if (mount === undefined) {
				c.files.set(full.replace(/^\//, ''), entry);
				continue;
			}
			if (mount.readOnly) throw new Error(readOnlyVolume);
			const volume = this.volumes.get(mount.name);
			if (volume === undefined) throw new Error(`no such volume ${mount.name}`);
			volume.files.set(full.slice(mount.destination.length).replace(/^\//, ''), entry);
		}
		this.events.push(`copied into ${container}:${destination}`);
	}
	// The files a container sees, by path without the leading slash: its
	// root filesystem's copied files and its volumes' contents.
	private filesOf(c: FakeContainer): Map<string, FakeFile> {
		const out = new Map(c.files);
		for (const mount of c.volumes) {
			const volume = this.volumes.get(mount.name);
			if (volume === undefined) continue;
			const at = mount.destination.replace(/^\//, '');
			for (const [path, entry] of volume.files) out.set(path === '' ? at : `${at}/${path}`, entry);
		}
		return out;
	}
	// Starts the container and runs the verifier script over its streams.
	async attach(name: string): Promise<AttachedContainer> {
		if (this.attachError !== undefined) {
			const error = this.attachError;
			this.attachError = undefined;
			throw new Error(error);
		}
		const c = this.containers.get(name);
		if (c === undefined) throw new Error(`no such container ${name}`);
		const options = this.helpers.findLast((h) => h.options.name === name)?.options as
			| VerifierOptions
			| undefined;
		if (options === undefined) throw new Error(`${name} is not a verifier`);
		await this.start(name);
		if (this.runningAfterInspects > 0) {
			// Docker's client is up; the container is not running yet.
			c.running = false;
			delete c.ip;
			this.starting.set(name, this.runningAfterInspects);
		}
		const encoder = new TextEncoder();
		let outController: ReadableStreamDefaultController<Uint8Array> | undefined;
		let errController: ReadableStreamDefaultController<Uint8Array> | undefined;
		const stdout = new ReadableStream<Uint8Array>({
			start(controller) {
				outController = controller;
			},
		});
		const stderr = new ReadableStream<Uint8Array>({
			start(controller) {
				errController = controller;
			},
		});
		const inbox: string[] = [];
		const waiting: Array<(line: string) => void> = [];
		let partial = '';
		let written = 0;
		let seq = 0;
		const stdinLines = this.stdinLines;
		// What a script prints through supervisorLine goes out signed, once
		// there is a key to sign with. Before that it goes out as it would
		// from a runner guessing.
		const signed = (text: string): string => {
			if (!text.startsWith(TO_SIGN)) return text;
			const fields = JSON.parse(text.slice(TO_SIGN.length, -1)) as Record<string, unknown>;
			if (fake.key === undefined)
				return JSON.stringify({ version: 1, type: 'supervisor', ...fields });
			seq += 1;
			return signedSupervisorLine(fake.key, seq, fields);
		};
		let stopContainer = () => {};
		const stopped = new Promise<void>((resolve) => {
			stopContainer = resolve;
		});
		this.stopWaiters.set(name, stopContainer);
		const fake: FakeVerifier = {
			name,
			env: options.env,
			options,
			files: this.filesOf(c),
			out: (text) => outController?.enqueue(encoder.encode(`${signed(text)}\n`)),
			err: (text) => errController?.enqueue(encoder.encode(`${text}\n`)),
			write: (bytes) => outController?.enqueue(bytes),
			nextLine: () =>
				new Promise<string>((resolve) => {
					const line = inbox.shift();
					if (line !== undefined) resolve(line);
					else waiting.push(resolve);
				}),
			stopped,
			detached: false,
			key: undefined,
			keepOutputOpen: false,
			failOutput: () => outController?.error(new Error('the client went away')),
			closeOutput: () => {
				outController?.close();
				errController?.close();
			},
			closeErrors: () => errController?.close(),
		};
		this.verifiers.push(fake);
		const script = this.verifierScript ?? defaultVerifierScript;
		const exited = (async () => {
			let code: number;
			try {
				code = await script(fake);
			} catch (err) {
				fake.err(`script: ${err instanceof Error ? err.message : String(err)}`);
				code = 1;
			}
			if (!fake.keepOutputOpen) {
				try {
					outController?.close();
				} catch {}
				try {
					errController?.close();
				} catch {}
			}
			this.starting.delete(name);
			const container = this.containers.get(name);
			if (container?.running) {
				container.running = false;
				delete container.ip;
				this.events.push(`exited ${name} ${code}`);
			}
			if (!this.exits.has(name)) {
				this.exits.set(name, { status: 'exited', exitCode: code, oomKilled: false });
			}
			return code;
		})();
		return {
			async write(data, o) {
				const signal = o?.signal;
				const abandoned = () => new Error('the write to the container was abandoned');
				if (signal?.aborted) throw abandoned();
				written += 1;
				if (stdinLines !== undefined && written > stdinLines) {
					await new Promise<never>((_, reject) => {
						signal?.addEventListener('abort', () => reject(abandoned()), { once: true });
					});
				}
				const lines = (partial + new TextDecoder().decode(data)).split('\n');
				partial = lines.pop() ?? '';
				for (const line of lines) {
					const said = JSON.parse(line) as { type?: string; key?: string };
					if (said.type === 'start') fake.key = said.key;
					const waiter = waiting.shift();
					if (waiter !== undefined) waiter(line);
					else inbox.push(line);
				}
			},
			stdout,
			stderr,
			exited,
			detach() {
				fake.detached = true;
			},
		};
	}
	async exitState(name: string): Promise<ExitState | undefined> {
		const c = this.containers.get(name);
		if (c === undefined) return undefined;
		const recorded = this.exits.get(name);
		if (recorded !== undefined) return recorded;
		return c.running
			? { status: 'running', exitCode: 0, oomKilled: false }
			: { status: 'created', exitCode: 0, oomKilled: false };
	}
	async endpoint(container: string, network: string) {
		const c = this.containers.get(container);
		if (c === undefined) throw new Error(`no such container ${container}`);
		return c.attachments.get(network);
	}
	async mounts(container: string, _signal?: AbortSignal): Promise<Mount[]> {
		const c = this.containers.get(container);
		if (c === undefined) throw new Error(`no such container ${container}`);
		return [
			...c.mounts,
			...c.volumes.map((v) => ({
				type: 'volume',
				destination: v.destination,
				name: v.name,
				readOnly: v.readOnly,
			})),
		];
	}
	// As docker ps --filter label=koi.run: whatever carries the label, a
	// preview whose image set it included.
	async listRun() {
		return [...this.containers.entries()]
			.filter(([, c]) => c.labels['koi.run'] !== undefined)
			.map(([name, c]) => ({ name, labels: { ...c.labels } }));
	}
	// Simulates the box stopping: every container stops.
	stopAll() {
		for (const c of this.containers.values()) {
			c.running = false;
			delete c.ip;
		}
	}
}

// A MAC as Docker gave it before Docker 28: 02:42 and the address's bytes.
// Fixed here so tests can name it; real ones are random now.
function dockerMac(ip: string): string {
	return ['02', '42', ...ip.split('.').map((o) => Number(o).toString(16).padStart(2, '0'))].join(
		':',
	);
}

// A build log file holding `text`.
export function memoryFile(text: string): LogFile {
	const bytes = Buffer.from(text, 'utf8');
	return {
		size: bytes.length,
		read: async (position, length) => bytes.subarray(position, position + length),
		close: async () => {},
	};
}

// `files`, counting the bytes read through it.
export function countingFiles(files: LogFiles): LogFiles & { bytesRead: () => number } {
	let total = 0;
	const counting = async (path: string) => {
		const file = await files(path);
		if (file === undefined) return undefined;
		return {
			size: file.size,
			async read(position: number, length: number) {
				const bytes = await file.read(position, length);
				total += bytes.length;
				return bytes;
			},
			close: () => file.close(),
		};
	};
	return Object.assign(counting, { bytesRead: () => total });
}

// A point the code under test stops at: `reached` resolves when it gets
// there, and it goes on after release().
export class Gate {
	readonly reached: Promise<void>;
	private arrive = () => {};
	private go = () => {};
	private readonly released = new Promise<void>((resolve) => {
		this.go = resolve;
	});

	constructor() {
		this.reached = new Promise<void>((resolve) => {
			this.arrive = resolve;
		});
	}

	async pass(): Promise<void> {
		this.arrive();
		await this.released;
	}

	release(): void {
		this.go();
	}
}

type HoldPoint = 'apply' | 'inspect' | 'keepAwake' | 'probe';

// Waits until `done` is true, for work the code under test starts in the
// background. Fails after a second.
export async function eventually(done: () => boolean): Promise<void> {
	const deadline = Date.now() + 1000;
	while (!done()) {
		if (Date.now() > deadline) throw new Error('timed out waiting');
		await Bun.sleep(5);
	}
}

export function request(overrides: Partial<UpRequest> = {}): UpRequest {
	return {
		version: 1,
		id: 'aaaaaaaaaaaaaaaa1',
		label: 'hello-pr-7',
		project: 'hello',
		repo: 'github.com/acme/hello',
		commit: 'a'.repeat(40),
		branch: 'feature/x',
		pr: 7,
		dirty: false,
		recipe: { kind: 'repo', recipe: repoRecipe() },
		createdAt: '2026-10-06T00:00:00.000Z',
		...overrides,
	};
}

function repoRecipe() {
	return {
		port: 8080,
		healthPath: '/',
		env: {},
		ttlDays: 7,
		buildTimeoutMinutes: 45,
		healthTimeoutSeconds: 5,
		build: {
			kind: 'dockerfile' as const,
			from: 'source' as const,
			path: 'Dockerfile',
			context: '.',
		},
	};
}

export async function setup(
	options: {
		builtin?: Recipe;
		egress?: Egress;
		// Stands in for the helper that gives a started preview its route.
		routeOut?: (container: string) => Promise<void>;
		proxy?: boolean;
		// A live list with no size cap, as a file gives.
		unboundedLive?: boolean;
		// An upload store in place of the one in memory, such as a real spool.
		uploads?: Uploads;
	} = {},
) {
	const root = await mkdtemp(join(tmpdir(), 'koid-test-'));
	const stateDir = join(root, 'state');
	const recipesDir = join(root, 'recipes');
	await mkdir(stateDir, { recursive: true });
	const store = new PreviewStore(stateDir);
	await store.init();
	const docker = new FakeDocker();
	const requests = new Map<string, UpRequest>();
	const applied: Route[][] = [];
	const published: string[][] = [];
	const logs: string[] = [];
	// Directories sources were unpacked into, and the size of each tarball.
	const extracted: string[] = [];
	const tarballSizes: number[] = [];
	// What the deployer asked of the upload store, in order: "claim ID",
	// "download ID", "release ID".
	const uploadEvents: string[] = [];
	// The next claims fail with this message, when set.
	let claimError: string | undefined;
	let clock = Date.parse('2026-10-06T12:00:00.000Z');
	let awake = 0;
	// Points where the next call waits until the test releases it.
	const gates = new Map<HoldPoint, Gate>();
	const pass = async (point: HoldPoint) => {
		const gate = gates.get(point);
		gates.delete(point);
		await gate?.pass();
	};
	// The next caddy applies fail with this message, as many times as
	// rejectApplies says.
	let applyError: string | undefined;
	let applyFailures = 0;
	// Applies that pass before those failures begin.
	let applySkips = 0;
	// Likewise for publishing the live list.
	let publishError: string | undefined;
	let publishFailures = 0;
	// Likewise for telling the egress proxy the address map.
	let mapFailures = 0;
	// The maps the egress proxy took, in order.
	const maps: Array<Record<string, string>> = [];
	// The disk Docker keeps its data on.
	const disk = { free: 60 * 1024 ** 3, size: 80 * 1024 ** 3 };
	// Addresses that answer health checks. Undefined: everything is healthy.
	let healthy: ((url: string) => boolean) | undefined;

	docker.onInspect = () => pass('inspect');
	// Visits counted and not yet written, on the test's clock.
	const activity = new Activity(join(root, 'last-activity'), () => clock);

	if (options.builtin !== undefined) {
		// As installed on the box: the recipe's file beside its Dockerfile.
		// A build copies the directory and plans from the copy's recipe.json.
		const dir = join(recipesDir, options.builtin.name);
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, 'recipe.json'), `${JSON.stringify(options.builtin)}\n`);
		await writeFile(join(dir, 'Dockerfile'), 'FROM scratch\n');
	}

	const deps: DeployerDeps = {
		domain: 'previews.example.net',
		network: 'koi-previews',
		slice: 'koi.slice',
		stateDir,
		store,
		docker,
		uploads: options.uploads ?? {
			async request(id) {
				const r = requests.get(id);
				if (r === undefined) throw new Error(`no request ${id}`);
				return r;
			},
			async claim(id) {
				if (claimError !== undefined) throw new Error(claimError);
				uploadEvents.push(`claim ${id}`);
			},
			async release(id) {
				uploadEvents.push(`release ${id}`);
			},
			async downloadSource(id, file) {
				uploadEvents.push(`download ${id}`);
				await writeFile(file, 'tarball');
			},
		},
		caddy: {
			async apply(routes) {
				await pass('apply');
				if (applySkips > 0) {
					applySkips -= 1;
				} else if (applyFailures > 0) {
					applyFailures -= 1;
					throw new Error(applyError);
				}
				applied.push(routes);
			},
		},
		live: {
			room: options.unboundedLive ? () => ({ ok: true }) : ssmRoom,
			async publish(labels) {
				if (publishFailures > 0) {
					publishFailures -= 1;
					throw new Error(publishError);
				}
				published.push([...labels].sort());
			},
		},
		buildLogs: new BuildLogs(stateDir),
		builtinRecipe: async (name) => {
			if (options.builtin === undefined || options.builtin.name !== name)
				throw new Error(`no recipe ${name}`);
			return { recipe: options.builtin, dir: join(recipesDir, name) };
		},
		readRecipe,
		keepAwake: async () => {
			awake += 1;
			await pass('keepAwake');
		},
		extract: async (tarball, dir) => {
			extracted.push(dir);
			tarballSizes.push((await stat(tarball)).size);
			await mkdir(dir, { recursive: true });
			await writeFile(join(dir, 'Dockerfile'), 'FROM scratch\n');
		},
		resolveInside,
		diskSpace: async () => ({ ...disk }),
		...(options.egress !== undefined ? { egress: options.egress } : {}),
		...(options.routeOut !== undefined ? { routeOut: options.routeOut } : {}),
		...(options.proxy
			? {
					previews: async (addresses: Record<string, string>) => {
						if (mapFailures > 0) {
							mapFailures -= 1;
							throw new Error('the egress proxy did not answer');
						}
						maps.push(addresses);
						docker.events.push(`map ${JSON.stringify(addresses)}`);
					},
				}
			: {}),
		probe: async (url) => {
			await pass('probe');
			return healthy === undefined ? true : healthy(url);
		},
		drainVisits: () => activity.drainVisits(),
		now: () => new Date(clock),
		sleep: async (ms) => {
			clock += ms;
		},
		log: (m) => logs.push(m),
	};
	let deployer = new Deployer(deps);
	// As koid does at startup, before anything can visit.
	await deployer.stopOversized();

	return {
		root,
		stateDir,
		store,
		docker,
		deps,
		get deployer() {
			return deployer;
		},
		// A new koid on the same store, Docker and Caddy, as after a restart.
		// It has not measured the disk yet.
		restart(): Deployer {
			deployer = new Deployer(deps);
			return deployer;
		},
		activity,
		applied,
		published,
		maps,
		// The next `count` maps sent to the egress proxy fail.
		rejectMaps(count: number) {
			mapFailures = count;
		},
		logs,
		extracted,
		tarballSizes,
		uploadEvents,
		// Every claim from now on fails with `message`.
		rejectClaims(message: string) {
			claimError = message;
		},
		disk,
		awakeCalls: () => awake,
		lastRoutes: () => applied.at(-1) ?? [],
		addRequest(r: UpRequest) {
			requests.set(r.id, r);
		},
		setHealthy(fn: ((url: string) => boolean) | undefined) {
			healthy = fn;
		},
		advance(ms: number) {
			clock += ms;
		},
		now: () => clock,
		// The next call at `point` waits until the returned gate is released.
		hold(point: HoldPoint): Gate {
			const gate = new Gate();
			gates.set(point, gate);
			return gate;
		},
		rejectNextApply(message: string) {
			this.rejectApplies(1, message);
		},
		// The next `count` applies fail with `message`, after `skip` that pass:
		// a container start's own sync goes first (startFresh).
		rejectApplies(count: number, message = 'caddy rejected the config: 400 bad', skip = 0) {
			applyError = message;
			applyFailures = count;
			applySkips = skip;
		},
		rejectPublishes(count: number, message = 'ThrottlingException: Rate exceeded') {
			publishError = message;
			publishFailures = count;
		},
		async up(r: UpRequest) {
			requests.set(r.id, r);
			const result = await deployer.up(r.id);
			await deployer.settled(r.label);
			await deployer.published();
			return result;
		},
	};
}

// Opens files as usual, and hands each handle to `adjust` with the path it
// was opened for, before the code under test reads it.
export function openingWith(adjust: (path: string, handle: FileHandle) => void) {
	const original = fsp.open;
	return spyOn(fsp, 'open').mockImplementation(async (path, ...rest) => {
		const handle = await original(path, ...rest);
		adjust(String(path), handle);
		return handle;
	});
}

// Removes files as usual, except `path` or the paths it picks, whose removal
// fails with `error`. A predicate is for a file whose name is random.
export function refusingRemoval(path: string | ((target: string) => boolean), error: string) {
	const original = fsp.rm;
	const refused = typeof path === 'string' ? (target: string) => target === path : path;
	return spyOn(fsp, 'rm').mockImplementation(async (target, options) => {
		if (refused(String(target))) throw new Error(error);
		return original(target, options);
	});
}

// Removes files as usual, except the first one `picks` chooses, which waits
// for `finish`: it then goes through, or fails with the error `finish` names.
// `reached` settles once that removal is waiting.
export function holdingRemoval(picks: (target: string) => boolean) {
	const original = fsp.rm;
	let held = false;
	let arrive = () => {};
	const reached = new Promise<void>((resolve) => {
		arrive = resolve;
	});
	let finish: (error?: string) => void = () => {};
	const finished = new Promise<string | undefined>((resolve) => {
		finish = resolve;
	});
	const spy = spyOn(fsp, 'rm').mockImplementation(async (target, options) => {
		if (!held && picks(String(target))) {
			held = true;
			arrive();
			const error = await finished;
			if (error !== undefined) throw new Error(error);
		}
		return original(target, options);
	});
	return { spy, reached, finish: (error?: string) => finish(error) };
}

// Renames files as usual, except onto a path `refused` picks, which fails
// with `error`. Other renames, such as the run's status, go through.
export function refusingRename(refused: (to: string) => boolean, error: string) {
	const original = fsp.rename;
	return spyOn(fsp, 'rename').mockImplementation(async (from, to) => {
		if (refused(String(to))) throw new Error(error);
		return original(from, to);
	});
}

// Every read of `handle` gives at most `most` bytes, as a read of a regular
// file may; `reads` counts them.
export function readingShort(handle: FileHandle, most: number): { reads: number } {
	const state = { reads: 0 };
	const real = handle.read.bind(handle);
	spyOn(handle, 'read').mockImplementation((async (
		buffer: Buffer,
		offset: number,
		length: number,
		position: number,
	) => {
		state.reads += 1;
		return real(buffer, offset, Math.min(most, length), position);
	}) as typeof handle.read);
	return state;
}

// `handle.stat` says the file is a byte longer than it is, so a read to
// that size meets the end of the file first, as it would were the file cut
// after the check or misread.
export function overstatingSize(handle: FileHandle): void {
	const real = handle.stat.bind(handle);
	spyOn(handle, 'stat').mockImplementation((async () => {
		const stat = await real();
		return Object.create(stat, { size: { value: stat.size + 1 } });
	}) as typeof handle.stat);
}
