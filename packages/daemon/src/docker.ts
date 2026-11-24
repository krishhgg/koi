import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, posix } from 'node:path';
import {
	DigestSchema,
	DockerContainerLabelsSchema,
	DockerContainerStateSchema,
	DockerEndpointsSchema,
	DockerImageEnvSchema,
	DockerMountsSchema,
	DockerNetworkInspectSchema,
	parseHelperName,
} from '@koi/shared';
import type { z } from 'zod';
import { ExecError, type ExecOptions, exec, WHOLE_OUTPUT } from './exec.ts';
import { tarFileText } from './tar.ts';

export interface ContainerState {
	exists: boolean;
	running: boolean;
	// Address on the preview network, when running.
	ip?: string;
}

export interface BuildOptions {
	dockerfile: string;
	context: string;
	// Extra named build contexts (`--build-context name=dir`), such as the
	// directory of a built-in recipe, which its Dockerfile copies files from.
	contexts?: Record<string, string>;
	// Build arguments (`--build-arg NAME=value`), such as KOI_KEEP for a
	// recipe that slices. Each goes to docker as one argument, never through
	// a shell.
	buildArgs?: Record<string, string>;
	tag: string;
	labels: Record<string, string>;
	timeoutMs: number;
	onLine: (line: string) => void;
	// Ends the build: koi down stops a preview's build this way.
	signal?: AbortSignal | undefined;
}

export interface ImageFileOptions {
	image: string;
	// An absolute path in the image (ImagePathSchema).
	path: string;
	// The container the file is read through: created from the image, never
	// started, and removed again. Labelled as a preview of the label, so
	// that one koid leaves behind is removed with the other leftovers when
	// it starts (Deployer.reconcile).
	name: string;
	labels: Record<string, string>;
	// The most the file may hold.
	maxBytes: number;
	// Where a failure to remove the reader goes. The read stands, and
	// reconcile removes the reader when koid next starts.
	log: (line: string) => void;
}

export interface RunOptions {
	name: string;
	image: string;
	network: string;
	user: string;
	env: Record<string, string>;
	labels: Record<string, string>;
	// Files placed in the container before it starts: the CA bundle that lets
	// it trust the egress proxy. Copied, never mounted, so the container gets
	// no view of the host. Each must go in a directory every container has,
	// such as /etc: docker cp creates none. The container exists under its name only once
	// every file is in (see run), so a container found by name never lacks
	// them.
	files?: Array<{ path: string; content: string }>;
}

// A network, from `docker network inspect`, with what koid checks on a
// verification run network (host.ts checks the preview networks apart).
export interface NetworkInfo {
	id: string;
	name: string;
	driver: string;
	internal: boolean;
	ipv6: boolean;
	// enable_icc is "false": containers on it cannot reach each other.
	icc: boolean;
	// The com.docker.network.bridge.name option, when set.
	bridge?: string;
	subnets: string[];
	// The koi.run label, on a run network.
	run?: string;
	// Names of the containers attached.
	containers: string[];
}

// A container's attachment to one network. The address and MAC are what
// Docker gave a running container, or what a created one was asked to use.
export interface NetworkEndpoint {
	ip?: string;
	mac?: string;
	endpointId?: string;
}

// What the daemon needs from Docker. The real one shells out to the docker CLI
// with argument arrays; tests use a fake.
export interface Docker {
	build(options: BuildOptions): Promise<void>;
	// Trims the builder's cache to at most `maxUsedSpace`, such as "30gb".
	pruneBuildCache(maxUsedSpace: string): Promise<void>;
	imageUser(image: string): Promise<string>;
	// The image's id: sha256 of its configuration, which names its content.
	// A locally built image has no repository digest, so this is the one
	// Docker gives it.
	imageDigest(image: string): Promise<string>;
	// The text of the regular file at an absolute path in an image, read
	// without running anything from it (readImageFileArgs).
	readImageFile(options: ImageFileOptions): Promise<string>;
	run(options: RunOptions): Promise<void>;
	// The calls a verification run makes under its budget take the budget's
	// signal: a docker command still pending when the run's time is up is
	// ended, so a hung daemon cannot hold the run past its lease. The
	// firewall helper's steps take none: a permit change aborted part way
	// is worse than one that finishes late.
	start(name: string, signal?: AbortSignal): Promise<void>;
	stop(name: string, signal?: AbortSignal): Promise<void>;
	// Removes the container and its anonymous volumes.
	remove(name: string, signal?: AbortSignal): Promise<void>;
	removeImage(image: string): Promise<void>;
	inspect(name: string, network: string, signal?: AbortSignal): Promise<ContainerState>;
	logs(name: string, tail: number): Promise<string>;
	// Every preview container koi created (running or not), by name. A
	// run's helpers are not among them (isPreview).
	list(): Promise<Array<{ name: string; label: string }>>;
	// Every image koi built, as repository:tag.
	listImages(): Promise<string[]>;
	// The disk each koi container uses, running or stopped: its writable
	// layer plus the volumes it mounts, in bytes.
	diskUsage(): Promise<DiskUsage[]>;
	// The systemd slice a running container runs in; undefined when it is
	// not running.
	slice(name: string): Promise<string | undefined>;
	// Verification run networks (verification-network.ts).
	createNetwork(options: NetworkOptions, signal?: AbortSignal): Promise<void>;
	// Removes a network; one that does not exist is fine.
	removeNetwork(name: string, signal?: AbortSignal): Promise<void>;
	// Every network on the box.
	networks(signal?: AbortSignal): Promise<NetworkInfo[]>;
	// Attaches a running container to a network at a fixed address.
	connect(network: string, container: string, ip: string, signal?: AbortSignal): Promise<void>;
	// Detaches a container from a network; one not attached is fine.
	disconnect(network: string, container: string, signal?: AbortSignal): Promise<void>;
	// Creates, without starting, a run's recorder or verifier.
	createRecorder(options: RecorderOptions, signal?: AbortSignal): Promise<void>;
	createVerifier(options: VerifierOptions, signal?: AbortSignal): Promise<void>;
	// A named volume with the labels given. The verifier's inputs live in
	// volumes koid creates per run (verifier.ts).
	createVolume(name: string, labels: Record<string, string>, signal?: AbortSignal): Promise<void>;
	// Removes a volume; one that does not exist is fine. Docker refuses one
	// a container still mounts, created or running.
	removeVolume(name: string, signal?: AbortSignal): Promise<void>;
	// Every volume labelled koi.run, with all its labels.
	listRunVolumes(): Promise<LabelledVolume[]>;
	// Creates, without starting, the container a point's inputs are copied
	// through: its volumes mounted writable, no network, never started.
	createStaging(options: StagingOptions, signal?: AbortSignal): Promise<void>;
	// An image on the box: its id and the environment its configuration
	// declares, or undefined when no such image is on the box. Never pulls.
	imageInfo(image: string): Promise<ImageInfo | undefined>;
	// Extracts a tar archive at `destination` in a created container's
	// filesystem (`docker cp - NAME:DEST`), before it starts. Entries keep
	// the owner and mode the archive gives them, and an entry under a mounted
	// volume lands in the volume. Docker decides from `destination`: it
	// refuses a path on the root filesystem of a container created read-only
	// (`container rootfs is marked read-only`), whatever the entries are, and
	// a path in a volume mounted read-only.
	copyIn(
		container: string,
		tar: Uint8Array,
		destination: string,
		signal?: AbortSignal,
	): Promise<void>;
	// Starts a created container with its stdin, stdout and stderr attached
	// and no TTY (`docker start --attach --interactive`). Docker's client
	// splits the multiplexed stream into the two output streams.
	attach(container: string): Promise<AttachedContainer>;
	// How a container ended, or undefined when there is no such container.
	exitState(container: string): Promise<ExitState | undefined>;
	// The container's attachment to `network`, or undefined when it has none.
	endpoint(
		container: string,
		network: string,
		signal?: AbortSignal,
	): Promise<NetworkEndpoint | undefined>;
	// The volume and bind mounts a container has, from the moment it is
	// created; a --tmpfs is not among them. A volume mount names its volume
	// and says whether the container may write to it.
	mounts(container: string, signal?: AbortSignal): Promise<Mount[]>;
	// Every container labelled koi.run, running or not, with all its labels.
	// koid's helpers carry it; so can a preview whose image set it, so the
	// caller decides which are helpers (verification-network.ts, helperOf).
	listRun(signal?: AbortSignal): Promise<LabelledContainer[]>;
}

export interface LabelledContainer {
	name: string;
	labels: Record<string, string>;
}

export interface LabelledVolume {
	name: string;
	labels: Record<string, string>;
}

export interface Mount {
	type: string;
	destination: string;
	// The volume's name, on a volume mount.
	name?: string | undefined;
	// Whether the container may write to it; undefined when Docker did not
	// say.
	readOnly?: boolean | undefined;
}

// A volume mounted into a helper, by name, at a path.
export interface VolumeMount {
	name: string;
	destination: string;
}

export interface StagingOptions {
	name: string;
	// Any image on the box; the container never starts.
	image: string;
	runId: string;
	// Mounted writable, so `docker cp` can fill them.
	volumes: VolumeMount[];
}

export interface ImageInfo {
	id: string;
	// KEY=value, as the image's configuration lists them.
	env: string[];
}

export interface ExitState {
	// created, running, exited, dead...
	status: string;
	exitCode: number;
	oomKilled: boolean;
}

// A container started with its streams attached. Reading the streams is the
// caller's, and it has to start at once: until something holds a reader on them,
// Bun reads the process's pipes into memory with no limit (verifier.ts,
// OutputReader).
export interface AttachedContainer {
	// Writes to the container's stdin. A container that does not read its
	// stdin fills the pipe, and the write then waits; the signal ends the
	// wait, and the bytes are dropped with the attachment.
	write(data: Uint8Array, options?: { signal?: AbortSignal | undefined }): Promise<void>;
	stdout: ReadableStream<Uint8Array>;
	stderr: ReadableStream<Uint8Array>;
	// The exit code `docker start --attach` reported: the container's once
	// it ends, or the client's own (125 and up) when it could not start or
	// follow the container.
	exited: Promise<number>;
	// Ends the attachment. The container is not stopped by this.
	detach(): void;
}

export interface DiskUsage {
	name: string;
	label: string;
	bytes: number;
	running: boolean;
}

// Whether a container is a preview koid made: it carries a non-empty
// koi.preview and koid did not name it as a run's helper. Only koid names
// containers. A preview is koi-<label>-<id>, where the id is 16 to 40
// letters and digits; a helper is koi-verify-<runId>-recorder or -verifier,
// and a staging container koi-verify-<runId>-staging (shared,
// verify-network.ts). No name fits both. Labels other than
// koi.preview are not asked. Docker copies an image's labels onto the
// container, a preview's image comes from a pull request, and an older
// koid did not set koi.role to nothing on a preview, so a preview may
// carry any koi.role or koi.run its image chose; the name decides, and no
// label hides a preview from the reconciler, the disk watchdog or the
// death watch, which all go through this. Cleanup, which removes, asks
// more of a helper (verification-network.ts, helperOf).
export function isPreview(name: string, preview: string | undefined): boolean {
	return preview !== undefined && preview !== '' && parseHelperName(name) === undefined;
}

export interface CliDockerOptions {
	// The BuildKit builder every build runs in. Provisioning creates it with the
	// docker-container driver on the koi-build network, with memory and CPU
	// limits, so RUN steps from a pull request cannot reach host services or
	// starve the box (host/cloud-init.sh).
	builder: string;
	// The systemd slice preview containers run in, under the memory ceiling
	// they share with the builder (host/cloud-init.sh). Unset, Docker's
	// default applies.
	slice?: string | undefined;
	// Runs a command; tests pass a fake.
	exec?: typeof exec;
}

// Build cache kept after each successful deploy. Warm caches make rebuilds
// fast; the box has 80 GB.
export const BUILD_CACHE_LIMIT = '30gb';

// Build cache kept when a build is about to start on a disk that is short
// of space.
export const BUILD_CACHE_LOW_DISK = '20gb';

// `docker system df --verbose`, one line per container and per volume with
// only the fields diskUsage reads. Its JSON form carries every field of
// every image, container, volume and cache record, megabytes on a busy box.
const DF_FORMAT =
	'{{range .Containers}}container\t{{.Names}}\t{{.State}}\t{{.Size}}\n{{end}}' +
	'{{range .Volumes}}volume\t{{.Name}}\t{{.Size}}\n{{end}}';

// `docker container inspect`, one line per container: its name, its
// koi.preview label (empty when absent), and the volumes it mounts. The
// JSON form includes the environment, which a recipe can make large. The
// name and the label are both koid's own on every container it creates
// (runArgs, helperArgs), so neither carries a value a pull request's image
// chose into the line.
const MOUNTS_FORMAT =
	'{{.Name}}\t{{index .Config.Labels "koi.preview"}}' +
	'{{range .Mounts}}{{if eq .Type "volume"}}\t{{.Name}}{{end}}{{end}}';

// `docker events`, one line per event: the container's name and its
// koi.preview label, which Docker puts among the event's attributes.
const DEATH_FORMAT = '{{.Actor.Attributes.name}}\t{{index .Actor.Attributes "koi.preview"}}';

// `docker container inspect` for one container, as JSON with only what
// parseInspect reads.
const STATE_FORMAT =
	'{"State":{"Running":{{json .State.Running}}},' +
	'"NetworkSettings":{"Networks":{{json .NetworkSettings.Networks}}}}';

// Limits for every preview container. Generous enough for a large app
// server, small enough that one preview cannot starve the box. Previews and the
// builder together stay under the ceiling of the slice they run in.
export const CONTAINER_LIMITS = {
	memory: '6g',
	cpus: '3',
	pids: 2048,
};

// The `docker run` arguments for a preview, in `slice` when one is given, or
// with `create` the `docker create` ones. Exported so the confinement flags
// can be tested without Docker.
export function runArgs(
	options: RunOptions,
	slice?: string,
	command: 'run' | 'create' = 'run',
): string[] {
	const args = [
		'docker',
		...(command === 'run' ? ['run', '--detach'] : ['create']),
		'--name',
		options.name,
		'--network',
		options.network,
		'--user',
		options.user,
		'--cap-drop',
		'ALL',
		'--security-opt',
		'no-new-privileges',
		'--pids-limit',
		String(CONTAINER_LIMITS.pids),
		'--memory',
		CONTAINER_LIMITS.memory,
		'--memory-swap',
		CONTAINER_LIMITS.memory,
		'--cpus',
		CONTAINER_LIMITS.cpus,
		// koid starts every preview itself (Deployer.startFresh): after a
		// sync has taken dead containers out of the egress proxy's map, and
		// with no route until a health check passes. A restart policy would
		// have Docker start one that died, or every one when the box starts,
		// at an address the proxy may still map to another preview. When koid
		// starts, it starts the previews that serve (Deployer.restore).
		'--restart',
		'no',
		'--log-opt',
		'max-size=10m',
		'--log-opt',
		'max-file=3',
		// A pull request's Dockerfile can LABEL koi.role, and Docker would
		// copy it onto the container. The name, not this label, makes the
		// container a preview (isPreview); set to nothing here, the label
		// does not call a preview a helper to whoever reads it.
		'--label',
		'koi.role=',
	];
	if (slice !== undefined) args.push('--cgroup-parent', slice);
	for (const [key, value] of Object.entries(options.labels))
		args.push('--label', `${key}=${value}`);
	for (const [key, value] of Object.entries(options.env)) args.push('--env', `${key}=${value}`);
	args.push(options.image);
	return args;
}

// Watches Docker for koi preview containers that stop, for as long as koid
// runs: `docker events` for die events of containers labelled koi.preview.
// The filter matches the label's key, which a run's helper has too (set to
// nothing), so each event's name and label are read and only previews
// (isPreview) are passed on. Calls onEvent with each one's name, and with
// undefined each time the watch starts, since containers may have died
// while nothing watched. When docker events exits it starts again after
// restartMs. Returns a stop function.
export function watchDeaths(
	onEvent: (name: string | undefined) => void,
	log: (message: string) => void,
	options: { docker?: string; restartMs?: number } = {},
): () => void {
	const docker = options.docker ?? 'docker';
	const restartMs = options.restartMs ?? 5_000;
	let stopped = false;
	let proc: ReturnType<typeof Bun.spawn> | undefined;
	let timer: ReturnType<typeof setTimeout> | undefined;
	const watch = async () => {
		try {
			proc = Bun.spawn(
				[
					docker,
					'events',
					'--filter',
					'type=container',
					'--filter',
					'event=die',
					'--filter',
					'label=koi.preview',
					'--format',
					DEATH_FORMAT,
				],
				{ stdin: 'ignore', stdout: 'pipe', stderr: 'pipe' },
			);
			onEvent(undefined);
			const decoder = new TextDecoder();
			let partial = '';
			for await (const chunk of proc.stdout as ReadableStream<Uint8Array>) {
				const lines = (partial + decoder.decode(chunk, { stream: true })).split('\n');
				partial = lines.pop() ?? '';
				for (const line of lines) {
					const [rawName = '', preview = ''] = line.split('\t');
					const name = rawName.trim();
					if (name !== '' && isPreview(name, preview)) onEvent(name);
				}
			}
			await proc.exited;
		} catch (err) {
			log(
				`watching Docker for stopped previews: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
		if (stopped) return;
		log(`docker events stopped; watching again in ${restartMs / 1000}s`);
		timer = setTimeout(() => void watch(), restartMs);
	};
	void watch();
	return () => {
		stopped = true;
		if (timer !== undefined) clearTimeout(timer);
		proc?.kill();
	};
}

// The name a container has while koid copies its files in. Preview names
// have no dots, so it cannot be another preview's.
export function creatingName(name: string): string {
	return `${name}.creating`;
}

// The name of the container koid reads a preview's sliceFile through, which
// is never started. Like creatingName, it cannot be another preview's.
export function readerName(name: string): string {
	return `${name}.reader`;
}

// What a tar stream of one small file from `docker cp` adds to the file:
// its header, a PAX header Docker may add for its attributes, padding, and
// the two empty blocks at the end.
const TAR_OVERHEAD_BYTES = 8 * 1024;

// `docker create` for the container readImageFile reads through: no network,
// an entrypoint that is never run, the labels given.
export function readerArgs(options: ImageFileOptions): string[] {
	const args = ['docker', 'create', '--name', options.name, '--network', 'none'];
	args.push('--entrypoint', 'true');
	for (const [key, value] of Object.entries(options.labels))
		args.push('--label', `${key}=${value}`);
	args.push(options.image);
	return args;
}

// --- Verification run networks and their helpers ------------------------------
// One run gets a bridge network of its own and two containers koi owns, the
// recorder and the verifier (docs/verify.md, "Run network"). Their option
// types are separate from the app's RunOptions on purpose: nothing of the
// app's environment, files or limits reaches them.

export interface NetworkOptions {
	name: string;
	// kv<12 hex>: the firewall's default denies match kv+.
	bridge: string;
	// A /28 from the reserved pool, and its first address.
	subnet: string;
	gateway: string;
	labels: Record<string, string>;
}

// `docker network create` for a run network: internal (no route out), IPv4
// only, inter-container traffic off (the firewall helper permits exact flows
// above Docker's drop), and a bridge name the firewall matches.
export function networkArgs(options: NetworkOptions): string[] {
	const args = [
		'docker',
		'network',
		'create',
		'--driver',
		'bridge',
		'--internal',
		'--ipv6=false',
		'--subnet',
		options.subnet,
		'--gateway',
		options.gateway,
		'--opt',
		'com.docker.network.bridge.enable_icc=false',
		'--opt',
		'com.docker.network.bridge.enable_ip_masquerade=false',
		'--opt',
		`com.docker.network.bridge.name=${options.bridge}`,
	];
	for (const [key, value] of Object.entries(options.labels))
		args.push('--label', `${key}=${value}`);
	args.push(options.name);
	return args;
}

interface HelperOptions {
	name: string;
	image: string;
	network: string;
	// Fixed on create, so the firewall permits can name them before the
	// container starts.
	ip: string;
	mac: string;
	runId: string;
	// The private application name, app.<runId>.invalid, pinned to the app's
	// address on the run network in the container's /etc/hosts.
	appHost: { name: string; ip: string };
	// Where Docker's embedded resolver forwards names it does not know: the
	// run's gateway, where nothing answers, so such a lookup fails on the
	// box instead of leaving it.
	dns: string;
	// The helper's own environment: run id and private URL. Never the
	// daemon's or the app's.
	env: Record<string, string>;
}

export interface RecorderOptions extends HelperOptions {
	// A seccomp profile that lets Chromium's user namespace sandbox work.
	// Without one, Docker's default profile applies.
	seccompProfile?: string | undefined;
}

export interface VerifierOptions extends HelperOptions {
	// The program the container runs in place of the image's ENTRYPOINT:
	// the supervisor's interpreter (verifier.ts). Absent, the image's own
	// entrypoint runs, as for the placeholder the run network creates.
	entrypoint?: string | undefined;
	// The arguments after the entrypoint, or after the image's own.
	command?: string[] | undefined;
	// The working directory, over the image's.
	workdir?: string | undefined;
	// The run's input volumes, mounted read-only (verifier.ts). The
	// placeholder the run network creates has none.
	volumes?: VolumeMount[] | undefined;
}

// Limits for the two helpers, from the design's table. The recorder runs a
// browser; the verifier runs a point's commands.
export const RECORDER_LIMITS = {
	user: '10001:10001',
	memory: '2g',
	cpus: '1.5',
	pids: 512,
	tmp: '512m',
	shm: '256m',
};

export const VERIFIER_LIMITS = {
	user: '10002:10002',
	memory: '1g',
	cpus: '1',
	pids: 256,
	tmp: '256m',
	work: '128m',
};

type Limits = { user: string; memory: string; cpus: string; pids: number };

// The flags both helpers share: a fixed address and MAC on the run network
// only, a numeric user, a read-only root, no capabilities, no new
// privileges, private namespaces, an init process, no restart, bounded
// memory, CPU, processes and files, no core dumps, a 10-second stop, no
// Docker logs (capture data never goes through them), and labels that
// name the run and the role and make it no preview. The container is
// created, not started.
// The flags that confine a helper: a numeric user, a read-only root, no
// capabilities, no new privileges, a private IPC namespace, an init process,
// and bounded memory, CPU, processes and files, with no core dumps. The
// sandbox probe runs under the recorder's (sandboxProbeArgs).
function confinementArgs(limits: Limits): string[] {
	return [
		'--user',
		limits.user,
		'--read-only',
		'--cap-drop',
		'ALL',
		'--security-opt',
		'no-new-privileges=true',
		'--ipc',
		'private',
		'--init',
		'--memory',
		limits.memory,
		'--memory-swap',
		limits.memory,
		'--cpus',
		limits.cpus,
		'--pids-limit',
		String(limits.pids),
		'--ulimit',
		'nofile=4096:4096',
		'--ulimit',
		'core=0:0',
	];
}

// What the recorder has that the verifier does not: a /tmp for Chromium, its
// shared memory, and the seccomp profile that lets Chromium's sandbox make
// its namespaces.
function recorderOwnArgs(seccompProfile: string | undefined): string[] {
	const l = RECORDER_LIMITS;
	const args = [
		'--tmpfs',
		`/tmp:rw,nosuid,nodev,noexec,size=${l.tmp},uid=${uidOf(l.user)},gid=${gidOf(l.user)}`,
		'--shm-size',
		l.shm,
	];
	if (seccompProfile !== undefined) args.push('--security-opt', `seccomp=${seccompProfile}`);
	return args;
}

function helperArgs(
	options: HelperOptions,
	role: 'recorder' | 'verifier',
	limits: Limits,
	slice: string | undefined,
): string[] {
	const args = [
		'docker',
		'create',
		'--name',
		options.name,
		'--network',
		options.network,
		'--ip',
		options.ip,
		'--mac-address',
		options.mac,
		...confinementArgs(limits),
		'--restart',
		'no',
		'--stop-timeout',
		'10',
		'--log-driver',
		'none',
		'--dns',
		options.dns,
		'--add-host',
		`${options.appHost.name}:${options.appHost.ip}`,
		// The project chooses the verifier image, which may carry
		// koi.preview, and Docker would copy it onto the container. The
		// name, not this label, makes the helper no preview (isPreview);
		// set to nothing here, the label does not call a helper a preview,
		// and cleanup, which removes only what it is sure of, accepts the
		// helper as koid's (verification-network.ts, helperOf).
		'--label',
		'koi.preview=',
		'--label',
		`koi.role=${role}`,
		'--label',
		`koi.run=${options.runId}`,
	];
	if (slice !== undefined) args.push('--cgroup-parent', slice);
	for (const [key, value] of Object.entries(options.env)) args.push('--env', `${key}=${value}`);
	return args;
}

const uidOf = (user: string) => user.split(':')[0] ?? user;
const gidOf = (user: string) => user.split(':')[1] ?? user;

// The `docker create` arguments for a run's recorder. Exported so the flags
// can be tested without Docker.
export function recorderArgs(options: RecorderOptions, slice?: string): string[] {
	const args = helperArgs(options, 'recorder', RECORDER_LIMITS, slice);
	args.push(...recorderOwnArgs(options.seccompProfile), options.image);
	return args;
}

// The label on a sandbox probe, so koid can find one a crash or a stalled
// Docker left behind (host.ts). Nothing else koid cleans up looks at it:
// previews and helpers are found by koi.preview and koi.run.
export const SANDBOX_PROBE_LABEL = 'koi.sandbox-probe';

// A probe's name: koi-sandbox-probe- and 12 hex digits (host.ts). The label
// alone proves nothing, since a preview's image can carry any label and
// Docker copies it onto the container. No preview has this name: koid names
// one koi-<label>-<request id>, and a request id is 16 to 40 letters and
// digits. A helper's name ends in its role.
export function isSandboxProbe(name: string): boolean {
	return /^koi-sandbox-probe-[0-9a-f]{12}$/.test(name);
}

// The `docker run` arguments for the sandbox probe: the recorder image,
// under the recorder's confinement and with its /tmp, shared memory and
// seccomp profile, on no network, running dist/probe.js instead of the
// server. The probe starts Chromium as the recorder does, with its sandbox
// on, opens a page and closes it, and exits 0 only when all of that works.
// koid runs it before it calls verification available (host.ts).
export function sandboxProbeArgs(name: string, image: string, seccompProfile: string): string[] {
	return [
		'docker',
		'run',
		'--rm',
		'--name',
		name,
		'--label',
		SANDBOX_PROBE_LABEL,
		'--network',
		'none',
		...confinementArgs(RECORDER_LIMITS),
		...recorderOwnArgs(seccompProfile),
		'--log-driver',
		'none',
		'--entrypoint',
		'node',
		image,
		'/app/dist/probe.js',
	];
}

// The `docker create` arguments for a run's verifier: like the recorder,
// with a smaller /tmp, a /work tmpfs, the input volumes read-only, stdin
// kept open for the runner protocol (no TTY), the entrypoint and working
// directory koid chooses over the image's, and the command after the
// image. A volume is mounted with volume-nocopy, so what the image has at
// the path never gets copied over the inputs.
export function verifierArgs(options: VerifierOptions, slice?: string): string[] {
	const l = VERIFIER_LIMITS;
	const args = helperArgs(options, 'verifier', l, slice);
	const owner = `uid=${uidOf(l.user)},gid=${gidOf(l.user)}`;
	args.push(
		'--tmpfs',
		`/tmp:rw,nosuid,nodev,noexec,size=${l.tmp},${owner}`,
		'--tmpfs',
		`/work:rw,nosuid,nodev,noexec,size=${l.work},${owner}`,
		'--interactive',
	);
	for (const volume of options.volumes ?? []) {
		args.push('--mount', `${volumeMount(volume)},readonly`);
	}
	if (options.entrypoint !== undefined) args.push('--entrypoint', options.entrypoint);
	if (options.workdir !== undefined) args.push('--workdir', options.workdir);
	args.push(options.image, ...(options.command ?? []));
	return args;
}

function volumeMount(volume: VolumeMount): string {
	return `type=volume,source=${volume.name},target=${volume.destination},volume-nocopy`;
}

// The `docker create` arguments for the staging container a point's inputs
// are copied through: labelled as the run's, on no network, with the
// volumes mounted writable, and an entrypoint of `true` so an image with
// no command of its own can still be created. It is never started, so the
// image runs nothing; its root is not read-only, and `docker cp` into the
// volumes is allowed. The project chooses the image, so koi.preview is set to
// nothing for the reason helperArgs gives: cleanup would otherwise leave
// behind a staging container whose image carries that label.
export function stagingArgs(options: StagingOptions): string[] {
	const args = [
		'docker',
		'create',
		'--name',
		options.name,
		'--network',
		'none',
		'--entrypoint',
		'true',
		'--label',
		'koi.preview=',
		'--label',
		'koi.role=staging',
		'--label',
		`koi.run=${options.runId}`,
	];
	for (const volume of options.volumes) args.push('--mount', volumeMount(volume));
	args.push(options.image);
	return args;
}

// `docker network inspect --format '{{json .}}'` prints one network per
// line as JSON, so a label holding a tab or a newline stays inside its
// string instead of becoming another field or another line.
const NETWORK_FORMAT = '{{json .}}';

// From `docker network inspect --format NETWORK_FORMAT`, one network per line.
export function parseNetworks(text: string): NetworkInfo[] {
	return lines(text).map((line) => {
		const n = parseDockerJson(DockerNetworkInspectSchema, line, 'docker network inspect');
		const options = n.Options ?? {};
		const bridge = options['com.docker.network.bridge.name'];
		const run = n.Labels?.['koi.run'];
		return {
			id: n.Id,
			name: n.Name,
			driver: n.Driver,
			internal: n.Internal,
			ipv6: n.EnableIPv6,
			icc: options['com.docker.network.bridge.enable_icc'] === 'false',
			...(bridge ? { bridge } : {}),
			subnets: (n.IPAM?.Config ?? []).flatMap((c) => (c.Subnet ? [c.Subnet] : [])),
			...(run !== undefined ? { run } : {}),
			containers: Object.values(n.Containers ?? {}).map((c) => c.Name),
		};
	});
}

// `docker container inspect` for several containers: one line each, as
// JSON, with the name and the labels. JSON for the same reason as above.
const LABELS_FORMAT = '{"Name":{{json .Name}},"Labels":{{json .Config.Labels}}}';

// The same for `docker volume inspect`, whose labels sit at the top.
const VOLUME_LABELS_FORMAT = '{"Name":{{json .Name}},"Labels":{{json .Labels}}}';

// From `docker container inspect --format LABELS_FORMAT`, one container per
// line. Docker prints the name with a leading slash.
export function parseLabelled(text: string): LabelledContainer[] {
	return lines(text).map((line) => {
		const c = parseDockerJson(DockerContainerLabelsSchema, line, 'docker container inspect');
		return { name: c.Name.replace(/^\//, ''), labels: c.Labels ?? {} };
	});
}

export function cliDocker(options: CliDockerOptions): Docker {
	const run = options.exec ?? exec;
	const ok = async (cmd: string[], o: ExecOptions = {}) => {
		const r = await run(cmd, o);
		if (r.code !== 0 || r.timedOut) throw new ExecError(cmd, r);
		return r;
	};
	const docker: Docker = {
		async build(o) {
			const args = [
				'docker',
				'buildx',
				'build',
				'--builder',
				options.builder,
				'--load',
				'--progress=plain',
				'--file',
				o.dockerfile,
				'--tag',
				o.tag,
			];
			for (const [key, value] of Object.entries(o.labels)) args.push('--label', `${key}=${value}`);
			for (const [name, dir] of Object.entries(o.contexts ?? {})) {
				args.push('--build-context', `${name}=${dir}`);
			}
			for (const [name, value] of Object.entries(o.buildArgs ?? {})) {
				args.push('--build-arg', `${name}=${value}`);
			}
			args.push(o.context);
			await ok(args, { timeoutMs: o.timeoutMs, onLine: o.onLine, signal: o.signal });
		},
		async pruneBuildCache(maxUsedSpace) {
			await ok(
				[
					'docker',
					'buildx',
					'prune',
					'--builder',
					options.builder,
					'--force',
					'--max-used-space',
					maxUsedSpace,
				],
				{ timeoutMs: 10 * 60_000 },
			);
		},
		async imageUser(image) {
			const r = await ok(['docker', 'image', 'inspect', '--format', '{{.Config.User}}', image]);
			return r.stdout.trim();
		},
		async imageDigest(image) {
			const r = await ok(['docker', 'image', 'inspect', '--format', '{{.Id}}', image]);
			const id = DigestSchema.safeParse(r.stdout.trim());
			if (!id.success) {
				throw new Error(
					`docker image inspect printed ${JSON.stringify(r.stdout.trim())} for ${image}, not a sha256 image id`,
				);
			}
			return id.data;
		},
		// Through a container created from the image and never started, so
		// nothing in the image runs. docker cp prints whatever is at the path
		// as a tar archive, cut off past the limit, and koid reads it in
		// memory, never on the disk. docker cp resolves the path inside the
		// image and archives a symlink at it as a symlink, so only an archive
		// of one regular file is read (tarFileText).
		async readImageFile(o) {
			const cannot = `cannot read ${o.path} from the image`;
			await docker.remove(o.name);
			try {
				await ok(readerArgs(o), { timeoutMs: 60_000 });
				const copy = await run(['docker', 'cp', `${o.name}:${o.path}`, '-'], {
					timeoutMs: 60_000,
					maxBytes: o.maxBytes + TAR_OVERHEAD_BYTES,
					raw: true,
				}).catch((err: unknown) => {
					// exec throws an ExecError only for output past maxBytes.
					if (!(err instanceof ExecError)) throw err;
					throw new Error(`${cannot}: it is more than ${o.maxBytes} bytes`);
				});
				if (copy.code !== 0 || copy.timedOut) {
					throw new Error(`${cannot}: ${new ExecError(['docker', 'cp'], copy).message}`);
				}
				try {
					return tarFileText(
						copy.stdoutBytes ?? new Uint8Array(),
						o.maxBytes,
						posix.basename(o.path),
					);
				} catch (err) {
					throw new Error(`${cannot}: ${err instanceof Error ? err.message : String(err)}`);
				}
			} finally {
				await docker.remove(o.name).catch((err: unknown) => {
					o.log(`removing ${o.name}: ${err instanceof Error ? err.message : String(err)}`);
				});
			}
		},
		async run(o) {
			if (o.files === undefined || o.files.length === 0) {
				await ok(runArgs(o, options.slice), { timeoutMs: 60_000 });
				return;
			}
			// Created under a name of its own and renamed once every file is
			// in. If a copy fails, or koid stops part way, no container has the
			// preview's name, so the next start creates one instead of starting
			// one without its files. A leftover under the temporary name goes
			// first; reconcile removes any that koid did not come back for.
			const creating = creatingName(o.name);
			await docker.remove(creating);
			await ok(runArgs({ ...o, name: creating }, options.slice, 'create'), { timeoutMs: 60_000 });
			const dir = await mkdtemp(join(tmpdir(), 'koid-files-'));
			try {
				for (const [i, file] of o.files.entries()) {
					const local = join(dir, String(i));
					await writeFile(local, file.content, { mode: 0o644 });
					await ok(['docker', 'cp', local, `${creating}:${file.path}`], { timeoutMs: 60_000 });
				}
				await ok(['docker', 'rename', creating, o.name], { timeoutMs: 60_000 });
			} catch (err) {
				await docker.remove(creating).catch(() => {});
				throw err;
			} finally {
				await rm(dir, { recursive: true, force: true });
			}
			await ok(['docker', 'start', o.name], { timeoutMs: 60_000 });
		},
		async start(name, signal) {
			await ok(['docker', 'start', name], { timeoutMs: 60_000, signal });
		},
		async stop(name, signal) {
			const r = await run(['docker', 'stop', '--time', '10', name], {
				timeoutMs: 30_000,
				signal,
			});
			if (r.code !== 0 && !isMissing(r.stderr)) throw new ExecError(['docker', 'stop'], r);
		},
		async remove(name, signal) {
			const r = await run(['docker', 'rm', '--force', '--volumes', name], {
				timeoutMs: 30_000,
				signal,
			});
			if (r.code !== 0 && !isMissing(r.stderr)) throw new ExecError(['docker', 'rm'], r);
		},
		async removeImage(image) {
			const r = await run(['docker', 'image', 'rm', '--force', image], { timeoutMs: 60_000 });
			if (r.code !== 0 && !isMissing(r.stderr)) throw new ExecError(['docker', 'image', 'rm'], r);
		},
		async inspect(name, network, signal) {
			const r = await run(['docker', 'container', 'inspect', '--format', STATE_FORMAT, name], {
				timeoutMs: 15_000,
				maxBytes: WHOLE_OUTPUT,
				signal,
			});
			if (r.code !== 0) {
				if (isMissing(r.stderr)) return { exists: false, running: false };
				throw new ExecError(['docker', 'inspect'], r);
			}
			return parseInspect(r.stdout, network);
		},
		async list() {
			// The filter matches the label's key whatever its value, so a
			// run's helper (koi.preview set to nothing) is among the rows;
			// its name tells it apart (isPreview).
			const r = await ok(
				[
					'docker',
					'ps',
					'--all',
					'--filter',
					'label=koi.preview',
					'--format',
					'{{.Names}}\t{{.Label "koi.preview"}}',
				],
				{ timeoutMs: 15_000, maxBytes: WHOLE_OUTPUT },
			);
			return lines(r.stdout).flatMap((line) => {
				const [name = '', label = ''] = line.split('\t');
				return isPreview(name, label) ? [{ name, label }] : [];
			});
		},
		async listImages() {
			const r = await ok(
				[
					'docker',
					'image',
					'ls',
					'--filter',
					'label=koi.preview',
					'--format',
					'{{.Repository}}:{{.Tag}}',
				],
				{ timeoutMs: 15_000, maxBytes: WHOLE_OUTPUT },
			);
			// Untagged layers show as <none>:<none> and go with their image.
			return lines(r.stdout).filter((ref) => !ref.includes('<none>'));
		},
		async diskUsage() {
			// One pass over the disk measures every container's writable layer
			// and every volume, by name.
			const df = parseSystemDf(
				(
					await ok(['docker', 'system', 'df', '--verbose', '--format', DF_FORMAT], {
						timeoutMs: 240_000,
						maxBytes: WHOLE_OUTPUT,
					})
				).stdout,
			);
			if (df.layers.size === 0) return [];
			// Which of the containers are previews koi started (isPreview),
			// and what each mounts. One that went away in between is left
			// out.
			const cmd = [
				'docker',
				'container',
				'inspect',
				'--format',
				MOUNTS_FORMAT,
				...df.layers.keys(),
			];
			const r = await run(cmd, { timeoutMs: 60_000, maxBytes: WHOLE_OUTPUT });
			if (r.code !== 0 && !isMissing(r.stderr)) throw new ExecError(cmd, r);
			return lines(r.stdout).flatMap((line) => {
				const [slashName = '', label = '', ...mounted] = line.split('\t');
				const name = slashName.replace(/^\//, '');
				if (!isPreview(name, label)) return [];
				const layer = df.layers.get(name);
				let bytes = layer?.bytes ?? 0;
				for (const volume of mounted) bytes += df.volumes.get(volume) ?? 0;
				return [{ name, label, bytes, running: layer?.running ?? false }];
			});
		},
		async slice(name) {
			const r = await run(
				['docker', 'container', 'inspect', '--format', '{{.Id}} {{.State.Running}}', name],
				{ timeoutMs: 15_000 },
			);
			if (r.code !== 0) {
				if (isMissing(r.stderr)) return undefined;
				throw new ExecError(['docker', 'inspect'], r);
			}
			const [id = '', running] = r.stdout.trim().split(' ');
			if (running !== 'true') return undefined;
			// Docker's systemd cgroup driver runs a container in docker-<id>.scope.
			const scope = await ok(
				['systemctl', 'show', '--property=Slice', '--value', `docker-${id}.scope`],
				{
					timeoutMs: 15_000,
				},
			);
			return scope.stdout.trim() || undefined;
		},
		async logs(name, tail) {
			const r = await run(['docker', 'logs', '--tail', String(tail), name], { timeoutMs: 15_000 });
			if (r.code !== 0 && isMissing(r.stderr)) return '';
			return `${r.stdout}${r.stderr}`;
		},
		async createNetwork(o, signal) {
			await ok(networkArgs(o), { timeoutMs: 60_000, signal });
		},
		async removeNetwork(name, signal) {
			const r = await run(['docker', 'network', 'rm', name], { timeoutMs: 60_000, signal });
			if (r.code !== 0 && !isMissingNetwork(r.stderr)) {
				throw new ExecError(['docker', 'network', 'rm'], r);
			}
		},
		async networks(signal) {
			const ids = lines(
				(await ok(['docker', 'network', 'ls', '--quiet'], { timeoutMs: 15_000, signal })).stdout,
			);
			if (ids.length === 0) return [];
			const r = await ok(['docker', 'network', 'inspect', '--format', NETWORK_FORMAT, ...ids], {
				timeoutMs: 60_000,
				maxBytes: WHOLE_OUTPUT,
				signal,
			});
			return parseNetworks(r.stdout);
		},
		async connect(network, container, ip, signal) {
			await ok(['docker', 'network', 'connect', '--ip', ip, network, container], {
				timeoutMs: 60_000,
				signal,
			});
		},
		async disconnect(network, container, signal) {
			const r = await run(['docker', 'network', 'disconnect', network, container], {
				timeoutMs: 60_000,
				signal,
			});
			if (r.code !== 0 && !isMissing(r.stderr) && !isMissingNetwork(r.stderr)) {
				if (!/is not connected to/i.test(r.stderr)) {
					throw new ExecError(['docker', 'network', 'disconnect'], r);
				}
			}
		},
		async createRecorder(o, signal) {
			await ok(recorderArgs(o, options.slice), { timeoutMs: 60_000, signal });
		},
		async createVerifier(o, signal) {
			await ok(verifierArgs(o, options.slice), { timeoutMs: 60_000, signal });
		},
		async createVolume(name, labels, signal) {
			const args = ['docker', 'volume', 'create'];
			for (const [key, value] of Object.entries(labels)) args.push('--label', `${key}=${value}`);
			args.push(name);
			await ok(args, { timeoutMs: 30_000, signal });
		},
		async removeVolume(name, signal) {
			const r = await run(['docker', 'volume', 'rm', name], { timeoutMs: 30_000, signal });
			if (r.code !== 0 && !isMissingVolume(r.stderr))
				throw new ExecError(['docker', 'volume', 'rm'], r);
		},
		async listRunVolumes() {
			const names = lines(
				(
					await ok(['docker', 'volume', 'ls', '--quiet', '--filter', 'label=koi.run'], {
						timeoutMs: 15_000,
						maxBytes: WHOLE_OUTPUT,
					})
				).stdout,
			);
			if (names.length === 0) return [];
			// One that went away in between is left out.
			const cmd = ['docker', 'volume', 'inspect', '--format', VOLUME_LABELS_FORMAT, ...names];
			const r = await run(cmd, { timeoutMs: 60_000, maxBytes: WHOLE_OUTPUT });
			if (r.code !== 0 && !isMissingVolume(r.stderr)) throw new ExecError(cmd, r);
			return parseLabelled(r.stdout);
		},
		async createStaging(o, signal) {
			await ok(stagingArgs(o), { timeoutMs: 60_000, signal });
		},
		async imageInfo(image) {
			const r = await run(
				['docker', 'image', 'inspect', '--format', '{{.Id}}\t{{json .Config.Env}}', image],
				{ timeoutMs: 15_000, maxBytes: WHOLE_OUTPUT },
			);
			if (r.code !== 0) {
				if (isMissing(r.stderr)) return undefined;
				throw new ExecError(['docker', 'image', 'inspect'], r);
			}
			return parseImageInfo(r.stdout, image);
		},
		async copyIn(container, tar, destination, signal) {
			await ok(['docker', 'cp', '-', `${container}:${destination}`], {
				timeoutMs: 120_000,
				stdin: tar,
				signal,
			});
		},
		async attach(container) {
			const proc = Bun.spawn(['docker', 'start', '--attach', '--interactive', container], {
				stdin: 'pipe',
				stdout: 'pipe',
				stderr: 'pipe',
			});
			return {
				async write(data, o) {
					const signal = o?.signal;
					const abandoned = () => new Error('the write to the container was abandoned');
					if (signal?.aborted) throw abandoned();
					proc.stdin.write(data);
					const flushed = Promise.resolve(proc.stdin.flush());
					if (signal === undefined) {
						await flushed;
						return;
					}
					// A full pipe holds the flush, so the wait has to end elsewhere.
					let stop = () => {};
					try {
						await Promise.race([
							flushed,
							new Promise<never>((_, reject) => {
								stop = () => reject(abandoned());
								signal.addEventListener('abort', stop, { once: true });
							}),
						]);
					} finally {
						signal.removeEventListener('abort', stop);
					}
				},
				stdout: proc.stdout,
				stderr: proc.stderr,
				exited: proc.exited,
				detach() {
					proc.kill('SIGKILL');
				},
			};
		},
		async exitState(container) {
			const r = await run(
				[
					'docker',
					'container',
					'inspect',
					'--format',
					'{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}',
					container,
				],
				{ timeoutMs: 15_000 },
			);
			if (r.code !== 0) {
				if (isMissing(r.stderr)) return undefined;
				throw new ExecError(['docker', 'container', 'inspect'], r);
			}
			return parseExitState(r.stdout);
		},
		async endpoint(container, network, signal) {
			const r = await ok(
				[
					'docker',
					'container',
					'inspect',
					'--format',
					'{{json .NetworkSettings.Networks}}',
					container,
				],
				{ timeoutMs: 15_000, maxBytes: WHOLE_OUTPUT, signal },
			);
			const networks = parseDockerJson(DockerEndpointsSchema, r.stdout, 'docker container inspect');
			const attached = networks?.[network];
			if (attached === undefined) return undefined;
			const ip = attached.IPAddress || attached.IPAMConfig?.IPv4Address;
			return {
				...(ip ? { ip } : {}),
				...(attached.MacAddress ? { mac: attached.MacAddress } : {}),
				...(attached.EndpointID ? { endpointId: attached.EndpointID } : {}),
			};
		},
		async mounts(container, signal) {
			const r = await ok(
				['docker', 'container', 'inspect', '--format', '{{json .Mounts}}', container],
				{ timeoutMs: 15_000, maxBytes: WHOLE_OUTPUT, signal },
			);
			const mounts = parseDockerJson(DockerMountsSchema, r.stdout, 'docker container inspect');
			return (mounts ?? []).map((m) => ({
				type: m.Type,
				destination: m.Destination,
				...(m.Name !== undefined ? { name: m.Name } : {}),
				...(m.RW !== undefined ? { readOnly: !m.RW } : {}),
			}));
		},
		async listRun(signal) {
			const ids = lines(
				(
					await ok(['docker', 'ps', '--all', '--quiet', '--filter', 'label=koi.run'], {
						timeoutMs: 15_000,
						maxBytes: WHOLE_OUTPUT,
						signal,
					})
				).stdout,
			);
			if (ids.length === 0) return [];
			// One that went away in between is left out.
			const cmd = ['docker', 'container', 'inspect', '--format', LABELS_FORMAT, ...ids];
			const r = await run(cmd, { timeoutMs: 60_000, maxBytes: WHOLE_OUTPUT, signal });
			if (r.code !== 0 && !isMissing(r.stderr)) throw new ExecError(cmd, r);
			return parseLabelled(r.stdout);
		},
	};
	return docker;
}

function lines(text: string): string[] {
	return text.split('\n').filter((line) => line.trim() !== '');
}

// From `docker image inspect --format '{{.Id}}\t{{json .Config.Env}}'`:
// the id and the environment, which Docker prints as null when the image
// declares none.
export function parseImageInfo(text: string, image: string): ImageInfo {
	const [id = '', envJson = 'null'] = text.trim().split('\t');
	if (!DigestSchema.safeParse(id).success) {
		throw new Error(
			`docker image inspect printed ${JSON.stringify(id)} for ${image}, not a sha256 image id`,
		);
	}
	const env = parseDockerJson(DockerImageEnvSchema, envJson, `docker image inspect of ${image}`);
	return { id, env: env ?? [] };
}

// From `docker container inspect --format '{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}'`.
export function parseExitState(text: string): ExitState {
	const [status = '', code = '', oom = ''] = text.trim().split(' ');
	const exitCode = Number(code);
	if (status === '' || !Number.isInteger(exitCode) || (oom !== 'true' && oom !== 'false')) {
		throw new Error(`docker container inspect printed ${JSON.stringify(text.trim())}, not a state`);
	}
	return { status, exitCode, oomKilled: oom === 'true' };
}

const SIZE_UNITS: Record<string, number> = {
	B: 1,
	kB: 1e3,
	KB: 1e3,
	MB: 1e6,
	GB: 1e9,
	TB: 1e12,
	PB: 1e15,
	KiB: 1024,
	MiB: 1024 ** 2,
	GiB: 1024 ** 3,
	TiB: 1024 ** 4,
	PiB: 1024 ** 5,
};

// A size as docker prints it, such as "3.15MB" or "3.15MB (virtual
// 7.74MB)", in bytes. Docker prints decimal units (1 kB = 1000 B).
export function parseSize(text: string): number {
	const match = /^\s*([0-9]+(?:\.[0-9]+)?)\s*([kKMGTP]?i?B)\b/.exec(text);
	const unit = match?.[2] === undefined ? undefined : SIZE_UNITS[match[2]];
	if (match?.[1] === undefined || unit === undefined) {
		throw new Error(`cannot read a size from ${JSON.stringify(text)}`);
	}
	return Math.round(Number(match[1]) * unit);
}

// From `docker system df --verbose --format DF_FORMAT`: the writable-layer
// size of each container, and whether it runs, and the size of each volume,
// by name. Stopped containers count: a preview stopped for disk use keeps
// what it wrote, and koid must not start it again. Docker prints decimal
// units, and N/A for a volume it cannot measure.
export function parseSystemDf(text: string): {
	layers: Map<string, { bytes: number; running: boolean }>;
	volumes: Map<string, number>;
} {
	const layers = new Map<string, { bytes: number; running: boolean }>();
	const volumes = new Map<string, number>();
	for (const line of lines(text)) {
		const [kind, name = '', ...rest] = line.split('\t');
		if (kind === 'container') {
			const [state, size = ''] = rest;
			if (name !== '') layers.set(name, { bytes: parseSize(size), running: state === 'running' });
		} else if (kind === 'volume') {
			const [size = ''] = rest;
			if (name !== '' && size !== 'N/A') volumes.set(name, parseSize(size));
		}
	}
	return { layers, volumes };
}

function isMissing(stderr: string): boolean {
	return /no such (container|object|image)/i.test(stderr);
}

function isMissingNetwork(stderr: string): boolean {
	return /network \S+ not found|no such network/i.test(stderr);
}

function isMissingVolume(stderr: string): boolean {
	return /no such volume/i.test(stderr);
}

export function parseInspect(json: string, network: string): ContainerState {
	const data = parseDockerJson(DockerContainerStateSchema, json, 'docker container inspect');
	const running = data.State.Running;
	const ip = data.NetworkSettings.Networks?.[network]?.IPAddress;
	return running && ip ? { exists: true, running, ip } : { exists: true, running };
}

// Docker's JSON output, checked against one of the schemas in
// packages/shared. Throws an error that names the command and every field
// that did not match.
export function parseDockerJson<T>(schema: z.ZodType<T>, text: string, command: string): T {
	let data: unknown;
	try {
		data = JSON.parse(text);
	} catch {
		throw new Error(`${command} printed something other than JSON`);
	}
	const result = schema.safeParse(data);
	if (!result.success) {
		const fields = result.error.issues.map(
			(i) => `${i.path.join('.') || 'the output'}: ${i.message}`,
		);
		throw new Error(`${command} printed what koid cannot read: ${fields.join('; ')}`);
	}
	return result.data;
}
