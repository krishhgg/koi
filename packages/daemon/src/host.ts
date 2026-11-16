import { randomBytes } from 'node:crypto';
import { stat } from 'node:fs/promises';
import {
	type DockerNetwork,
	DockerNetworkSchema,
	type VerifyAttestation,
	verifyPoolProblem,
} from '@koi/shared';
import type { Config } from './config.ts';
import {
	isSandboxProbe,
	parseDockerJson,
	SANDBOX_PROBE_LABEL,
	sandboxProbeArgs,
} from './docker.ts';
import { type ExecOptions, type ExecResult, exec, WHOLE_OUTPUT } from './exec.ts';
import { attestationProblems, parseAttestation } from './verification-network.ts';

// What koid expects of the box before it builds or runs anything. Provisioning
// (host/cloud-init.sh) sets it up. The firewall there drops new connections
// arriving from the two bridges by name, so a network with another bridge
// name is not confined, and one with inter-container traffic enabled lets
// previews or builds reach each other. koid runs as koi and cannot read
// iptables, so the rules themselves are not checked here; koid.service
// requires koi-firewall.service instead. The slice that caps the memory of
// builds and previews together is checked here, and required there too.
export interface NetworkSpec {
	name: string;
	bridge: string;
	internal: boolean;
}

export interface HostSpec {
	networks: NetworkSpec[];
	builder: { name: string; network: string };
	// The systemd slice that holds the builder and the previews under one
	// memory ceiling, if koid uses one.
	slice?: string | undefined;
}

export function hostSpec(
	config: Pick<Config, 'network' | 'buildNetwork' | 'builder' | 'slice'>,
): HostSpec {
	return {
		networks: [
			// Previews: no route out (the egress proxy will be the only way out).
			{ name: config.network, bridge: 'koi-previews0', internal: true },
			// Builds: the internet, for packages, but not the host.
			{ name: config.buildNetwork, bridge: 'koi-build0', internal: false },
		],
		builder: { name: config.builder, network: config.buildNetwork },
		slice: config.slice,
	};
}

type Run = (cmd: string[], options?: ExecOptions) => Promise<ExecResult>;

// Every way the box differs from `spec`; empty when it is ready.
export async function verifyHost(spec: HostSpec, run: Run = exec): Promise<string[]> {
	const problems: string[] = [];
	for (const network of spec.networks) {
		const r = await run(['docker', 'network', 'inspect', '--format', '{{json .}}', network.name], {
			timeoutMs: 15_000,
			maxBytes: WHOLE_OUTPUT,
		});
		if (r.code === 0) problems.push(...networkProblems(network, r.stdout));
		else if (/not found/i.test(r.stderr)) problems.push(`network ${network.name} does not exist`);
		else problems.push(`cannot inspect network ${network.name}: ${r.stderr.trim()}`);
	}
	if (spec.slice !== undefined) problems.push(...(await sliceProblems(spec.slice, run)));
	// Started if it is not running, so that koid can see where it runs.
	const { name } = spec.builder;
	const r = await run(['docker', 'buildx', 'inspect', '--bootstrap', name], {
		timeoutMs: 120_000,
		maxBytes: WHOLE_OUTPUT,
	});
	if (r.code === 0) {
		problems.push(...builderProblems(spec.builder, r.stdout));
		if (spec.slice !== undefined) {
			const node = builderNode(r.stdout, name);
			problems.push(...(await builderSliceProblems(name, node, spec.slice, run)));
		}
	} else if (/no builder/i.test(r.stderr)) problems.push(`buildx builder ${name} does not exist`);
	else problems.push(`cannot inspect buildx builder ${name}: ${r.stderr.trim()}`);
	return problems;
}

// What verification needs of the box, over the preview checks above:
// KOI_VERIFY_POOL, the root-owned firewall helper and the slice.
export interface VerificationSpec {
	pool: string | undefined;
	helper: string;
	slice: string | undefined;
	// KOI_RECORDER_IMAGE and KOI_RECORDER_SECCOMP (config.ts).
	recorderImage: string | undefined;
	recorderSeccomp: string;
	// KOI_VERIFIER_IMAGE: the default verifier image (host/verifier).
	verifierImage: string | undefined;
	// Removes what earlier runs left (VerificationNetwork.cleanupOrphans).
	// Startup passes it; verificationCapability calls it once the helper
	// answers, before the box is judged, and a failure is a reason of its
	// own.
	cleanup?: (() => Promise<unknown>) | undefined;
}

export type VerificationCapability =
	// The image ids are what Docker resolves the configured images to.
	| {
			available: true;
			attestation: VerifyAttestation;
			recorderImageId: string;
			verifierImageId: string;
	  }
	| { available: false; reason: string };

// A file's owner and mode, or undefined when there is none. Tests pass a fake.
export type FileStat = (
	path: string,
) => Promise<{ isFile: boolean; uid: number; gid: number; mode: number } | undefined>;

async function fileStat(path: string): ReturnType<FileStat> {
	try {
		const s = await stat(path);
		return { isFile: s.isFile(), uid: s.uid, gid: s.gid, mode: s.mode & 0o7777 };
	} catch (err) {
		if (typeof err === 'object' && err !== null && 'code' in err && err.code === 'ENOENT') {
			return undefined;
		}
		throw err;
	}
}

// How long sudo and the helper get to attest.
const ATTEST_TIMEOUT_MS = 60_000;

// What a step of the check throws when it cannot finish: the reason
// verification is unavailable, naming the step.
class Unavailable extends Error {}

// Runs `work` for the check; anything it throws becomes the reason that
// `doing` did not finish.
async function step<T>(doing: string, work: () => Promise<T>): Promise<T> {
	try {
		return await work();
	} catch (err) {
		throw new Unavailable(`${doing}: ${errorText(err)}`);
	}
}

// Whether this box can run verification: the pool is set and is a network
// address of the right size, the helper is installed root-owned with mode
// 0755 and koi may run it through sudo, it
// reports the policy version koid expects, the same pool, the KOI-VERIFY
// chains with their defaults, the IPv6 denies and the bridge filtering
// sysctls, the slice the helpers share with previews holds, and the recorder
// and verifier images are named and on the box, the recorder's seccomp profile
// with them, and Chromium's sandbox starts in the recorder image under the
// recorder's confinement. Any of these missing makes verification unavailable with the
// reason; previews
// are not affected, so an old box keeps serving them.
//
// So does any failure of the check itself: a helper koi cannot stat (a
// parent directory it may not search), no sudo binary, or a step that
// throws for a reason this code did not foresee. Each becomes a reason
// that names the step; none is thrown, since koid would stop over it, and
// a box that cannot verify can still serve previews. After the helper has
// answered, such a reason joins the others and the later checks still run,
// so the operator sees every problem in one start.
//
// The cleanup runs as soon as the helper answers, whatever it attests, and
// a fresh attestation judges the box after it. The helper's revoke also
// finishes or discards a chain swap an interrupted provision left, which
// attest reports as a problem until then (the parent jumps to
// KOI-VERIFY-NEW). Judged first, such a box would skip the cleanup, keep
// the old permits and run networks, and report the same problem at every
// start.
export async function verificationCapability(
	spec: VerificationSpec,
	run: Run = exec,
	fileInfo: FileStat = fileStat,
): Promise<VerificationCapability> {
	// What the sweep of earlier probes could not do. Kept here, so a later step
	// that throws does not take it out of the answer.
	const swept: string[] = [];
	try {
		return await judgeVerification(spec, run, fileInfo, swept);
	} catch (err) {
		return { available: false, reason: [...swept, failureReason(err)].join('; ') };
	}
}

function failureReason(err: unknown): string {
	return err instanceof Unavailable
		? err.message
		: `checking the box for verification: ${errorText(err)}`;
}

async function judgeVerification(
	spec: VerificationSpec,
	run: Run,
	fileInfo: FileStat,
	swept: string[],
): Promise<VerificationCapability> {
	// What the sweep of earlier probes could not do is a reason in every answer.
	const unavailable = (reason: string): VerificationCapability => ({
		available: false,
		reason: [...swept, reason].filter((r) => r !== '').join('; '),
	});
	if (spec.pool === undefined) {
		return unavailable(
			'KOI_VERIFY_POOL is not set; provisioning writes it to /etc/koi/verify/env (scripts/provision-host.sh)',
		);
	}
	// Judged here and not when the config loads, so a wrong value costs
	// verification and nothing else.
	const malformed = verifyPoolProblem(spec.pool);
	if (malformed !== undefined) {
		return unavailable(
			`KOI_VERIFY_POOL is ${spec.pool}, which ${malformed}; it must be an IPv4 network between a /16 and a /28 with its host bits clear, as in 10.213.0.0/20 (var.verify_pool in infra/, which provisioning writes to /etc/koi/verify/env)`,
		);
	}
	if (spec.slice === undefined) {
		return unavailable(
			'koid runs without a slice, and the recorder and verifier must share one with previews',
		);
	}
	const { pool, slice } = spec;
	// First of all that asks the box: probes an earlier start left go whatever
	// the later checks find, a helper missing or sudo refused included.
	try {
		swept.push(...(await removeLeftoverProbes(run)));
	} catch (err) {
		swept.push(failureReason(err));
	}
	const file = await step(`checking ${spec.helper}`, () => fileInfo(spec.helper));
	if (file === undefined) {
		return unavailable(`${spec.helper} is not installed; scripts/deploy-host.sh installs it`);
	}
	if (!file.isFile) return unavailable(`${spec.helper} is not a regular file`);
	if (file.uid !== 0 || file.gid !== 0) {
		return unavailable(`${spec.helper} is owned by ${file.uid}:${file.gid}, not root`);
	}
	if (file.mode !== 0o755) {
		return unavailable(
			`${spec.helper} has mode ${file.mode.toString(8).padStart(4, '0')}, not 0755`,
		);
	}
	const command = ['sudo', '-n', spec.helper, 'attest'];
	// Spawning can throw too, as when the box has no sudo.
	const attest = () =>
		step(`running ${command.join(' ')}`, () =>
			run(command, { timeoutMs: ATTEST_TIMEOUT_MS, maxBytes: WHOLE_OUTPUT }),
		);
	// Why sudo or the helper gave no answer, or undefined when it answered.
	// exec kills a command that runs past its time and says so.
	const unanswered = (r: ExecResult): string | undefined => {
		const detail = r.stderr.trim() || r.stdout.trim();
		if (r.timedOut) {
			return `${command.join(' ')} gave no answer in ${ATTEST_TIMEOUT_MS / 1000} seconds${detail ? `: ${detail}` : ''}`;
		}
		if (r.code !== 0) {
			return `${command.join(' ')} exited ${r.code}: ${detail}; provisioning installs the sudoers rule for it`;
		}
		return undefined;
	};
	let r = await attest();
	const refused = unanswered(r);
	if (refused !== undefined) return unavailable(refused);
	const problems: string[] = [];
	// Runs a step that may throw. The catch in verificationCapability cannot
	// see `problems`, so a failure has to join them here or they are lost.
	const collecting = async <T>(work: () => Promise<T>): Promise<T | undefined> => {
		try {
			return await work();
		} catch (err) {
			problems.push(failureReason(err));
			return undefined;
		}
	};
	if (spec.cleanup !== undefined) {
		try {
			await spec.cleanup();
		} catch (err) {
			problems.push(`removing what earlier runs left: ${errorText(err)}`);
		}
		const after = await collecting(attest);
		if (after === undefined) return unavailable(problems.join('; '));
		r = after;
		const stopped = unanswered(r);
		if (stopped !== undefined) return unavailable([...problems, stopped].join('; '));
	}
	let attestation: VerifyAttestation;
	try {
		attestation = parseAttestation(r.stdout);
	} catch (err) {
		return unavailable([...problems, errorText(err)].join('; '));
	}
	// No run outlives koid, so a cleanup that reported nothing wrong leaves
	// the helper holding no run. One it still lists may hold permits that
	// nothing accounts for.
	if (spec.cleanup !== undefined && problems.length === 0 && attestation.runs.length > 0) {
		const listed = attestation.runs.map((id) => `run ${id}`).join(', ');
		problems.push(`the helper still lists ${listed} after the cleanup`);
	}
	problems.push(...attestationProblems(attestation, pool));
	const sliceFound = await collecting(() =>
		step(`checking ${slice}`, () => sliceProblems(slice, run)),
	);
	problems.push(...(sliceFound ?? []));
	const images = await collecting(() => judgeImages(spec, run, fileInfo));
	if (images?.ready === false) problems.push(images.problem);
	if (images?.ready !== true || problems.length > 0 || swept.length > 0) {
		return unavailable(problems.join('; '));
	}
	return {
		available: true,
		attestation,
		recorderImageId: images.recorderImageId,
		verifierImageId: images.verifierImageId,
	};
}

// The recorder's image and seccomp profile, and the default verifier image.
// The caller asks only after the cleanup: none of them has a part in removing
// what earlier runs left, so a box without them must not keep those permits
// and networks.
async function judgeImages(
	spec: VerificationSpec,
	run: Run,
	fileInfo: FileStat,
): Promise<
	| { ready: true; recorderImageId: string; verifierImageId: string }
	| { ready: false; problem: string }
> {
	const { recorderImage, recorderSeccomp, verifierImage } = spec;
	if (recorderImage === undefined) {
		return {
			ready: false,
			problem:
				'KOI_RECORDER_IMAGE is not set; build host/recorder on the box and set it to the image id in /etc/koi/verify/env',
		};
	}
	if (verifierImage === undefined) {
		return {
			ready: false,
			problem:
				'KOI_VERIFIER_IMAGE is not set; build host/verifier on the box and set it to the image id in /etc/koi/verify/env',
		};
	}
	const seccomp = await step(`checking ${recorderSeccomp}`, () => fileInfo(recorderSeccomp));
	if (seccomp === undefined || !seccomp.isFile) {
		return {
			ready: false,
			problem: `${recorderSeccomp} is not installed; copy host/recorder/seccomp.json there (KOI_RECORDER_SECCOMP)`,
		};
	}
	const imageIds: string[] = [];
	for (const [role, image] of [
		['recorder', recorderImage],
		['verifier', verifierImage],
	] as const) {
		const inspected = await step(`checking the ${role} image ${image}`, () =>
			run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], {
				timeoutMs: 15_000,
			}),
		);
		const id = inspected.stdout.trim();
		if (inspected.code !== 0 || !/^sha256:[0-9a-f]{64}$/.test(id)) {
			return {
				ready: false,
				problem: `the ${role} image ${image} is not on the box: ${inspected.stderr.trim() || 'docker image inspect printed no id'}`,
			};
		}
		imageIds.push(id);
	}
	const [recorderImageId = '', verifierImageId = ''] = imageIds;
	// Chromium's sandbox, tried where it will run. A seccomp file older than
	// host/recorder/seccomp.json, or a host whose AppArmor policy keeps Docker's
	// containers from making a user namespace, would let every run start and
	// then lose its recorder, with Chromium's own words for why.
	const problem = await sandboxProbe(run, recorderImageId, recorderSeccomp);
	if (problem !== undefined) return { ready: false, problem };
	return { ready: true, recorderImageId, verifierImageId };
}

// How long the sandbox probe may take: the recorder image starting, and
// Chromium launching, opening a page and closing.
const PROBE_TIMEOUT_MS = 120_000;

// The first line a command printed to stderr, or how it ended when it
// printed none.
function said(r: ExecResult, timeoutMs: number): string {
	if (r.timedOut) return `no answer in ${timeoutMs / 1000} seconds`;
	const line = r.stderr
		.split('\n')
		.map((l) => l.trim())
		.find((l) => l !== '');
	return line?.slice(0, 400) ?? `it exited ${r.code}`;
}

// Whether `docker rm --force` left none of what it was given: it removed
// each, or one was gone already, as a probe that ran and exited is (--rm).
function removed(r: ExecResult): boolean {
	if (r.timedOut) return false;
	if (r.code === 0) return true;
	const errors = r.stderr
		.split('\n')
		.map((l) => l.trim())
		.filter((l) => l !== '');
	return errors.length > 0 && errors.every((l) => /No such container/i.test(l));
}

// Removes the sandbox probes an earlier start left, because koid stopped or
// Docker stalled before the container ran (--rm removes only a container that
// ran), and returns what it could not do. A probe is known by its label and
// its name both: a preview's image can carry the label, never the name.
async function removeLeftoverProbes(run: Run): Promise<string[]> {
	const listing = await step('looking for sandbox probes left behind', () =>
		run(
			[
				'docker',
				'ps',
				'--all',
				'--filter',
				`label=${SANDBOX_PROBE_LABEL}`,
				'--format',
				'{{.Names}}',
			],
			// Whole: a preview's image can carry the label, and a listing cut to
			// its last part could leave a real probe out.
			{ timeoutMs: 15_000, maxBytes: WHOLE_OUTPUT },
		),
	);
	if (listing.code !== 0 || listing.timedOut) {
		return [`looking for sandbox probes left behind: ${said(listing, 15_000)}`];
	}
	const names = listing.stdout
		.split('\n')
		.map((line) => line.trim())
		.filter(isSandboxProbe);
	if (names.length === 0) return [];
	const removal = await step('removing sandbox probes left behind', () =>
		run(['docker', 'rm', '--force', ...names], { timeoutMs: 30_000 }),
	);
	if (removed(removal)) return [];
	return [`removing the sandbox probes ${names.join(', ')} left behind: ${said(removal, 30_000)}`];
}

// Runs the sandbox probe (docker.ts, sandboxProbeArgs) and returns why
// verification cannot run, or undefined when Chromium started. The probe's
// container is removed after, whatever happened; one that stays is a reason
// too, and the next start removes it (removeLeftoverProbes).
async function sandboxProbe(run: Run, image: string, seccomp: string): Promise<string | undefined> {
	const name = `koi-sandbox-probe-${randomBytes(6).toString('hex')}`;
	let probe: ExecResult;
	let removal: ExecResult;
	try {
		probe = await step("trying Chromium's sandbox in the recorder image", () =>
			run(sandboxProbeArgs(name, image, seccomp), { timeoutMs: PROBE_TIMEOUT_MS }),
		);
	} finally {
		removal = await run(['docker', 'rm', '--force', name], { timeoutMs: 30_000 }).catch(
			(err: unknown): ExecResult => ({
				code: -1,
				stdout: '',
				stderr: errorText(err),
				timedOut: false,
			}),
		);
	}
	const problems: string[] = [];
	if (probe.code !== 0) {
		// An image built before the probe was: Node's first line names only its own loader.
		problems.push(
			probe.stderr.includes("Cannot find module '/app/dist/probe.js'")
				? `the recorder image ${image} has no dist/probe.js, so koid cannot check that Chromium's sandbox starts in it; rebuild it from host/recorder and set KOI_RECORDER_IMAGE to the new id`
				: `Chromium's sandbox cannot start in the recorder image under its confinement: ${probe.timedOut ? `it did not finish in ${PROBE_TIMEOUT_MS / 1000} seconds` : said(probe, PROBE_TIMEOUT_MS)}. Copy host/recorder/seccomp.json to ${seccomp} again; if that is current, this host's AppArmor policy keeps Docker's containers from making a user namespace`,
		);
	}
	if (!removed(removal)) {
		problems.push(
			`the sandbox probe ${name} was not removed: ${said(removal, 30_000)}; the next start removes it`,
		);
	}
	return problems.length > 0 ? problems.join('; ') : undefined;
}

function errorText(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

// Problems with the slice: Docker must use its systemd cgroup driver, the
// only one that places containers in a systemd slice, and the slice must be
// active with a memory ceiling. A slice systemd made up because a container
// named it has none.
async function sliceProblems(slice: string, run: Run): Promise<string[]> {
	const problems: string[] = [];
	const info = await run(['docker', 'info', '--format', '{{.CgroupDriver}}'], {
		timeoutMs: 15_000,
	});
	const driver = info.stdout.trim();
	if (info.code !== 0) {
		problems.push(`cannot ask docker for its cgroup driver: ${info.stderr.trim()}`);
	} else if (driver !== 'systemd') {
		problems.push(
			`docker uses the ${driver} cgroup driver, not systemd, so its containers are not in ${slice}`,
		);
	}
	const show = await run(['systemctl', 'show', '--property=ActiveState,MemoryMax', slice], {
		timeoutMs: 15_000,
	});
	if (show.code !== 0) {
		problems.push(`cannot read ${slice}: ${show.stderr.trim()}`);
		return problems;
	}
	const unit = properties(show.stdout);
	if (unit.get('ActiveState') !== 'active') problems.push(`${slice} is not active`);
	const max = unit.get('MemoryMax');
	if (max === undefined || max === 'infinity') {
		problems.push(`${slice} has no memory ceiling (MemoryMax)`);
	}
	return problems;
}

// Problems with where the builder's container runs. buildx makes it without
// a cgroup parent under the systemd driver, so it lands in the slice only
// through Docker's default parent (/etc/docker/daemon.json), which koid
// cannot read from Docker; it reads where the running container is instead.
async function builderSliceProblems(
	builder: string,
	node: string,
	slice: string,
	run: Run,
): Promise<string[]> {
	const container = `buildx_buildkit_${node}`;
	const r = await run(
		['docker', 'container', 'inspect', '--format', '{{.Id}} {{.State.Running}}', container],
		{ timeoutMs: 15_000 },
	);
	const [id = '', running] = r.stdout.trim().split(' ');
	if (r.code !== 0 || running !== 'true') {
		return [
			`buildx builder ${builder} is not running in ${container}, so koid cannot see its slice`,
		];
	}
	const scope = await run(
		['systemctl', 'show', '--property=Slice', '--value', `docker-${id}.scope`],
		{
			timeoutMs: 15_000,
		},
	);
	const where = scope.stdout.trim();
	if (scope.code === 0 && where === slice) return [];
	return [
		`buildx builder ${builder} runs in ${where || 'no slice'}, not ${slice}; set cgroup-parent in /etc/docker/daemon.json and restart docker`,
	];
}

// The builder's node, from `docker buildx inspect`: the first Name under
// Nodes, which buildx makes <builder>0. Its container is
// buildx_buildkit_<node>.
export function builderNode(output: string, builder: string): string {
	const at = output.indexOf('\nNodes:');
	const name = at < 0 ? undefined : /^Name:\s+(\S+)\s*$/m.exec(output.slice(at))?.[1];
	return name ?? `${builder}0`;
}

// `systemctl show` output, one key=value per line.
function properties(text: string): Map<string, string> {
	const out = new Map<string, string>();
	for (const line of text.split('\n')) {
		const at = line.indexOf('=');
		if (at > 0) out.set(line.slice(0, at), line.slice(at + 1).trim());
	}
	return out;
}

// Problems with one network, from `docker network inspect --format '{{json .}}'`.
export function networkProblems(spec: NetworkSpec, json: string): string[] {
	const name = `network ${spec.name}`;
	let n: DockerNetwork;
	try {
		n = parseDockerJson(DockerNetworkSchema, json, 'docker network inspect');
	} catch (err) {
		return [`${name}: ${err instanceof Error ? err.message : String(err)}`];
	}
	const problems: string[] = [];
	if (n.Driver !== 'bridge') problems.push(`${name} uses the ${n.Driver} driver, not bridge`);
	if ((n.Internal === true) !== spec.internal) {
		problems.push(spec.internal ? `${name} is not internal` : `${name} is internal`);
	}
	if (n.Options?.['com.docker.network.bridge.enable_icc'] !== 'false') {
		problems.push(`${name} lets its containers reach each other (enable_icc is not false)`);
	}
	const bridge = n.Options?.['com.docker.network.bridge.name'];
	if (bridge !== spec.bridge) {
		problems.push(`${name} has bridge ${bridge ?? '(automatic)'}, not ${spec.bridge}`);
	}
	return problems;
}

// Problems with the builder, from `docker buildx inspect <name>`, which lists
// the driver options even while the builder is stopped.
export function builderProblems(spec: HostSpec['builder'], output: string): string[] {
	const problems: string[] = [];
	const name = `buildx builder ${spec.name}`;
	if (!/^Driver:\s+docker-container\s*$/m.test(output)) {
		problems.push(`${name} does not use the docker-container driver`);
	}
	const line = /^Driver Options:(.*)$/m.exec(output)?.[1] ?? '';
	const options = new Map(
		[...line.matchAll(/([a-z.-]+)="([^"]*)"/g)].map((m) => [m[1] ?? '', m[2] ?? '']),
	);
	if (options.get('network') !== spec.network) {
		problems.push(`${name} is not on network ${spec.network}`);
	}
	for (const limit of ['memory', 'cpu-quota']) {
		if (!options.has(limit)) problems.push(`${name} has no ${limit} limit`);
	}
	return problems;
}
