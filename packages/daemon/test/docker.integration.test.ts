import { afterAll, beforeAll, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DockerHostConfigSchema } from '@koi/shared';
import { z } from 'zod';
import { BuildLogs } from '../src/buildlog.ts';
import type { Route } from '../src/caddy.ts';
import { Deployer } from '../src/deployer.ts';
import { cliDocker, creatingName, parseDockerJson, watchDeaths } from '../src/docker.ts';
import { egressFiles } from '../src/egress-config.ts';
import { exec } from '../src/exec.ts';
import { diskSpace, extractTarball, resolveInside } from '../src/fsutil.ts';
import { verifyHost } from '../src/host.ts';
import { PreviewStore } from '../src/store.ts';
import {
	addressesOf,
	bridgeName,
	helperMac,
	helperName,
	privateHost,
	runNetworkName,
	runNetworkProblems,
} from '../src/verification-network.ts';
import { request } from './fakes.ts';

// Real Docker, opt in with KOI_DOCKER_TESTS=1. Builds examples/hello in a
// BuildKit builder of its own, runs it with the production confinement flags
// on an internal network, and checks the result answers on its routed address
// and cannot reach the internet.
//
// Every name is unique to this run, and cleanup removes only what this run
// created, so it can run next to real previews or another run.
const enabled = process.env.KOI_DOCKER_TESTS === '1';
const run = randomUUID().replace(/-/g, '').slice(0, 10);
const label = `it-${run}`;
const network = `koi-it-${run}`;
const buildNetwork = `koi-it-build-${run}`;
const builder = `koi-it-${run}`;
// Interface names are at most 15 characters.
const bridge = `kp${run.slice(0, 8)}0`;
const buildBridge = `kb${run.slice(0, 8)}0`;
const volumeImage = `koi-it-volume:${run}`;
const scratchImage = `koi-it-scratch:${run}`;
// A slice of this run's own. Not koi-...: a dash in a slice name nests it in
// the slice its first word names, here the box's koi.slice.
const slice = `koiit${run}.slice`;
// A verification run of this test's own: its network and helpers carry
// koi.run=<this>, and its subnet is in TEST-NET-1, which nothing routes.
const verifyRun = `it${run}${run}`;
const verifySubnet = '192.0.2.0/28';
const repo = resolve(import.meta.dir, '../../..');
const docker = cliDocker({ builder });
// Anonymous volumes this run saw, removed at the end even if a test failed.
const volumes: string[] = [];
// What the volume test reads from `docker container inspect`.
const MountsSchema = z.array(z.object({ Type: z.string(), Name: z.string().optional() }));

async function must(cmd: string[]): Promise<string> {
	const r = await exec(cmd, { timeoutMs: 180_000 });
	if (r.code !== 0) throw new Error(`${cmd.join(' ')}: ${r.stderr}`);
	return r.stdout;
}

// The systemd slice the running container `name` is in.
async function sliceOf(name: string): Promise<string> {
	const id = (await must(['docker', 'container', 'inspect', '--format', '{{.Id}}', name])).trim();
	return (
		await must(['systemctl', 'show', '--property=Slice', '--value', `docker-${id}.scope`])
	).trim();
}

// An image that sleeps with an empty volume at /data, built once.
let volumeImageBuilt: Promise<void> | undefined;
function buildVolumeImage(): Promise<void> {
	volumeImageBuilt ??= (async () => {
		const context = await mkdtemp(join(tmpdir(), 'koid-it-volume-'));
		await writeFile(
			join(context, 'Dockerfile'),
			'FROM busybox:1.37\nRUN mkdir /data && chown 65534:65534 /data\nVOLUME /data\nCMD ["sleep", "300"]\n',
		);
		await docker.build({
			dockerfile: join(context, 'Dockerfile'),
			context,
			tag: volumeImage,
			labels: { 'koi.preview': label },
			timeoutMs: 180_000,
			onLine: () => {},
		});
	})();
	return volumeImageBuilt;
}

beforeAll(async () => {
	if (!enabled) return;
	const confined = (name: string) => [
		'-o',
		'com.docker.network.bridge.enable_icc=false',
		'-o',
		`com.docker.network.bridge.name=${name}`,
	];
	await must(['docker', 'network', 'create', '--internal', ...confined(bridge), network]);
	await must(['docker', 'network', 'create', ...confined(buildBridge), buildNetwork]);
	await must([
		'docker',
		'buildx',
		'create',
		'--name',
		builder,
		'--driver',
		'docker-container',
		'--driver-opt',
		`network=${buildNetwork}`,
		'--driver-opt',
		'memory=2g',
		'--driver-opt',
		'cpu-quota=200000',
		'--bootstrap',
	]);
}, 180_000);

afterAll(async () => {
	if (!enabled) return;
	const containers = await exec(['docker', 'ps', '-aq', '--filter', `label=koi.preview=${label}`]);
	for (const id of containers.stdout.split('\n').filter(Boolean)) {
		await exec(['docker', 'rm', '--force', '--volumes', id]);
	}
	const images = await exec([
		'docker',
		'image',
		'ls',
		'--filter',
		`reference=koi-preview/${label}`,
		'--format',
		'{{.Repository}}:{{.Tag}}',
	]);
	for (const image of [...images.stdout.split('\n').filter(Boolean), volumeImage, scratchImage]) {
		await exec(['docker', 'image', 'rm', '--force', image]);
	}
	for (const volume of volumes) await exec(['docker', 'volume', 'rm', volume]);
	await exec(['docker', 'buildx', 'rm', '--force', builder]);
	const helpers = await exec(['docker', 'ps', '-aq', '--filter', `label=koi.run=${verifyRun}`]);
	for (const id of helpers.stdout.split('\n').filter(Boolean)) {
		await exec(['docker', 'rm', '--force', '--volumes', id]);
	}
	await exec(['docker', 'network', 'rm', network, buildNetwork, runNetworkName(verifyRun)]);
}, 120_000);

test.skipIf(!enabled)(
	'koid accepts networks and a builder made the way provisioning makes them',
	async () => {
		expect(
			await verifyHost({
				networks: [
					{ name: network, bridge, internal: true },
					{ name: buildNetwork, bridge: buildBridge, internal: false },
				],
				builder: { name: builder, network: buildNetwork },
			}),
		).toEqual([]);
		expect(
			await verifyHost({
				networks: [{ name: network, bridge: 'koi-previews0', internal: false }],
				builder: { name: `${builder}-missing`, network: buildNetwork },
			}),
		).toEqual([
			`network ${network} is internal`,
			`network ${network} has bridge ${bridge}, not koi-previews0`,
			`buildx builder ${builder}-missing does not exist`,
		]);
	},
);

test.skipIf(!enabled)(
	'builds in its own builder and serves examples/hello, confined',
	async () => {
		const state = await mkdtemp(join(tmpdir(), 'koid-it-'));
		const tarball = join(state, 'hello.tar.gz');
		await must(['tar', '-czf', tarball, '-C', join(repo, 'examples/hello'), '.']);
		const store = new PreviewStore(state);
		await store.init();
		const routes: Route[][] = [];
		const up = request({ id: randomUUID().replace(/-/g, ''), label });
		const deployer = new Deployer({
			domain: 'previews.example.net',
			network,
			stateDir: state,
			store,
			docker,
			uploads: {
				request: async () => up,
				claim: async () => {},
				release: async () => {},
				downloadSource: async (_id, file) => {
					await Bun.write(file, Bun.file(tarball));
				},
			},
			caddy: { apply: async (r) => void routes.push(r) },
			live: { publish: async () => {}, room: () => ({ ok: true }) },
			buildLogs: new BuildLogs(state),
			builtinRecipe: async () => {
				throw new Error('unused');
			},
			readRecipe: async () => {
				throw new Error('unused');
			},
			keepAwake: async () => {},
			extract: extractTarball,
			resolveInside,
			diskSpace: () => diskSpace('/var/lib/docker'),
			probe: async (url) => {
				try {
					return (await fetch(url, { signal: AbortSignal.timeout(2000) })).status < 500;
				} catch {
					return false;
				}
			},
			drainVisits: () => [],
			now: () => new Date(),
			sleep: (ms) => Bun.sleep(ms),
			log: (m) => console.log(m),
		});

		await deployer.up(up.id);
		await deployer.settled(up.label);
		const record = await store.get(up.label);
		expect(record?.error).toBeUndefined();
		expect(record?.status).toBe('running');
		const upstream = routes.at(-1)?.[0]?.upstream;
		expect(upstream).toMatch(/^\d+\.\d+\.\d+\.\d+:8080$/);
		const page = await (await fetch(`http://${upstream}/`)).text();
		expect(page).toContain('hello from koi');
		// The build ran in this run's builder: its cache holds the layers.
		expect(await must(['docker', 'buildx', 'du', '--builder', builder])).toMatch(/Total:\s+[1-9]/);

		const container = record?.deployment?.container ?? '';
		const inspect = await must([
			'docker',
			'inspect',
			'--format',
			'{{.Config.User}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}} {{json .HostConfig.PortBindings}} {{json .HostConfig.Binds}}',
			container,
		]);
		expect(inspect.trim()).toBe('65534:65534 ["ALL"] ["no-new-privileges"] {} null');
		const out = await exec([
			'docker',
			'exec',
			container,
			'wget',
			'-q',
			'-T',
			'3',
			'-O',
			'-',
			'http://example.com/',
		]);
		expect(out.code).not.toBe(0);

		await deployer.down(up.label);
		expect((await docker.inspect(container, network)).exists).toBe(false);
		const left = await must([
			'docker',
			'image',
			'ls',
			'--quiet',
			'--filter',
			`reference=koi-preview/${label}`,
		]);
		expect(left.trim()).toBe('');
	},
	300_000,
);

test.skipIf(!enabled)(
	'the watchdog counts what a container writes to its volumes, running or stopped, and removing it removes them',
	async () => {
		await buildVolumeImage();
		const name = `koi-${label}-volume`;
		await docker.run({
			name,
			image: volumeImage,
			network,
			user: '65534:65534',
			env: {},
			labels: { 'koi.preview': label },
		});
		const mounts = MountsSchema.parse(
			JSON.parse(
				await must(['docker', 'container', 'inspect', '--format', '{{json .Mounts}}', name]),
			),
		);
		const mine = mounts.flatMap((m) => (m.Type === 'volume' && m.Name ? [m.Name] : []));
		volumes.push(...mine);
		expect(mine).toHaveLength(1);
		// 16 MiB in the volume, nothing in the writable layer.
		await must([
			'docker',
			'exec',
			name,
			'dd',
			'if=/dev/zero',
			'of=/data/fill',
			'bs=1M',
			'count=16',
		]);
		const usage = (await docker.diskUsage()).find((c) => c.name === name);
		expect(usage?.label).toBe(label);
		expect(usage?.running).toBe(true);
		expect(usage?.bytes).toBeGreaterThanOrEqual(16 * 1024 ** 2);
		// Stopped, it still counts: a stopped preview keeps what it wrote.
		await docker.stop(name);
		const stopped = (await docker.diskUsage()).find((c) => c.name === name);
		expect(stopped?.running).toBe(false);
		expect(stopped?.bytes).toBeGreaterThanOrEqual(16 * 1024 ** 2);
		await docker.remove(name);
		for (const volume of mine) {
			expect((await exec(['docker', 'volume', 'inspect', volume])).code).not.toBe(0);
		}
	},
	300_000,
);

test.skipIf(!enabled)(
	'the watchdog and inspect read containers whose full inspect output is large',
	async () => {
		await buildVolumeImage();
		// About 100 KB of environment each, so the three together inspect to
		// more than 256 KiB of JSON.
		const env = Object.fromEntries(
			Array.from({ length: 25 }, (_, i) => [`KOI_BIG_${i}`, 'x'.repeat(4000)]),
		);
		const names = [1, 2, 3].map((i) => `koi-${label}-big${i}`);
		for (const name of names) {
			await docker.run({
				name,
				image: volumeImage,
				network,
				user: '65534:65534',
				env,
				labels: { 'koi.preview': label },
			});
		}
		const full = await exec(
			['docker', 'container', 'inspect', '--format', '{{json .}}', ...names],
			{
				maxBytes: 1024 ** 2,
			},
		);
		expect(full.stdout.length).toBeGreaterThan(256 * 1024);
		const usage = await docker.diskUsage();
		for (const name of names) {
			expect(usage.find((c) => c.name === name)?.label).toBe(label);
			const state = await docker.inspect(name, network);
			expect(state.running).toBe(true);
			expect(state.ip).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
			await docker.remove(name);
		}
	},
	300_000,
);

// Assumes Docker's systemd cgroup driver, as on the box.
test.skipIf(!enabled)(
	'runs a preview in the slice it is given, and koid sees a slice without a ceiling and a builder outside it',
	async () => {
		await buildVolumeImage();
		const name = `koi-${label}-sliced`;
		await cliDocker({ builder, slice }).run({
			name,
			image: volumeImage,
			network,
			user: '65534:65534',
			env: {},
			labels: { 'koi.preview': label },
		});
		expect(await sliceOf(name)).toBe(slice);
		expect(await cliDocker({ builder, slice }).slice(name)).toBe(slice);
		// systemd made the slice up for the container, with no ceiling, and
		// this run's builder runs where Docker puts containers by default:
		// system.slice on a workstation, koi.slice on a box provisioned for
		// koi. Either way, not in this run's slice.
		const builderSlice = await sliceOf(`buildx_buildkit_${builder}0`);
		expect(builderSlice).not.toBe(slice);
		const problems = await verifyHost({
			networks: [],
			builder: { name: builder, network: buildNetwork },
			slice,
		});
		expect(problems).toContain(`${slice} has no memory ceiling (MemoryMax)`);
		expect(problems).toContain(
			`buildx builder ${builder} runs in ${builderSlice}, not ${slice}; set cgroup-parent in /etc/docker/daemon.json and restart docker`,
		);
		await docker.remove(name);
	},
	300_000,
);

test.skipIf(!enabled)(
	'a preview whose files did not all go in never has its name, and the next run replaces what an interrupted one left',
	async () => {
		await buildVolumeImage();
		const name = `koi-${label}-files`;
		const base = {
			name,
			image: volumeImage,
			network,
			user: '65534:65534',
			env: {},
			labels: { 'koi.preview': label },
		};
		const gone = { exists: false, running: false };
		// The second copy fails: the image has no such directory.
		await expect(
			docker.run({
				...base,
				files: [
					{ path: '/etc/koi-ca.pem', content: 'CA\n' },
					{ path: '/no/such/dir/file', content: 'x' },
				],
			}),
		).rejects.toThrow();
		expect(await docker.inspect(name, network)).toEqual(gone);
		expect(await docker.inspect(creatingName(name), network)).toEqual(gone);
		// koid stopped after creating the container and before its copies.
		await must([
			'docker',
			'create',
			'--name',
			creatingName(name),
			'--label',
			`koi.preview=${label}`,
			volumeImage,
		]);
		// A visit finds no container by the preview's name, so it runs one.
		expect(await docker.inspect(name, network)).toEqual(gone);
		await docker.run({ ...base, files: [{ path: '/etc/koi-ca.pem', content: 'CA\n' }] });
		expect((await docker.inspect(name, network)).running).toBe(true);
		expect(await must(['docker', 'exec', name, 'cat', '/etc/koi-ca.pem'])).toBe('CA\n');
		expect(await docker.inspect(creatingName(name), network)).toEqual(gone);
		await docker.remove(name);
	},
	300_000,
);

test.skipIf(!enabled)(
	'a preview from an image with no /etc gets the CA files, created and created again',
	async () => {
		// A static busybox on its own: no /etc or any other directory.
		const context = await mkdtemp(join(tmpdir(), 'koid-it-scratch-'));
		await writeFile(
			join(context, 'Dockerfile'),
			'FROM busybox:1.37-musl AS busybox\nFROM scratch\nCOPY --from=busybox /bin/busybox /busybox\nCMD ["/busybox", "sleep", "300"]\n',
		);
		await docker.build({
			dockerfile: join(context, 'Dockerfile'),
			context,
			tag: scratchImage,
			labels: { 'koi.preview': label },
			timeoutMs: 180_000,
			onLine: () => {},
		});
		const files = egressFiles({
			proxy: 'http://192.0.2.1:3128',
			caBundle: 'BUNDLE\n',
			caCert: 'CA\n',
		});
		const name = `koi-${label}-scratch`;
		const options = {
			name,
			image: scratchImage,
			network,
			user: '65534:65534',
			env: {},
			labels: { 'koi.preview': label },
			files,
		};
		// As a deploy creates it, then as a visit recreates it after it went.
		for (const _ of ['create', 'recreate']) {
			await docker.run(options);
			expect((await docker.inspect(name, network)).running).toBe(true);
			for (const file of files) {
				expect(await must(['docker', 'exec', name, '/busybox', 'cat', file.path])).toBe(
					file.content,
				);
			}
			await docker.remove(name);
		}
	},
	300_000,
);

test.skipIf(!enabled)(
	'watchDeaths hears of a preview container that dies on its own, and Docker gives its address to the next',
	async () => {
		await buildVolumeImage();
		const events: Array<string | undefined> = [];
		const stop = watchDeaths(
			(name) => events.push(name),
			() => {},
		);
		try {
			const until = async (done: () => boolean) => {
				const deadline = Date.now() + 15_000;
				while (!done() && Date.now() < deadline) await Bun.sleep(50);
				return done();
			};
			// The watch has started, and docker events has had time to subscribe.
			expect(await until(() => events.includes(undefined))).toBe(true);
			await Bun.sleep(1000);
			const dying = `koi-${label}-dying`;
			const next = `koi-${label}-next`;
			const options = {
				image: volumeImage,
				network,
				user: '65534:65534',
				env: {},
				labels: { 'koi.preview': label },
			};
			await docker.run({ name: dying, ...options });
			const ip = (await docker.inspect(dying, network)).ip;
			// Dies on its own: koid did not stop it.
			await must(['docker', 'kill', dying]);
			expect(await until(() => events.includes(dying))).toBe(true);
			// Why the map must change before the next start: Docker hands the
			// address out again at once.
			await docker.run({ name: next, ...options });
			expect((await docker.inspect(next, network)).ip).toBe(ip);
			await docker.remove(dying);
			await docker.remove(next);
		} finally {
			stop();
		}
	},
	120_000,
);

test.skipIf(!enabled)(
	'makes a run network around a running app and creates the helpers stopped, as koid would',
	async () => {
		await buildVolumeImage();
		const app = `koi-${label}-app`;
		await docker.run({
			name: app,
			image: volumeImage,
			network,
			user: '65534:65534',
			env: {},
			labels: { 'koi.preview': label },
		});
		const before = await docker.inspect(app, network);
		expect(before.running).toBe(true);
		const runNetwork = runNetworkName(verifyRun);
		const bridge = bridgeName(verifyRun);
		const addresses = addressesOf(verifySubnet);
		const record = { network: runNetwork, bridge, subnet: verifySubnet, runId: verifyRun };
		await docker.createNetwork({
			name: runNetwork,
			bridge,
			subnet: verifySubnet,
			gateway: addresses.gateway,
			labels: { 'koi.run': verifyRun },
		});
		// Internal, IPv4 only, no inter-container traffic, the bridge as named.
		const made = (await docker.networks()).find((n) => n.name === runNetwork);
		expect(runNetworkProblems(made, record)).toEqual([]);
		expect(made?.containers).toEqual([]);
		// The app gets a second interface and keeps its first.
		await docker.connect(runNetwork, app, addresses.app);
		const appEndpoint = await docker.endpoint(app, runNetwork);
		expect(appEndpoint?.ip).toBe(addresses.app);
		// Docker 28 picks a random MAC, so there is no prefix to match. It is
		// still locally administered and unicast: in the first octet, the
		// second-lowest bit is set and the lowest is clear.
		const appMac = appEndpoint?.mac ?? '';
		expect(appMac).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/);
		expect(Number.parseInt(appMac.slice(0, 2), 16) & 0b11).toBe(0b10);
		expect((await docker.inspect(app, network)).ip).toBe(before.ip);
		// The helpers: created, not started, at their fixed addresses, with
		// no mounts but the tmpfs asked for. busybox declares no volume;
		// the volume image does, and koid would refuse it.
		const common = {
			network: runNetwork,
			runId: verifyRun,
			appHost: { name: privateHost(verifyRun), ip: addresses.app },
			dns: addresses.gateway,
			env: { KOI_RUN_ID: verifyRun },
		};
		const recorder = helperName(verifyRun, 'recorder');
		await docker.createRecorder({
			...common,
			name: recorder,
			image: 'busybox:1.37',
			ip: addresses.recorder,
			mac: helperMac(addresses.recorder),
		});
		const verifier = helperName(verifyRun, 'verifier');
		await docker.createVerifier({
			...common,
			name: verifier,
			image: volumeImage,
			ip: addresses.verifier,
			mac: helperMac(addresses.verifier),
			command: ['sleep', '1'],
		});
		for (const [name, ip] of [
			[recorder, addresses.recorder],
			[verifier, addresses.verifier],
		] as const) {
			const state = await docker.inspect(name, runNetwork);
			expect(state).toEqual({ exists: true, running: false });
			const endpoint = await docker.endpoint(name, runNetwork);
			expect(endpoint?.ip).toBe(ip);
			if (endpoint?.mac !== undefined) expect(endpoint.mac).toBe(helperMac(ip));
		}
		expect(await docker.mounts(recorder)).toEqual([]);
		expect(
			(await docker.mounts(verifier)).map((m) => ({ type: m.type, destination: m.destination })),
		).toEqual([{ type: 'volume', destination: '/data' }]);
		const inspected = parseDockerJson(
			DockerHostConfigSchema,
			await must(['docker', 'container', 'inspect', '--format', '{{json .HostConfig}}', recorder]),
			'docker container inspect',
		);
		expect(inspected.ReadonlyRootfs).toBe(true);
		expect(inspected.CapDrop).toEqual(['ALL']);
		expect(inspected.SecurityOpt).toEqual(['no-new-privileges=true']);
		expect(inspected.LogConfig).toEqual({ Type: 'none', Config: {} });
		expect(inspected.Tmpfs).toEqual({
			'/tmp': 'rw,nosuid,nodev,noexec,size=512m,uid=10001,gid=10001',
		});
		expect(inspected.RestartPolicy).toEqual({ Name: 'no', MaximumRetryCount: 0 });
		expect(inspected.NetworkMode).toBe(runNetwork);
		// listRun gives every container labelled koi.run with all its labels.
		// The verifier's image carries koi.preview=<label>; koid sets it to
		// nothing over that, and the helpers' names keep them out of list()
		// and the disk watchdog, while the app is in both.
		expect(await docker.listRun()).toEqual(
			expect.arrayContaining([
				{
					name: recorder,
					labels: expect.objectContaining({
						'koi.preview': '',
						'koi.run': verifyRun,
						'koi.role': 'recorder',
					}),
				},
				{
					name: verifier,
					labels: expect.objectContaining({
						'koi.preview': '',
						'koi.run': verifyRun,
						'koi.role': 'verifier',
					}),
				},
			]),
		);
		const listed = (await docker.list()).map((c) => c.name);
		expect(listed).toContain(app);
		expect(listed).not.toContain(recorder);
		expect(listed).not.toContain(verifier);
		const measured = (await docker.diskUsage()).map((c) => c.name);
		expect(measured).toContain(app);
		expect(measured).not.toContain(recorder);
		expect(measured).not.toContain(verifier);
		// Teardown in koid's order: the app off the run network and nothing
		// else of it, the helpers, the network.
		await docker.disconnect(runNetwork, app);
		expect(await docker.endpoint(app, runNetwork)).toBeUndefined();
		expect((await docker.inspect(app, network)).ip).toBe(before.ip);
		await docker.remove(recorder);
		await docker.remove(verifier);
		await docker.removeNetwork(runNetwork);
		expect((await docker.networks()).some((n) => n.name === runNetwork)).toBe(false);
		await docker.remove(app);
	},
	180_000,
);
