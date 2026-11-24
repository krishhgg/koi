import { describe, expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DockerHostConfigSchema } from '@koi/shared';
import {
	cliDocker,
	isPreview,
	networkArgs,
	parseDockerJson,
	parseImageInfo,
	parseInspect,
	parseNetworks,
	parseSize,
	RECORDER_LIMITS,
	recorderArgs,
	runArgs,
	SANDBOX_PROBE_LABEL,
	sandboxProbeArgs,
	stagingArgs,
	VERIFIER_LIMITS,
	verifierArgs,
	watchDeaths,
} from '../src/docker.ts';
import { type ExecResult, exec } from '../src/exec.ts';

// cliDocker with a recorded exec: every command, answering with `stdout`.
function recorded(stdout = '') {
	const calls: string[][] = [];
	const docker = cliDocker({
		builder: 'koi-builder',
		exec: async (cmd): Promise<ExecResult> => {
			calls.push(cmd);
			return { code: 0, stdout, stderr: '', timedOut: false };
		},
	});
	return { calls, docker };
}

describe('the calls a run makes under its budget', () => {
	test('hand their signal to each docker command, so the end of the budget kills it', async () => {
		const seen: Array<AbortSignal | undefined> = [];
		const docker = cliDocker({
			builder: 'koi-builder',
			exec: async (_cmd, options): Promise<ExecResult> => {
				seen.push(options?.signal);
				return { code: 0, stdout: '', stderr: '', timedOut: false };
			},
		});
		const { signal } = new AbortController();
		await docker.start('c', signal);
		await docker.stop('c', signal);
		await docker.remove('c', signal);
		await docker.networks(signal);
		await docker.removeNetwork('n', signal);
		await docker.connect('n', 'c', '10.0.0.2', signal);
		await docker.disconnect('n', 'c', signal);
		await docker.listRun(signal);
		// A point's preparation, which a cancel has to be able to end anywhere.
		await docker.createVolume('v', {}, signal);
		await docker.removeVolume('v', signal);
		await docker.createStaging({ name: 's', image: 'i', runId: 'r', volumes: [] }, signal);
		await docker.copyIn('s', new Uint8Array(0), '/', signal);
		expect(seen).toHaveLength(12);
		expect(seen.every((s) => s === signal)).toBe(true);
	});
});

describe('runArgs', () => {
	const args = runArgs({
		name: 'koi-hello-abc',
		image: 'koi-preview/hello:abc',
		network: 'koi-previews',
		user: '65534:65534',
		env: { KOI_PREVIEW_URL: 'https://hello.previews.example.net', MODE: 'a b; rm -rf /' },
		labels: { 'koi.preview': 'hello' },
	});

	test('sets koi.role to nothing, so a label the image carries never reaches the container', () => {
		// Docker copies the image's labels onto the container, and the
		// flag's value wins over the image's. The name makes it a preview
		// either way (isPreview); this keeps the label from claiming a role.
		expect(args.filter((a) => a.startsWith('koi.role'))).toEqual(['koi.role=']);
		expect(args[args.indexOf('koi.role=') - 1]).toBe('--label');
		expect(args.filter((a) => a.startsWith('koi.preview'))).toEqual(['koi.preview=hello']);
	});

	test('confines the container', () => {
		const joined = args.join(' ');
		expect(joined).toContain('--network koi-previews');
		expect(joined).toContain('--user 65534:65534');
		expect(joined).toContain('--cap-drop ALL');
		expect(joined).toContain('--security-opt no-new-privileges');
		expect(joined).toContain('--pids-limit');
		expect(joined).toContain('--memory');
		expect(joined).toContain('--restart no');
	});

	test('never publishes ports, mounts paths, or uses host networking or privileges', () => {
		for (const flag of [
			'-p',
			'--publish',
			'-v',
			'--volume',
			'--mount',
			'--privileged',
			'--cap-add',
			'--pid',
			'--ipc',
		]) {
			expect(args).not.toContain(flag);
		}
		expect(args).not.toContain('host');
	});

	test("runs the container in the slice when one is given, and in Docker's default otherwise", () => {
		expect(args).not.toContain('--cgroup-parent');
		const sliced = runArgs(
			{ name: 'n', image: 'i', network: 'koi-previews', user: '1:1', env: {}, labels: {} },
			'koi.slice',
		);
		expect(
			sliced.slice(sliced.indexOf('--cgroup-parent'), sliced.indexOf('--cgroup-parent') + 2),
		).toEqual(['--cgroup-parent', 'koi.slice']);
		expect(sliced.at(-1)).toBe('i');
	});

	test('passes env values as single arguments, never through a shell', () => {
		expect(args).toContain('MODE=a b; rm -rf /');
		expect(args.at(-1)).toBe('koi-preview/hello:abc');
	});
});

describe('run network and helper flags', () => {
	const RUN = 'abcdefghijklmnop0123';
	const common = {
		network: `koi-v-${RUN}`,
		runId: RUN,
		appHost: { name: `app.${RUN}.invalid`, ip: '10.213.0.18' },
		dns: '10.213.0.17',
		env: { KOI_RUN_ID: RUN, KOI_PREVIEW_URL: `http://app.${RUN}.invalid:8080` },
	};

	test('a run network is internal, IPv4 only, without inter-container traffic, on a named bridge', () => {
		expect(
			networkArgs({
				name: `koi-v-${RUN}`,
				bridge: 'kv0123456789ab',
				subnet: '10.213.0.16/28',
				gateway: '10.213.0.17',
				labels: { 'koi.run': RUN },
			}),
		).toEqual([
			'docker',
			'network',
			'create',
			'--driver',
			'bridge',
			'--internal',
			'--ipv6=false',
			'--subnet',
			'10.213.0.16/28',
			'--gateway',
			'10.213.0.17',
			'--opt',
			'com.docker.network.bridge.enable_icc=false',
			'--opt',
			'com.docker.network.bridge.enable_ip_masquerade=false',
			'--opt',
			'com.docker.network.bridge.name=kv0123456789ab',
			'--label',
			`koi.run=${RUN}`,
			`koi-v-${RUN}`,
		]);
	});

	test('the recorder is created, not run, with the flags from the design', () => {
		expect(
			recorderArgs(
				{
					...common,
					name: `koi-verify-${RUN}-recorder`,
					image: `koi-recorder@sha256:${'1'.repeat(64)}`,
					ip: '10.213.0.19',
					mac: '02:4b:0a:d5:00:13',
					seccompProfile: '/etc/koi/verify/chromium.json',
				},
				'koi.slice',
			),
		).toEqual([
			'docker',
			'create',
			'--name',
			`koi-verify-${RUN}-recorder`,
			'--network',
			`koi-v-${RUN}`,
			'--ip',
			'10.213.0.19',
			'--mac-address',
			'02:4b:0a:d5:00:13',
			'--user',
			'10001:10001',
			'--read-only',
			'--cap-drop',
			'ALL',
			'--security-opt',
			'no-new-privileges=true',
			'--ipc',
			'private',
			'--init',
			'--memory',
			'2g',
			'--memory-swap',
			'2g',
			'--cpus',
			'1.5',
			'--pids-limit',
			'512',
			'--ulimit',
			'nofile=4096:4096',
			'--ulimit',
			'core=0:0',
			'--restart',
			'no',
			'--stop-timeout',
			'10',
			'--log-driver',
			'none',
			'--dns',
			'10.213.0.17',
			'--add-host',
			`app.${RUN}.invalid:10.213.0.18`,
			'--label',
			'koi.preview=',
			'--label',
			'koi.role=recorder',
			'--label',
			`koi.run=${RUN}`,
			'--cgroup-parent',
			'koi.slice',
			'--env',
			`KOI_RUN_ID=${RUN}`,
			'--env',
			`KOI_PREVIEW_URL=http://app.${RUN}.invalid:8080`,
			'--tmpfs',
			'/tmp:rw,nosuid,nodev,noexec,size=512m,uid=10001,gid=10001',
			'--shm-size',
			'256m',
			'--security-opt',
			'seccomp=/etc/koi/verify/chromium.json',
			`koi-recorder@sha256:${'1'.repeat(64)}`,
		]);
	});

	test('the verifier gets the smaller limits, a /work tmpfs, stdin without a TTY, and its command last', () => {
		const args = verifierArgs(
			{
				...common,
				name: `koi-verify-${RUN}-verifier`,
				image: `curlimages/curl@sha256:${'2'.repeat(64)}`,
				ip: '10.213.0.20',
				mac: '02:4b:0a:d5:00:14',
				command: ['sh', '.koi/runners/home.sh'],
			},
			'koi.slice',
		);
		const joined = args.join(' ');
		expect(joined).toContain('--user 10002:10002');
		expect(joined).toContain('--memory 1g --memory-swap 1g --cpus 1 --pids-limit 256');
		expect(joined).toContain('--tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,uid=10002,gid=10002');
		expect(joined).toContain('--tmpfs /work:rw,nosuid,nodev,noexec,size=128m,uid=10002,gid=10002');
		expect(joined).toContain('--label koi.role=verifier');
		expect(joined).toContain('--log-driver none');
		expect(args).toContain('--interactive');
		expect(args).not.toContain('--tty');
		expect(args).not.toContain('-t');
		expect(args.slice(-3)).toEqual([
			`curlimages/curl@sha256:${'2'.repeat(64)}`,
			'sh',
			'.koi/runners/home.sh',
		]);
		// Without a command, the image's entrypoint runs.
		const plain = verifierArgs({
			...common,
			name: 'v',
			image: 'img',
			ip: '10.213.0.20',
			mac: '02:4b:0a:d5:00:14',
		});
		expect(plain.at(-1)).toBe('img');
		expect(plain).not.toContain('--cgroup-parent');
	});

	test("the verifier mounts its input volumes read-only, and never copies an image's data over them", () => {
		const args = verifierArgs({
			...common,
			name: 'v',
			image: 'img',
			ip: '10.213.0.20',
			mac: '02:4b:0a:d5:00:14',
			volumes: [
				{ name: 'koi-verify-r-inputs-koi', destination: '/koi' },
				{ name: 'koi-verify-r-inputs-workspace', destination: '/workspace' },
			],
		});
		const mounts = args.flatMap((a, i) => (a === '--mount' ? [args[i + 1]] : []));
		expect(mounts).toEqual([
			'type=volume,source=koi-verify-r-inputs-koi,target=/koi,volume-nocopy,readonly',
			'type=volume,source=koi-verify-r-inputs-workspace,target=/workspace,volume-nocopy,readonly',
		]);
		// The root stays read-only with the volumes on it, and no bind mount
		// of the host appears.
		expect(args).toContain('--read-only');
		expect(args.join(' ')).not.toContain('type=bind');
		expect(args).not.toContain('--volume');
	});

	test('the staging container is writable, on no network, and labelled for cleanup', () => {
		const args = stagingArgs({
			name: 'koi-verify-r-staging',
			image: 'img',
			runId: 'r',
			volumes: [{ name: 'koi-verify-r-inputs-koi', destination: '/koi' }],
		});
		expect(args).toEqual([
			'docker',
			'create',
			'--name',
			'koi-verify-r-staging',
			'--network',
			'none',
			'--entrypoint',
			'true',
			'--label',
			'koi.preview=',
			'--label',
			'koi.role=staging',
			'--label',
			'koi.run=r',
			'--mount',
			'type=volume,source=koi-verify-r-inputs-koi,target=/koi,volume-nocopy',
			'img',
		]);
		// `docker cp` is refused on a read-only root; this one must take it.
		expect(args).not.toContain('--read-only');
	});

	test("neither helper is a preview, shares the app's settings, or gets host access", () => {
		const recorder = recorderArgs({
			...common,
			name: 'r',
			image: 'i',
			ip: '10.213.0.19',
			mac: '02:4b:0a:d5:00:13',
		});
		const verifier = verifierArgs({
			...common,
			name: 'v',
			image: 'i',
			ip: '10.213.0.20',
			mac: '02:4b:0a:d5:00:14',
		});
		for (const args of [recorder, verifier]) {
			expect(args[1]).toBe('create');
			// koi.preview is set to nothing, over whatever the image carries.
			// The name makes the helper no preview (isPreview); this keeps
			// the label from saying otherwise, and cleanup takes it for
			// koid's (helperOf).
			expect(args.filter((a) => a.startsWith('koi.preview'))).toEqual(['koi.preview=']);
			expect(args[args.indexOf('koi.preview=') - 1]).toBe('--label');
			for (const flag of [
				'-p',
				'--publish',
				'-v',
				'--volume',
				'--mount',
				'--privileged',
				'--cap-add',
				'--pid',
				'--device',
				'--tty',
				'-t',
			]) {
				expect(args).not.toContain(flag);
			}
			expect(args).not.toContain('host');
			expect(args.join(' ')).not.toContain('_PROXY');
			expect(args.join(' ')).not.toContain('seccomp=unconfined');
			expect(args[args.indexOf('--ipc') + 1]).toBe('private');
		}
		expect(RECORDER_LIMITS.user).toBe('10001:10001');
		expect(VERIFIER_LIMITS.user).toBe('10002:10002');
	});

	test("the sandbox probe runs under the recorder's confinement, with nothing added", () => {
		const seccomp = '/usr/local/share/koi/recorder-seccomp.json';
		const image = `koi-recorder@sha256:${'1'.repeat(64)}`;
		const args = sandboxProbeArgs('koi-sandbox-probe-abc', image, seccomp);
		const recorder = recorderArgs(
			{
				...common,
				name: 'r',
				image,
				ip: '10.213.0.19',
				mac: '02:4b:0a:d5:00:13',
				seccompProfile: seccomp,
			},
			'koi.slice',
		);
		expect(args.slice(0, 7)).toEqual([
			'docker',
			'run',
			'--rm',
			'--name',
			'koi-sandbox-probe-abc',
			'--label',
			SANDBOX_PROBE_LABEL,
		]);
		expect(args[args.indexOf('--network') + 1]).toBe('none');
		// Every flag of the recorder's but what puts it on its run's network,
		// names it, labels it, gives it its environment, stops and logs it: the
		// same user, root, capabilities, privileges, IPC, limits, /tmp, shared
		// memory and seccomp profile, in the same order.
		const own = new Set(['--name', '--network', '--ip', '--mac-address', '--dns', '--add-host']);
		const others = new Set(['--label', '--env', '--cgroup-parent', '--restart', '--stop-timeout']);
		const confining = (list: string[], end: number) => {
			const kept: string[] = [];
			for (let i = 2; i < end; i++) {
				const flag = list[i] ?? '';
				if (own.has(flag) || others.has(flag) || flag === '--log-driver') {
					i++;
					continue;
				}
				if (flag === '--rm') continue;
				kept.push(flag);
			}
			return kept;
		};
		expect(confining(args, args.indexOf('--entrypoint'))).toEqual(
			confining(recorder, recorder.indexOf(image)),
		);
		for (const flag of ['--privileged', '--cap-add', '-v', '--volume', '--mount', '-p', '--pid']) {
			expect(args).not.toContain(flag);
		}
		// The image's entrypoint is not the server: the probe runs dist/probe.js.
		expect(args.slice(args.indexOf('--entrypoint'))).toEqual([
			'--entrypoint',
			'node',
			image,
			'/app/dist/probe.js',
		]);
	});
});

describe('parseNetworks', () => {
	test('reads the fields koid checks on a run network, one JSON object per line', () => {
		const text = [
			JSON.stringify({
				Id: 'abc',
				Name: 'koi-v-run',
				Driver: 'bridge',
				Internal: true,
				EnableIPv6: false,
				Options: {
					'com.docker.network.bridge.enable_icc': 'false',
					'com.docker.network.bridge.name': 'kv0123456789ab',
				},
				Labels: { 'koi.run': 'run1234567890abcdef' },
				IPAM: { Config: [{ Subnet: '10.213.0.16/28', Gateway: '10.213.0.17' }] },
				Containers: {
					c1: { Name: 'koi-app', EndpointID: 'e1' },
					c2: { Name: 'koi-verify-run-recorder', EndpointID: 'e2' },
				},
			}),
			JSON.stringify({
				Id: 'def',
				Name: 'bridge',
				Driver: 'bridge',
				Internal: false,
				EnableIPv6: false,
				Options: { 'com.docker.network.bridge.name': 'docker0' },
				Labels: {},
				IPAM: { Config: [{ Subnet: '172.17.0.0/16' }] },
				Containers: {},
			}),
			JSON.stringify({
				Id: 'ghi',
				Name: 'host',
				Driver: 'host',
				Internal: false,
				EnableIPv6: false,
				Options: null,
				Labels: null,
				IPAM: { Config: null },
				Containers: null,
			}),
			'',
		].join('\n');
		expect(parseNetworks(text)).toEqual([
			{
				id: 'abc',
				name: 'koi-v-run',
				driver: 'bridge',
				internal: true,
				ipv6: false,
				icc: true,
				bridge: 'kv0123456789ab',
				subnets: ['10.213.0.16/28'],
				run: 'run1234567890abcdef',
				containers: ['koi-app', 'koi-verify-run-recorder'],
			},
			{
				id: 'def',
				name: 'bridge',
				driver: 'bridge',
				internal: false,
				ipv6: false,
				icc: false,
				bridge: 'docker0',
				subnets: ['172.17.0.0/16'],
				containers: [],
			},
			{
				id: 'ghi',
				name: 'host',
				driver: 'host',
				internal: false,
				ipv6: false,
				icc: false,
				subnets: [],
				containers: [],
			},
		]);
	});
});

describe('parseInspect', () => {
	test('reads running state and the address on the preview network', () => {
		const json = JSON.stringify({
			State: { Running: true },
			NetworkSettings: {
				Networks: {
					'koi-previews': { IPAddress: '172.19.0.9' },
					bridge: { IPAddress: '172.17.0.2' },
				},
			},
		});
		expect(parseInspect(json, 'koi-previews')).toEqual({
			exists: true,
			running: true,
			ip: '172.19.0.9',
		});
	});

	test('reports a stopped container without an address', () => {
		const json = JSON.stringify({ State: { Running: false }, NetworkSettings: { Networks: {} } });
		expect(parseInspect(json, 'koi-previews')).toEqual({ exists: true, running: false });
	});

	test('reads a container on no network', () => {
		const json = JSON.stringify({ State: { Running: true }, NetworkSettings: { Networks: null } });
		expect(parseInspect(json, 'koi-previews')).toEqual({ exists: true, running: true });
	});

	test('refuses output whose fields have another shape, rather than read it as stopped', () => {
		const json = JSON.stringify({
			State: { Running: 'true' },
			NetworkSettings: { Networks: { 'koi-previews': { IPAddress: 9 } } },
		});
		expect(() => parseInspect(json, 'koi-previews')).toThrow(
			/docker container inspect printed what koid cannot read: State\.Running: .*; NetworkSettings\.Networks\.koi-previews\.IPAddress: /,
		);
		expect(() => parseInspect('{"State":', 'koi-previews')).toThrow('something other than JSON');
	});
});

describe('DockerHostConfigSchema', () => {
	// The reply the Docker test reads back for a helper created with
	// recorderArgs, with only the fields it checks.
	test('keeps what the Docker test checks of a helper, and accepts the nulls Docker prints', () => {
		const reply = {
			ReadonlyRootfs: true,
			CapDrop: ['ALL'],
			SecurityOpt: ['no-new-privileges=true'],
			LogConfig: { Type: 'none', Config: {} },
			Tmpfs: { '/tmp': 'rw,nosuid,nodev,noexec,size=512m,uid=10001,gid=10001' },
			RestartPolicy: { Name: 'no', MaximumRetryCount: 0 },
			NetworkMode: 'koi-v-0123456789ab',
		};
		const json = JSON.stringify({ ...reply, Binds: null, Privileged: false });
		expect(parseDockerJson(DockerHostConfigSchema, json, 'docker container inspect')).toEqual(
			reply,
		);
		const bare = JSON.stringify({ ...reply, CapDrop: null, SecurityOpt: null, Tmpfs: null });
		expect(
			parseDockerJson(DockerHostConfigSchema, bare, 'docker container inspect').CapDrop,
		).toBeNull();
		expect(() =>
			parseDockerJson(
				DockerHostConfigSchema,
				JSON.stringify({ ...reply, ReadonlyRootfs: 'true' }),
				'docker container inspect',
			),
		).toThrow(/docker container inspect printed what koid cannot read: ReadonlyRootfs: /);
	});
});

describe('cliDocker', () => {
	test('builds in the koi builder and loads the result into Docker', async () => {
		const { calls, docker } = recorded();
		await docker.build({
			dockerfile: '/work/src/Dockerfile',
			context: '/work/src',
			tag: 'koi-preview/hello:abc',
			labels: { 'koi.preview': 'hello' },
			timeoutMs: 1000,
			onLine: () => {},
		});
		expect(calls).toEqual([
			[
				'docker',
				'buildx',
				'build',
				'--builder',
				'koi-builder',
				'--load',
				'--progress=plain',
				'--file',
				'/work/src/Dockerfile',
				'--tag',
				'koi-preview/hello:abc',
				'--label',
				'koi.preview=hello',
				'/work/src',
			],
		]);
	});

	test('hands docker buildx the build signal, so koi down can kill it', async () => {
		const seen: Array<AbortSignal | undefined> = [];
		const docker = cliDocker({
			builder: 'koi-builder',
			exec: async (_cmd, options): Promise<ExecResult> => {
				seen.push(options?.signal);
				return { code: 0, stdout: '', stderr: '', timedOut: false };
			},
		});
		const { signal } = new AbortController();
		await docker.build({
			dockerfile: '/work/src/Dockerfile',
			context: '/work/src',
			tag: 'koi-preview/hello:abc',
			labels: { 'koi.preview': 'hello' },
			timeoutMs: 1000,
			onLine: () => {},
			signal,
		});
		expect(seen).toEqual([signal]);
	});

	test('runs previews in the slice it was given', async () => {
		const calls: string[][] = [];
		const docker = cliDocker({
			builder: 'koi-builder',
			slice: 'koi.slice',
			exec: async (cmd): Promise<ExecResult> => {
				calls.push(cmd);
				return { code: 0, stdout: '', stderr: '', timedOut: false };
			},
		});
		await docker.run({
			name: 'koi-hello-abc',
			image: 'koi-preview/hello:abc',
			network: 'koi-previews',
			user: '65534:65534',
			env: {},
			labels: {},
		});
		expect(calls[0]?.join(' ')).toContain('--cgroup-parent koi.slice');
	});

	test('reads the slice a running container is in from its systemd scope', async () => {
		const calls: string[][] = [];
		const answers = new Map([
			['docker', `${'c0'.repeat(32)} true\n`],
			['systemctl', 'koi.slice\n'],
		]);
		const docker = cliDocker({
			builder: 'koi-builder',
			exec: async (cmd): Promise<ExecResult> => {
				calls.push(cmd);
				return { code: 0, stdout: answers.get(cmd[0] ?? '') ?? '', stderr: '', timedOut: false };
			},
		});
		expect(await docker.slice('koi-hello-abc')).toBe('koi.slice');
		expect(calls[1]).toEqual([
			'systemctl',
			'show',
			'--property=Slice',
			'--value',
			`docker-${'c0'.repeat(32)}.scope`,
		]);
		answers.set('docker', `${'c0'.repeat(32)} false\n`);
		expect(await docker.slice('koi-hello-abc')).toBeUndefined();
	});

	test('reads an image id as its digest, and refuses anything else', async () => {
		const id = `sha256:${'a'.repeat(64)}`;
		const { calls, docker } = recorded(`${id}\n`);
		expect(await docker.imageDigest('koi-preview/hello:abc')).toBe(id);
		expect(calls).toEqual([
			['docker', 'image', 'inspect', '--format', '{{.Id}}', 'koi-preview/hello:abc'],
		]);
		await expect(recorded('latest\n').docker.imageDigest('koi-preview/hello:abc')).rejects.toThrow(
			'not a sha256 image id',
		);
	});

	test('trims the build cache of the koi builder', async () => {
		const { calls, docker } = recorded();
		await docker.pruneBuildCache('30gb');
		expect(calls).toEqual([
			[
				'docker',
				'buildx',
				'prune',
				'--builder',
				'koi-builder',
				'--force',
				'--max-used-space',
				'30gb',
			],
		]);
	});

	test('removes a container together with its anonymous volumes', async () => {
		const { calls, docker } = recorded();
		await docker.remove('koi-hello-abc');
		expect(calls).toEqual([['docker', 'rm', '--force', '--volumes', 'koi-hello-abc']]);
	});

	test('lists only previews: a non-empty koi.preview under a name that is not a helper', async () => {
		// docker ps --filter label=koi.preview matches the key whatever its
		// value. Here: a preview, a run's helper (koi.preview set to nothing
		// over its image's), a helper whose koi.preview an image forged, and
		// a container with the key and no value. Only the name and
		// koi.preview are asked for: koi.role and koi.run on a preview are
		// its image's, and the row must carry nothing an image chose.
		const run = 'r'.repeat(16);
		const previews = recorded(
			[
				'koi-hello-abc\thello',
				`koi-verify-${run}-recorder\t`,
				`koi-verify-${run}-verifier\tx`,
				'bare\t',
				'',
			].join('\n'),
		);
		expect(await previews.docker.list()).toEqual([{ name: 'koi-hello-abc', label: 'hello' }]);
		expect(previews.calls[0]).toContain('label=koi.preview');
		expect(previews.calls[0]?.at(-1)).toBe('{{.Names}}\t{{.Label "koi.preview"}}');
	});

	test('lists what carries koi.run with its labels, from JSON, so a label cannot forge a row', async () => {
		const calls: string[][] = [];
		// A recorder, and a preview whose image set koi.run and koi.role with
		// a line break and a tab in the value.
		const inspected = [
			JSON.stringify({
				Name: '/koi-verify-r-recorder',
				Labels: { 'koi.role': 'recorder', 'koi.run': 'r' },
			}),
			JSON.stringify({
				Name: '/koi-hello-abc',
				Labels: {
					'koi.preview': 'hello',
					'koi.run': 'r\n/koi-verify-r-verifier\tr\tverifier',
					'koi.role': 'recorder',
				},
			}),
			JSON.stringify({ Name: '/bare', Labels: null }),
			'',
		].join('\n');
		const docker = cliDocker({
			builder: 'koi-builder',
			exec: async (cmd): Promise<ExecResult> => {
				calls.push(cmd);
				const stdout = cmd[1] === 'ps' ? 'id1\nid2\nid3\n' : inspected;
				return { code: 0, stdout, stderr: '', timedOut: false };
			},
		});
		expect(await docker.listRun()).toEqual([
			{ name: 'koi-verify-r-recorder', labels: { 'koi.role': 'recorder', 'koi.run': 'r' } },
			{
				name: 'koi-hello-abc',
				labels: {
					'koi.preview': 'hello',
					'koi.run': 'r\n/koi-verify-r-verifier\tr\tverifier',
					'koi.role': 'recorder',
				},
			},
			{ name: 'bare', labels: {} },
		]);
		expect(calls[0]).toEqual(['docker', 'ps', '--all', '--quiet', '--filter', 'label=koi.run']);
		expect(calls[1]).toEqual([
			'docker',
			'container',
			'inspect',
			'--format',
			'{"Name":{{json .Name}},"Labels":{{json .Config.Labels}}}',
			'id1',
			'id2',
			'id3',
		]);
		// Nothing labelled: one call, no inspect.
		expect(await recorded('').docker.listRun()).toEqual([]);
		// A line that is not a container's JSON is an error, not a row.
		const odd = cliDocker({
			builder: 'koi-builder',
			exec: async (cmd): Promise<ExecResult> => ({
				code: 0,
				stdout: cmd[1] === 'ps' ? 'id1\n' : 'koi-verify-r-recorder\tr\trecorder\n',
				stderr: '',
				timedOut: false,
			}),
		});
		await expect(odd.listRun()).rejects.toThrow('something other than JSON');
	});

	test("reads a container's attachment to one network, created or running", async () => {
		const running = recorded(
			JSON.stringify({
				'koi-previews': {
					IPAddress: '172.19.0.2',
					MacAddress: '02:42:ac:13:00:02',
					EndpointID: 'e1',
				},
				'koi-v-run': {
					IPAddress: '10.213.0.18',
					MacAddress: '02:42:0a:d5:00:12',
					EndpointID: 'e2',
					IPAMConfig: { IPv4Address: '10.213.0.18' },
				},
			}),
		);
		expect(await running.docker.endpoint('koi-app', 'koi-v-run')).toEqual({
			ip: '10.213.0.18',
			mac: '02:42:0a:d5:00:12',
			endpointId: 'e2',
		});
		expect(await running.docker.endpoint('koi-app', 'other')).toBeUndefined();
		expect(running.calls[0]).toEqual([
			'docker',
			'container',
			'inspect',
			'--format',
			'{{json .NetworkSettings.Networks}}',
			'koi-app',
		]);
		// Created, not started: the address it was asked to take, no endpoint yet.
		const created = recorded(
			JSON.stringify({
				'koi-v-run': {
					IPAddress: '',
					MacAddress: '02:4b:0a:d5:00:13',
					EndpointID: '',
					IPAMConfig: { IPv4Address: '10.213.0.19' },
				},
			}),
		);
		expect(await created.docker.endpoint('r', 'koi-v-run')).toEqual({
			ip: '10.213.0.19',
			mac: '02:4b:0a:d5:00:13',
		});
		expect(await recorded('null').docker.endpoint('r', 'koi-v-run')).toBeUndefined();
		await expect(
			recorded('{"koi-v-run": {"IPAddress": 5}}').docker.endpoint('r', 'koi-v-run'),
		).rejects.toThrow('cannot read');
	});

	test("reads a container's mounts, and an image volume among them", async () => {
		const { calls, docker } = recorded(
			JSON.stringify([
				{
					Type: 'volume',
					Name: 'abc',
					Source: '/var/lib/docker/volumes/abc/_data',
					Destination: '/data',
					RW: true,
				},
			]),
		);
		expect(await docker.mounts('r')).toEqual([
			{ type: 'volume', destination: '/data', name: 'abc', readOnly: false },
		]);
		expect(calls[0]).toEqual([
			'docker',
			'container',
			'inspect',
			'--format',
			'{{json .Mounts}}',
			'r',
		]);
		expect(await recorded('[]').docker.mounts('r')).toEqual([]);
		expect(await recorded('null').docker.mounts('r')).toEqual([]);
	});

	test('makes, lists and removes volumes, and copies an archive to a path in a container', async () => {
		const { calls, docker } = recorded();
		await docker.createVolume('koi-verify-r-inputs-koi', { 'koi.run': 'r', 'koi.role': 'inputs' });
		await docker.removeVolume('koi-verify-r-inputs-koi');
		await docker.copyIn('s', new Uint8Array(0), '/');
		expect(calls).toEqual([
			[
				'docker',
				'volume',
				'create',
				'--label',
				'koi.run=r',
				'--label',
				'koi.role=inputs',
				'koi-verify-r-inputs-koi',
			],
			['docker', 'volume', 'rm', 'koi-verify-r-inputs-koi'],
			['docker', 'cp', '-', 's:/'],
		]);
		expect(await docker.listRunVolumes()).toEqual([]);

		const listed = cliDocker({
			builder: 'b',
			exec: async (cmd): Promise<ExecResult> => {
				if (cmd.includes('ls')) return { code: 0, stdout: 'a\nb\n', stderr: '', timedOut: false };
				return {
					code: 0,
					stdout: '{"Name":"a","Labels":{"koi.run":"r"}}\n{"Name":"b","Labels":null}\n',
					stderr: '',
					timedOut: false,
				};
			},
		});
		expect(await listed.listRunVolumes()).toEqual([
			{ name: 'a', labels: { 'koi.run': 'r' } },
			{ name: 'b', labels: {} },
		]);

		// One already gone is fine; one Docker refuses to remove is not.
		const answers = [
			'Error response from daemon: get x: no such volume',
			'Error response from daemon: remove x: volume is in use - [abc]',
		];
		const removing = cliDocker({
			builder: 'b',
			exec: async (): Promise<ExecResult> => ({
				code: 1,
				stdout: '',
				stderr: answers.shift() ?? '',
				timedOut: false,
			}),
		});
		await removing.removeVolume('x');
		await expect(removing.removeVolume('x')).rejects.toThrow('volume is in use');
	});

	test('attaches and detaches containers and removes networks, quietly when they are already gone', async () => {
		const { calls, docker } = recorded();
		await docker.connect('koi-v-run', 'koi-app', '10.213.0.18');
		await docker.disconnect('koi-v-run', 'koi-app');
		await docker.removeNetwork('koi-v-run');
		expect(calls).toEqual([
			['docker', 'network', 'connect', '--ip', '10.213.0.18', 'koi-v-run', 'koi-app'],
			['docker', 'network', 'disconnect', 'koi-v-run', 'koi-app'],
			['docker', 'network', 'rm', 'koi-v-run'],
		]);
		const failing = (stderr: string) =>
			cliDocker({
				builder: 'b',
				exec: async (): Promise<ExecResult> => ({ code: 1, stdout: '', stderr, timedOut: false }),
			});
		await failing('Error response from daemon: network koi-v-run not found').removeNetwork(
			'koi-v-run',
		);
		await failing(
			'Error response from daemon: container koi-app is not connected to network koi-v-run',
		).disconnect('koi-v-run', 'koi-app');
		await failing('Error: No such container: koi-app').disconnect('koi-v-run', 'koi-app');
		await expect(
			failing('Error response from daemon: network koi-v-run has active endpoints').removeNetwork(
				'koi-v-run',
			),
		).rejects.toThrow('active endpoints');
		await expect(
			failing('permission denied').connect('koi-v-run', 'koi-app', '10.213.0.18'),
		).rejects.toThrow('permission denied');
	});

	test('lists every network and inspects them in one call', async () => {
		const calls: string[][] = [];
		const docker = cliDocker({
			builder: 'b',
			exec: async (cmd): Promise<ExecResult> => {
				calls.push(cmd);
				const network = (id: string, name: string) =>
					JSON.stringify({
						Id: id,
						Name: name,
						Driver: 'bridge',
						Internal: false,
						EnableIPv6: false,
						Options: {},
						Labels: {},
						IPAM: { Config: [] },
						Containers: {},
					});
				const stdout =
					cmd[2] === 'ls'
						? 'abc\ndef\n'
						: `${network('abc', 'koi-v-run')}\n${network('def', 'bridge')}\n`;
				return { code: 0, stdout, stderr: '', timedOut: false };
			},
		});
		const networks = await docker.networks();
		expect(networks.map((n) => n.name)).toEqual(['koi-v-run', 'bridge']);
		expect(calls[0]).toEqual(['docker', 'network', 'ls', '--quiet']);
		expect(calls[1]?.slice(0, 4)).toEqual(['docker', 'network', 'inspect', '--format']);
		expect(calls[1]?.slice(-2)).toEqual(['abc', 'def']);
		expect(await recorded('').docker.networks()).toEqual([]);
	});

	describe('diskUsage', () => {
		const run = 'r'.repeat(16);
		const df = [
			'container\tkoi-a\trunning\t4.1kB',
			'container\tkoi-b\texited\t1GB',
			'container\tother\trunning\t2MB (virtual 7.74MB)',
			`container\tkoi-verify-${run}-recorder\texited\t3GB`,
			`container\tkoi-verify-${run}-verifier\texited\t3GB`,
			'volume\tv1\t16.78MB',
			'volume\tv2\tN/A',
			'volume\tv3\t1GB',
			'',
		].join('\n');
		// Name, koi.preview, then the volumes. Two previews; a container
		// without the label; a run's helper, with koi.preview set to
		// nothing over its image's; and a helper whose koi.preview an image
		// forged, which its name keeps out all the same.
		const inspected = [
			'/koi-a\ta\tv1\tv2',
			'/koi-b\tb',
			'/other\t\tv3',
			`/koi-verify-${run}-recorder\t`,
			`/koi-verify-${run}-verifier\tx\tv3`,
			'',
		].join('\n');

		// cliDocker answering `docker system df` with `df` and docker
		// container inspect with `inspect`.
		function scripted(inspect: Partial<ExecResult>) {
			const calls: string[][] = [];
			const docker = cliDocker({
				builder: 'koi-builder',
				exec: async (cmd): Promise<ExecResult> => {
					calls.push(cmd);
					return cmd[1] === 'system'
						? { code: 0, stdout: df, stderr: '', timedOut: false }
						: { code: 0, stdout: inspected, stderr: '', timedOut: false, ...inspect };
				},
			});
			return { calls, docker };
		}

		test('adds the volumes a koi container mounts to its writable layer, running or not', async () => {
			const { calls, docker } = scripted({});
			expect(await docker.diskUsage()).toEqual([
				{ name: 'koi-a', label: 'a', bytes: 4_100 + 16_780_000, running: true },
				{ name: 'koi-b', label: 'b', bytes: 1_000_000_000, running: false },
			]);
			expect(calls.map((c) => c.slice(0, 4))).toEqual([
				['docker', 'system', 'df', '--verbose'],
				['docker', 'container', 'inspect', '--format'],
			]);
			expect(calls[1]?.slice(5)).toEqual([
				'koi-a',
				'koi-b',
				'other',
				`koi-verify-${run}-recorder`,
				`koi-verify-${run}-verifier`,
			]);
		});

		test('leaves out a container that went away between the two calls', async () => {
			const { docker } = scripted({ code: 1, stderr: 'Error: No such container: other' });
			expect(await docker.diskUsage()).toHaveLength(2);
			const broken = scripted({ code: 1, stderr: 'permission denied' });
			await expect(broken.docker.diskUsage()).rejects.toThrow('permission denied');
		});
	});

	// Real processes print these outputs, so exec's limits apply as they do
	// on the box.
	describe('reads all of an output longer than 256 KiB', () => {
		async function printing(outputs: (cmd: string[]) => string) {
			const dir = await mkdtemp(join(tmpdir(), 'koid-docker-'));
			let n = 0;
			return cliDocker({
				builder: 'koi-builder',
				exec: async (cmd, options) => {
					const file = join(dir, `${n++}.out`);
					await writeFile(file, outputs(cmd));
					return exec(['cat', file], options);
				},
			});
		}
		const many = Array.from(
			{ length: 10_000 },
			(_, i) => `koi-preview-${String(i).padStart(5, '0')}`,
		);

		test('diskUsage, with ten thousand containers and volumes', async () => {
			const docker = await printing((cmd) =>
				cmd[1] === 'system'
					? many
							.flatMap((name) => [`container\t${name}\trunning\t1kB`, `volume\tv-${name}\t2kB`])
							.join('\n')
					: many.map((name) => `/${name}\t${name}\t\tv-${name}\n`).join(''),
			);
			const usage = await docker.diskUsage();
			expect(usage).toHaveLength(many.length);
			expect(usage[0]).toEqual({
				name: many[0] ?? '',
				label: many[0] ?? '',
				bytes: 3_000,
				running: true,
			});
		});

		test('inspect, for a container with a large environment', async () => {
			const big = JSON.stringify({
				State: { Running: true },
				Config: { Env: Array.from({ length: 80 }, (_, i) => `K${i}=${'x'.repeat(4096)}`) },
				NetworkSettings: { Networks: { 'koi-previews': { IPAddress: '172.19.0.9' } } },
			});
			expect(big.length).toBeGreaterThan(256 * 1024);
			const docker = await printing(() => big);
			expect(await docker.inspect('koi-a', 'koi-previews')).toEqual({
				exists: true,
				running: true,
				ip: '172.19.0.9',
			});
		});

		test('list and listImages', async () => {
			const docker = await printing((cmd) =>
				cmd[1] === 'ps'
					? many.map((name) => `${name}\t${name}\n`).join('')
					: many.map((name) => `koi-preview/${name}:abc\n`).join(''),
			);
			expect(await docker.list()).toHaveLength(many.length);
			expect((await docker.list())[0]).toEqual({ name: many[0] ?? '', label: many[0] ?? '' });
			expect(await docker.listImages()).toHaveLength(many.length);
		});
	});

	test('lists tagged koi images only', async () => {
		const { docker } = recorded('koi-preview/a:x\n<none>:<none>\n');
		expect(await docker.listImages()).toEqual(['koi-preview/a:x']);
	});
});

describe('parseSize', () => {
	test('reads the decimal units docker prints', () => {
		expect(parseSize('0B')).toBe(0);
		expect(parseSize('12.3kB (virtual 4MB)')).toBe(12_300);
		expect(parseSize('10.8GB')).toBe(10_800_000_000);
		expect(parseSize('1.5TB')).toBe(1_500_000_000_000);
		expect(parseSize('2GiB')).toBe(2 * 1024 ** 3);
	});

	test('refuses text it cannot read', () => {
		expect(() => parseSize('')).toThrow();
		expect(() => parseSize('lots')).toThrow();
	});
});

describe('isPreview', () => {
	const run = 'r'.repeat(16);
	const id = 'a'.repeat(20);

	test('a preview has a non-empty koi.preview and a name that is not a helper', () => {
		// Labels other than koi.preview are not asked: a preview an older
		// koid made carries whatever koi.role or koi.run its image set, and
		// it is a preview all the same.
		expect(isPreview(`koi-hello-pr-7-${id}`, 'hello-pr-7')).toBe(true);
		// A preview whose label starts with "verify" is still named as a
		// preview: the id after the last dash is 16 to 40 characters, never a
		// role.
		expect(isPreview(`koi-verify-${id}`, 'verify')).toBe(true);
		expect(isPreview(`koi-verify-${run}-recorder-${id}`, `verify-${run}-recorder`)).toBe(true);
		// A run's helper, by its name: koi.preview set to nothing, as koid
		// creates it, or a value its image forged.
		expect(isPreview(`koi-verify-${run}-recorder`, '')).toBe(false);
		expect(isPreview(`koi-verify-${run}-verifier`, undefined)).toBe(false);
		expect(isPreview(`koi-verify-${run}-verifier`, 'hello-pr-7')).toBe(false);
		// No koi.preview value: not a preview, whatever the name.
		expect(isPreview(`koi-hello-pr-7-${id}`, '')).toBe(false);
		expect(isPreview(`koi-hello-pr-7-${id}`, undefined)).toBe(false);
		expect(isPreview('bare', '')).toBe(false);
	});
});

describe('watchDeaths', () => {
	test('reports each preview container docker events says died, and watches again when it exits', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-events-'));
		const fake = join(dir, 'docker');
		// docker events, as a script: records its arguments, prints the
		// deaths of two previews, a run's helper (koi.preview set to nothing)
		// and a helper whose koi.preview an image forged, then exits as the
		// real one does when the daemon restarts. Each line is the name and
		// the label, as DEATH_FORMAT prints them; a helper's name keeps it
		// out whatever the label says.
		const run = 'r'.repeat(16);
		await writeFile(
			fake,
			`#!/bin/sh\necho "$@" >> ${join(dir, 'args')}\nprintf 'koi-a-1\\thello\\nkoi-verify-${run}-recorder\\t\\nkoi-b-2\\tbye\\nkoi-verify-${run}-verifier\\tx\\n'\n`,
			{ mode: 0o755 },
		);
		const events: Array<string | undefined> = [];
		const logs: string[] = [];
		const stop = watchDeaths(
			(name) => events.push(name),
			(m) => logs.push(m),
			{
				docker: fake,
				restartMs: 20,
			},
		);
		const deadline = Date.now() + 3000;
		while (events.length < 6 && Date.now() < deadline) await Bun.sleep(10);
		stop();
		expect(events.slice(0, 6)).toEqual([
			undefined,
			'koi-a-1',
			'koi-b-2',
			undefined,
			'koi-a-1',
			'koi-b-2',
		]);
		expect((await Bun.file(join(dir, 'args')).text()).split('\n')[0]).toBe(
			'events --filter type=container --filter event=die --filter label=koi.preview --format ' +
				'{{.Actor.Attributes.name}}\t{{index .Actor.Attributes "koi.preview"}}',
		);
		expect(logs[0]).toContain('docker events stopped; watching again');
	});
});

describe('parseImageInfo', () => {
	const ID = `sha256:${'a'.repeat(64)}`;

	test('reads the id and the environment, and an image that declares none has an empty one', () => {
		expect(parseImageInfo(`${ID}\t["PATH=/usr/bin","LANG=C.UTF-8"]\n`, 'img')).toEqual({
			id: ID,
			env: ['PATH=/usr/bin', 'LANG=C.UTF-8'],
		});
		expect(parseImageInfo(`${ID}\tnull\n`, 'img')).toEqual({ id: ID, env: [] });
	});

	test('refuses an id or an environment it cannot read, naming the image', () => {
		expect(() => parseImageInfo('nope\tnull\n', 'img')).toThrow('for img, not a sha256 image id');
		expect(() => parseImageInfo(`${ID}\t{oops\n`, 'img')).toThrow(
			'docker image inspect of img printed something other than JSON',
		);
		expect(() => parseImageInfo(`${ID}\t{"PATH":"/usr/bin"}\n`, 'img')).toThrow(
			'docker image inspect of img printed what koid cannot read',
		);
		expect(() => parseImageInfo(`${ID}\t["PATH=/usr/bin",7]\n`, 'img')).toThrow(
			'docker image inspect of img printed what koid cannot read: 1: ',
		);
	});
});
