import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { loadConfig } from '../src/config.ts';
import { SANDBOX_PROBE_LABEL, sandboxProbeArgs } from '../src/docker.ts';
import { type ExecOptions, type ExecResult, exec, WHOLE_OUTPUT } from '../src/exec.ts';
import {
	builderNode,
	builderProblems,
	type FileStat,
	hostSpec,
	networkProblems,
	verificationCapability,
	verifyHost,
} from '../src/host.ts';

const spec = hostSpec({
	network: 'koi-previews',
	buildNetwork: 'koi-build',
	builder: 'koi-builder',
});
const [previews, build] = spec.networks as [(typeof spec.networks)[0], (typeof spec.networks)[0]];

const network = (internal: boolean, options: Record<string, string>) =>
	JSON.stringify({ Name: 'n', Driver: 'bridge', Internal: internal, Options: options });

const confined = (bridge: string) => ({
	'com.docker.network.bridge.enable_icc': 'false',
	'com.docker.network.bridge.name': bridge,
});

// docker buildx inspect, as printed by buildx 0.34 for a stopped builder.
const builderOutput = `Name:          koi-builder
Driver:        docker-container
Last Activity: 2026-10-06 01:15:13 +0000 UTC

Nodes:
Name:                  koi-builder0
Endpoint:              unix:///var/run/docker.sock
Driver Options:        cpu-quota="300000" memory="8g" network="koi-build"
Status:                stopped
`;

describe('networkProblems', () => {
	test('accepts the networks provisioning creates', () => {
		expect(networkProblems(previews, network(true, confined('koi-previews0')))).toEqual([]);
		expect(networkProblems(build, network(false, confined('koi-build0')))).toEqual([]);
	});

	test('refuses an automatic bridge name, which the firewall rule would not match', () => {
		expect(
			networkProblems(previews, network(true, { 'com.docker.network.bridge.enable_icc': 'false' })),
		).toEqual(['network koi-previews has bridge (automatic), not koi-previews0']);
	});

	test('refuses inter-container traffic and the wrong reach', () => {
		expect(
			networkProblems(
				previews,
				network(false, {
					...confined('koi-previews0'),
					'com.docker.network.bridge.enable_icc': 'true',
				}),
			),
		).toEqual([
			'network koi-previews is not internal',
			'network koi-previews lets its containers reach each other (enable_icc is not false)',
		]);
		expect(networkProblems(build, network(true, confined('koi-build0')))).toEqual([
			'network koi-build is internal',
		]);
	});

	test('reports output whose fields have another shape, rather than read it as wrong', () => {
		const odd = JSON.stringify({
			Driver: 'bridge',
			Internal: 'true',
			Options: confined('koi-previews0'),
		});
		const problems = networkProblems(previews, odd);
		expect(problems).toHaveLength(1);
		expect(problems[0]).toStartWith(
			'network koi-previews: docker network inspect printed what koid cannot read: Internal: ',
		);
		expect(networkProblems(previews, 'Error: no such network')).toEqual([
			'network koi-previews: docker network inspect printed something other than JSON',
		]);
	});
});

describe('builderProblems', () => {
	test('accepts the builder provisioning creates, even while it is stopped', () => {
		expect(builderProblems(spec.builder, builderOutput)).toEqual([]);
	});

	test('refuses a builder on another network, without limits, or with another driver', () => {
		expect(
			builderProblems(
				spec.builder,
				builderOutput
					.replace('Driver:        docker-container', 'Driver:        docker')
					.replace('cpu-quota="300000" memory="8g" network="koi-build"', 'network="bridge"'),
			),
		).toEqual([
			'buildx builder koi-builder does not use the docker-container driver',
			'buildx builder koi-builder is not on network koi-build',
			'buildx builder koi-builder has no memory limit',
			'buildx builder koi-builder has no cpu-quota limit',
		]);
	});
});

describe('verifyHost', () => {
	const answer = (code: number, stdout: string, stderr = ''): ExecResult => ({
		code,
		stdout,
		stderr,
		timedOut: false,
	});

	test('passes when every network and the builder are as provisioning made them', async () => {
		const problems = await verifyHost(spec, async (cmd) => {
			if (cmd.includes('koi-previews')) return answer(0, network(true, confined('koi-previews0')));
			if (cmd.includes('koi-build')) return answer(0, network(false, confined('koi-build0')));
			return answer(0, builderOutput);
		});
		expect(problems).toEqual([]);
	});

	test('reads all of a network inspection longer than 256 KiB', async () => {
		// A network with many containers on it lists every one.
		const containers = Object.fromEntries(
			Array.from({ length: 2000 }, (_, i) => [
				`${i}`.padStart(64, '0'),
				{ Name: `koi-preview-${i}`, IPv4Address: '172.19.0.2/16', MacAddress: '02:42:ac:13:00:02' },
			]),
		);
		const dir = await mkdtemp(join(tmpdir(), 'koid-host-'));
		const printed = async (text: string, options: Parameters<typeof exec>[1]) => {
			const file = join(dir, `${Math.random()}`);
			await writeFile(file, text);
			return exec(['cat', file], options);
		};
		const problems = await verifyHost(spec, async (cmd, options) => {
			if (cmd.includes('koi-previews')) {
				const text = JSON.stringify({
					...JSON.parse(network(true, confined('koi-previews0'))),
					Containers: containers,
				});
				expect(text.length).toBeGreaterThan(256 * 1024);
				return printed(text, options);
			}
			if (cmd.includes('koi-build')) return answer(0, network(false, confined('koi-build0')));
			return answer(0, builderOutput);
		});
		expect(problems).toEqual([]);
	});

	test('reports what is missing, and errors other than missing', async () => {
		const problems = await verifyHost(spec, async (cmd) => {
			if (cmd.includes('koi-previews'))
				return answer(1, '', 'Error response from daemon: network koi-previews not found');
			if (cmd.includes('koi-build'))
				return answer(1, '', 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock');
			return answer(1, '', 'ERROR: no builder "koi-builder" found');
		});
		expect(problems).toEqual([
			'network koi-previews does not exist',
			'cannot inspect network koi-build: Cannot connect to the Docker daemon at unix:///var/run/docker.sock',
			'buildx builder koi-builder does not exist',
		]);
	});
});

describe('the slice', () => {
	const sliced = { ...spec, slice: 'koi.slice' };
	const id = 'c0ffee'.repeat(10).slice(0, 64);
	const answer = (code: number, stdout: string, stderr = ''): ExecResult => ({
		code,
		stdout,
		stderr,
		timedOut: false,
	});
	// The box as provisioning leaves it, with `change` answering first.
	const box =
		(change: (cmd: string) => ExecResult | undefined = () => undefined) =>
		async (cmd: string[]): Promise<ExecResult> => {
			const line = cmd.join(' ');
			const changed = change(line);
			if (changed !== undefined) return changed;
			if (line.startsWith('docker network inspect') && line.endsWith(' koi-previews'))
				return answer(0, network(true, confined('koi-previews0')));
			if (line.startsWith('docker network inspect') && line.endsWith(' koi-build'))
				return answer(0, network(false, confined('koi-build0')));
			if (line === 'docker info --format {{.CgroupDriver}}') return answer(0, 'systemd\n');
			if (line === 'systemctl show --property=ActiveState,MemoryMax koi.slice')
				return answer(0, 'MemoryMax=13369344000\nActiveState=active\n');
			if (line === 'docker buildx inspect --bootstrap koi-builder') return answer(0, builderOutput);
			if (line.endsWith('buildx_buildkit_koi-builder0')) return answer(0, `${id} true\n`);
			if (line === `systemctl show --property=Slice --value docker-${id}.scope`)
				return answer(0, 'koi.slice\n');
			throw new Error(`unexpected command: ${line}`);
		};

	test('passes when the slice has a ceiling and holds the builder', async () => {
		expect(await verifyHost(sliced, box())).toEqual([]);
	});

	test('refuses docker with the cgroupfs driver, which ignores slice names', async () => {
		const problems = await verifyHost(
			sliced,
			box((line) => (line.startsWith('docker info') ? answer(0, 'cgroupfs\n') : undefined)),
		);
		expect(problems).toEqual([
			'docker uses the cgroupfs cgroup driver, not systemd, so its containers are not in koi.slice',
		]);
	});

	test('refuses a slice that is missing, or that systemd made up without a ceiling', async () => {
		const missing = await verifyHost(
			sliced,
			box((line) =>
				line.includes('ActiveState')
					? answer(0, 'MemoryMax=infinity\nActiveState=inactive\n')
					: undefined,
			),
		);
		expect(missing).toEqual([
			'koi.slice is not active',
			'koi.slice has no memory ceiling (MemoryMax)',
		]);
		const unlimited = await verifyHost(
			sliced,
			box((line) =>
				line.includes('ActiveState')
					? answer(0, 'MemoryMax=infinity\nActiveState=active\n')
					: undefined,
			),
		);
		expect(unlimited).toEqual(['koi.slice has no memory ceiling (MemoryMax)']);
	});

	test('refuses a builder that runs outside the slice, or that it cannot see', async () => {
		const outside = await verifyHost(
			sliced,
			box((line) => (line.includes('--property=Slice') ? answer(0, 'system.slice\n') : undefined)),
		);
		expect(outside).toEqual([
			'buildx builder koi-builder runs in system.slice, not koi.slice; set cgroup-parent in /etc/docker/daemon.json and restart docker',
		]);
		const stopped = await verifyHost(
			sliced,
			box((line) => (line.includes('buildx_buildkit_') ? answer(0, `${id} false\n`) : undefined)),
		);
		expect(stopped).toEqual([
			'buildx builder koi-builder is not running in buildx_buildkit_koi-builder0, so koid cannot see its slice',
		]);
	});

	test('checks nothing about slices when koid runs without one', async () => {
		const asked: string[] = [];
		const run = box();
		expect(
			await verifyHost(spec, async (cmd) => {
				asked.push(cmd.join(' '));
				return run(cmd);
			}),
		).toEqual([]);
		expect(asked.some((c) => c.includes('systemctl') || c.startsWith('docker info'))).toBe(false);
	});

	test('reads the builder node from buildx inspect', () => {
		expect(builderNode(builderOutput, 'koi-builder')).toBe('koi-builder0');
		expect(builderNode('Name: koi-builder\n', 'koi-builder')).toBe('koi-builder0');
	});
});

describe('verificationCapability', () => {
	const answer = (code: number, stdout: string, stderr = ''): ExecResult => ({
		code,
		stdout,
		stderr,
		timedOut: false,
	});
	const attestation = {
		policy: 2,
		pool: '10.213.0.0/20',
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
	const recorderImage = `sha256:${'7'.repeat(64)}`;
	const verifierImage = `sha256:${'8'.repeat(64)}`;
	const spec = {
		pool: '10.213.0.0/20',
		helper: '/usr/local/libexec/koi-verify-net',
		slice: 'koi.slice',
		recorderImage,
		recorderSeccomp: '/usr/local/share/koi/recorder-seccomp.json',
		verifierImage,
	};
	const installed: FileStat = async () => ({ isFile: true, uid: 0, gid: 0, mode: 0o755 });
	// The probe has a name of its own each time: koi-sandbox-probe- and 12 hex digits.
	const probeName = (line: string) => line.split(' ')[4] ?? '';
	const isProbe = (line: string) =>
		/^koi-sandbox-probe-[0-9a-f]{12}$/.test(probeName(line)) &&
		line === sandboxProbeArgs(probeName(line), recorderImage, spec.recorderSeccomp).join(' ');
	const leftover = `docker ps --all --filter label=${SANDBOX_PROBE_LABEL} --format {{.Names}}`;
	const removal = /^docker rm --force koi-sandbox-probe-[0-9a-f]{12}$/;
	// The box as provisioning and deploy leave it, with `change` answering first.
	const box =
		(change: (cmd: string) => ExecResult | undefined = () => undefined) =>
		async (cmd: string[]): Promise<ExecResult> => {
			const line = cmd.join(' ');
			const changed = change(line);
			if (changed !== undefined) return changed;
			if (line === 'sudo -n /usr/local/libexec/koi-verify-net attest')
				return answer(0, `${JSON.stringify(attestation)}\n`);
			if (line === `docker image inspect --format {{.Id}} ${recorderImage}`)
				return answer(0, `${recorderImage}\n`);
			if (line === `docker image inspect --format {{.Id}} ${verifierImage}`)
				return answer(0, `${verifierImage}\n`);
			if (line === leftover) return answer(0, '');
			if (isProbe(line)) return answer(0, '');
			// --rm took the probe already.
			if (removal.test(line))
				return answer(1, '', 'Error response from daemon: No such container\n');
			if (line === 'docker info --format {{.CgroupDriver}}') return answer(0, 'systemd\n');
			if (line === 'systemctl show --property=ActiveState,MemoryMax koi.slice')
				return answer(0, 'MemoryMax=13369344000\nActiveState=active\n');
			throw new Error(`unexpected command: ${line}`);
		};

	test('is available on a box with the pool, both images, the helper, its sudo rule, the chains and the slice', async () => {
		expect(await verificationCapability(spec, box(), installed)).toEqual({
			available: true,
			attestation,
			recorderImageId: recorderImage,
			verifierImageId: verifierImage,
		});
	});

	test("is unavailable when Chromium's sandbox cannot start in the recorder image", async () => {
		const asked: string[] = [];
		const judge = (result: ExecResult) =>
			verificationCapability(
				spec,
				box((line) => {
					if (!isProbe(line)) return undefined;
					asked.push(line);
					return result;
				}),
				installed,
			);
		const why = (said: string) =>
			`Chromium's sandbox cannot start in the recorder image under its confinement: ${said}. Copy host/recorder/seccomp.json to /usr/local/share/koi/recorder-seccomp.json again; if that is current, this host's AppArmor policy keeps Docker's containers from making a user namespace`;
		// A seccomp file from before chroot was allowed.
		expect(
			await judge(
				answer(125, '', "chroot: cannot change root directory to '/': Operation not permitted\n"),
			),
		).toEqual({
			available: false,
			reason: why("chroot: cannot change root directory to '/': Operation not permitted"),
		});
		// Docker's own error: only its first line is kept.
		expect(
			await judge(
				answer(
					127,
					'',
					"\ndocker: Error response from daemon: unable to apply apparmor profile\n\nRun 'docker run --help' for more information\n",
				),
			),
		).toEqual({
			available: false,
			reason: why('docker: Error response from daemon: unable to apply apparmor profile'),
		});
		expect(await judge({ code: 1, stdout: '', stderr: '', timedOut: false })).toEqual({
			available: false,
			reason: why('it exited 1'),
		});
		expect(await judge({ code: -1, stdout: '', stderr: '', timedOut: true })).toEqual({
			available: false,
			reason: why('it did not finish in 120 seconds'),
		});
		// A recorder image built before the probe was.
		expect(
			await judge(
				answer(
					1,
					'',
					"node:internal/modules/cjs/loader:1607\n  throw err;\n  ^\n\nError: Cannot find module '/app/dist/probe.js'\n",
				),
			),
		).toEqual({
			available: false,
			reason: `the recorder image ${recorderImage} has no dist/probe.js, so koid cannot check that Chromium's sandbox starts in it; rebuild it from host/recorder and set KOI_RECORDER_IMAGE to the new id`,
		});
		expect(asked).toHaveLength(5);
	});

	test('removes probes an earlier start left before it probes, and its own after, whatever happened, and nothing that only carries the label', async () => {
		for (const result of [
			answer(0, ''),
			answer(1, '', 'Check failed: sys_chroot("/proc/self/fdinfo/") == 0\n'),
			{ code: -1, stdout: '', stderr: '', timedOut: true },
		]) {
			const asked: string[] = [];
			const judged = await verificationCapability(
				spec,
				box((line) => {
					if (line === leftover) {
						asked.push(line);
						// Two probes, then what carries the label without being one: a
						// preview whose image set it, a name a digit too long, and
						// one that is not hex.
						return answer(
							0,
							[
								'koi-sandbox-probe-0123456789ab',
								'koi-sandbox-probe-ba9876543210',
								'koi-sandbox-probe-abcdefghijklmnopqrst',
								'koi-sandbox-probe-0123456789abc',
								'koi-sandbox-probe-0123456789ag',
								'koi-hello-abcdefghij0123456789',
								'',
							].join('\n'),
						);
					}
					if (line.startsWith('docker rm ') || isProbe(line)) {
						asked.push(line);
						return isProbe(line) ? result : answer(0, '');
					}
					return undefined;
				}),
				installed,
			);
			expect(judged.available).toBe(result.code === 0);
			const name = probeName(asked[2] ?? '');
			expect(asked).toEqual([
				leftover,
				'docker rm --force koi-sandbox-probe-0123456789ab koi-sandbox-probe-ba9876543210',
				sandboxProbeArgs(name, recorderImage, spec.recorderSeccomp).join(' '),
				`docker rm --force ${name}`,
			]);
		}
	});

	test('counts a probe it could not list, remove, or see gone as a reason, and sweeps before it judges the images', async () => {
		const probeLine = 'koi-sandbox-probe-0123456789ab\n';
		const judge = (
			answers: { listing?: ExecResult; leftover?: ExecResult; own?: ExecResult },
			files: FileStat = installed,
		) => {
			const asked: string[] = [];
			const judged = verificationCapability(
				spec,
				box((line) => {
					if (line === leftover) {
						asked.push('list');
						return answers.listing ?? answer(0, probeLine);
					}
					if (line === 'docker rm --force koi-sandbox-probe-0123456789ab') {
						asked.push('remove leftover');
						return answers.leftover ?? answer(0, '');
					}
					if (removal.test(line)) {
						asked.push('remove own');
						return answers.own;
					}
					return undefined;
				}),
				files,
			);
			return { judged, asked };
		};
		const daemonDown = answer(1, '', 'Cannot connect to the Docker daemon\n');
		let t = judge({ listing: daemonDown });
		expect(await t.judged).toEqual({
			available: false,
			reason: 'looking for sandbox probes left behind: Cannot connect to the Docker daemon',
		});
		t = judge({ leftover: answer(1, '', 'Error response from daemon: device or resource busy\n') });
		expect(await t.judged).toEqual({
			available: false,
			reason:
				'removing the sandbox probes koi-sandbox-probe-0123456789ab left behind: Error response from daemon: device or resource busy',
		});
		// Gone already is removed.
		t = judge({ leftover: answer(1, '', 'Error response from daemon: No such container: x\n') });
		expect((await t.judged).available).toBe(true);
		// Its own probe, still there after the probe.
		t = judge({ own: { code: -1, stdout: '', stderr: '', timedOut: true } });
		expect(await t.judged).toMatchObject({
			available: false,
			reason: expect.stringMatching(
				/^the sandbox probe koi-sandbox-probe-[0-9a-f]{12} was not removed: no answer in 30 seconds; the next start removes it$/,
			),
		});
		// A box that has lost its seccomp file still loses its old probe.
		const noSeccomp: FileStat = async (path) =>
			path === spec.recorderSeccomp ? undefined : { isFile: true, uid: 0, gid: 0, mode: 0o755 };
		t = judge({}, noSeccomp);
		expect((await t.judged).available).toBe(false);
		expect(t.asked).toEqual(['list', 'remove leftover']);
	});

	test('reads the whole listing of labelled containers, so many previews cannot hide a probe', async () => {
		const options: Array<ExecOptions | undefined> = [];
		const run = box();
		await verificationCapability(
			spec,
			async (cmd, opts) => {
				if (cmd.join(' ') === leftover) options.push(opts);
				return run(cmd);
			},
			installed,
		);
		expect(options).toEqual([{ timeoutMs: 15_000, maxBytes: WHOLE_OUTPUT }]);
	});

	test('sweeps earlier probes when the helper is missing or sudo refuses, and names a sweep that failed', async () => {
		for (const [files, attest] of [
			[async () => undefined, undefined],
			[installed, answer(1, '', 'sudo: a password is required\n')],
		] as const) {
			const asked: string[] = [];
			const judged = await verificationCapability(
				spec,
				box((line) => {
					if (line === leftover) return answer(0, 'koi-sandbox-probe-0123456789ab\n');
					if (line.startsWith('docker rm ')) {
						asked.push(line);
						return answer(0, '');
					}
					if (line.startsWith('sudo ') && attest !== undefined) return attest;
					return undefined;
				}),
				files,
			);
			expect(judged.available).toBe(false);
			expect(asked).toEqual(['docker rm --force koi-sandbox-probe-0123456789ab']);
		}
		const judged = await verificationCapability(
			spec,
			box((line) =>
				line === leftover ? answer(1, '', 'Cannot connect to the Docker daemon\n') : undefined,
			),
			async () => undefined,
		);
		expect(judged).toEqual({
			available: false,
			reason:
				'looking for sandbox probes left behind: Cannot connect to the Docker daemon; /usr/local/libexec/koi-verify-net is not installed; scripts/deploy-host.sh installs it',
		});
		// A later step that throws keeps the sweep's reason beside its own.
		const busy = (line: string) =>
			line.startsWith('docker rm ')
				? answer(1, '', 'Error response from daemon: device or resource busy\n')
				: line === leftover
					? answer(0, 'koi-sandbox-probe-0123456789ab\n')
					: undefined;
		const unreadable: FileStat = async (path) => {
			throw new Error(`EACCES: permission denied, stat '${path}'`);
		};
		expect(await verificationCapability(spec, box(busy), unreadable)).toEqual({
			available: false,
			reason:
				"removing the sandbox probes koi-sandbox-probe-0123456789ab left behind: Error response from daemon: device or resource busy; checking /usr/local/libexec/koi-verify-net: EACCES: permission denied, stat '/usr/local/libexec/koi-verify-net'",
		});
		const noSudo = await verificationCapability(
			spec,
			box((line) => {
				if (line.startsWith('sudo ')) throw new Error('spawn sudo ENOENT');
				return busy(line);
			}),
			installed,
		);
		expect(noSudo).toEqual({
			available: false,
			reason:
				'removing the sandbox probes koi-sandbox-probe-0123456789ab left behind: Error response from daemon: device or resource busy; running sudo -n /usr/local/libexec/koi-verify-net attest: spawn sudo ENOENT',
		});
	});

	test('is unavailable without a recorder image, its seccomp profile, or the image on the box', async () => {
		expect(
			await verificationCapability({ ...spec, recorderImage: undefined }, box(), installed),
		).toEqual({
			available: false,
			reason:
				'KOI_RECORDER_IMAGE is not set; build host/recorder on the box and set it to the image id in /etc/koi/verify/env',
		});
		expect(
			await verificationCapability({ ...spec, verifierImage: undefined }, box(), installed),
		).toEqual({
			available: false,
			reason:
				'KOI_VERIFIER_IMAGE is not set; build host/verifier on the box and set it to the image id in /etc/koi/verify/env',
		});
		const noSeccomp: FileStat = async (path) =>
			path === spec.recorderSeccomp ? undefined : { isFile: true, uid: 0, gid: 0, mode: 0o755 };
		expect(await verificationCapability(spec, box(), noSeccomp)).toEqual({
			available: false,
			reason:
				'/usr/local/share/koi/recorder-seccomp.json is not installed; copy host/recorder/seccomp.json there (KOI_RECORDER_SECCOMP)',
		});
		const missing = await verificationCapability(
			spec,
			box((line) =>
				line.startsWith('docker image inspect')
					? answer(1, '', 'Error response from daemon: No such image\n')
					: undefined,
			),
			installed,
		);
		expect(missing).toEqual({
			available: false,
			reason: `the recorder image ${recorderImage} is not on the box: Error response from daemon: No such image`,
		});
		const noVerifier = await verificationCapability(
			spec,
			box((line) =>
				line === `docker image inspect --format {{.Id}} ${verifierImage}`
					? answer(1, '', 'Error response from daemon: No such image\n')
					: undefined,
			),
			installed,
		);
		expect(noVerifier).toEqual({
			available: false,
			reason: `the verifier image ${verifierImage} is not on the box: Error response from daemon: No such image`,
		});
	});

	test('is unavailable without a pool or a slice, asking nothing of the box', async () => {
		const asked: string[] = [];
		const run = async (cmd: string[]) => {
			asked.push(cmd.join(' '));
			return answer(0, '');
		};
		expect(await verificationCapability({ ...spec, pool: undefined }, run, installed)).toEqual({
			available: false,
			reason:
				'KOI_VERIFY_POOL is not set; provisioning writes it to /etc/koi/verify/env (scripts/provision-host.sh)',
		});
		expect(await verificationCapability({ ...spec, slice: undefined }, run, installed)).toEqual({
			available: false,
			reason:
				'koid runs without a slice, and the recorder and verifier must share one with previews',
		});
		expect(asked).toEqual([]);
	});

	test('is unavailable with a pool of the wrong shape, naming the variable and asking nothing of the box', async () => {
		const asked: string[] = [];
		const run = async (cmd: string[]) => {
			asked.push(cmd.join(' '));
			return answer(0, '');
		};
		const rule =
			'it must be an IPv4 network between a /16 and a /28 with its host bits clear, as in 10.213.0.0/20 (var.verify_pool in infra/, which provisioning writes to /etc/koi/verify/env)';
		for (const [pool, problem] of [
			['10.213.0.1/20', 'has host bits set'],
			['10.0.0.0/8', 'must be between a /16 and a /28'],
			['10.213.0.0/29', 'must be between a /16 and a /28'],
			['fd00::/64', 'is not an IPv4 network in CIDR form'],
			['pool', 'is not an IPv4 network in CIDR form'],
		] as const) {
			expect(await verificationCapability({ ...spec, pool }, run, installed)).toEqual({
				available: false,
				reason: `KOI_VERIFY_POOL is ${pool}, which ${problem}; ${rule}`,
			});
		}
		expect(asked).toEqual([]);
	});

	test("is unavailable when the helper is missing, not root's, or writable by others", async () => {
		const asked: string[] = [];
		const run = async (cmd: string[]) => {
			asked.push(cmd.join(' '));
			return answer(0, '');
		};
		const file =
			(changes: Partial<Awaited<ReturnType<FileStat>>>): FileStat =>
			async () => ({ isFile: true, uid: 0, gid: 0, mode: 0o755, ...changes });
		expect(await verificationCapability(spec, run, async () => undefined)).toEqual({
			available: false,
			reason:
				'/usr/local/libexec/koi-verify-net is not installed; scripts/deploy-host.sh installs it',
		});
		expect(
			(await verificationCapability(spec, run, file({ uid: 1001 }))).available === false &&
				(await verificationCapability(spec, run, file({ uid: 1001 }))),
		).toMatchObject({
			reason: '/usr/local/libexec/koi-verify-net is owned by 1001:0, not root',
		});
		expect(await verificationCapability(spec, run, file({ mode: 0o775 }))).toEqual({
			available: false,
			reason: '/usr/local/libexec/koi-verify-net has mode 0775, not 0755',
		});
		expect(await verificationCapability(spec, run, file({ mode: 0o4755 }))).toEqual({
			available: false,
			reason: '/usr/local/libexec/koi-verify-net has mode 4755, not 0755',
		});
		expect(await verificationCapability(spec, run, file({ isFile: false }))).toEqual({
			available: false,
			reason: '/usr/local/libexec/koi-verify-net is not a regular file',
		});
		// Only the sweep of earlier probes asks the box: it goes first, whatever
		// the helper is.
		expect(new Set(asked)).toEqual(new Set([leftover]));
	});

	test('is unavailable when sudo refuses, or the helper prints something else', async () => {
		const refused = await verificationCapability(
			spec,
			box((line) =>
				line.startsWith('sudo') ? answer(1, '', 'sudo: a password is required\n') : undefined,
			),
			installed,
		);
		expect(refused).toEqual({
			available: false,
			reason:
				'sudo -n /usr/local/libexec/koi-verify-net attest exited 1: sudo: a password is required; provisioning installs the sudoers rule for it',
		});
		const odd = await verificationCapability(
			spec,
			box((line) =>
				line.startsWith('sudo') ? answer(0, 'usage: koi-verify-net ...\n') : undefined,
			),
			installed,
		);
		expect(odd).toEqual({
			available: false,
			reason: 'koi-verify-net attest printed something other than JSON',
		});
	});

	test('is unavailable when the attestation says the host is not ready, naming everything', async () => {
		const bad = {
			...attestation,
			policy: 1,
			pool: '10.0.0.0/20',
			ipv4: {
				chains: false,
				jump: true,
				defaults: false,
				permits: false,
				problems: ['chain KOI-VERIFY does not exist'],
			},
			ipv6: { defaults: false, problems: ['ip6tables INPUT has no rule -i kv+ -j DROP'] },
			bridge: {
				guard: false,
				pins: true,
				problems: ['ebtables chain KOI-VERIFY-L2 does not exist'],
			},
			sysctl: {
				br_netfilter: true,
				bridge_nf_call_iptables: false,
				bridge_nf_call_ip6tables: true,
				bridge_nf_filter_vlan_tagged: false,
			},
		};
		const result = await verificationCapability(
			spec,
			box((line) => (line.startsWith('sudo') ? answer(0, JSON.stringify(bad)) : undefined)),
			installed,
		);
		expect(result).toEqual({
			available: false,
			reason: [
				'the helper installs policy version 1, and koid expects 2',
				"the helper's pool is 10.0.0.0/20 and KOI_VERIFY_POOL is 10.213.0.0/20; both come from /etc/koi/verify/env",
				'chain KOI-VERIFY does not exist',
				'ip6tables INPUT has no rule -i kv+ -j DROP',
				'ebtables chain KOI-VERIFY-L2 does not exist',
				'net.bridge.bridge-nf-call-iptables is not 1',
				'net.bridge.bridge-nf-filter-vlan-tagged is not 1',
			].join('; '),
		});
	});

	test('is unavailable when the slice has no ceiling', async () => {
		const result = await verificationCapability(
			spec,
			box((line) =>
				line.includes('ActiveState')
					? answer(0, 'MemoryMax=infinity\nActiveState=active\n')
					: undefined,
			),
			installed,
		);
		expect(result).toEqual({
			available: false,
			reason: 'koi.slice has no memory ceiling (MemoryMax)',
		});
	});

	// An interrupted provision left the parent jumping to the staged chain.
	// attest reports it; the helper's revoke, which the cleanup calls for
	// each leftover, finishes the swap.
	const swapped = {
		...attestation,
		ipv4: {
			...attestation.ipv4,
			jump: false,
			problems: [
				'chain DOCKER-USER does not start with -j KOI-VERIFY: its first rule is -A DOCKER-USER -j KOI-VERIFY-NEW',
			],
		},
	};
	const counting = () => {
		const calls = { n: 0 };
		const cleanup = async () => {
			calls.n += 1;
		};
		return { calls, cleanup };
	};

	test('cleans up once the helper answers, whatever it attests, and judges the box after', async () => {
		// The cleanup mends the box, as a revoke does.
		const mended = counting();
		const asked: string[] = [];
		const result = await verificationCapability(
			{ ...spec, cleanup: mended.cleanup },
			box((line) => {
				asked.push(line);
				if (!line.endsWith(' attest') || mended.calls.n > 0) return undefined;
				return answer(0, JSON.stringify(swapped));
			}),
			installed,
		);
		expect(mended.calls.n).toBe(1);
		expect(result).toEqual({
			available: true,
			attestation,
			recorderImageId: recorderImage,
			verifierImageId: verifierImage,
		});
		// Once to know the helper answers, once more for the box as the
		// cleanup left it.
		expect(asked.filter((line) => line.endsWith(' attest'))).toHaveLength(2);
		// A box the cleanup does not mend is cleaned up all the same, and
		// reports the problem.
		const still = counting();
		const unmended = await verificationCapability(
			{ ...spec, cleanup: still.cleanup },
			box((line) => (line.endsWith(' attest') ? answer(0, JSON.stringify(swapped)) : undefined)),
			installed,
		);
		expect(still.calls.n).toBe(1);
		expect(unmended).toEqual({ available: false, reason: swapped.ipv4.problems.join('; ') });
	});

	// A box with no recorder yet can still hold permits and networks from
	// earlier runs, so the recorder checks must not stop the cleanup.
	test('cleans up on a box whose recorder is not ready, and reports both problems', async () => {
		const noImage = counting();
		expect(
			await verificationCapability(
				{ ...spec, recorderImage: undefined, cleanup: noImage.cleanup },
				box((line) => (line.endsWith(' attest') ? answer(0, JSON.stringify(swapped)) : undefined)),
				installed,
			),
		).toEqual({
			available: false,
			reason: `${swapped.ipv4.problems.join('; ')}; KOI_RECORDER_IMAGE is not set; build host/recorder on the box and set it to the image id in /etc/koi/verify/env`,
		});
		expect(noImage.calls.n).toBe(1);

		const noSeccomp = counting();
		await verificationCapability({ ...spec, cleanup: noSeccomp.cleanup }, box(), async (path) =>
			path === spec.recorderSeccomp ? undefined : { isFile: true, uid: 0, gid: 0, mode: 0o755 },
		);
		expect(noSeccomp.calls.n).toBe(1);

		const imageGone = counting();
		await verificationCapability(
			{ ...spec, cleanup: imageGone.cleanup },
			box((line) =>
				line.startsWith('docker image inspect') ? answer(1, '', 'No such image\n') : undefined,
			),
			installed,
		);
		expect(imageGone.calls.n).toBe(1);
	});

	// A failure of the recorder checks is a reason too, never an error that
	// would stop koid.
	test('is unavailable, naming the step, when the recorder checks throw', async () => {
		const unreadable: FileStat = async (path) => {
			if (path === spec.recorderSeccomp) throw new Error('EACCES: permission denied');
			return { isFile: true, uid: 0, gid: 0, mode: 0o755 };
		};
		expect(await verificationCapability(spec, box(), unreadable)).toEqual({
			available: false,
			reason: 'checking /usr/local/share/koi/recorder-seccomp.json: EACCES: permission denied',
		});
		const noDocker = box((line) => {
			if (line.startsWith('docker image inspect')) throw new Error('spawn docker ENOENT');
			return undefined;
		});
		expect(await verificationCapability(spec, noDocker, installed)).toEqual({
			available: false,
			reason: `checking the recorder image ${recorderImage}: spawn docker ENOENT`,
		});
	});

	test('a cleanup that reports nothing wrong does not excuse a run the helper still lists', async () => {
		const { cleanup } = counting();
		const run = 'a'.repeat(16);
		const held = JSON.stringify({ ...attestation, runs: [run] });
		const result = await verificationCapability(
			{ ...spec, cleanup },
			box((line) => (line.endsWith(' attest') ? answer(0, held) : undefined)),
			installed,
		);
		expect(result).toEqual({
			available: false,
			reason: `the helper still lists run ${run} after the cleanup`,
		});
	});

	test('skips the cleanup when the helper is missing, or sudo refuses, and the reason says which', async () => {
		const { calls, cleanup } = counting();
		expect(
			await verificationCapability({ ...spec, cleanup }, box(), async () => undefined),
		).toEqual({
			available: false,
			reason:
				'/usr/local/libexec/koi-verify-net is not installed; scripts/deploy-host.sh installs it',
		});
		const refused = await verificationCapability(
			{ ...spec, cleanup },
			box((line) =>
				line.startsWith('sudo') ? answer(1, '', 'sudo: a password is required\n') : undefined,
			),
			installed,
		);
		expect(refused).toEqual({
			available: false,
			reason:
				'sudo -n /usr/local/libexec/koi-verify-net attest exited 1: sudo: a password is required; provisioning installs the sudoers rule for it',
		});
		expect(calls.n).toBe(0);
	});

	test('a cleanup that fails makes verification unavailable, with what the box attests', async () => {
		const cleanup = async () => {
			throw new Error('EACCES: permission denied, scandir');
		};
		expect(await verificationCapability({ ...spec, cleanup }, box(), installed)).toEqual({
			available: false,
			reason: 'removing what earlier runs left: EACCES: permission denied, scandir',
		});
		const both = await verificationCapability(
			{ ...spec, cleanup },
			box((line) => (line.endsWith(' attest') ? answer(0, JSON.stringify(swapped)) : undefined)),
			installed,
		);
		expect(both).toEqual({
			available: false,
			reason: `removing what earlier runs left: EACCES: permission denied, scandir; ${swapped.ipv4.problems.join('; ')}`,
		});
	});

	// The catch around the check cannot see the reasons found so far, so a
	// check that throws must add to them. A cleanup failure followed by a
	// seccomp EACCES once returned only the EACCES.
	describe('a check that throws after other reasons are known', () => {
		const cleanup = async () => {
			throw new Error('EACCES: permission denied, scandir');
		};
		const left = 'removing what earlier runs left: EACCES: permission denied, scandir';
		const unreadable: FileStat = async (path) => {
			if (path === spec.recorderSeccomp) throw new Error('EACCES: permission denied');
			return { isFile: true, uid: 0, gid: 0, mode: 0o755 };
		};
		const seccomp =
			'checking /usr/local/share/koi/recorder-seccomp.json: EACCES: permission denied';

		test('a throwing recorder check keeps the cleanup failure', async () => {
			expect(await verificationCapability({ ...spec, cleanup }, box(), unreadable)).toEqual({
				available: false,
				reason: `${left}; ${seccomp}`,
			});
			const noDocker = box((line) => {
				if (line.startsWith('docker image inspect')) throw new Error('spawn docker ENOENT');
				return undefined;
			});
			expect(await verificationCapability({ ...spec, cleanup }, noDocker, installed)).toEqual({
				available: false,
				reason: `${left}; checking the recorder image ${recorderImage}: spawn docker ENOENT`,
			});
		});

		test('a throwing recorder check keeps what the box attests', async () => {
			const result = await verificationCapability(
				spec,
				box((line) => (line.endsWith(' attest') ? answer(0, JSON.stringify(swapped)) : undefined)),
				unreadable,
			);
			expect(result).toEqual({
				available: false,
				reason: `${swapped.ipv4.problems.join('; ')}; ${seccomp}`,
			});
		});

		test('a throwing slice check keeps the cleanup failure, and the recorder is still judged', async () => {
			const noSystemctl = box((line) => {
				if (line.startsWith('systemctl')) throw new Error('spawn systemctl ENOENT');
				return undefined;
			});
			expect(await verificationCapability({ ...spec, cleanup }, noSystemctl, unreadable)).toEqual({
				available: false,
				reason: [left, 'checking koi.slice: spawn systemctl ENOENT', seccomp].join('; '),
			});
		});

		test('an attest that throws after the cleanup keeps the cleanup failure', async () => {
			let attests = 0;
			const sudoGone = box((line) => {
				if (!line.endsWith(' attest')) return undefined;
				attests += 1;
				if (attests > 1) throw new Error('spawn sudo ENOENT');
				return undefined;
			});
			expect(await verificationCapability({ ...spec, cleanup }, sudoGone, installed)).toEqual({
				available: false,
				reason: `${left}; running sudo -n /usr/local/libexec/koi-verify-net attest: spawn sudo ENOENT`,
			});
		});
	});

	// A failure of the check itself is a reason, never an error out of it:
	// koid logs it and keeps serving previews.
	test('is unavailable, naming the step, when the helper cannot be checked', async () => {
		// KOI_VERIFY_HELPER under a directory the koi user may not search:
		// stat fails with EACCES, which is not a missing file.
		const { calls, cleanup } = counting();
		const asked: string[] = [];
		const unreadable: FileStat = async (path) => {
			throw new Error(`EACCES: permission denied, stat '${path}'`);
		};
		expect(
			await verificationCapability(
				{ ...spec, cleanup },
				box((line) => {
					asked.push(line);
					return undefined;
				}),
				unreadable,
			),
		).toEqual({
			available: false,
			reason:
				"checking /usr/local/libexec/koi-verify-net: EACCES: permission denied, stat '/usr/local/libexec/koi-verify-net'",
		});
		expect(asked).toEqual([leftover]);
		expect(calls.n).toBe(0);
	});

	test.skipIf(process.getuid?.() === 0)(
		'a helper under a directory koi cannot search is such a case, with the real stat',
		async () => {
			const dir = await mkdtemp(join(tmpdir(), 'koid-helper-'));
			const locked = join(dir, 'locked');
			await mkdir(locked, { mode: 0o000 });
			const helper = join(locked, 'koi-verify-net');
			try {
				const result = await verificationCapability({ ...spec, helper }, box());
				expect(result.available).toBe(false);
				expect(result.available === false && result.reason).toMatch(
					new RegExp(`^checking ${helper}: EACCES`),
				);
			} finally {
				await chmod(locked, 0o755);
				await rm(dir, { recursive: true, force: true });
			}
		},
	);

	test('is unavailable, naming the command, when sudo cannot be spawned', async () => {
		const { calls, cleanup } = counting();
		const noSudo = async (cmd: string[]): Promise<ExecResult> => {
			if (cmd[0] === 'sudo') throw new Error('Executable not found in $PATH: "sudo"');
			return box()(cmd);
		};
		expect(await verificationCapability({ ...spec, cleanup }, noSudo, installed)).toEqual({
			available: false,
			reason:
				'running sudo -n /usr/local/libexec/koi-verify-net attest: Executable not found in $PATH: "sudo"',
		});
		expect(calls.n).toBe(0);
		// With the real exec: spawning a binary that is not there throws,
		// and the reason carries what it said.
		const missing = async (cmd: string[], options?: ExecOptions): Promise<ExecResult> =>
			cmd[0] === 'sudo'
				? exec([join(tmpdir(), 'no-such-sudo'), ...cmd.slice(1)], options)
				: box()(cmd);
		const result = await verificationCapability(spec, missing, installed);
		expect(result.available).toBe(false);
		expect(result.available === false && result.reason).toMatch(
			/^running sudo -n \/usr\/local\/libexec\/koi-verify-net attest: .+/,
		);
	});

	test('is unavailable when the helper gives no answer in time', async () => {
		// exec kills a command past its time limit and reports it as timed
		// out, with whatever it printed.
		const { calls, cleanup } = counting();
		const hung = (stderr: string) =>
			box((line) =>
				line.endsWith(' attest') ? { code: 137, stdout: '', stderr, timedOut: true } : undefined,
			);
		expect(await verificationCapability({ ...spec, cleanup }, hung(''), installed)).toEqual({
			available: false,
			reason: 'sudo -n /usr/local/libexec/koi-verify-net attest gave no answer in 60 seconds',
		});
		expect(
			await verificationCapability(
				{ ...spec, cleanup },
				hung('waiting for the xtables lock\n'),
				installed,
			),
		).toEqual({
			available: false,
			reason:
				'sudo -n /usr/local/libexec/koi-verify-net attest gave no answer in 60 seconds: waiting for the xtables lock',
		});
		expect(calls.n).toBe(0);
	});

	test('is unavailable, naming the slice, when the slice cannot be checked', async () => {
		const result = await verificationCapability(
			spec,
			box((line) => {
				if (line.startsWith('systemctl')) {
					throw new Error('Executable not found in $PATH: "systemctl"');
				}
				return undefined;
			}),
			installed,
		);
		expect(result).toEqual({
			available: false,
			reason: 'checking koi.slice: Executable not found in $PATH: "systemctl"',
		});
	});
});

describe('host/cloud-init.sh', () => {
	const script = readFileSync(resolve(import.meta.dir, '../../../host/cloud-init.sh'), 'utf8');
	const unit = (name: string) =>
		new RegExp(`cat > /etc/systemd/system/${name} <<'UNIT'\\n([\\s\\S]*?)\\nUNIT`).exec(
			script,
		)?.[1] ?? '';

	test('koid starts only after the firewall, and stops with it', () => {
		const koid = unit('koid.service');
		expect(koid).toMatch(/^Requires=.*\bkoi-firewall\.service\b/m);
		expect(koid).toMatch(/^After=.*\bkoi-firewall\.service\b/m);
	});

	test('the box powers off after 10 idle minutes', () => {
		expect(script).toMatch(/^IDLE_MINUTES=10$/m);
		expect(script).toContain('limit=$(( IDLE_MINUTES * 60 ))');
	});

	test('koid starts only once the slice is up, and stops with it', () => {
		const koid = unit('koid.service');
		expect(koid).toMatch(/^Requires=.*\bkoi\.slice\b/m);
		expect(koid).toMatch(/^After=.*\bkoi\.slice\b/m);
	});

	test('the slice leaves 2.5 to 3 GiB of a 16 GiB box to the host', () => {
		const slice = unit('koi.slice');
		const percent = Number(/^MemoryMax=(\d+)%$/m.exec(slice)?.[1]);
		const left = (16 * (100 - percent)) / 100;
		expect(left).toBeGreaterThanOrEqual(2.5);
		expect(left).toBeLessThanOrEqual(3);
	});

	test('the slice koid uses by default is the one provisioning makes, before docker runs', () => {
		const { slice } = loadConfig({
			KOI_UPLOADS_BUCKET: 'koi-uploads',
			KOI_DOMAIN: 'previews.example.net',
		});
		expect(slice).toBe('koi.slice');
		expect(script).toContain(`cat > /etc/systemd/system/${slice} <<'UNIT'`);
		expect(script).toContain(`'. + {"cgroup-parent": "${slice}"}'`);
		const started = script.indexOf(`systemctl start ${slice}`);
		expect(started).toBeGreaterThan(0);
		expect(started).toBeLessThan(script.indexOf('apt-get install -y docker-ce'));
		expect(started).toBeLessThan(script.indexOf('systemctl restart docker.service'));
	});

	test('the firewall drops new connections to the host from both bridges', () => {
		expect(script).toContain('for bridge in koi-previews0 koi-build0; do');
		expect(script).toContain('rule=(INPUT -i "$bridge" -m conntrack --ctstate NEW -j DROP)');
	});

	test('provisioning makes the networks and builder koid checks for', () => {
		for (const n of spec.networks) {
			expect(script).toContain(`ensure_network ${n.name} ${n.bridge} ${n.internal}\n`);
		}
		expect(script).toContain(
			'--driver-opt network=koi-build --driver-opt memory=8g --driver-opt cpu-quota=300000',
		);
	});

	describe('verification', () => {
		const helper = loadConfig({
			KOI_UPLOADS_BUCKET: 'koi-uploads',
			KOI_DOMAIN: 'previews.example.net',
		}).verifyHelper;

		test('lets koi run exactly the helper as root, after visudo has accepted the rule', () => {
			expect(script).toContain(`koi ALL=(root:root) NOPASSWD: ${helper}\n`);
			const check = script.indexOf('visudo -cf /etc/sudoers.d/.koi-verify-net.new');
			expect(check).toBeGreaterThan(0);
			expect(check).toBeLessThan(
				script.indexOf('mv -f /etc/sudoers.d/.koi-verify-net.new /etc/sudoers.d/koi-verify-net'),
			);
			expect(script).toContain('chmod 0440 /etc/sudoers.d/.koi-verify-net.new');
		});

		test("writes the pool where koid and the helper read it, with a default outside Docker's pools", () => {
			expect(script).toMatch(/^KOI_VERIFY_POOL=\$\{KOI_VERIFY_POOL:-10\.213\.0\.0\/20\}$/m);
			expect(script).toContain(
				`printf 'KOI_VERIFY_POOL=%s\\n' "$KOI_VERIFY_POOL" > /etc/koi/verify/env`,
			);
			expect(unit('koid.service')).toContain('EnvironmentFile=-/etc/koi/verify/env');
			// The infra variable and the provisioning script hand it over like the domain.
			const box = readFileSync(
				resolve(import.meta.dir, '../../../infra/modules/koi/box.tf'),
				'utf8',
			);
			expect(box).toContain(['"KOI_VERIFY_POOL=$', '{var.verify_pool}",'].join(''));
			const provision = readFileSync(
				resolve(import.meta.dir, '../../../scripts/provision-host.sh'),
				'utf8',
			);
			expect(provision).toContain('KOI_VERIFY_POOL=%s');
			const variables = readFileSync(
				resolve(import.meta.dir, '../../../infra/modules/koi/variables.tf'),
				'utf8',
			);
			expect(variables).toContain('default     = "10.213.0.0/20"');
			// The variable takes a network address alone, so a value the
			// capability check would refuse for its host bits never leaves infra.
			expect(variables).toContain(
				'try(cidrsubnet(var.verify_pool, 0, 0), var.verify_pool) == var.verify_pool',
			);
			expect(variables).toContain('with its host bits clear: 10.213.0.0/20, not 10.213.0.1/20');
		});

		test("gives Caddy the deployment's region, which infra and provisioning pass like the domain", () => {
			expect(script).toMatch(/^KOI_REGION=\$\{KOI_REGION:-us-east-1\}$/m);
			const caddy =
				/cat > \/etc\/systemd\/system\/caddy\.service <<UNIT\n([\s\S]*?)\nUNIT\n/.exec(
					script,
				)?.[1] ?? '';
			expect(caddy).toContain('Environment=AWS_REGION=$KOI_REGION\n');
			// The heredoc is unquoted for the region, so nothing else in it may expand.
			expect(caddy.replace('$KOI_REGION', '')).not.toMatch(/[$`\\]/);
			const box = readFileSync(
				resolve(import.meta.dir, '../../../infra/modules/koi/box.tf'),
				'utf8',
			);
			expect(box).toContain(['"KOI_REGION=$', '{local.region}",'].join(''));
			const provision = readFileSync(
				resolve(import.meta.dir, '../../../scripts/provision-host.sh'),
				'utf8',
			);
			expect(provision).toContain('KOI_REGION=%s');
		});

		test('loads br_netfilter and keeps the bridge sysctls on across boots', () => {
			expect(script).toContain("printf 'br_netfilter\\n' > /etc/modules-load.d/koi-verify.conf");
			expect(script).toContain('net.bridge.bridge-nf-call-iptables = 1');
			expect(script).toContain('net.bridge.bridge-nf-call-ip6tables = 1');
			// A VLAN-tagged frame reaches iptables only with this one on.
			expect(script).toContain('net.bridge.bridge-nf-filter-vlan-tagged = 1');
			expect(script).toContain('sysctl -q -p /etc/sysctl.d/90-koi-verify.conf');
			// And in the firewall unit, which runs before koid.
			const firewall =
				/cat > \/usr\/local\/sbin\/koi-firewall <<'FW'\n([\s\S]*?)\nFW\n/.exec(script)?.[1] ?? '';
			expect(firewall).toContain('modprobe br_netfilter');
			expect(firewall).toContain(
				'sysctl -q -w net.bridge.bridge-nf-call-iptables=1 net.bridge.bridge-nf-call-ip6tables=1 net.bridge.bridge-nf-filter-vlan-tagged=1',
			);
		});

		test('the firewall leaves the kv+ chains, their denies and their jumps to the helper', () => {
			const firewall =
				/cat > \/usr\/local\/sbin\/koi-firewall <<'FW'\n([\s\S]*?)\nFW\n/.exec(script)?.[1] ?? '';
			// Called when installed; a box before its first deploy says so instead.
			expect(firewall).toContain('KOI_VERIFY_NET=/usr/local/libexec/koi-verify-net');
			expect(firewall).toContain(
				'if [ -x "$KOI_VERIFY_NET" ]; then\n\t"$KOI_VERIFY_NET" provision',
			);
			expect(firewall).toContain(
				'is not installed yet; the verification chains come with the first deploy',
			);
			// No rule of those chains is written here: every iptables line is
			// about the preview bridges and the metadata address.
			const commands = firewall.split('\n').filter((l) => /^\s*(ip6?tables|xargs)/.test(l));
			expect(commands.length).toBeGreaterThan(0);
			for (const line of commands) {
				expect(line).not.toContain('KOI-VERIFY');
				expect(line).not.toContain('kv+');
			}
			expect(script).not.toContain('reset_defaults');
			// The preview rules are as they were.
			expect(firewall).toContain('for bridge in koi-previews0 koi-build0; do');
			expect(firewall).toContain(
				'accept=(INPUT -i koi-previews0 -p tcp --dport 3128 -m conntrack --ctstate NEW -j ACCEPT)',
			);
			// The installer provisions too, so a box that gets the helper for
			// the first time gets the chains with it.
			const install = readFileSync(
				resolve(import.meta.dir, '../../../host/verify/install.sh'),
				'utf8',
			);
			expect(install).toContain('"$TARGET" provision');
		});

		test('the deploy installs the helper bundle, and conntrack is on the box for revoke', () => {
			expect(script).toMatch(/^apt-get install -y .*\bconntrack\b/m);
			const deploy = readFileSync(
				resolve(import.meta.dir, '../../../scripts/deploy-host.sh'),
				'utf8',
			);
			expect(deploy).toContain('bash /usr/local/share/koi/verify/install.sh');
			const install = readFileSync(
				resolve(import.meta.dir, '../../../host/verify/install.sh'),
				'utf8',
			);
			expect(install).toContain(`TARGET=${helper}`);
			expect(install).toContain('install -o root -g root -m 0755');
		});
	});
});

// scripts/host-settings.sh as deploy-host.sh and provision-host.sh source it,
// with tofu and aws replaced by scripts that log their calls. The fake tofu
// has two of the personal root's outputs, and the region output only when
// STATE_REGION is set, as in state applied before that output existed; the
// fake aws knows a profile region only when PROFILE_REGION is set.
describe('scripts/host-settings.sh, run in bash', () => {
	const repo = resolve(import.meta.dir, '../../..');

	async function run(body: string, env: Record<string, string> = {}) {
		const dir = await mkdtemp(join(tmpdir(), 'koi-host-settings-'));
		const calls = join(dir, 'calls');
		await writeFile(calls, '');
		await writeFile(
			join(dir, 'tofu'),
			[
				'#!/bin/bash',
				`echo "tofu $*" >> '${calls}'`,
				'case "$4" in',
				'box_instance_id) printf i-0123456789abcdef0 ;;',
				'domain) printf previews.example.com ;;',
				`region) if [ -n "\${STATE_REGION:-}" ]; then printf %s "$STATE_REGION"; else echo "Output region not found" >&2; exit 1; fi ;;`,
				'*) echo "Output $4 not found" >&2; exit 1 ;;',
				'esac',
			].join('\n'),
			{ mode: 0o755 },
		);
		await writeFile(
			join(dir, 'aws'),
			[
				'#!/bin/bash',
				`echo "aws $*" >> '${calls}'`,
				`[ -n "\${PROFILE_REGION:-}" ] && printf '%s\\n' "$PROFILE_REGION"`,
				'exit 0',
			].join('\n'),
			{ mode: 0o755 },
		);
		const file = join(dir, 'run.sh');
		await writeFile(
			file,
			['set -euo pipefail', `repo='${repo}'`, '. "$repo/scripts/host-settings.sh"', body].join(
				'\n',
			),
		);
		const vars = Object.entries(env).map(([k, v]) => `${k}=${v}`);
		const r = await exec(['env', '-i', `PATH=${dir}:/usr/bin:/bin`, ...vars, 'bash', file], {
			timeoutMs: 30_000,
		});
		const lines = (await readFile(calls, 'utf8')).split('\n').filter((l) => l !== '');
		return { code: r.code, stdout: r.stdout, stderr: r.stderr, calls: lines };
	}

	test('takes each value from its variable and runs no tofu when it is set', async () => {
		const r = await run(
			'koi_setting KOI_INSTANCE_ID box_instance_id\nkoi_setting KOI_DOMAIN domain',
			{
				KOI_INSTANCE_ID: 'i-0fedcba9876543210',
				KOI_DOMAIN: 'previews.example.org',
			},
		);
		expect(r.code).toBe(0);
		expect(r.stdout).toBe('i-0fedcba9876543210\npreviews.example.org\n');
		expect(r.calls).toEqual([]);
	});

	test('reads an unset value from the tofu output of infra/', async () => {
		const r = await run(
			'instance=$(koi_setting KOI_INSTANCE_ID box_instance_id)\necho "$instance"',
		);
		expect(r.code).toBe(0);
		expect(r.stdout).toBe('i-0123456789abcdef0\n');
		expect(r.calls).toEqual([`tofu -chdir=${repo}/infra output -raw box_instance_id`]);
	});

	test('stops on an empty variable, and on an output infra/ does not have', async () => {
		const empty = await run('x=$(koi_setting KOI_BUCKET uploads_bucket)\necho "went on"', {
			KOI_BUCKET: '',
		});
		expect(empty.code).not.toBe(0);
		expect(empty.stdout).toBe('');
		expect(empty.stderr).toContain('KOI_BUCKET is set but empty');
		expect(empty.calls).toEqual([]);
		const missing = await run('x=$(koi_setting KOI_BUCKET uploads_bucket)\necho "went on"');
		expect(missing.code).not.toBe(0);
		expect(missing.stdout).toBe('');
		expect(missing.stderr).toContain(
			'KOI_BUCKET is not set, and infra/ has no uploads_bucket output',
		);
	});

	test('takes the region from AWS_REGION, else from where the deployment comes from', async () => {
		const env = await run('koi_region', { AWS_REGION: 'eu-west-1', PROFILE_REGION: 'us-west-2' });
		expect(env.stdout).toBe('eu-west-1\n');
		expect(env.calls).toEqual([]);
		// The deployment from infra/'s state is where that state put it,
		// whatever region the profile names.
		const state = await run('koi_region', {
			STATE_REGION: 'eu-central-1',
			PROFILE_REGION: 'us-west-2',
		});
		expect(state.stdout).toBe('eu-central-1\n');
		expect(state.calls).toEqual([`tofu -chdir=${repo}/infra output -raw region`]);
		const old = await run('koi_region', { PROFILE_REGION: 'us-west-2' });
		expect(old.stdout).toBe('us-east-1\n');
		// One from another root names its instance, and is in the profile's.
		const profile = await run('koi_region', {
			KOI_INSTANCE_ID: 'i-0fedcba9876543210',
			AWS_PROFILE: 'koi-sso',
			PROFILE_REGION: 'us-west-2',
		});
		expect(profile.stdout).toBe('us-west-2\n');
		expect(profile.calls).toEqual(['aws configure get region']);
		const none = await run('koi_region', { KOI_INSTANCE_ID: 'i-0fedcba9876543210' });
		expect(none.stdout).toBe('us-east-1\n');
	});

	test('takes a verification pool only as a network address koid accepts', async () => {
		for (const pool of ['10.213.0.0/20', '10.213.16.0/20', '192.168.0.16/28']) {
			const r = await run(`koi_check_pool ${pool} KOI_VERIFY_POOL\necho "went on"`);
			expect({ pool, stdout: r.stdout }).toEqual({ pool, stdout: 'went on\n' });
		}
		for (const [pool, problem] of [
			['10.213.0.1/20', 'names a host'],
			['10.213.8.0/20', 'names a host'],
			['10.256.0.0/16', '256 is over 255'],
			['010.213.0.0/20', 'not an IPv4 network between /16 and /28'],
			['10.213.0.0/29', 'not an IPv4 network between /16 and /28'],
		]) {
			const r = await run(`koi_check_pool ${pool} KOI_VERIFY_POOL\necho "went on"`);
			expect({ pool, code: r.code, stdout: r.stdout }).toEqual({ pool, code: 1, stdout: '' });
			expect(r.stderr).toContain(`KOI_VERIFY_POOL is '${pool}', which`);
			expect(r.stderr).toContain(problem as string);
		}
	});

	test('stops on a value that is not the shape it goes to the box as', async () => {
		const bad = await run(
			`koi_check 'x$(reboot)' '^[a-z0-9.-]+$' 'KOI_DOMAIN or the domain output' 'a bare hostname'\necho "went on"`,
		);
		expect(bad.code).toBe(1);
		expect(bad.stdout).toBe('');
		expect(bad.stderr).toBe(
			"KOI_DOMAIN or the domain output is 'x$(reboot)', which is not a bare hostname\n",
		);
		const ok = await run(`koi_check i-0123456789abcdef0 '^i-[0-9a-f]{8,17}$' x y\necho "went on"`);
		expect(ok.stdout).toBe('went on\n');
	});

	test('both scripts read the deployment through it and check every value they send', () => {
		for (const name of ['deploy-host.sh', 'provision-host.sh']) {
			const text = readFileSync(join(repo, 'scripts', name), 'utf8');
			expect(text).toContain('. "$repo/scripts/host-settings.sh"');
			expect(text).not.toContain('output -raw');
			const read = [...text.matchAll(/^(\w+)=\$\(koi_(?:setting|region)\b/gm)].map((m) => m[1]);
			expect(read.length).toBeGreaterThan(2);
			for (const v of read) expect(text).toMatch(new RegExp(`koi_check(_pool)? "\\$${v}"`));
		}
	});
});

// The firewall script as its unit runs it, in bash, with iptables, ip6tables,
// modprobe and sysctl replaced by functions that log their calls and the
// helper by a script of this test's. koid.service Requires= the unit, so an
// exit other than 0 here keeps koid and every preview from starting.
describe('koi-firewall, run in bash', () => {
	const script = readFileSync(resolve(import.meta.dir, '../../../host/cloud-init.sh'), 'utf8');
	const firewall =
		/cat > \/usr\/local\/sbin\/koi-firewall <<'FW'\n([\s\S]*?)\nFW\n/.exec(script)?.[1] ?? '';
	const helperLine = 'KOI_VERIFY_NET=/usr/local/libexec/koi-verify-net';

	// `helper` is the body of the fake helper, undefined for none installed.
	// A -C or -D that fails means the rule is not there, as on a new box, so
	// the script inserts every rule and the -D loop ends.
	async function runFirewall(helper: string | undefined, stubs = '') {
		const dir = await mkdtemp(join(tmpdir(), 'koi-firewall-'));
		const calls = join(dir, 'calls');
		const path = join(dir, 'koi-verify-net');
		if (helper !== undefined) {
			const body = `#!/bin/bash\necho "helper $*" >> '${calls}'\n${helper}\n`;
			await writeFile(path, body, { mode: 0o755 });
		}
		const file = join(dir, 'firewall.sh');
		await writeFile(
			file,
			[
				`calls='${calls}'`,
				': > "$calls"',
				'iptables() { echo "iptables $*" >> "$calls"; case "$1" in -C | -D) return 1 ;; esac; }',
				'ip6tables() { echo "ip6tables $*" >> "$calls"; case "$1" in -C | -D) return 1 ;; esac; }',
				'modprobe() { echo "modprobe $*" >> "$calls"; }',
				'sysctl() { echo "sysctl $*" >> "$calls"; }',
				stubs,
				firewall.replace(helperLine, `KOI_VERIFY_NET='${path}'`),
			].join('\n'),
		);
		const r = await exec(['bash', file], { timeoutMs: 30_000 });
		const lines = (await readFile(calls, 'utf8')).split('\n').filter((l) => l !== '');
		return { code: r.code, stdout: r.stdout, stderr: r.stderr, calls: lines, path };
	}

	const previewRules = [
		'ip6tables -I DOCKER-USER -d fd00:ec2::254 -j DROP',
		'iptables -I DOCKER-USER -d 169.254.169.254 -j DROP',
		'iptables -I INPUT -i koi-build0 -m conntrack --ctstate NEW -j DROP',
		'iptables -I INPUT -i koi-previews0 -m conntrack --ctstate NEW -j DROP',
		'iptables -I INPUT -i koi-previews0 -p tcp --dport 3128 -m conntrack --ctstate NEW -j ACCEPT',
	];
	const inserted = (calls: string[]) => calls.filter((c) => / -I /.test(c)).sort();

	test('the script names the helper on a line these tests can replace', () => {
		expect(firewall).toContain(helperLine);
	});

	test('a helper that succeeds runs after every preview rule, and nothing is reported', async () => {
		const run = await runFirewall('echo \'{"changed": []}\'');
		expect(run.code).toBe(0);
		expect(run.stderr).toBe('');
		expect(inserted(run.calls)).toEqual(previewRules);
		expect(run.calls.at(-1)).toBe('helper provision');
	});

	test('the provision call cannot end the script, however the helper fails', async () => {
		const failures = [
			['refused', 'echo "koi-verify-net: refused: no pool" >&2\nexit 2', 'exit 2'],
			['failed', 'echo "koi-verify-net: iptables exited 4" >&2\nexit 1', 'exit 1'],
			['killed', 'kill -9 $$', 'exit 137'],
		] as const;
		for (const [name, helper, exit] of failures) {
			const run = await runFirewall(helper);
			expect([name, run.code]).toEqual([name, 0]);
			expect(inserted(run.calls)).toEqual(previewRules);
			expect(run.calls.at(-1)).toBe('helper provision');
			expect(run.stderr).toContain(`koi: ${run.path} provision (${exit}) failed.`);
			expect(run.stderr).toContain('Previews are not affected');
		}
	});

	test('br_netfilter and its sysctls cannot end the script either, and the helper still runs', async () => {
		const run = await runFirewall(
			'exit 0',
			[
				'modprobe() { echo "modprobe $*" >> "$calls"; return 1; }',
				'sysctl() { echo "sysctl $*" >> "$calls"; return 255; }',
			].join('\n'),
		);
		expect(run.code).toBe(0);
		expect(inserted(run.calls)).toEqual(previewRules);
		expect(run.calls.at(-1)).toBe('helper provision');
		expect(run.stderr).toContain('koi: modprobe br_netfilter failed.');
		expect(run.stderr).toContain('koi: setting the bridge sysctls failed.');
	});

	test('a box before its first deploy says the helper is not installed, and passes', async () => {
		const run = await runFirewall(undefined);
		expect(run.code).toBe(0);
		expect(inserted(run.calls)).toEqual(previewRules);
		expect(run.stdout).toContain('is not installed yet');
	});

	test('a preview rule that cannot be installed still fails the script', async () => {
		// The mandatory half stays mandatory: koid must not run without it.
		const run = await runFirewall(
			'exit 0',
			'iptables() { echo "iptables $*" >> "$calls"; return 4; }',
		);
		expect(run.code).not.toBe(0);
		expect(run.calls).not.toContain('helper provision');
	});
});

// Provisioning's own shell functions, run in bash against a directory of
// this test's, with systemctl and docker replaced by functions that log
// their calls (and answer from `stubs`).
describe('provisioning steps, run in bash', () => {
	const script = readFileSync(resolve(import.meta.dir, '../../../host/cloud-init.sh'), 'utf8');
	const fn = (name: string) => {
		const body = new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?\\n\\}$`, 'm').exec(script)?.[0];
		if (body === undefined) throw new Error(`cloud-init.sh defines no ${name}`);
		return body;
	};

	async function provision(dir: string, steps: string, stubs = '') {
		const file = join(dir, 'run.sh');
		await writeFile(
			file,
			[
				'set -euo pipefail',
				`DOCKER_ETC=${dir}/docker`,
				'DOCKER_RESTART_PENDING=$DOCKER_ETC/koi-restart-pending',
				'BUILDER_CONTAINER=buildx_buildkit_koi-builder0',
				`calls=${dir}/calls`,
				': > "$calls"',
				'systemctl() { echo "systemctl $*" >> "$calls"; }',
				stubs,
				fn('configure_docker'),
				fn('restart_docker_if_pending'),
				fn('container_slice'),
				fn('move_builder_into_slice'),
				steps,
			].join('\n'),
		);
		const r = await exec(['bash', file], { timeoutMs: 30_000 });
		const calls = (await readFile(join(dir, 'calls'), 'utf8')).split('\n').filter((l) => l !== '');
		return { code: r.code, stdout: r.stdout, stderr: r.stderr, calls };
	}

	const daemonJson = async (dir: string) =>
		JSON.parse(await readFile(join(dir, 'docker', 'daemon.json'), 'utf8')) as unknown;
	const pending = (dir: string) =>
		stat(join(dir, 'docker', 'koi-restart-pending')).then(
			() => true,
			() => false,
		);

	test('a run that fails after changing daemon.json still restarts Docker on the next run', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-provision-'));
		// The first run writes daemon.json, then fails (a download, say)
		// before it restarts Docker.
		const first = await provision(dir, 'configure_docker\nexit 1');
		expect(first.code).toBe(1);
		expect(first.calls).toEqual([]);
		expect(await daemonJson(dir)).toEqual({ 'cgroup-parent': 'koi.slice' });
		expect(await pending(dir)).toBe(true);
		const second = await provision(dir, 'configure_docker\nrestart_docker_if_pending');
		expect(second.code).toBe(0);
		expect(second.calls).toEqual(['systemctl restart docker.service']);
		expect(await pending(dir)).toBe(false);
		const third = await provision(dir, 'configure_docker\nrestart_docker_if_pending');
		expect(third.calls).toEqual([]);
	});

	test('keeps the rest of an existing daemon.json, and keeps the restart pending when it fails', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-provision-'));
		await mkdir(join(dir, 'docker'));
		await writeFile(join(dir, 'docker', 'daemon.json'), '{"log-driver": "local"}\n');
		const failing = await provision(
			dir,
			'configure_docker\nrestart_docker_if_pending',
			'systemctl() { echo "systemctl $*" >> "$calls"; return 1; }',
		);
		expect(failing.code).not.toBe(0);
		expect(await daemonJson(dir)).toEqual({ 'cgroup-parent': 'koi.slice', 'log-driver': 'local' });
		expect(await pending(dir)).toBe(true);
		const again = await provision(dir, 'configure_docker\nrestart_docker_if_pending');
		expect(again.calls).toEqual(['systemctl restart docker.service']);
		expect(await pending(dir)).toBe(false);
	});

	// Docker and systemd for move_builder_into_slice: one file per container in
	// $state, holding "<running> <slice> <builder|preview>". A container
	// that starts goes to $starts_in.
	const containers = `
state=$(dirname "$calls")/state
docker() {
	echo "docker $*" >> "$calls"
	case "$1 $2" in
	'container inspect')
		[ -f "$state/$5" ] || return 1
		case "$4" in
		'{{.Id}}') echo "id-$5" ;;
		'{{.State.Running}}') cut -d' ' -f1 "$state/$5" ;;
		esac ;;
	'restart '*) echo "true $starts_in $(cut -d' ' -f3 "$state/$2")" > "$state/$2" ;;
	'stop '*) echo "false $(cut -d' ' -f2,3 "$state/$2")" > "$state/$2" ;;
	esac
}
systemctl() {
	echo "systemctl $*" >> "$calls"
	if [ "$1" = show ]; then
		local name=\${4#docker-id-}
		cut -d' ' -f2 "$state/\${name%.scope}"
	fi
}`;

	async function boxWith(entries: Record<string, string>) {
		const dir = await mkdtemp(join(tmpdir(), 'koi-provision-'));
		await mkdir(join(dir, 'state'));
		for (const [name, line] of Object.entries(entries)) {
			await writeFile(join(dir, 'state', name), `${line}\n`);
		}
		return dir;
	}
	const stateOf = (dir: string, name: string) =>
		readFile(join(dir, 'state', name), 'utf8').then((t) => t.trim());

	test('moves a builder that kept running through the restart into the slice, and leaves previews to koid', async () => {
		// As live-restore leaves them: Docker restarted with the new default,
		// and the containers running where they were.
		const dir = await boxWith({
			'buildx_buildkit_koi-builder0': 'true system.slice builder',
			'koi-a': 'true system.slice preview',
		});
		const run = await provision(dir, 'starts_in=koi.slice\nmove_builder_into_slice', containers);
		expect(run.stderr).toBe('');
		expect(run.code).toBe(0);
		const changes = run.calls.filter((c) => /^docker (restart|stop)/.test(c));
		expect(changes).toEqual(['docker restart buildx_buildkit_koi-builder0']);
		expect(await stateOf(dir, 'buildx_buildkit_koi-builder0')).toBe('true koi.slice builder');
		// koid takes a preview out of Caddy's routes before it stops one.
		expect(await stateOf(dir, 'koi-a')).toBe('true system.slice preview');
		expect(run.stdout).toContain(
			'restarting buildx_buildkit_koi-builder0, which runs in system.slice',
		);
	});

	test('changes nothing when the builder is in the slice, or not running', async () => {
		for (const builder of ['true koi.slice builder', 'false system.slice builder']) {
			const dir = await boxWith({ 'buildx_buildkit_koi-builder0': builder });
			const run = await provision(dir, 'starts_in=koi.slice\nmove_builder_into_slice', containers);
			expect(run.code).toBe(0);
			expect(run.calls.filter((c) => /^docker (restart|stop)/.test(c))).toEqual([]);
		}
	});

	test('stops provisioning when Docker still starts the builder outside the slice', async () => {
		const dir = await boxWith({ 'buildx_buildkit_koi-builder0': 'true system.slice builder' });
		const run = await provision(dir, 'starts_in=system.slice\nmove_builder_into_slice', containers);
		expect(run.code).not.toBe(0);
		expect(run.stderr).toContain(
			'koi: buildx_buildkit_koi-builder0 runs in system.slice, not koi.slice; check cgroup-parent',
		);
	});

	test('provisioning moves the builder into the slice after Docker and the builder are set up', () => {
		const at = (text: string) => script.lastIndexOf(text);
		expect(at('\nmove_builder_into_slice\n')).toBeGreaterThan(at('\nrestart_docker_if_pending\n'));
		expect(at('\nmove_builder_into_slice\n')).toBeGreaterThan(at('as_koi docker buildx create'));
	});
});
