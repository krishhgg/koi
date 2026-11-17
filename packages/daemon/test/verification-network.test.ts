import { describe, expect, spyOn, test } from 'bun:test';
import * as fsp from 'node:fs/promises';
import { mkdir, mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	INPUT_VOLUME_PARTS,
	INPUT_VOLUME_ROLE,
	inputVolumeName,
	type RunNetworkDescriptor,
	stagingName,
	type VerifyAttestation,
} from '@koi/shared';
import type { ExecResult } from '../src/exec.ts';
import { verificationCapability } from '../src/host.ts';
import {
	addressesOf,
	allocateSubnet,
	attestationProblems,
	bridgeName,
	helperMac,
	helperName,
	helperOf,
	parseAttestation,
	privateHost,
	runNetworkName,
	runNetworkOf,
	runNetworkProblems,
	subnetsOf,
	sudoHelper,
	VerificationNetwork,
	type VerifyNetHelper,
} from '../src/verification-network.ts';
import { eventually, FakeDocker, Gate } from './fakes.ts';

const RUN = 'abcdefghijklmnop0123';
const OTHER = 'z'.repeat(16);
const APP = 'koi-hello-pr-7-aaaaaaaaaaaaaaaa1';

function attestation(changes: Partial<VerifyAttestation> = {}): VerifyAttestation {
	return {
		policy: 2,
		pool: '10.213.0.0/26',
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
		...changes,
	};
}

// The root-owned helper in memory: it remembers what was applied, and
// attests what the test says plus the runs it holds.
class FakeHelper implements VerifyNetHelper {
	applied: RunNetworkDescriptor[] = [];
	revoked: string[] = [];
	runs = new Set<string>();
	applyError: string | undefined;
	// Every revoke fails with revokeError; a revoke of a run in revokeErrors
	// fails with that run's message, and the others pass.
	revokeError: string | undefined;
	revokeErrors = new Map<string, string>();
	attestError: string | undefined;
	attestation = attestation();

	constructor(private readonly events: string[]) {}

	async apply(descriptor: RunNetworkDescriptor) {
		if (this.applyError !== undefined) throw new Error(this.applyError);
		this.applied.push(descriptor);
		this.runs.add(descriptor.runId);
		this.events.push(`apply ${descriptor.runId}`);
	}
	async revoke(runId: string) {
		const refused = this.revokeError ?? this.revokeErrors.get(runId);
		if (refused !== undefined) throw new Error(refused);
		this.revoked.push(runId);
		this.runs.delete(runId);
		this.events.push(`revoke ${runId}`);
	}
	async attest() {
		if (this.attestError !== undefined) throw new Error(this.attestError);
		return { ...this.attestation, runs: [...this.runs] };
	}
}

async function setup(options: { pool?: string; links?: Set<string> } = {}) {
	const root = await mkdtemp(join(tmpdir(), 'koid-verify-'));
	const docker = new FakeDocker();
	const helper = new FakeHelper(docker.events);
	const logs: string[] = [];
	// The serving app, as a deploy leaves it: running on the preview network.
	await docker.run({
		name: APP,
		image: 'koi-preview/hello-pr-7:aaaaaaaaaaaaaaaa1',
		network: 'koi-previews',
		user: '65534:65534',
		env: { KOI_PREVIEW_URL: 'https://hello-pr-7.previews.example.net' },
		labels: { 'koi.preview': 'hello-pr-7', 'koi.request': 'aaaaaaaaaaaaaaaa1' },
	});
	docker.events.length = 0;
	const deps = {
		docker,
		helper,
		pool: options.pool ?? '10.213.0.0/26',
		previewNetwork: 'koi-previews',
		stateDir: root,
		slice: 'koi.slice',
		linkExists: async (name: string) => options.links?.has(name) ?? false,
		now: () => new Date('2026-10-06T12:00:00.000Z'),
		log: (m: string) => logs.push(m),
	};
	helper.attestation = attestation({ pool: deps.pool });
	const networks = new VerificationNetwork(deps);
	const request = (runId = RUN) => ({
		runId,
		appContainer: APP,
		appPort: 8080,
		recorderImage: `koi-recorder@sha256:${'1'.repeat(64)}`,
		verifierImage: `curlimages/curl@sha256:${'2'.repeat(64)}`,
	});
	return {
		root,
		docker,
		helper,
		logs,
		deps,
		networks,
		request,
		// A new koid on the same state and Docker, as after a restart.
		restart: () => new VerificationNetwork(deps),
		records: () => readdir(join(root, 'verification', 'networks')).catch(() => [] as string[]),
	};
}

describe('addresses', () => {
	test('a /28 per run, lowest first, skipping what is taken', () => {
		expect(subnetsOf('10.213.0.0/26')).toEqual([
			'10.213.0.0/28',
			'10.213.0.16/28',
			'10.213.0.32/28',
			'10.213.0.48/28',
		]);
		expect(subnetsOf('10.213.0.0/20')).toHaveLength(256);
		expect(allocateSubnet('10.213.0.0/26', [])).toBe('10.213.0.0/28');
		expect(allocateSubnet('10.213.0.0/26', ['10.213.0.0/28', '10.213.0.32/28'])).toBe(
			'10.213.0.16/28',
		);
		// A larger network over part of the pool takes every /28 under it.
		expect(allocateSubnet('10.213.0.0/26', ['10.213.0.0/27', '172.18.0.0/16'])).toBe(
			'10.213.0.32/28',
		);
		expect(allocateSubnet('10.213.0.0/26', ['10.213.0.0/26'])).toBeUndefined();
		expect(allocateSubnet('10.213.0.0/28', [])).toBe('10.213.0.0/28');
	});

	test('fixed host numbers: gateway .1, app .2, recorder .3, verifier .4', () => {
		expect(addressesOf('10.213.0.16/28')).toEqual({
			gateway: '10.213.0.17',
			app: '10.213.0.18',
			recorder: '10.213.0.19',
			verifier: '10.213.0.20',
		});
		expect(addressesOf('10.213.0.240/28').verifier).toBe('10.213.0.244');
	});

	test("helper MACs are local unicast with the address in them, apart from Docker's own", () => {
		expect(helperMac('10.213.0.19')).toBe('02:4b:0a:d5:00:13');
		expect(helperMac('10.213.0.19')).not.toBe('02:42:0a:d5:00:13');
	});

	test('names: the network, the helpers, the bridge and the private host', () => {
		expect(runNetworkName(RUN)).toBe(`koi-v-${RUN}`);
		expect(helperName(RUN, 'recorder')).toBe(`koi-verify-${RUN}-recorder`);
		expect(privateHost(RUN)).toBe(`app.${RUN}.invalid`);
		expect(bridgeName(RUN)).toMatch(/^kv[0-9a-f]{12}$/);
		expect(bridgeName(RUN, 1)).not.toBe(bridgeName(RUN, 0));
		expect(bridgeName(RUN)).toBe(bridgeName(RUN));
	});

	test('a helper is a container koid named as one whose labels say the same, and no preview', () => {
		const labels = { 'koi.role': 'recorder', 'koi.run': RUN };
		expect(helperOf({ name: helperName(RUN, 'recorder'), labels })).toEqual({
			name: helperName(RUN, 'recorder'),
			runId: RUN,
			role: 'recorder',
		});
		// A preview whose image set the labels: the name is koid's, not a helper's.
		expect(helperOf({ name: APP, labels })).toBeUndefined();
		// Named as a helper but labelled as a preview, another run or another role.
		const name = helperName(RUN, 'verifier');
		expect(helperOf({ name, labels: { ...labels, 'koi.preview': 'x' } })).toBeUndefined();
		// koi.preview set to nothing, as koid creates every helper so that
		// its image's value does not reach it, is no preview.
		expect(
			helperOf({ name: helperName(RUN, 'recorder'), labels: { ...labels, 'koi.preview': '' } }),
		).toEqual({ name: helperName(RUN, 'recorder'), runId: RUN, role: 'recorder' });
		expect(helperOf({ name, labels })).toBeUndefined();
		expect(
			helperOf({ name, labels: { 'koi.role': 'verifier', 'koi.run': OTHER } }),
		).toBeUndefined();
		expect(helperOf({ name, labels: { 'koi.role': 'verifier' } })).toBeUndefined();
		// Named like a helper with only a preview's label: no preview to the
		// reconciler (docker.ts, isPreview) and no helper here.
		expect(helperOf({ name, labels: { 'koi.preview': 'x' } })).toBeUndefined();
		expect(helperOf({ name: `koi-verify-${RUN}-app`, labels })).toBeUndefined();
		// A label with a line break or a tab is a value, never another row.
		expect(
			helperOf({ name, labels: { 'koi.role': 'verifier', 'koi.run': `${RUN}\n${OTHER}\t` } }),
		).toBeUndefined();
	});

	test('a run network is one koid named as such and labelled with the same run', () => {
		const network = {
			id: 'n',
			name: runNetworkName(RUN),
			driver: 'bridge',
			internal: true,
			ipv6: false,
			icc: true,
			subnets: ['10.213.0.0/28'],
			run: RUN,
			containers: [],
		};
		expect(runNetworkOf(network)).toBe(RUN);
		expect(runNetworkOf({ ...network, run: OTHER })).toBeUndefined();
		expect(runNetworkOf({ ...network, name: 'koi-previews' })).toBeUndefined();
		const { run: _r, ...unlabelled } = network;
		expect(runNetworkOf(unlabelled)).toBeUndefined();
		expect(runNetworkOf({ ...network, name: 'koi-v-Not A Run', run: 'Not A Run' })).toBeUndefined();
	});
});

describe('runNetworkProblems', () => {
	const record = {
		network: `koi-v-${RUN}`,
		bridge: 'kv0123456789ab',
		subnet: '10.213.0.16/28',
		runId: RUN,
	};
	const good = {
		id: 'n',
		name: `koi-v-${RUN}`,
		driver: 'bridge',
		internal: true,
		ipv6: false,
		icc: true,
		bridge: 'kv0123456789ab',
		subnets: ['10.213.0.16/28'],
		run: RUN,
		containers: [],
	};

	test('accepts the network as koid creates it', () => {
		expect(runNetworkProblems(good, record)).toEqual([]);
	});

	test('names every difference', () => {
		expect(
			runNetworkProblems(
				{
					...good,
					internal: false,
					ipv6: true,
					icc: false,
					subnets: ['10.213.0.16/28', 'fd00::/64'],
				},
				record,
			),
		).toEqual([
			`network koi-v-${RUN} is not internal`,
			`network koi-v-${RUN} has IPv6 enabled`,
			`network koi-v-${RUN} lets its containers reach each other (enable_icc is not false)`,
			`network koi-v-${RUN} has subnets 10.213.0.16/28 fd00::/64, not 10.213.0.16/28`,
		]);
		const { bridge: _b, run: _r, ...bare } = good;
		expect(runNetworkProblems(bare, record)).toEqual([
			`network koi-v-${RUN} has bridge (automatic), not kv0123456789ab`,
			`network koi-v-${RUN} is not labelled koi.run=${RUN}`,
		]);
		expect(runNetworkProblems(undefined, record)).toEqual([`network koi-v-${RUN} does not exist`]);
	});
});

describe('attestation', () => {
	test('a provisioned host has no problems', () => {
		expect(attestationProblems(attestation(), '10.213.0.0/26')).toEqual([]);
	});

	test('names the policy, the pool, the chains, IPv6 and the sysctls', () => {
		expect(
			attestationProblems(
				attestation({
					policy: 1,
					pool: '10.0.0.0/20',
					ipv4: {
						chains: true,
						jump: false,
						defaults: true,
						permits: true,
						problems: ['chain DOCKER-USER has no rule -j KOI-VERIFY'],
					},
					ipv6: { defaults: false, problems: ['ip6tables OUTPUT has no rule -o kv+ -j DROP'] },
					sysctl: {
						br_netfilter: true,
						bridge_nf_call_iptables: false,
						bridge_nf_call_ip6tables: true,
						bridge_nf_filter_vlan_tagged: true,
					},
				}),
				'10.213.0.0/26',
			),
		).toEqual([
			'the helper installs policy version 1, and koid expects 2',
			"the helper's pool is 10.0.0.0/20 and KOI_VERIFY_POOL is 10.213.0.0/26; both come from /etc/koi/verify/env",
			'chain DOCKER-USER has no rule -j KOI-VERIFY',
			'ip6tables OUTPUT has no rule -o kv+ -j DROP',
			'net.bridge.bridge-nf-call-iptables is not 1',
		]);
		expect(
			attestationProblems(
				attestation({
					pool: null,
					sysctl: {
						br_netfilter: false,
						bridge_nf_call_iptables: false,
						bridge_nf_call_ip6tables: false,
					},
				}),
				'10.213.0.0/26',
			),
		).toEqual([
			"the helper's pool is not set and KOI_VERIFY_POOL is 10.213.0.0/26; both come from /etc/koi/verify/env",
			'br_netfilter is not loaded',
		]);
	});

	test('names the layer 2 allowlist, the MAC pins and the VLAN sysctl, and an older helper that says nothing of them', () => {
		expect(
			attestationProblems(
				attestation({
					bridge: {
						guard: true,
						pins: false,
						problems: [`run ${RUN}: 02:4b:0a:d5:00:03 is not pinned to veth1 on kv0123456789ab`],
					},
					sysctl: {
						br_netfilter: true,
						bridge_nf_call_iptables: true,
						bridge_nf_call_ip6tables: true,
						bridge_nf_filter_vlan_tagged: false,
					},
				}),
				'10.213.0.0/26',
			),
		).toEqual([
			`run ${RUN}: 02:4b:0a:d5:00:03 is not pinned to veth1 on kv0123456789ab`,
			'net.bridge.bridge-nf-filter-vlan-tagged is not 1',
		]);
		const older = parseAttestation(
			JSON.stringify({
				...attestation({ policy: 1 }),
				bridge: undefined,
				sysctl: {
					br_netfilter: true,
					bridge_nf_call_iptables: true,
					bridge_nf_call_ip6tables: true,
				},
			}),
		);
		expect(attestationProblems(older, '10.213.0.0/26')).toEqual([
			'the helper installs policy version 1, and koid expects 2',
			'the helper does not report the layer 2 allowlist and the MAC pins',
			'net.bridge.bridge-nf-filter-vlan-tagged is not 1',
		]);
	});

	test('an unknown rule above the defaults is a problem on its own', () => {
		expect(
			attestationProblems(
				attestation({
					ipv4: {
						chains: true,
						jump: true,
						defaults: true,
						permits: false,
						problems: [
							'chain KOI-VERIFY has a rule that is not a run permit above its defaults: -i kv+ -j ACCEPT',
						],
					},
				}),
				'10.213.0.0/26',
			),
		).toEqual([
			'chain KOI-VERIFY has a rule that is not a run permit above its defaults: -i kv+ -j ACCEPT',
		]);
	});

	test("parseAttestation refuses what is not the helper's output", () => {
		expect(parseAttestation(JSON.stringify(attestation()))).toEqual(attestation());
		expect(() => parseAttestation('not json')).toThrow('something other than JSON');
		expect(() => parseAttestation('{"policy":"1"}')).toThrow(/cannot read: policy: /);
	});
});

describe('sudoHelper', () => {
	function recorded(answer: Partial<ExecResult> = {}) {
		const calls: Array<{ cmd: string[]; stdin?: string | Uint8Array }> = [];
		const helper = sudoHelper('/usr/local/libexec/koi-verify-net', async (cmd, options) => {
			calls.push({ cmd, ...(options?.stdin !== undefined ? { stdin: options.stdin } : {}) });
			return { code: 0, stdout: '', stderr: '', timedOut: false, ...answer };
		});
		return { calls, helper };
	}
	const descriptor: RunNetworkDescriptor = {
		version: 1,
		runId: RUN,
		bridge: 'kv0123456789ab',
		subnet: '10.213.0.16/28',
		appPort: 8080,
		endpoints: [
			{ role: 'app', container: APP, ip: '10.213.0.18', mac: '02:42:0a:d5:00:12' },
			{ role: 'recorder', container: 'r', ip: '10.213.0.19', mac: '02:4b:0a:d5:00:13' },
			{ role: 'verifier', container: 'v', ip: '10.213.0.20', mac: '02:4b:0a:d5:00:14' },
		],
	};

	test('runs the helper through sudo -n with the descriptor on stdin', async () => {
		const { calls, helper } = recorded({ stdout: '{"runId":"x","rules":9}\n' });
		await helper.apply(descriptor);
		expect(calls).toEqual([
			{
				cmd: ['sudo', '-n', '/usr/local/libexec/koi-verify-net', 'apply'],
				stdin: `${JSON.stringify(descriptor)}\n`,
			},
		]);
		await helper.revoke(RUN);
		expect(calls[1]).toEqual({
			cmd: ['sudo', '-n', '/usr/local/libexec/koi-verify-net', 'revoke', RUN],
		});
		await expect(helper.revoke('../etc')).rejects.toThrow();
		expect(calls).toHaveLength(2);
	});

	test("reads the attestation, and fails with the helper's message", async () => {
		const { helper } = recorded({ stdout: `${JSON.stringify(attestation())}\n` });
		expect(await helper.attest()).toEqual(attestation());
		const refused = recorded({
			code: 2,
			stderr: 'koi-verify-net: refused: subnet 10.0.0.0/28 is outside the reserved pool',
		});
		await expect(refused.helper.apply(descriptor)).rejects.toThrow(
			'sudo -n exited 2: koi-verify-net: refused: subnet 10.0.0.0/28 is outside the reserved pool',
		);
		const noSudo = recorded({ code: 1, stderr: 'sudo: a password is required' });
		await expect(noSudo.helper.attest()).rejects.toThrow('a password is required');
	});
});

describe('create', () => {
	test('makes the network around the app, creates both helpers stopped, applies the permits and records it', async () => {
		const t = await setup();
		const record = await t.networks.create(t.request());
		const bridge = bridgeName(RUN);
		expect(record).toEqual({
			version: 1,
			runId: RUN,
			network: `koi-v-${RUN}`,
			bridge,
			subnet: '10.213.0.0/28',
			gateway: '10.213.0.1',
			appContainer: APP,
			appPort: 8080,
			state: 'ready',
			endpoints: [
				{ role: 'app', container: APP, ip: '10.213.0.2', mac: '02:42:0a:d5:00:02' },
				{
					role: 'recorder',
					container: `koi-verify-${RUN}-recorder`,
					ip: '10.213.0.3',
					mac: '02:4b:0a:d5:00:03',
				},
				{
					role: 'verifier',
					container: `koi-verify-${RUN}-verifier`,
					ip: '10.213.0.4',
					mac: '02:4b:0a:d5:00:04',
				},
			],
			createdAt: '2026-10-06T12:00:00.000Z',
		});
		// In order: the network, the app's second interface, the helpers, the permits.
		expect(t.docker.events).toEqual([
			`created network koi-v-${RUN}`,
			`connected ${APP} to koi-v-${RUN} at 10.213.0.2`,
			`created recorder koi-verify-${RUN}-recorder`,
			`created verifier koi-verify-${RUN}-verifier`,
			`apply ${RUN}`,
		]);
		const network = t.docker.networksMade.get(`koi-v-${RUN}`);
		expect(network?.options).toEqual({
			name: `koi-v-${RUN}`,
			bridge,
			subnet: '10.213.0.0/28',
			gateway: '10.213.0.1',
			labels: { 'koi.run': RUN },
		});
		// Neither helper started, and neither is a preview: koi.preview is
		// set to nothing, over whatever the image carries.
		for (const role of ['recorder', 'verifier'] as const) {
			const c = t.docker.containers.get(`koi-verify-${RUN}-${role}`);
			expect(c?.running).toBe(false);
			expect(c?.labels).toEqual({ 'koi.preview': '', 'koi.role': role, 'koi.run': RUN });
		}
		expect(await t.docker.list()).toEqual([{ name: APP, label: 'hello-pr-7' }]);
		// The app keeps its preview address.
		expect((await t.docker.inspect(APP)).ip).toBe('172.19.0.2');
		expect(await t.networks.list()).toEqual([record]);
		// On disk for koid alone.
		const dir = join(t.root, 'verification', 'networks');
		expect((await stat(dir)).mode & 0o777).toBe(0o700);
		expect((await stat(join(dir, `${RUN}.json`))).mode & 0o777).toBe(0o600);
		expect(JSON.parse(await readFile(join(dir, `${RUN}.json`), 'utf8'))).toEqual(record);
	});

	test('gives each helper its fixed address and MAC, the private host, the gateway as resolver and only its own environment', async () => {
		const t = await setup();
		await t.networks.create({
			...t.request(),
			verifierCommand: ['sh', '.koi/runners/home.sh'],
			seccompProfile: '/etc/koi/verify/chromium.json',
		});
		expect(t.docker.helpers.map((h) => h.role)).toEqual(['recorder', 'verifier']);
		const [recorder, verifier] = t.docker.helpers;
		expect(recorder?.options).toEqual({
			name: `koi-verify-${RUN}-recorder`,
			image: `koi-recorder@sha256:${'1'.repeat(64)}`,
			network: `koi-v-${RUN}`,
			ip: '10.213.0.3',
			mac: '02:4b:0a:d5:00:03',
			runId: RUN,
			appHost: { name: `app.${RUN}.invalid`, ip: '10.213.0.2' },
			dns: '10.213.0.1',
			env: { KOI_RUN_ID: RUN, KOI_PREVIEW_URL: `http://app.${RUN}.invalid:8080` },
			seccompProfile: '/etc/koi/verify/chromium.json',
		});
		expect(verifier?.options).toEqual({
			name: `koi-verify-${RUN}-verifier`,
			image: `curlimages/curl@sha256:${'2'.repeat(64)}`,
			network: `koi-v-${RUN}`,
			ip: '10.213.0.4',
			mac: '02:4b:0a:d5:00:04',
			runId: RUN,
			appHost: { name: `app.${RUN}.invalid`, ip: '10.213.0.2' },
			dns: '10.213.0.1',
			env: { KOI_RUN_ID: RUN, KOI_PREVIEW_URL: `http://app.${RUN}.invalid:8080` },
			command: ['sh', '.koi/runners/home.sh'],
		});
	});

	test('sends the helper exactly the three endpoints as Docker reports them, then checks the attestation', async () => {
		const t = await setup();
		const record = await t.networks.create(t.request());
		expect(t.helper.applied).toEqual([
			{
				version: 1,
				runId: RUN,
				bridge: record.bridge,
				subnet: '10.213.0.0/28',
				appPort: 8080,
				endpoints: record.endpoints,
			},
		]);
		// A helper whose MAC Docker only fills in at start is recorded with the one asked for.
		const u = await setup();
		u.docker.reportHelperMac = false;
		const made = await u.networks.create(u.request());
		expect(made.endpoints.map((e) => e.mac)).toEqual([
			'02:42:0a:d5:00:02',
			'02:4b:0a:d5:00:03',
			'02:4b:0a:d5:00:04',
		]);
	});

	test('refuses a second network for a run, and a run id that is not one', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		await expect(t.networks.create(t.request())).rejects.toThrow(
			`run ${RUN} already has a network`,
		);
		await expect(t.networks.create(t.request('not a run id'))).rejects.toThrow();
		expect(await t.records()).toEqual([`${RUN}.json`]);
	});

	test('refuses when the app is not running on the preview network, before anything is made', async () => {
		const t = await setup();
		t.docker.kill(APP);
		await expect(t.networks.create(t.request())).rejects.toThrow(
			`${APP} is not running on koi-previews`,
		);
		expect(t.docker.networksMade.size).toBe(0);
		expect(t.helper.applied).toEqual([]);
		expect(await t.records()).toEqual([]);
	});

	test('skips a bridge name another network or a host interface already uses', async () => {
		const t = await setup({ links: new Set([bridgeName(RUN, 1)]) });
		t.docker.otherNetworks.push({
			id: 'x',
			name: 'something',
			driver: 'bridge',
			internal: false,
			ipv6: false,
			icc: false,
			bridge: bridgeName(RUN, 0),
			subnets: ['172.20.0.0/16'],
			containers: [],
		});
		const record = await t.networks.create(t.request());
		expect(record.bridge).toBe(bridgeName(RUN, 2));
	});

	test('allocates around subnets other networks on the box already use', async () => {
		const t = await setup();
		t.docker.otherNetworks.push({
			id: 'x',
			name: 'stray',
			driver: 'bridge',
			internal: false,
			ipv6: false,
			icc: false,
			subnets: ['10.213.0.0/27'],
			containers: [],
		});
		expect((await t.networks.create(t.request())).subnet).toBe('10.213.0.32/28');
	});

	test('fails when the pool is full, holding nothing', async () => {
		const t = await setup({ pool: '10.213.0.0/27' });
		await t.networks.create(t.request('a'.repeat(16)));
		await t.networks.create(t.request('b'.repeat(16)));
		await expect(t.networks.create(t.request('c'.repeat(16)))).rejects.toThrow(
			'the verification pool 10.213.0.0/27 has no free /28: 2 run networks hold one each',
		);
		expect((await t.records()).sort()).toEqual([
			`${'a'.repeat(16)}.json`,
			`${'b'.repeat(16)}.json`,
		]);
	});
});

describe('failures while making a network', () => {
	// What every failure must leave: no network, no helpers, the app on the
	// preview network alone, the permits revoked, and the subnet free.
	async function expectClean(t: Awaited<ReturnType<typeof setup>>) {
		expect(t.docker.networksMade.size).toBe(0);
		expect([...t.docker.containers.keys()]).toEqual([APP]);
		expect(t.docker.containers.get(APP)?.attachments.size).toBe(0);
		expect((await t.docker.inspect(APP)).ip).toBe('172.19.0.2');
		expect(t.helper.revoked).toEqual([RUN]);
		expect(await t.records()).toEqual([]);
	}

	test('a helper with a mount koi did not ask for is refused', async () => {
		const t = await setup();
		t.docker.helperMounts = [{ type: 'volume', destination: '/data' }];
		await expect(t.networks.create(t.request())).rejects.toThrow(
			`koi-verify-${RUN}-recorder has mounts koi did not ask for: volume at /data`,
		);
		expect(t.helper.applied).toEqual([]);
		await expectClean(t);
	});

	test('a network Docker made differently is refused', async () => {
		const t = await setup();
		const create = t.docker.createNetwork.bind(t.docker);
		t.docker.createNetwork = async (o) => {
			await create(o);
			const made = t.docker.networksMade.get(o.name);
			if (made !== undefined) made.info.ipv6 = true;
		};
		await expect(t.networks.create(t.request())).rejects.toThrow(
			`network koi-v-${RUN} has IPv6 enabled`,
		);
		await expectClean(t);
	});

	test('an app whose preview address changed under it is refused', async () => {
		const t = await setup();
		t.docker.onInspect = async () => {
			const app = t.docker.containers.get(APP);
			if (app?.attachments.size) app.ip = '172.19.0.9';
		};
		await expect(t.networks.create(t.request())).rejects.toThrow(
			`${APP} is at 172.19.0.9 on koi-previews, where it was at 172.19.0.2`,
		);
		expect(t.docker.networksMade.size).toBe(0);
		expect(await t.records()).toEqual([]);
	});

	test('a helper refusal, or a host that attests badly after apply, takes everything down', async () => {
		const t = await setup();
		t.helper.applyError =
			'sudo -n exited 2: koi-verify-net: refused: subnet 10.213.0.0/28 overlaps the host route 10.213.0.0/24';
		await expect(t.networks.create(t.request())).rejects.toThrow('overlaps the host route');
		await expectClean(t);
		const u = await setup();
		u.helper.attestation = attestation({
			ipv4: {
				chains: true,
				jump: true,
				defaults: false,
				permits: true,
				problems: ['chain KOI-VERIFY does not end with its default denies'],
			},
		});
		await expect(u.networks.create(u.request())).rejects.toThrow(
			'after apply, chain KOI-VERIFY does not end with its default denies',
		);
		await expectClean(u);
	});

	test('a failure to create the network frees the record', async () => {
		const t = await setup();
		t.docker.createNetworkError =
			'Error response from daemon: Pool overlaps with other one on this address space';
		await expect(t.networks.create(t.request())).rejects.toThrow('Pool overlaps');
		await expectClean(t);
		// The next attempt gets the same subnet.
		expect((await t.networks.create(t.request())).subnet).toBe('10.213.0.0/28');
	});

	test("a change whose signal fired while it waited for the lock is not made, and a Docker call gets the run's signal", async () => {
		const t = await setup();
		// The first creation holds the lock at its first Docker call.
		const gate = new Gate();
		let held = false;
		t.docker.onInspect = async () => {
			if (held) return;
			held = true;
			await gate.pass();
		};
		const budget = new AbortController();
		const first = t.networks.create(t.request(), { signal: budget.signal });
		await gate.reached;
		// The second waits for the lock; its run stops waiting before the
		// lock is free, as a run at its deadline does.
		const abandoned = new AbortController();
		const second = t.networks.create(t.request(OTHER), { signal: abandoned.signal });
		abandoned.abort(new Error('the budget ended'));
		gate.release();
		await first;
		await expect(second).rejects.toThrow('the budget ended');
		expect(await t.records()).toEqual([`${RUN}.json`]);
		expect([...t.docker.networksMade.keys()]).toEqual([runNetworkName(RUN)]);
		// Each docker command of the first creation was given the signal.
		expect(t.docker.networkSignals).toEqual([budget.signal]);
	});

	test('when the teardown after a failure fails too, the record stays and says so', async () => {
		const t = await setup();
		t.docker.helperMounts = [{ type: 'volume', destination: '/data' }];
		t.helper.revokeError = 'sudo -n exited 1: xtables lock';
		await expect(t.networks.create(t.request())).rejects.toThrow('mounts koi did not ask for');
		expect(await t.records()).toEqual([`${RUN}.json`]);
		expect((await t.networks.list())[0]?.state).toBe('destroying');
		expect(t.logs.join('\n')).toContain(
			`taking down the run network of ${RUN} after a failure: revoking its permits: sudo -n exited 1: xtables lock; kept for the next start`,
		);
	});
});

describe('destroy', () => {
	test('takes the network down in reverse order, then releases the subnet', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		t.docker.events.length = 0;
		expect(await t.networks.destroy(RUN)).toBe(true);
		expect(t.docker.events).toEqual([
			`revoke ${RUN}`,
			`disconnected ${APP} from koi-v-${RUN}`,
			`removed koi-verify-${RUN}-recorder`,
			`removed koi-verify-${RUN}-verifier`,
			`removed network koi-v-${RUN}`,
		]);
		// The app runs on, where it was.
		expect(await t.docker.inspect(APP)).toEqual({
			exists: true,
			running: true,
			ip: '172.19.0.2',
		});
		expect(await t.records()).toEqual([]);
		expect(await t.networks.destroy(RUN)).toBe(false);
	});

	test('a record the disk does not take holds up no permit or helper, and goes last', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		t.docker.events.length = 0;
		const gate = new Gate();
		const write = fsp.writeFile;
		const held = spyOn(fsp, 'writeFile').mockImplementation(async (...args) => {
			await gate.pass();
			return write(...args);
		});
		try {
			const destroyed = t.networks.destroy(RUN);
			await gate.reached;
			await eventually(() => t.docker.events.includes(`removed network koi-v-${RUN}`));
			expect(t.docker.events[0]).toBe(`revoke ${RUN}`);
			// The write has not ended, so the record stays, and goes once it does.
			expect(await t.records()).toEqual([`${RUN}.json`]);
			gate.release();
			expect(await destroyed).toBe(true);
			expect(await t.records()).toEqual([]);
		} finally {
			held.mockRestore();
		}
	});

	test('a freed subnet is the next allocation; one whose revoke failed is not', async () => {
		const t = await setup();
		await t.networks.create(t.request('a'.repeat(16)));
		await t.networks.create(t.request('b'.repeat(16)));
		await t.networks.destroy('a'.repeat(16));
		expect((await t.networks.create(t.request('c'.repeat(16)))).subnet).toBe('10.213.0.0/28');
		// The helper refuses to revoke run b: its permits may still be in,
		// so its subnet stays held.
		t.helper.revokeError = 'sudo -n exited 1: xtables lock';
		await expect(t.networks.destroy('b'.repeat(16))).rejects.toThrow('xtables lock');
		const b = (await t.networks.list()).find((r) => r.runId === 'b'.repeat(16));
		expect(b?.state).toBe('destroying');
		expect(b?.subnet).toBe('10.213.0.16/28');
		expect((await t.networks.create(t.request('d'.repeat(16)))).subnet).toBe('10.213.0.32/28');
		// Acknowledged later, it is free.
		t.helper.revokeError = undefined;
		expect(await t.networks.destroy('b'.repeat(16))).toBe(true);
		expect((await t.networks.create(t.request('e'.repeat(16)))).subnet).toBe('10.213.0.16/28');
	});

	test('a network that still has an endpoint koid does not know is kept, with its record', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		// Something else joined the run network.
		await t.docker.run({
			name: 'stray',
			image: 'x',
			network: 'koi-previews',
			user: '1',
			env: {},
			labels: { 'koi.preview': 'stray' },
		});
		await t.docker.connect(`koi-v-${RUN}`, 'stray', '10.213.0.9');
		await expect(t.networks.destroy(RUN)).rejects.toThrow(
			`network koi-v-${RUN} has active endpoints: stray`,
		);
		expect(await t.records()).toEqual([`${RUN}.json`]);
		expect(t.helper.revoked).toEqual([RUN]);
	});
});

describe('cleanupOrphans', () => {
	test('at startup, removes every recorded network and whatever carries koi.run without a record', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		// A run that crashed before its record was written: a network and a
		// recorder labelled koi.run, with the app still attached.
		await t.docker.createNetwork({
			name: `koi-v-${OTHER}`,
			bridge: 'kvffffffffffff',
			subnet: '10.213.0.48/28',
			gateway: '10.213.0.49',
			labels: { 'koi.run': OTHER },
		});
		await t.docker.connect(`koi-v-${OTHER}`, APP, '10.213.0.50');
		await t.docker.createRecorder({
			name: `koi-verify-${OTHER}-recorder`,
			image: 'r',
			network: `koi-v-${OTHER}`,
			ip: '10.213.0.51',
			mac: helperMac('10.213.0.51'),
			runId: OTHER,
			appHost: { name: 'a', ip: '10.213.0.50' },
			dns: '10.213.0.49',
			env: {},
		});
		t.docker.events.length = 0;
		const cleaned = await t.restart().cleanupOrphans();
		expect(cleaned.sort()).toEqual([RUN, OTHER].sort());
		expect(t.docker.networksMade.size).toBe(0);
		expect([...t.docker.containers.keys()]).toEqual([APP]);
		expect(t.docker.containers.get(APP)?.attachments.size).toBe(0);
		expect(t.helper.revoked.sort()).toEqual([RUN, OTHER].sort());
		expect(await t.records()).toEqual([]);
		// For the orphan, revoke went first.
		expect(t.docker.events.indexOf(`revoke ${OTHER}`)).toBeLessThan(
			t.docker.events.indexOf(`removed network koi-v-${OTHER}`),
		);
	});

	test('removes the staging container and the input volumes of a recorded run, and of one with no record', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		const inputs = (run: string) =>
			INPUT_VOLUME_PARTS.map((part) => ({
				name: inputVolumeName(run, part),
				destination: `/${part}`,
			}));
		for (const run of [RUN, OTHER]) {
			for (const v of inputs(run)) {
				await t.docker.createVolume(v.name, { 'koi.run': run, 'koi.role': INPUT_VOLUME_ROLE });
			}
			await t.docker.createStaging({
				name: stagingName(run),
				image: 'i',
				runId: run,
				volumes: inputs(run),
			});
		}
		const cleaned = await t.restart().cleanupOrphans();
		expect(cleaned.sort()).toEqual([RUN, OTHER].sort());
		expect(t.docker.volumes.size).toBe(0);
		expect(t.docker.containers.has(stagingName(RUN))).toBe(false);
		expect(t.docker.containers.has(stagingName(OTHER))).toBe(false);
		// Docker refuses a volume a container mounts, so the container went
		// first, for the orphan as for the recorded run.
		for (const run of [RUN, OTHER]) {
			expect(t.docker.events.indexOf(`removed ${stagingName(run)}`)).toBeLessThan(
				t.docker.events.indexOf(`removed volume ${inputVolumeName(run, 'koi')}`),
			);
		}
	});

	test('removes a staging container whose image carries koi.preview', async () => {
		// The project chooses the image, and Docker copies its labels onto the
		// container, so koid has to set this one to nothing or cleanup leaves it.
		const t = await setup();
		t.docker.imageLabels.set('labelled', { 'koi.preview': 'from-the-image' });
		await t.docker.createStaging({
			name: stagingName(OTHER),
			image: 'labelled',
			runId: OTHER,
			volumes: [],
		});
		expect(await t.restart().cleanupOrphans()).toEqual([OTHER]);
		expect(t.docker.containers.has(stagingName(OTHER))).toBe(false);
	});

	test('takes down a volume with the run network it belongs to', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		await t.docker.createVolume(inputVolumeName(RUN, 'koi'), {
			'koi.run': RUN,
			'koi.role': INPUT_VOLUME_ROLE,
		});
		expect(await t.networks.destroy(RUN)).toBe(true);
		expect(t.docker.volumes.size).toBe(0);
	});

	test('leaves a volume koid did not make, and says so', async () => {
		const t = await setup();
		// Labelled for a run, but named by someone else.
		await t.docker.createVolume('someones-data', {
			'koi.run': OTHER,
			'koi.role': INPUT_VOLUME_ROLE,
		});
		// Named for a run, but labelled for another.
		await t.docker.createVolume(inputVolumeName(OTHER, 'koi'), {
			'koi.run': RUN,
			'koi.role': INPUT_VOLUME_ROLE,
		});
		// Named and labelled for a run, but not as inputs.
		await t.docker.createVolume(inputVolumeName(OTHER, 'workspace'), { 'koi.run': OTHER });
		expect(await t.networks.cleanupOrphans()).toEqual([]);
		expect(t.docker.volumes.size).toBe(3);
		expect(t.helper.revoked).toEqual([]);
		expect(t.logs.join('\n')).toContain(
			`leaving volume someones-data, labelled koi.run="${OTHER}": not an input volume koid made`,
		);
	});

	test('leaves what it cannot clean for the next start, says so, and fails', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		t.helper.revokeError = 'sudo -n exited 1: xtables lock';
		await expect(t.restart().cleanupOrphans()).rejects.toThrow(
			`run ${RUN}, revoking its permits: sudo -n exited 1: xtables lock`,
		);
		expect(await t.records()).toEqual([`${RUN}.json`]);
		expect(t.docker.networksMade.has(`koi-v-${RUN}`)).toBe(true);
		expect(t.logs.join('\n')).toContain(
			`removing the run network of ${RUN}: revoking its permits: sudo -n exited 1: xtables lock; kept for the next start`,
		);
		t.helper.revokeError = undefined;
		expect(await t.restart().cleanupOrphans()).toEqual([RUN]);
		expect(await t.records()).toEqual([]);
		expect(t.logs.join('\n')).toContain(`removed the run networks of ${RUN}`);
	});

	test('attempts every record and orphan, then names each run and step that failed', async () => {
		const t = await setup();
		const THIRD = 'c'.repeat(16);
		// Two recorded runs, and an orphan network from a run that crashed
		// before its record was written.
		await t.networks.create(t.request());
		await t.networks.create(t.request(OTHER));
		await t.docker.createNetwork({
			name: `koi-v-${THIRD}`,
			bridge: 'kvffffffffffff',
			subnet: '10.213.0.48/28',
			gateway: '10.213.0.49',
			labels: { 'koi.run': THIRD },
		});
		// The helper refuses the first record and the orphan; the second
		// record goes through.
		t.helper.revokeErrors.set(RUN, 'sudo -n exited 1: xtables lock');
		t.helper.revokeErrors.set(THIRD, 'sudo -n exited 2: koi-verify-net: no such run');
		await expect(t.restart().cleanupOrphans()).rejects.toThrow(
			`run ${RUN}, revoking its permits: sudo -n exited 1: xtables lock; run ${THIRD}, revoking its permits: sudo -n exited 2: koi-verify-net: no such run`,
		);
		expect(t.helper.revoked).toEqual([OTHER]);
		expect(await t.records()).toEqual([`${RUN}.json`]);
		expect(t.docker.networksMade.has(`koi-v-${RUN}`)).toBe(true);
		expect(t.docker.networksMade.has(`koi-v-${OTHER}`)).toBe(false);
		expect(t.docker.networksMade.has(`koi-v-${THIRD}`)).toBe(true);
		expect(t.logs.join('\n')).toContain(
			`removing what run ${THIRD} left: revoking its permits: sudo -n exited 2: koi-verify-net: no such run; tried again next start`,
		);
		expect(t.logs.join('\n')).toContain(`removed the run networks of ${OTHER}`);
		// A later step that fails is named as well: something else sits on
		// the orphan's network and will not come off. The record goes.
		t.helper.revokeErrors.clear();
		await t.docker.run({
			name: 'stray',
			image: 'x',
			network: 'koi-previews',
			user: '1',
			env: {},
			labels: { 'koi.preview': 'stray' },
		});
		await t.docker.connect(`koi-v-${THIRD}`, 'stray', '10.213.0.50');
		t.docker.undisconnectable.add('stray');
		await expect(t.restart().cleanupOrphans()).rejects.toThrow(
			`run ${THIRD}, taking stray off koi-v-${THIRD}: docker network disconnect exited 1: stray is busy`,
		);
		expect(await t.records()).toEqual([]);
		expect(t.docker.networksMade.has(`koi-v-${RUN}`)).toBe(false);
		expect(t.docker.networksMade.has(`koi-v-${THIRD}`)).toBe(true);
	});

	test('does not touch a network that carries koi.run without being a run network koid made', async () => {
		const t = await setup();
		await t.docker.createNetwork({
			name: 'odd',
			bridge: 'kvffffffffffff',
			subnet: '10.213.0.48/28',
			gateway: '10.213.0.49',
			labels: { 'koi.run': 'Not A Run' },
		});
		// Named like a run network, labelled with another run.
		await t.docker.createNetwork({
			name: `koi-v-${OTHER}`,
			bridge: 'kveeeeeeeeeeee',
			subnet: '10.213.0.32/28',
			gateway: '10.213.0.33',
			labels: { 'koi.run': RUN },
		});
		expect(await t.networks.cleanupOrphans()).toEqual([]);
		expect(t.docker.networksMade.has('odd')).toBe(true);
		expect(t.docker.networksMade.has(`koi-v-${OTHER}`)).toBe(true);
		expect(t.helper.revoked).toEqual([]);
		expect(t.logs.join('\n')).toContain(
			'leaving network odd, labelled koi.run="Not A Run": not a run network koid made',
		);
		expect(t.logs.join('\n')).toContain(
			`leaving network koi-v-${OTHER}, labelled koi.run="${RUN}": not a run network koid made`,
		);
	});

	test('leaves a preview whose image carries koi.run and koi.role, and a container only named like a helper', async () => {
		const t = await setup();
		// A pull request's Dockerfile can LABEL anything; the labels reach the
		// preview container. The run id is well formed and has no record.
		await t.docker.run({
			name: 'koi-forged-pr-9-cccccccccccccccc3',
			image: 'koi-preview/forged:c',
			network: 'koi-previews',
			user: '65534:65534',
			env: {},
			labels: { 'koi.preview': 'forged-pr-9', 'koi.run': OTHER, 'koi.role': 'recorder' },
		});
		// And one with a helper's name but a preview's label.
		await t.docker.run({
			name: helperName(OTHER, 'verifier'),
			image: 'koi-preview/forged:c',
			network: 'koi-previews',
			user: '65534:65534',
			env: {},
			labels: { 'koi.preview': 'forged-pr-9', 'koi.run': OTHER, 'koi.role': 'verifier' },
		});
		t.docker.events.length = 0;
		expect(await t.networks.cleanupOrphans()).toEqual([]);
		expect(t.docker.containers.has('koi-forged-pr-9-cccccccccccccccc3')).toBe(true);
		expect(t.docker.containers.has(helperName(OTHER, 'verifier'))).toBe(true);
		expect(t.helper.revoked).toEqual([]);
		expect(t.docker.events).toEqual([]);
		expect(t.logs.join('\n')).toContain(
			`leaving container koi-forged-pr-9-cccccccccccccccc3, labelled koi.run="${OTHER}": not a helper koid made`,
		);
		expect(t.logs.join('\n')).toContain(
			`leaving container ${helperName(OTHER, 'verifier')}, labelled koi.run="${OTHER}": not a helper koid made`,
		);
	});

	test('a record that does not parse is skipped and reported', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		await Bun.write(join(t.root, 'verification', 'networks', 'bad.json'), '{"version": 2}');
		expect(await t.networks.list()).toHaveLength(1);
		expect(t.logs.join('\n')).toContain('skipping run network record bad.json');
	});

	test('a record that cannot be read or parsed fails the cleanup, and the rest still goes', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		const dir = join(t.root, 'verification', 'networks');
		const bad = join(dir, 'bad.json');
		// A directory where the file should be: reading it fails for any
		// user, root included, which a chmod would not.
		const unreadable = join(dir, `${OTHER}.json`);
		await Bun.write(bad, '{"version": 2}');
		await mkdir(unreadable);
		const error = await t
			.restart()
			.cleanupOrphans()
			.then(
				() => '',
				(err: Error) => err.message,
			);
		expect(error).toContain(`cannot read run network record ${bad}: version: `);
		expect(error).toContain(`cannot read run network record ${unreadable}: `);
		expect(error).toContain('look at it and remove it');
		expect(t.logs.join('\n')).toContain(`cannot read run network record ${bad}`);
		// The readable record went, and the two others are still there.
		expect(t.helper.revoked).toEqual([RUN]);
		expect(t.docker.networksMade.has(`koi-v-${RUN}`)).toBe(false);
		expect((await t.records()).sort()).toEqual(['bad.json', `${OTHER}.json`]);
		// Still reported at the next start, until the operator acts.
		await expect(t.restart().cleanupOrphans()).rejects.toThrow(bad);
		await rm(bad);
		await rm(unreadable, { recursive: true });
		expect(await t.restart().cleanupOrphans()).toEqual([]);
	});

	test('what a run with an unreadable record left goes as an orphan, and the file stays', async () => {
		const t = await setup();
		await t.networks.create(t.request(OTHER));
		const file = join(t.root, 'verification', 'networks', `${OTHER}.json`);
		await Bun.write(file, 'not json');
		await expect(t.restart().cleanupOrphans()).rejects.toThrow(
			`cannot read run network record ${file}`,
		);
		expect(t.helper.revoked).toEqual([OTHER]);
		expect(t.docker.networksMade.has(`koi-v-${OTHER}`)).toBe(false);
		expect([...t.docker.containers.keys()]).toEqual([APP]);
		expect(t.docker.containers.get(APP)?.attachments.size).toBe(0);
		expect(await t.records()).toEqual([`${OTHER}.json`]);
	});

	test('a run only the helper still holds gets a revoke', async () => {
		const t = await setup();
		t.helper.runs.add(OTHER);
		expect(await t.networks.cleanupOrphans()).toEqual([OTHER]);
		expect(t.helper.revoked).toEqual([OTHER]);
		expect(t.helper.runs.size).toBe(0);
		expect(t.logs.join('\n')).toContain(
			`revoked run ${OTHER}, which the helper held and koid had no record of`,
		);
	});

	test('a revoke of such a run that fails names the run, and the other runs still go', async () => {
		const t = await setup();
		const THIRD = 'c'.repeat(16);
		t.helper.runs.add(OTHER);
		t.helper.runs.add(THIRD);
		t.helper.revokeErrors.set(OTHER, 'sudo -n exited 1: xtables lock');
		await expect(t.networks.cleanupOrphans()).rejects.toThrow(
			`run ${OTHER}, revoking its permits: sudo -n exited 1: xtables lock`,
		);
		expect(t.helper.revoked).toEqual([THIRD]);
		expect([...t.helper.runs]).toEqual([OTHER]);
	});

	test('a helper that cannot say which runs it holds fails the cleanup', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		t.helper.attestError = 'sudo -n exited 1: a password is required';
		await expect(t.restart().cleanupOrphans()).rejects.toThrow(
			'asking the helper which runs it holds: sudo -n exited 1: a password is required',
		);
		// The record still went: the attestation comes after it.
		expect(await t.records()).toEqual([]);
	});
});

describe('reapply', () => {
	test("with a role to check, holds until the attestation names that role's bridge port", async () => {
		const t = await setup();
		await t.networks.create(t.request());
		const ports = (verifier: string | null) => ({
			[RUN]: { app: 'vethapp', recorder: 'vethrec', verifier },
		});
		t.helper.attestation = { ...t.helper.attestation, ports: ports('vethver') };
		await t.networks.reapply(RUN, { bound: ['verifier'] });
		// The container was not running when the helper looked.
		t.helper.attestation = { ...t.helper.attestation, ports: ports(null) };
		await expect(t.networks.reapply(RUN, { bound: ['verifier'] })).rejects.toThrow(
			"after apply, the helper has not bound the verifier's permits to a bridge port",
		);
		// The helper could not read the run's state.
		t.helper.attestation = { ...t.helper.attestation, ports: { [RUN]: null } };
		await expect(t.networks.reapply(RUN, { bound: ['verifier'] })).rejects.toThrow(
			"the helper has not bound the verifier's permits",
		);
		// A helper from before the field says nothing, which is not a yes.
		const { ports: _ports, ...old } = t.helper.attestation;
		t.helper.attestation = old;
		await expect(t.networks.reapply(RUN, { bound: ['verifier'] })).rejects.toThrow(
			"the helper has not bound the verifier's permits",
		);
		// With nothing to check, as for the recorder's start.
		await t.networks.reapply(RUN);
	});

	test('installs the permits again for a ready network, and refuses one that is not', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		expect(t.helper.applied).toHaveLength(1);
		await t.networks.reapply(RUN);
		expect(t.helper.applied).toHaveLength(2);
		expect(t.helper.applied[1]).toEqual(t.helper.applied[0]);
		expect((await t.networks.record(RUN))?.state).toBe('ready');
		await expect(t.networks.reapply(OTHER)).rejects.toThrow('has no network');
		t.helper.applyError = 'the bridge port is gone';
		await expect(t.networks.reapply(RUN)).rejects.toThrow('the bridge port is gone');
	});

	describe('abandoned by its caller', () => {
		const holdingApply = async () => {
			const t = await setup();
			await t.networks.create(t.request());
			const gate = new Gate();
			const apply = t.helper.apply.bind(t.helper);
			t.helper.apply = async (descriptor) => {
				await gate.pass();
				return apply(descriptor);
			};
			return { t, gate };
		};

		test('while it waits for the lock, it asks the helper for nothing', async () => {
			const { t, gate } = await holdingApply();
			const first = t.networks.reapply(RUN);
			await gate.reached;
			const abandoned = new AbortController();
			const second = t.networks.reapply(RUN, { signal: abandoned.signal });
			abandoned.abort(new Error('the point stopped'));
			gate.release();
			await first;
			await expect(second).rejects.toThrow('the point stopped');
			// The network's own apply, and the first reapply's.
			expect(t.helper.applied).toHaveLength(2);
		});

		test('while it reads the record, it asks the helper for nothing', async () => {
			const t = await setup();
			await t.networks.create(t.request());
			const abandoned = new AbortController();
			const record = t.networks.record.bind(t.networks);
			t.networks.record = async (runId) => {
				const found = await record(runId);
				abandoned.abort(new Error('the point stopped'));
				return found;
			};
			await expect(t.networks.reapply(RUN, { signal: abandoned.signal })).rejects.toThrow(
				'the point stopped',
			);
			expect(t.helper.applied).toHaveLength(1);
		});

		test('with the helper already at work, it keeps the lock, so the revoke comes after the apply', async () => {
			const { t, gate } = await holdingApply();
			const abandoned = new AbortController();
			const reapply = t.networks.reapply(RUN, { signal: abandoned.signal });
			await gate.reached;
			abandoned.abort(new Error('the point stopped'));
			const destroyed = t.networks.destroy(RUN);
			await Bun.sleep(5);
			expect(t.helper.revoked).toEqual([]);
			gate.release();
			await expect(reapply).rejects.toThrow('the point stopped');
			await destroyed;
			const applied = t.docker.events.lastIndexOf(`apply ${RUN}`);
			expect(applied).toBeGreaterThanOrEqual(0);
			expect(t.docker.events.indexOf(`revoke ${RUN}`)).toBeGreaterThan(applied);
			expect(t.helper.runs.has(RUN)).toBe(false);
		});

		test('one that gets the lock after the teardown finds no record and changes nothing', async () => {
			const t = await setup();
			await t.networks.create(t.request());
			const destroyed = t.networks.destroy(RUN);
			const late = t.networks.reapply(RUN);
			await destroyed;
			await expect(late).rejects.toThrow('has no network');
			expect(t.helper.applied).toHaveLength(1);
			expect(t.helper.runs.has(RUN)).toBe(false);
		});
	});
});

describe('startup', () => {
	const SWAP =
		'chain DOCKER-USER does not start with -j KOI-VERIFY: its first rule is -A DOCKER-USER -j KOI-VERIFY-NEW';
	const IMAGE = `sha256:${'7'.repeat(64)}`;
	const SECCOMP = '/usr/local/share/koi/recorder-seccomp.json';

	test('revokes every leftover before judging a box whose provision was interrupted', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		// A run that crashed before its record was written, with the app
		// still attached.
		await t.docker.createNetwork({
			name: `koi-v-${OTHER}`,
			bridge: 'kvffffffffffff',
			subnet: '10.213.0.48/28',
			gateway: '10.213.0.49',
			labels: { 'koi.run': OTHER },
		});
		await t.docker.connect(`koi-v-${OTHER}`, APP, '10.213.0.50');
		await t.docker.createRecorder({
			name: `koi-verify-${OTHER}-recorder`,
			image: 'r',
			network: `koi-v-${OTHER}`,
			ip: '10.213.0.51',
			mac: helperMac('10.213.0.51'),
			runId: OTHER,
			appHost: { name: 'a', ip: '10.213.0.50' },
			dns: '10.213.0.49',
			env: {},
		});
		// The parent chain still jumps to the staged copy an interrupted
		// provision left. attest reports it until a revoke, which finishes
		// the swap.
		const attested: string[] = [];
		const ok = (stdout: string): ExecResult => ({ code: 0, stdout, stderr: '', timedOut: false });
		const run = async (cmd: string[]): Promise<ExecResult> => {
			const line = cmd.join(' ');
			if (line === 'sudo -n /usr/local/libexec/koi-verify-net attest') {
				const current = await t.helper.attest();
				const swapped = t.helper.revoked.length === 0;
				const ipv4 = { ...current.ipv4, jump: !swapped, problems: swapped ? [SWAP] : [] };
				attested.push(ipv4.problems.join('; '));
				return ok(`${JSON.stringify({ ...current, ipv4 })}\n`);
			}
			if (line === `docker image inspect --format {{.Id}} ${IMAGE}`) return ok(`${IMAGE}\n`);
			// Chromium's sandbox starts in the recorder image (host.ts, sandboxProbe).
			if (
				/^docker (run --rm --name|ps --all --filter label=|rm --force) ?koi[.-]sandbox-probe/.test(
					line,
				)
			)
				return ok('');
			if (line === 'docker info --format {{.CgroupDriver}}') return ok('systemd\n');
			if (line.startsWith('systemctl show ')) {
				return ok('MemoryMax=13369344000\nActiveState=active\n');
			}
			throw new Error(`unexpected command: ${line}`);
		};
		const result = await verificationCapability(
			{
				pool: t.deps.pool,
				helper: '/usr/local/libexec/koi-verify-net',
				slice: 'koi.slice',
				recorderImage: IMAGE,
				recorderSeccomp: SECCOMP,
				verifierImage: IMAGE,
				cleanup: () => t.restart().cleanupOrphans(),
			},
			run,
			async () => ({ isFile: true, uid: 0, gid: 0, mode: 0o755 }),
		);
		expect(t.helper.revoked.sort()).toEqual([RUN, OTHER].sort());
		expect(await t.records()).toEqual([]);
		expect(t.docker.networksMade.size).toBe(0);
		expect([...t.docker.containers.keys()]).toEqual([APP]);
		expect(t.docker.containers.get(APP)?.attachments.size).toBe(0);
		// Attested badly before the cleanup, and cleanly after it.
		expect(attested).toEqual([SWAP, '']);
		expect(result).toEqual({
			available: true,
			attestation: attestation({ pool: t.deps.pool }),
			recorderImageId: IMAGE,
			verifierImageId: IMAGE,
		});
	});

	test('a leftover the cleanup could not remove makes verification unavailable, naming it', async () => {
		const t = await setup();
		await t.networks.create(t.request());
		await t.networks.create(t.request(OTHER));
		const ok = (stdout: string): ExecResult => ({ code: 0, stdout, stderr: '', timedOut: false });
		// The box as provisioning left it, attesting what the helper holds.
		const run = async (cmd: string[]): Promise<ExecResult> => {
			const line = cmd.join(' ');
			if (line === 'sudo -n /usr/local/libexec/koi-verify-net attest') {
				return ok(`${JSON.stringify(await t.helper.attest())}\n`);
			}
			if (line === `docker image inspect --format {{.Id}} ${IMAGE}`) return ok(`${IMAGE}\n`);
			// Chromium's sandbox starts in the recorder image (host.ts, sandboxProbe).
			if (
				/^docker (run --rm --name|ps --all --filter label=|rm --force) ?koi[.-]sandbox-probe/.test(
					line,
				)
			)
				return ok('');
			if (line === 'docker info --format {{.CgroupDriver}}') return ok('systemd\n');
			if (line.startsWith('systemctl show ')) {
				return ok('MemoryMax=13369344000\nActiveState=active\n');
			}
			throw new Error(`unexpected command: ${line}`);
		};
		const check = () =>
			verificationCapability(
				{
					pool: t.deps.pool,
					helper: '/usr/local/libexec/koi-verify-net',
					slice: 'koi.slice',
					recorderImage: IMAGE,
					recorderSeccomp: SECCOMP,
					verifierImage: IMAGE,
					cleanup: () => t.restart().cleanupOrphans(),
				},
				run,
				async () => ({ isFile: true, uid: 0, gid: 0, mode: 0o755 }),
			);
		// The helper refuses one run's revoke; the other run goes.
		t.helper.revokeErrors.set(RUN, 'sudo -n exited 1: xtables lock');
		expect(await check()).toEqual({
			available: false,
			reason: `removing what earlier runs left: run ${RUN}, revoking its permits: sudo -n exited 1: xtables lock`,
		});
		expect(t.helper.revoked).toEqual([OTHER]);
		expect(await t.records()).toEqual([`${RUN}.json`]);
		expect(t.docker.networksMade.has(`koi-v-${RUN}`)).toBe(true);
		// Once the helper lets it go, the next start is clean and ready.
		t.helper.revokeErrors.clear();
		expect(await check()).toEqual({
			available: true,
			attestation: attestation({ pool: t.deps.pool }),
			recorderImageId: IMAGE,
			verifierImageId: IMAGE,
		});
		expect(await t.records()).toEqual([]);
		expect(t.docker.networksMade.size).toBe(0);
	});

	// The check at startup, on a box as provisioning left it, attesting what
	// the fake helper holds.
	const capabilityOf = (t: Awaited<ReturnType<typeof setup>>) => {
		const ok = (stdout: string): ExecResult => ({ code: 0, stdout, stderr: '', timedOut: false });
		const run = async (cmd: string[]): Promise<ExecResult> => {
			const line = cmd.join(' ');
			if (line === 'sudo -n /usr/local/libexec/koi-verify-net attest') {
				return ok(`${JSON.stringify(await t.helper.attest())}\n`);
			}
			if (line === 'docker info --format {{.CgroupDriver}}') return ok('systemd\n');
			if (line.startsWith('systemctl show ')) {
				return ok('MemoryMax=13369344000\nActiveState=active\n');
			}
			if (line === `docker image inspect --format {{.Id}} ${IMAGE}`) return ok(`${IMAGE}\n`);
			// Chromium's sandbox starts in the recorder image (host.ts, sandboxProbe).
			if (
				/^docker (run --rm --name|ps --all --filter label=|rm --force) ?koi[.-]sandbox-probe/.test(
					line,
				)
			)
				return ok('');
			throw new Error(`unexpected command: ${line}`);
		};
		return verificationCapability(
			{
				pool: t.deps.pool,
				helper: '/usr/local/libexec/koi-verify-net',
				slice: 'koi.slice',
				recorderImage: IMAGE,
				recorderSeccomp: SECCOMP,
				verifierImage: IMAGE,
				cleanup: () => t.restart().cleanupOrphans(),
			},
			run,
			async () => ({ isFile: true, uid: 0, gid: 0, mode: 0o755 }),
		);
	};

	test('an unreadable record with no Docker objects and a run in the helper: revoked, and unavailable', async () => {
		const t = await setup();
		const file = join(t.root, 'verification', 'networks', `${RUN}.json`);
		await Bun.write(file, 'not json');
		t.helper.runs.add(RUN);
		const result = await capabilityOf(t);
		expect(result.available).toBe(false);
		expect(result.available === false && result.reason).toStartWith(
			`removing what earlier runs left: cannot read run network record ${file}: `,
		);
		expect(result.available === false && result.reason).toContain('look at it and remove it');
		expect(t.helper.revoked).toEqual([RUN]);
		expect(t.helper.runs.size).toBe(0);
		expect(await t.records()).toEqual([`${RUN}.json`]);
		// The operator removes the file, and the next start is clean.
		await rm(file);
		expect(await capabilityOf(t)).toEqual({
			available: true,
			attestation: attestation({ pool: t.deps.pool }),
			recorderImageId: IMAGE,
			verifierImageId: IMAGE,
		});
	});

	test('a run only the helper holds is revoked, and the box is available', async () => {
		const t = await setup();
		t.helper.runs.add(OTHER);
		expect(await capabilityOf(t)).toEqual({
			available: true,
			attestation: attestation({ pool: t.deps.pool }),
			recorderImageId: IMAGE,
			verifierImageId: IMAGE,
		});
		expect(t.helper.revoked).toEqual([OTHER]);
	});

	test('a run only the helper holds, whose revoke fails, makes verification unavailable, naming it', async () => {
		const t = await setup();
		t.helper.runs.add(OTHER);
		t.helper.revokeErrors.set(OTHER, 'sudo -n exited 1: xtables lock');
		expect(await capabilityOf(t)).toEqual({
			available: false,
			reason: `removing what earlier runs left: run ${OTHER}, revoking its permits: sudo -n exited 1: xtables lock`,
		});
	});
});
