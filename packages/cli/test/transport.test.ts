import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	CTL_EXIT,
	decodeCtlArgs,
	type HostInfo,
	requestKey,
	sourceKey,
	type UpRequest,
} from '@koi/shared';
import { BuildLogs } from '../../daemon/src/buildlog.ts';
import type { ControlDeps } from '../../daemon/src/control.ts';
import { CTL_USAGE } from '../../daemon/src/ctl.ts';
import type { Clients } from '../src/box.ts';
import { toYaml } from '../src/config-command.ts';
import { openHost, transportFor } from '../src/host.ts';
import {
	abandonedCalls,
	BoxUnavailableError,
	HostMismatchError,
	type HostTransport,
	type LogEvent,
	type OperationOptions,
	UnknownOutcomeError,
	UnsupportedCapabilityError,
	verifiedTransport,
} from '../src/transport.ts';
import { awsTransport } from '../src/transports/aws.ts';
import { hostInfoFor, koidClients, koidDeps, previewRecord, s3Stub, settings } from './koid.ts';

const AWS_TARGET = {
	domain: 'previews.example.net',
	transport: { kind: 'aws-ssm' },
	aws: {
		profile: 'koi-cli',
		region: 'us-east-1',
		instanceId: 'i-0abc',
		uploadsBucket: 'koi-uploads-123456789012',
	},
	power: { kind: 'ec2' },
};

const SSH_TARGET = {
	domain: 'previews.example.com',
	transport: {
		kind: 'ssh',
		endpoint: {
			host: '203.0.113.10',
			user: 'koi-connect',
			identityFile: '/home/operator/.ssh/koi_team_ed25519',
			knownHostsFile: '/home/operator/.config/koi/known_hosts',
			hostKeyAlias: 'team',
		},
	},
	power: { kind: 'always-on' },
};

// AWS as openHost meets it: EC2 with one tagged running box and STS for the
// account, and SSM commands run by the real koid ctl and control API with
// `deps` behind them (koidClients). With `oldDaemon`, koid ctl describe
// answers as a koid from before the descriptor does: usage, exit 2. Every
// EC2 and STS call lands in `calls` with its input.
function aws(
	deps: ControlDeps,
	{ domainTag = 'previews.example.net' as string | null, oldDaemon = false } = {},
) {
	const koid = koidClients(deps);
	const calls: Array<{ name: string; input: unknown }> = [];
	const made: string[] = [];
	const send = async (cmd: { constructor: { name: string }; input: unknown }) => {
		const name = cmd.constructor.name;
		if (name === 'DescribeInstancesCommand') {
			calls.push({ name, input: cmd.input });
			const Tags = domainTag === null ? [] : [{ Key: 'Domain', Value: domainTag }];
			return {
				Reservations: [{ Instances: [{ InstanceId: 'i-0abc', Tags, State: { Name: 'running' } }] }],
			};
		}
		if (name === 'GetCallerIdentityCommand') {
			calls.push({ name, input: cmd.input });
			return { Account: '123456789012' };
		}
		if (oldDaemon && name === 'SendCommandCommand') {
			const input = cmd.input as { Parameters: { commands: string[] } };
			const blob = input.Parameters.commands[0]?.split(' ')[2] ?? '';
			if (decodeCtlArgs(blob)[0] === 'describe') return { Command: { CommandId: 'old-describe' } };
		}
		if (oldDaemon && name === 'GetCommandInvocationCommand') {
			const input = cmd.input as { CommandId: string };
			if (input.CommandId === 'old-describe') {
				return {
					Status: 'Failed',
					ResponseCode: CTL_EXIT.usage,
					StandardOutputContent: '',
					StandardErrorContent: CTL_USAGE,
				};
			}
		}
		return (koid.ssm as unknown as { send: (c: unknown) => Promise<unknown> }).send(cmd);
	};
	const client = { send } as never;
	return {
		calls,
		made,
		commands: koid.commands,
		make: (profile: string, region: string): Clients => {
			made.push(`${profile}@${region}`);
			return { s3: client, ec2: client, ssm: client, sts: client };
		},
	};
}

async function home(config?: unknown): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), 'koi-home-'));
	if (config !== undefined) {
		await mkdir(join(dir, '.config', 'koi'), { recursive: true, mode: 0o700 });
		await writeFile(join(dir, '.config', 'koi', 'config.yaml'), toYaml(config), { mode: 0o600 });
	}
	return dir;
}

function notices() {
	const lines: string[] = [];
	return { lines, notice: (m: string) => void lines.push(m) };
}

describe('openHost on the legacy AWS path', () => {
	test('discovers the deployment as before, says so once, and checks the host after waking it', async () => {
		const h = await home();
		const a = aws(koidDeps({}));
		const n = notices();
		const opened = await openHost({
			flags: {},
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: n.notice,
			awsClients: a.make,
		});
		expect(opened.domain).toBe('previews.example.net');
		expect(opened.resolved.kind).toBe('legacy');
		expect(a.made).toEqual(['koi-cli@us-east-1']);
		// The box by both tag sets, then the account for the bucket.
		expect(a.calls.map((c) => c.name)).toEqual([
			'DescribeInstancesCommand',
			'DescribeInstancesCommand',
			'GetCallerIdentityCommand',
		]);
		expect(a.calls[0]?.input).toMatchObject({
			Filters: [
				{ Name: 'tag:koi:role', Values: ['box'] },
				{ Name: 'instance-state-name', Values: ['pending', 'running', 'stopping', 'stopped'] },
			],
		});
		expect(n.lines).toHaveLength(1);
		expect(n.lines[0]).toContain(`no koi config file at ${join(h, '.config/koi/config.yaml')}`);
		expect(n.lines[0]).toContain(
			'aws-ssm to i-0abc in us-east-1, previews under previews.example.net',
		);
		expect(n.lines[0]).toContain('koi config import-aws --name NAME');

		await opened.box.ensureAwake(() => {});
		expect(a.commands).toEqual([['ping'], ['describe']]);
		// Checked once per process, not on every wake.
		await opened.box.ensureAwake(() => {});
		expect(a.commands).toEqual([['ping'], ['describe'], ['ping']]);
		expect(n.lines).toHaveLength(1);
	});

	test('--domain stands in for KOI_DOMAIN and is what the host must serve', async () => {
		const h = await home();
		const a = aws(koidDeps({ describe: async () => hostInfoFor('other.example.com') }));
		const opened = await openHost({
			flags: { domain: 'other.example.com' },
			env: { HOME: h, KOI_DOMAIN: 'env.example.com' },
			checkoutDir: '/nonexistent',
			notice: () => {},
			awsClients: a.make,
		});
		expect(opened.domain).toBe('other.example.com');
		// The domain came from the flag, so the tag was not needed; the box
		// still is.
		expect(a.calls.map((c) => c.name)).toEqual([
			'DescribeInstancesCommand',
			'DescribeInstancesCommand',
			'GetCallerIdentityCommand',
		]);
		await opened.box.ensureAwake(() => {});
		expect(a.commands).toEqual([['ping'], ['describe']]);
	});

	test('takes an old koid at its word, with a warning that names the configured domain', async () => {
		const h = await home();
		const a = aws(koidDeps({}), { oldDaemon: true });
		const n = notices();
		const opened = await openHost({
			flags: {},
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: n.notice,
			awsClients: a.make,
		});
		await opened.box.ensureAwake(() => {});
		// The fixture answers describe itself, so koid saw only the ping.
		expect(a.commands).toEqual([['ping']]);
		expect(n.lines.at(-1)).toMatch(
			/^koid on the koi box predates koid ctl describe, so koi cannot check that it serves previews\.example\.net; taking the configured domain/,
		);
	});
});

describe('openHost with a configured target', () => {
	test('a full AWS target asks AWS nothing before it is used, and prints the target', async () => {
		const h = await home({
			version: 1,
			defaultTarget: 'owner-aws',
			targets: { 'owner-aws': AWS_TARGET },
		});
		const a = aws(koidDeps({}));
		const n = notices();
		const opened = await openHost({
			flags: {},
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: n.notice,
			awsClients: a.make,
		});
		expect(opened.domain).toBe('previews.example.net');
		expect(opened.resolved.kind === 'target' && opened.resolved.name).toBe('owner-aws');
		expect(a.calls).toEqual([]);
		expect(a.made).toEqual(['koi-cli@us-east-1']);
		expect(n.lines).toEqual([
			`target owner-aws (defaultTarget) from ${join(h, '.config/koi/config.yaml')}: aws-ssm, previews under previews.example.net`,
		]);
		await opened.box.ensureAwake(() => {});
		// Waking describes the one instance the target names; nothing is
		// discovered by tag, and the account is not asked.
		expect(a.calls.map((c) => c.name)).toEqual(['DescribeInstancesCommand']);
		expect(a.calls[0]?.input).toEqual({ InstanceIds: ['i-0abc'] });
		expect(a.commands).toEqual([['ping'], ['describe']]);
	});

	test('stops when the host serves another domain than the target names', async () => {
		const h = await home({
			version: 1,
			defaultTarget: 'owner-aws',
			targets: { 'owner-aws': { ...AWS_TARGET, domain: 'wrong.example.com' } },
		});
		const a = aws(koidDeps({}));
		const opened = await openHost({
			flags: {},
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: () => {},
			awsClients: a.make,
		});
		const err = await opened.box.ensureAwake(() => {}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(HostMismatchError);
		expect((err as Error).message).toContain(
			'the host behind target "owner-aws" serves previews under previews.example.net, not wrong.example.com as configured',
		);
		expect(a.commands).toEqual([['ping'], ['describe']]);
		// --domain names the domain the host does serve, and the check passes.
		const fixed = await openHost({
			flags: { domain: 'previews.example.net' },
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: () => {},
			awsClients: a.make,
		});
		await fixed.box.ensureAwake(() => {});
		expect(fixed.domain).toBe('previews.example.net');
	});

	test('never falls back on a descriptor it cannot read', async () => {
		const h = await home({
			version: 1,
			defaultTarget: 'owner-aws',
			targets: { 'owner-aws': AWS_TARGET },
		});
		for (const bad of [
			{ ...hostInfoFor('previews.example.net'), protocol: 2 },
			{ ...hostInfoFor('previews.example.net'), hostId: '../x' },
			{ ok: true },
		]) {
			const a = aws(koidDeps({ describe: async () => bad as HostInfo }));
			const n = notices();
			const opened = await openHost({
				flags: {},
				env: { HOME: h },
				checkoutDir: '/nonexistent',
				notice: n.notice,
				awsClients: a.make,
			});
			await expect(opened.box.ensureAwake(() => {})).rejects.toThrow(
				/koid ctl describe returned a descriptor koi cannot read/,
			);
			expect(n.lines).toHaveLength(1);
		}
	});

	test('an old koid is allowed on an AWS target with a warning', async () => {
		const h = await home({
			version: 1,
			defaultTarget: 'owner-aws',
			targets: { 'owner-aws': AWS_TARGET },
		});
		const a = aws(koidDeps({}), { oldDaemon: true });
		const n = notices();
		const opened = await openHost({
			flags: {},
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: n.notice,
			awsClients: a.make,
		});
		await opened.box.ensureAwake(() => {});
		expect(n.lines.at(-1)).toContain(
			'koid on target "owner-aws" predates koid ctl describe, so koi cannot check that it serves previews.example.net',
		);
	});

	test('an SSH target builds the SSH transport and is printed before anything is sent', async () => {
		const h = await home({ version: 1, targets: { team: SSH_TARGET } });
		const n = notices();
		const opened = await openHost({
			flags: { target: 'team' },
			env: { HOME: h, PATH: '/usr/bin' },
			checkoutDir: '/nonexistent',
			notice: n.notice,
			awsClients: () => {
				throw new Error('no AWS clients expected');
			},
		});
		expect(opened.domain).toBe('previews.example.com');
		expect(n.lines).toEqual([
			`target team (--target) from ${join(h, '.config', 'koi', 'config.yaml')}: ssh, previews under previews.example.com`,
		]);
		expect(typeof opened.box.upload).toBe('function');
		await opened.box.close();
	});

	test('an SSH target with ec2 power, a local target, a channel or another port is not supported yet', async () => {
		const h = await home({
			version: 1,
			targets: {
				sshwake: { ...SSH_TARGET, power: { kind: 'ec2' }, aws: AWS_TARGET.aws },
				local: {
					domain: 'koi.test',
					transport: { kind: 'local', controlSocket: '/run/koi-local/control.sock' },
					power: { kind: 'always-on' },
				},
				port: { ...AWS_TARGET, address: { port: 8443 } },
				channel: {
					...AWS_TARGET,
					transport: { kind: 'aws-ssm', channel: SSH_TARGET.transport.endpoint },
				},
			},
		});
		const open = (target: string) =>
			openHost({
				flags: { target },
				env: { HOME: h },
				checkoutDir: '/nonexistent',
				notice: () => {},
				awsClients: () => {
					throw new Error('no AWS clients expected');
				},
			});
		for (const [target, why] of [
			[
				'sshwake',
				/target "sshwake" reaches the host over ssh and manages its power with ec2; this version of koi can only reach an always-on host over ssh/,
			],
			[
				'local',
				/target "local" uses the local transport, which this version of koi does not support yet/,
			],
			[
				'port',
				/target "port" serves previews on port 8443; this version of koi supports port 443 only/,
			],
			[
				'channel',
				/target "channel" sets an SSH channel next to SSM; this version of koi does not support it yet/,
			],
		] as const) {
			const err = await open(target).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(UnsupportedCapabilityError);
			expect((err as Error).message).toMatch(why);
		}
	});

	test('a repository alias selects the target and is printed before anything is sent', async () => {
		const h = await home({ version: 1, targets: { team: AWS_TARGET } });
		const repo = await mkdtemp(join(tmpdir(), 'koi-repo-'));
		await mkdir(join(repo, '.koi'));
		await writeFile(join(repo, '.koi', 'target.yaml'), 'version: 1\ntarget: team\n');
		const a = aws(koidDeps({}));
		const n = notices();
		await openHost({
			flags: {},
			env: { HOME: h },
			checkoutDir: repo,
			notice: n.notice,
			awsClients: a.make,
		});
		expect(n.lines).toEqual([
			`target team (.koi/target.yaml) from ${join(h, '.config/koi/config.yaml')}: aws-ssm, previews under previews.example.net`,
		]);
		expect(a.commands).toEqual([]);
	});
});

// A transport that answers describe with `info`, or throws `err`, and
// counts how often.
function fakeInner(info: HostInfo | Error): HostTransport & { describes: () => number } {
	let describes = 0;
	return {
		upload: async () => {},
		ensureAwake: async () => {},
		ctl: async () => ({ code: 0, stdout: '', stderr: '' }),
		describe: async () => {
			describes += 1;
			if (info instanceof Error) throw info;
			return info;
		},
		streamLogs: () => {
			throw new Error('not used');
		},
		openChannel: async () => {
			throw new Error('not used');
		},
		close: async () => {},
		describes: () => describes,
	};
}

describe('verifiedTransport', () => {
	test('excuses an old koid only where allowed', async () => {
		const old = new UnsupportedCapabilityError('describe', 'no describe');
		const n = notices();
		const allowed = verifiedTransport(
			fakeInner(old),
			{ name: 'target "x"', domain: 'a.example.com', oldDaemonOk: true },
			n.notice,
		);
		await allowed.ensureAwake(() => {});
		expect(n.lines).toEqual([
			'koid on target "x" predates koid ctl describe, so koi cannot check that it serves a.example.com; taking the configured domain. Deploy the current koid (scripts/deploy-host.sh) to remove this warning',
		]);
		const strict = verifiedTransport(
			fakeInner(old),
			{ name: 'target "y"', domain: 'a.example.com', oldDaemonOk: false },
			n.notice,
		);
		await expect(strict.ensureAwake(() => {})).rejects.toThrow('no describe');
		// Any other unsupported capability, or error, is never excused.
		const other = verifiedTransport(
			fakeInner(new UnsupportedCapabilityError('duplex', 'no channel')),
			{ name: 'target "z"', domain: 'a.example.com', oldDaemonOk: true },
			n.notice,
		);
		await expect(other.ensureAwake(() => {})).rejects.toThrow('no channel');
	});

	test('rejects another address policy', async () => {
		const t = verifiedTransport(
			fakeInner(hostInfoFor('a.example.com', { address: { scheme: 'https', port: 8443 } })),
			{ name: 'target "x"', domain: 'a.example.com', oldDaemonOk: true },
			() => {},
		);
		await expect(t.ensureAwake(() => {})).rejects.toThrow(
			'the host behind target "x" serves previews on https port 8443; this version of koi expects https on 443',
		);
	});

	test('checks again after a failed check, and not after a passed one', async () => {
		let info: HostInfo | Error = new BoxUnavailableError('SSM throttled');
		const inner = fakeInner(hostInfoFor('a.example.com'));
		inner.describe = async () => {
			if (info instanceof Error) throw info;
			return info;
		};
		const t = verifiedTransport(
			inner,
			{ name: 'target "x"', domain: 'a.example.com', oldDaemonOk: true },
			() => {},
		);
		await expect(t.ensureAwake(() => {})).rejects.toThrow('SSM throttled');
		info = hostInfoFor('a.example.com');
		await t.ensureAwake(() => {});
		info = hostInfoFor('b.example.com');
		await t.ensureAwake(() => {});
	});

	test("the wake and the check share the caller's time limit", async () => {
		// The wake takes most of the limit on an injected clock. The check
		// gets what is left, with the caller's signal; without a limit it
		// gets none.
		for (const [limit, left] of [
			[10_000, 1_000],
			[undefined, undefined],
		] as const) {
			let clock = 0;
			const seen: Array<OperationOptions | undefined> = [];
			const inner = fakeInner(hostInfoFor('a.example.com'));
			inner.ensureAwake = async () => {
				clock += 9_000;
			};
			inner.describe = async (o) => {
				seen.push(o);
				return hostInfoFor('a.example.com');
			};
			const t = verifiedTransport(
				inner,
				{ name: 'target "x"', domain: 'a.example.com', oldDaemonOk: true },
				() => {},
				() => clock,
			);
			const stop = new AbortController();
			await t.ensureAwake(() => {}, { signal: stop.signal, timeoutMs: limit });
			expect(seen).toEqual([{ signal: stop.signal, timeoutMs: left }]);
		}
	});

	test('a wake that used up the limit fails as a wake timeout, before the check', async () => {
		let clock = 0;
		let describes = 0;
		const inner = fakeInner(hostInfoFor('a.example.com'));
		inner.ensureAwake = async () => {
			clock += 10_000;
		};
		inner.describe = async () => {
			describes += 1;
			return hostInfoFor('a.example.com');
		};
		const t = verifiedTransport(
			inner,
			{ name: 'target "x"', domain: 'a.example.com', oldDaemonOk: true },
			() => {},
			() => clock,
		);
		await expect(t.ensureAwake(() => {}, { timeoutMs: 10_000 })).rejects.toThrow(
			'the box did not come awake within 10 seconds',
		);
		expect(describes).toBe(0);
		// Not a verdict on the host: the next wake, with time to spare, checks.
		inner.ensureAwake = async () => {};
		await t.ensureAwake(() => {}, { timeoutMs: 10_000 });
		expect(describes).toBe(1);
	});

	test('passes the other methods through', async () => {
		const inner = fakeInner(hostInfoFor('a.example.com'));
		const t = verifiedTransport(
			inner,
			{ name: 'target "x"', domain: 'a.example.com', oldDaemonOk: true },
			() => {},
		);
		expect(await t.ctl(['ping'])).toEqual({ code: 0, stdout: '', stderr: '' });
		expect(await t.describe()).toEqual(hostInfoFor('a.example.com'));
		expect(inner.describes()).toBe(1);
	});
});

describe('transportFor', () => {
	test('builds the AWS transport from the target, with its profile and region', () => {
		const made: string[] = [];
		const target = {
			...AWS_TARGET,
			address: { scheme: 'https' as const, port: 443 },
			transport: { kind: 'aws-ssm' as const },
			power: { kind: 'ec2' as const },
			aws: { ...AWS_TARGET.aws, profile: 'other', region: 'eu-west-1' },
		};
		const t = transportFor(
			'x',
			target,
			(profile, region) => {
				made.push(`${profile}@${region}`);
				return koidClients(koidDeps({}));
			},
			() => {},
			{},
		);
		expect(made).toEqual(['other@eu-west-1']);
		expect(typeof t.streamLogs).toBe('function');
	});

	test('hands the power policy to the transport: always-on never starts the instance', async () => {
		const b = instanceBox('stopped');
		const t = transportFor(
			'boat',
			{
				...AWS_TARGET,
				address: { scheme: 'https' as const, port: 443 },
				transport: { kind: 'aws-ssm' as const },
				power: { kind: 'always-on' as const },
			},
			() => b.clients,
			() => {},
			{},
		);
		await expect(t.ensureAwake(() => {})).rejects.toThrow(
			'the instance i-0abc is stopped, and this target does not manage its power (power: always-on), so koi does not start it; its operator must',
		);
		expect(b.sent).toEqual(['DescribeInstancesCommand']);
	});
});

// An instance in `state` whose SSM agent is online and whose koid answers
// the ping. `sent` lists the AWS commands in order.
function instanceBox(state: string | undefined) {
	const sent: string[] = [];
	const send = async (cmd: { constructor: { name: string } }) => {
		sent.push(cmd.constructor.name);
		switch (cmd.constructor.name) {
			case 'DescribeInstancesCommand':
				return { Reservations: [{ Instances: [{ State: { Name: state } }] }] };
			case 'StartInstancesCommand':
				return {};
			case 'DescribeInstanceInformationCommand':
				return { InstanceInformationList: [{ PingStatus: 'Online' }] };
			case 'SendCommandCommand':
				return { Command: { CommandId: 'cmd-1' } };
			case 'GetCommandInvocationCommand':
				return { Status: 'Success', ResponseCode: 0, StandardOutputContent: '{"ok":true}\n' };
		}
		throw new Error(`unexpected ${cmd.constructor.name}`);
	};
	const client = { send } as never;
	return { sent, clients: { s3: client, ec2: client, ssm: client, sts: client } as Clients };
}

describe('awsTransport power', () => {
	test('always-on fails on an instance that is not running, without starting it', async () => {
		for (const state of ['stopped', 'stopping', 'shutting-down', 'terminated', undefined]) {
			const b = instanceBox(state);
			const t = awsTransport({ ...settings, power: 'always-on' }, b.clients, async () => {});
			await expect(t.ensureAwake(() => {})).rejects.toThrow(
				`the instance i-0abc is ${state ?? 'in an unknown state'}, and this target does not manage its power (power: always-on)`,
			);
			expect(b.sent).toEqual(['DescribeInstancesCommand']);
		}
	});

	test('always-on waits for a running or starting instance as usual', async () => {
		for (const state of ['running', 'pending']) {
			const b = instanceBox(state);
			const t = awsTransport({ ...settings, power: 'always-on' }, b.clients, async () => {});
			await t.ensureAwake(() => {});
			expect(b.sent).not.toContain('StartInstancesCommand');
			expect(b.sent).toContain('SendCommandCommand');
		}
	});

	test('ec2 power, and the default, start a stopped instance as before', async () => {
		for (const power of ['ec2', undefined] as const) {
			const b = instanceBox('stopped');
			const t = awsTransport(
				power === undefined ? settings : { ...settings, power },
				b.clients,
				async () => {},
			);
			const status: string[] = [];
			await t.ensureAwake((m) => status.push(m));
			expect(b.sent.slice(0, 2)).toEqual(['DescribeInstancesCommand', 'StartInstancesCommand']);
			expect(status).toEqual(['waking the box']);
		}
	});
});

const request: UpRequest = {
	version: 1,
	id: 'r'.repeat(16),
	label: 'hello-pr-7',
	project: 'hello',
	repo: 'github.com/acme/hello',
	commit: 'c'.repeat(40),
	branch: 'feature/x',
	pr: 7,
	dirty: false,
	recipe: { kind: 'repo', recipe: { port: 8080, build: { kind: 'dockerfile' } } },
	createdAt: '2026-10-06T00:00:00.000Z',
} as UpRequest;

describe('awsTransport upload and ensureAwake with options', () => {
	async function source(): Promise<string> {
		const path = join(await mkdtemp(join(tmpdir(), 'koi-upload-')), 'source.tar.gz');
		await writeFile(path, Buffer.alloc(1000, 'koi'));
		return path;
	}

	// S3 where every command hangs until the caller gives up.
	function hangingS3() {
		const names: string[] = [];
		const s3 = s3Stub((name) => {
			names.push(name);
			return new Promise(() => {});
		});
		const client = { send: async () => ({}) } as never;
		return { names, clients: { s3, ec2: client, ssm: client, sts: client } as Clients };
	}

	test('a time limit stops an upload that hangs, before the request is written', async () => {
		const h = hangingS3();
		const t = awsTransport(settings, h.clients);
		const began = Date.now();
		await expect(t.upload(request, await source(), { timeoutMs: 50 })).rejects.toThrow(
			'uploading the source of hello-pr-7 did not finish within 50 ms',
		);
		expect(Date.now() - began).toBeLessThan(5000);
		expect(h.names).toEqual(['PutObjectCommand']);
	});

	test('a signal stops an upload, with its own reason', async () => {
		const h = hangingS3();
		const t = awsTransport(settings, h.clients);
		const stop = new AbortController();
		const uploading = t.upload(request, await source(), { signal: stop.signal });
		while (h.names.length === 0) await Bun.sleep(1);
		stop.abort(new Error('the user pressed ctrl-c'));
		await expect(uploading).rejects.toThrow('the user pressed ctrl-c');
		expect(h.names).toEqual(['PutObjectCommand']);
		// Already aborted: nothing is sent at all.
		await expect(t.upload(request, await source(), { signal: stop.signal })).rejects.toThrow();
		expect(h.names).toEqual(['PutObjectCommand']);
	});

	// S3 that takes the source at once and answers the request's PutObject
	// as `hang` has it. `keys` lists what was put, in order.
	function slowRequestS3(hang: (opts?: { abortSignal?: AbortSignal }) => Promise<never>) {
		const keys: unknown[] = [];
		const s3 = s3Stub(async (_name, input, opts) => {
			keys.push(input.Key);
			if (input.Key === requestKey(request.id)) return hang(opts);
			return {};
		});
		const client = { send: async () => ({}) } as never;
		return { keys, clients: { s3, ec2: client, ssm: client, sts: client } as Clients };
	}

	test('a time limit ends a request PutObject that hangs, whether or not it answers the abort', async () => {
		for (const hang of [hangs, hangsForever]) {
			const h = slowRequestS3(hang);
			const t = awsTransport(settings, h.clients);
			const began = Date.now();
			await expect(t.upload(request, await source(), { timeoutMs: 50 })).rejects.toThrow(
				'uploading the source of hello-pr-7 did not finish within 50 ms',
			);
			expect(Date.now() - began).toBeLessThan(2000);
			expect(h.keys).toEqual([sourceKey(request.id), requestKey(request.id)]);
		}
	});

	test('a stop as the source finishes leaves the request unwritten and reports the stop', async () => {
		const stop = new AbortController();
		const keys: unknown[] = [];
		const s3 = s3Stub(async (_name, input) => {
			keys.push(input.Key);
			// The caller stops as S3 answers the last of the source.
			stop.abort(new Error('the user pressed ctrl-c'));
			return {};
		});
		const client = { send: async () => ({}) } as never;
		const t = awsTransport(settings, { s3, ec2: client, ssm: client, sts: client } as Clients);
		await expect(t.upload(request, await source(), { signal: stop.signal })).rejects.toThrow(
			'the user pressed ctrl-c',
		);
		expect(keys).toEqual([sourceKey(request.id)]);
	});

	test('a time limit that passes as the source finishes leaves the request unwritten', async () => {
		// On the injected clock, so that the source's PutObject is answered
		// after the limit passed rather than interrupted by it.
		let clock = 0;
		const keys: unknown[] = [];
		const s3 = s3Stub(async (_name, input) => {
			keys.push(input.Key);
			clock += 60_000;
			return {};
		});
		const client = { send: async () => ({}) } as never;
		const t = awsTransport(
			settings,
			{ s3, ec2: client, ssm: client, sts: client } as Clients,
			async () => {},
			() => clock,
		);
		await expect(t.upload(request, await source(), { timeoutMs: 30_000 })).rejects.toThrow(
			'uploading the source of hello-pr-7 did not finish within 30 seconds',
		);
		expect(keys).toEqual([sourceKey(request.id)]);
	});

	// A running instance whose SSM agent never reports online, on a clock
	// that `sleep` advances.
	function offlineBox() {
		let clock = 0;
		const sent: string[] = [];
		const send = async (cmd: { constructor: { name: string } }) => {
			sent.push(cmd.constructor.name);
			if (cmd.constructor.name === 'DescribeInstancesCommand') {
				return { Reservations: [{ Instances: [{ State: { Name: 'running' } }] }] };
			}
			if (cmd.constructor.name === 'DescribeInstanceInformationCommand') {
				return { InstanceInformationList: [] };
			}
			throw new Error(`unexpected ${cmd.constructor.name}`);
		};
		const client = { send } as never;
		const t = awsTransport(
			settings,
			{ s3: client, ec2: client, ssm: client, sts: client },
			async (ms) => {
				clock += ms;
			},
			() => clock,
		);
		return { t, sent, clock: () => clock };
	}

	test('a time limit stops the wake while SSM is still offline', async () => {
		const b = offlineBox();
		await expect(b.t.ensureAwake(() => {}, { timeoutMs: 12_000 })).rejects.toThrow(
			'the box did not come awake within 12 seconds',
		);
		expect(b.clock()).toBeGreaterThanOrEqual(12_000);
		expect(b.clock()).toBeLessThan(12_000 + 5000);
		expect(b.sent.filter((n) => n === 'DescribeInstanceInformationCommand')).toHaveLength(3);
	});

	test('a time limit bounds the wait for koid as well', async () => {
		// Online at once; koid never answers the ping.
		let clock = 0;
		const sent: string[] = [];
		const send = async (cmd: { constructor: { name: string } }) => {
			sent.push(cmd.constructor.name);
			switch (cmd.constructor.name) {
				case 'DescribeInstancesCommand':
					return { Reservations: [{ Instances: [{ State: { Name: 'running' } }] }] };
				case 'DescribeInstanceInformationCommand':
					return { InstanceInformationList: [{ PingStatus: 'Online' }] };
				case 'SendCommandCommand':
					return { Command: { CommandId: 'cmd-1' } };
				case 'GetCommandInvocationCommand':
					return {
						Status: 'Failed',
						ResponseCode: 3,
						StandardOutputContent: '',
						StandardErrorContent: 'koid ctl: cannot reach koid\n',
					};
			}
			throw new Error(`unexpected ${cmd.constructor.name}`);
		};
		const client = { send } as never;
		const t = awsTransport(
			settings,
			{ s3: client, ec2: client, ssm: client, sts: client },
			async (ms) => {
				clock += ms;
			},
			() => clock,
		);
		await expect(t.ensureAwake(() => {}, { timeoutMs: 10_000 })).rejects.toThrow(
			'the box did not come awake within 10 seconds',
		);
		expect(clock).toBeLessThan(20_000);
		expect(sent.filter((n) => n === 'SendCommandCommand').length).toBeGreaterThan(1);
	});

	// A box that is running and online, where the SSM or EC2 call named in
	// `hanging` never answers, as a dropped connection has it. Like the real
	// clients, the call ends with an AbortError once its abort signal fires;
	// without a signal it hangs for good, so a call made without one would
	// hang the test rather than pass it.
	function hangingBox(hanging: string, state = 'running', hang = hangs) {
		const sent: string[] = [];
		const send = async (
			cmd: { constructor: { name: string } },
			opts?: { abortSignal?: AbortSignal },
		) => {
			const name = cmd.constructor.name;
			sent.push(name);
			if (name === hanging) return hang(opts);
			switch (name) {
				case 'DescribeInstancesCommand':
					return { Reservations: [{ Instances: [{ State: { Name: state } }] }] };
				case 'StartInstancesCommand':
					return {};
				case 'DescribeInstanceInformationCommand':
					return { InstanceInformationList: [{ PingStatus: 'Online' }] };
				case 'SendCommandCommand':
					return { Command: { CommandId: 'cmd-1' } };
				case 'GetCommandInvocationCommand':
					return { Status: 'Success', ResponseCode: 0, StandardOutputContent: '{"ok":true}\n' };
			}
			throw new Error(`unexpected ${name}`);
		};
		const client = { send } as never;
		return { sent, clients: { s3: client, ec2: client, ssm: client, sts: client } as Clients };
	}

	test('a time limit on the wake stops a ping whose SSM call hangs', async () => {
		// Online at once; the ping's GetCommandInvocation never answers.
		const b = hangingBox('GetCommandInvocationCommand');
		const t = awsTransport(settings, b.clients, async () => {});
		const began = Date.now();
		await expect(t.ensureAwake(() => {}, { timeoutMs: 100 })).rejects.toThrow(
			'the box did not come awake within 100 ms',
		);
		expect(Date.now() - began).toBeGreaterThanOrEqual(90);
		expect(Date.now() - began).toBeLessThan(5000);
		expect(b.sent).toContain('SendCommandCommand');
		expect(b.sent).toContain('GetCommandInvocationCommand');
	});

	test('a time limit on the wake stops an EC2 or SSM call that hangs', async () => {
		for (const [hanging, state] of [
			['DescribeInstancesCommand', 'running'],
			['DescribeInstanceInformationCommand', 'running'],
			['SendCommandCommand', 'running'],
		] as const) {
			const b = hangingBox(hanging, state);
			const t = awsTransport(settings, b.clients, async () => {});
			const began = Date.now();
			await expect(t.ensureAwake(() => {}, { timeoutMs: 100 })).rejects.toThrow(
				'the box did not come awake within 100 ms',
			);
			expect(Date.now() - began).toBeGreaterThanOrEqual(90);
			expect(Date.now() - began).toBeLessThan(5000);
			expect(b.sent).toContain(hanging);
		}
	});

	test('a signal stops a wake whose call hangs, with its own reason', async () => {
		for (const hanging of [
			'DescribeInstancesCommand',
			'DescribeInstanceInformationCommand',
			'GetCommandInvocationCommand',
		]) {
			const b = hangingBox(hanging);
			const t = awsTransport(settings, b.clients, async () => {});
			const stop = new AbortController();
			const waking = t.ensureAwake(() => {}, { signal: stop.signal });
			while (!b.sent.includes(hanging)) await Bun.sleep(1);
			stop.abort(new Error('the user pressed ctrl-c'));
			await expect(waking).rejects.toThrow('the user pressed ctrl-c');
		}
	});

	test('an interrupted start of the instance is an unknown outcome, not a timeout', async () => {
		// The start may have reached EC2 and the box may be waking; a plain
		// timeout or cancellation would hide that from the caller. The same
		// whether the SDK honours the abort or not.
		for (const hang of [hangs, hangsForever]) {
			const b = hangingBox('StartInstancesCommand', 'stopped', hang);
			const t = awsTransport(settings, b.clients, async () => {});
			const began = Date.now();
			const err = await t.ensureAwake(() => {}, { timeoutMs: 100 }).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(UnknownOutcomeError);
			expect((err as Error).message).toBe(
				'the start of i-0abc may have reached EC2: koi stopped waiting for it to be accepted, so whether the box is waking is unknown',
			);
			expect(Date.now() - began).toBeGreaterThanOrEqual(90);
			expect(Date.now() - began).toBeLessThan(5000);
			expect(b.sent).toEqual(['DescribeInstancesCommand', 'StartInstancesCommand']);
		}
		// By the caller's signal as well.
		const b = hangingBox('StartInstancesCommand', 'stopped');
		const t = awsTransport(settings, b.clients, async () => {});
		const stop = new AbortController();
		const waking = t.ensureAwake(() => {}, { signal: stop.signal });
		while (!b.sent.includes('StartInstancesCommand')) await Bun.sleep(1);
		stop.abort(new Error('the user pressed ctrl-c'));
		await expect(waking).rejects.toBeInstanceOf(UnknownOutcomeError);
	});

	test('a wake call that never settles, not even on abort, still ends at the deadline', async () => {
		// The SDK does not watch the signal while it resolves credentials or
		// waits out a retry, so a call can ignore the abort for minutes. The
		// deadline holds regardless, and the call is left behind.
		for (const hanging of [
			'DescribeInstancesCommand',
			'DescribeInstanceInformationCommand',
			'SendCommandCommand',
			'GetCommandInvocationCommand',
		]) {
			const b = hangingBox(hanging, 'running', hangsForever);
			const t = awsTransport(settings, b.clients, async () => {});
			const began = Date.now();
			await expect(t.ensureAwake(() => {}, { timeoutMs: 100 })).rejects.toThrow(
				'the box did not come awake within 100 ms',
			);
			expect(Date.now() - began).toBeGreaterThanOrEqual(90);
			expect(Date.now() - began).toBeLessThan(5000);
			expect(b.sent).toContain(hanging);
		}
		// And at the caller's signal, with its reason.
		const b = hangingBox('DescribeInstancesCommand', 'running', hangsForever);
		const t = awsTransport(settings, b.clients, async () => {});
		const stop = new AbortController();
		const waking = t.ensureAwake(() => {}, { signal: stop.signal });
		while (!b.sent.includes('DescribeInstancesCommand')) await Bun.sleep(1);
		stop.abort(new Error('the user pressed ctrl-c'));
		await expect(waking).rejects.toThrow('the user pressed ctrl-c');
	});
});

const A = 'a'.repeat(20);
const B = 'b'.repeat(20);

describe('awsTransport describe', () => {
	test("returns koid's descriptor", async () => {
		const clients = koidClients(koidDeps({}));
		const t = awsTransport(settings, clients, async () => {});
		expect(await t.describe()).toEqual(hostInfoFor('previews.example.net'));
		expect(clients.commands).toEqual([['describe']]);
	});

	test('reports a koid without the command as a missing capability', async () => {
		const client = {
			send: async (cmd: { constructor: { name: string } }) =>
				cmd.constructor.name === 'SendCommandCommand'
					? { Command: { CommandId: 'c' } }
					: {
							Status: 'Failed',
							ResponseCode: 2,
							StandardOutputContent: '',
							StandardErrorContent: CTL_USAGE,
						},
		} as never;
		const t = awsTransport(
			settings,
			{ s3: client, ec2: client, ssm: client, sts: client },
			async () => {},
		);
		const err = await t.describe().catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnsupportedCapabilityError);
		expect((err as UnsupportedCapabilityError).capability).toBe('describe');
	});

	test('reports any other failure as what koid said', async () => {
		const clients = koidClients(
			koidDeps({
				describe: async () => {
					throw new Error('state directory unreadable');
				},
			}),
		);
		const t = awsTransport(settings, clients, async () => {});
		await expect(t.describe()).rejects.toThrow('state directory unreadable');
	});
});

describe('awsTransport streamLogs', () => {
	// koid as a build log stream meets it: the record at each status read,
	// and a real build log for attempt A. `records` gets each read's number
	// and a writer for another attempt's log, which replaces A's as a new
	// attempt on the box does. `clock` is the transport's sleep and clock;
	// by default waits are skipped and the clock is the real one.
	async function koid(
		records: (
			read: number,
			write: (attempt: string, lines: string[]) => Promise<void>,
		) => Promise<ReturnType<typeof previewRecord>> | ReturnType<typeof previewRecord>,
		clock: { sleep: (ms: number) => Promise<void>; now: () => number } = {
			sleep: async () => {},
			now: Date.now,
		},
	) {
		const logs = new BuildLogs(await mkdtemp(join(tmpdir(), 'koi-logs-')));
		const write = async (attempt: string, lines: string[]) => {
			const log = await logs.open('hello-pr-7', attempt);
			for (const line of lines) log.line(line);
			await log.close();
		};
		await write(A, ['step 1', 'step 2']);
		let reads = 0;
		const clients = koidClients(
			koidDeps({
				store: { get: async () => records(++reads, write), list: async () => [] },
				buildLogs: logs,
			}),
		);
		return {
			t: awsTransport(settings, clients, clock.sleep, clock.now),
			commands: clients.commands,
		};
	}

	// Without the timestamp koid writes before each line.
	const untimed = (e: LogEvent) =>
		e.type === 'line' ? { ...e, text: e.text.replace(/^\S+ /, '') } : e;

	async function collect(stream: AsyncIterable<LogEvent>): Promise<LogEvent[]> {
		const events: LogEvent[] = [];
		for await (const e of stream) events.push(untimed(e));
		return events;
	}

	test('follows the build through a new attempt to its end, with cursors', async () => {
		const k = await koid(async (read, write) => {
			if (read <= 2) return previewRecord({ attempt: A, status: 'building' });
			// koid starts attempt B, whose log replaces A's.
			if (read === 3) await write(B, ['b 1']);
			return previewRecord({ attempt: B, status: read <= 4 ? 'building' : 'running' });
		});
		expect(await collect(k.t.streamLogs({ label: 'hello-pr-7', kind: 'build' }))).toEqual([
			{ type: 'line', cursor: '0:1', text: 'step 1' },
			{ type: 'line', cursor: '0:2', text: 'step 2' },
			{
				type: 'gap',
				reason: 'koid is building hello-pr-7 again; its new build log follows from the start',
			},
			{ type: 'line', cursor: '0:1', text: 'b 1' },
			{ type: 'end' },
		]);
		expect(k.commands.map((c) => c.slice(0, 3))).toEqual([
			['status', 'hello-pr-7'],
			['status', 'hello-pr-7', A],
			['status', 'hello-pr-7', A],
			['status', 'hello-pr-7', B],
			['status', 'hello-pr-7', B],
		]);
	});

	test('resumes after the line a cursor came from', async () => {
		const k = await koid(() => previewRecord({ attempt: A, status: 'running' }));
		expect(
			await collect(
				k.t.streamLogs({ label: 'hello-pr-7', kind: 'build', attempt: A, cursor: '0:1' }),
			),
		).toEqual([{ type: 'line', cursor: '0:2', text: 'step 2' }, { type: 'end' }]);
		await expect(
			collect(k.t.streamLogs({ label: 'hello-pr-7', kind: 'build', attempt: A, cursor: 'x' })),
		).rejects.toThrow('"x" is not a build log cursor');
	});

	test('stops when a newer request took the label', async () => {
		const k = await koid(() =>
			previewRecord({ attempt: A, status: 'building', requestId: 'n'.repeat(16) }),
		);
		await expect(
			collect(k.t.streamLogs({ label: 'hello-pr-7', kind: 'build', requestId: 'o'.repeat(16) })),
		).rejects.toThrow('superseded by a newer koi up for hello-pr-7');
		const same = await koid(() =>
			previewRecord({ attempt: A, status: 'running', requestId: 'n'.repeat(16) }),
		);
		expect(
			await collect(
				same.t.streamLogs({ label: 'hello-pr-7', kind: 'build', requestId: 'n'.repeat(16) }),
			),
		).toHaveLength(3);
	});

	test('stops when koid no longer has the preview', async () => {
		const clients = koidClients(
			koidDeps({ store: { get: async () => undefined, list: async () => [] } }),
		);
		const t = awsTransport(settings, clients, async () => {});
		await expect(collect(t.streamLogs({ label: 'hello-pr-7', kind: 'build' }))).rejects.toThrow(
			'koid no longer has hello-pr-7; someone may have removed it with koi down',
		);
	});

	test('can be cancelled between polls', async () => {
		const k = await koid(() => previewRecord({ attempt: A, status: 'building' }));
		const stop = new AbortController();
		const events: LogEvent[] = [];
		const follow = async () => {
			const stream = k.t.streamLogs(
				{ label: 'hello-pr-7', kind: 'build' },
				{ signal: stop.signal },
			);
			for await (const e of stream) {
				events.push(e);
				if (events.length === 2) stop.abort();
			}
		};
		await expect(follow()).rejects.toThrow();
		expect(events).toHaveLength(2);
		expect(k.commands).toHaveLength(2);
	});

	test('a signal that fires during a status read ends the stream with an error', async () => {
		const stop = new AbortController();
		const k = await koid(() => {
			stop.abort();
			return previewRecord({ attempt: A, status: 'building' });
		});
		await expect(
			collect(k.t.streamLogs({ label: 'hello-pr-7', kind: 'build' }, { signal: stop.signal })),
		).rejects.toBeInstanceOf(UnknownOutcomeError);
		expect(k.commands).toHaveLength(1);
	});

	// What a stream ends with at its time limit.
	const atLimit = (limit: string): LogEvent[] => [
		{
			type: 'gap',
			reason: `stopped following hello-pr-7 at the ${limit} limit; the build log may go on`,
		},
		{ type: 'end' },
	];

	test('a time limit bounds the whole stream, which ends with a gap at the deadline', async () => {
		// A build that never finishes: every status read is in time, so only
		// a limit on the stream itself ends the follow.
		const k = await koid(() => previewRecord({ attempt: A, status: 'building' }));
		const began = Date.now();
		const events = await collect(
			k.t.streamLogs({ label: 'hello-pr-7', kind: 'build' }, { timeoutMs: 50 }),
		);
		expect(Date.now() - began).toBeGreaterThanOrEqual(40);
		expect(Date.now() - began).toBeLessThan(5000);
		expect(events).toEqual([
			{ type: 'line', cursor: '0:1', text: 'step 1' },
			{ type: 'line', cursor: '0:2', text: 'step 2' },
			...atLimit('50 ms'),
		]);
		expect(k.commands.length).toBeGreaterThan(2);
		// Without a limit the stream polls until the build finishes.
		const long = await koid((read) =>
			previewRecord({ attempt: A, status: read <= 20 ? 'building' : 'running' }),
		);
		expect(await collect(long.t.streamLogs({ label: 'hello-pr-7', kind: 'build' }))).toEqual([
			{ type: 'line', cursor: '0:1', text: 'step 1' },
			{ type: 'line', cursor: '0:2', text: 'step 2' },
			{ type: 'end' },
		]);
		expect(long.commands).toHaveLength(21);
	});

	test('a wait between reads is cut to what is left of the limit', async () => {
		let clock = 0;
		const k = await koid(() => previewRecord({ attempt: A, status: 'building' }), {
			sleep: async (ms) => {
				clock += ms;
			},
			now: () => clock,
		});
		expect(
			await collect(k.t.streamLogs({ label: 'hello-pr-7', kind: 'build' }, { timeoutMs: 5000 })),
		).toEqual([
			{ type: 'line', cursor: '0:1', text: 'step 1' },
			{ type: 'line', cursor: '0:2', text: 'step 2' },
			...atLimit('5 seconds'),
		]);
		// Reads at 0, 400 and 3800 ms. The last wait is cut from 3000 to 800
		// ms, which ends at the deadline, and no fourth read is sent.
		expect(k.commands).toHaveLength(3);
		expect(clock).toBe(5000);
	});

	test('a limit that passes during a status read ends the stream the same way', async () => {
		let clock = 0;
		const k = await koid(
			() => {
				clock += 2000;
				return previewRecord({ attempt: A, status: 'building' });
			},
			{ sleep: async () => {}, now: () => clock },
		);
		expect(
			await collect(k.t.streamLogs({ label: 'hello-pr-7', kind: 'build' }, { timeoutMs: 5000 })),
		).toEqual([
			{ type: 'line', cursor: '0:1', text: 'step 1' },
			{ type: 'line', cursor: '0:2', text: 'step 2' },
			...atLimit('5 seconds'),
		]);
		// The third read ran past the deadline, and koi stopped waiting for it.
		expect(k.commands).toHaveLength(3);
	});

	test('ends for a preview that was stopped or expired, once its log is drained', async () => {
		for (const status of ['stopped', 'expired'] as const) {
			const k = await koid(() => previewRecord({ attempt: A, status }));
			expect(await collect(k.t.streamLogs({ label: 'hello-pr-7', kind: 'build' }))).toEqual([
				{ type: 'line', cursor: '0:1', text: 'step 1' },
				{ type: 'line', cursor: '0:2', text: 'step 2' },
				{ type: 'end' },
			]);
			expect(k.commands).toHaveLength(3);
		}
	});

	test('does not follow a container log over SSM', () => {
		const t = awsTransport(settings, koidClients(koidDeps({})), async () => {});
		expect(() => t.streamLogs({ label: 'hello-pr-7', kind: 'runtime' })).toThrow(
			UnsupportedCapabilityError,
		);
	});
});

describe('awsTransport channel and close', () => {
	test('has no channel', async () => {
		const t = awsTransport(settings, koidClients(koidDeps({})), async () => {});
		const err = await t.openChannel().catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnsupportedCapabilityError);
		expect((err as UnsupportedCapabilityError).capability).toBe('duplex');
	});

	test('close destroys clients that can be destroyed, and tolerates fakes', async () => {
		let destroyed = 0;
		const client = {
			send: async () => ({}),
			destroy: () => {
				destroyed += 1;
			},
		} as never;
		await awsTransport(settings, { s3: client, ec2: client, ssm: client, sts: client }).close();
		expect(destroyed).toBe(4);
		await awsTransport(settings, koidClients(koidDeps({}))).close();
	});
});

describe('awsTransport ctl with options', () => {
	// SSM where every command stays in progress.
	function pending() {
		const sent: string[] = [];
		const client = {
			send: async (cmd: { constructor: { name: string } }) => {
				sent.push(cmd.constructor.name);
				return cmd.constructor.name === 'SendCommandCommand'
					? { Command: { CommandId: 'c-1' } }
					: { Status: 'InProgress' };
			},
		} as never;
		return { sent, clients: { s3: client, ec2: client, ssm: client, sts: client } as Clients };
	}

	test('an aborted signal sends nothing', async () => {
		const p = pending();
		const t = awsTransport(settings, p.clients, async () => {});
		const stop = new AbortController();
		stop.abort();
		await expect(t.ctl(['down', 'hello-pr-7'], { signal: stop.signal })).rejects.toThrow();
		expect(p.sent).toEqual([]);
	});

	test('stopping after the command was sent reports an unknown outcome', async () => {
		const p = pending();
		const stop = new AbortController();
		const t = awsTransport(settings, p.clients, async () => {
			stop.abort();
		});
		const err = await t
			.ctl(['down', 'hello-pr-7'], { signal: stop.signal })
			.catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect((err as Error).message).toContain('koid ctl down was sent to the box (SSM command c-1)');
		expect(p.sent).toEqual(['SendCommandCommand']);
	});

	test('a time limit after the command was sent reports an unknown outcome too', async () => {
		const p = pending();
		let clock = 0;
		const t = awsTransport(
			settings,
			p.clients,
			async (ms) => {
				clock += ms;
			},
			() => clock,
		);
		const err = await t.ctl(['up', 'r'.repeat(16)], { timeoutMs: 5000 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect(clock).toBeGreaterThanOrEqual(5000);
		expect(p.sent.filter((n) => n === 'GetCommandInvocationCommand').length).toBeLessThan(10);
	});

	// SSM where the command is accepted and the call named in `hanging`
	// never answers, until its abort signal fires.
	function hanging(hanging: string, hang = hangs) {
		const sent: string[] = [];
		const client = {
			send: async (
				cmd: { constructor: { name: string } },
				opts?: { abortSignal?: AbortSignal },
			) => {
				sent.push(cmd.constructor.name);
				if (cmd.constructor.name === hanging) return hang(opts);
				return cmd.constructor.name === 'SendCommandCommand'
					? { Command: { CommandId: 'c-1' } }
					: { Status: 'InProgress' };
			},
		} as never;
		return { sent, clients: { s3: client, ec2: client, ssm: client, sts: client } as Clients };
	}

	test('counts the calls it stopped waiting for, and no others', async () => {
		const before = abandonedCalls();
		const t = awsTransport(settings, koidClients(koidDeps({})), async () => {});
		expect((await t.ctl(['describe'], { timeoutMs: 5000 })).code).toBe(0);
		expect(abandonedCalls()).toBe(before);
		const h = hanging('GetCommandInvocationCommand', hangsForever);
		const slow = awsTransport(settings, h.clients, async () => {});
		await expect(slow.ctl(['down', 'hello-pr-7'], { timeoutMs: 100 })).rejects.toBeInstanceOf(
			UnknownOutcomeError,
		);
		expect(abandonedCalls()).toBe(before + 1);
	});

	test('a time limit ends a result call that hangs, with the outcome unknown', async () => {
		const h = hanging('GetCommandInvocationCommand');
		const t = awsTransport(settings, h.clients, async () => {});
		const began = Date.now();
		const err = await t.ctl(['down', 'hello-pr-7'], { timeoutMs: 100 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect((err as Error).message).toContain('koid ctl down was sent to the box (SSM command c-1)');
		expect(Date.now() - began).toBeGreaterThanOrEqual(90);
		expect(Date.now() - began).toBeLessThan(5000);
		expect(h.sent).toEqual(['SendCommandCommand', 'GetCommandInvocationCommand']);
	});

	test('a time limit ends a send that hangs; the command may have gone out', async () => {
		const h = hanging('SendCommandCommand');
		const t = awsTransport(settings, h.clients, async () => {});
		const began = Date.now();
		const err = await t.ctl(['down', 'hello-pr-7'], { timeoutMs: 100 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect((err as Error).message).toBe(
			'koid ctl down may have been sent to the box: koi stopped waiting for SSM to accept it, so its outcome is unknown',
		);
		expect(Date.now() - began).toBeGreaterThanOrEqual(90);
		expect(Date.now() - began).toBeLessThan(5000);
		expect(h.sent).toEqual(['SendCommandCommand']);
	});

	test('a signal ends a call that hangs after the command was sent', async () => {
		const h = hanging('GetCommandInvocationCommand');
		const t = awsTransport(settings, h.clients, async () => {});
		const stop = new AbortController();
		const running = t.ctl(['down', 'hello-pr-7'], { signal: stop.signal });
		while (!h.sent.includes('GetCommandInvocationCommand')) await Bun.sleep(1);
		stop.abort();
		const err = await running.catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect(h.sent).toEqual(['SendCommandCommand', 'GetCommandInvocationCommand']);
	});

	test('a call that never settles, not even on abort, still ends at the time limit', async () => {
		// The SDK does not watch the signal while it resolves credentials or
		// waits out a retry. The time limit holds regardless; the command may
		// have gone out either way, so the outcome is unknown.
		for (const name of ['SendCommandCommand', 'GetCommandInvocationCommand']) {
			const h = hanging(name, hangsForever);
			const t = awsTransport(settings, h.clients, async () => {});
			const began = Date.now();
			const err = await t.ctl(['down', 'hello-pr-7'], { timeoutMs: 100 }).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(UnknownOutcomeError);
			expect(Date.now() - began).toBeGreaterThanOrEqual(90);
			expect(Date.now() - began).toBeLessThan(5000);
			expect(h.sent.at(-1)).toBe(name);
		}
		// And at the caller's signal.
		const h = hanging('GetCommandInvocationCommand', hangsForever);
		const t = awsTransport(settings, h.clients, async () => {});
		const stop = new AbortController();
		const running = t.ctl(['down', 'hello-pr-7'], { signal: stop.signal });
		while (!h.sent.includes('GetCommandInvocationCommand')) await Bun.sleep(1);
		stop.abort();
		await expect(running).rejects.toBeInstanceOf(UnknownOutcomeError);
	});
});

// An SDK call that never answers and, as the real clients do, rejects with an
// AbortError once its abort signal fires. Without a signal it hangs for good.
function hangs(opts?: { abortSignal?: AbortSignal }): Promise<never> {
	return new Promise((_, reject) => {
		const signal = opts?.abortSignal;
		const abort = () => reject(Object.assign(new Error('Request aborted'), { name: 'AbortError' }));
		if (signal?.aborted) abort();
		else signal?.addEventListener('abort', abort, { once: true });
	});
}

// An SDK call that never answers and ignores its abort signal, as the real
// clients do while they resolve credentials or wait out a retry.
function hangsForever(): Promise<never> {
	return new Promise(() => {});
}
