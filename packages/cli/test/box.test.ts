import { describe, expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	decodeCtlArgs,
	NO_SUCH_PREVIEW,
	RepoRecipeSchema,
	type UpRequest,
	UpRequestSchema,
} from '@koi/shared';
import type { Clients } from '../src/box.ts';
import {
	awsBox,
	BoxUnavailableError,
	ctlCommand,
	resolveSettings,
	type Settings,
} from '../src/box.ts';
import { exec } from '../src/exec.ts';
import * as transport from '../src/transport.ts';
import * as aws from '../src/transports/aws.ts';
import { koidClients, koidDeps, s3Stub } from './koid.ts';

describe('box.ts', () => {
	test('keeps the old names for what moved to transport.ts and transports/aws.ts', () => {
		expect(awsBox).toBe(aws.awsTransport);
		expect(resolveSettings).toBe(aws.resolveSettings);
		expect(ctlCommand).toBe(aws.ctlCommand);
		expect(BoxUnavailableError).toBe(transport.BoxUnavailableError);
	});
});

// Shell metacharacters, quotes, a newline and text outside ASCII.
const NASTY = `x'; rm -rf / $(id) \`id\` "q" \\ | & > < * ?\n é😀`;

// The arguments in an SSM command from ctlCommand, as koid decodes them.
function sentArgs(command: string | undefined): string[] {
	return decodeCtlArgs((command ?? '').split(' ')[2] ?? '');
}

describe('ctlCommand', () => {
	test('sends the arguments as base64 that koid decodes to the same list', () => {
		for (const args of [
			['up', 'abcdefghij0123456'],
			['status', NASTY, '-rf', ''],
		]) {
			const command = ctlCommand(args);
			expect(command).toMatch(/^\/usr\/local\/bin\/koid ctl-b64 [A-Za-z0-9+/]+=*$/);
			expect(sentArgs(command)).toEqual(args);
		}
	});

	test('a shell reads the command as three words with the blob intact', async () => {
		const command = ctlCommand(['status', NASTY]);
		const r = await exec(['sh', '-c', `set -- ${command}; printf '%s\\0' "$@"`]);
		expect(r.code).toBe(0);
		expect(r.stdout.split('\0').slice(0, -1)).toEqual(command.split(' '));
	});
});

// EC2 and STS as resolveSettings sees them: the boxes DescribeInstances
// returns, each tagged with the preview domain as infra/modules/koi tags it
// (no tag when domain is null), and with koi:bucket when bucket is set. With
// only = 'koi:role' or 'Project', a query by tags answers only when it asks
// for that tag, as for a box that has only the one or only the other. legacy
// names boxes that only a query by Project finds, next to those in instances.
// Every DescribeInstances input lands in described.
function fakeClients(
	instances: string[],
	{
		account = '123456789012',
		domain = 'previews.example.com' as string | null,
		bucket = undefined as string | undefined,
		described = [] as unknown[],
		only = undefined as 'koi:role' | 'Project' | undefined,
		legacy = [] as string[],
	} = {},
): Clients {
	const send = async (cmd: { constructor: { name: string }; input: unknown }) => {
		if (cmd.constructor.name === 'DescribeInstancesCommand') {
			described.push(cmd.input);
			const input = cmd.input as { Filters?: Array<{ Name: string }> };
			const asks = (input.Filters ?? []).map((f) => f.Name);
			if (only !== undefined && input.Filters !== undefined && !asks.includes(`tag:${only}`)) {
				return { Reservations: [] };
			}
			const Tags = [
				...(domain === null ? [] : [{ Key: 'Domain', Value: domain }]),
				...(bucket === undefined ? [] : [{ Key: 'koi:bucket', Value: bucket }]),
			];
			const ids = asks.includes('tag:Project') ? [...instances, ...legacy] : instances;
			return {
				Reservations: [{ Instances: ids.map((InstanceId) => ({ InstanceId, Tags })) }],
			};
		}
		if (cmd.constructor.name === 'GetCallerIdentityCommand') return { Account: account };
		throw new Error(`unexpected ${cmd.constructor.name}`);
	};
	const client = { send } as never;
	return { s3: client, ec2: client, ssm: client, sts: client };
}

describe('resolveSettings', () => {
	test('discovers the box by tag, the domain from its Domain tag and the bucket from the account', async () => {
		const { settings } = await resolveSettings({}, () => fakeClients(['i-0abc']));
		expect(settings).toEqual({
			profile: 'koi-cli',
			region: 'us-east-1',
			domain: 'previews.example.com',
			instanceId: 'i-0abc',
			bucket: 'koi-uploads-123456789012',
		});
	});

	test('finds the box by koi:role, whatever Project says', async () => {
		const { settings } = await resolveSettings({}, () =>
			fakeClients(['i-0abc'], { only: 'koi:role' }),
		);
		expect(settings.instanceId).toBe('i-0abc');
	});

	test('counts a box that has both koi:role and Project=koi once', async () => {
		const { settings } = await resolveSettings({}, () => fakeClients(['i-0abc']));
		expect(settings.instanceId).toBe('i-0abc');
	});

	test('refuses to pick between a koi:role box and an older box found by Project', async () => {
		await expect(
			resolveSettings({}, () => fakeClients(['i-0new'], { legacy: ['i-0old'] })),
		).rejects.toThrow(/expected one koi box, found 2; set KOI_INSTANCE_ID/);
	});

	test('reads the bucket tag of the box KOI_INSTANCE_ID names, with the domain given', async () => {
		const described: unknown[] = [];
		const { settings } = await resolveSettings(
			{ KOI_INSTANCE_ID: 'i-1', KOI_DOMAIN: 'example.dev' },
			() => fakeClients(['i-1'], { described, bucket: 'acme-koi-uploads-123456789012' }),
		);
		expect(settings.bucket).toBe('acme-koi-uploads-123456789012');
		expect(settings.domain).toBe('example.dev');
		expect(described).toEqual([{ InstanceIds: ['i-1'] }]);
	});

	test("reads the bucket from the box's koi:bucket tag, which carries the module's prefix", async () => {
		const { settings } = await resolveSettings({}, () =>
			fakeClients(['i-0abc'], { bucket: 'acme-koi-uploads-123456789012' }),
		);
		expect(settings.bucket).toBe('acme-koi-uploads-123456789012');
	});

	test('finds a box applied before koi:role by Project and Name', async () => {
		const described: unknown[] = [];
		const { settings } = await resolveSettings({}, () =>
			fakeClients(['i-0old'], { described, only: 'Project' }),
		);
		expect(settings.instanceId).toBe('i-0old');
		expect(settings.domain).toBe('previews.example.com');
		expect(described).toEqual([
			{
				Filters: [
					{ Name: 'tag:koi:role', Values: ['box'] },
					{ Name: 'instance-state-name', Values: ['pending', 'running', 'stopping', 'stopped'] },
				],
			},
			{
				Filters: [
					{ Name: 'tag:Project', Values: ['koi'] },
					{ Name: 'tag:Name', Values: ['koi-box'] },
					{ Name: 'instance-state-name', Values: ['pending', 'running', 'stopping', 'stopped'] },
				],
			},
		]);
	});

	test('reads the domain from the box KOI_INSTANCE_ID names', async () => {
		const described: unknown[] = [];
		const { settings } = await resolveSettings({ KOI_INSTANCE_ID: 'i-1' }, () =>
			fakeClients(['i-1'], { described }),
		);
		expect(settings.instanceId).toBe('i-1');
		expect(settings.domain).toBe('previews.example.com');
		expect(described).toEqual([{ InstanceIds: ['i-1'] }]);
	});

	test('refuses to guess the domain when the box has no Domain tag', async () => {
		await expect(
			resolveSettings({}, () => fakeClients(['i-0abc'], { domain: null })),
		).rejects.toThrow(/no Domain tag.*KOI_DOMAIN/);
	});

	test('uses overrides from the environment and asks AWS nothing', async () => {
		// Every client refuses every call, so any request at all fails the test,
		// not only the DescribeInstances the fake above would answer.
		const refuse = {
			send: async (cmd: { constructor: { name: string } }) => {
				throw new Error(`unexpected ${cmd.constructor.name}`);
			},
		} as never;
		const { settings } = await resolveSettings(
			{
				KOI_AWS_PROFILE: 'other',
				KOI_INSTANCE_ID: 'i-1',
				KOI_BUCKET: 'b',
				KOI_DOMAIN: 'example.dev',
			},
			() => ({ s3: refuse, ec2: refuse, ssm: refuse, sts: refuse }),
		);
		expect(settings).toEqual({
			profile: 'other',
			region: 'us-east-1',
			domain: 'example.dev',
			instanceId: 'i-1',
			bucket: 'b',
		});
	});

	test('refuses to guess between several boxes, or none', async () => {
		await expect(resolveSettings({}, () => fakeClients(['i-1', 'i-2']))).rejects.toThrow(
			/expected one koi box, found 2/,
		);
		await expect(resolveSettings({}, () => fakeClients([]))).rejects.toThrow(/found 0/);
	});
});

const settings: Settings = {
	profile: 'koi-cli',
	region: 'us-east-1',
	domain: 'previews.example.net',
	instanceId: 'i-0abc',
	bucket: 'koi-uploads-123456789012',
};

// SSM that runs every command at once and answers with the given output.
function fakeSsm(stdout: string) {
	const sent: Array<{ name: string; input: unknown }> = [];
	const send = async (cmd: { constructor: { name: string }; input: unknown }) => {
		sent.push({ name: cmd.constructor.name, input: cmd.input });
		if (cmd.constructor.name === 'SendCommandCommand') return { Command: { CommandId: 'cmd-1' } };
		if (cmd.constructor.name === 'GetCommandInvocationCommand') {
			return {
				Status: 'Success',
				ResponseCode: 0,
				StandardOutputContent: stdout,
				StandardErrorContent: '',
			};
		}
		throw new Error(`unexpected ${cmd.constructor.name}`);
	};
	const client = { send } as never;
	return { clients: { s3: client, ec2: client, ssm: client, sts: client } as Clients, sent };
}

describe('awsBox ctl', () => {
	test('returns what koid ctl printed', async () => {
		const reply = JSON.stringify({ record: 'x'.repeat(23_000) });
		const { clients, sent } = fakeSsm(reply);
		const box = awsBox(settings, clients, async () => {});
		expect(await box.ctl(['status', 'hello-pr-7', '0'])).toEqual({
			code: 0,
			stdout: reply,
			stderr: '',
		});
		const input = sent[0]?.input as { Parameters: { commands: string[] } };
		expect(input.Parameters.commands).toHaveLength(1);
		expect(sentArgs(input.Parameters.commands[0])).toEqual(['status', 'hello-pr-7', '0']);
	});

	test('a value with shell metacharacters reaches koid unchanged, and koid refuses it', async () => {
		const clients = koidClients(koidDeps({}));
		const box = awsBox(settings, clients, async () => {});
		const r = await box.ctl(['status', NASTY]);
		expect(clients.commands).toEqual([['status', NASTY]]);
		expect(r.code).toBe(2);
		expect(r.stdout).toBe('');
		expect(r.stderr).toContain('koid ctl:');
	});

	test('tells failures that can pass from those that cannot', async () => {
		const sdkError = (name: string, extra: object = {}) =>
			Object.assign(new Error(`${name} happened`), { name, ...extra });
		const cases: Array<[Error, boolean]> = [
			[sdkError('InvalidInstanceId'), true],
			[sdkError('ThrottlingException', { $retryable: { throttling: true } }), true],
			[sdkError('InternalServerError', { $fault: 'server' }), true],
			[sdkError('Error', { code: 'ECONNRESET' }), true],
			[sdkError('AccessDeniedException', { $fault: 'client' }), false],
			[sdkError('ValidationException', { $fault: 'client' }), false],
		];
		for (const [err, passes] of cases) {
			const client = {
				send: async () => {
					throw err;
				},
			} as never;
			const box = awsBox(settings, { s3: client, ec2: client, ssm: client, sts: client });
			const thrown = await box.ctl(['ping']).catch((e: unknown) => e);
			expect(thrown instanceof BoxUnavailableError).toBe(passes);
			expect((thrown as Error).message).toBe(`${err.name} happened`);
		}
	});

	test('reports a command SSM did not run to the end as one that can pass', async () => {
		for (const out of [
			{ Status: 'TimedOut', StatusDetails: 'ExecutionTimedOut' },
			{ Status: 'Cancelled' },
			{ Status: 'Failed', ResponseCode: -1 },
		]) {
			const client = {
				send: async (cmd: { constructor: { name: string } }) =>
					cmd.constructor.name === 'SendCommandCommand' ? { Command: { CommandId: 'c' } } : out,
			} as never;
			const box = awsBox(
				settings,
				{ s3: client, ec2: client, ssm: client, sts: client },
				async () => {},
			);
			const thrown = await box.ctl(['status', 'hello-pr-7']).catch((e: unknown) => e);
			expect(thrown).toBeInstanceOf(BoxUnavailableError);
			expect((thrown as Error).message).toStartWith('SSM reports koid ctl status as');
		}
	});

	test("returns koid ctl's own exit status", async () => {
		const client = {
			send: async (cmd: { constructor: { name: string } }) =>
				cmd.constructor.name === 'SendCommandCommand'
					? { Command: { CommandId: 'c' } }
					: { Status: 'Failed', ResponseCode: 3, StandardErrorContent: 'cannot reach koid' },
		} as never;
		const box = awsBox(
			settings,
			{ s3: client, ec2: client, ssm: client, sts: client },
			async () => {},
		);
		expect(await box.ctl(['ping'])).toEqual({ code: 3, stdout: '', stderr: 'cannot reach koid' });
	});

	test("drops the status line SSM adds to a failed command's standard error", async () => {
		const client = {
			send: async (cmd: { constructor: { name: string } }) =>
				cmd.constructor.name === 'SendCommandCommand'
					? { Command: { CommandId: 'c' } }
					: {
							Status: 'Failed',
							ResponseCode: 1,
							StandardErrorContent:
								'{"error":"no such preview"}\nfailed to run commands: exit status 1',
						},
		} as never;
		const box = awsBox(
			settings,
			{ s3: client, ec2: client, ssm: client, sts: client },
			async () => {},
		);
		const r = await box.ctl(['status', 'hello-pr-7']);
		expect(r).toEqual({ code: 1, stdout: '', stderr: '{"error":"no such preview"}' });
		expect(transport.ctlErrorText(r)).toBe(NO_SUCH_PREVIEW);
	});

	test('refuses output that SSM cut at 24,000 characters', async () => {
		// The first 24,000 characters of a longer JSON reply: not valid JSON.
		const cut = JSON.stringify({ record: 'x'.repeat(30_000) }).slice(0, 24_000);
		const box = awsBox(settings, fakeSsm(cut).clients, async () => {});
		await expect(box.ctl(['list'])).rejects.toThrow(/koid ctl list was cut off by SSM/);
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
	recipe: {
		kind: 'repo',
		recipe: RepoRecipeSchema.parse({ port: 8080, build: { kind: 'dockerfile' } }),
	},
	createdAt: '2026-10-06T00:00:00.000Z',
};

// A tarball of `size` bytes, and its content.
async function tarball(size: number): Promise<{ path: string; content: Buffer }> {
	const path = join(await mkdtemp(join(tmpdir(), 'koi-upload-')), 'source.tar.gz');
	const content = Buffer.alloc(size, 'koi');
	await writeFile(path, content);
	return { path, content };
}

// S3 as awsBox uploads to it: each command in order, with what it wrote. A
// command named in `fail` throws.
function uploadBox(fail?: string) {
	const sent: Array<{ name: string; bucket: unknown; key: unknown; body?: Buffer }> = [];
	const parts = new Map<number, Buffer>();
	const s3 = s3Stub(async (name, input) => {
		const body = input.Body as Uint8Array | string | undefined;
		sent.push({
			name,
			bucket: input.Bucket,
			key: input.Key,
			...(body !== undefined ? { body: Buffer.from(body) } : {}),
		});
		if (name === fail) throw Object.assign(new Error('Access Denied'), { name: 'AccessDenied' });
		if (name === 'CreateMultipartUploadCommand') return { UploadId: 'u-1' };
		if (name === 'UploadPartCommand') {
			parts.set(input.PartNumber as number, Buffer.from(body ?? ''));
			return { ETag: `"${input.PartNumber}"` };
		}
		return {};
	});
	const box = awsBox(settings, { ...fakeSsm('').clients, s3 }, async () => {});
	// The source as S3 holds it: from one PutObject, or from its parts.
	const source = () => {
		const put = sent.find((c) => c.name === 'PutObjectCommand' && c.key === sourceKey);
		if (put !== undefined) return put.body;
		return Buffer.concat([...parts.entries()].sort(([a], [b]) => a - b).map(([, part]) => part));
	};
	return { box, sent, source };
}

const sourceKey = `sources/${request.id}.tar.gz`;
const requestKey = `requests/${request.id}.json`;

describe('awsBox upload', () => {
	test('uploads the source, then the request that names it', async () => {
		const { path, content } = await tarball(100_000);
		const u = uploadBox();
		await u.box.upload(request, path);
		expect(u.sent.map((c) => [c.name, c.bucket, c.key])).toEqual([
			['PutObjectCommand', settings.bucket, sourceKey],
			['PutObjectCommand', settings.bucket, requestKey],
		]);
		expect(u.source()?.equals(content)).toBe(true);
		const sentRequest = u.sent[1]?.body?.toString() ?? '';
		expect(UpRequestSchema.parse(JSON.parse(sentRequest))).toEqual(request);
	});

	test('finishes every part of a large source before the request', async () => {
		// More than one 16 MiB part.
		const { path, content } = await tarball(17 * 1024 * 1024);
		const u = uploadBox();
		await u.box.upload(request, path);
		const names = u.sent.map((c) => c.name);
		expect(names[0]).toBe('CreateMultipartUploadCommand');
		expect(names.filter((n) => n === 'UploadPartCommand')).toHaveLength(2);
		expect(names.slice(-2)).toEqual(['CompleteMultipartUploadCommand', 'PutObjectCommand']);
		expect(u.sent.at(-1)?.key).toBe(requestKey);
		expect(u.source()?.equals(content)).toBe(true);
	});

	test('a failed source upload stops before the request', async () => {
		for (const [size, fail] of [
			[100_000, 'PutObjectCommand'],
			[17 * 1024 * 1024, 'UploadPartCommand'],
		] as const) {
			const { path } = await tarball(size);
			const u = uploadBox(fail);
			await expect(u.box.upload(request, path)).rejects.toThrow('Access Denied');
			expect(u.sent.map((c) => c.key)).not.toContain(requestKey);
		}
	});
});

// A box whose EC2 state is the next of `states` at each DescribeInstances,
// whose SSM agent reports online from the `online`-th check, and whose koid
// answers the first ping. `sent` lists the AWS commands in order.
function wakeBox(states: string[], online = 1) {
	const sent: string[] = [];
	const started: unknown[] = [];
	const sleeps: number[] = [];
	let checks = 0;
	const send = async (cmd: { constructor: { name: string }; input: unknown }) => {
		const name = cmd.constructor.name;
		sent.push(name);
		switch (name) {
			case 'DescribeInstancesCommand': {
				const state = states.length > 1 ? states.shift() : states[0];
				return { Reservations: [{ Instances: [{ State: { Name: state } }] }] };
			}
			case 'StartInstancesCommand':
				started.push(cmd.input);
				return {};
			case 'DescribeInstanceInformationCommand':
				checks += 1;
				return { InstanceInformationList: checks >= online ? [{ PingStatus: 'Online' }] : [] };
			case 'SendCommandCommand':
				return { Command: { CommandId: 'cmd-1' } };
			case 'GetCommandInvocationCommand':
				return { Status: 'Success', ResponseCode: 0, StandardOutputContent: '{"ok":true}\n' };
		}
		throw new Error(`unexpected ${name}`);
	};
	const client = { send } as never;
	const box = awsBox(
		settings,
		{ s3: client, ec2: client, ssm: client, sts: client },
		async (ms) => {
			sleeps.push(ms);
		},
	);
	return { box, sent, started, sleeps };
}

describe('awsBox ensureAwake from sleep', () => {
	test('starts a stopped box, then waits for SSM and koid', async () => {
		const b = wakeBox(['stopped'], 3);
		const status: string[] = [];
		await b.box.ensureAwake((m) => status.push(m));
		expect(b.started).toEqual([{ InstanceIds: [settings.instanceId] }]);
		expect(b.sent).toEqual([
			'DescribeInstancesCommand',
			'StartInstancesCommand',
			'DescribeInstanceInformationCommand',
			'DescribeInstanceInformationCommand',
			'DescribeInstanceInformationCommand',
			'SendCommandCommand',
			'GetCommandInvocationCommand',
		]);
		expect(status).toEqual(['waking the box']);
	});

	test('waits for a stopping box to stop, then starts it', async () => {
		const b = wakeBox(['stopping', 'stopping', 'stopped']);
		const status: string[] = [];
		await b.box.ensureAwake((m) => status.push(m));
		expect(b.sent.slice(0, 4)).toEqual([
			'DescribeInstancesCommand',
			'DescribeInstancesCommand',
			'DescribeInstancesCommand',
			'StartInstancesCommand',
		]);
		expect(b.started).toEqual([{ InstanceIds: [settings.instanceId] }]);
		expect(b.sleeps.slice(0, 2)).toEqual([5000, 5000]);
		expect(status).toEqual(['the box is stopping; waiting to start it again', 'waking the box']);
	});

	test('does not start a box that is running or already starting', async () => {
		for (const state of ['running', 'pending']) {
			const b = wakeBox([state]);
			await b.box.ensureAwake(() => {});
			expect(b.started).toEqual([]);
		}
	});
});

// A running box whose SSM agent is online, where each `koid ctl ping` gets the
// next scripted reply: a command result, or an error SendCommand throws.
function pingBox(replies: Array<{ code: number; stdout: string; stderr?: string } | Error>) {
	let clock = 0;
	const sleeps: number[] = [];
	const pings: string[][] = [];
	let reply: { code: number; stdout: string; stderr?: string } | undefined;
	const send = async (cmd: { constructor: { name: string }; input: unknown }) => {
		const input = cmd.input as { Parameters?: { commands?: string[] } };
		switch (cmd.constructor.name) {
			case 'DescribeInstancesCommand':
				return { Reservations: [{ Instances: [{ State: { Name: 'running' } }] }] };
			case 'DescribeInstanceInformationCommand':
				return { InstanceInformationList: [{ PingStatus: 'Online' }] };
			case 'SendCommandCommand': {
				pings.push(input.Parameters?.commands ?? []);
				const next = replies.length > 1 ? replies.shift() : replies[0];
				if (next instanceof Error) throw next;
				reply = next;
				return { Command: { CommandId: `cmd-${pings.length}` } };
			}
			case 'GetCommandInvocationCommand':
				return {
					Status: reply?.code === 0 ? 'Success' : 'Failed',
					ResponseCode: reply?.code,
					StandardOutputContent: reply?.stdout,
					StandardErrorContent: reply?.stderr ?? '',
				};
		}
		throw new Error(`unexpected ${cmd.constructor.name}`);
	};
	const client = { send } as never;
	const box = awsBox(
		settings,
		{ s3: client, ec2: client, ssm: client, sts: client },
		async (ms) => {
			sleeps.push(ms);
			clock += ms;
		},
		() => clock,
	);
	return { box, sleeps, pings, clock: () => clock };
}

function invalidInstance(): Error {
	const err = new Error('Instances [[i-0abc]] not in a valid state for account');
	err.name = 'InvalidInstanceId';
	return err;
}

const OK = { code: 0, stdout: '{"ok":true}\n' };
const DOWN = { code: 3, stdout: '', stderr: 'koid ctl: cannot reach koid: ENOENT\n' };

describe('awsBox ensureAwake', () => {
	test('asks koid for a ping once SSM reports the box online', async () => {
		const b = pingBox([OK]);
		const status: string[] = [];
		await b.box.ensureAwake((m) => status.push(m));
		expect(b.pings).toEqual([[ctlCommand(['ping'])]]);
		expect(status).toEqual([]);
	});

	test('retries the ping every 3 seconds until koid answers', async () => {
		const b = pingBox([invalidInstance(), DOWN, DOWN, OK]);
		const status: string[] = [];
		await b.box.ensureAwake((m) => status.push(m));
		expect(b.pings).toHaveLength(4);
		expect(b.sleeps.filter((ms) => ms === 3000)).toHaveLength(3);
		expect(status).toEqual(['waiting for koid on the box to start']);
	});

	test('gives up after five minutes, saying why', async () => {
		const b = pingBox([DOWN]);
		await expect(b.box.ensureAwake(() => {})).rejects.toThrow(
			'koid on the box did not answer within 5 minutes: koid ctl: cannot reach koid: ENOENT',
		);
		expect(b.clock()).toBeGreaterThanOrEqual(5 * 60_000);
		expect(b.clock()).toBeLessThan(5 * 60_000 + 10_000);
	});

	test('does not retry an error that waiting will not fix', async () => {
		const denied = new Error('not authorized to perform ssm:SendCommand');
		denied.name = 'AccessDeniedException';
		const b = pingBox([denied]);
		await expect(b.box.ensureAwake(() => {})).rejects.toThrow(/not authorized/);
		expect(b.pings).toHaveLength(1);
	});
});
