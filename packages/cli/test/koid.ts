import { S3Client } from '@aws-sdk/client-s3';
import { decodeCtlArgs, type HostInfo, type PreviewRecord } from '@koi/shared';
import { type ControlDeps, control } from '../../daemon/src/control.ts';
import { ctlEncoded } from '../../daemon/src/ctl.ts';
import type { Clients, Settings } from '../src/box.ts';

// GetCommandInvocation returns at most this much of a command's stdout.
const SSM_STDOUT_LIMIT = 24_000;

export const settings: Settings = {
	profile: 'koi-cli',
	region: 'us-east-1',
	domain: 'previews.example.net',
	instanceId: 'i-0abc',
	bucket: 'koi-uploads-123456789012',
};

// AWS clients for a running box whose SSM agent is online, where each SSM
// command runs the real koid ctl and control API in this process, with
// `deps` behind them. GetCommandInvocation returns what koid ctl printed as
// SSM does: at most its first 24,000 characters. `commands` lists the koid
// ctl arguments of each command as koid decoded them, and `outputs` what each
// printed on stdout.
export function koidClients(
	deps: ControlDeps,
): Clients & { commands: string[][]; outputs: string[] } {
	const commands: string[][] = [];
	const outputs: string[] = [];
	const results = new Map<string, { code: number; stdout: string; stderr: string }>();
	const send = async (cmd: { constructor: { name: string }; input: unknown }) => {
		const input = cmd.input as { CommandId?: string; Parameters?: { commands?: string[] } };
		switch (cmd.constructor.name) {
			case 'DescribeInstancesCommand':
				return { Reservations: [{ Instances: [{ State: { Name: 'running' } }] }] };
			case 'DescribeInstanceInformationCommand':
				return { InstanceInformationList: [{ PingStatus: 'Online' }] };
			case 'SendCommandCommand': {
				// "/usr/local/bin/koid ctl-b64 <blob>", run as koid's entry point
				// runs it.
				const [program, command, ...words] = (input.Parameters?.commands?.[0] ?? '').split(' ');
				if (program !== '/usr/local/bin/koid' || command !== 'ctl-b64') {
					throw new Error(`not a koid ctl-b64 command: ${input.Parameters?.commands?.[0]}`);
				}
				commands.push(decodeCtlArgs(words[0] ?? ''));
				let stdout = '';
				let stderr = '';
				const code = await ctlEncoded(words, {
					stdout: (t) => {
						stdout += t;
					},
					stderr: (t) => {
						stderr += t;
					},
					fetch: (path, init) => control(new Request(`http://koid${path}`, init), deps),
				});
				outputs.push(stdout);
				const id = `cmd-${commands.length}`;
				results.set(id, { code, stdout: stdout.slice(0, SSM_STDOUT_LIMIT), stderr });
				return { Command: { CommandId: id } };
			}
			case 'GetCommandInvocationCommand': {
				const r = results.get(input.CommandId ?? '');
				if (r === undefined) throw new Error(`no command ${input.CommandId}`);
				return {
					Status: r.code === 0 ? 'Success' : 'Failed',
					ResponseCode: r.code,
					StandardOutputContent: r.stdout,
					StandardErrorContent: r.stderr,
				};
			}
		}
		throw new Error(`unexpected ${cmd.constructor.name}`);
	};
	const client = { send } as never;
	return { s3: client, ec2: client, ssm: client, sts: client, commands, outputs };
}

// A real S3 client whose commands go to `handle` instead of AWS, with the
// options of the send, which carry the abort signal. The upload helper reads
// the client's configuration, so a bare { send } will not do.
export function s3Stub(
	handle: (
		name: string,
		input: Record<string, unknown>,
		opts?: { abortSignal?: AbortSignal },
	) => Promise<unknown>,
): S3Client {
	const s3 = new S3Client({
		region: 'us-east-1',
		credentials: { accessKeyId: 'AKIDTEST', secretAccessKey: 'test' },
	});
	s3.send = (async (
		cmd: { constructor: { name: string }; input: Record<string, unknown> },
		opts?: { abortSignal?: AbortSignal },
	) => handle(cmd.constructor.name, cmd.input, opts)) as never;
	return s3;
}

// The descriptor of a koid that serves previews under `domain`, as the box
// of `settings` would describe itself.
export function hostInfoFor(domain: string, over: Partial<HostInfo> = {}): HostInfo {
	return {
		protocol: 1,
		hostId: 'h'.repeat(20),
		domain,
		address: { scheme: 'https', port: 443 },
		capabilities: {
			duplex: false,
			buildLogCursor: true,
			runtimeLogStream: false,
			artifactTransfer: false,
		},
		...over,
	};
}

// Control API dependencies that fail when used, to override per test. The
// descriptor answers, as koid's always does, for the domain of `settings`.
export function koidDeps(over: Partial<ControlDeps>): ControlDeps {
	const unused = () => {
		throw new Error('not used in this test');
	};
	return {
		deployer: { up: unused, down: unused, acquireLease: unused, releaseLease: unused },
		store: { get: unused, list: unused },
		docker: { logs: unused },
		buildLogs: { read: unused, tail: unused },
		keepAwake: async () => {},
		describe: async () => hostInfoFor(settings.domain),
		...over,
	};
}

export function previewRecord(over: Partial<PreviewRecord> = {}): PreviewRecord {
	return {
		label: 'hello-pr-7',
		project: 'hello',
		repo: 'github.com/acme/hello',
		status: 'running',
		commit: 'c'.repeat(40),
		branch: 'feature/x',
		pr: 7,
		dirty: false,
		requestId: 'a'.repeat(16),
		attempt: 'b'.repeat(20),
		ttlDays: 7,
		createdAt: '2026-10-06T00:00:00.000Z',
		updatedAt: '2026-10-06T00:00:00.000Z',
		...over,
	};
}
