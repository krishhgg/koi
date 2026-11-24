import {
	DescribeInstancesCommand,
	EC2Client,
	type Filter,
	type Instance,
	StartInstancesCommand,
} from '@aws-sdk/client-ec2';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import {
	DescribeInstanceInformationCommand,
	GetCommandInvocationCommand,
	type GetCommandInvocationCommandOutput,
	SendCommandCommand,
	type SendCommandCommandOutput,
	SSMClient,
} from '@aws-sdk/client-ssm';
import { GetCallerIdentityCommand, STSClient } from '@aws-sdk/client-sts';
import { fromIni } from '@aws-sdk/credential-providers';
import { Upload } from '@aws-sdk/lib-storage';
import { encodeCtlArgs, requestKey, sourceKey } from '@koi/shared';
import {
	BoxUnavailableError,
	type CtlResult,
	describeMs,
	type HostTransport,
	type OperationOptions,
	type Progress,
	UnknownOutcomeError,
	UnsupportedCapabilityError,
	wakeTimeout,
} from '../transport.ts';
import {
	buildLog,
	describeViaCtl,
	InterruptedError,
	KOID_READY_MS,
	saysOk,
	within,
} from './common.ts';

// The AWS transport: source goes to S3, the box is an EC2 instance that
// sleeps when idle, and `koid ctl` runs on it through SSM Run Command. Each
// command is one bounded round trip; there is no channel and no live log.

export interface Settings {
	profile: string;
	region: string;
	domain: string;
	instanceId: string;
	bucket: string;
	// Whether koi may start the instance (ec2, the default) or must find it
	// running (always-on). The legacy path and import-aws know only ec2.
	power?: 'ec2' | 'always-on' | undefined;
}

const PASSING = new Set([
	'InvalidInstanceId',
	'ThrottlingException',
	'TimeoutError',
	'RequestTimeout',
	'ECONNRESET',
	'ECONNREFUSED',
	'ETIMEDOUT',
	'ENOTFOUND',
	'EAI_AGAIN',
	'EPIPE',
]);

// err as a BoxUnavailableError if it can pass, else err itself.
function unavailable(err: unknown): unknown {
	if (!(err instanceof Error)) return err;
	const passes =
		PASSING.has(err.name) ||
		('code' in err && typeof err.code === 'string' && PASSING.has(err.code)) ||
		// AWS SDK errors: AWS's fault, or one the SDK counts as retryable.
		('$fault' in err && err.$fault === 'server') ||
		('$retryable' in err && err.$retryable !== undefined);
	return passes ? new BoxUnavailableError(err.message, { cause: err }) : err;
}

// GetCommandInvocation returns only the first 24,000 characters of a
// command's stdout. koid ctl keeps its replies far below that; output this
// long was cut and is not used.
const SSM_STDOUT_LIMIT = 24_000;

// The SSM command that runs koid ctl with these arguments. The command is a
// shell string, so the arguments go as data: the base64 of their JSON, which
// koid ctl-b64 decodes and checks. Nothing else in the string comes from the
// caller.
export function ctlCommand(args: string[]): string {
	return ['/usr/local/bin/koid', 'ctl-b64', encodeCtlArgs(args)].join(' ');
}

export interface Clients {
	s3: S3Client;
	ec2: EC2Client;
	ssm: SSMClient;
	sts: STSClient;
}

export function clients(profile: string, region: string): Clients {
	const credentials = fromIni({ profile });
	return {
		s3: new S3Client({ region, credentials }),
		ec2: new EC2Client({ region, credentials }),
		ssm: new SSMClient({ region, credentials }),
		sts: new STSClient({ region, credentials }),
	};
}

// The instance tag infra/modules/koi sets to var.domain, the base domain
// previews live under. Read here and nowhere else: an explicit target names
// its domain in the config file.
const DOMAIN_TAG = 'Domain';

// The tags discovery finds the box by, in order. infra/modules/koi tags it
// koi:role=box whatever its name prefix, and leaves Project to the caller's
// default_tags, which another account may set to its own project name. A box
// applied before koi:role existed has only Project=koi and Name=koi-box, so
// those are asked for when no box has koi:role. An explicit target names its
// instance, and none of this runs.
const BOX_TAGS: Filter[][] = [
	[{ Name: 'tag:koi:role', Values: ['box'] }],
	[
		{ Name: 'tag:Project', Values: ['koi'] },
		{ Name: 'tag:Name', Values: ['koi-box'] },
	],
];
const BOX_STATES: Filter = {
	Name: 'instance-state-name',
	Values: ['pending', 'running', 'stopping', 'stopped'],
};

// Settings from the environment, discovering what is not set: the box by its
// tags (BOX_TAGS), the domain from the box's Domain tag, the bucket from the
// account id. This is the legacy path from before config files, and what
// `koi config import-aws` writes down.
export async function resolveSettings(
	env: Record<string, string | undefined>,
	make: (profile: string, region: string) => Clients = clients,
): Promise<{ settings: Settings; clients: Clients }> {
	const profile = env.KOI_AWS_PROFILE ?? 'koi-cli';
	const region = env.KOI_AWS_REGION ?? 'us-east-1';
	const c = make(profile, region);
	let instanceId = env.KOI_INSTANCE_ID;
	let domain = env.KOI_DOMAIN;
	if (instanceId === undefined || domain === undefined) {
		const describe = async (input: { Filters: Filter[] } | { InstanceIds: string[] }) => {
			const out = await c.ec2.send(new DescribeInstancesCommand(input));
			return (out.Reservations ?? []).flatMap((r) => r.Instances ?? []);
		};
		let instances: Instance[] = [];
		if (instanceId === undefined) {
			for (const tags of BOX_TAGS) {
				instances = await describe({ Filters: [...tags, BOX_STATES] });
				if (instances.length > 0) break;
			}
		} else {
			instances = await describe({ InstanceIds: [instanceId] });
		}
		if (instanceId === undefined) {
			const ids = instances.map((i) => i.InstanceId ?? '');
			if (ids.length !== 1 || ids[0] === '') {
				throw new Error(`expected one koi box, found ${ids.length}; set KOI_INSTANCE_ID`);
			}
			instanceId = ids[0] as string;
		}
		if (domain === undefined) {
			const tag = instances[0]?.Tags?.find((t) => t.Key === DOMAIN_TAG)?.Value;
			if (tag === undefined || tag === '') {
				throw new Error(
					`the koi box ${instanceId} has no ${DOMAIN_TAG} tag; apply the current koi module (infra/modules/koi), which tags it with var.domain, or set KOI_DOMAIN`,
				);
			}
			domain = tag;
		}
	}
	let bucket = env.KOI_BUCKET;
	if (bucket === undefined) {
		const who = await c.sts.send(new GetCallerIdentityCommand({}));
		bucket = `koi-uploads-${who.Account}`;
	}
	return { settings: { profile, region, domain, instanceId, bucket }, clients: c };
}

export function awsTransport(
	settings: Settings,
	c: Clients,
	sleep: (ms: number) => Promise<void> = Bun.sleep,
	now: () => number = Date.now,
): HostTransport {
	const ctl = async (args: string[], o?: OperationOptions): Promise<CtlResult> => {
		o?.signal?.throwIfAborted();
		const deadline = o?.timeoutMs === undefined ? undefined : now() + o.timeoutMs;
		const what = `koid ctl ${args[0] ?? ''}`;
		// Every SSM call ends when the caller's signal fires or the time
		// limit passes, so a call that hangs cannot outlast either.
		const call = <T>(send: (abortSignal: AbortSignal | undefined) => Promise<T>) =>
			within(o?.signal, deadline, now, send);
		let sent: SendCommandCommandOutput;
		try {
			sent = await call((abortSignal) =>
				c.ssm.send(
					new SendCommandCommand({
						InstanceIds: [settings.instanceId],
						DocumentName: 'AWS-RunShellScript',
						Comment: `koi ctl ${args[0] ?? ''}`,
						Parameters: { commands: [ctlCommand(args)], executionTimeout: ['300'] },
					}),
					sdkOptions(abortSignal),
				),
			);
		} catch (err) {
			// The request may have reached SSM before koi stopped waiting.
			if (err instanceof InterruptedError) {
				throw new UnknownOutcomeError(
					`${what} may have been sent to the box: koi stopped waiting for SSM to accept it, so its outcome is unknown`,
				);
			}
			throw unavailable(err);
		}
		const commandId = sent.Command?.CommandId;
		if (commandId === undefined) throw new Error('SSM did not return a command id');
		const unknownOutcome = () =>
			new UnknownOutcomeError(
				`${what} was sent to the box (SSM command ${commandId}) and koi stopped waiting for its result, so its outcome is unknown`,
			);
		for (let i = 0; i < 600; i++) {
			await sleep(i === 0 ? 400 : 1000);
			// From here the command is on the box: stopping is not undoing.
			if (o?.signal?.aborted || (deadline !== undefined && now() >= deadline)) {
				throw unknownOutcome();
			}
			let out: GetCommandInvocationCommandOutput;
			try {
				out = await call((abortSignal) =>
					c.ssm.send(
						new GetCommandInvocationCommand({
							CommandId: commandId,
							InstanceId: settings.instanceId,
						}),
						sdkOptions(abortSignal),
					),
				);
			} catch (err) {
				if (err instanceof InterruptedError) throw unknownOutcome();
				// Not registered yet right after SendCommand.
				if (err instanceof Error && err.name === 'InvocationDoesNotExist') continue;
				throw unavailable(err);
			}
			if (
				out.Status === 'Pending' ||
				out.Status === 'InProgress' ||
				out.Status === 'Delayed' ||
				out.Status === 'Cancelling'
			)
				continue;
			// Success or Failed carry koid ctl's exit status. Anything else
			// (TimedOut, Cancelled, or Failed with no status) means it did not
			// run to the end.
			const code = out.ResponseCode ?? (out.Status === 'Success' ? 0 : -1);
			if ((out.Status !== 'Success' && out.Status !== 'Failed') || code < 0) {
				throw new BoxUnavailableError(
					`SSM reports koid ctl ${args[0] ?? ''} as ${out.StatusDetails ?? out.Status}`,
				);
			}
			const stdout = out.StandardOutputContent ?? '';
			if (stdout.length >= SSM_STDOUT_LIMIT) {
				throw new Error(
					`the output of koid ctl ${args[0] ?? ''} was cut off by SSM, which returns only the first ${SSM_STDOUT_LIMIT} characters, so koi cannot use it`,
				);
			}
			return { code, stdout, stderr: out.StandardErrorContent ?? '' };
		}
		throw new BoxUnavailableError(`koid ctl ${args[0] ?? ''} did not finish`);
	};

	// SSM online means the agent runs, not that koid has finished starting.
	// koid ctl ping answers once it takes commands; until then it fails, or
	// SSM refuses the command while the instance settles. `deadline` is the
	// caller's limit on the whole wake, when it gave one; each ping gets what
	// is left of the earlier of the two.
	const waitForKoid = async (
		progress: Progress,
		o: OperationOptions | undefined,
		deadline: number | undefined,
	) => {
		const until = Math.min(now() + KOID_READY_MS, deadline ?? Number.POSITIVE_INFINITY);
		let last = '';
		for (let attempt = 0; now() < until; attempt++) {
			try {
				const r = await ctl(['ping'], { signal: o?.signal, timeoutMs: until - now() });
				if (r.code === 0 && saysOk(r.stdout)) return;
				last = (r.stderr || r.stdout).trim();
			} catch (err) {
				// A ping koi stopped waiting for has no outcome worth knowing; the
				// limit it ran into is reported below.
				if (!(err instanceof BoxUnavailableError) && !(err instanceof UnknownOutcomeError)) {
					throw err;
				}
				last = err.message;
			}
			o?.signal?.throwIfAborted();
			if (now() >= until) break;
			if (attempt === 0) progress('waiting for koid on the box to start');
			await sleep(3000);
			o?.signal?.throwIfAborted();
		}
		if (deadline !== undefined && now() >= deadline) throw wakeTimeout(o);
		throw new Error(
			`koid on the box did not answer within ${KOID_READY_MS / 60_000} minutes${last === '' ? '' : `: ${last}`}`,
		);
	};

	const power = settings.power ?? 'ec2';

	return {
		async upload(request, tarball, o) {
			o?.signal?.throwIfAborted();
			const deadline = o?.timeoutMs === undefined ? undefined : now() + o.timeoutMs;
			const timeout = () =>
				new Error(
					`uploading the source of ${request.label} did not finish within ${describeMs(o?.timeoutMs ?? 0)}`,
				);
			// Both S3 calls end when the caller's signal fires or the time
			// limit passes, whatever the SDK is doing then. An interrupted
			// call means the caller stopped, or the upload ran out of time.
			const call = async <T>(send: (abortSignal: AbortSignal | undefined) => Promise<T>) => {
				try {
					return await within(o?.signal, deadline, now, send);
				} catch (err) {
					if (!(err instanceof InterruptedError)) throw err;
					o?.signal?.throwIfAborted();
					throw timeout();
				}
			};
			await call((abortSignal) => {
				// lib-storage takes a controller, not a signal, and stops a
				// multipart upload through it. The signal aborts that controller.
				const stop = new AbortController();
				if (abortSignal?.aborted) stop.abort();
				else abortSignal?.addEventListener('abort', () => stop.abort(), { once: true });
				return new Upload({
					client: c.s3,
					params: {
						Bucket: settings.bucket,
						Key: sourceKey(request.id),
						Body: Bun.file(tarball).stream(),
						ContentType: 'application/gzip',
					},
					queueSize: 4,
					partSize: 16 * 1024 * 1024,
					abortController: stop,
				}).done();
			});
			// The source is up. The caller may have stopped, or the time may
			// have run out, just as its last part was answered. Then the
			// request is not written either.
			o?.signal?.throwIfAborted();
			if (deadline !== undefined && now() >= deadline) throw timeout();
			// The request goes last: the daemon reads it first and expects the
			// source to be there.
			await call((abortSignal) =>
				c.s3.send(
					new PutObjectCommand({
						Bucket: settings.bucket,
						Key: requestKey(request.id),
						Body: JSON.stringify(request),
						ContentType: 'application/json',
					}),
					sdkOptions(abortSignal),
				),
			);
		},

		async ensureAwake(progress, o) {
			o?.signal?.throwIfAborted();
			const deadline = o?.timeoutMs === undefined ? undefined : now() + o.timeoutMs;
			const overdue = () => deadline !== undefined && now() >= deadline;
			// Every EC2 and SSM read ends when the caller's signal fires or
			// the time limit passes. One that did is the caller's stop, or
			// the wake running out of time. The one mutation, StartInstances,
			// is handled where it is sent.
			const call = async <T>(send: (abortSignal: AbortSignal | undefined) => Promise<T>) => {
				try {
					return await within(o?.signal, deadline, now, send);
				} catch (err) {
					if (!(err instanceof InterruptedError)) throw err;
					o?.signal?.throwIfAborted();
					throw wakeTimeout(o);
				}
			};
			const describeInstance = async () => {
				const out = await call((abortSignal) =>
					c.ec2.send(
						new DescribeInstancesCommand({ InstanceIds: [settings.instanceId] }),
						sdkOptions(abortSignal),
					),
				);
				return out.Reservations?.[0]?.Instances?.[0]?.State?.Name;
			};
			let state = await describeInstance();
			if (power === 'always-on') {
				// The target does not manage power: koi may wait for an instance
				// that is starting, but never starts one itself.
				if (state !== 'running' && state !== 'pending') {
					throw new Error(
						`the instance ${settings.instanceId} is ${state ?? 'in an unknown state'}, and this target does not manage its power (power: always-on), so koi does not start it; its operator must`,
					);
				}
			} else {
				if (state === 'stopping') {
					progress('the box is stopping; waiting to start it again');
					for (let i = 0; i < 60; i++) {
						await sleep(5000);
						o?.signal?.throwIfAborted();
						if (overdue()) throw wakeTimeout(o);
						state = await describeInstance();
						if (state === 'stopped') break;
					}
				}
				if (state === 'stopped' || state === 'stopping') {
					progress('waking the box');
					try {
						await within(o?.signal, deadline, now, (abortSignal) =>
							c.ec2.send(
								new StartInstancesCommand({ InstanceIds: [settings.instanceId] }),
								sdkOptions(abortSignal),
							),
						);
					} catch (err) {
						// The start is a mutation, like SendCommand: the request may
						// have reached EC2 before koi stopped waiting, and the box may
						// be starting. That is not a plain timeout or cancellation.
						if (err instanceof InterruptedError) {
							throw new UnknownOutcomeError(
								`the start of ${settings.instanceId} may have reached EC2: koi stopped waiting for it to be accepted, so whether the box is waking is unknown`,
							);
						}
						throw err;
					}
				}
			}
			for (let i = 0; i < 120; i++) {
				const info = await call((abortSignal) =>
					c.ssm.send(
						new DescribeInstanceInformationCommand({
							Filters: [{ Key: 'InstanceIds', Values: [settings.instanceId] }],
						}),
						sdkOptions(abortSignal),
					),
				);
				if (info.InstanceInformationList?.[0]?.PingStatus === 'Online') {
					await waitForKoid(progress, o, deadline);
					return;
				}
				await sleep(5000);
				o?.signal?.throwIfAborted();
				if (overdue()) throw wakeTimeout(o);
			}
			throw new Error('the box did not come online within ten minutes');
		},

		ctl,

		describe(o) {
			return describeViaCtl(ctl, o);
		},

		streamLogs(q, o) {
			if (q.kind === 'runtime') {
				throw new UnsupportedCapabilityError(
					'runtimeLogStream',
					'the AWS transport cannot follow a container log over SSM; koi logs shows a bounded tail instead',
				);
			}
			return buildLog(q, o, ctl, sleep, now);
		},

		async openChannel() {
			throw new UnsupportedCapabilityError(
				'duplex',
				'the AWS transport has no control channel over SSM; a separate SSH channel is needed for interactive verification',
			);
		},

		async close() {
			for (const client of [c.s3, c.ec2, c.ssm, c.sts]) {
				if (typeof client.destroy === 'function') client.destroy();
			}
		},
	};
}

// A signal as the SDK takes it on a send, when there is one.
function sdkOptions(signal: AbortSignal | undefined): { abortSignal: AbortSignal } | undefined {
	return signal === undefined ? undefined : { abortSignal: signal };
}
