import { stat } from 'node:fs/promises';
import { CTL_EXIT, encodeCtlArgs, type UpRequest } from '@koi/shared';
import { RelayBrokenError, RelayIdleError } from '../http1.ts';
import { readAll, type SshClient, SshMissingError } from '../ssh.ts';
import {
	BoxUnavailableError,
	type CtlResult,
	checkHostInfo,
	ctlErrorText,
	describeMs,
	type HostTransport,
	type OperationOptions,
	type Progress,
	UnknownOutcomeError,
	UnsupportedCapabilityError,
	WakeTimeoutError,
	wakeTimeout,
} from '../transport.ts';
import {
	buildLog,
	describeViaCtl,
	InterruptedError,
	KOID_READY_MS,
	parseDescriptor,
	within,
} from './common.ts';
import { digestFile, type Source, uploadSequence } from './upload.ts';

// The SSH transport: a plain Linux host that is always on, reached as the
// koi-connect account through the system ssh client (ssh.ts). On the host,
// sshd runs the koi gateway for that account and nothing else, and the
// gateway takes two commands (host/ssh/koi-ssh-gateway.ts):
//
//   ctl-b64 <blob>   runs `koid ctl` with the arguments encoded as the SSM
//                    path encodes them, and relays its output and exit status;
//   tunnel-v1        copies bytes between the session and koid's control
//                    socket, over which the source upload speaks HTTP to the
//                    upload API (packages/daemon/src/upload-api.ts).
//
// Nothing else crosses: no shell, no file transfer, no forwarding. koi cannot
// start the host; ensureAwake connects and waits for koid, and reports a
// host that does not take the connection as one its operator must start.
//
// The host is checked against the target here, not by verifiedTransport
// (transport.ts): the upload hands the source to koid itself, so the
// descriptor must be checked before it, and ensureAwake has the descriptor
// in hand when koid first answers. The check runs once per process and
// again after a failure.

// ssh's own exit status, for a failure before or outside the remote command.
const SSH_FAILED = 255;

// How long each operation may take when the caller sets no limit of its
// own. ssh keeps a session up for as long as the host keeps the connection,
// so a koid that stops answering while sshd stays up would otherwise hold
// koi for good: the deadline is what ends the wait. A limit the caller
// gives stands instead, shorter or longer.
export const SSH_DEFAULT_LIMITS = {
	// One koid ctl command: as long as the AWS transport lets SSM run one
	// (executionTimeout in transports/aws.ts). A build is not waited for
	// here; koid answers up at once and status is read again and again.
	ctlMs: 5 * 60_000,
	// koid ctl describe reads one small file; a minute is generous.
	describeMs: 60_000,
	// The whole upload: the wait for a koid that is starting, the digest of
	// the archive, and its transfer, up to 2 GiB over a slow link.
	uploadMs: 30 * 60_000,
	// How long the upload waits for the tunnel to carry anything, in either
	// direction, before it gives koid up as not answering (RelayIdleError).
	// The clock restarts after each 64 KiB ssh takes (http1.ts), so a slow
	// transfer does not run it out and only a stall counts.
	tunnelIdleMs: 2 * 60_000,
};
export type SshLimits = typeof SSH_DEFAULT_LIMITS;

// koid did not trust, or no longer trusts, the host key: nothing was sent.
export class HostKeyError extends Error {}

// The client's view of the target, for messages and for the check of the
// host's descriptor: the domain the target is configured with.
export interface SshHost {
	name: string;
	host: string;
	user: string;
	domain: string;
}

export interface SshTransportOptions {
	// Where a wait for koid is reported while an upload waits for it.
	progress?: Progress | undefined;
	sleep?: ((ms: number) => Promise<void>) | undefined;
	now?: (() => number) | undefined;
	// The limits that apply when a caller sets none; SSH_DEFAULT_LIMITS
	// unless a test passes its own.
	limits?: Partial<SshLimits> | undefined;
}

export function sshTransport(
	target: SshHost,
	client: SshClient,
	options: SshTransportOptions = {},
): HostTransport {
	const sleep = options.sleep ?? Bun.sleep;
	const now = options.now ?? Date.now;
	const progress = options.progress ?? (() => {});
	const limits: SshLimits = { ...SSH_DEFAULT_LIMITS, ...options.limits };
	const where = `${target.host} (target ${target.name})`;
	const expected = { name: `target ${JSON.stringify(target.name)}`, domain: target.domain };
	let verified = false;

	const ctl = async (args: string[], o?: OperationOptions): Promise<CtlResult> => {
		o?.signal?.throwIfAborted();
		const timeoutMs = o?.timeoutMs ?? limits.ctlMs;
		const deadline = now() + timeoutMs;
		const what = `koid ctl ${args[0] ?? ''}`;
		const command = `ctl-b64 ${encodeCtlArgs(args)}`;
		let r: { code: number; stdout: string; stderr: string };
		try {
			r = await within(o?.signal, deadline, now, (abortSignal) => client.run(command, abortSignal));
		} catch (err) {
			// From the moment ssh started the command may have reached the
			// host; stopping is not undoing. The limit is named when it, and
			// not the caller's signal, ended the wait.
			if (err instanceof InterruptedError) {
				const why = o?.signal?.aborted
					? 'koi stopped waiting for its result'
					: `koi stopped waiting for its result after ${describeMs(timeoutMs)}`;
				throw new UnknownOutcomeError(
					`${what} may have run on ${where}: ${why}, so its outcome is unknown`,
				);
			}
			throw err;
		}
		if (r.code === SSH_FAILED) throw sshFailure(target, r.stderr);
		return r;
	};

	// Connects, and waits for koid to answer `describe`. A host that does
	// not take the connection is reported as one koi cannot start: this
	// transport manages no power. The first descriptor koid gives is
	// checked against the target; a mismatch stops here and nothing is
	// sent to koid after it.
	const ensureAwake: HostTransport['ensureAwake'] = async (report, o) => {
		o?.signal?.throwIfAborted();
		const deadline = o?.timeoutMs === undefined ? undefined : now() + o.timeoutMs;
		const until = Math.min(now() + KOID_READY_MS, deadline ?? Number.POSITIVE_INFINITY);
		let last = '';
		for (let attempt = 0; now() < until; attempt++) {
			try {
				const r = await ctl(['describe'], { signal: o?.signal, timeoutMs: until - now() });
				if (r.code === CTL_EXIT.ok) {
					if (!verified) {
						checkHostInfo(parseDescriptor(r), expected);
						verified = true;
					}
					return;
				}
				if (r.code === CTL_EXIT.usage) {
					throw new UnsupportedCapabilityError(
						'describe',
						`koid on ${where} does not answer koid ctl describe; it predates the host descriptor, and an SSH target needs the current koid`,
					);
				}
				if (r.code !== CTL_EXIT.unavailable) {
					throw new Error(ctlErrorText(r) || `koid ctl describe exited ${r.code} on ${where}`);
				}
				// koid is starting, or restarting after a deploy.
				last = ctlErrorText(r);
			} catch (err) {
				if (err instanceof BoxUnavailableError) {
					throw new Error(
						`${err.message}; target ${target.name} does not manage the host's power (power: always-on), so koi cannot start it; its operator must`,
					);
				}
				// A describe koi stopped waiting for has no outcome worth
				// knowing; the limit it ran into is reported below.
				if (!(err instanceof UnknownOutcomeError)) throw err;
				last = err.message;
			}
			o?.signal?.throwIfAborted();
			if (now() >= until) break;
			if (attempt === 0) report(`waiting for koid on ${target.host} to start`);
			await sleep(3000);
			o?.signal?.throwIfAborted();
		}
		if (deadline !== undefined && now() >= deadline) throw wakeTimeout(o);
		throw new Error(
			`koid on ${where} did not answer within ${KOID_READY_MS / 60_000} minutes${last === '' ? '' : `: ${last}`}`,
		);
	};

	return {
		// The source goes to koid over a tunnel, so koid must be up and the
		// host checked before any of it is sent: ensureAwake does both. The
		// archive's size and digest, the wait and the tunnel all count
		// against the caller's deadline and stop on the caller's signal.
		async upload(request, tarball, o) {
			o?.signal?.throwIfAborted();
			const timeoutMs = o?.timeoutMs ?? limits.uploadMs;
			const deadline = now() + timeoutMs;
			try {
				await within(o?.signal, deadline, now, async (abortSignal) => {
					const timeLeft = () => Math.max(0, deadline - now());
					try {
						await ensureAwake(progress, { signal: abortSignal, timeoutMs: timeLeft() });
					} catch (err) {
						// The wait for koid ran out of the upload's time, which can
						// be gone before the wait starts: that is the upload's
						// limit, reported as such below, not the wake's.
						if (err instanceof WakeTimeoutError) throw new InterruptedError(err.message);
						throw err;
					}
					const size = (await stat(tarball)).size;
					const sha256 = await digestFile(tarball, abortSignal);
					// Hashing a large archive takes time of its own; a deadline
					// that passed meanwhile is honoured before ssh is started.
					abortSignal?.throwIfAborted();
					if (now() >= deadline) {
						throw new InterruptedError('the deadline passed before the upload started');
					}
					await uploadSource(
						target,
						client,
						request,
						{ tarball, size, sha256 },
						abortSignal,
						sleep,
						limits.tunnelIdleMs,
					);
				});
			} catch (err) {
				if (!(err instanceof InterruptedError)) throw err;
				o?.signal?.throwIfAborted();
				throw new Error(
					`uploading the source of ${request.label} did not finish within ${describeMs(timeoutMs)}`,
				);
			}
		},

		ensureAwake,

		ctl,

		describe(o) {
			return describeViaCtl(ctl, {
				signal: o?.signal,
				timeoutMs: o?.timeoutMs ?? limits.describeMs,
			});
		},

		streamLogs(q, o) {
			if (q.kind === 'runtime') {
				throw new UnsupportedCapabilityError(
					'runtimeLogStream',
					'the SSH transport cannot follow a container log yet; koi logs shows a bounded tail instead',
				);
			}
			return buildLog(q, o, ctl, sleep, now);
		},

		async openChannel() {
			throw new UnsupportedCapabilityError(
				'duplex',
				'the SSH transport has no control channel yet; interactive verification needs one',
			);
		},

		close() {
			return client.close();
		},
	};
}

// Why ssh exited 255, as an error the caller can act on. A host key koi does
// not trust, and a key the host refuses, are the operator's to fix; the rest
// is the network or the host, which can pass.
export function sshFailure(target: SshHost, stderr: string): Error {
	const text = stderr.trim().replace(/\s+/g, ' ');
	if (
		/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|host key for .* has changed|No .*host key is known/i.test(
			text,
		)
	) {
		return new HostKeyError(
			`koi does not trust the host key of ${target.host} for target ${target.name}: ${text}. koi never trusts a key on first use; get the key's SHA256 fingerprint from the host's operator and run koi target trust ${target.name} --fingerprint SHA256:...`,
		);
	}
	if (/Permission denied/.test(text)) {
		return new Error(
			`${target.host} refused koi's key for ${target.user}: ${text}. On the host, the key's public half must be in /etc/ssh/koi-connect/authorized_keys`,
		);
	}
	return new BoxUnavailableError(
		`cannot connect to ${target.host} as ${target.user}: ${text || 'ssh exited 255'}`,
	);
}

// Whether a 255 is one the next attempt may not meet: the connection was
// lost or timed out part way, which the network does and then stops doing.
// A refused key, an untrusted host key, a name that does not resolve and a
// host that refuses the connection stay that way, and are not tried again.
export function sshFailureIsTransient(stderr: string): boolean {
	const text = stderr.trim().replace(/\s+/g, ' ');
	if (
		/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|host key for .* has changed|No .*host key is known|Permission denied|Could not resolve hostname|Name or service not known|nodename nor servname/i.test(
			text,
		)
	) {
		return false;
	}
	return /Connection closed|Connection reset|Broken pipe|timed out|Timeout/i.test(text);
}

// How many times the sequence is started over after the tunnel broke part
// way. Starting over is safe: the ticket request says whether the commit
// landed, and a ticket left behind expires on the host.
const TUNNEL_RETRIES = 1;

// The upload sequence (upload.ts) over a tunnel. On a tunnel that breaks the sequence starts over once, from the
// ticket, which answers 200 if the commit had landed. A tunnel whose ssh
// ended with a lost connection counts as broken the same way; one ssh
// refused, or the gateway refused, is reported at once. A tunnel that
// carried nothing for `idleMs` is koid not answering with the connection
// up: it is not tried again, since a second tunnel would stall the same
// way, and the stall is reported as koid's.
async function uploadSource(
	target: SshHost,
	client: SshClient,
	request: UpRequest,
	source: Source,
	signal: AbortSignal | undefined,
	sleep: (ms: number) => Promise<void>,
	idleMs: number,
): Promise<void> {
	for (let attempt = 0; ; attempt++) {
		const tunnel = await client.open('tunnel-v1', true, signal);
		const stderr = readAll(tunnel.stderr, 64 * 1024);
		try {
			const relay = { write: (chunk: Uint8Array) => tunnel.write(chunk), readable: tunnel.stdout };
			await uploadSequence(target.host, relay, request, source, sleep, idleMs);
			// The end of input tells the gateway the tunnel is done; the
			// session then closes on its own, and is killed only if it lingers.
			await tunnel.end();
			await Promise.race([tunnel.exited, sleep(3000)]);
			return;
		} catch (err) {
			if (!(err instanceof RelayBrokenError)) throw err;
			tunnel.kill();
			if (err instanceof RelayIdleError) {
				throw new BoxUnavailableError(
					`koid on ${target.host} stopped answering during the upload of ${request.label}: nothing crossed the tunnel for ${describeMs(err.idleMs)}`,
				);
			}
			// The tunnel is gone. If ssh or the gateway refused it, retrying
			// changes nothing and the reason is in what they printed.
			const code = await tunnel.exited;
			const text = ((await stderr) ?? '').trim();
			if (code === SSH_FAILED && !sshFailureIsTransient(text)) throw sshFailure(target, text);
			if (code === CTL_EXIT.unavailable) {
				throw new BoxUnavailableError(`koid on ${target.host} is not taking uploads: ${text}`);
			}
			if (code === CTL_EXIT.usage) {
				throw new Error(
					`the koi gateway on ${target.host} refused tunnel-v1: ${text}. Install the current gateway (host/ssh/install.sh)`,
				);
			}
			if (attempt >= TUNNEL_RETRIES) {
				throw new BoxUnavailableError(
					`the connection to ${target.host} ended during the upload of ${request.label}: ${err.message}${text === '' ? '' : ` (${text})`}`,
				);
			}
		} finally {
			tunnel.kill();
		}
	}
}

export { SshMissingError };
