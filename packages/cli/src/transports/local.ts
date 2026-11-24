import { lstat, realpath, stat } from 'node:fs/promises';
import { connect } from 'node:net';
import { CTL_EXIT } from '@koi/shared';
import { ctl as koidCtl, socketFetch } from '../../../daemon/src/ctl.ts';
import { type ByteRelay, RelayBrokenError, RelayIdleError } from '../http1.ts';
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
import { digestFile, uploadSequence } from './upload.ts';

// The local transport: koid on this machine, or in a Linux VM whose control
// socket a tool such as Lima forwards here, reached through that socket
// with no SSH, SSM or bucket in between. It speaks to the socket as the SSH
// gateway does on its host (host/ssh/koi-ssh-gateway.ts):
//
//   ctl     runs koid ctl's own client (packages/daemon/src/ctl.ts) in this
//           process against the socket, so every command, its arguments
//           and its replies are the same as `koid ctl` on the host;
//   upload  sends the source to the upload API over a connection to the
//           socket, in the same three requests the SSH tunnel carries
//           (upload.ts).
//
// Who may do this is decided on the host, as for the gateway: koid makes
// the socket mode 0660 with the group koi-control (packages/daemon/src/
// control.ts), in the directory koid.service makes 2750 with that group, so
// root, koi and the members of koi-control can open it, and nobody else.
// host/install-vm.sh --user puts accounts in that group, as
// host/ssh/install.sh puts koi-connect there. Being in the group is what
// holding a key for koi-connect is over SSH: any koid command, and uploads.
//
// What stands in for the SSH host key is the socket's path. koi talks only
// to a socket that no account but root, this one and the accounts those two
// gave a directory to could have put there (socketPathProblem), so another
// user of the machine cannot plant a socket of their own and receive the
// source. Then, as over SSH, the first descriptor koid gives is checked
// against the target before anything is sent: in ensureAwake, and in the
// upload, which hands the source to koid itself.
//
// koi cannot start koid: a socket that is not there is reported for its
// operator to start, and a koid that is starting is waited for.

// How long each operation may take when the caller sets no limit of its
// own: the SSH transport's limits (ssh.ts), for the same reason. A koid that
// stops answering with its socket open would otherwise hold koi for good.
export const LOCAL_DEFAULT_LIMITS = {
	ctlMs: 5 * 60_000,
	describeMs: 60_000,
	uploadMs: 30 * 60_000,
	// How long the upload waits with nothing crossing the socket.
	idleMs: 2 * 60_000,
};
export type LocalLimits = typeof LOCAL_DEFAULT_LIMITS;

export interface LocalHost {
	name: string;
	socket: string;
	domain: string;
}

export interface LocalTransportOptions {
	progress?: Progress | undefined;
	sleep?: ((ms: number) => Promise<void>) | undefined;
	now?: (() => number) | undefined;
	limits?: Partial<LocalLimits> | undefined;
	// This account's uid, for the check of the socket's path; the process's
	// unless a test passes its own.
	uid?: number | undefined;
}

export function localTransport(
	target: LocalHost,
	options: LocalTransportOptions = {},
): HostTransport {
	const sleep = options.sleep ?? Bun.sleep;
	const now = options.now ?? Date.now;
	const progress = options.progress ?? (() => {});
	const limits: LocalLimits = { ...LOCAL_DEFAULT_LIMITS, ...options.limits };
	const uid = options.uid ?? process.getuid?.() ?? 0;
	const where = `koid at ${target.socket} (target ${target.name})`;
	const expected = { name: `target ${JSON.stringify(target.name)}`, domain: target.domain };
	const fetchKoid = socketFetch(target.socket);
	let pathChecked = false;
	let verified = false;

	const ctl = async (args: string[], o?: OperationOptions): Promise<CtlResult> => {
		o?.signal?.throwIfAborted();
		const timeoutMs = o?.timeoutMs ?? limits.ctlMs;
		const deadline = now() + timeoutMs;
		try {
			return await within(o?.signal, deadline, now, async (abortSignal) => {
				let stdout = '';
				let stderr = '';
				const code = await koidCtl(args, {
					stdout: (text) => {
						stdout += text;
					},
					stderr: (text) => {
						stderr += text;
					},
					fetch: (path, init) =>
						fetchKoid(path, { ...init, signal: joinSignals(init?.signal, abortSignal) }),
				});
				return { code, stdout, stderr };
			});
		} catch (err) {
			// koid may have taken the request before koi stopped waiting.
			if (err instanceof InterruptedError) {
				const why = o?.signal?.aborted
					? 'koi stopped waiting for its result'
					: `koi stopped waiting for its result after ${describeMs(timeoutMs)}`;
				throw new UnknownOutcomeError(
					`koid ctl ${args[0] ?? ''} may have run on ${where}: ${why}, so its outcome is unknown`,
				);
			}
			throw err;
		}
	};

	// The socket is there, may be koid's, and this account may open it. The
	// path is checked once; a socket that is missing, or one this account
	// may not open, is reported at once rather than waited for.
	const checkSocket = async () => {
		const problem = await socketProblem(target.socket);
		if (problem !== undefined) throw new Error(problem);
		if (!pathChecked) {
			const untrusted = await socketPathProblem(target.socket, uid);
			if (untrusted !== undefined) {
				throw new Error(
					`koi does not trust the control socket of target ${target.name}: ${untrusted}. Another account could have put a socket there and would receive the source; use a socket in a directory only root, you or koid's account can write to, such as the /run/koi/control.sock koid makes`,
				);
			}
			pathChecked = true;
		}
	};

	// Waits for koid to answer `describe`, and checks the first descriptor
	// against the target; a mismatch stops here and nothing is sent to koid
	// after it.
	const ensureAwake: HostTransport['ensureAwake'] = async (report, o) => {
		o?.signal?.throwIfAborted();
		const deadline = o?.timeoutMs === undefined ? undefined : now() + o.timeoutMs;
		const until = Math.min(now() + KOID_READY_MS, deadline ?? Number.POSITIVE_INFINITY);
		await checkSocket();
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
						`${where} does not answer koid ctl describe; it predates the host descriptor, and a local target needs the current koid`,
					);
				}
				if (r.code !== CTL_EXIT.unavailable) {
					throw new Error(ctlErrorText(r) || `koid ctl describe exited ${r.code} on ${where}`);
				}
				// The socket is there and nothing answers: koid is starting.
				last = ctlErrorText(r);
			} catch (err) {
				if (!(err instanceof UnknownOutcomeError)) throw err;
				last = err.message;
			}
			o?.signal?.throwIfAborted();
			if (now() >= until) break;
			if (attempt === 0) report(`waiting for koid at ${target.socket} to start`);
			await sleep(3000);
			o?.signal?.throwIfAborted();
		}
		if (deadline !== undefined && now() >= deadline) throw wakeTimeout(o);
		throw new Error(
			`${where} did not answer within ${KOID_READY_MS / 60_000} minutes${last === '' ? '' : `: ${last}`}`,
		);
	};

	return {
		// As over SSH: koid must be up and checked before any of the source
		// goes out, and the wait, the digest and the transfer all count
		// against the caller's deadline.
		async upload(request, tarball, o) {
			o?.signal?.throwIfAborted();
			const timeoutMs = o?.timeoutMs ?? limits.uploadMs;
			const deadline = now() + timeoutMs;
			try {
				await within(o?.signal, deadline, now, async (abortSignal) => {
					try {
						await ensureAwake(progress, {
							signal: abortSignal,
							timeoutMs: Math.max(0, deadline - now()),
						});
					} catch (err) {
						if (err instanceof WakeTimeoutError) throw new InterruptedError(err.message);
						throw err;
					}
					const size = (await stat(tarball)).size;
					const sha256 = await digestFile(tarball, abortSignal);
					abortSignal?.throwIfAborted();
					if (now() >= deadline) {
						throw new InterruptedError('the deadline passed before the upload started');
					}
					const relay = await socketRelay(target.socket, abortSignal);
					try {
						await uploadSequence(
							`${target.socket}`,
							relay,
							request,
							{ tarball, size, sha256 },
							sleep,
							limits.idleMs,
						);
					} catch (err) {
						if (err instanceof RelayIdleError) {
							throw new BoxUnavailableError(
								`${where} stopped answering during the upload of ${request.label}: nothing crossed the socket for ${describeMs(err.idleMs)}`,
							);
						}
						if (err instanceof RelayBrokenError) {
							throw new BoxUnavailableError(
								`the connection to ${where} ended during the upload of ${request.label}: ${err.message}; run koi up again`,
							);
						}
						throw err;
					} finally {
						relay.close();
					}
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
					'the local transport cannot follow a container log yet; koi logs shows a bounded tail instead',
				);
			}
			return buildLog(q, o, ctl, sleep, now);
		},

		async openChannel() {
			throw new UnsupportedCapabilityError(
				'duplex',
				'the local transport has no control channel yet; interactive verification needs one',
			);
		},

		async close() {},
	};
}

// koid ctl's own signal for a request (ping has one) and the caller's.
function joinSignals(a: AbortSignal | null | undefined, b: AbortSignal | undefined) {
	const signals = [a, b].filter((s): s is AbortSignal => s !== null && s !== undefined);
	return signals.length < 2 ? (signals[0] ?? null) : AbortSignal.any(signals);
}

// Why koi cannot use the socket at `path` now, or undefined when it can
// try: it is missing (koid is not running), it is not a socket, or this
// account may not open it. A socket that is there but refuses connections
// is a koid that is starting, which ensureAwake waits for.
export async function socketProblem(path: string): Promise<string | undefined> {
	let info: Awaited<ReturnType<typeof lstat>>;
	try {
		info = await lstat(path);
	} catch (err) {
		const code = errorCode(err);
		if (code === 'ENOENT' || code === 'ENOTDIR') {
			return `there is no control socket at ${path}, so koid is not running on this machine. koi cannot start it: start it with sudo systemctl start koid, or set the machine up as a koi host (docs/configuration.md, "A local host")`;
		}
		if (code === 'EACCES') return notAllowed(path);
		throw err;
	}
	if (!info.isSocket()) return `${path} is not a socket`;
	const reach = await connectable(path);
	if (reach === 'EACCES') return notAllowed(path);
	if (reach === 'ENOENT') return socketProblem(path);
	return undefined;
}

function notAllowed(path: string): string {
	return `this account may not open ${path}. koid lets root, its own account and the members of the socket's group (koi-control) in; host/install-vm.sh --local --user NAME adds an account to that group, which takes effect at the account's next login (or in a shell started with newgrp koi-control)`;
}

// Tries to connect to the socket, and says why that failed, if it did.
function connectable(path: string): Promise<string | undefined> {
	return new Promise((resolve) => {
		const conn = connect({ path });
		conn.once('connect', () => {
			conn.destroy();
			resolve(undefined);
		});
		conn.once('error', (err) => {
			conn.destroy();
			resolve(errorCode(err) as string | undefined);
		});
	});
}

// Why the socket at `path` may not be koid's, or undefined when it can only
// be: no account other than root, `uid` and the accounts those two gave a
// directory to could have put it, or anything on the way to it, there. The
// path is walked from / as written, up to its first symbolic link, and
// again as it resolves. Each entry must sit in a directory that only its
// owner can write to, and then its own owner is trusted as well, since only
// root and the directory's owner could have put it there; or in a directory
// that anyone may write to but only the owner of an entry may change, such
// as /tmp, and then the entry must be owned by an account already trusted.
// A directory that a group or anyone may write to without that is refused,
// as OpenSSH's StrictModes refuses one on the way to authorized_keys.
export async function socketPathProblem(path: string, uid: number): Promise<string | undefined> {
	const real = await realpath(path);
	for (const walk of real === path ? [path] : [path, real]) {
		const problem = await pathWalkProblem(walk, new Set([0, uid]));
		if (problem !== undefined) return problem;
	}
	return undefined;
}

async function pathWalkProblem(path: string, trusted: Set<number>): Promise<string | undefined> {
	let parent = await lstat('/');
	let parentPath = '/';
	if (!trusted.has(parent.uid) || (parent.mode & 0o022) !== 0) {
		return '/ is not root-owned and closed to other writers';
	}
	const parts = path.split('/').filter((p) => p !== '');
	for (const i of parts.keys()) {
		const here = `/${parts.slice(0, i + 1).join('/')}`;
		const info = await lstat(here);
		if ((parent.mode & 0o022) !== 0) {
			if ((parent.mode & 0o1000) === 0) {
				return `${parentPath} is writable by ${(parent.mode & 0o002) !== 0 ? 'any account' : 'its group'} (mode ${octal(parent.mode)})`;
			}
			if (!trusted.has(info.uid)) {
				return `${here} belongs to uid ${info.uid}, in ${parentPath}, where any account may add an entry`;
			}
		} else {
			trusted.add(info.uid);
		}
		// What follows a link is walked again from the resolved path.
		if (info.isSymbolicLink()) return undefined;
		parent = info;
		parentPath = here;
	}
	return undefined;
}

function octal(mode: number): string {
	return (mode & 0o7777).toString(8).padStart(4, '0');
}

function errorCode(err: unknown): unknown {
	return err instanceof Error && 'code' in err ? err.code : undefined;
}

// A connection to the socket as a byte relay for the upload, closed when
// the caller's signal fires.
async function socketRelay(
	path: string,
	signal: AbortSignal | undefined,
): Promise<ByteRelay & { close(): void }> {
	const conn = connect({ path, allowHalfOpen: true });
	await new Promise<void>((resolve, reject) => {
		conn.once('connect', resolve);
		conn.once('error', reject);
	});
	let done = false;
	const readable = new ReadableStream<Uint8Array>({
		start(c) {
			const finish = () => {
				if (done) return;
				done = true;
				try {
					c.close();
				} catch {}
			};
			conn.on('data', (d: Buffer) => {
				if (!done) c.enqueue(new Uint8Array(d));
			});
			conn.on('end', finish);
			conn.on('close', finish);
			conn.on('error', finish);
		},
	});
	const close = () => conn.destroy();
	signal?.addEventListener('abort', close, { once: true });
	return {
		readable,
		write: (chunk) =>
			new Promise<void>((resolve, reject) =>
				conn.write(chunk, (err) => (err ? reject(err) : resolve())),
			),
		close() {
			signal?.removeEventListener('abort', close);
			conn.destroy();
		},
	};
}
