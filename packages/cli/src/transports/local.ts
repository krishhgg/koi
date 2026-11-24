import { lstat, readFile, readlink, stat } from 'node:fs/promises';
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
// to a socket that no account but root, this one and koid's own (koi) could
// have put there (socketPathProblem), so another user of the machine cannot
// plant a socket of their own and receive the source. Then, as over SSH, the first descriptor koid gives is checked
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

	// No account but root, this one and koi could have put the socket there.
	// Checked again right before the upload connects, not only at the start:
	// a directory on the way that is removed during the run, from a sticky
	// directory such as /tmp, could be made again by anyone.
	const checkPath = async () => {
		const untrusted = await socketPathProblem(target.socket, uid);
		if (untrusted !== undefined) {
			throw new Error(
				`koi does not trust the control socket of target ${target.name}: ${untrusted}. Another account could have put a socket there and would receive the source; use a socket in a directory only root, you or koid's account can write to, such as the /run/koi/control.sock koid makes`,
			);
		}
	};

	// The socket is there, may be koid's, and this account may open it. A
	// socket that is missing, or one this account may not open, is reported
	// at once rather than waited for.
	const checkSocket = async () => {
		const problem = await socketProblem(target.socket);
		if (problem !== undefined) throw new Error(problem);
		await checkPath();
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
					await checkPath();
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
// be. Only root, `uid` and koi, the account koid runs as, may own the socket
// or anything on the way to it; a socket a tool forwards from a VM is this
// account's. The path is resolved here one entry at a time from /, and a
// symbolic link's target is walked in its place, so every entry on every
// link is checked, not only those of the path as written. The directory each
// entry is in must be writable by its owner alone, or be sticky like /tmp,
// where only an entry's owner may replace it. A directory that a group or
// anyone may write to without the sticky bit is refused, as OpenSSH's
// StrictModes refuses one on the way to authorized_keys. koi's uid comes
// from `accounts`; with no koi there, only root and `uid` count.
export async function socketPathProblem(
	path: string,
	uid: number,
	accounts = '/etc/passwd',
): Promise<string | undefined> {
	const owners = new Set([0, uid]);
	const koi = await accountUid('koi', accounts);
	if (koi !== undefined) owners.add(koi);
	return pathWalkProblem(path.startsWith('/') ? path : `${process.cwd()}/${path}`, owners);
}

// As many symbolic links as Linux follows in one path before ELOOP.
const MAX_LINKS = 40;

async function pathWalkProblem(
	path: string,
	owners: ReadonlySet<number>,
): Promise<string | undefined> {
	const root = await lstat('/');
	if (!owners.has(root.uid) || (root.mode & 0o022) !== 0) {
		return '/ is not root-owned and closed to other writers';
	}
	// The directory reached so far, which has no link in it, and what is
	// left of the path below it.
	let dir = '/';
	let dirInfo = root;
	let rest = parts(path);
	let links = 0;
	for (let name = rest.shift(); name !== undefined; name = rest.shift()) {
		if (name === '.') continue;
		if (name === '..') {
			// Every directory above this one was checked on the way down.
			dir = dir.slice(0, dir.lastIndexOf('/')) || '/';
			dirInfo = await lstat(dir);
			continue;
		}
		if ((dirInfo.mode & 0o022) !== 0 && (dirInfo.mode & 0o1000) === 0) {
			return `${dir} is writable by ${(dirInfo.mode & 0o002) !== 0 ? 'any account' : 'its group'} (mode ${octal(dirInfo.mode)})`;
		}
		const here = dir === '/' ? `/${name}` : `${dir}/${name}`;
		const info = await lstat(here);
		if (!owners.has(info.uid)) {
			return (dirInfo.mode & 0o022) !== 0
				? `${here} belongs to uid ${info.uid}, in ${dir}, where any account may add an entry`
				: `${here} belongs to uid ${info.uid}, which is not root, this account or koid's account koi`;
		}
		if (info.isSymbolicLink()) {
			links++;
			if (links > MAX_LINKS) {
				return `more than ${MAX_LINKS} symbolic links on the way to ${path}`;
			}
			// The target, from / or from the link's directory, then the rest.
			const target = await readlink(here);
			if (target.startsWith('/')) {
				dir = '/';
				dirInfo = root;
			}
			rest = [...parts(target), ...rest];
			continue;
		}
		dir = here;
		dirInfo = info;
	}
	return undefined;
}

function parts(path: string): string[] {
	return path.split('/').filter((p) => p !== '');
}

// The uid of `name` in a passwd file, or undefined when the file or the
// account is not there.
export async function accountUid(name: string, file: string): Promise<number | undefined> {
	let text: string;
	try {
		text = await readFile(file, 'utf8');
	} catch {
		return undefined;
	}
	for (const line of text.split('\n')) {
		const fields = line.split(':');
		if (fields[0] === name && /^\d+$/.test(fields[2] ?? '')) return Number(fields[2]);
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
	// A signal that fired while connecting, before the listener below.
	if (signal?.aborted) {
		conn.destroy();
		signal.throwIfAborted();
	}
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
