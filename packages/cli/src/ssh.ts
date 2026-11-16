import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Env } from './config.ts';

// The system OpenSSH client, as the SSH transport drives it (transports/
// ssh.ts). ssh is run with an argument array, never through a shell, and
// with every option on the command line: `-F none` keeps it from reading
// the user's or the system's ssh_config, so nothing outside the target can
// add a ProxyCommand, a forwarding or another identity. The host key is
// pinned in the target's own known_hosts file under its alias and nothing
// else is consulted; a key that is missing or changed stops the connection
// (StrictHostKeyChecking=yes), and `koi target trust` is the only way to
// enroll one. The identity is the target's private key file alone, or the
// one key ssh-agent holds for the target's public key (IdentitiesOnly=yes
// with a public key file). No PTY, no agent or X11 forwarding, no local
// command, batch mode so nothing ever prompts.
//
// One master connection serves every session of a koi process
// (ControlMaster=auto): the first ssh opens the connection and stays in the
// background as the master, each later one is a cheap session on it. The
// control socket lives in a directory of this process alone, mode 0700, and
// close() ends the master and removes the directory. Should koi die without
// closing, the master ends itself after CONTROL_PERSIST_S idle.
//
// ssh reads each `-o` value with its ssh_config parser, which splits on
// whitespace: an unquoted `UserKnownHostsFile=/a b` names two files, /a and
// a relative `b`, and the second could supply trust from the working
// directory. Every path is therefore passed in double quotes (quoteSshValue),
// and a path ssh could not read back whole is refused (sshPathProblem).

// What the client needs to know of a target. The config schema (config.ts,
// SshEndpoint) fixes the user to koi-connect; this type leaves it a string so
// a test can run a throwaway sshd as the current user.
export interface SshTarget {
	host: string;
	port: number;
	user: string;
	identityFile?: string | undefined;
	identityPublicKey?: string | undefined;
	knownHostsFile: string;
	hostKeyAlias: string;
}

// How long an idle master stays alive without a close(), in seconds.
export const CONTROL_PERSIST_S = 600;

const CLOSED = 'the SSH connection is closed';

// A running ssh, as the transport sees it: bytes in and out of the remote
// command, its exit status, and a kill for the caller's signal or deadline.
export interface SshProcess {
	// Sends bytes to the remote command's stdin. Settles once ssh has taken
	// the chunk, so a slow link holds the writer back rather than buffer.
	write(chunk: Uint8Array): Promise<void>;
	// Closes the remote command's stdin.
	end(): Promise<void>;
	stdout: ReadableStream<Uint8Array>;
	stderr: ReadableStream<Uint8Array>;
	// ssh's exit status: the remote command's, or 255 for ssh's own failure.
	exited: Promise<number>;
	kill(): void;
}

export interface SpawnRequest {
	cmd: string[];
	env: Record<string, string>;
	// Whether the remote command reads stdin (tunnel-v1) or has none.
	stdin: boolean;
}

export type SshSpawn = (request: SpawnRequest) => SshProcess;

// The program could not be started: OpenSSH is not installed or not on PATH.
export class SshMissingError extends Error {}

// Runs ssh with Bun.spawn. The executable is looked up on PATH here, so the
// child gets a resolved path and not a name to search for.
export const spawnSsh: SshSpawn = (request) => {
	const [program, ...rest] = request.cmd;
	const resolved = Bun.which(program ?? '', { PATH: request.env.PATH ?? '' });
	if (resolved === null) {
		throw new SshMissingError(
			`cannot find ${program} on PATH; koi reaches an SSH target through the system OpenSSH client`,
		);
	}
	const proc = Bun.spawn([resolved, ...rest], {
		env: request.env,
		stdin: request.stdin ? 'pipe' : 'ignore',
		stdout: 'pipe',
		stderr: 'pipe',
	});
	const sink = request.stdin ? (proc.stdin as Bun.FileSink) : undefined;
	return {
		async write(chunk) {
			if (sink === undefined) throw new Error('this ssh has no stdin');
			const written = sink.write(chunk);
			if (written instanceof Promise) await written;
			const flushed = sink.flush();
			if (flushed instanceof Promise) await flushed;
		},
		async end() {
			if (sink === undefined) return;
			const ended = sink.end();
			if (ended instanceof Promise) await ended;
		},
		stdout: proc.stdout as ReadableStream<Uint8Array>,
		stderr: proc.stderr as ReadableStream<Uint8Array>,
		exited: proc.exited,
		kill() {
			proc.kill('SIGKILL');
		},
	};
};

// Why ssh could not be given this path as an option value, or undefined
// when it can. A newline ends the option and starts another; `%` begins a
// token ssh expands (%d, %h and so on) and `${NAME}` an environment
// variable it reads, and quoting stops neither; a control character has no
// place in a path ssh is told about. The config schema refuses these
// (config.ts, SshPathSchema), so the message is for a person editing the
// file.
export function sshPathProblem(path: string): string | undefined {
	if (path.includes('%')) return 'ssh would expand % in it as a token';
	// biome-ignore lint/suspicious/noTemplateCurlyInString: ssh's syntax for a variable, not a template
	if (path.includes('${')) return 'ssh would expand ${NAME} in it as an environment variable';
	if (/[\n\r]/.test(path)) return 'ssh reads a line break as the end of the option';
	// biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are the point
	if (/[\u0000-\u001f\u007f]/.test(path)) return 'it has a control character';
	return undefined;
}

// The value as ssh_config syntax reads it back whole: in double quotes,
// with the backslash and the double quote escaped. ssh splits an unquoted
// value on whitespace, and a `#` at the start of a word begins a comment;
// neither applies inside quotes.
export function quoteSshValue(value: string): string {
	return `"${value.replace(/[\\"]/g, (c) => `\\${c}`)}"`;
}

// A path as an option value, or an error for one ssh could not take.
function sshPath(what: string, path: string): string {
	const problem = sshPathProblem(path);
	if (problem !== undefined) {
		throw new Error(`the ${what} ${JSON.stringify(path)} cannot be given to ssh: ${problem}`);
	}
	return quoteSshValue(path);
}

// The ssh command line for `command` on the target, with the master's
// control socket at `controlPath`. Every option is here; see the top of
// this file for why each is set. The target's identity, known_hosts file
// and alias come from the config file, nothing from the environment.
export function sshArgs(target: SshTarget, controlPath: string, command?: string): string[] {
	const identity = target.identityFile ?? target.identityPublicKey;
	if (identity === undefined) throw new Error('an SSH target needs an identity');
	const options = [
		// No ssh_config, of the user or the system.
		'-F none',
		'BatchMode=yes',
		'IdentitiesOnly=yes',
		`IdentityFile=${sshPath('identity file', identity)}`,
		// A private key file is the whole identity: no agent is asked. A
		// public key file names a key the agent holds, so the agent stays.
		...(target.identityFile !== undefined ? ['IdentityAgent=none'] : []),
		'PubkeyAuthentication=yes',
		'PreferredAuthentications=publickey',
		'PasswordAuthentication=no',
		'KbdInteractiveAuthentication=no',
		'HostbasedAuthentication=no',
		'GSSAPIAuthentication=no',
		'NumberOfPasswordPrompts=0',
		'StrictHostKeyChecking=yes',
		`UserKnownHostsFile=${sshPath('known_hosts file', target.knownHostsFile)}`,
		'GlobalKnownHostsFile=/dev/null',
		`HostKeyAlias=${target.hostKeyAlias}`,
		'CheckHostIP=no',
		'UpdateHostKeys=no',
		'HashKnownHosts=no',
		'RequestTTY=no',
		'ForwardAgent=no',
		'ForwardX11=no',
		'ForwardX11Trusted=no',
		'ClearAllForwardings=yes',
		'PermitLocalCommand=no',
		'ProxyCommand=none',
		'ProxyJump=none',
		'ConnectTimeout=30',
		'ServerAliveInterval=15',
		'ServerAliveCountMax=4',
		'ControlMaster=auto',
		`ControlPath=${sshPath('control socket', controlPath)}`,
		`ControlPersist=${CONTROL_PERSIST_S}`,
		'LogLevel=ERROR',
		`Port=${target.port}`,
		`User=${target.user}`,
	];
	return [
		'ssh',
		...options.flatMap((o) => (o.startsWith('-') ? o.split(' ') : ['-o', o])),
		'--',
		target.host,
		...(command === undefined ? [] : [command]),
	];
}

// The environment ssh runs with: PATH, so that it finds itself and its
// helpers, and the agent socket only when the target's identity lives in
// the agent. Nothing else of koi's environment reaches it.
export function sshEnv(target: SshTarget, env: Env): Record<string, string> {
	const out: Record<string, string> = {};
	if (env.PATH !== undefined) out.PATH = env.PATH;
	if (target.identityPublicKey !== undefined && env.SSH_AUTH_SOCK !== undefined) {
		out.SSH_AUTH_SOCK = env.SSH_AUTH_SOCK;
	}
	return out;
}

export interface SshClientOptions {
	target: SshTarget;
	env: Env;
	spawn?: SshSpawn | undefined;
	// Makes the directory for the control socket; mkdtemp under the system
	// temporary directory unless a test passes its own.
	controlDir?: (() => Promise<string>) | undefined;
}

// One target's ssh sessions over one master connection.
export class SshClient {
	private readonly target: SshTarget;
	private readonly env: Env;
	private readonly spawn: SshSpawn;
	private readonly makeControlDir: () => Promise<string>;
	private controlDir: Promise<string> | undefined;
	private closed = false;
	// The opens past their first checks, each settled once its session is
	// in `sessions` or it has thrown, so that close can wait for them
	// before it sweeps and no session starts after it.
	private readonly opening = new Set<Promise<unknown>>();
	// The sessions still running, for close to end.
	private readonly sessions = new Set<SshProcess>();
	// The one close, which every call of close returns.
	private closing: Promise<void> | undefined;

	constructor(options: SshClientOptions) {
		this.target = options.target;
		this.env = options.env;
		this.spawn = options.spawn ?? spawnSsh;
		this.makeControlDir = options.controlDir ?? (() => mkdtemp(join(tmpdir(), 'koi-ssh-')));
	}

	// The control socket's path; its directory is made on first use.
	private async controlPath(): Promise<string> {
		this.controlDir ??= this.makeControlDir().catch((err: unknown) => {
			this.controlDir = undefined;
			throw err;
		});
		return join(await this.controlDir, 'm');
	}

	// Starts `command` on the target. With `stdin`, the process takes bytes
	// for the command's stdin; without, its stdin is closed. `signal` kills
	// the process when it fires.
	async open(command: string, stdin: boolean, signal?: AbortSignal): Promise<SshProcess> {
		if (this.closed) throw new Error(CLOSED);
		signal?.throwIfAborted();
		const started = this.start(command, stdin, signal);
		this.opening.add(started);
		try {
			return await started;
		} finally {
			this.opening.delete(started);
		}
	}

	// The rest of open: the control directory, which takes a turn of the
	// event loop to make, then the process. A close or an abort can come in
	// that turn, so both are checked again after the wait and before
	// anything is spawned; a process is never started for a connection that
	// is closed or a call that is over.
	private async start(command: string, stdin: boolean, signal?: AbortSignal): Promise<SshProcess> {
		const controlPath = await this.controlPath();
		if (this.closed) throw new Error(CLOSED);
		signal?.throwIfAborted();
		const proc = this.spawn({
			cmd: sshArgs(this.target, controlPath, command),
			env: sshEnv(this.target, this.env),
			stdin,
		});
		this.sessions.add(proc);
		void proc.exited.finally(() => this.sessions.delete(proc));
		if (signal !== undefined) {
			const kill = () => proc.kill();
			signal.addEventListener('abort', kill, { once: true });
			void proc.exited.finally(() => signal.removeEventListener('abort', kill));
		}
		return proc;
	}

	// Runs `command` with no stdin and collects what it printed, up to
	// `maxStdout` bytes of stdout. Throws on more: koid's replies are
	// bounded, so longer output is not one of them.
	async run(
		command: string,
		signal?: AbortSignal,
		maxStdout = 1024 ** 2,
	): Promise<{ code: number; stdout: string; stderr: string }> {
		const proc = await this.open(command, false, signal);
		// Output past the bound ends the process the moment it is seen: a
		// command that keeps printing would otherwise be waited for to the
		// end, and one that never stops, forever.
		const [stdout, stderr] = await Promise.all([
			readAll(proc.stdout, maxStdout).then((text) => {
				if (text === undefined) proc.kill();
				return text;
			}),
			readAll(proc.stderr, 64 * 1024),
		]);
		const code = await proc.exited;
		if (stdout === undefined) {
			throw new Error(
				`the output of ${command.split(' ')[0]} on ${this.target.host} passed ${maxStdout} bytes; koi does not use part of a reply`,
			);
		}
		return { code, stdout, stderr: stderr ?? '' };
	}

	// Ends every session still running, then the master connection, if one
	// was started, and removes its directory. A session is killed rather
	// than waited for: close comes when the command is over, or when a
	// signal ends it, and a session that is still connecting would hold the
	// process to ssh's own timeout. Every call returns the one close, so a
	// second caller waits for it rather than return while it runs.
	close(): Promise<void> {
		this.closed = true;
		this.closing ??= this.end();
		return this.closing;
	}

	private async end(): Promise<void> {
		// An open past its first checks either registers its session here,
		// for the sweep, or throws now that the connection is closed; the
		// sweep waits for it to do one or the other. An open that starts
		// after this throws at once.
		await Promise.allSettled(this.opening);
		for (const proc of this.sessions) proc.kill();
		this.sessions.clear();
		const dir = this.controlDir;
		this.controlDir = undefined;
		if (dir === undefined) return;
		let path: string;
		try {
			path = await dir;
		} catch {
			return;
		}
		try {
			const proc = this.spawn({
				cmd: [
					'ssh',
					'-F',
					'none',
					'-o',
					`ControlPath=${quoteSshValue(join(path, 'm'))}`,
					'-O',
					'exit',
					'--',
					this.target.host,
				],
				env: sshEnv(this.target, this.env),
				stdin: false,
			});
			// A master that is already gone answers with an error; either way
			// the exit is awaited, bounded, so close never hangs on it.
			const timer = setTimeout(() => proc.kill(), 5000);
			await Promise.all([proc.exited, drain(proc.stdout), drain(proc.stderr)]).finally(() =>
				clearTimeout(timer),
			);
		} catch {
			// Without ssh there is no master to end.
		}
		await rm(path, { recursive: true, force: true });
	}
}

// The whole stream as text, or undefined once it passes `max` bytes.
export async function readAll(
	stream: ReadableStream<Uint8Array>,
	max: number,
): Promise<string | undefined> {
	const decoder = new TextDecoder();
	const parts: string[] = [];
	let bytes = 0;
	for await (const chunk of stream) {
		bytes += chunk.byteLength;
		if (bytes > max) {
			await stream.cancel().catch(() => {});
			return undefined;
		}
		parts.push(decoder.decode(chunk, { stream: true }));
	}
	parts.push(decoder.decode());
	return parts.join('');
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<void> {
	for await (const _ of stream) {
		// Discarded.
	}
}
