#!/usr/bin/env bun
import { connect } from 'node:net';
import type { Readable, Writable } from 'node:stream';
import { type CtlIo, ctlEncoded, socketFetch } from '../../packages/daemon/src/ctl.ts';
import { CTL_EXIT, decodeCtlArgs } from '../../packages/shared/src/index.ts';

// The forced command for the koi-connect account on a host the CLI reaches
// over SSH (packages/cli/src/transports/ssh.ts). sshd runs it for every
// session of that account, whatever the client asked for, with the client's
// request in SSH_ORIGINAL_COMMAND. It takes two commands and nothing else:
//
//   ctl-b64 <blob>   runs koid ctl with the arguments the blob encodes,
//                    through the same client koid's own `ctl-b64` uses
//                    (packages/daemon/src/ctl.ts), and exits as it does;
//   tunnel-v1        copies bytes between the session and koid's control
//                    socket until either side ends, parsing nothing. The
//                    CLI speaks HTTP over it to the upload API.
//
// The command is matched as an exact grammar, never handed to a shell. A
// request for a shell (no command), scp, sftp, rsync, an environment
// assignment, a second argument or any other word is refused with exit 2
// and nothing runs. The control socket's path is fixed here, or set by the
// sshd configuration (`--socket`), never by the environment, which is
// cleared before anything else runs. The gateway spawns nothing and opens
// nothing but the socket.
//
// Built with `bun build --compile` and installed root-owned at
// /usr/local/libexec/koi-ssh-gateway (host/ssh/install.sh); run from source
// with bun in tests.

export const CONTROL_SOCKET = '/run/koi/control.sock';

export type Command = { verb: 'ctl-b64'; blob: string } | { verb: 'tunnel-v1' };

// A request outside the grammar.
export class RefusedError extends Error {}

const CTL_B64 = /^ctl-b64 ([A-Za-z0-9+/]+={0,2})$/;

// The verbs of file transfer, named in the refusal so the reason is plain.
const TRANSFER = new Set(['scp', 'sftp', 'internal-sftp', 'rsync', 'sftp-server']);

// The most a request may be. A blob is at most 16 KiB (decodeCtlArgs).
const MAX_COMMAND_CHARS = 32 * 1024;

export function parseCommand(command: string | undefined): Command {
	if (command === undefined || command === '') {
		throw new RefusedError('this account runs no shell; it takes "ctl-b64 <blob>" or "tunnel-v1"');
	}
	if (command.length > MAX_COMMAND_CHARS) throw new RefusedError('the request is too long');
	if (command === 'tunnel-v1') return { verb: 'tunnel-v1' };
	const m = CTL_B64.exec(command);
	if (m?.[1] !== undefined) {
		// What koid ctl-b64 would refuse is refused here, before anything
		// reaches it.
		try {
			decodeCtlArgs(m[1]);
		} catch (err) {
			throw new RefusedError(`ctl-b64: ${message(err)}`);
		}
		return { verb: 'ctl-b64', blob: m[1] };
	}
	const word = command.split(/\s/, 1)[0] ?? '';
	if (TRANSFER.has(word)) {
		throw new RefusedError(
			`file transfer is not available on this account (${JSON.stringify(word)})`,
		);
	}
	throw new RefusedError(
		`${JSON.stringify(command.slice(0, 80))} is not a command of this account; it takes "ctl-b64 <blob>" or "tunnel-v1"`,
	);
}

// The socket from the gateway's own arguments, which the sshd configuration
// sets (ForceCommand), or the fixed path.
export function socketFromArgv(argv: string[]): string {
	if (argv.length === 0) return CONTROL_SOCKET;
	const [flag, path, ...rest] = argv;
	if (flag === '--socket' && path !== undefined && path.startsWith('/') && rest.length === 0) {
		return path;
	}
	throw new Error('usage: koi-ssh-gateway [--socket /path/to/control.sock]');
}

// Removes every variable: nothing after this reads the environment, and
// nothing that might (a library's proxy setting, say) finds anything.
export function sanitizeEnvironment(env: NodeJS.ProcessEnv = process.env): void {
	for (const key of Object.keys(env)) delete env[key];
}

export interface GatewayStreams {
	stdin: Readable;
	stdout: Writable;
	stderr: (text: string) => void;
}

// Runs one request and returns the exit status.
export async function gateway(
	command: string | undefined,
	argv: string[],
	socket: string,
	streams: GatewayStreams,
): Promise<number> {
	let parsed: Command;
	try {
		parsed = parseCommand(command);
	} catch (err) {
		streams.stderr(`koi-ssh-gateway: ${message(err)}\n`);
		return CTL_EXIT.usage;
	}
	if (argv.length > 0) {
		// Never reached through sshd, whose configuration is root's; kept so
		// a wrong line there fails plainly.
		streams.stderr('koi-ssh-gateway: unexpected arguments\n');
		return CTL_EXIT.usage;
	}
	if (parsed.verb === 'ctl-b64') {
		const io: CtlIo = {
			stdout: (text) => void streams.stdout.write(text),
			stderr: streams.stderr,
			fetch: socketFetch(socket),
		};
		return ctlEncoded([parsed.blob], io);
	}
	return relay(socket, streams.stdin, streams.stdout, streams.stderr);
}

// Copies bytes between the session and koid's socket, both ways, until one
// side ends. The session's end of input ends the socket's write side, so
// koid sees the end of a request body; koid's end of output ends the relay,
// and with it the session. Nothing in between is read.
export function relay(
	socket: string,
	input: Readable,
	output: Writable,
	stderr: (text: string) => void,
): Promise<number> {
	return new Promise((resolve) => {
		let connected = false;
		let done = false;
		const finish = (code: number) => {
			if (done) return;
			done = true;
			input.unpipe();
			resolve(code);
		};
		const conn = connect({ path: socket, allowHalfOpen: true });
		conn.once('connect', () => {
			connected = true;
			input.pipe(conn);
			// The session's output stays open: it is the process's to end.
			conn.pipe(output, { end: false });
		});
		conn.on('error', (err) => {
			if (!connected) {
				stderr(`koi-ssh-gateway: cannot reach koid at ${socket}: ${err.message}\n`);
				return finish(CTL_EXIT.unavailable);
			}
			stderr(`koi-ssh-gateway: the connection to koid failed: ${err.message}\n`);
			finish(1);
		});
		// koid has sent everything it will: close the relay's side too, which
		// ends the socket, and with it the relay.
		conn.on('end', () => conn.end());
		conn.on('close', () => finish(0));
		input.on('error', (err) => {
			stderr(`koi-ssh-gateway: the session's input failed: ${err.message}\n`);
			conn.destroy();
			finish(1);
		});
		// The session is gone: nothing can take koid's bytes any more.
		output.on('error', () => {
			conn.destroy();
			finish(1);
		});
	});
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

if (import.meta.main) {
	const command = process.env.SSH_ORIGINAL_COMMAND;
	sanitizeEnvironment();
	let socket: string;
	let argv = process.argv.slice(2);
	try {
		socket = socketFromArgv(argv);
		argv = [];
	} catch (err) {
		process.stderr.write(`koi-ssh-gateway: ${message(err)}\n`);
		process.exit(CTL_EXIT.usage);
	}
	const code = await gateway(command, argv, socket, {
		stdin: process.stdin,
		stdout: process.stdout,
		stderr: (text) => void process.stderr.write(text),
	});
	// What was written to a pipe leaves with the stream's end, not before.
	await new Promise<void>((done) => process.stdout.end(done));
	process.exit(code);
}
