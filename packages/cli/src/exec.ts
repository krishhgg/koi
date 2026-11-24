// Runs a program with an argument array (never a shell string), with an
// optional time limit and a callback per output line.
//
// Each program runs in a session and process group of its own. A program
// that runs out of time, or writes too much, is killed with everything it
// started that stayed in its group (git fetch's ssh, a credential helper),
// and exec waits at most PIPE_GRACE_MS more for its output to end: a process
// that left the group can hold the pipes open for as long as it runs. With
// no terminal of their own, the programs cannot prompt on koi's: a git or
// ssh that needs a password fails rather than asks. killRunning ends them
// all when koi itself is interrupted.
//
// Stdout is kept whole up to `maxBytes`. A program that writes more is killed
// and exec throws OutputTooLargeError: callers parse stdout (file lists, JSON),
// and a list cut at an arbitrary byte can turn "src/.env" into ".env". Stderr
// is only for diagnostics, so its end is kept and the rest dropped.
export interface ExecResult {
	code: number;
	stdout: string;
	stderr: string;
	timedOut: boolean;
}

export interface ExecOptions {
	timeoutMs?: number;
	onLine?: (line: string) => void;
	stdin?: string;
	// The most stdout to accept, in bytes. Default 256 KiB.
	maxBytes?: number;
	// Variables to set for the program, on top of koi's own environment. A
	// variable given as undefined is removed from the program's environment.
	env?: Record<string, string | undefined>;
}

const DEFAULT_MAX_BYTES = 256 * 1024;
const STDERR_KEEP = 256 * 1024;

// For commands whose whole output the caller needs: file lists, API pages.
export const FULL_OUTPUT = 64 * 1024 * 1024;

export class OutputTooLargeError extends Error {
	constructor(
		readonly cmd: string[],
		readonly maxBytes: number,
	) {
		super(
			`${commandName(cmd)} wrote more than ${maxBytes} bytes; koi does not use part of a command's output`,
		);
	}
}

// The program could not be started: it is not installed, not on PATH, or
// not executable.
export class SpawnError extends Error {
	constructor(
		readonly program: string,
		cause: unknown,
	) {
		super(`cannot run ${program}: ${cause instanceof Error ? cause.message : String(cause)}`, {
			cause,
		});
	}
}

// How long exec waits for a killed program's output to end.
export const PIPE_GRACE_MS = 2_000;

// The programs exec is running, by process id, which is also the id of
// each one's process group.
const running = new Set<number>();

export async function exec(cmd: string[], options: ExecOptions = {}): Promise<ExecResult> {
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
	const proc = spawn(cmd, options.stdin, options.env);
	running.add(proc.pid);
	const out = proc.stdout.getReader();
	const err = proc.stderr.getReader();
	let timedOut = false;
	let tooLarge = false;
	let grace: ReturnType<typeof setTimeout> | undefined;
	// Kills the program's group, and after PIPE_GRACE_MS stops reading
	// whatever output is still open, which ends both collectors.
	const kill = () => {
		killGroup(proc.pid);
		grace ??= setTimeout(() => {
			out.cancel().catch(() => {});
			err.cancel().catch(() => {});
		}, PIPE_GRACE_MS);
	};
	const timer =
		options.timeoutMs === undefined
			? undefined
			: setTimeout(() => {
					timedOut = true;
					kill();
				}, options.timeoutMs);
	try {
		const [stdout, stderr] = await Promise.all([
			collectAll(out, options.onLine, maxBytes, () => {
				tooLarge = true;
				kill();
			}),
			collectTail(err, options.onLine),
		]);
		const code = await proc.exited;
		if (tooLarge) throw new OutputTooLargeError(cmd, maxBytes);
		return { code, stdout, stderr, timedOut };
	} finally {
		if (timer !== undefined) clearTimeout(timer);
		if (grace !== undefined) clearTimeout(grace);
		running.delete(proc.pid);
	}
}

// Kills every program exec is running, with what each started, for koi
// interrupted (see main): they are in groups of their own, so the signal
// that reached koi did not reach them.
export function killRunning(): void {
	for (const pid of running) killGroup(pid);
}

function killGroup(pid: number): void {
	try {
		process.kill(-pid, 'SIGKILL');
	} catch {
		// The group has ended.
	}
}

function spawn(
	cmd: string[],
	stdin: string | undefined,
	env: Record<string, string | undefined> | undefined,
) {
	try {
		return Bun.spawn(cmd, {
			stdin: stdin === undefined ? 'ignore' : new TextEncoder().encode(stdin),
			stdout: 'pipe',
			stderr: 'pipe',
			detached: true,
			...(env !== undefined ? { env: withEnv(env) } : {}),
		});
	} catch (err) {
		throw new SpawnError(cmd[0] ?? '', err);
	}
}

// koi's environment with `env` on top, less the variables `env` gives as
// undefined.
function withEnv(env: Record<string, string | undefined>): Record<string, string> {
	const merged: Record<string, string> = {};
	for (const [name, value] of Object.entries({ ...process.env, ...env })) {
		if (value !== undefined) merged[name] = value;
	}
	return merged;
}

// Calls onLine for each complete line, and once for a last line with no newline.
function lineSplitter(onLine: ((line: string) => void) | undefined) {
	let partial = '';
	return {
		push(text: string) {
			if (onLine === undefined) return;
			const lines = (partial + text).split('\n');
			partial = lines.pop() ?? '';
			for (const line of lines) onLine(line);
		},
		end(text: string) {
			if (onLine === undefined) return;
			if (partial + text !== '') onLine(partial + text);
		},
	};
}

// What the collectors need of a reader of a program's output.
interface Reader {
	read(): Promise<
		{ done: true; value?: Uint8Array | undefined } | { done: false; value: Uint8Array }
	>;
	cancel(): Promise<void>;
}

// The whole stream, or '' after calling onOverflow once it passes maxBytes.
async function collectAll(
	reader: Reader,
	onLine: ((line: string) => void) | undefined,
	maxBytes: number,
	onOverflow: () => void,
): Promise<string> {
	const decoder = new TextDecoder();
	const lines = lineSplitter(onLine);
	const chunks: string[] = [];
	let bytes = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		bytes += value.byteLength;
		if (bytes > maxBytes) {
			onOverflow();
			await reader.cancel().catch(() => {});
			return '';
		}
		const text = decoder.decode(value, { stream: true });
		chunks.push(text);
		lines.push(text);
	}
	const rest = decoder.decode();
	chunks.push(rest);
	lines.end(rest);
	return chunks.join('');
}

// The last STDERR_KEEP characters of the stream, which is where errors are.
async function collectTail(
	reader: Reader,
	onLine: ((line: string) => void) | undefined,
): Promise<string> {
	const decoder = new TextDecoder();
	const lines = lineSplitter(onLine);
	let kept = '';
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		const text = decoder.decode(value, { stream: true });
		kept = (kept + text).slice(-STDERR_KEEP);
		lines.push(text);
	}
	const rest = decoder.decode();
	kept = (kept + rest).slice(-STDERR_KEEP);
	lines.end(rest);
	return kept;
}

// A failed command, named for people: `git fetch` rather than `git -C`.
// `timeoutMs` is the limit it ran under, to say how long it was given.
export class ExecError extends Error {
	constructor(
		readonly cmd: string[],
		readonly result: ExecResult,
		timeoutMs?: number,
	) {
		const detail = (result.stderr || result.stdout).trim().split('\n').slice(-5).join('\n');
		const what = result.timedOut
			? `did not finish within ${timeoutMs === undefined ? 'its time limit' : duration(timeoutMs)}`
			: `exited ${result.code}`;
		super(`${commandName(cmd)} ${what}${detail ? `: ${detail}` : ''}`);
	}
}

export async function execOk(cmd: string[], options: ExecOptions = {}): Promise<ExecResult> {
	const result = await exec(cmd, options);
	if (result.code !== 0 || result.timedOut) throw new ExecError(cmd, result, options.timeoutMs);
	return result;
}

// The program and its subcommand: git's -C and -c options, and its long
// options before the subcommand, are skipped, and at most two words that
// look like subcommands are kept (gh pr view).
export function commandName(cmd: string[]): string {
	const [program = '', ...rest] = cmd;
	const words = [program];
	for (let i = 0; i < rest.length && words.length < 3; i++) {
		const word = rest[i] ?? '';
		if (program === 'git' && (word === '-C' || word === '-c')) {
			i++;
			continue;
		}
		if (program === 'git' && words.length === 1 && word.startsWith('--')) continue;
		if (!/^[a-z][a-z-]*$/.test(word)) break;
		words.push(word);
	}
	return words.join(' ');
}

function duration(ms: number): string {
	if (ms % 60_000 === 0) return ms === 60_000 ? '1 minute' : `${ms / 60_000} minutes`;
	return `${ms / 1000} seconds`;
}
