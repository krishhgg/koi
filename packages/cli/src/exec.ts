// Runs a program with an argument array (never a shell string), with an
// optional time limit and a callback per output line.
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

export async function exec(cmd: string[], options: ExecOptions = {}): Promise<ExecResult> {
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
	const proc = spawn(cmd, options.stdin, options.env);
	let timedOut = false;
	let tooLarge = false;
	const timer =
		options.timeoutMs === undefined
			? undefined
			: setTimeout(() => {
					timedOut = true;
					proc.kill('SIGKILL');
				}, options.timeoutMs);
	try {
		const [stdout, stderr] = await Promise.all([
			collectAll(proc.stdout, options.onLine, maxBytes, () => {
				tooLarge = true;
				proc.kill('SIGKILL');
			}),
			collectTail(proc.stderr, options.onLine),
		]);
		const code = await proc.exited;
		if (tooLarge) throw new OutputTooLargeError(cmd, maxBytes);
		return { code, stdout, stderr, timedOut };
	} finally {
		if (timer !== undefined) clearTimeout(timer);
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

// The whole stream, or '' after calling onOverflow once it passes maxBytes.
async function collectAll(
	stream: ReadableStream<Uint8Array>,
	onLine: ((line: string) => void) | undefined,
	maxBytes: number,
	onOverflow: () => void,
): Promise<string> {
	const decoder = new TextDecoder();
	const lines = lineSplitter(onLine);
	const chunks: string[] = [];
	let bytes = 0;
	for await (const chunk of stream) {
		bytes += chunk.byteLength;
		if (bytes > maxBytes) {
			onOverflow();
			return '';
		}
		const text = decoder.decode(chunk, { stream: true });
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
	stream: ReadableStream<Uint8Array>,
	onLine: ((line: string) => void) | undefined,
): Promise<string> {
	const decoder = new TextDecoder();
	const lines = lineSplitter(onLine);
	let kept = '';
	for await (const chunk of stream) {
		const text = decoder.decode(chunk, { stream: true });
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
