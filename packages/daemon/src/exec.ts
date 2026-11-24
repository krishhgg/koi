// Runs a program with an argument array (never a shell string), with an
// optional time limit and a callback per output line. By default the output
// kept in memory is capped, keeping the end, which is where errors are. A
// caller that parses the whole output sets maxBytes instead.
export interface ExecResult {
	code: number;
	stdout: string;
	stderr: string;
	timedOut: boolean;
}

export interface ExecOptions {
	timeoutMs?: number;
	onLine?: (line: string, stream: 'stdout' | 'stderr') => void;
	// Written to the process's stdin, which is then closed.
	stdin?: string | Uint8Array;
	// Ends the process when aborted: SIGTERM, then SIGKILL if it has not
	// exited after abortGraceMs. SIGTERM first because the docker CLI ends a
	// plugin such as buildx only when it gets to handle the signal; killed
	// outright, it can leave buildx building with the output pipes open.
	signal?: AbortSignal | undefined;
	abortGraceMs?: number;
	// Keeps all of each stream, up to this many bytes. When a stream passes
	// it, the process is killed and exec throws an ExecError, so the caller
	// never gets part of the output as if it were all of it.
	maxBytes?: number;
}

const KEEP_BYTES = 256 * 1024;

// How long an aborted process has to exit after SIGTERM, as docker stop
// gives a container.
const ABORT_GRACE_MS = 10_000;

// maxBytes for a command whose output koid parses whole.
export const WHOLE_OUTPUT = 32 * 1024 ** 2;

export async function exec(cmd: string[], options: ExecOptions = {}): Promise<ExecResult> {
	const proc = Bun.spawn(cmd, {
		stdin:
			options.stdin === undefined
				? 'ignore'
				: typeof options.stdin === 'string'
					? new TextEncoder().encode(options.stdin)
					: options.stdin,
		stdout: 'pipe',
		stderr: 'pipe',
	});
	let timedOut = false;
	const timer =
		options.timeoutMs === undefined
			? undefined
			: setTimeout(() => {
					timedOut = true;
					proc.kill('SIGKILL');
				}, options.timeoutMs);
	let killer: ReturnType<typeof setTimeout> | undefined;
	const abort = () => {
		proc.kill('SIGTERM');
		killer = setTimeout(() => proc.kill('SIGKILL'), options.abortGraceMs ?? ABORT_GRACE_MS);
	};
	if (options.signal?.aborted) abort();
	options.signal?.addEventListener('abort', abort, { once: true });
	const onLine = options.onLine;
	let tooLarge = false;
	const overflow = () => {
		tooLarge = true;
		proc.kill('SIGKILL');
	};
	try {
		const [stdout, stderr] = await Promise.all([
			collect(
				proc.stdout,
				onLine && ((line) => onLine(line, 'stdout')),
				options.maxBytes,
				overflow,
			),
			collect(
				proc.stderr,
				onLine && ((line) => onLine(line, 'stderr')),
				options.maxBytes,
				overflow,
			),
		]);
		const code = await proc.exited;
		const result = { code, stdout, stderr, timedOut };
		if (tooLarge) {
			throw new ExecError(cmd, result, `printed more than ${options.maxBytes} bytes`);
		}
		return result;
	} finally {
		if (timer !== undefined) clearTimeout(timer);
		if (killer !== undefined) clearTimeout(killer);
		options.signal?.removeEventListener('abort', abort);
	}
}

// Reads a stream to its end. With a limit, keeps all of it, or calls
// `overflow` and returns nothing once it passes the limit; without one,
// keeps the last KEEP_BYTES.
async function collect(
	stream: ReadableStream<Uint8Array>,
	onLine: ((line: string) => void) | undefined,
	limit: number | undefined,
	overflow: () => void,
): Promise<string> {
	const decoder = new TextDecoder();
	const whole: string[] = [];
	let kept = '';
	let bytes = 0;
	let partial = '';
	for await (const chunk of stream) {
		bytes += chunk.byteLength;
		if (limit !== undefined && bytes > limit) {
			overflow();
			return '';
		}
		const text = decoder.decode(chunk, { stream: true });
		if (limit === undefined) kept = (kept + text).slice(-KEEP_BYTES);
		else whole.push(text);
		if (onLine !== undefined) {
			const lines = (partial + text).split('\n');
			partial = lines.pop() ?? '';
			for (const line of lines) onLine(line);
		}
	}
	const rest = decoder.decode();
	if (onLine !== undefined && partial + rest !== '') onLine(partial + rest);
	if (limit !== undefined) return whole.join('') + rest;
	return (kept + rest).slice(-KEEP_BYTES);
}

export class ExecError extends Error {
	// `problem` replaces the exit status in the message, for a failure the
	// status does not describe.
	constructor(
		readonly cmd: string[],
		readonly result: ExecResult,
		problem?: string,
	) {
		const detail = (result.stderr || result.stdout).trim().split('\n').slice(-5).join('\n');
		const what = problem ?? (result.timedOut ? 'timed out' : `exited ${result.code}`);
		super(`${cmd.slice(0, 2).join(' ')} ${what}${detail ? `: ${detail}` : ''}`);
	}
}

export async function execOk(cmd: string[], options: ExecOptions = {}): Promise<ExecResult> {
	const result = await exec(cmd, options);
	if (result.code !== 0 || result.timedOut) throw new ExecError(cmd, result);
	return result;
}
