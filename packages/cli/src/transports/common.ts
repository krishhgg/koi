import {
	CTL_EXIT,
	type HostInfo,
	HostInfoSchema,
	IN_FLIGHT_STATUSES,
	NO_SUCH_PREVIEW,
	PingReplySchema,
	type StatusReply,
	StatusReplySchema,
} from '@koi/shared';
import {
	BoxUnavailableError,
	type CtlResult,
	ctlErrorText,
	describeMs,
	type LogEvent,
	type LogQuery,
	noteAbandonedCall,
	type OperationOptions,
	UnknownOutcomeError,
	UnsupportedCapabilityError,
} from '../transport.ts';

// What every transport does the same way once it can run `koid ctl`: read
// the host descriptor, follow a build log by polling status, and hold each
// call to the caller's deadline and signal. The AWS transport (aws.ts) did
// this first; the SSH transport (ssh.ts) shares it unchanged.

export type Ctl = (args: string[], o?: OperationOptions) => Promise<CtlResult>;

// The host's descriptor through `koid ctl describe`.
export async function describeViaCtl(ctl: Ctl, o: OperationOptions | undefined) {
	const r = await ctl(['describe'], o);
	// A koid from before the descriptor: its ctl knows no such command
	// and answers as for bad arguments.
	if (r.code === CTL_EXIT.usage) {
		throw new UnsupportedCapabilityError(
			'describe',
			'koid on the box does not answer koid ctl describe; it predates the host descriptor',
		);
	}
	if (r.code !== CTL_EXIT.ok) {
		throw new Error(ctlErrorText(r) || `koid ctl describe exited ${r.code}`);
	}
	return parseDescriptor(r);
}

// The descriptor a successful `koid ctl describe` printed.
export function parseDescriptor(r: CtlResult): HostInfo {
	const parsed = HostInfoSchema.safeParse(parseJson(r.stdout));
	if (!parsed.success) {
		throw new Error(
			`koid ctl describe returned a descriptor koi cannot read: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
		);
	}
	return parsed.data;
}

// How long ensureAwake waits for koid to answer once the host answers.
export const KOID_READY_MS = 5 * 60_000;

// How long streamLogs keeps asking for a status while the host or koid cannot
// answer, as while koid restarts.
export const STATUS_RETRY_MS = 5 * 60_000;

// How long streamLogs waits between two status reads of a build in flight.
export const STATUS_POLL_MS = 3000;

// A build log as koid ctl status pages it: the lines of one attempt from a
// byte offset, with the offset to ask for next. The stream follows the
// attempt koid is on: when koid builds the request again, a gap says so and
// the new attempt's log follows from its start. It ends once the build has
// finished and its log is drained. A cursor is `<offset>:<skip>`: page from
// that byte offset and skip that many lines, which resumes exactly after the
// line that carried it, since koid pages a finished stretch of log the same
// way each time. With a time limit, the whole stream has one deadline from
// its start, and ends there with a gap that says so, then `end`.
export async function* buildLog(
	q: LogQuery,
	o: OperationOptions | undefined,
	ctl: Ctl,
	sleep: (ms: number) => Promise<void>,
	now: () => number,
): AsyncGenerator<LogEvent> {
	let attempt = q.attempt;
	let { offset, skip } = q.cursor === undefined ? { offset: 0, skip: 0 } : parseCursor(q.cursor);
	let wait = false;
	let failing: { since: number; why: string } | undefined;
	// The limit is on the stream, not on each status read: a limit set on
	// each read alone would let a stream whose reads all finish in time go
	// on for as long as the build does. The deadline is set when the caller
	// first pulls, which is when the stream starts for it, and every read
	// gets what is left of it.
	const deadline = o?.timeoutMs === undefined ? undefined : now() + o.timeoutMs;
	const left = () => (deadline === undefined ? undefined : deadline - now());
	for (;;) {
		// A wait between reads is cut to what is left, so the stream ends at
		// the deadline and not up to a poll interval after it.
		if (wait) {
			const ms = left();
			await sleep(ms === undefined ? STATUS_POLL_MS : Math.max(0, Math.min(STATUS_POLL_MS, ms)));
		}
		wait = true;
		o?.signal?.throwIfAborted();
		const read =
			deadline !== undefined && now() >= deadline
				? { overdue: true as const }
				: await readStatus(
						ctl,
						q.label,
						attempt === undefined
							? ['status', q.label]
							: ['status', q.label, attempt, String(offset)],
						{ signal: o?.signal, timeoutMs: left() },
					);
		if ('overdue' in read) {
			// The caller asked for the limit, and the lines so far stand. The
			// gap says the log may go on past them; throwing would make a
			// bounded follow look like a failure.
			yield {
				type: 'gap',
				reason: `stopped following ${q.label} at the ${describeMs(o?.timeoutMs ?? 0)} limit; the build log may go on`,
			};
			yield { type: 'end' };
			return;
		}
		if ('unavailable' in read) {
			failing = { since: failing?.since ?? now(), why: read.unavailable };
			if (now() - failing.since > STATUS_RETRY_MS) {
				throw new Error(
					`could not read the status of ${q.label} for ${Math.round(STATUS_RETRY_MS / 60_000)} minutes: ${failing.why}`,
				);
			}
			continue;
		}
		failing = undefined;
		const { record, log } = read.reply;
		if (q.requestId !== undefined && record.requestId !== q.requestId) {
			throw new Error(`superseded by a newer koi up for ${q.label}`);
		}
		if (record.attempt !== attempt) {
			if (attempt !== undefined) {
				yield {
					type: 'gap',
					reason: `koid is building ${q.label} again; its new build log follows from the start`,
				};
			}
			attempt = record.attempt;
			offset = 0;
			skip = 0;
			wait = false;
			continue;
		}
		for (const [i, text] of log.lines.entries()) {
			if (i < skip) continue;
			yield { type: 'line', cursor: `${offset}:${i + 1}`, text };
		}
		skip = 0;
		if (log.lines.length > 0) offset = log.next;
		// Any status but an in-flight one is a verdict on the build: running,
		// failed, and also stopped or expired, which koid keeps the record and
		// log of. The log will not grow, so drain it and end.
		if (!IN_FLIGHT_STATUSES.has(record.status)) {
			if (log.lines.length === 0) {
				yield { type: 'end' };
				return;
			}
			// The build has finished; drain the rest of its log first.
			wait = false;
		}
	}
}

// One SDK call ended before it answered: the caller's signal fired, or the
// time limit passed. The SDK's own AbortError is not kept: whichever of the
// two it was, the caller tells by looking at its signal.
export class InterruptedError extends Error {}

// The longest wait a timer takes; a longer one would fire at once.
const MAX_TIMER_MS = 2 ** 31 - 1;

// Runs one call and ends it when the caller's signal fires or when
// `deadline` passes, whichever is first. Without either the call runs as it
// is. The SDK gets a signal that is aborted then, but the result does not
// wait on it: credential resolution and retry back-off in the SDK do not
// watch the signal, so a slow credential_process could hold a call minutes
// past its deadline. Instead the call races the deadline, and the loser is
// left to settle on its own, unobserved, and counted (noteAbandonedCall):
// what the SDK started for it may outlive the command. The deadline is on
// the injected clock and the timer is a real one, which agree outside tests;
// the loops that call this check the clock as well.
export async function within<T>(
	signal: AbortSignal | undefined,
	deadline: number | undefined,
	now: () => number,
	send: (abortSignal: AbortSignal | undefined) => Promise<T>,
): Promise<T> {
	if (signal === undefined && deadline === undefined) return send(undefined);
	const stop = new AbortController();
	let interrupt!: () => void;
	const interrupted = new Promise<never>((_, reject) => {
		interrupt = () => {
			stop.abort();
			reject(new InterruptedError('the call was interrupted'));
		};
	});
	if (signal?.aborted) interrupt();
	else signal?.addEventListener('abort', interrupt, { once: true });
	const timer =
		deadline === undefined
			? undefined
			: setTimeout(interrupt, Math.min(Math.max(0, deadline - now()), MAX_TIMER_MS));
	try {
		return await Promise.race([send(stop.signal), interrupted]);
	} catch (err) {
		// The SDK may answer the abort with its own error first; the caller
		// is told it was interrupted either way. The call is left behind,
		// and with it whatever the SDK started for it.
		if (stop.signal.aborted) {
			noteAbandonedCall();
			throw new InterruptedError('the call was interrupted');
		}
		throw err;
	} finally {
		if (timer !== undefined) clearTimeout(timer);
		signal?.removeEventListener('abort', interrupt);
	}
}

export function parseCursor(cursor: string): { offset: number; skip: number } {
	const m = /^(0|[1-9][0-9]{0,14}):(0|[1-9][0-9]{0,5})$/.exec(cursor);
	if (m === null) throw new Error(`${JSON.stringify(cursor)} is not a build log cursor`);
	return { offset: Number(m[1]), skip: Number(m[2]) };
}

// One status read: koid's reply, why it could not be had this time, or that
// the stream's time limit passed while koi waited for it. Throws on a
// failure that asking again will not fix, and when the caller's signal
// ended the read.
async function readStatus(
	ctl: Ctl,
	label: string,
	args: string[],
	o: OperationOptions | undefined,
): Promise<{ reply: StatusReply } | { unavailable: string } | { overdue: true }> {
	let r: CtlResult;
	try {
		r = await ctl(args, o);
	} catch (err) {
		if (err instanceof BoxUnavailableError) return { unavailable: err.message };
		// A read koi stopped waiting for has no outcome worth knowing: status
		// changes nothing on the box. ctl stops waiting for the caller's
		// signal, which keeps its error, or for the time limit.
		if (err instanceof UnknownOutcomeError && !o?.signal?.aborted) return { overdue: true };
		throw err;
	}
	if (r.code === CTL_EXIT.unavailable) return { unavailable: ctlErrorText(r) };
	if (r.code !== CTL_EXIT.ok) {
		const why = ctlErrorText(r) || `koid ctl status exited ${r.code}`;
		throw new Error(
			why === NO_SUCH_PREVIEW
				? `koid no longer has ${label}; someone may have removed it with koi down`
				: `stopped following ${label}: ${why}`,
		);
	}
	return { reply: StatusReplySchema.parse(parseJson(r.stdout)) };
}

export function parseJson(text: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
}

export function saysOk(stdout: string): boolean {
	try {
		return PingReplySchema.safeParse(JSON.parse(stdout)).success;
	} catch {
		return false;
	}
}
