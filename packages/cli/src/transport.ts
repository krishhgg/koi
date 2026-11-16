import {
	ErrorReplySchema,
	type HostInfo,
	type UpRequest,
	VerificationErrorReplySchema,
} from '@koi/shared';

// How the CLI reaches a host: upload source, wake it, run `koid ctl`, read
// its descriptor and follow logs. One implementation per transport; AWS over
// S3, EC2 and SSM is in transports/aws.ts. host.ts picks one from the
// selected target.

export interface OperationOptions {
	// Stops waiting. A command that was already sent may still run on the
	// host: see UnknownOutcomeError.
	signal?: AbortSignal | undefined;
	// How long to wait for the operation's result.
	timeoutMs?: number | undefined;
}

export type Progress = (message: string) => void;

export interface CtlResult {
	code: number;
	stdout: string;
	stderr: string;
}

// Which log to follow. For a build log, `attempt` and `cursor` say where to
// resume: the attempt whose log it is and a cursor from an earlier line
// event. Without them the stream starts with the preview's current attempt.
// With `requestId`, the stream stops when koid replaced that request with a
// newer one for the label.
export interface LogQuery {
	label: string;
	kind: 'build' | 'runtime';
	attempt?: string | undefined;
	cursor?: string | undefined;
	requestId?: string | undefined;
}

// One event of a log stream. A line's cursor resumes the stream right after
// that line, without missing or repeating one. A gap says lines may be
// missing from here: the host restarted the build, rotated the log away, or
// the stream reached the caller's time limit, in which case `end` follows.
export type LogEvent =
	| { type: 'line'; cursor: string; text: string }
	| { type: 'gap'; reason: string }
	| { type: 'end' };

export interface ChannelEvent {
	topic: string;
	cursor: string;
	body: unknown;
}

// A two-way connection to koid for verification calls and events. No
// transport opens one yet; the SSH transport will. Artifact transfer joins it
// then, with its shared protocol types.
export interface ControlChannel {
	readonly host: HostInfo;
	call(method: string, body: unknown, o?: OperationOptions): Promise<unknown>;
	subscribe(topic: string, cursor?: string): AsyncIterable<ChannelEvent>;
	close(): Promise<void>;
}

export interface HostTransport {
	// Puts the source and the request where koid reads them. On AWS that is
	// S3, which takes uploads while the box sleeps.
	upload(request: UpRequest, tarball: string, o?: OperationOptions): Promise<void>;
	// Starts the host if the transport can, then waits until koid answers.
	ensureAwake(progress: Progress, o?: OperationOptions): Promise<void>;
	// Runs `koid ctl` with these arguments. Throws BoxUnavailableError when
	// the command could not run to the end this time.
	ctl(args: string[], o?: OperationOptions): Promise<CtlResult>;
	// The host's descriptor. Throws UnsupportedCapabilityError('describe')
	// for a koid from before the descriptor existed.
	describe(o?: OperationOptions): Promise<HostInfo>;
	// Follows a log. A time limit bounds the whole stream: at it the stream
	// ends with a gap that says so, then end, and does not throw.
	streamLogs(q: LogQuery, o?: OperationOptions): AsyncIterable<LogEvent>;
	openChannel(o?: OperationOptions): Promise<ControlChannel>;
	close(): Promise<void>;
}

// The three methods the CLI used before there were transports, and the
// close main.ts calls once a command is done. up.ts and main.ts still take
// a Box; every HostTransport is one.
export type Box = Pick<HostTransport, 'upload' | 'ensureAwake' | 'ctl'> &
	Partial<Pick<HostTransport, 'close'>>;

// A koid ctl command did not run to the end, for a reason that can pass: the
// host not ready for commands, throttling, a fault on the provider's side, the
// network, or the command timing out or being cancelled on the host.
export class BoxUnavailableError extends Error {}

// The transport, or the host behind it, cannot do this. The caller must
// report it, not quietly do less.
export class UnsupportedCapabilityError extends Error {
	constructor(
		readonly capability: string,
		message: string,
	) {
		super(message);
	}
}

// A command was sent and koi stopped waiting for its result (the caller's
// signal or time limit). It may have run: a request may be accepted, a
// preview removed. Look at the host's state before doing it again.
export class UnknownOutcomeError extends Error {}

// The host's descriptor does not match the target: another domain or address
// than configured. Nothing is sent to koid after this.
export class HostMismatchError extends Error {}

// How many calls a transport stopped waiting for. Such a call ran into its
// time limit or the caller's signal and was left to settle on its own, so
// what the SDK started for it may still be running: a credential_process it
// spawned, or a retry it is waiting out. Neither ends with the command, and
// either keeps the runtime alive after it. main.ts ends the process itself
// when the count is above zero, once the command's output is written.
let abandoned = 0;

export function noteAbandonedCall(): void {
	abandoned += 1;
}

export function abandonedCalls(): number {
	return abandoned;
}

// Why koid ctl failed: the error in koid's JSON reply, in either of its
// shapes (the verification routes answer {version, error: {code, message}}),
// or else what it printed.
export function ctlErrorText(r: CtlResult): string {
	const text = (r.stderr || r.stdout).trim();
	try {
		const data: unknown = JSON.parse(text);
		const versioned = VerificationErrorReplySchema.safeParse(data);
		if (versioned.success) {
			return `${versioned.data.error.message} (${versioned.data.error.code})`;
		}
		const reply = ErrorReplySchema.safeParse(data);
		if (reply.success) return reply.data.error;
	} catch {}
	return text;
}

// The error for a wake that ran into the caller's time limit. The transports
// throw it from the wake itself, and verifiedTransport throws it when the
// wake returned with none of the limit left for the host check, so the two
// read the same. Its own class, so that an upload whose wait for the host
// ran into the upload's limit can report that limit as its own.
export class WakeTimeoutError extends Error {}

export function wakeTimeout(o: OperationOptions | undefined): WakeTimeoutError {
	return new WakeTimeoutError(`the box did not come awake within ${describeMs(o?.timeoutMs ?? 0)}`);
}

// A duration in words: whole minutes or seconds when it is one, else ms.
export function describeMs(ms: number): string {
	if (ms > 0 && ms % 60_000 === 0) return `${ms / 60_000} ${ms === 60_000 ? 'minute' : 'minutes'}`;
	if (ms > 0 && ms % 1000 === 0) return `${ms / 1000} ${ms === 1000 ? 'second' : 'seconds'}`;
	return `${ms} ms`;
}

export interface ExpectedHost {
	// The target's name, for messages.
	name: string;
	domain: string;
	// Take a koid from before `koid ctl describe` at its word, with a
	// warning. Only the AWS paths allow this: the CLI-only migration must not
	// require a koid upgrade. A mismatch or a descriptor koi cannot read is
	// never excused.
	oldDaemonOk: boolean;
}

// The descriptor against the target: it must name the target's domain and
// serve https on 443. Throws HostMismatchError otherwise.
export function checkHostInfo(info: HostInfo, expected: Pick<ExpectedHost, 'name' | 'domain'>) {
	if (info.domain !== expected.domain) {
		throw new HostMismatchError(
			`the host behind ${expected.name} serves previews under ${info.domain}, not ${expected.domain} as configured; koi stops rather than publish under the wrong domain. Fix the target's domain, or pass --domain ${info.domain} if that host is the right one`,
		);
	}
	if (info.address.scheme !== 'https' || info.address.port !== 443) {
		throw new HostMismatchError(
			`the host behind ${expected.name} serves previews on ${info.address.scheme} port ${info.address.port}; this version of koi expects https on 443`,
		);
	}
}

// The transport with the host checked against the target the first time it
// is awake: once koid answers, its descriptor must name the target's domain
// and address (checkHostInfo). The check sits in ensureAwake because every
// command wakes the host before it sends anything to koid, and on AWS koi
// up uploads to S3 before it wakes, so this is the first point where the
// host can answer and the last before source is handed to koid. A time
// limit on ensureAwake covers the wake and the check together. The SSH
// transport is not wrapped: its upload reaches koid directly, so it checks
// the descriptor itself, before the upload as well (transports/ssh.ts).
export function verifiedTransport(
	inner: HostTransport,
	expected: ExpectedHost,
	notice: (message: string) => void,
	now: () => number = Date.now,
): HostTransport {
	let verified: Promise<void> | undefined;
	const verify = async (o: OperationOptions | undefined, deadline: number | undefined) => {
		// The wake had the caller's whole limit. The check gets what the wake
		// left of it, and when nothing is left the call has run out of time:
		// it fails as the wake does, and sends nothing to koid.
		let timeoutMs: number | undefined;
		if (deadline !== undefined) {
			timeoutMs = deadline - now();
			if (timeoutMs <= 0) throw wakeTimeout(o);
		}
		let info: HostInfo;
		try {
			info = await inner.describe({ signal: o?.signal, timeoutMs });
		} catch (err) {
			if (
				err instanceof UnsupportedCapabilityError &&
				err.capability === 'describe' &&
				expected.oldDaemonOk
			) {
				notice(
					`koid on ${expected.name} predates koid ctl describe, so koi cannot check that it serves ${expected.domain}; taking the configured domain. Deploy the current koid (scripts/deploy-host.sh) to remove this warning`,
				);
				return;
			}
			throw err;
		}
		checkHostInfo(info, expected);
	};
	return {
		...inner,
		async ensureAwake(progress, o) {
			// One deadline, read before the wake starts, for the wake and the
			// check after it. Giving each its own copy of the limit would let
			// the call take twice what the caller allowed.
			const deadline = o?.timeoutMs === undefined ? undefined : now() + o.timeoutMs;
			await inner.ensureAwake(progress, o);
			verified ??= verify(o, deadline).catch((err: unknown) => {
				// A failed check is not a verdict; the next wake checks again.
				verified = undefined;
				throw err;
			});
			await verified;
		},
	};
}
