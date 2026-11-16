import { randomBytes } from 'node:crypto';
import {
	type Artifact,
	type ArtifactKind,
	RECORDER_CONTROL_PORT,
	RECORDER_OVERLONG_FIELD,
	type RecorderCapture,
	RecorderCaptureSchema,
	type RecorderContext,
	RecorderContextSchema,
	RecorderErrorSchema,
	type RecorderEventsPage,
	RecorderEventsPageSchema,
	type RecorderHealth,
	RecorderHealthSchema,
	type RunNetworkRecord,
} from '@koi/shared';
import type { Docker } from './docker.ts';
import type { SecretRegistry } from './redact.ts';
import {
	type BodyPolicy,
	isWithheldKind,
	LIMITATIONS,
	MAX_LIMITATIONS,
	policyDigest,
	type Sanitized,
	SanitizeError,
	sanitizeHttpResponse,
	sanitizeNetwork,
	sanitizeScreenshot,
	TextSanitizer,
	WITHHELD_KINDS,
} from './sanitize.ts';
import { privateHost, type VerificationNetwork } from './verification-network.ts';
import { scrubFields } from './verification-sanitize.ts';
import { CapExceededError, type RunWriter } from './verification-store.ts';

// koid's side of the recorder (docs/verify.md, "Recorder and evidence"):
// starts the stopped recorder B3a created, waits for it on the control port
// through the run network, has the firewall bind the run's permits to the
// recorder's bridge port now that it has one, and then asks it for a
// context, captures and state reads. Every capture's bytes come back raw,
// go through the kind's sanitizer, are hashed and written to the run's
// directory by the store, and only then is the recorder told to drop them.
// Every request carries the run's control token; the verifier gets the
// other token, for the browser port, and never this one.

export interface RecorderTokens {
	// koid's capability for the control port.
	control: string;
	// The verifier's capability for the browser port.
	browser: string;
}

export function newRecorderTokens(): RecorderTokens {
	return { control: randomBytes(32).toString('hex'), browser: randomBytes(32).toString('hex') };
}

// What the recorder is created with (RunNetworkRequest.recorderEnv).
export function recorderEnv(tokens: RecorderTokens): Record<string, string> {
	return {
		KOI_RECORDER_CONTROL_TOKEN: tokens.control,
		KOI_RECORDER_BROWSER_TOKEN: tokens.browser,
	};
}

export class RecorderError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string,
	) {
		super(message);
	}
}

// The recorder stopped answering: a call failed in transport (status 0,
// `unreachable`), not with an answer of its own. The session keeps the
// first such failure in `lost`, and every call that fails this way throws
// this, so the controller ends the run as interrupted (`recorder_lost`)
// instead of taking a lost recorder for a capture that failed.
export class RecorderLostError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'RecorderLostError';
	}
}

// The budget ended before a call was made, or while it was pending. Not a
// recorder failure: the controller decides what the run does with the time
// it has left.
export class RecorderDeadlineError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'RecorderDeadlineError';
	}
}

// The time a phase of a run may use, as the controller gives it to the
// session: an end, in deps.now() milliseconds, and a signal the controller
// aborts when the phase ends. Every call to the recorder gets what is left
// as its timeout and the signal, so a call pending at the end is aborted,
// and a call asked for past the end is refused before it is made. The
// controller replaces the budget when the teardown begins, which has time
// of its own (verification.ts), and narrows it for each point, whose recorder
// calls stop at the point's own limit. `of` says whose time it is, for the
// error's words; the run's when it is left out.
export interface RunBudget {
	until: number;
	signal: AbortSignal;
	of?: 'run' | 'point' | undefined;
}

// What a call may be given besides its arguments: the signal that ends it.
export interface CallOptions {
	signal?: AbortSignal | undefined;
}

export interface CaptureRequest {
	kind: 'screenshot' | 'aria' | 'console' | 'network';
	label: string;
	pageId?: string | undefined;
}

export interface ReadRequest {
	method: 'GET' | 'HEAD';
	path: string;
	maxBodyBytes: number;
}

// The control API as koid calls it. Tests use a fake. Every call takes the
// options last; the HTTP one aborts the request on the signal, and a fake
// may ignore it.
export interface RecorderApi {
	health(options?: CallOptions): Promise<RecorderHealth>;
	openContext(
		request: {
			pointId: string;
			attempt: number;
			open?: string | undefined;
		},
		options?: CallOptions,
	): Promise<RecorderContext>;
	closeContext(contextId: string, options?: CallOptions): Promise<void>;
	capture(
		contextId: string,
		request: CaptureRequest,
		options?: CallOptions,
	): Promise<RecorderCapture>;
	read(contextId: string, request: ReadRequest, options?: CallOptions): Promise<RecorderCapture>;
	bytes(captureId: string, options?: CallOptions): Promise<ReadableStream<Uint8Array>>;
	acknowledge(captureId: string, options?: CallOptions): Promise<void>;
	events(after: number, limit: number, options?: CallOptions): Promise<RecorderEventsPage>;
}

type Schema<T> = { safeParse(data: unknown): { success: true; data: T } | { success: false } };

// What the client needs of fetch: the call alone. A test hands in a plain
// function, which Bun's own fetch type, with preconnect on it, would refuse.
export type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

// The control API over HTTP, at http://<recorder ip>:4318.
export function httpRecorder(
	baseUrl: string,
	token: string,
	fetchImpl: Fetch = fetch,
): RecorderApi {
	const headers = { authorization: `Bearer ${token}`, accept: 'application/json' };
	// A call ends at its own timeout or on the caller's signal, whichever
	// comes first. The caller's signal carries the run's budget, so a call
	// pending at the run's deadline does not run on to its timeout.
	const ending = (timeoutMs: number, signal: AbortSignal | undefined): AbortSignal =>
		signal === undefined
			? AbortSignal.timeout(timeoutMs)
			: AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]);
	const request = async (
		method: string,
		path: string,
		body?: unknown,
		timeoutMs = 30_000,
		signal?: AbortSignal,
	): Promise<Response> => {
		let res: Response;
		try {
			res = await fetchImpl(`${baseUrl}${path}`, {
				method,
				headers: body === undefined ? headers : { ...headers, 'content-type': 'application/json' },
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
				signal: ending(timeoutMs, signal),
			});
		} catch (err) {
			throw new RecorderError(0, 'unreachable', `the recorder did not answer: ${message(err)}`);
		}
		if (res.ok) return res;
		let code = 'error';
		let text = `${res.status}`;
		try {
			const parsed = RecorderErrorSchema.safeParse(await res.json());
			if (parsed.success) {
				code = parsed.data.code ?? code;
				text = parsed.data.error;
			}
		} catch {
			// The reply was not JSON; the status is the message.
		}
		throw new RecorderError(res.status, code, text);
	};
	// Two reads, because the two failures mean different things. A body that
	// stops arriving is the recorder not answering, the same loss as a request
	// that was never answered (transportErrorsAsUnreachable), and a run must
	// not take it for a bad reply. Bytes that arrive whole and do not parse
	// are an answer from a recorder that is still there.
	const json = async <T>(res: Response, schema: Schema<T>): Promise<T> => {
		let text: string;
		try {
			text = await res.text();
		} catch (err) {
			throw new RecorderError(0, 'unreachable', `the recorder stopped sending: ${message(err)}`);
		}
		let data: unknown;
		try {
			data = JSON.parse(text);
		} catch {
			throw new RecorderError(
				502,
				'bad_reply',
				'the recorder answered with something other than JSON',
			);
		}
		const parsed = schema.safeParse(data);
		if (!parsed.success)
			throw new RecorderError(
				502,
				'bad_reply',
				'the recorder answered with a shape koid cannot read',
			);
		return parsed.data;
	};
	return {
		async health(options) {
			let res: Response;
			try {
				res = await fetchImpl(`${baseUrl}/health`, {
					headers,
					signal: ending(5_000, options?.signal),
				});
			} catch (err) {
				throw new RecorderError(0, 'unreachable', `the recorder did not answer: ${message(err)}`);
			}
			if (res.status === 401)
				throw new RecorderError(401, 'unauthorized', 'the recorder refused the control token');
			return json(res, RecorderHealthSchema);
		},
		async openContext(r, options) {
			return json(
				await request('POST', '/contexts', r, 60_000, options?.signal),
				RecorderContextSchema,
			);
		},
		async closeContext(contextId, options) {
			await request(
				'DELETE',
				`/contexts/${encodeURIComponent(contextId)}`,
				undefined,
				30_000,
				options?.signal,
			);
		},
		async capture(contextId, r, options) {
			return json(
				await request(
					'POST',
					`/contexts/${encodeURIComponent(contextId)}/captures`,
					r,
					60_000,
					options?.signal,
				),
				RecorderCaptureSchema,
			);
		},
		async read(contextId, r, options) {
			return json(
				await request(
					'POST',
					`/contexts/${encodeURIComponent(contextId)}/reads`,
					r,
					60_000,
					options?.signal,
				),
				RecorderCaptureSchema,
			);
		},
		async bytes(captureId, options) {
			const res = await request(
				'GET',
				`/captures/${encodeURIComponent(captureId)}`,
				undefined,
				120_000,
				options?.signal,
			);
			if (res.body === null) throw new RecorderError(502, 'bad_reply', 'the recorder sent no body');
			return transportErrorsAsUnreachable(res.body);
		},
		async acknowledge(captureId, options) {
			await request(
				'DELETE',
				`/captures/${encodeURIComponent(captureId)}`,
				undefined,
				30_000,
				options?.signal,
			);
		},
		async events(after, limit, options) {
			return json(
				await request(
					'GET',
					`/events?after=${after}&limit=${limit}`,
					undefined,
					30_000,
					options?.signal,
				),
				RecorderEventsPageSchema,
			);
		},
	};
}

// A capture's body as the session reads it. The request itself fails with
// status 0 when the recorder does not answer; a connection that drops
// while the body is read fails the read instead, with whatever the fetch
// implementation throws. Both are the recorder not answering, so the read
// fails the same way, and `guarded` treats it as a loss. An abort by the
// caller's signal is reported first by `guarded`, which checks the signal
// before the error.
function transportErrorsAsUnreachable(
	body: ReadableStream<Uint8Array>,
): ReadableStream<Uint8Array> {
	const reader = body.getReader();
	return new ReadableStream<Uint8Array>({
		async pull(controller) {
			let next: Awaited<ReturnType<typeof reader.read>>;
			try {
				next = await reader.read();
			} catch (err) {
				controller.error(
					new RecorderError(0, 'unreachable', `the recorder stopped sending: ${message(err)}`),
				);
				return;
			}
			if (next.done) controller.close();
			else controller.enqueue(next.value);
		},
		cancel(reason) {
			return reader.cancel(reason);
		},
	});
}

export interface RecorderSessionDeps {
	docker: Pick<Docker, 'start' | 'stop' | 'remove'>;
	network: Pick<VerificationNetwork, 'reapply'>;
	// The API for a recorder at a URL; httpRecorder by default.
	api?: (baseUrl: string, token: string) => RecorderApi;
	secrets: SecretRegistry;
	now: () => Date;
	sleep: (ms: number) => Promise<void>;
	log: (message: string) => void;
}

export interface RecorderSessionOptions {
	record: RunNetworkRecord;
	tokens: RecorderTokens;
	run: RunWriter;
	// How long the recorder may take to answer healthy after start.
	healthTimeoutMs?: number;
	// The run's budget for the start and the points (RunBudget). The
	// controller replaces the session's `budget` for the teardown.
	budget?: RunBudget | undefined;
}

// The most koid reads of one capture before sanitizing it whole. The store
// caps the sanitized result again.
const MAX_RAW_BYTES = 32 * 1024 ** 2;
const EVENTS_PAGE = 500;
// The most one string of an event may be once written.
const MAX_EVENT_STRING = 4096;
// A recorder event's fields that the session writes itself, whatever the event says.
const ENVELOPE_FIELDS: ReadonlySet<string> = new Set([
	'seq',
	'at',
	'source',
	'type',
	'pointId',
	'attempt',
]);

// What the manifest's limitations say when the recorder discarded a field
// of an event (RECORDER_OVERLONG_FIELD).
export const OVERLONG_EVENT_FIELDS =
	'the recorder discarded one or more event fields over 4096 characters whole; the events name them in truncatedFields';

type Ready = Extract<RecorderHealth, { ok: true }>;

export class RecorderSession {
	private contextId: string | undefined;
	private point: { pointId: string; attempt: number } | undefined;
	// The contexts the recorder's events say are open, and whether an open was
	// cut short by a budget. A request the session stops waiting for still
	// finishes in the recorder, so such an open leaves a context the session
	// has no id for, and the recorder refuses the next open while it stands.
	private readonly openContexts = new Set<string>();
	private openCutShort = false;
	// The last recorder sequence number read, and the last host one written.
	private recorderSeq = 0;
	private hostSeq = 0;
	// The last drain in line (drainEvents).
	private drains: Promise<unknown> = Promise.resolve();
	private stopped = false;
	// What the verifier could do that the descriptor must say. raw-cdp is here
	// from the start, not learned from an event: the browser port gives every
	// run's verifier a DevTools connection, and the proxy emits no event for it.
	// A client-capability event adds any other.
	readonly capabilities = new Set<string>(['raw-cdp']);
	// What the recorder could not keep whole, which the manifest's
	// limitations must say.
	readonly limitations = new Set<string>();
	// The time the session's calls may use (RunBudget). The controller sets
	// it for the points and again for the teardown; without one, each call
	// has only its own timeout.
	budget: RunBudget | undefined;
	// The first call the recorder did not answer, once it has stopped
	// answering (RecorderLostError). Set whatever the caller did with the
	// error, so the controller learns of a loss that a capture or a drain
	// absorbed.
	lost: string | undefined;

	private constructor(
		private readonly deps: RecorderSessionDeps,
		private readonly api: RecorderApi,
		private readonly container: string,
		readonly runId: string,
		private readonly run: RunWriter,
		readonly health: Ready,
		budget: RunBudget | undefined,
	) {
		this.budget = budget;
	}

	// Starts the recorder and waits for it. Whatever fails after the
	// container is started, the health wait, the firewall, the first events,
	// the container is stopped and removed before the error is thrown, so
	// no browser runs on with no session to stop it; the run records why.
	static async start(
		deps: RecorderSessionDeps,
		options: RecorderSessionOptions,
	): Promise<RecorderSession> {
		const { record, run } = options;
		const endpoint = record.endpoints.find((e) => e.role === 'recorder');
		if (endpoint === undefined)
			throw new Error(`the run network of ${record.runId} has no recorder`);
		const api = (deps.api ?? httpRecorder)(
			`http://${endpoint.ip}:${RECORDER_CONTROL_PORT}`,
			options.tokens.control,
		);
		await run.appendEvent({
			source: 'host',
			type: 'recorder-starting',
			container: endpoint.container,
		});
		// The start and the permits are under the run's budget like every
		// call: a docker or lock wait pending at the deadline is ended.
		await deps.docker.start(endpoint.container, options.budget?.signal);
		// The one error the catch below records nothing for: giveUp wrote
		// its problem already. The HTTP client throws the same class for a
		// connection that drops or a reply koid cannot read, and those have
		// no problem yet.
		let recorded: RecorderError | undefined;
		try {
			const deadline = deps.now().getTime() + (options.healthTimeoutMs ?? 90_000);
			let health: Ready | undefined;
			let reason = 'no answer yet';
			for (;;) {
				try {
					// A recorder that is not up yet does not answer, which is no
					// loss; the run's deadline, though, ends the wait.
					const answer = await guarded(
						options.budget,
						deps.now,
						'health',
						(o) => api.health(o),
						() => {},
					);
					if (answer.ok) {
						health = answer;
						break;
					}
					reason = answer.reason;
					// The browser failed for good, at startup or since (the
					// recorder's Broker.fail); waiting changes nothing.
					if (
						reason.startsWith('the browser did not start') ||
						reason.startsWith('the recorder failed')
					) {
						break;
					}
				} catch (err) {
					if (err instanceof RecorderDeadlineError) throw err;
					reason = message(err);
					if (err instanceof RecorderError && err.status === 401) break;
				}
				if (deps.now().getTime() >= deadline) break;
				await deps.sleep(1_000);
			}
			// The error for a recorder that is no use, once the run knows why.
			const giveUp = async (code: string, detail: string): Promise<RecorderError> => {
				await run.addProblem(code, detail);
				recorded = new RecorderError(503, code, `the recorder of ${record.runId} ${detail}`);
				return recorded;
			};
			if (health === undefined) {
				throw await giveUp('recorder_unavailable', `did not become ready: ${reason}`);
			}
			if (health.runId !== record.runId) {
				throw await giveUp(
					'recorder_mismatch',
					`answers for run ${health.runId}, not ${record.runId}`,
				);
			}
			// koid gave it this address, and execution.json and the report say it unscrubbed
			// as a value of koid's, so it must be that value.
			const origin = new URL(`http://${privateHost(record.runId)}:${record.appPort}`).origin;
			if (health.origin !== origin) {
				throw await giveUp('recorder_mismatch', `answers for another origin, not ${origin}`);
			}
			// The recorder has a bridge port now; the permits bind to it.
			await deps.network.reapply(record.runId, { signal: options.budget?.signal });
			const session = new RecorderSession(
				deps,
				api,
				endpoint.container,
				record.runId,
				run,
				health,
				options.budget,
			);
			await session.record({
				type: 'recorder-ready',
				browser: health.browser.version,
				playwright: health.playwright,
				origin: health.origin,
			});
			await session.drainEvents();
			return session;
		} catch (err) {
			// A failure past the health wait has no problem on the run yet,
			// unless giveUp wrote it. A recorder that answered an error or
			// something koid cannot read failed; one that stopped answering,
			// or anything else that broke (the firewall, the store), is
			// unavailable. The run's budget ending is not a failure of the
			// recorder: the points say not-run, and the evidence stays as it
			// was.
			const ended = err instanceof RecorderDeadlineError || options.budget?.signal.aborted;
			if (err !== recorded && !ended) {
				const code =
					err instanceof RecorderError && err.status !== 0
						? 'recorder_failed'
						: 'recorder_unavailable';
				await run
					.addProblem(code, `the recorder did not start: ${message(err)}`)
					.catch((problem: unknown) =>
						deps.log(`recording why the recorder did not start: ${message(problem)}`),
					);
			}
			await deps.docker
				.stop(endpoint.container)
				.catch((stop: unknown) => deps.log(`stopping the recorder: ${message(stop)}`));
			await deps.docker
				.remove(endpoint.container)
				.catch((remove: unknown) => deps.log(`removing the recorder: ${message(remove)}`));
			throw err;
		}
	}

	// Opens a point's context. One point at a time: the recorder refuses a
	// second context, and so does this.
	async openPoint(pointId: string, attempt: number, open?: string): Promise<RecorderContext> {
		this.assertRunning();
		if (this.contextId !== undefined) throw new Error('a point is open already');
		let context: RecorderContext;
		try {
			context = await this.call('opening the point', (o) =>
				this.api.openContext(
					{
						pointId,
						attempt,
						...(open !== undefined ? { open } : {}),
					},
					o,
				),
			);
		} catch (err) {
			if (err instanceof RecorderDeadlineError) this.openCutShort = true;
			throw err;
		}
		this.contextId = context.contextId;
		this.point = { pointId, attempt };
		await this.drainEvents();
		await this.record({
			type: 'point-opened',
			contextId: context.contextId,
			pageId: context.pageId,
			url: context.url,
		});
		return context;
	}

	async closePoint(): Promise<void> {
		if (this.contextId === undefined) {
			if (this.openCutShort) await this.closeUnnamed();
			return;
		}
		const contextId = this.contextId;
		this.contextId = undefined;
		try {
			await this.call('closing the point', (o) => this.api.closeContext(contextId, o));
		} finally {
			await this.drainOrGap('closing the point');
			await this.record({ type: 'point-closed', contextId });
			this.point = undefined;
		}
	}

	// Closes what an open cut short left in the recorder. The session never
	// got its id, so the recorder's events name it. The context is closed
	// while its navigation may still be going, which ends the navigation. One
	// not yet opened shows no event; the next open is then refused and the
	// controller stops the run (verification.ts, runPoint).
	private async closeUnnamed(): Promise<void> {
		this.openCutShort = false;
		await this.drainOrGap('closing a point whose open was cut short');
		if (this.openContexts.size === 0) return;
		for (const contextId of [...this.openContexts]) {
			await this.call('closing the point', (o) => this.api.closeContext(contextId, o)).catch(
				(err: unknown) => this.deps.log(`closing a context left open: ${message(err)}`),
			);
		}
		await this.drainOrGap('closing a point whose open was cut short');
	}

	// A drain that fails is a gap: whatever the recorder saw since the last
	// read is not in the run, so the run cannot be complete.
	private async drainOrGap(when: string): Promise<void> {
		try {
			await this.drainEvents();
		} catch (err) {
			await this.run
				.addProblem(
					'observation_gap',
					`the recorder's events were not read when ${when}: ${message(err)}`,
				)
				.catch((problem: unknown) =>
					this.deps.log(`recording an observation gap: ${message(problem)}`),
				);
		}
	}

	// Captures one artifact of the open point. The entry comes back whatever
	// happened: sanitized with its bytes on disk, withheld with the reason,
	// or failed, in which case nothing of it is on disk and the run has a
	// problem. Once the run can keep no more entries at all (its artifact
	// cap), this throws CapExceededError instead. The signal ends it early.
	async capture(
		request: {
			kind: ArtifactKind;
			label: string;
			pageId?: string | undefined;
		},
		options?: CallOptions,
	): Promise<Artifact> {
		const { pointId, attempt } = this.requirePoint();
		const capturedAt = this.deps.now().toISOString();
		const first = this.hostSeq;
		const { kind, label } = request;
		if (isWithheldKind(kind)) {
			return this.withheld(
				{ pointId, attempt, kind, label, capturedAt, first },
				WITHHELD_KINDS[kind],
			);
		}
		if (kind === 'http-response') throw new Error('a state read goes through read()');
		if (this.run.capped !== undefined) {
			return this.failed(
				{ pointId, attempt, kind, label, capturedAt, first },
				`capture stopped: ${this.run.capped.message}`,
				false,
			);
		}
		let capture: RecorderCapture;
		try {
			capture = await this.call(
				'capturing',
				(o) =>
					this.api.capture(
						this.contextId as string,
						{
							kind,
							label,
							...(request.pageId !== undefined ? { pageId: request.pageId } : {}),
						},
						o,
					),
				options?.signal,
			);
		} catch (err) {
			return this.notCaptured({ pointId, attempt, kind, label, capturedAt, first }, err);
		}
		return this.keep(
			{ pointId, attempt, kind, label, capturedAt, first },
			capture,
			async (stream) => {
				if (kind === 'screenshot') return sanitizeScreenshot(await collect(stream, MAX_RAW_BYTES));
				if (kind === 'network')
					return sanitizeNetwork(await collect(stream, MAX_RAW_BYTES), this.deps.secrets);
				return streamText(stream, new TextSanitizer(this.deps.secrets), kind);
			},
			options?.signal,
		);
	}

	// Reads the app's state at a path from inside the point's context and
	// keeps the reply as an http-response artifact under the body policy. The
	// signal ends it early.
	async read(
		request: {
			path: string;
			method?: 'GET' | 'HEAD' | undefined;
			body: BodyPolicy;
		},
		options?: CallOptions,
	): Promise<Artifact> {
		const { pointId, attempt } = this.requirePoint();
		const capturedAt = this.deps.now().toISOString();
		const first = this.hostSeq;
		const kind = 'http-response' as const;
		const label = 'state-read';
		if (this.run.capped !== undefined) {
			return this.failed(
				{ pointId, attempt, kind, label, capturedAt, first },
				`capture stopped: ${this.run.capped.message}`,
				false,
			);
		}
		let capture: RecorderCapture;
		try {
			capture = await this.call(
				'reading state',
				(o) =>
					this.api.read(
						this.contextId as string,
						{
							method: request.method ?? 'GET',
							path: request.path,
							maxBodyBytes: request.body.body ? request.body.maxBodyBytes : 0,
						},
						o,
					),
				options?.signal,
			);
		} catch (err) {
			return this.notCaptured({ pointId, attempt, kind, label, capturedAt, first }, err, 'read');
		}
		return this.keep(
			{ pointId, attempt, kind, label, capturedAt, first },
			capture,
			async (stream) =>
				sanitizeHttpResponse(await collect(stream, MAX_RAW_BYTES), this.deps.secrets, request.body),
			options?.signal,
		);
	}

	// Reads the recorder's events since the last read into the run, scrubbed
	// and bounded, and notes what among them changes the run: a target the
	// recorder cannot see, the browser failing, a capability the verifier
	// used, a field the recorder discarded. Returns how many were written.
	//
	// Drains take turns. Captures and state reads can overlap, each one
	// drains, and the cursor moves only as events are written, so two at once
	// would fetch and persist the same events.
	async drainEvents(signal?: AbortSignal): Promise<number> {
		const turn = this.drains.then(() => this.drainTurn(signal));
		// The next drain runs whatever this one did. A failure reaches this
		// caller, and the next drain goes on from the last event written.
		this.drains = turn.catch(() => {});
		return turn;
	}

	private async drainTurn(signal?: AbortSignal): Promise<number> {
		let count = 0;
		for (;;) {
			const page = await this.call(
				'reading events',
				(o) => this.api.events(this.recorderSeq, EVENTS_PAGE, o),
				signal,
			);
			// What the recorder lost after the last sequence read: events koid
			// never got. The recorder counts against the read's cursor, so an
			// eviction of an event already read is not a gap.
			if (page.dropped > 0) {
				await this.run.addProblem(
					'observation_gap',
					`the recorder dropped ${page.dropped} events before koid read them`,
				);
			}
			for (const event of page.events) {
				const { seq, at, type, ...fields } = event;
				await this.record({ type, recorderSeq: seq, recorderAt: at, ...this.flatten(fields) });
				this.recorderSeq = seq;
				count += 1;
				if (discardedField(fields)) this.limitations.add(OVERLONG_EVENT_FIELDS);
				if (typeof fields.contextId === 'string') {
					if (type === 'context-opened') this.openContexts.add(fields.contextId);
					else if (type === 'context-closed') this.openContexts.delete(fields.contextId);
				}
				if (type === 'foreign-target') {
					await this.run.addProblem(
						'unobserved_target',
						fields.closed === true
							? 'the browser opened a target outside the contexts the recorder made; the recorder closed it'
							: 'the browser opened a target outside the contexts the recorder made, and could not close it',
					);
				} else if (type === 'dropped') {
					// The recorder keeps a bounded number of console and network
					// observations per context; past it, they are lost.
					await this.run.addProblem(
						'observations_dropped',
						`the recorder dropped ${String(fields.what ?? 'some')} observations past its limit of ${String(fields.limit ?? '?')} per context`,
					);
				} else if (type === 'guard-unavailable') {
					await this.run.addProblem(
						'origin_guard_unavailable',
						`the recorder could not guard a ${String(fields.targetType ?? '')} target; only the proxy layer held it`,
					);
				} else if (type === 'recorder-failed') {
					await this.run.addProblem('recorder_failed', 'the recorder reported a failure');
				} else if (type === 'page-crashed') {
					await this.run.addProblem('page_crashed', 'a page crashed');
				} else if (type === 'client-capability' && typeof fields.capability === 'string') {
					this.capabilities.add(fields.capability);
				}
			}
			if (page.events.length < EVENTS_PAGE) return count;
		}
	}

	// Ends the session: the open point, the last events, and the container,
	// which is stopped and removed. The controller gives the session the
	// teardown's budget first, so the last calls and the docker commands end
	// with the allowance; a loss in the last drain is left in `lost` for the
	// controller to see.
	async stop(): Promise<void> {
		if (this.stopped) return;
		this.stopped = true;
		try {
			if (this.contextId !== undefined) {
				const contextId = this.contextId;
				this.contextId = undefined;
				await this.call('closing the point', (o) => this.api.closeContext(contextId, o)).catch(
					(err: unknown) => this.deps.log(`closing the recorder context: ${message(err)}`),
				);
			}
			await this.drainOrGap('stopping the recorder');
		} finally {
			const signal = this.budget?.signal;
			await this.deps.docker
				.stop(this.container, signal)
				.catch((err: unknown) => this.deps.log(`stopping the recorder: ${message(err)}`));
			await this.deps.docker
				.remove(this.container, signal)
				.catch((err: unknown) => this.deps.log(`removing the recorder: ${message(err)}`));
			await this.record({ type: 'recorder-stopped' }).catch(() => {});
		}
	}

	private assertRunning(): void {
		if (this.stopped) throw new Error('the recorder session is stopped');
	}

	// One call to the recorder under the session's budget, with a loss
	// noted (see `lost`).
	// `signal` is the point's, beside the run's budget: the verifier's end
	// ends a capture or a read it asked for (verifier.ts).
	private call<T>(
		what: string,
		fn: (options: CallOptions) => Promise<T>,
		signal?: AbortSignal,
	): Promise<T> {
		return guarded(
			this.budget,
			this.deps.now,
			what,
			fn,
			(why) => {
				this.lost ??= why;
			},
			signal,
		);
	}

	// A capture or read the recorder did not make. A recorder that stopped
	// answering, or a budget that ended, is recorded as a failed entry and
	// then thrown, since the point cannot go on; anything else is a failed
	// entry the point goes on from. The budget's end is the run's own
	// decision and no capture error: the point's outcome says it.
	private async notCaptured(
		meta: ArtifactStart,
		err: unknown,
		verb: 'capture' | 'read' = 'capture',
	): Promise<Artifact> {
		if (err instanceof RecorderDeadlineError) {
			await this.failed(meta, `the ${verb} was not made: ${err.message}`, false);
			throw err;
		}
		if (err instanceof RecorderLostError) {
			await this.failed(meta, `the recorder did not ${verb}: ${err.message}`, true);
			throw err;
		}
		return this.failed(meta, `the recorder did not ${verb}: ${message(err)}`, true);
	}

	private requirePoint(): { pointId: string; attempt: number } {
		this.assertRunning();
		if (this.point === undefined || this.contextId === undefined)
			throw new Error('no point is open');
		return this.point;
	}

	// One event of this session, with the point when one is open. The writer
	// scrubs every string in it too: a page's final URL or a reason is the app's
	// words as much as a recorder event's are. Scrubbed here as well because of
	// the cut: a cut first could leave most of a secret.
	private async record(fields: Record<string, unknown> & { type: string }): Promise<void> {
		const { type, ...rest } = fields;
		const written = await this.run.appendEvent({
			source: rest.recorderSeq === undefined ? 'host' : 'recorder',
			...(this.point !== undefined
				? { pointId: this.point.pointId, attempt: this.point.attempt }
				: {}),
			type,
			...scrubFields(this.deps.secrets, rest, MAX_EVENT_STRING),
		});
		this.hostSeq = written.seq;
	}

	// A recorder event's fields with anything that is not a primitive made
	// into JSON text, so one field is one bounded string however deep the
	// recorder nested it. The one list kept as a list is truncatedFields,
	// the names of the fields the recorder discarded, bounded by count. record()
	// scrubs and then cuts the result like every other event. A point and an
	// attempt are the envelope's, so the session's own go there (record): the
	// recorder only says back what koid told it, and a scrub of its copy would
	// put a mask in a field the event's schema holds to a point id.
	private flatten(fields: Record<string, unknown>): Record<string, unknown> {
		const out: Record<string, unknown> = {};
		for (const [key, value] of Object.entries(fields)) {
			if (ENVELOPE_FIELDS.has(key) || value === undefined) continue;
			if (key === 'truncatedFields' && Array.isArray(value)) {
				out[key] = value.filter((name) => typeof name === 'string').slice(0, 100);
			} else if (typeof value === 'object' && value !== null) {
				out[key] = JSON.stringify(value);
			} else {
				out[key] = value;
			}
		}
		return out;
	}

	private async keep(
		meta: ArtifactStart,
		capture: RecorderCapture,
		sanitize: (stream: ReadableStream<Uint8Array>) => Promise<Sanitized | Streamed>,
		signal?: AbortSignal,
	): Promise<Artifact> {
		const { pointId, attempt, kind, label, capturedAt, first } = meta;
		let entry: Artifact;
		try {
			// The bytes are read, sanitized and written under one guarded
			// call: the stream is consumed long after the request returned it,
			// and a deadline or a loss during that is the same deadline or loss
			// as one during the request. A text kind streams to disk inside
			// writeArtifact, so that is under the guard too.
			entry = await this.call(
				'reading a capture',
				async (o) => {
					const stream = await this.api.bytes(capture.captureId, o);
					const result = await sanitize(stream);
					// The recorder's events up to the capture go in before the entry
					// that spans them.
					await this.drainEvents(signal);
					// What the recorder could not promise comes after what the policy
					// cannot, each scrubbed and bounded like any text of the recorder's.
					const noted = (capture.limitations ?? []).map((text) => this.reason(text));
					const start = {
						pointId,
						attempt,
						kind,
						mediaType: capture.mediaType,
						capturedAt,
						eventRange: { first, last: this.hostSeq },
						redaction: {
							status: 'sanitized' as const,
							policyDigest: policyDigest(kind),
							removedFields: result.removedFields,
							limitations: [...result.limitations, ...noted].slice(0, MAX_LIMITATIONS),
						},
					};
					return isStreamed(result)
						? this.run.writeArtifact(start, result.chunks)
						: this.run.writeArtifact(start, result.bytes);
				},
				signal,
			);
		} catch (err) {
			await this.call(
				'acknowledging',
				(o) => this.api.acknowledge(capture.captureId, o),
				signal,
			).catch(() => {});
			if (err instanceof SanitizeError) return this.withheld(meta, err.message);
			// A cap the store reached is on the run already; one found here,
			// in the raw bytes, is not yet.
			if (err instanceof CapExceededError) {
				return this.failed(meta, err.message, this.run.capped === undefined);
			}
			if (err instanceof RecorderDeadlineError || err instanceof RecorderLostError) {
				return this.notCaptured(meta, err);
			}
			return this.failed(meta, `the capture was not kept: ${message(err)}`, true);
		}
		// Only now may the recorder drop the raw bytes.
		await this.call(
			'acknowledging',
			(o) => this.api.acknowledge(capture.captureId, o),
			signal,
		).catch((err: unknown) => this.deps.log(`acknowledging a capture: ${message(err)}`));
		if (entry.availability !== 'available') {
			// The store refused the entry and recorded it as failed, with the
			// run's problem; nothing of the capture is on disk.
			await this.record({
				type: 'capture-failed',
				kind,
				label,
				artifact: entry.id,
				reason: entry.redaction.limitations[0] ?? 'the entry was not valid',
			});
			return entry;
		}
		await this.record({
			type: 'capture',
			kind,
			label,
			artifact: entry.id,
			captureId: capture.captureId,
			size: entry.size,
			sha256: entry.sha256,
			recorderRange: capture.eventRange,
		});
		return entry;
	}

	// A reason may quote what the recorder or a stream said, which can carry
	// application text; it is scrubbed and bounded before it is kept.
	private reason(text: string): string {
		return this.deps.secrets.redact(text).slice(0, 500);
	}

	private async withheld(meta: ArtifactStart, why: string): Promise<Artifact> {
		const { pointId, attempt, kind, label, capturedAt, first } = meta;
		const reason = this.reason(why);
		const entry = await this.run.recordArtifact({
			pointId,
			attempt,
			kind,
			capturedAt,
			eventRange: { first, last: this.hostSeq },
			redaction: {
				status: 'withheld',
				policyDigest: policyDigest(kind),
				removedFields: [],
				limitations: [reason],
			},
		});
		await this.record({ type: 'capture-withheld', kind, label, artifact: entry.id, reason });
		return entry;
	}

	// An entry for a capture that failed. `problem` says whether the run
	// learns a new problem from it; a cap it already knows does not add one.
	// Past the run's artifact cap the store refuses the entry itself, and
	// the error says so.
	private async failed(meta: ArtifactStart, why: string, problem: boolean): Promise<Artifact> {
		const { pointId, attempt, kind, label, capturedAt, first } = meta;
		const reason = this.reason(why);
		if (problem) await this.run.addProblem('capture_failed', `${kind} ${label}: ${reason}`);
		const entry = await this.run.recordArtifact({
			pointId,
			attempt,
			kind,
			capturedAt,
			eventRange: { first, last: this.hostSeq },
			redaction: {
				status: 'failed',
				policyDigest: policyDigest(kind),
				removedFields: [],
				limitations: [reason],
			},
		});
		await this.record({ type: 'capture-failed', kind, label, artifact: entry.id, reason });
		return entry;
	}
}

interface ArtifactStart {
	pointId: string;
	attempt: number;
	kind: ArtifactKind;
	label: string;
	capturedAt: string;
	first: number;
}

interface Streamed {
	chunks: AsyncIterable<Uint8Array>;
	removedFields: string[];
	limitations: string[];
}

function isStreamed(result: Sanitized | Streamed): result is Streamed {
	return 'chunks' in result;
}

// One call to the recorder under a budget. Refused before it is made once
// the budget has ended; otherwise made with what is left of the budget as
// its signal, on top of the call's own timeout. A caller's signal ends the
// call the same way. A call the budget or that signal ended is a
// RecorderDeadlineError; one the recorder did not answer at all (status 0) is
// a RecorderLostError, and `onLost` hears of it first. `fn` may do more than
// the request, such as consume the body it returned: whatever it awaits is
// under the same signal and the same two rules.
async function guarded<T>(
	budget: RunBudget | undefined,
	now: () => Date,
	what: string,
	fn: (options: CallOptions) => Promise<T>,
	onLost: (why: string) => void,
	caller?: AbortSignal,
): Promise<T> {
	if (caller?.aborted) throw new RecorderDeadlineError(`${what}: the point's time is up`);
	let signal = caller;
	const whose = budget?.of ?? 'run';
	if (budget !== undefined) {
		const remaining = budget.until - now().getTime();
		if (budget.signal.aborted || remaining <= 0) {
			throw new RecorderDeadlineError(`${what}: the ${whose}'s time is up`);
		}
		signal = AbortSignal.any([
			budget.signal,
			AbortSignal.timeout(remaining),
			...(caller !== undefined ? [caller] : []),
		]);
	}
	try {
		return await fn({ signal });
	} catch (err) {
		if (caller?.aborted) {
			throw new RecorderDeadlineError(`${what}: the point's time ran out during the call`);
		}
		if (signal?.aborted) {
			throw new RecorderDeadlineError(`${what}: the ${whose}'s time ran out during the call`);
		}
		if (err instanceof RecorderError && err.status === 0) {
			const why = `${what}: ${err.message}`;
			onLost(why);
			throw new RecorderLostError(why);
		}
		throw err;
	}
}

// Text kinds go through the scrubber chunk by chunk into the store.
function streamText(
	stream: ReadableStream<Uint8Array>,
	sanitizer: TextSanitizer,
	kind: 'aria' | 'console',
): Streamed {
	const chunks = (async function* () {
		for await (const chunk of stream) {
			const out = sanitizer.push(chunk);
			if (out.length > 0) yield out;
		}
		const tail = sanitizer.end();
		if (tail.length > 0) yield tail;
	})();
	return { chunks, removedFields: [], limitations: [...LIMITATIONS[kind]] };
}

// The whole stream, refused past `max` bytes.
async function collect(stream: ReadableStream<Uint8Array>, max: number): Promise<Uint8Array> {
	const chunks: Uint8Array[] = [];
	let size = 0;
	for await (const chunk of stream) {
		size += chunk.length;
		if (size > max)
			throw new CapExceededError(
				'bytesPerArtifact',
				`the capture is over ${max} bytes, the most one artifact may be`,
			);
		chunks.push(chunk);
	}
	const out = new Uint8Array(size);
	let at = 0;
	for (const c of chunks) {
		out.set(c, at);
		at += c.length;
	}
	return out;
}

// Whether a recorder event carries the marker the recorder puts in place of
// a field it discarded, or names such fields.
function discardedField(fields: Record<string, unknown>): boolean {
	if (Array.isArray(fields.truncatedFields) && fields.truncatedFields.length > 0) return true;
	return Object.values(fields).some((value) => value === RECORDER_OVERLONG_FIELD);
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
