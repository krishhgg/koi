import { afterEach, describe, expect, spyOn, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	EvidenceEventSchema,
	RECORDER_OVERLONG_FIELD,
	type RecorderCapture,
	type RecorderEvent,
	type RecorderEventsPage,
	type RecorderHealth,
	type RunNetworkRecord,
} from '@koi/shared';
import {
	type CallOptions,
	type CaptureRequest,
	type Fetch,
	httpRecorder,
	newRecorderTokens,
	OVERLONG_EVENT_FIELDS,
	type ReadRequest,
	type RecorderApi,
	RecorderDeadlineError,
	RecorderError,
	RecorderLostError,
	RecorderSession,
	type RecorderSessionDeps,
	recorderEnv,
} from '../src/recorder.ts';
import { SecretRegistry } from '../src/redact.ts';
import { LIMITATIONS, policyDigest, WITHHELD_KINDS } from '../src/sanitize.ts';
import { scrubFields } from '../src/verification-sanitize.ts';
import { CapExceededError, EvidenceStore, type RunWriter } from '../src/verification-store.ts';
import { PNG_STRIPPED, PNG_WITH_METADATA } from './png.ts';

const RUN = 'abcdefghijklmnop0123';
const RECORDER = `koi-verify-${RUN}-recorder`;
const AT = '2026-10-06T12:00:00.000Z';
const sha = (bytes: Uint8Array | string) =>
	`sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const encode = (text: string) => new TextEncoder().encode(text);

const record: RunNetworkRecord = {
	version: 1,
	runId: RUN,
	network: `koi-v-${RUN}`,
	bridge: 'kv0123456789ab',
	subnet: '10.213.0.0/28',
	gateway: '10.213.0.1',
	appContainer: 'koi-hello-pr-7-aaaaaaaaaaaaaaaa1',
	appPort: 8080,
	state: 'ready',
	endpoints: [
		{
			role: 'app',
			container: 'koi-hello-pr-7-aaaaaaaaaaaaaaaa1',
			ip: '10.213.0.2',
			mac: '02:42:0a:d5:00:02',
		},
		{ role: 'recorder', container: RECORDER, ip: '10.213.0.3', mac: '02:4b:0a:d5:00:03' },
		{
			role: 'verifier',
			container: `koi-verify-${RUN}-verifier`,
			ip: '10.213.0.4',
			mac: '02:4b:0a:d5:00:04',
		},
	],
	createdAt: AT,
};

const healthy: RecorderHealth = {
	ok: true,
	runId: RUN,
	origin: `http://app.${RUN}.invalid:8080`,
	browser: { name: 'chromium', version: '142.0.7444.52' },
	playwright: '1.64.1',
	contexts: 0,
	captures: { count: 0, bytes: 0 },
	events: { next: 1, dropped: 0 },
};

// The recorder's control API in memory. Captures are given bytes by kind;
// a stream can be made to fail part way.
class FakeRecorder implements RecorderApi {
	calls: string[] = [];
	// What health answers, in order; the last answer repeats.
	healthAnswers: Array<RecorderHealth | Error> = [healthy];
	bytesByKind = new Map<string, Uint8Array[]>();
	readAnswer: Uint8Array = encode(
		JSON.stringify({
			request: { method: 'GET', url: `http://app.${RUN}.invalid:8080/api/state` },
			response: {
				status: 200,
				headers: { 'content-type': 'application/json', 'set-cookie': 'a=b' },
				bodyBase64: Buffer.from('{"saved":true}').toString('base64'),
				bodyBytes: 14,
				truncated: false,
			},
			startedAt: AT,
			endedAt: AT,
		}),
	);
	held = new Map<string, Uint8Array[]>();
	acknowledged: string[] = [];
	feed: RecorderEvent[] = [];
	// How many of the oldest events the recorder's ring has lost, as a ring
	// at capacity loses them: sequence numbers 1 to `lost` are gone.
	lost = 0;
	failBytes = false;
	// What a stream that fails part way fails with; a plain error unless set.
	bytesError: Error | undefined;
	// Runs as each bytes read begins, before the stream is returned.
	onBytes: (() => void) | undefined;
	captureError: RecorderError | undefined;
	// Fails every events read with this, when set.
	eventsError: Error | undefined;
	// How long an events read takes. Real reads cross the network, so a
	// second drain can start while the first waits for its page.
	eventsDelayMs = 0;
	// What a capture answers as its media type, when set: the control API
	// takes any non-empty string, the artifact schema does not.
	mediaTypeOverride: string | undefined;
	// What a capture says the recorder could not promise, when set.
	captureLimitations: string[] | undefined;
	private nextCapture = 1;
	private seq = 1;

	emit(type: string, fields: Record<string, unknown> = {}) {
		this.feed.push({ seq: this.seq++, at: AT, type, ...fields });
	}

	async health() {
		this.calls.push('health');
		const answer =
			this.healthAnswers.length > 1
				? (this.healthAnswers.shift() as RecorderHealth | Error)
				: this.healthAnswers[0];
		if (answer instanceof Error) throw answer;
		if (answer === undefined) throw new Error('no answer');
		return answer;
	}
	async openContext(r: { pointId: string; attempt: number; open?: string | undefined }) {
		this.calls.push(`open ${r.pointId} ${r.attempt}${r.open === undefined ? '' : ` ${r.open}`}`);
		this.emit('context-opened', { contextId: 'x1', pointId: r.pointId, attempt: r.attempt });
		this.emit('page-opened', { contextId: 'x1', pageId: 'p1', url: 'about:blank' });
		return {
			contextId: 'x1',
			pageId: 'p1',
			url: r.open === undefined ? 'about:blank' : `http://app.${RUN}.invalid:8080${r.open}`,
		};
	}
	async closeContext(contextId: string) {
		this.calls.push(`close ${contextId}`);
		this.emit('context-closed', { contextId });
	}
	// An open the recorder goes on with after the session stopped waiting: the
	// context exists at once, and the answer never comes.
	openNeverAnswers(): void {
		this.openContext = (async (r: { pointId: string; attempt: number }, options?: CallOptions) => {
			this.calls.push(`open ${r.pointId} ${r.attempt}`);
			this.emit('context-opened', { contextId: 'x1', pointId: r.pointId, attempt: r.attempt });
			return new Promise((_, reject) => {
				options?.signal?.addEventListener('abort', () =>
					reject(new RecorderError(0, 'unreachable', 'the recorder did not answer: aborted')),
				);
			});
		}) as FakeRecorder['openContext'];
	}
	private store(kind: string, mediaType: string, chunks: Uint8Array[]): RecorderCapture {
		const captureId = `c${this.nextCapture++}`;
		this.held.set(captureId, chunks);
		const whole = Buffer.concat(chunks);
		this.emit('capture', { contextId: 'x1', kind, captureId });
		return {
			captureId,
			kind: kind as RecorderCapture['kind'],
			mediaType,
			size: whole.length,
			sha256: sha(whole),
			pageId: 'p1',
			url: `http://app.${RUN}.invalid:8080/`,
			eventRange: { first: 1, last: this.seq - 1 },
			capturedAt: AT,
			...(this.captureLimitations !== undefined ? { limitations: this.captureLimitations } : {}),
		};
	}
	async capture(contextId: string, r: CaptureRequest, _options?: CallOptions) {
		this.calls.push(`capture ${contextId} ${r.kind} ${r.label}`);
		if (this.captureError !== undefined) throw this.captureError;
		const chunks = this.bytesByKind.get(r.kind) ?? [new Uint8Array(0)];
		const mediaType =
			this.mediaTypeOverride ??
			(r.kind === 'screenshot'
				? 'image/png'
				: r.kind === 'aria'
					? 'text/plain; charset=utf-8'
					: 'application/x-ndjson');
		return this.store(r.kind, mediaType, chunks);
	}
	async read(contextId: string, r: ReadRequest) {
		this.calls.push(`read ${contextId} ${r.method} ${r.path} ${r.maxBodyBytes}`);
		return this.store('http-response', 'application/json', [this.readAnswer]);
	}
	async bytes(captureId: string) {
		this.calls.push(`bytes ${captureId}`);
		const chunks = this.held.get(captureId);
		if (chunks === undefined) throw new RecorderError(404, 'no_capture', 'no such capture');
		this.onBytes?.();
		const fail = this.failBytes;
		const failure = this.bytesError ?? new Error('the connection dropped');
		return new ReadableStream<Uint8Array>({
			start(controller) {
				for (const [i, chunk] of chunks.entries()) {
					if (fail && i === chunks.length - 1) {
						controller.error(failure);
						return;
					}
					controller.enqueue(chunk);
				}
				controller.close();
			},
		});
	}
	async acknowledge(captureId: string) {
		this.calls.push(`ack ${captureId}`);
		this.acknowledged.push(captureId);
		this.held.delete(captureId);
	}
	async events(after: number, limit: number, _options?: CallOptions): Promise<RecorderEventsPage> {
		if (this.eventsError !== undefined) throw this.eventsError;
		if (this.eventsDelayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, this.eventsDelayMs));
		}
		const retained = this.feed.filter((e) => e.seq > this.lost);
		const events = retained.filter((e) => e.seq > after).slice(0, limit);
		// As the recorder counts: what the reader never got, relative to its
		// cursor, never an eviction of something it had read.
		const oldest = retained[0]?.seq ?? this.seq;
		return {
			events,
			next: events.at(-1)?.seq ?? after,
			dropped: Math.max(0, oldest - after - 1),
		};
	}
}

// Run writers the tests opened, closed after each so no file handle is left
// to the garbage collector.
const open: RunWriter[] = [];
afterEach(async () => {
	for (const writer of open) await writer.abandon();
	open.length = 0;
});

async function setup(
	options: { limits?: ConstructorParameters<typeof EvidenceStore>[0]['limits'] } = {},
) {
	const root = await mkdtemp(join(tmpdir(), 'koid-recorder-'));
	let clock = Date.parse(AT);
	const secrets = new SecretRegistry();
	const store = new EvidenceStore({
		stateDir: root,
		now: () => new Date(clock),
		diskSpace: async () => ({ free: 60 * 1024 ** 3, size: 80 * 1024 ** 3 }),
		...(options.limits !== undefined ? { limits: options.limits } : {}),
		scrub: (text) => secrets.redact(text),
	});
	await store.init();
	const run = await store.openRun(RUN);
	open.push(run);
	const api = new FakeRecorder();
	const docker = { started: [] as string[], stopped: [] as string[], removed: [] as string[] };
	const reapplied: string[] = [];
	const logs: string[] = [];
	const deps: RecorderSessionDeps = {
		docker: {
			start: async (name) => {
				docker.started.push(name);
			},
			stop: async (name) => {
				docker.stopped.push(name);
			},
			remove: async (name) => {
				docker.removed.push(name);
			},
		},
		network: {
			reapply: async (runId) => {
				reapplied.push(runId);
			},
		},
		api: () => api,
		secrets,
		now: () => new Date(clock),
		sleep: async (ms) => {
			clock += ms;
		},
		log: (m) => logs.push(m),
	};
	const tokens = newRecorderTokens();
	const events = async () =>
		(await readFile(join(store.runDir(RUN), 'events.ndjson'), 'utf8'))
			.trimEnd()
			.split('\n')
			.filter((l) => l !== '')
			.map((l) => EvidenceEventSchema.parse(JSON.parse(l)));
	const artifacts = async () => readdir(join(store.runDir(RUN), 'artifacts'));
	return {
		root,
		store,
		run,
		api,
		docker,
		reapplied,
		logs,
		secrets,
		deps,
		tokens,
		events,
		artifacts,
		start: () => RecorderSession.start(deps, { record, tokens, run }),
	};
}

describe('tokens', () => {
	test('two random hex tokens, given to the recorder as its environment', () => {
		const tokens = newRecorderTokens();
		expect(tokens.control).toMatch(/^[0-9a-f]{64}$/);
		expect(tokens.browser).toMatch(/^[0-9a-f]{64}$/);
		expect(tokens.control).not.toBe(tokens.browser);
		expect(recorderEnv(tokens)).toEqual({
			KOI_RECORDER_CONTROL_TOKEN: tokens.control,
			KOI_RECORDER_BROWSER_TOKEN: tokens.browser,
		});
	});
});

describe('RecorderSession.start', () => {
	test('starts the container, waits for health, re-applies the permits and records it', async () => {
		const t = await setup();
		t.api.healthAnswers = [
			new Error('connection refused'),
			{ ok: false, reason: 'starting' },
			healthy,
		];
		const session = await t.start();
		expect(t.docker.started).toEqual([RECORDER]);
		expect(t.api.calls.filter((c) => c === 'health')).toHaveLength(3);
		expect(t.reapplied).toEqual([RUN]);
		expect(session.health.browser.version).toBe('142.0.7444.52');
		expect((await t.events()).map((e) => e.type)).toEqual(['recorder-starting', 'recorder-ready']);
		await session.stop();
		expect(t.docker.stopped).toEqual([RECORDER]);
		expect(t.docker.removed).toEqual([RECORDER]);
		expect((await t.events()).at(-1)?.type).toBe('recorder-stopped');
	});

	test('gives up when the recorder never answers, recording why and removing the container', async () => {
		const t = await setup();
		t.api.healthAnswers = [new Error('connection refused')];
		await expect(
			RecorderSession.start(t.deps, {
				record,
				tokens: t.tokens,
				run: t.run,
				healthTimeoutMs: 5_000,
			}),
		).rejects.toThrow(RecorderError);
		expect(t.reapplied).toEqual([]);
		expect(t.docker.stopped).toEqual([RECORDER]);
		expect(t.docker.removed).toEqual([RECORDER]);
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['recorder_unavailable']);
		expect(t.run.status.evidence).toBe('incomplete');
	});

	test('stops waiting when the browser failed for good', async () => {
		const t = await setup();
		t.api.healthAnswers = [{ ok: false, reason: 'the browser did not start: sandbox' }];
		await expect(t.start()).rejects.toThrow('sandbox');
		expect(t.api.calls.filter((c) => c === 'health')).toHaveLength(1);
		expect(t.docker.stopped).toEqual([RECORDER]);
		expect(t.docker.removed).toEqual([RECORDER]);
	});

	test('stops waiting when the recorder lost its browser after it started', async () => {
		const t = await setup();
		t.api.healthAnswers = [{ ok: false, reason: 'the recorder failed: the browser disconnected' }];
		await expect(t.start()).rejects.toThrow('the browser disconnected');
		expect(t.api.calls.filter((c) => c === 'health')).toHaveLength(1);
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['recorder_unavailable']);
		expect(t.docker.removed).toEqual([RECORDER]);
	});

	test('a failure after the recorder is healthy still stops and removes it, and the run says why', async () => {
		// The firewall will not bind the permits.
		const t = await setup();
		t.deps.network.reapply = async () => {
			throw new Error('sudo -n exited 1: xtables lock');
		};
		await expect(t.start()).rejects.toThrow('xtables lock');
		expect(t.docker.stopped).toEqual([RECORDER]);
		expect(t.docker.removed).toEqual([RECORDER]);
		expect(t.run.status.problems.map((p) => [p.code, p.detail])).toEqual([
			['recorder_unavailable', 'the recorder did not start: sudo -n exited 1: xtables lock'],
		]);
		// The first drain of events fails.
		const u = await setup();
		u.api.eventsError = new Error('connection reset');
		await expect(u.start()).rejects.toThrow('connection reset');
		expect(u.docker.stopped).toEqual([RECORDER]);
		expect(u.docker.removed).toEqual([RECORDER]);
		expect(u.run.status.problems.map((p) => p.code)).toEqual(['recorder_unavailable']);
		expect((await u.events()).map((e) => e.type)).toEqual(['recorder-starting', 'recorder-ready']);
	});

	test('a control call that fails after health is a problem on the run, from the HTTP client too', async () => {
		// The recorder answered healthy over HTTP; its first events read does
		// not reach it. The client's own error class must not hide that.
		const t = await setup();
		const unreachable: Fetch = async (input) => {
			if (String(input).endsWith('/health')) return Response.json(healthy);
			throw new TypeError('connection reset by peer');
		};
		t.deps.api = (baseUrl, token) => httpRecorder(baseUrl, token, unreachable);
		const failed = await t.start().catch((err: unknown) => err);
		expect(failed).toBeInstanceOf(RecorderLostError);
		expect(t.docker.stopped).toEqual([RECORDER]);
		expect(t.docker.removed).toEqual([RECORDER]);
		expect(t.run.status.problems.map((p) => [p.code, p.detail])).toEqual([
			[
				'recorder_unavailable',
				'the recorder did not start: reading events: the recorder did not answer: connection reset by peer',
			],
		]);
		expect((await t.events()).map((e) => e.type)).toEqual(['recorder-starting', 'recorder-ready']);
		const manifest = await t.run.finalize({ limitations: [] });
		expect(manifest.status.evidence).toBe('incomplete');
		// A reply koid cannot read is the recorder failing, not missing.
		const u = await setup();
		const garbled: Fetch = async (input) => {
			if (String(input).endsWith('/health')) return Response.json(healthy);
			return new Response('<html>not json</html>', { status: 200 });
		};
		u.deps.api = (baseUrl, token) => httpRecorder(baseUrl, token, garbled);
		const bad = await u.start().catch((err: unknown) => err);
		expect(bad).toBeInstanceOf(RecorderError);
		expect((bad as RecorderError).code).toBe('bad_reply');
		expect(u.docker.removed).toEqual([RECORDER]);
		expect(u.run.status.problems.map((p) => [p.code, p.detail])).toEqual([
			[
				'recorder_failed',
				'the recorder did not start: the recorder answered with something other than JSON',
			],
		]);
		expect(u.run.status.evidence).toBe('incomplete');
		// What giveUp recorded is recorded once: a recorder for another run.
		const v = await setup();
		v.api.healthAnswers = [{ ...healthy, runId: 'z'.repeat(20) }];
		await expect(v.start()).rejects.toThrow('answers for run');
		expect(v.run.status.problems.map((p) => p.code)).toEqual(['recorder_mismatch']);
	});

	test("every string of a host event is scrubbed, the page's final URL included", async () => {
		const t = await setup();
		const token = `koi_${'f'.repeat(32)}`;
		const login = 'the-login-value-12345';
		t.secrets.add(login);
		t.api.healthAnswers = [{ ...healthy, playwright: `1.64.1+${login}` }];
		const session = await t.start();
		// The app redirects the first page to a URL carrying a login key and
		// a koi token; the recorder reports where the page ended up.
		t.api.openContext = async (r) => {
			t.api.calls.push(`open ${r.pointId}`);
			return {
				contextId: 'x1',
				pageId: 'p1',
				url: `http://app.${RUN}.invalid:8080/login?key=${login}&t=${token}#${encodeURIComponent(login)}`,
			};
		};
		await session.openPoint('hello.home', 1, '/');
		await session.stop();
		const events = await t.events();
		const opened = events.find((e) => e.type === 'point-opened');
		expect(opened).toMatchObject({
			source: 'host',
			pointId: 'hello.home',
			url: `http://app.${RUN}.invalid:8080/login?key=[redacted]&t=[redacted]#[redacted]`,
		});
		expect(events.find((e) => e.type === 'recorder-ready')?.playwright).toBe('1.64.1+[redacted]');
		const text = await readFile(join(t.store.runDir(RUN), 'events.ndjson'), 'utf8');
		expect(text).not.toContain(login);
		expect(text).not.toContain(token);
		expect(text).not.toContain(encodeURIComponent(login));
	});
});

describe('captures', () => {
	test('a screenshot is stripped, hashed, written, acknowledged and recorded', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1, '/');
		expect(t.api.calls).toContain('open hello.home 1 /');
		t.api.bytesByKind.set('screenshot', [
			PNG_WITH_METADATA.subarray(0, 20),
			PNG_WITH_METADATA.subarray(20),
		]);
		const artifact = await session.capture({ kind: 'screenshot', label: 'after-load' });
		expect(artifact.id).toBe('recorder:screenshot:1');
		expect(artifact.kind).toBe('screenshot');
		expect(artifact.size).toBe(PNG_STRIPPED.length);
		expect(artifact.sha256).toBe(sha(PNG_STRIPPED));
		expect(artifact.redaction).toEqual({
			status: 'sanitized',
			policyDigest: policyDigest('screenshot'),
			removedFields: ['png:tEXt', 'png:tIME'],
			limitations: [
				'pixels may contain unknown application data; only password fields were masked before capture',
				'PNG metadata chunks were removed; the image data itself was not inspected',
			],
		});
		expect(artifact.availability).toBe('available');
		expect(artifact.pointId).toBe('hello.home');
		expect(await readFile(join(t.store.runDir(RUN), 'artifacts', artifact.id))).toEqual(
			Buffer.from(PNG_STRIPPED),
		);
		expect(t.api.acknowledged).toEqual(['c1']);
		expect(t.api.held.size).toBe(0);
		const events = await t.events();
		const capture = events.find((e) => e.type === 'capture' && e.source === 'host');
		expect(capture).toMatchObject({
			pointId: 'hello.home',
			attempt: 1,
			kind: 'screenshot',
			label: 'after-load',
			artifact: artifact.id,
			captureId: 'c1',
		});
		// The recorder's own events came in before the entry that spans them.
		expect(events.filter((e) => e.source === 'recorder').map((e) => e.type)).toEqual([
			'context-opened',
			'page-opened',
			'capture',
		]);
		expect(artifact.eventRange.last).toBeGreaterThan(artifact.eventRange.first);
		await session.stop();
	});

	test('a point id that matches a known value opens as any other, and its events keep it', async () => {
		const t = await setup();
		t.secrets.add('hello.home');
		const session = await t.start();
		await session.openPoint('hello.home', 1, '/');
		await session.capture({ kind: 'aria', label: 'first-view' });
		await session.closePoint();
		await session.stop();
		const lines = (await readFile(join(t.run.dir, 'events.ndjson'), 'utf8')).trimEnd().split('\n');
		const events = lines.map((line) => EvidenceEventSchema.parse(JSON.parse(line)));
		// The recorder's own events name the point too. Its copy would scrub to a mask,
		// which the event's schema refuses, so the envelope holds the session's.
		const opened = events.find((e) => e.type === 'context-opened');
		expect(opened?.pointId).toBe('hello.home');
		expect(events.find((e) => e.type === 'point-opened')?.pointId).toBe('hello.home');
		expect(lines.join('\n')).not.toContain('"pointId":"[redacted]"');
		expect(t.run.artifacts[0]?.pointId).toBe('hello.home');
	});

	test('a failed capture named after a known value keeps it out of the run problems', async () => {
		const t = await setup();
		t.secrets.add('the-login-value-12345');
		const session = await t.start();
		await session.openPoint('hello.home', 1, '/');
		t.api.captureError = new RecorderError(500, 'capture_failed', 'the page went away');
		await session.capture({ kind: 'screenshot', label: 'the-login-value-12345' });
		const problems = t.run.status.problems.map((problem) => problem.detail).join('\n');
		expect(problems).toContain('[redacted]');
		expect(problems).not.toContain('the-login-value-12345');
		await session.stop();
	});

	test("what the recorder could not promise joins the entry's limitations, scrubbed", async () => {
		const t = await setup();
		t.secrets.add('the-login-value-12345');
		const session = await t.start();
		await session.openPoint('hello.home', 1, '/');
		t.api.bytesByKind.set('screenshot', [PNG_WITH_METADATA]);
		const frames =
			'the page replaced a child frame while the capture was taken; only password fields in the main frame were masked';
		t.api.captureLimitations = [frames, 'a frame at /?k=the-login-value-12345'];
		const artifact = await session.capture({ kind: 'screenshot', label: 'frames' });
		expect(artifact.availability).toBe('available');
		expect(artifact.redaction.limitations).toEqual([
			...LIMITATIONS.screenshot,
			frames,
			'a frame at /?k=[redacted]',
		]);
		await session.stop();
	});

	test('text captures are scrubbed in the stream, a known value split across chunks included', async () => {
		const t = await setup();
		t.secrets.add('the-login-value-12345');
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.bytesByKind.set('aria', [
			encode('- textbox "Key": the-login-'),
			encode('value-12345\n- text: fine\n'),
		]);
		const artifact = await session.capture({ kind: 'aria', label: 'tree' });
		expect(await readFile(join(t.store.runDir(RUN), 'artifacts', artifact.id), 'utf8')).toBe(
			'- textbox "Key": [redacted]\n- text: fine\n',
		);
		expect(artifact.mediaType).toBe('text/plain; charset=utf-8');
		t.api.bytesByKind.set('console', [
			encode('[log] token koi_0123456789abcdefghijklmnopqrstuv\n'),
		]);
		const console = await session.capture({ kind: 'console', label: 'console' });
		expect(await readFile(join(t.store.runDir(RUN), 'artifacts', console.id), 'utf8')).toBe(
			'[log] token [redacted]\n',
		);
		await session.stop();
	});

	test('trace, har and file are withheld without asking the recorder', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		const before = t.api.calls.length;
		const trace = await session.capture({ kind: 'trace', label: 'journey' });
		expect(trace.redaction).toEqual({
			status: 'withheld',
			policyDigest: policyDigest('trace'),
			removedFields: [],
			limitations: [WITHHELD_KINDS.trace],
		});
		expect(trace.availability).toBe('withheld');
		expect(trace.size).toBe(0);
		expect(t.api.calls.slice(before).filter((c) => c.startsWith('capture'))).toEqual([]);
		expect((await t.artifacts()).length).toBe(0);
		expect((await t.events()).at(-1)).toMatchObject({
			type: 'capture-withheld',
			kind: 'trace',
			artifact: trace.id,
		});
		// Withholding is policy, not a problem.
		expect(t.run.status.problems).toEqual([]);
		await session.stop();
	});

	test('a failure mid-capture leaves no partial artifact, records a failed entry and a problem, and frees the raw bytes', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.bytesByKind.set('aria', [encode('first\n'), encode('second\n')]);
		t.api.failBytes = true;
		const artifact = await session.capture({ kind: 'aria', label: 'tree' });
		expect(artifact.redaction.status).toBe('failed');
		expect(artifact.availability).toBe('failed');
		expect(artifact.redaction.limitations[0]).toContain('the connection dropped');
		expect(await t.artifacts()).toEqual([]);
		expect(await readdir(join(t.store.runDir(RUN), '.pending'))).toEqual([]);
		expect(t.api.acknowledged).toEqual(['c1']);
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['capture_failed']);
		t.api.failBytes = false;
		t.api.captureError = new RecorderError(
			409,
			'ambiguous_page',
			'the context has several pages; name one',
		);
		const second = await session.capture({ kind: 'screenshot', label: 'two-pages' });
		expect(second.redaction.status).toBe('failed');
		expect(second.redaction.limitations[0]).toContain('several pages');
		await session.stop();
	});

	test('a stream that fails as the recorder stopping is a loss: the call throws and the session says so', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.bytesByKind.set('aria', [encode('first\n'), encode('second\n')]);
		t.api.failBytes = true;
		// What the HTTP client's stream fails with once the connection is
		// gone: the same status 0 as a request the recorder did not answer.
		t.api.bytesError = new RecorderError(0, 'unreachable', 'the recorder stopped sending: reset');
		await expect(session.capture({ kind: 'aria', label: 'tree' })).rejects.toBeInstanceOf(
			RecorderLostError,
		);
		expect(session.lost).toBe('reading a capture: the recorder stopped sending: reset');
		expect(t.run.artifacts.map((a) => [a.availability, a.redaction.limitations[0]])).toEqual([
			[
				'failed',
				'the recorder did not capture: reading a capture: the recorder stopped sending: reset',
			],
		]);
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['capture_failed']);
		await session.stop();
	});

	test("the run's time running out while a stream is read is the deadline, not a capture error", async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		const aborter = new AbortController();
		session.budget = { until: Date.parse(AT) + 60_000, signal: aborter.signal };
		t.api.bytesByKind.set('aria', [encode('first\n'), encode('second\n')]);
		// The budget ends while the body is being read: the request was
		// answered in time, the bytes were not.
		t.api.onBytes = () => aborter.abort(new Error('the budget ended'));
		t.api.failBytes = true;
		await expect(session.capture({ kind: 'aria', label: 'tree' })).rejects.toBeInstanceOf(
			RecorderDeadlineError,
		);
		expect(t.run.artifacts.map((a) => [a.availability, a.redaction.limitations[0]])).toEqual([
			[
				'failed',
				"the capture was not made: reading a capture: the run's time ran out during the call",
			],
		]);
		expect(t.run.status.problems).toEqual([]);
		expect(session.lost).toBeUndefined();
		session.budget = undefined;
		await session.stop();
	});

	test('a reason that quotes the recorder is scrubbed before it is kept', async () => {
		const t = await setup();
		t.secrets.add('the-login-value-12345');
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.captureError = new RecorderError(
			500,
			'internal',
			'the page said the-login-value-12345 and then failed',
		);
		const artifact = await session.capture({ kind: 'screenshot', label: 'odd' });
		expect(artifact.redaction.limitations[0]).toBe(
			'the recorder did not capture: the page said [redacted] and then failed',
		);
		expect(t.run.status.problems[0]?.detail).not.toContain('the-login-value-12345');
		expect(JSON.stringify(await t.events())).not.toContain('the-login-value-12345');
		await session.stop();
	});

	test('an entry the store refuses is acknowledged and recorded as failed', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		// The recorder's reply passes the control API's loose shape; the
		// artifact entry made from it does not pass the manifest's.
		t.api.mediaTypeOverride = 'not a media type';
		t.api.bytesByKind.set('aria', [encode('- text: fine\n')]);
		const artifact = await session.capture({ kind: 'aria', label: 'all' });
		expect(artifact.availability).toBe('failed');
		expect(artifact.redaction.status).toBe('failed');
		expect(await t.artifacts()).toEqual([]);
		expect(t.api.acknowledged).toEqual(['c1']);
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['artifact_invalid']);
		expect((await t.events()).at(-1)).toMatchObject({
			type: 'capture-failed',
			kind: 'aria',
			artifact: artifact.id,
		});
		expect(artifact.redaction.limitations[0]).toContain('mediaType');
		await session.stop();
	});

	test('a capture that is not what the sanitizer accepts is withheld', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.bytesByKind.set('screenshot', [encode('<svg/>')]);
		const artifact = await session.capture({ kind: 'screenshot', label: 'odd' });
		expect(artifact.redaction.status).toBe('withheld');
		expect(artifact.redaction.limitations[0]).toContain('not a PNG');
		expect(t.api.acknowledged).toEqual(['c1']);
		await session.stop();
	});

	test('once the run can keep no more entries, a capture throws the cap, and the run still finalizes', async () => {
		const t = await setup({ limits: { artifactsPerRun: 2 } });
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		await session.capture({ kind: 'trace', label: 'one' });
		// A failed capture counts like a withheld one.
		t.api.captureError = new RecorderError(409, 'frames_changed', 'the frames would not hold');
		const failed = await session.capture({ kind: 'screenshot', label: 'moving' });
		expect(failed.availability).toBe('failed');
		t.api.captureError = undefined;
		await expect(session.capture({ kind: 'trace', label: 'two' })).rejects.toThrow(
			'the most it may keep',
		);
		await expect(session.capture({ kind: 'aria', label: 'three' })).rejects.toThrow(
			CapExceededError,
		);
		await expect(
			session.read({ path: '/api/state', body: { body: false, maxBodyBytes: 0 } }),
		).rejects.toThrow(CapExceededError);
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['capture_failed', 'cap_exceeded']);
		expect(t.run.artifacts).toHaveLength(2);
		await session.stop();
		const manifest = await t.run.finalize({ limitations: [...session.limitations] });
		expect(manifest.artifacts).toHaveLength(2);
		expect(manifest.status.evidence).toBe('incomplete');
	});

	test('a screenshot the recorder could not take with every frame masked is a failed entry, never an artifact', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.captureError = new RecorderError(
			409,
			'frames_changed',
			'the page attached or detached a frame while the screenshot was taken, on both attempts; a password field in a frame the mask was not made for could show, so the screenshot was discarded',
		);
		const artifact = await session.capture({ kind: 'screenshot', label: 'moving' });
		expect(artifact.availability).toBe('failed');
		expect(artifact.redaction.status).toBe('failed');
		expect(artifact.redaction.limitations[0]).toContain('attached or detached a frame');
		expect(await t.artifacts()).toEqual([]);
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['capture_failed']);
		expect(t.api.calls.filter((c) => c.startsWith('bytes'))).toEqual([]);
		await session.stop();
	});

	test('a cap stops capture for the run', async () => {
		const t = await setup({ limits: { bytesPerArtifact: 16 } });
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.bytesByKind.set('aria', [encode('x'.repeat(40))]);
		const first = await session.capture({ kind: 'aria', label: 'big' });
		expect(first.redaction.status).toBe('failed');
		expect(t.run.capped?.cap).toBe('bytesPerArtifact');
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['cap_exceeded']);
		const before = t.api.calls.length;
		t.api.bytesByKind.set('aria', [encode('small\n')]);
		const second = await session.capture({ kind: 'aria', label: 'small' });
		expect(second.redaction.status).toBe('failed');
		expect(second.redaction.limitations[0]).toStartWith('capture stopped');
		expect(t.api.calls.slice(before).filter((c) => c.startsWith('capture'))).toEqual([]);
		expect(t.run.status.problems).toHaveLength(1);
		await session.stop();
	});

	test('a state read keeps the status and allowlisted headers, the body under policy', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		const artifact = await session.read({
			path: '/api/state',
			body: { body: false, maxBodyBytes: 4096 },
		});
		expect(t.api.calls).toContain('read x1 GET /api/state 0');
		expect(artifact.kind).toBe('http-response');
		const kept = JSON.parse(
			await readFile(join(t.store.runDir(RUN), 'artifacts', artifact.id), 'utf8'),
		) as { response: Record<string, unknown> };
		expect(kept.response).toEqual({
			status: 200,
			headers: { 'content-type': 'application/json' },
			bodyBytes: 14,
			truncated: false,
			bodyOmitted: 'the point policy did not ask for the body',
		});
		expect(artifact.redaction.removedFields).toEqual(['body', 'header:set-cookie']);
		const withBody = await session.read({
			path: '/api/state',
			body: { body: true, maxBodyBytes: 4096 },
		});
		expect(t.api.calls).toContain('read x1 GET /api/state 4096');
		expect(
			(
				JSON.parse(await readFile(join(t.store.runDir(RUN), 'artifacts', withBody.id), 'utf8')) as {
					response: { body: string };
				}
			).response.body,
		).toBe('{"saved":true}');
		await session.stop();
	});
});

describe('budget and loss', () => {
	test("a call past the run's budget is refused before it is made, as a failed entry without a problem", async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		const aborter = new AbortController();
		session.budget = { until: Date.parse(AT) - 1, signal: aborter.signal };
		await expect(session.capture({ kind: 'aria', label: 'tree' })).rejects.toBeInstanceOf(
			RecorderDeadlineError,
		);
		expect(t.api.calls.filter((c) => c.startsWith('capture'))).toEqual([]);
		expect(t.run.artifacts.map((a) => [a.availability, a.redaction.limitations[0]])).toEqual([
			['failed', "the capture was not made: capturing: the run's time is up"],
		]);
		// The deadline is the run's own limit, not a capture error.
		expect(t.run.status.problems).toEqual([]);
		expect(session.lost).toBeUndefined();
		// A budget with time left whose signal has fired is over too.
		session.budget = { until: Date.parse(AT) + 60_000, signal: AbortSignal.abort() };
		await expect(session.drainEvents()).rejects.toBeInstanceOf(RecorderDeadlineError);
		// The teardown gets a budget of its own, and closes the point with it.
		session.budget = { until: Date.parse(AT) + 60_000, signal: aborter.signal };
		await session.stop();
		expect(t.api.calls).toContain('close x1');
		expect(t.docker.removed).toEqual([`koi-verify-${RUN}-recorder`]);
	});

	test("a caller's signal ends a capture or a read as the budget would, with no problem on the run", async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		await expect(
			session.capture({ kind: 'aria', label: 'tree' }, { signal: AbortSignal.abort() }),
		).rejects.toBeInstanceOf(RecorderDeadlineError);
		await expect(
			session.read(
				{ path: '/', body: { body: true, maxBodyBytes: 1024 } },
				{ signal: AbortSignal.abort() },
			),
		).rejects.toBeInstanceOf(RecorderDeadlineError);
		expect(t.api.calls.filter((c) => c.startsWith('capture') || c.startsWith('read'))).toEqual([]);
		expect(t.run.artifacts.map((a) => [a.availability, a.redaction.limitations[0]])).toEqual([
			['failed', "the capture was not made: capturing: the point's time is up"],
			['failed', "the read was not made: reading state: the point's time is up"],
		]);
		expect(t.run.status.problems).toEqual([]);
		expect(session.lost).toBeUndefined();

		// One that fires during the call ends it, and the call carries it.
		const aborter = new AbortController();
		const capture = t.api.capture.bind(t.api);
		let seen: AbortSignal | undefined;
		t.api.capture = async (_context: string, _r: CaptureRequest, o?: CallOptions) => {
			seen = o?.signal;
			aborter.abort();
			throw new Error('aborted');
		};
		await expect(
			session.capture({ kind: 'aria', label: 'later' }, { signal: aborter.signal }),
		).rejects.toBeInstanceOf(RecorderDeadlineError);
		expect(seen?.aborted).toBe(true);
		expect(t.run.status.problems).toEqual([]);
		t.api.capture = capture;
	});

	test("a budget's end says whose time it was", async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		session.budget = {
			until: Date.parse(AT) - 1,
			signal: new AbortController().signal,
			of: 'point',
		};
		await expect(session.capture({ kind: 'aria', label: 'tree' })).rejects.toThrow(
			"capturing: the point's time is up",
		);
		session.budget = undefined;
		await session.stop();
	});

	test('an open that a budget cut short leaves a context the next close finds by its event', async () => {
		const t = await setup();
		const session = await t.start();
		const aborter = new AbortController();
		session.budget = { until: Date.parse(AT) + 60_000, signal: aborter.signal, of: 'point' };
		const open = t.api.openContext.bind(t.api);
		t.api.openNeverAnswers();
		const pending = session.openPoint('hello.home', 1, '/');
		aborter.abort();
		await expect(pending).rejects.toBeInstanceOf(RecorderDeadlineError);
		// The controller closes the point under the run's budget.
		session.budget = undefined;
		await session.closePoint();
		expect(t.api.calls).toContain('close x1');
		expect(t.run.status.problems).toEqual([]);
		// The recorder has nothing open now, so the next point opens and closes
		// as usual.
		t.api.openContext = open;
		await session.openPoint('hello.other', 1, '/');
		await session.closePoint();
		expect(t.api.calls.filter((c) => c === 'close x1')).toHaveLength(2);
		await session.stop();
	});

	test('a recorder that stops answering is a loss: the call throws, the session says so, the entry has a problem', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.captureError = new RecorderError(
			0,
			'unreachable',
			'the recorder did not answer: ECONNREFUSED',
		);
		await expect(session.capture({ kind: 'aria', label: 'tree' })).rejects.toBeInstanceOf(
			RecorderLostError,
		);
		expect(session.lost).toBe('capturing: the recorder did not answer: ECONNREFUSED');
		expect(t.run.artifacts.map((a) => a.availability)).toEqual(['failed']);
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['capture_failed']);
		// An answer the recorder gave, whatever it was, is no loss.
		t.api.captureError = new RecorderError(409, 'ambiguous_page', 'several pages');
		expect((await session.capture({ kind: 'aria', label: 'two' })).availability).toBe('failed');
		await session.stop();
	});

	test('the HTTP client ends a call on the signal it is given, besides its own timeout', async () => {
		const seen: Array<AbortSignal | null | undefined> = [];
		const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
			seen.push(init?.signal);
			return new Promise<Response>((_, reject) => {
				init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
			});
		}) as typeof fetch;
		const api = httpRecorder('http://10.0.0.2:4318', 'token', fetchImpl);
		const aborter = new AbortController();
		const pending = api.capture('x1', { kind: 'aria', label: 'tree' }, { signal: aborter.signal });
		aborter.abort();
		await expect(pending).rejects.toMatchObject({ status: 0, code: 'unreachable' });
		expect(seen[0]?.aborted).toBe(true);
		// Without a signal, a call still has its own timeout.
		const alone = api.events(0, 10);
		expect(seen[1]).toBeInstanceOf(AbortSignal);
		expect(seen[1]?.aborted).toBe(false);
		void alone.catch(() => {});
	});
});

describe('events', () => {
	test('the HTTP client reports a body that stops part way as the recorder not answering', async () => {
		const fetchImpl = (async () =>
			new Response(
				new ReadableStream<Uint8Array>({
					start(controller) {
						controller.enqueue(encode('first\n'));
						controller.error(new Error('socket hang up'));
					},
				}),
				{ status: 200 },
			)) as unknown as typeof fetch;
		const api = httpRecorder('http://10.0.0.2:4318', 'token', fetchImpl);
		const stream = await api.bytes('c1');
		const read = async () => {
			const got: Uint8Array[] = [];
			for await (const chunk of stream) got.push(chunk);
			return got;
		};
		// The request was answered; the bytes stopped. That is the same loss
		// as a request that was never answered, and reads as one.
		await expect(read()).rejects.toMatchObject({
			status: 0,
			code: 'unreachable',
			message: 'the recorder stopped sending: socket hang up',
		});
	});

	test('the HTTP client tells a reply that stops part way from one that is not JSON', async () => {
		const replying = (body: string | ReadableStream<Uint8Array>) =>
			httpRecorder(
				'http://10.0.0.2:4318',
				'token',
				(async () => new Response(body, { status: 200 })) as unknown as typeof fetch,
			);
		const stops = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(encode('{"events":['));
				controller.error(new Error('socket hang up'));
			},
		});
		// The headers came and the bytes stopped: the recorder is not answering.
		await expect(replying(stops).events(0, 10)).rejects.toMatchObject({
			status: 0,
			code: 'unreachable',
			message: 'the recorder stopped sending: socket hang up',
		});
		// The bytes came whole: the recorder is there, and said something wrong.
		await expect(replying('{"events":[').events(0, 10)).rejects.toMatchObject({
			status: 502,
			code: 'bad_reply',
			message: 'the recorder answered with something other than JSON',
		});
		await expect(replying('{"events":"none"}').events(0, 10)).rejects.toMatchObject({
			status: 502,
			code: 'bad_reply',
			message: 'the recorder answered with a shape koid cannot read',
		});
	});

	test('a reply that stops part way in the final drain is a loss the session notes', async () => {
		const t = await setup();
		const session = await t.start();
		const dropped = httpRecorder(
			'http://10.0.0.2:4318',
			'token',
			(async () =>
				new Response(
					new ReadableStream<Uint8Array>({
						start(controller) {
							controller.error(new Error('socket hang up'));
						},
					}),
					{ status: 200 },
				)) as unknown as typeof fetch,
		);
		t.api.events = (after, limit, options) => dropped.events(after, limit, options);
		await session.stop();
		// The gap says what is missing, and `lost` says why: the controller
		// ends the run as recorder_lost instead of a capture error.
		expect(session.lost).toBe('reading events: the recorder stopped sending: socket hang up');
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['observation_gap']);
		expect(t.docker.removed).toEqual([RECORDER]);
	});

	test('a reply that is not JSON in the final drain is a gap, and no loss', async () => {
		const t = await setup();
		const session = await t.start();
		const garbled = httpRecorder(
			'http://10.0.0.2:4318',
			'token',
			(async () => new Response('<html>', { status: 200 })) as unknown as typeof fetch,
		);
		t.api.events = (after, limit, options) => garbled.events(after, limit, options);
		await session.stop();
		expect(session.lost).toBeUndefined();
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['observation_gap']);
	});

	test('recorder events are scrubbed into the run, and some become problems or capabilities', async () => {
		const t = await setup();
		t.secrets.add('the-login-value-12345');
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.emit('denied', {
			contextId: 'x1',
			what: 'navigation',
			url: 'http://example.com/?k=the-login-value-12345',
			reason: 'outside the app origin',
		});
		t.api.emit('foreign-target', { targetType: 'page', url: 'about:blank', closed: true });
		t.api.emit('client-capability', { capability: 'login-key' });
		t.api.emit('console', { nested: { deep: 'the-login-value-12345' } });
		t.api.emit('dropped', { contextId: 'x1', what: 'console', limit: 10_000 });
		t.api.emit('guard-unavailable', { targetType: 'other', url: 'x', error: 'no Fetch' });
		expect(await session.drainEvents()).toBe(6);
		const events = await t.events();
		const denied = events.find((e) => e.type === 'denied');
		expect(denied).toMatchObject({
			source: 'recorder',
			pointId: 'hello.home',
			attempt: 1,
			url: 'http://example.com/?k=[redacted]',
			recorderSeq: 3,
		});
		expect(events.find((e) => e.type === 'console')?.nested).toBe('{"deep":"[redacted]"}');
		// A secret as a field's name, and in the one list kept as a list.
		t.api.emit('page-error', {
			'the-login-value-12345': 'where',
			text: RECORDER_OVERLONG_FIELD,
			truncatedFields: ['the-login-value-12345'],
		});
		expect(await session.drainEvents()).toBe(1);
		const text = await readFile(join(t.store.runDir(RUN), 'events.ndjson'), 'utf8');
		expect(text).not.toContain('the-login-value-12345');
		expect((await t.events()).at(-1)).toMatchObject({
			type: 'page-error',
			'[redacted]': 'where',
			truncatedFields: ['[redacted]'],
		});
		expect(t.run.status.problems.map((p) => [p.code, p.detail])).toEqual([
			[
				'unobserved_target',
				'the browser opened a target outside the contexts the recorder made; the recorder closed it',
			],
			[
				'observations_dropped',
				'the recorder dropped console observations past its limit of 10000 per context',
			],
			[
				'origin_guard_unavailable',
				'the recorder could not guard a other target; only the proxy layer held it',
			],
		]);
		expect(t.run.status.evidence).toBe('incomplete');
		expect([...session.capabilities]).toEqual(['raw-cdp', 'login-key']);
		// Nothing is read twice.
		expect(await session.drainEvents()).toBe(0);
		await session.stop();
	});

	// The events host/recorder/src/proxy.ts emits for a verifier's connection.
	// None of them names a capability, and the proxy has no other event for one.
	test('a verifier on the browser port leaves raw-cdp in the capabilities', async () => {
		const t = await setup();
		const session = await t.start();
		expect([...session.capabilities]).toEqual(['raw-cdp']);
		await session.openPoint('hello.home', 1);
		t.api.emit('client-connected', { client: '10.213.0.4' });
		t.api.emit('client-rewritten', { method: 'Target.attachToTarget' });
		t.api.emit('client-denied', {
			method: 'Fetch.enable',
			reason: 'Fetch.enable is not permitted',
		});
		t.api.emit('client-disconnected', { reason: 'client closed' });
		await session.drainEvents();
		expect((await t.events()).map((e) => e.type)).toContain('client-connected');
		expect([...session.capabilities]).toEqual(['raw-cdp']);
		await session.stop();
	});

	// Captures and state reads each drain the feed. Without turns, two at
	// once fetched from the same cursor and persisted [1, 1, 2, 2].
	describe('drains at the same time', () => {
		const recorderSeqs = (events: Array<Record<string, unknown>>) =>
			events.flatMap((e) => (typeof e.recorderSeq === 'number' ? [e.recorderSeq] : []));

		test('two captures persist each event once', async () => {
			const t = await setup();
			const session = await t.start();
			await session.openPoint('hello.home', 1);
			t.api.bytesByKind.set('aria', [encode('- text: fine\n')]);
			t.api.emit('console', { text: 'one' });
			t.api.emit('console', { text: 'two' });
			t.api.eventsDelayMs = 5;
			const [first, second] = await Promise.all([
				session.capture({ kind: 'aria', label: 'first' }),
				session.capture({ kind: 'aria', label: 'second' }),
			]);
			expect(first.availability).toBe('available');
			expect(second.availability).toBe('available');
			expect(recorderSeqs(await t.events())).toEqual(t.api.feed.map((e) => e.seq));
			await session.stop();
		});

		test('a capture and a state read persist each event once', async () => {
			const t = await setup();
			const session = await t.start();
			await session.openPoint('hello.home', 1);
			t.api.bytesByKind.set('aria', [encode('- text: fine\n')]);
			t.api.emit('console', { text: 'one' });
			t.api.emit('console', { text: 'two' });
			t.api.eventsDelayMs = 5;
			await Promise.all([
				session.capture({ kind: 'aria', label: 'tree' }),
				session.read({ path: '/api/state', body: { body: false, maxBodyBytes: 0 } }),
			]);
			expect(recorderSeqs(await t.events())).toEqual(t.api.feed.map((e) => e.seq));
			await session.stop();
		});

		test('the second waits for the first and starts from its cursor', async () => {
			const t = await setup();
			const session = await t.start();
			t.api.emit('console', { text: 'one' });
			t.api.emit('console', { text: 'two' });
			t.api.eventsDelayMs = 5;
			const events = spyOn(t.api, 'events');
			expect(await Promise.all([session.drainEvents(), session.drainEvents()])).toEqual([2, 0]);
			expect(events.mock.calls.map(([after]) => after)).toEqual([0, 2]);
			await session.stop();
		});

		test('a drain that fails leaves the chain open, and the next takes up the events', async () => {
			const t = await setup();
			const session = await t.start();
			t.api.emit('console', { text: 'one' });
			t.api.emit('console', { text: 'two' });
			spyOn(t.api, 'events').mockImplementationOnce(async () => {
				throw new Error('the connection dropped');
			});
			const first = session.drainEvents();
			const second = session.drainEvents();
			await expect(first).rejects.toThrow('the connection dropped');
			expect(await second).toBe(2);
			expect(recorderSeqs(await t.events())).toEqual([1, 2]);
			await session.stop();
		});
	});

	test('events the recorder dropped before koid read them are a gap; ones koid had read are not', async () => {
		const t = await setup();
		const session = await t.start();
		for (let i = 0; i < 10; i++) t.api.emit('navigation', { url: `/${i}` });
		// The ring lost 1 to 7 before koid read anything.
		t.api.lost = 7;
		expect(await session.drainEvents()).toBe(3);
		expect(t.run.status.problems).toMatchObject([
			{ code: 'observation_gap', detail: 'the recorder dropped 7 events before koid read them' },
		]);
		await session.drainEvents();
		expect(t.run.status.problems).toHaveLength(1);
		// The ring now loses what koid had read already: no gap.
		t.api.lost = 10;
		for (let i = 0; i < 3; i++) t.api.emit('navigation', { url: `/${i}` });
		expect(await session.drainEvents()).toBe(3);
		expect(t.run.status.problems).toHaveLength(1);
		// Then loses two more koid had not: a second gap, of exactly those.
		for (let i = 0; i < 4; i++) t.api.emit('navigation', { url: `/${i}` });
		t.api.lost = 15;
		expect(await session.drainEvents()).toBe(2);
		expect(t.run.status.problems.at(-1)).toMatchObject({
			code: 'observation_gap',
			detail: 'the recorder dropped 2 events before koid read them',
		});
		await session.stop();
	});

	test('a field the recorder discarded is a limitation, and the marker is kept as is', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.emit('page-error', {
			contextId: 'x1',
			pageId: 'p1',
			text: RECORDER_OVERLONG_FIELD,
			truncatedFields: ['text'],
		});
		expect(await session.drainEvents()).toBe(1);
		expect([...session.limitations]).toEqual([OVERLONG_EVENT_FIELDS]);
		expect((await t.events()).at(-1)).toMatchObject({
			type: 'page-error',
			text: RECORDER_OVERLONG_FIELD,
			truncatedFields: ['text'],
		});
		// Not a problem: nothing about the run is in doubt, only one text.
		expect(t.run.status.problems).toEqual([]);
		await session.stop();
	});

	test('a final drain that fails is an observation gap, on stop and on closing a point', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		t.api.eventsError = new Error('connection reset');
		await session.closePoint();
		expect(t.run.status.problems.map((p) => p.code)).toEqual(['observation_gap']);
		expect(t.run.status.problems[0]?.detail).toBe(
			"the recorder's events were not read when closing the point: connection reset",
		);
		await session.stop();
		expect(t.run.status.problems.map((p) => p.code)).toEqual([
			'observation_gap',
			'observation_gap',
		]);
		expect(t.run.status.problems[1]?.detail).toContain('when stopping the recorder');
		expect(t.run.status.evidence).toBe('incomplete');
		expect(t.docker.removed).toEqual([RECORDER]);
		const manifest = await t.run.finalize({ limitations: [] });
		expect(manifest.status.evidence).toBe('incomplete');
	});

	test('a secret is scrubbed from keys and values at any depth, in objects and lists', () => {
		const secrets = new SecretRegistry();
		const secret = 'the-login-value-12345';
		secrets.add(secret);
		const scrubbed = scrubFields(secrets, {
			[secret]: 'as a key',
			list: [secret, { [secret]: secret }, [secret]],
			nested: { deeper: { [secret]: { [`k=${secret}`]: `v=${secret}` } } },
			count: 2,
			flag: null,
			gone: undefined,
		});
		expect(scrubbed).toEqual({
			'[redacted]': 'as a key',
			list: ['[redacted]', { '[redacted]': '[redacted]' }, ['[redacted]']],
			nested: { deeper: { '[redacted]': { 'k=[redacted]': 'v=[redacted]' } } },
			count: 2,
			flag: null,
		});
		expect(JSON.stringify(scrubbed)).not.toContain(secret);
		// Two keys that scrub to one name keep the first; a key that was the
		// mask already does not take the place of one scrubbed before it.
		secrets.add('other-login-value-67890');
		expect(
			scrubFields(secrets, {
				[secret]: 'first',
				'other-login-value-67890': 'second',
				'[redacted]': 'third',
				plain: 'stays',
			}),
		).toEqual({ '[redacted]': 'first', plain: 'stays' });
	});

	test('one point at a time, and nothing after stop', async () => {
		const t = await setup();
		const session = await t.start();
		await session.openPoint('hello.home', 1);
		await expect(session.openPoint('hello.other', 1)).rejects.toThrow('open already');
		await session.closePoint();
		expect(t.api.calls).toContain('close x1');
		await expect(session.capture({ kind: 'aria', label: 'x' })).rejects.toThrow('no point is open');
		await session.stop();
		await expect(session.openPoint('hello.home', 2)).rejects.toThrow('stopped');
		await session.stop();
		expect(t.docker.stopped).toEqual([RECORDER]);
	});
});
