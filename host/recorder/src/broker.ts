import { request as httpRequest } from 'node:http';
import { join } from 'node:path';
import {
	type Browser,
	type BrowserContext,
	type CDPSession,
	chromium,
	type Locator,
	type Page,
	type PageScreenshotOptions,
	type Request,
	type WebSocketRoute,
} from 'playwright-core';
import type { CaptureStore, StoredCapture } from './captures.ts';
import { CdpClient } from './cdp.ts';
import type { EventLog } from './events.ts';
import { OriginGuard } from './guard.ts';
import { type Origin, originUrl, proxyArgs, samePath, urlAllowed } from './origin.ts';
import type { Upstream } from './proxy.ts';

// The browser and what the recorder does with it. The broker launches one
// Chromium for the run with the origin guard (guard.ts) on every target it
// makes, opens a point's context on koid's request with service workers
// blocked and downloads refused, keeps the context's console and network
// observations, takes captures from it into the capture store, and reads
// the app's state from inside it. The verifier drives the same pages over
// the browser port (proxy.ts), so the recorder sees what the verifier did,
// and what it captures is what the verifier's client saw.
//
// Chromium's own DevTools port is bound to loopback, for the proxy and for
// the guard's own connection. A target made in a context the broker did
// not make is closed at once and reported: nothing the recorder cannot see
// may run.

// Where Chromium answers DevTools connections inside the container.
export const CDP_PORT = 9222;

// A point's context gets one viewport. Captures are of the viewport.
const VIEWPORT = { width: 1280, height: 800 };
const ACTION_TIMEOUT_MS = 15_000;
// The most observations one context keeps.
export const MAX_RECORDS = 10_000;

export class BrokerError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string,
	) {
		super(message);
	}
}

export interface BrokerOptions {
	runId: string;
	origin: Origin;
	captures: CaptureStore;
	events: EventLog;
	// The one directory the browser may write under.
	home: string;
	// The browser's whole environment: never the recorder's own.
	browserEnv: Record<string, string>;
	now?: () => Date;
}

export interface CaptureResult {
	captureId: string;
	kind: string;
	mediaType: string;
	size: number;
	sha256: string;
	pageId?: string;
	url?: string;
	eventRange: { first: number; last: number };
	capturedAt: string;
	// What the recorder itself could not promise about this capture. koid
	// copies it into the artifact's limitations, after the policy's own. No
	// kind sets it today: a screenshot whose frames would not hold still is
	// a failed capture, not one with a caveat.
	limitations?: string[];
}

interface NetworkRecord {
	id: number;
	pageId?: string | undefined;
	method: string;
	url: string;
	resourceType: string;
	navigation: boolean;
	redirectedFrom?: number | undefined;
	startedAt: string;
	status?: number | undefined;
	// The response's headers, every one. koid keeps an allowlist of them.
	headers?: Record<string, string> | undefined;
	endedAt?: string | undefined;
	failed?: string | undefined;
}

interface ConsoleRecord {
	at: string;
	pageId?: string | undefined;
	level: string;
	text: string;
	url?: string | undefined;
	line?: number | undefined;
}

interface Ctx {
	id: string;
	pointId: string;
	attempt: number;
	context: BrowserContext;
	pages: Map<string, Page>;
	pageIds: WeakMap<Page, string>;
	console: ConsoleRecord[];
	network: NetworkRecord[];
	requestIds: WeakMap<Request, number>;
	nextRequest: number;
	// Observations dropped past MAX_RECORDS, reported with the capture and
	// once in the event feed, so the run knows its evidence is incomplete.
	droppedConsole: number;
	droppedNetwork: number;
}

// Chromium's launch flags beyond Playwright's own: the DevTools port on
// loopback, the two proxy layers of origin.ts, and nothing that phones
// home.
// How the recorder launches Chromium, and the sandbox probe too (probe.ts):
// headless, with its own sandbox. Playwright adds --no-sandbox unless told
// otherwise. The seccomp profile the daemon starts the recorder with allows
// the user namespace the sandbox needs.
export const SANDBOXED = { headless: true, chromiumSandbox: true } as const;

export function chromiumArgs(origin: Origin): string[] {
	return [
		`--remote-debugging-port=${CDP_PORT}`,
		'--remote-debugging-address=127.0.0.1',
		...proxyArgs(origin),
		'--no-pings',
		'--disable-sync',
		'--disable-component-update',
		'--disable-domain-reliability',
		'--disable-breakpad',
		'--disable-crash-reporter',
		'--disable-default-apps',
	];
}

export class Broker {
	private readonly contexts = new Map<string, Ctx>();
	private nextContext = 1;
	private nextPage = 1;
	// Chromium's ids for the contexts this broker made. A target in any
	// other context is one the recorder does not observe.
	private readonly ownContextIds = new Set<string>();
	private readonly now: () => Date;
	// Why the broker is no use any more (fail), and whether the recorder is
	// closing it, when losing the browser and the guard is expected.
	private lost: string | undefined;
	private closing = false;

	private constructor(
		private readonly browser: Browser,
		private readonly session: CDPSession,
		private readonly guard: OriginGuard,
		readonly version: string,
		readonly cdp: Upstream,
		private readonly options: BrokerOptions,
	) {
		this.now = options.now ?? (() => new Date());
	}

	static async launch(options: BrokerOptions): Promise<Broker> {
		const browser = await chromium.launch({
			...SANDBOXED,
			timeout: 90_000,
			args: chromiumArgs(options.origin),
			env: options.browserEnv,
			downloadsPath: join(options.home, 'downloads'),
		});
		let client: CdpClient | undefined;
		try {
			const cdp = await discoverCdp();
			client = await CdpClient.connect(`ws://${cdp.host}:${cdp.port}${cdp.path}`);
			return await Broker.attach(browser, client, cdp, options);
		} catch (err) {
			client?.close();
			await browser.close().catch(() => {});
			throw err;
		}
	}

	// A broker on a browser that is running and a DevTools connection that is
	// open. Separate from launch so a test can hand in fakes of both.
	static async attach(
		browser: Browser,
		client: CdpClient,
		cdp: Upstream,
		options: BrokerOptions,
	): Promise<Broker> {
		// The guard goes on before any context exists, so no page runs
		// without it.
		const guard = await OriginGuard.start(client, options.origin, options.events);
		const session = await browser.newBrowserCDPSession();
		const broker = new Broker(browser, session, guard, browser.version(), cdp, options);
		await broker.watchTargets();
		broker.watchConnections();
		return broker;
	}

	get contextCount(): number {
		return this.contexts.size;
	}

	// Why the broker is no use any more, or undefined while it is.
	get failure(): string | undefined {
		return this.lost;
	}

	// Whether Chromium's id for a browser context is one this broker made.
	ownsContext(browserContextId: string): boolean {
		return this.ownContextIds.has(browserContextId);
	}

	// Every target Chromium makes. One in a context the broker did not make
	// is a page the recorder cannot see: it is closed at once and the run
	// learns of it.
	private async watchTargets(): Promise<void> {
		this.session.on('Target.targetCreated', ({ targetInfo }) => {
			if (targetInfo.type === 'browser') return;
			const contextId = targetInfo.browserContextId;
			if (contextId !== undefined && this.ownContextIds.has(contextId)) return;
			void this.session
				.send('Target.closeTarget', { targetId: targetInfo.targetId })
				.then(
					() => true,
					() => false,
				)
				.then((closed) => {
					this.options.events.push('foreign-target', {
						targetType: targetInfo.type,
						url: targetInfo.url,
						closed,
					});
				});
		});
		await this.session.send('Target.setDiscoverTargets', { discover: true });
	}

	// The two connections the run's evidence depends on. Losing either raises
	// no error by itself: a CdpClient only rejects the calls in flight, and a
	// browser that dies after the last capture has no call in flight at all.
	// Without this the run would finalize as if nothing happened.
	private watchConnections(): void {
		const browserLost = () => this.fail('the recorder failed: the browser disconnected');
		this.browser.on('disconnected', browserLost);
		if (!this.browser.isConnected()) browserLost();
		this.guard.onClosed(() =>
			this.fail("the recorder failed: the origin guard's DevTools connection closed"),
		);
	}

	// Marks the broker failed and puts recorder-failed in the event feed. koid
	// records that event as a problem, so the run cannot pass. koid also knows
	// the reason's first words (RecorderSession.start). The browser's death
	// closes the guard's connection too, so only the first loss is reported.
	private fail(reason: string): void {
		if (this.closing || this.lost !== undefined) return;
		this.lost = reason;
		this.options.events.push('recorder-failed', { reason });
	}

	// Learns Chromium's id for a context just made: the one not known before.
	private async learnContextIds(): Promise<void> {
		const { browserContextIds } = await this.session.send('Target.getBrowserContexts');
		for (const id of browserContextIds) this.ownContextIds.add(id);
	}

	async openContext(request: {
		pointId: string;
		attempt: number;
		open?: string;
	}): Promise<{ contextId: string; pageId: string; url: string }> {
		// A page opened now would have no browser under it, or no guard on it.
		if (this.lost !== undefined) throw new BrokerError(503, 'recorder_failed', this.lost);
		if (this.contexts.size > 0) {
			throw new BrokerError(409, 'context_open', 'a context is open already; close it first');
		}
		const target =
			request.open === undefined ? undefined : samePath(request.open, this.options.origin);
		if (request.open !== undefined && target === undefined) {
			throw new BrokerError(400, 'bad_path', 'open must be a path on the app origin');
		}
		const context = await this.browser.newContext({
			acceptDownloads: false,
			serviceWorkers: 'block',
			ignoreHTTPSErrors: false,
			javaScriptEnabled: true,
			locale: 'en-US',
			timezoneId: 'UTC',
			viewport: VIEWPORT,
		});
		const ctx: Ctx = {
			id: `x${this.nextContext++}`,
			pointId: request.pointId,
			attempt: request.attempt,
			context,
			pages: new Map(),
			pageIds: new WeakMap(),
			console: [],
			network: [],
			requestIds: new WeakMap(),
			nextRequest: 1,
			droppedConsole: 0,
			droppedNetwork: 0,
		};
		try {
			await this.learnContextIds();
			context.setDefaultTimeout(ACTION_TIMEOUT_MS);
			context.setDefaultNavigationTimeout(ACTION_TIMEOUT_MS);
			// HTTP requests are the guard's (guard.ts); WebSockets do not pass
			// through the Fetch domain, so they are checked here, and the proxy
			// layer fails one to any other host in any case.
			await context.routeWebSocket(
				() => true,
				(ws) => this.onWebSocket(ctx, ws),
			);
			context.on('page', (page) => this.registerPage(ctx, page));
			context.on('request', (req) => this.onRequest(ctx, req));
			context.on('response', (res) => {
				const id = ctx.requestIds.get(res.request());
				const record = id === undefined ? undefined : ctx.network.find((r) => r.id === id);
				if (record !== undefined) {
					record.status = res.status();
					record.headers = res.headers();
				}
			});
			context.on('requestfinished', (req) => this.endRequest(ctx, req));
			context.on('requestfailed', (req) => this.endRequest(ctx, req, req.failure()?.errorText));
			context.on('console', (message) => {
				const location = message.location();
				this.push(ctx, 'console', {
					at: this.now().toISOString(),
					pageId: this.pageIdOf(ctx, message.page()),
					level: message.type(),
					text: message.text(),
					url: location.url,
					line: location.lineNumber,
				});
			});
			context.on('weberror', (error) => {
				this.options.events.push('page-error', {
					contextId: ctx.id,
					pageId: this.pageIdOf(ctx, error.page()),
					text: error.error().message,
				});
			});
			context.on('close', () => {
				this.contexts.delete(ctx.id);
				this.options.events.push('context-closed', { contextId: ctx.id });
			});
			this.contexts.set(ctx.id, ctx);
			this.options.events.push('context-opened', {
				contextId: ctx.id,
				pointId: ctx.pointId,
				attempt: ctx.attempt,
			});
			const page = await context.newPage();
			const pageId = this.registerPage(ctx, page);
			if (target !== undefined) {
				try {
					await page.goto(target, { waitUntil: 'load' });
				} catch (err) {
					this.options.events.push('navigation-failed', {
						contextId: ctx.id,
						pageId,
						url: target,
						error: messageOf(err),
					});
				}
			}
			return { contextId: ctx.id, pageId, url: page.url() };
		} catch (err) {
			this.contexts.delete(ctx.id);
			await context.close().catch(() => {});
			throw err;
		}
	}

	async closeContext(contextId: string): Promise<void> {
		const ctx = this.ctx(contextId);
		await ctx.context.close();
		this.contexts.delete(contextId);
	}

	async capture(
		contextId: string,
		request: { kind: string; label: string; pageId?: string },
	): Promise<CaptureResult> {
		const ctx = this.ctx(contextId);
		const first = this.options.events.last;
		const capturedAt = this.now().toISOString();
		let stored: StoredCapture;
		let page: Page | undefined;
		switch (request.kind) {
			case 'screenshot': {
				page = this.pickPage(ctx, request.pageId);
				const bytes = await maskedScreenshot(page, ACTION_TIMEOUT_MS);
				stored = this.options.captures.put('screenshot', 'image/png', bytes);
				break;
			}
			case 'aria': {
				page = this.pickPage(ctx, request.pageId);
				const text = await page.ariaSnapshot({ timeout: ACTION_TIMEOUT_MS });
				stored = this.options.captures.put(
					'aria',
					'text/plain; charset=utf-8',
					new TextEncoder().encode(`${text}\n`),
				);
				break;
			}
			case 'console':
				stored = this.options.captures.put(
					'console',
					'application/x-ndjson',
					ndjson(ctx.console, ctx.droppedConsole),
				);
				break;
			case 'network':
				stored = this.options.captures.put(
					'network',
					'application/x-ndjson',
					ndjson(ctx.network, ctx.droppedNetwork),
				);
				break;
			default:
				throw new BrokerError(
					422,
					'unsupported_kind',
					`the recorder does not capture ${request.kind}`,
				);
		}
		const pageId = page === undefined ? undefined : this.pageIdOf(ctx, page);
		this.options.events.push('capture', {
			contextId,
			pageId,
			kind: request.kind,
			label: request.label,
			captureId: stored.captureId,
			size: stored.size,
		});
		return {
			captureId: stored.captureId,
			kind: stored.kind,
			mediaType: stored.mediaType,
			size: stored.size,
			sha256: stored.sha256,
			...(pageId !== undefined ? { pageId } : {}),
			...(page !== undefined ? { url: page.url() } : {}),
			eventRange: { first, last: this.options.events.last },
			capturedAt,
		};
	}

	// Asks the app for a path, as a browser in the point's context would
	// (its cookies go along), and keeps what came back as a capture: the
	// status, every header, and the body up to maxBodyBytes.
	async read(
		contextId: string,
		request: { method: 'GET' | 'HEAD'; path: string; maxBodyBytes: number },
	): Promise<CaptureResult> {
		const ctx = this.ctx(contextId);
		const url = samePath(request.path, this.options.origin);
		if (url === undefined) {
			throw new BrokerError(400, 'bad_path', 'path must be a path on the app origin');
		}
		const first = this.options.events.last;
		const startedAt = this.now().toISOString();
		const cookies = await ctx.context.cookies([url]);
		const cookie = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
		const response = await boundedRequest(url, request.method, cookie, request.maxBodyBytes);
		const record = {
			request: { method: request.method, url },
			response: {
				status: response.status,
				headers: response.headers,
				bodyBase64: Buffer.from(response.body).toString('base64'),
				bodyBytes: response.body.length,
				truncated: response.truncated,
			},
			startedAt,
			endedAt: this.now().toISOString(),
		};
		const stored = this.options.captures.put(
			'http-response',
			'application/json',
			new TextEncoder().encode(JSON.stringify(record)),
		);
		this.options.events.push('state-read', {
			contextId,
			method: request.method,
			url,
			status: response.status,
			captureId: stored.captureId,
		});
		return {
			captureId: stored.captureId,
			kind: stored.kind,
			mediaType: stored.mediaType,
			size: stored.size,
			sha256: stored.sha256,
			url,
			eventRange: { first, last: this.options.events.last },
			capturedAt: startedAt,
		};
	}

	async close(): Promise<void> {
		this.closing = true;
		for (const ctx of this.contexts.values()) await ctx.context.close().catch(() => {});
		this.contexts.clear();
		this.guard.close();
		await this.browser.close();
	}

	private ctx(contextId: string): Ctx {
		const ctx = this.contexts.get(contextId);
		if (ctx === undefined) throw new BrokerError(404, 'no_context', 'no such context');
		return ctx;
	}

	// The page a capture is of: the one named, or the only one. With several
	// pages and no name, the capture fails rather than guess.
	private pickPage(ctx: Ctx, pageId: string | undefined): Page {
		if (pageId !== undefined) {
			const page = ctx.pages.get(pageId);
			if (page === undefined || page.isClosed()) {
				throw new BrokerError(404, 'no_page', 'no such page in the context');
			}
			return page;
		}
		const open = [...ctx.pages.values()].filter((p) => !p.isClosed());
		if (open.length === 0) throw new BrokerError(404, 'no_page', 'the context has no open page');
		if (open.length > 1) {
			throw new BrokerError(409, 'ambiguous_page', 'the context has several pages; name one');
		}
		return open[0] as Page;
	}

	private pageIdOf(ctx: Ctx, page: Page | null | undefined): string | undefined {
		return page ? ctx.pageIds.get(page) : undefined;
	}

	private registerPage(ctx: Ctx, page: Page): string {
		const known = ctx.pageIds.get(page);
		if (known !== undefined) return known;
		const pageId = `p${this.nextPage++}`;
		ctx.pageIds.set(page, pageId);
		ctx.pages.set(pageId, page);
		const events = this.options.events;
		events.push('page-opened', { contextId: ctx.id, pageId, url: page.url() });
		page.on('download', (download) => {
			events.push('denied', {
				contextId: ctx.id,
				pageId,
				what: 'download',
				url: download.url(),
				reason: 'downloads are not accepted',
			});
			download.cancel().catch(() => {});
		});
		page.on('framenavigated', (frame) => {
			if (frame === page.mainFrame()) {
				events.push('navigation', { contextId: ctx.id, pageId, url: frame.url() });
			}
		});
		// Recorded, not answered: the verifier's client decides what a
		// dialog gets. Without a listener here, this side would dismiss it
		// first.
		page.on('dialog', (dialog) => {
			events.push('dialog', {
				contextId: ctx.id,
				pageId,
				dialogType: dialog.type(),
				message: dialog.message(),
			});
		});
		page.on('crash', () => events.push('page-crashed', { contextId: ctx.id, pageId }));
		page.on('close', () => {
			ctx.pages.delete(pageId);
			events.push('page-closed', { contextId: ctx.id, pageId });
		});
		return pageId;
	}

	private onWebSocket(ctx: Ctx, ws: WebSocketRoute): void {
		routeWebSocket(ws, this.options.origin, this.options.events, ctx.id);
	}

	private onRequest(ctx: Ctx, request: Request): void {
		const id = ctx.nextRequest++;
		ctx.requestIds.set(request, id);
		const from = request.redirectedFrom();
		const redirectedFrom = from === null ? undefined : ctx.requestIds.get(from);
		this.push(ctx, 'network', {
			id,
			pageId: this.pageIdOf(ctx, pageOf(request)),
			method: request.method(),
			url: request.url(),
			resourceType: request.resourceType(),
			navigation: request.isNavigationRequest(),
			...(redirectedFrom !== undefined ? { redirectedFrom } : {}),
			startedAt: this.now().toISOString(),
		});
	}

	private endRequest(ctx: Ctx, request: Request, failed?: string): void {
		const id = ctx.requestIds.get(request);
		const record = id === undefined ? undefined : ctx.network.find((r) => r.id === id);
		if (record === undefined) return;
		record.endedAt = this.now().toISOString();
		if (failed !== undefined) record.failed = failed;
	}

	private push(ctx: Ctx, kind: 'console', record: ConsoleRecord): void;
	private push(ctx: Ctx, kind: 'network', record: NetworkRecord): void;
	private push(ctx: Ctx, kind: 'console' | 'network', record: ConsoleRecord | NetworkRecord) {
		const records = kind === 'console' ? ctx.console : ctx.network;
		if (records.length < MAX_RECORDS) {
			records.push(record as ConsoleRecord & NetworkRecord);
			return;
		}
		// The first drop is an event, so koid records the gap; the capture
		// carries the final count.
		const dropped = kind === 'console' ? ++ctx.droppedConsole : ++ctx.droppedNetwork;
		if (dropped === 1) {
			this.options.events.push('dropped', { contextId: ctx.id, what: kind, limit: MAX_RECORDS });
		}
	}
}

// What GET /health reports besides the broker's own state.
export interface HealthFacts {
	runId: string;
	origin: Origin;
	captures: Pick<CaptureStore, 'stats'>;
	events: Pick<EventLog, 'next' | 'dropped'>;
	playwright: string;
}

// The reply to GET /health: 503 with the reason while the browser starts, if it
// never started, and once the broker has failed; 200 with what runs otherwise.
// Not in server.ts because importing that file starts the recorder, so a test
// could not reach it there.
export function healthReply(
	broker: Pick<Broker, 'failure' | 'version' | 'contextCount'> | undefined,
	startupError: string | undefined,
	facts: HealthFacts,
): { status: number; body: Record<string, unknown> } {
	if (broker === undefined) {
		return { status: 503, body: { ok: false, reason: startupError ?? 'starting' } };
	}
	if (broker.failure !== undefined) {
		return { status: 503, body: { ok: false, reason: broker.failure } };
	}
	return {
		status: 200,
		body: {
			ok: true,
			runId: facts.runId,
			origin: originUrl(facts.origin),
			browser: { name: 'chromium', version: broker.version },
			playwright: facts.playwright,
			contexts: broker.contextCount,
			captures: facts.captures.stats(),
			events: { next: facts.events.next, dropped: facts.events.dropped },
		},
	};
}

// A WebSocket the page opens, as context.routeWebSocket hands it over.
// ws.url() is a ws: URL as Chromium normalizes it (a default port written
// out is dropped), and urlAllowed compares a ws: URL as the http: origin it
// shares, so the app's own socket passes on any port. Anything else is
// closed with a policy code and reported. Returns whether it was allowed.
export function routeWebSocket(
	ws: Pick<WebSocketRoute, 'url' | 'connectToServer' | 'close'>,
	origin: Origin,
	events: EventLog,
	contextId: string,
): boolean {
	const url = ws.url();
	if (urlAllowed(url, origin)) {
		ws.connectToServer();
		events.push('websocket', { contextId, url });
		return true;
	}
	events.push('denied', { contextId, what: 'websocket', url, reason: 'outside the app origin' });
	ws.close({ code: 1008, reason: 'outside the app origin' });
	return false;
}

// What the screenshot path uses of a page and its frames. A unit test
// stands in a fake whose frames come and go.
export interface MaskableFrame {
	isDetached(): boolean;
	locator(selector: string): Locator;
}

type FrameEvent = 'frameattached' | 'framedetached';

export interface MaskablePage {
	frames(): MaskableFrame[];
	screenshot(options: PageScreenshotOptions): Promise<Buffer>;
	on(event: FrameEvent, listener: (frame: MaskableFrame) => void): unknown;
	off(event: FrameEvent, listener: (frame: MaskableFrame) => void): unknown;
}

const PASSWORD_FIELDS = 'input[type=password i]';

// How many times the screenshot is taken before the capture fails because
// the page's frames would not hold still.
const MASK_ATTEMPTS = 2;

// The capture's error code and message when they would not.
export const FRAMES_CHANGED_CODE = 'frames_changed';
export const FRAMES_CHANGED =
	'the page attached or detached a frame while the screenshot was taken, on both attempts; a password field in a frame the mask was not made for could show, so the screenshot was discarded';

// A PNG of the viewport with every password field masked before the pixels
// exist: one locator per frame, the main frame and each child frame, since
// a locator on the main frame does not reach into an iframe. The frames
// are listed once, so a frame attached between the listing and the pixels
// has no mask. Frame attach and detach events are watched from before the
// listing until the screenshot is back: if any fired, the screenshot is
// discarded and taken again once; if the frames changed again, the capture
// fails with FRAMES_CHANGED. A frame that detaches during the capture makes
// Playwright fail the screenshot, which counts as a change too. No attempt
// masks less than every frame listed, and nothing partial is kept.
export async function maskedScreenshot(page: MaskablePage, timeout: number): Promise<Buffer> {
	const options: PageScreenshotOptions = {
		type: 'png',
		animations: 'disabled',
		caret: 'hide',
		scale: 'css',
		maskColor: '#000000',
		timeout,
	};
	for (let attempt = 0; attempt < MASK_ATTEMPTS; attempt++) {
		let changed = false;
		const note = () => {
			changed = true;
		};
		page.on('frameattached', note);
		page.on('framedetached', note);
		try {
			const mask = page
				.frames()
				.filter((frame) => !frame.isDetached())
				.map((frame) => frame.locator(PASSWORD_FIELDS));
			const bytes = await page.screenshot({ ...options, mask });
			if (!changed) return bytes;
		} catch (err) {
			if (!frameWentAway(err)) throw err;
		} finally {
			page.off('frameattached', note);
			page.off('framedetached', note);
		}
	}
	throw new BrokerError(409, FRAMES_CHANGED_CODE, FRAMES_CHANGED);
}

// Playwright's error for a mask whose frame is gone by the time the
// screenshot is taken.
function frameWentAway(err: unknown): boolean {
	return /frame.*detached/i.test(messageOf(err));
}

// The page a request belongs to, or undefined for one from a worker.
function pageOf(request: Request): Page | undefined {
	try {
		return request.frame().page();
	} catch {
		return undefined;
	}
}

function ndjson(records: unknown[], dropped: number): Uint8Array {
	const lines = records.map((r) => JSON.stringify(r));
	if (dropped > 0) lines.push(JSON.stringify({ dropped }));
	return new TextEncoder().encode(lines.length === 0 ? '' : `${lines.join('\n')}\n`);
}

function messageOf(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

// Chromium's browser endpoint, from its DevTools listing on loopback.
async function discoverCdp(): Promise<Upstream> {
	let lastError: unknown;
	for (let attempt = 0; attempt < 40; attempt++) {
		try {
			const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`, {
				signal: AbortSignal.timeout(2_000),
			});
			const data = (await res.json()) as { webSocketDebuggerUrl?: unknown };
			if (typeof data.webSocketDebuggerUrl === 'string') {
				const url = new URL(data.webSocketDebuggerUrl);
				return { host: '127.0.0.1', port: Number(url.port || CDP_PORT), path: url.pathname };
			}
			lastError = new Error('no webSocketDebuggerUrl in /json/version');
		} catch (err) {
			lastError = err;
		}
		await new Promise((resolve) => setTimeout(resolve, 250));
	}
	throw new Error(`Chromium's DevTools endpoint did not answer: ${messageOf(lastError)}`);
}

interface BoundedResponse {
	status: number;
	headers: Record<string, string>;
	body: Uint8Array;
	truncated: boolean;
}

// One request to the app with a body read to maxBodyBytes and no further.
function boundedRequest(
	url: string,
	method: 'GET' | 'HEAD',
	cookie: string,
	maxBodyBytes: number,
): Promise<BoundedResponse> {
	return new Promise((resolve, rejectWith) => {
		const req = httpRequest(
			url,
			{
				method,
				headers: { accept: '*/*', ...(cookie !== '' ? { cookie } : {}) },
				timeout: ACTION_TIMEOUT_MS,
			},
			(res) => {
				const headers: Record<string, string> = {};
				for (const [name, value] of Object.entries(res.headers)) {
					if (value === undefined) continue;
					headers[name] = Array.isArray(value) ? value.join(', ') : value;
				}
				const chunks: Uint8Array[] = [];
				let size = 0;
				let truncated = false;
				res.on('data', (chunk: Buffer) => {
					if (truncated) return;
					const room = maxBodyBytes - size;
					if (chunk.length > room) {
						chunks.push(chunk.subarray(0, room));
						size += room;
						truncated = true;
						res.destroy();
						return;
					}
					chunks.push(chunk);
					size += chunk.length;
				});
				const finish = () =>
					resolve({
						status: res.statusCode ?? 0,
						headers,
						body: Buffer.concat(chunks),
						truncated,
					});
				res.on('end', finish);
				res.on('close', finish);
				res.on('error', (err) => (truncated ? finish() : rejectWith(err)));
			},
		);
		req.on('timeout', () => req.destroy(new Error('the app did not answer in time')));
		req.on('error', rejectWith);
		req.end();
	});
}
