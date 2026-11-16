import { describe, expect, test } from 'bun:test';
import type { Browser, Locator, PageScreenshotOptions, WebSocketRoute } from 'playwright-core';
import {
	Broker,
	BrokerError,
	FRAMES_CHANGED,
	FRAMES_CHANGED_CODE,
	healthReply,
	type MaskableFrame,
	type MaskablePage,
	maskedScreenshot,
	routeWebSocket,
} from '../src/broker.ts';
import { CaptureStore } from '../src/captures.ts';
import { CdpClient, type CdpSocket } from '../src/cdp.ts';
import { EventLog } from '../src/events.ts';
import { parseOrigin } from '../src/origin.ts';

// A page as far as the screenshot path reads one: frames by name, some
// already detached, and a screenshot that records the masks it was given
// as "frame:selector". The first `failures` screenshots fail as
// Playwright's does when a masked frame is gone by then; the first
// `changes` screenshots attach a frame while they are taken, as a page
// that keeps loading iframes does.
function fakePage(
	names: string[],
	options: { detached?: string[]; failures?: number; changes?: number } = {},
) {
	const frame = (name: string): MaskableFrame => ({
		isDetached: () => options.detached?.includes(name) ?? false,
		locator: (selector) => ({ tag: `${name}:${selector}` }) as unknown as Locator,
	});
	const shots: string[][] = [];
	let failures = options.failures ?? 0;
	let changes = options.changes ?? 0;
	const listeners = new Map<string, Set<(frame: MaskableFrame) => void>>();
	const page: MaskablePage = {
		frames: () => names.map(frame),
		on: (event, listener) =>
			listeners.get(event)?.add(listener) ?? listeners.set(event, new Set([listener])),
		off: (event, listener) => listeners.get(event)?.delete(listener),
		screenshot: async (o: PageScreenshotOptions) => {
			shots.push((o.mask ?? []).map((l) => (l as unknown as { tag: string }).tag));
			if (failures > 0) {
				failures -= 1;
				throw new Error('page.screenshot: Frame was detached');
			}
			if (changes > 0) {
				changes -= 1;
				for (const listener of listeners.get('frameattached') ?? []) listener(frame('late'));
			}
			return Buffer.from('png');
		},
	};
	const listening = () => [...listeners.values()].reduce((n, set) => n + set.size, 0);
	return { page, shots, listening };
}

const PASSWORDS = 'input[type=password i]';

describe('maskedScreenshot', () => {
	test('masks password fields in the main frame and in every child frame', async () => {
		const { page, shots, listening } = fakePage(['main', 'login-iframe', 'ad']);
		expect(await maskedScreenshot(page, 1000)).toEqual(Buffer.from('png'));
		expect(shots).toEqual([[`main:${PASSWORDS}`, `login-iframe:${PASSWORDS}`, `ad:${PASSWORDS}`]]);
		expect(listening()).toBe(0);
	});

	test('leaves out a frame already detached when the frames are listed', async () => {
		const { page, shots } = fakePage(['main', 'gone', 'child'], { detached: ['gone'] });
		await maskedScreenshot(page, 1000);
		expect(shots).toEqual([[`main:${PASSWORDS}`, `child:${PASSWORDS}`]]);
	});

	test('lists the frames again and retries when one detaches during the capture', async () => {
		const { page, shots } = fakePage(['main', 'child'], { failures: 1 });
		expect(await maskedScreenshot(page, 1000)).toEqual(Buffer.from('png'));
		expect(shots).toEqual([
			[`main:${PASSWORDS}`, `child:${PASSWORDS}`],
			[`main:${PASSWORDS}`, `child:${PASSWORDS}`],
		]);
	});

	test('discards a screenshot taken while a frame was attached, and retries once', async () => {
		const { page, shots, listening } = fakePage(['main', 'child'], { changes: 1 });
		expect(await maskedScreenshot(page, 1000)).toEqual(Buffer.from('png'));
		expect(shots).toHaveLength(2);
		expect(listening()).toBe(0);
	});

	test('fails the capture when the frames changed on both attempts, keeping nothing', async () => {
		const { page, shots, listening } = fakePage(['main', 'child'], { changes: 2 });
		const failure = await maskedScreenshot(page, 1000).catch((err: unknown) => err);
		expect(failure).toBeInstanceOf(BrokerError);
		expect(failure).toMatchObject({
			status: 409,
			code: FRAMES_CHANGED_CODE,
			message: FRAMES_CHANGED,
		});
		expect(shots).toHaveLength(2);
		expect(listening()).toBe(0);
		// A detach that fails the screenshot counts as a change too.
		const mixed = fakePage(['main', 'child'], { failures: 1, changes: 1 });
		await expect(maskedScreenshot(mixed.page, 1000)).rejects.toThrow(FRAMES_CHANGED);
		expect(mixed.shots).toHaveLength(2);
	});

	test("any other failure is the capture's", async () => {
		const { page, shots, listening } = fakePage(['main']);
		page.screenshot = async () => {
			shots.push([]);
			throw new Error('page.screenshot: Timeout 1000ms exceeded');
		};
		await expect(maskedScreenshot(page, 1000)).rejects.toThrow('Timeout');
		expect(shots).toHaveLength(1);
		expect(listening()).toBe(0);
	});
});

// A browser as the broker starts on one: a CDP session that answers everything,
// and a disconnect the test can set off. browser.close() disconnects too, as
// Playwright's does.
function fakeBrowser() {
	const listeners = new Set<() => void>();
	let connected = true;
	const session = { on: () => session, send: async () => ({}) };
	const disconnect = () => {
		connected = false;
		for (const listener of listeners) listener();
	};
	const browser = {
		on: (event: string, listener: () => void) => {
			if (event === 'disconnected') listeners.add(listener);
			return browser;
		},
		isConnected: () => connected,
		newBrowserCDPSession: async () => session,
		version: () => '142.0.7444.52',
		close: async () => disconnect(),
		newContext: async () => {
			throw new Error('a failed broker opened a context');
		},
	};
	return { browser: browser as unknown as Browser, disconnect };
}

// The guard's DevTools connection: every command gets an empty result, and the
// test can close it from Chromium's side.
function fakeCdpSocket(): CdpSocket {
	const socket: CdpSocket = {
		onmessage: undefined,
		onclose: undefined,
		send(text) {
			const { id } = JSON.parse(text) as { id: number };
			queueMicrotask(() => socket.onmessage?.(JSON.stringify({ id, result: {} })));
		},
		close() {
			socket.onclose?.();
		},
	};
	return socket;
}

describe('a broker that loses its browser or its guard', () => {
	const origin = parseOrigin('http://app.abcdefghijklmnop0123.invalid:8080');

	async function started(chromium = fakeBrowser(), socket = fakeCdpSocket()) {
		const events = new EventLog(100);
		const captures = new CaptureStore({ perCapture: 1024, total: 1024 });
		const broker = await Broker.attach(
			chromium.browser,
			new CdpClient(socket),
			{ host: '127.0.0.1', port: 9222, path: '/devtools/browser/x' },
			{ runId: 'r1', origin, captures, events, home: '/tmp/none', browserEnv: {} },
		);
		const health = () =>
			healthReply(broker, undefined, {
				runId: 'r1',
				origin,
				captures,
				events,
				playwright: '1.64.1',
			});
		const failures = () => events.page(0, 100).events.filter((e) => e.type === 'recorder-failed');
		return { broker, chromium, socket, events, health, failures };
	}

	test('answers healthy while both are there', async () => {
		const t = await started();
		expect(t.broker.failure).toBeUndefined();
		expect(t.failures()).toEqual([]);
		expect(t.health()).toEqual({
			status: 200,
			body: {
				ok: true,
				runId: 'r1',
				origin: 'http://app.abcdefghijklmnop0123.invalid:8080',
				browser: { name: 'chromium', version: '142.0.7444.52' },
				playwright: '1.64.1',
				contexts: 0,
				captures: { count: 0, bytes: 0 },
				events: { next: 1, dropped: 0 },
			},
		});
	});

	test('a browser that disconnects fails the broker, emits recorder-failed and answers 503', async () => {
		const t = await started();
		t.chromium.disconnect();
		const reason = 'the recorder failed: the browser disconnected';
		expect(t.broker.failure).toBe(reason);
		expect(t.failures()).toMatchObject([{ type: 'recorder-failed', reason }]);
		expect(t.health()).toEqual({ status: 503, body: { ok: false, reason } });
	});

	test('a guard connection that closes fails the broker, emits recorder-failed and answers 503', async () => {
		const t = await started();
		t.socket.onclose?.();
		const reason = "the recorder failed: the origin guard's DevTools connection closed";
		expect(t.broker.failure).toBe(reason);
		expect(t.failures()).toMatchObject([{ type: 'recorder-failed', reason }]);
		expect(t.health()).toEqual({ status: 503, body: { ok: false, reason } });
	});

	test('a browser that dies takes the guard with it, and the run hears of it once', async () => {
		const t = await started();
		t.chromium.disconnect();
		t.socket.onclose?.();
		expect(t.failures()).toHaveLength(1);
		expect(t.broker.failure).toBe('the recorder failed: the browser disconnected');
	});

	test('a connection lost before the broker watched it still counts', async () => {
		const closedWhileStarting = fakeCdpSocket();
		const chromium = fakeBrowser();
		const newSession = chromium.browser.newBrowserCDPSession.bind(chromium.browser);
		chromium.browser.newBrowserCDPSession = async () => {
			const session = await newSession();
			closedWhileStarting.onclose?.();
			return session;
		};
		const t = await started(chromium, closedWhileStarting);
		expect(t.failures()).toHaveLength(1);
		expect(t.health().status).toBe(503);
	});

	test('a failed broker refuses a new context', async () => {
		const t = await started();
		t.socket.onclose?.();
		await expect(t.broker.openContext({ pointId: 'hello.home', attempt: 1 })).rejects.toMatchObject(
			{
				status: 503,
				code: 'recorder_failed',
				message: "the recorder failed: the origin guard's DevTools connection closed",
			},
		);
	});

	test('a close the recorder asked for is no failure', async () => {
		const t = await started();
		await t.broker.close();
		expect(t.broker.failure).toBeUndefined();
		expect(t.failures()).toEqual([]);
	});
});

describe('healthReply before a broker exists', () => {
	const facts = {
		runId: 'r1',
		origin: parseOrigin('http://app.abcdefghijklmnop0123.invalid:8080'),
		captures: { stats: () => ({ count: 0, bytes: 0 }) },
		events: { next: 1, dropped: 0 },
		playwright: '1.64.1',
	};

	test('says it is starting, or why the browser did not start', () => {
		expect(healthReply(undefined, undefined, facts)).toEqual({
			status: 503,
			body: { ok: false, reason: 'starting' },
		});
		expect(healthReply(undefined, 'the browser did not start: sandbox', facts)).toEqual({
			status: 503,
			body: { ok: false, reason: 'the browser did not start: sandbox' },
		});
	});
});

// A WebSocket route as the handler reads it: the URL Chromium reports, and
// what the handler did with it.
function fakeRoute(url: string) {
	const did: string[] = [];
	const ws: Pick<WebSocketRoute, 'url' | 'connectToServer' | 'close'> = {
		url: () => url,
		connectToServer: () => {
			did.push('connect');
			return ws as unknown as ReturnType<WebSocketRoute['connectToServer']>;
		},
		close: async (o) => {
			did.push(`close ${o?.code ?? ''} ${o?.reason ?? ''}`);
		},
	};
	return { ws, did };
}

describe('routeWebSocket', () => {
	const origin = parseOrigin('http://app.abcdefghijklmnop0123.invalid:8080');

	test.each([
		// What a headless Chromium reports for a socket the page opened to
		// its own origin: a ws: URL, never http:.
		['ws://app.abcdefghijklmnop0123.invalid:8080/socket', true],
		['ws://app.abcdefghijklmnop0123.invalid:8080/', true],
		['wss://app.abcdefghijklmnop0123.invalid:8080/socket', false],
		['ws://app.abcdefghijklmnop0123.invalid:8081/socket', false],
		['ws://app.abcdefghijklmnop0123.invalid/socket', false],
		['ws://example.com/socket', false],
		['ws://10.213.0.2:8080/socket', false],
		['http://app.abcdefghijklmnop0123.invalid:8080/socket', true],
	])('%s -> %p', (url, allowed) => {
		const events = new EventLog(10);
		const { ws, did } = fakeRoute(url);
		expect(routeWebSocket(ws, origin, events, 'x1')).toBe(allowed);
		expect(did).toEqual(allowed ? ['connect'] : ['close 1008 outside the app origin']);
		const [event] = events.page(0, 1).events;
		expect(event).toMatchObject(
			allowed
				? { type: 'websocket', contextId: 'x1', url }
				: { type: 'denied', contextId: 'x1', what: 'websocket', url },
		);
	});

	test('the app on port 80 passes whether Chromium wrote the port or not', () => {
		// Chromium drops a written default port: a page that opened
		// ws://app.x.invalid:80/x reports ws://app.x.invalid/x. Both forms
		// are compared as the canonical origin.
		for (const written of ['http://app.x.invalid', 'http://app.x.invalid:80']) {
			const plain = parseOrigin(written);
			for (const url of ['ws://app.x.invalid/socket', 'ws://app.x.invalid:80/socket']) {
				const { ws, did } = fakeRoute(url);
				expect(routeWebSocket(ws, plain, new EventLog(10), 'x1')).toBe(true);
				expect(did).toEqual(['connect']);
			}
			const { ws, did } = fakeRoute('ws://app.x.invalid:8080/socket');
			expect(routeWebSocket(ws, plain, new EventLog(10), 'x1')).toBe(false);
			expect(did).toEqual(['close 1008 outside the app origin']);
		}
	});
});
