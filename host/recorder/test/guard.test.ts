import { describe, expect, test } from 'bun:test';
import { CdpClient, type CdpSocket } from '../src/cdp.ts';
import { EventLog } from '../src/events.ts';
import { OriginGuard } from '../src/guard.ts';
import { parseOrigin } from '../src/origin.ts';

const APP = 'http://app.abcdefghijklmnop0123.invalid:8080';
const origin = parseOrigin(APP);

// Chromium's side of a DevTools connection, in memory: every command gets
// an empty result (or the error the test set for its method), and the test
// emits events into the client.
function fakeChromium() {
	const sent: Array<{ method: string; params: Record<string, unknown>; sessionId?: string }> = [];
	const errors = new Map<string, string>();
	const socket: CdpSocket = {
		onmessage: undefined,
		onclose: undefined,
		send(text) {
			const message = JSON.parse(text) as {
				id: number;
				method: string;
				params: Record<string, unknown>;
				sessionId?: string;
			};
			sent.push({
				method: message.method,
				params: message.params,
				...(message.sessionId !== undefined ? { sessionId: message.sessionId } : {}),
			});
			const error = errors.get(message.method);
			queueMicrotask(() =>
				socket.onmessage?.(
					JSON.stringify(
						error === undefined
							? { id: message.id, result: {} }
							: { id: message.id, error: { message: error } },
					),
				),
			);
		},
		close() {
			socket.onclose?.();
		},
	};
	return {
		socket,
		sent,
		errors,
		emit(method: string, params: Record<string, unknown>, sessionId?: string) {
			socket.onmessage?.(JSON.stringify({ method, params, ...(sessionId ? { sessionId } : {}) }));
		},
		// Commands sent on one session, by method, with their params.
		on(sessionId: string) {
			return sent.filter((s) => s.sessionId === sessionId).map((s) => [s.method, s.params]);
		},
	};
}

async function settle(): Promise<void> {
	for (let i = 0; i < 10; i++) await new Promise((resolve) => setTimeout(resolve, 0));
}

async function started() {
	const chromium = fakeChromium();
	const events = new EventLog(100);
	const guard = await OriginGuard.start(new CdpClient(chromium.socket), origin, events);
	return { chromium, events, guard };
}

const attach = (sessionId: string, type = 'page') => ({
	sessionId,
	targetInfo: { targetId: `T-${sessionId}`, type, url: 'about:blank', browserContextId: 'C' },
	waitingForDebugger: true,
});

const paused = (requestId: string, url: string, more: Record<string, unknown> = {}) => ({
	requestId,
	request: { url, method: 'GET' },
	resourceType: 'Document',
	frameId: 'F',
	...more,
});

describe('OriginGuard', () => {
	test('attaches to every target and enables Fetch before letting it run', async () => {
		const t = await started();
		expect(t.chromium.sent[0]).toEqual({
			method: 'Target.setAutoAttach',
			params: { autoAttach: true, waitForDebuggerOnStart: true, flatten: true },
		});
		t.chromium.emit('Target.attachedToTarget', attach('S1'));
		await settle();
		expect(t.chromium.on('S1')).toEqual([
			['Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] }],
			['Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }],
			['Runtime.runIfWaitingForDebugger', {}],
		]);
		expect(t.guard.sessionCount).toBe(1);
		// A worker attached through the page is guarded the same way.
		t.chromium.emit('Target.attachedToTarget', attach('S2', 'worker'), 'S1');
		await settle();
		expect(t.chromium.on('S2').map(([m]) => m)).toEqual([
			'Fetch.enable',
			'Target.setAutoAttach',
			'Runtime.runIfWaitingForDebugger',
		]);
		expect(t.guard.sessionCount).toBe(2);
		t.chromium.emit('Target.detachedFromTarget', { sessionId: 'S2', targetId: 'T-S2' });
		expect(t.guard.sessionCount).toBe(1);
	});

	test('continues a request on the app origin and fails every other, redirects included', async () => {
		const t = await started();
		t.chromium.emit('Target.attachedToTarget', attach('S1'));
		await settle();
		const before = t.chromium.sent.length;
		t.chromium.emit('Fetch.requestPaused', paused('R1', `${APP}/login`), 'S1');
		// The app answered with a redirect to an IP literal, then one to
		// loopback: the pinned Playwright's routes never see these, the
		// guard does.
		t.chromium.emit(
			'Fetch.requestPaused',
			paused('R2', 'http://10.213.0.1/', { redirectedRequestId: 'R1' }),
			'S1',
		);
		t.chromium.emit(
			'Fetch.requestPaused',
			paused('R3', 'http://127.0.0.1:4318/health', { redirectedRequestId: 'R1' }),
			'S1',
		);
		t.chromium.emit('Fetch.requestPaused', paused('R4', 'https://example.com/'), 'S1');
		t.chromium.emit('Fetch.requestPaused', paused('R5', `${APP}/api?x=1`), 'S1');
		await settle();
		expect(t.chromium.sent.slice(before)).toEqual([
			{ method: 'Fetch.continueRequest', params: { requestId: 'R1' }, sessionId: 'S1' },
			{
				method: 'Fetch.failRequest',
				params: { requestId: 'R2', errorReason: 'BlockedByClient' },
				sessionId: 'S1',
			},
			{
				method: 'Fetch.failRequest',
				params: { requestId: 'R3', errorReason: 'BlockedByClient' },
				sessionId: 'S1',
			},
			{
				method: 'Fetch.failRequest',
				params: { requestId: 'R4', errorReason: 'BlockedByClient' },
				sessionId: 'S1',
			},
			{ method: 'Fetch.continueRequest', params: { requestId: 'R5' }, sessionId: 'S1' },
		]);
		expect(t.events.page(0, 100).events.map((e) => [e.type, e.what, e.url])).toEqual([
			['denied', 'redirect', 'http://10.213.0.1/'],
			['denied', 'redirect', 'http://127.0.0.1:4318/health'],
			['denied', 'request', 'https://example.com/'],
		]);
		expect(t.events.page(0, 100).events[0]).toMatchObject({
			method: 'GET',
			resourceType: 'Document',
			reason: 'outside the app origin',
		});
	});

	test('a request paused without a session is left to the proxy layer', async () => {
		const t = await started();
		const before = t.chromium.sent.length;
		t.chromium.emit('Fetch.requestPaused', paused('R1', 'http://example.com/'));
		await settle();
		expect(t.chromium.sent.length).toBe(before);
	});

	test('a target Fetch cannot be enabled on still runs, and the feed says so', async () => {
		const t = await started();
		t.chromium.errors.set('Fetch.enable', 'Fetch is not supported on this target');
		t.chromium.emit('Target.attachedToTarget', attach('S1', 'other'));
		await settle();
		expect(t.chromium.on('S1').map(([m]) => m)).toEqual([
			'Fetch.enable',
			'Target.setAutoAttach',
			'Runtime.runIfWaitingForDebugger',
		]);
		expect(t.guard.sessionCount).toBe(0);
		expect(t.events.page(0, 100).events[0]).toMatchObject({
			type: 'guard-unavailable',
			targetType: 'other',
			error: 'Fetch.enable: Fetch is not supported on this target',
		});
	});

	test('closing the guard closes its connection', async () => {
		const t = await started();
		const client = new CdpClient(fakeChromium().socket);
		const guard = await OriginGuard.start(client, origin, t.events);
		guard.close();
		expect(client.isClosed).toBe(true);
		await expect(client.send('Browser.getVersion')).rejects.toThrow('closed');
	});
});

describe('CdpClient', () => {
	test('matches replies to calls, rejects errors and delivers events with their session', async () => {
		const chromium = fakeChromium();
		const client = new CdpClient(chromium.socket);
		const seen: unknown[] = [];
		client.on((event) => seen.push(event));
		await expect(client.send('Browser.getVersion')).resolves.toEqual({});
		chromium.errors.set('Page.navigate', 'Cannot navigate to invalid URL');
		await expect(client.send('Page.navigate', { url: 'x' }, 'S1')).rejects.toThrow(
			'Page.navigate: Cannot navigate to invalid URL',
		);
		chromium.emit('Page.loadEventFired', { timestamp: 1 }, 'S1');
		chromium.emit('Target.targetCreated', { targetInfo: {} });
		chromium.socket.onmessage?.('not json');
		expect(seen).toEqual([
			{ method: 'Page.loadEventFired', params: { timestamp: 1 }, sessionId: 'S1' },
			{ method: 'Target.targetCreated', params: { targetInfo: {} } },
		]);
		const pending = client.send('Runtime.evaluate');
		chromium.socket.onclose?.();
		await expect(pending).rejects.toThrow('the connection closed');
	});

	test('tells a listener once when the connection ends, whichever side ended it', () => {
		for (const end of [
			(client: CdpClient) => client.close(),
			(_client: CdpClient, socket: CdpSocket) => socket.onclose?.(),
		]) {
			const chromium = fakeChromium();
			const client = new CdpClient(chromium.socket);
			let calls = 0;
			client.onClosed(() => {
				calls += 1;
			});
			expect(calls).toBe(0);
			end(client, chromium.socket);
			chromium.socket.onclose?.();
			expect(calls).toBe(1);
		}
	});

	test('tells a listener at once when the connection has ended already', () => {
		const chromium = fakeChromium();
		const client = new CdpClient(chromium.socket);
		chromium.socket.onclose?.();
		let calls = 0;
		client.onClosed(() => {
			calls += 1;
		});
		expect(calls).toBe(1);
	});

	test("a guard reports its connection's end", async () => {
		const t = await started();
		let lost = false;
		t.guard.onClosed(() => {
			lost = true;
		});
		t.chromium.socket.onclose?.();
		expect(lost).toBe(true);
	});
});
