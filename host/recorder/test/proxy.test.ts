import { describe, expect, test } from 'bun:test';
import { type AddressInfo, createServer, type Socket } from 'node:net';
import {
	ALLOWED_METHODS,
	inspectMessage,
	METHOD_NOT_FOUND,
	REWRITTEN_METHODS,
} from '../src/cdp-allowlist.ts';
import { EventLog } from '../src/events.ts';
import { parseOrigin } from '../src/origin.ts';
import { InboundSessionReader, parseHandshake, pathHasToken, startProxy } from '../src/proxy.ts';
import { acceptKey, FrameParser, OPCODE, textFrame } from '../src/ws.ts';

const TOKEN = 'a1'.repeat(16);
const RUN_CONTEXT = 'C0FFEE0123456789';
const origin = parseOrigin('http://app.abcdefghijklmnop0123.invalid:8080');
const options = { ownsContext: (id: string) => id === RUN_CONTEXT, origin };

// Waits for `done`, for up to two seconds.
async function until(done: () => boolean): Promise<void> {
	const deadline = Date.now() + 2000;
	while (!done()) {
		if (Date.now() > deadline) throw new Error('timed out waiting');
		await Bun.sleep(5);
	}
}

// A stand-in for Chromium's DevTools endpoint: a WebSocket server on
// loopback that records the path each client connected to, echoes every
// text message it gets, and closes when told to. It refuses an unmasked
// frame as Chromium does.
async function fakeBrowser() {
	const received: string[] = [];
	const paths: string[] = [];
	let client: Socket | undefined;
	const server = createServer((socket) => {
		client = socket;
		let head = Buffer.alloc(0);
		let upgraded = false;
		const parser = new FrameParser();
		socket.on('data', (chunk: Buffer) => {
			let data: Buffer = chunk;
			if (!upgraded) {
				head = Buffer.concat([head, chunk]);
				const end = head.indexOf('\r\n\r\n');
				if (end < 0) return;
				const text = head.subarray(0, end).toString('latin1');
				paths.push(text.split(' ')[1] ?? '');
				const key = /sec-websocket-key: (.+)/i.exec(text)?.[1]?.trim() ?? '';
				socket.write(
					`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`,
				);
				upgraded = true;
				data = head.subarray(end + 4);
				if (data.length === 0) return;
			}
			for (const frame of parser.push(data)) {
				if (((frame.raw[1] ?? 0) & 0x80) === 0) {
					socket.destroy();
					return;
				}
				if (frame.opcode === OPCODE.text) {
					const message = new TextDecoder().decode(frame.payload);
					received.push(message);
					socket.write(textFrame(`echo:${message}`));
				} else if (frame.opcode === OPCODE.close) {
					socket.end();
				}
			}
		});
		socket.on('error', () => {});
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as AddressInfo).port,
		received,
		paths,
		// Pushes one text frame to the connected client, as Chromium would
		// send an event; used to announce an attached session.
		announce: (text: string) => client?.write(textFrame(text)),
		// Pushes bytes as they are: part of a frame, to split one across
		// chunks.
		raw: (bytes: Uint8Array) => client?.write(bytes),
		close: () => server.close(),
	};
}

// The attach event Chromium sends when it hands a client a session, with
// the keys in Chromium's order: method, params, then the parent session
// when the attach happened under one.
function attached(sessionId: string, extra: { url?: string; parent?: string } = {}): string {
	return JSON.stringify({
		method: 'Target.attachedToTarget',
		params: {
			sessionId,
			targetInfo: { targetId: `T-${sessionId}`, type: 'page', url: extra.url ?? 'about:blank' },
			waitingForDebugger: false,
		},
		...(extra.parent !== undefined ? { sessionId: extra.parent } : {}),
	});
}

function detached(sessionId: string): string {
	return JSON.stringify({
		method: 'Target.detachedFromTarget',
		params: { sessionId, targetId: `T-${sessionId}` },
	});
}

// A client of the proxy. Every message with an id is kept, parsed, with
// the fake browser's echo prefix removed: a reply the proxy wrote itself
// has `error`, an echo of a relayed message has `method`.
async function connectClient(port: number) {
	const ws = new WebSocket(`ws://127.0.0.1:${port}/${TOKEN}`);
	const replies: Record<string, unknown>[] = [];
	ws.onmessage = (event) => {
		const data = String(event.data);
		try {
			const parsed = JSON.parse(data.startsWith('echo:') ? data.slice(5) : data);
			if (typeof parsed.id === 'number') replies.push(parsed);
		} catch {
			/* an event, not a reply */
		}
	};
	await new Promise<void>((resolve, reject) => {
		ws.onopen = () => resolve();
		ws.onerror = () => reject(new Error('the connection failed'));
	});
	const reply = async (id: number) => {
		await until(() => replies.some((r) => r.id === id));
		return replies.find((r) => r.id === id);
	};
	return { ws, replies, reply };
}

async function proxyFor(browserPort: number | undefined, events: EventLog) {
	const server = await startProxy({
		port: 0,
		token: TOKEN,
		upstream: () =>
			browserPort === undefined
				? undefined
				: { host: '127.0.0.1', port: browserPort, path: '/devtools/browser/abc' },
		...options,
		events,
		maxClients: 2,
	});
	return { server, port: (server.address() as AddressInfo).port };
}

describe('parseHandshake', () => {
	test('reads the request line and lower-cases header names', () => {
		const request = parseHandshake(
			'GET /abc HTTP/1.1\r\nHost: x\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key: k==\r\n',
		);
		expect(request?.method).toBe('GET');
		expect(request?.path).toBe('/abc');
		expect(request?.headers.get('upgrade')).toBe('WebSocket');
		expect(request?.headers.get('sec-websocket-key')).toBe('k==');
		expect(parseHandshake('nonsense')).toBeUndefined();
		expect(parseHandshake('GET / HTTP/1.1\r\nbroken header\r\n')).toBeUndefined();
	});

	test('the token is the whole path, compared exactly', () => {
		expect(pathHasToken(`/${TOKEN}`, TOKEN)).toBe(true);
		expect(pathHasToken(`/${TOKEN}/`, TOKEN)).toBe(false);
		expect(pathHasToken(`/${TOKEN}?x=1`, TOKEN)).toBe(false);
		expect(pathHasToken('/', TOKEN)).toBe(false);
		expect(pathHasToken(`/${'b2'.repeat(16)}`, TOKEN)).toBe(false);
	});
});

describe('the allowlist', () => {
	const message = (method: string, params: Record<string, unknown> = {}, more = {}) =>
		JSON.stringify({ id: 7, method, params, ...more });

	test('forwards an allowed method as it came, with or without a session', () => {
		const plain = message('Page.navigate', {
			url: 'http://app.abcdefghijklmnop0123.invalid:8080/',
		});
		expect(inspectMessage(plain, options)).toEqual({
			id: 7,
			method: 'Page.navigate',
			forward: plain,
		});
		const nested = message('Runtime.evaluate', { expression: '1' }, { sessionId: 'S1' });
		expect(inspectMessage(nested, options).forward).toBe(nested);
		for (const method of ALLOWED_METHODS) {
			// These check a param (a context id, a URL, a cookie origin) that
			// an empty-param message does not carry; they have their own tests.
			if (
				method === 'Target.createTarget' ||
				method === 'Page.navigate' ||
				method.startsWith('Network.setCookie')
			) {
				continue;
			}
			expect(inspectMessage(message(method), options).forward).toBeDefined();
		}
	});

	test('a navigation goes only to http: or about:blank', () => {
		const app = 'http://app.abcdefghijklmnop0123.invalid:8080/';
		for (const url of [app, 'http://app.abcdefghijklmnop0123.invalid:8080/x?y=1', 'about:blank']) {
			const m = message('Page.navigate', { url });
			expect(inspectMessage(m, options).forward).toBe(m);
		}
		// Off-origin http passes the scheme check here; the origin guard fails
		// the request. Every non-http, non-about:blank scheme is refused.
		expect(
			inspectMessage(message('Page.navigate', { url: 'http://example.com/' }), options).forward,
		).toBeDefined();
		for (const url of [
			'javascript:alert(1)',
			'data:text/html,<p>x</p>',
			'blob:http://app.abcdefghijklmnop0123.invalid:8080/0a',
			'file:///etc/hostname',
			'chrome://version',
			'about:srcdoc',
			'ws://app.abcdefghijklmnop0123.invalid:8080/',
			'https://app.abcdefghijklmnop0123.invalid:8080/',
		]) {
			expect(inspectMessage(message('Page.navigate', { url }), options).denied).toBe(
				'Page.navigate to a non-navigable URL',
			);
		}
		expect(inspectMessage(message('Page.navigate', {}), options).denied).toBe(
			'Page.navigate to a non-navigable URL',
		);
	});

	test('a created target must be in the run context and at a navigable URL', () => {
		const good = message('Target.createTarget', {
			url: 'about:blank',
			browserContextId: RUN_CONTEXT,
		});
		expect(inspectMessage(good, options).forward).toBe(good);
		expect(
			inspectMessage(
				message('Target.createTarget', { url: 'javascript:1', browserContextId: RUN_CONTEXT }),
				options,
			).denied,
		).toBe('Target.createTarget to a non-navigable URL');
	});

	test('drag events and closing a page, by target or by Page.close, are refused', () => {
		expect(ALLOWED_METHODS.has('Input.dispatchDragEvent')).toBe(false);
		expect(ALLOWED_METHODS.has('Target.closeTarget')).toBe(false);
		expect(ALLOWED_METHODS.has('Page.close')).toBe(false);
		expect(
			inspectMessage(message('Input.dispatchDragEvent', { type: 'drop' }), options).denied,
		).toBe('Input.dispatchDragEvent is not permitted');
		expect(inspectMessage(message('Target.closeTarget', { targetId: 'T' }), options).denied).toBe(
			'Target.closeTarget is not permitted',
		);
		// The pinned client sends Page.close on the page's session for
		// page.close({ runBeforeUnload: true }).
		expect(inspectMessage(message('Page.close', {}, { sessionId: 'S1' }), options)).toEqual({
			id: 7,
			sessionId: 'S1',
			method: 'Page.close',
			denied: 'Page.close is not permitted',
		});
	});

	test('a sessionId the relay never handed out is refused, before the method', () => {
		const known = (id: string) => id === 'S-known';
		const bound = { ...options, knownSession: known };
		const good = message('Runtime.evaluate', { expression: '1' }, { sessionId: 'S-known' });
		expect(inspectMessage(good, bound).forward).toBe(good);
		// Unknown session: refused whatever the method, allowed or not.
		for (const method of ['Runtime.evaluate', 'Page.captureScreenshot', 'Tracing.start']) {
			expect(inspectMessage(message(method, {}, { sessionId: 'S-forged' }), bound).denied).toBe(
				`${method} for an unknown session`,
			);
		}
		// A browser-level message (no sessionId) is unaffected by the binding.
		expect(inspectMessage(message('Browser.getVersion'), bound).forward).toBeDefined();
		// Without the predicate (unit tests of the method policy), any session
		// is accepted.
		expect(inspectMessage(good, options).forward).toBe(good);
	});

	test('the Runtime rules: the session is checked, an objectId is left to Chromium', () => {
		const bound = { ...options, knownSession: (id: string) => id === 'S-known' };
		const runtime = [...ALLOWED_METHODS].filter((m) => m.startsWith('Runtime.'));
		expect(runtime).toEqual(
			expect.arrayContaining([
				'Runtime.evaluate',
				'Runtime.callFunctionOn',
				'Runtime.getProperties',
				'Runtime.releaseObject',
				'Runtime.releaseObjectGroup',
			]),
		);
		// An objectId is a handle in a session's own object table, and the
		// proxy does not read it: a handle minted elsewhere is forwarded as
		// it is, and Chromium resolves it within the session it arrives on.
		// What the proxy checks is the session the message names.
		const params = {
			objectId: '{"injectedScriptId":2,"id":1}',
			functionDeclaration: 'function () { return 1; }',
		};
		for (const method of runtime) {
			const known = message(method, params, { sessionId: 'S-known' });
			expect(inspectMessage(known, bound)).toEqual({
				id: 7,
				sessionId: 'S-known',
				method,
				forward: known,
			});
			expect(inspectMessage(message(method, params, { sessionId: 'S-other' }), bound)).toEqual({
				id: 7,
				sessionId: 'S-other',
				method,
				denied: `${method} for an unknown session`,
			});
		}
		// Script in the page is allowed by design: any expression goes through.
		const script = message(
			'Runtime.evaluate',
			{ expression: 'document.body.innerHTML = "authored"' },
			{ sessionId: 'S-known' },
		);
		expect(inspectMessage(script, bound).forward).toBe(script);
	});

	test.each([
		'Tracing.start',
		'Tracing.end',
		'Browser.close',
		'Browser.crash',
		'Browser.crashGpuProcess',
		'Browser.grantPermissions',
		'Target.createBrowserContext',
		'Target.disposeBrowserContext',
		'Target.exposeDevToolsProtocol',
		'Target.sendMessageToTarget',
		'Target.setDiscoverTargets',
		'Target.getTargets',
		'DOM.setFileInputFiles',
		'Input.dispatchDragEvent',
		'Target.closeTarget',
		'Page.close',
		'Page.setInterceptFileChooserDialog',
		'Page.printToPDF',
		'Page.startScreencast',
		'Page.setBypassCSP',
		'IO.read',
		'IO.close',
		'Storage.getCookies',
		'Storage.setCookies',
		'Storage.clearCookies',
		'Network.setRequestInterception',
		'Network.getCookies',
		'Network.getAllCookies',
		'Network.loadNetworkResource',
		'Fetch.enable',
		'Fetch.continueRequest',
		'Fetch.fulfillRequest',
		'Security.setIgnoreCertificateErrors',
		'Debugger.enable',
		'Profiler.enable',
		'HeapProfiler.collectGarbage',
		'Made.up',
	])('denies %s', (method) => {
		expect(inspectMessage(message(method), options)).toEqual({
			id: 7,
			method,
			denied: `${method} is not permitted`,
		});
		// Nested in an attached session, the same method is denied the same
		// way: the sessionId changes nothing.
		expect(inspectMessage(message(method, {}, { sessionId: 'S1' }), options).denied).toBe(
			`${method} is not permitted`,
		);
	});

	test('a wrapped message for a target is refused whatever it carries', () => {
		const wrapped = message('Target.sendMessageToTarget', {
			sessionId: 'S1',
			message: JSON.stringify({ id: 1, method: 'Page.navigate', params: {} }),
		});
		expect(inspectMessage(wrapped, options).denied).toBe(
			'Target.sendMessageToTarget is not permitted',
		);
	});

	test('attaching is rewritten to flattened sessions', () => {
		for (const method of ['Target.attachToTarget', 'Target.setAutoAttach']) {
			const verdict = inspectMessage(
				message(method, { targetId: 'T1', autoAttach: true, flatten: false }),
				options,
			);
			expect(verdict.rewritten).toBe(method);
			expect(JSON.parse(verdict.forward ?? '')).toEqual({
				id: 7,
				method,
				params: { targetId: 'T1', autoAttach: true, flatten: true },
			});
		}
		expect(REWRITTEN_METHODS.has('Target.attachToTarget')).toBe(true);
		// A session on the browser target, which the client's newCDPSession
		// opens first, goes through as it is; it names nothing.
		const toBrowser = message('Target.attachToBrowserTarget');
		expect(inspectMessage(toBrowser, options).forward).toBe(toBrowser);
	});

	test('download behaviour is forwarded only as a denial', () => {
		const sent = message('Browser.setDownloadBehavior', {
			behavior: 'allowAndName',
			browserContextId: RUN_CONTEXT,
			downloadPath: '/tmp/x',
			eventsEnabled: true,
		});
		const verdict = inspectMessage(sent, options);
		expect(verdict.rewritten).toBe('Browser.setDownloadBehavior');
		expect(JSON.parse(verdict.forward ?? '')).toEqual({
			id: 7,
			method: 'Browser.setDownloadBehavior',
			params: { behavior: 'deny', browserContextId: RUN_CONTEXT, eventsEnabled: true },
		});
		const page = inspectMessage(
			message(
				'Page.setDownloadBehavior',
				{ behavior: 'allow', downloadPath: '/x' },
				{ sessionId: 'S' },
			),
			options,
		);
		expect(JSON.parse(page.forward ?? '')).toMatchObject({
			sessionId: 'S',
			params: { behavior: 'deny' },
		});
	});

	test('a target may be created in the run context only', () => {
		const own = message('Target.createTarget', {
			url: 'about:blank',
			browserContextId: RUN_CONTEXT,
		});
		expect(inspectMessage(own, options).forward).toBe(own);
		for (const params of [
			{ url: 'about:blank' },
			{ url: 'about:blank', browserContextId: 'DEADBEEF' },
			{ url: 'about:blank', browserContextId: 7 },
		]) {
			expect(inspectMessage(message('Target.createTarget', params), options).denied).toBe(
				'Target.createTarget outside the run context',
			);
		}
	});

	test('cookies may be set for the app origin only', () => {
		const app = 'http://app.abcdefghijklmnop0123.invalid:8080/';
		const good = message('Network.setCookies', {
			cookies: [
				{ name: 'a', value: '1', url: app },
				{ name: 'b', value: '2', domain: 'app.abcdefghijklmnop0123.invalid' },
				{ name: 'c', value: '3', domain: '.app.abcdefghijklmnop0123.invalid' },
			],
		});
		expect(inspectMessage(good, options).forward).toBe(good);
		const single = message('Network.setCookie', { name: 'a', value: '1', url: app });
		expect(inspectMessage(single, options).forward).toBe(single);
		for (const cookie of [
			{ name: 'x', value: '1', url: 'http://example.com/' },
			{ name: 'x', value: '1', domain: 'example.com' },
			{ name: 'x', value: '1', url: 'http://app.abcdefghijklmnop0123.invalid:8081/' },
			{ name: 'x', value: '1', url: app, domain: 'example.com' },
			{ name: 'x', value: '1' },
		]) {
			expect(
				inspectMessage(message('Network.setCookies', { cookies: [cookie] }), options).denied,
			).toBe('Network.setCookies for another origin');
			expect(inspectMessage(message('Network.setCookie', cookie), options).denied).toBe(
				'Network.setCookie for another origin',
			);
		}
	});

	test('what is not a DevTools command is refused', () => {
		expect(inspectMessage('not json', options)).toEqual({ denied: 'not a JSON message' });
		expect(inspectMessage('[1,2]', options)).toEqual({ denied: 'not a DevTools message' });
		expect(inspectMessage('{"id":3}', options)).toEqual({ id: 3, denied: 'no method' });
		expect(inspectMessage('{"id":3,"method":7}', options)).toEqual({ id: 3, denied: 'no method' });
		expect(inspectMessage('', options).denied).toBe('not a JSON message');
	});

	test('nothing that widens the boundary is on the list', () => {
		for (const method of ALLOWED_METHODS) {
			expect(method).not.toMatch(/^(Tracing|IO|Fetch|Storage|Debugger|Profiler|HeapProfiler)\./);
			expect(method).not.toMatch(/FileInput|Download|BrowserContext|sendMessageToTarget/);
		}
		for (const method of REWRITTEN_METHODS) expect(ALLOWED_METHODS.has(method)).toBe(false);
	});
});

describe('InboundSessionReader', () => {
	const attachText = attached('S1');
	const attach = textFrame(attachText);

	test('reads a small text frame split across chunks', () => {
		const reader = new InboundSessionReader();
		const cut = Math.floor(attach.length / 2);
		expect(reader.read(attach.subarray(0, cut))).toEqual([]);
		const [text] = reader.read(attach.subarray(cut));
		expect(JSON.parse(text ?? '').params.sessionId).toBe('S1');
	});

	test('drops a large frame that is not a session event without losing the next frame', () => {
		const reader = new InboundSessionReader();
		// A screenshot-sized result arrives in pieces, then a small attach frame.
		const big = textFrame(JSON.stringify({ id: 9, result: { data: 'x'.repeat(100 * 1024) } }));
		expect(reader.read(big.subarray(0, 40_000))).toEqual([]);
		expect(reader.read(big.subarray(40_000))).toEqual([]);
		expect(reader.read(attach)).toEqual([attachText]);
	});

	test('holds a session event of any size: an attach with a long URL, in pieces', () => {
		const reader = new InboundSessionReader();
		// An allowed URL with a 70 KB fragment, as Chromium sends it: one
		// unfragmented frame with an eight-byte length, larger than the 64 KiB
		// the reader once scanned and then refused the session for.
		const url = `http://app.abcdefghijklmnop0123.invalid:8080/#${'a'.repeat(70_000)}`;
		const event = attached('S-long', { url });
		const frame = textFrame(event);
		expect(frame.length).toBeGreaterThan(65_536);
		// Cut inside the header, inside the prefix, and inside the payload.
		expect(reader.read(frame.subarray(0, 5))).toEqual([]);
		expect(reader.read(frame.subarray(5, 100))).toEqual([]);
		expect(reader.read(frame.subarray(100, 30_000))).toEqual([]);
		expect(reader.read(Buffer.concat([frame.subarray(30_000), attach]))).toEqual([
			event,
			attachText,
		]);
	});

	test('reads a detach event and an attach event nested under another session', () => {
		const reader = new InboundSessionReader();
		const detach = detached('S1');
		const nested = attached('S2', { parent: 'S1' });
		expect(reader.read(Buffer.concat([textFrame(detach), textFrame(nested)]))).toEqual([
			detach,
			nested,
		]);
	});

	test('a result that quotes an attach event in a string is not a session event', () => {
		// Inside a JSON string the quotes are escaped, so the needle does not
		// match and the frame is dropped like any other result.
		const reader = new InboundSessionReader();
		const quoted = JSON.stringify({ id: 1, result: { value: attachText } });
		expect(reader.read(textFrame(quoted))).toEqual([]);
		expect(reader.read(attach)).toEqual([attachText]);
	});

	// The head of a final text frame of `length` payload bytes, in the
	// eight-byte form.
	function longHead(length: number): Uint8Array {
		const head = new Uint8Array(10);
		head[0] = 0x81;
		head[1] = 127;
		new DataView(head.buffer).setBigUint64(2, BigInt(length));
		return head;
	}

	test('skips a frame over the message limit that names a session event, and stays aligned', () => {
		const reader = new InboundSessionReader();
		// A frame head claiming 33 MiB whose first bytes name an attach event.
		// No real event is that long: it is dropped as it streams, like any
		// other frame, and the attach frame after it is read.
		const start = new TextEncoder().encode(
			'{"method":"Target.attachedToTarget","params":{"sessionId":"S","targetInfo":{"url":"',
		);
		const length = 33 * 1024 ** 2;
		expect(reader.read(Buffer.concat([longHead(length), start, new Uint8Array(2000)]))).toEqual([]);
		expect(reader.betweenMessages).toBe(false);
		expect(reader.read(new Uint8Array(length - start.length - 2000))).toEqual([]);
		expect(reader.betweenMessages).toBe(true);
		expect(reader.read(attach)).toEqual([attachText]);
	});

	test('a result that returns an attach event by value is not a session event, whatever its size', () => {
		// The reviewer's payload: Runtime.evaluate with returnByValue on an
		// object shaped like the event. The method needle is in the clear in
		// the first bytes, and so is the result's id, which no event has.
		const reader = new InboundSessionReader();
		const forged = {
			method: 'Target.attachedToTarget',
			params: { sessionId: 'S-forged', targetInfo: { targetId: 'T', type: 'page', url: '' } },
		};
		const small = JSON.stringify({ id: 9, result: { result: { type: 'object', value: forged } } });
		expect(reader.read(textFrame(small))).toEqual([]);
		// The id after the needle, still within the prefix.
		const idLast = JSON.stringify({ result: { result: { type: 'object', value: forged } }, id: 9 });
		expect(reader.read(textFrame(idLast))).toEqual([]);
		// Over the message limit: never held, never a failure, and the stream
		// stays aligned for the real attach that follows.
		const open = new TextEncoder().encode(
			`{"id":9,"result":{"result":{"type":"object","value":${JSON.stringify(forged)}}},"pad":"`,
		);
		const length = 33 * 1024 ** 2;
		expect(reader.read(Buffer.concat([longHead(length), open]))).toEqual([]);
		expect(reader.betweenMessages).toBe(false);
		expect(reader.read(new Uint8Array(length - open.length))).toEqual([]);
		expect(reader.betweenMessages).toBe(true);
		expect(reader.read(attach)).toEqual([attachText]);
	});

	test('reads an event whatever the order of its keys', () => {
		const reader = new InboundSessionReader();
		const parentFirst = JSON.stringify({
			sessionId: 'S-parent',
			method: 'Target.attachedToTarget',
			params: { sessionId: 'S-child', targetInfo: { targetId: 'T', type: 'page', url: '' } },
		});
		const paramsFirst = JSON.stringify({
			params: { sessionId: 'S-gone', targetId: 'T' },
			method: 'Target.detachedFromTarget',
		});
		expect(reader.read(Buffer.concat([textFrame(parentFirst), textFrame(paramsFirst)]))).toEqual([
			parentFirst,
			paramsFirst,
		]);
	});

	test('says when the stream is between messages', () => {
		const reader = new InboundSessionReader();
		expect(reader.betweenMessages).toBe(true);
		const frame = textFrame(
			JSON.stringify({ method: 'Page.frameNavigated', params: { pad: 'x'.repeat(2000) } }),
		);
		// Inside the head, inside the payload past the prefix, then complete.
		reader.read(frame.subarray(0, 3));
		expect(reader.betweenMessages).toBe(false);
		reader.read(frame.subarray(3, 1500));
		expect(reader.betweenMessages).toBe(false);
		reader.read(frame.subarray(1500));
		expect(reader.betweenMessages).toBe(true);
		// A message in two frames ends with its final continuation frame.
		reader.read(new Uint8Array([0x01, 0x02, 0x7b, 0x22]));
		expect(reader.betweenMessages).toBe(false);
		reader.read(new Uint8Array([0x80, 0x02, 0x22, 0x7d]));
		expect(reader.betweenMessages).toBe(true);
	});

	test('a control frame between the fragments of a message does not end it', () => {
		const reader = new InboundSessionReader();
		// The first fragment of a text message, then a ping and a pong, each
		// a final frame of its own; the message is still open until its
		// final continuation frame.
		reader.read(new Uint8Array([0x01, 0x02, 0x7b, 0x22]));
		expect(reader.betweenMessages).toBe(false);
		reader.read(new Uint8Array([0x89, 0x00]));
		expect(reader.betweenMessages).toBe(false);
		reader.read(new Uint8Array([0x8a, 0x01, 0x41]));
		expect(reader.betweenMessages).toBe(false);
		reader.read(new Uint8Array([0x00, 0x01, 0x78]));
		expect(reader.betweenMessages).toBe(false);
		reader.read(new Uint8Array([0x80, 0x02, 0x22, 0x7d]));
		expect(reader.betweenMessages).toBe(true);
		// A ping between messages leaves the stream between messages.
		reader.read(new Uint8Array([0x89, 0x00]));
		expect(reader.betweenMessages).toBe(true);
	});

	test('does not return a binary frame', () => {
		const reader = new InboundSessionReader();
		const binary = new Uint8Array([0x82, 0x03, 1, 2, 3]); // fin, opcode 2, len 3
		expect(reader.read(binary)).toEqual([]);
		expect(reader.read(attach)).toHaveLength(1);
	});
});

describe('the browser port proxy', () => {
	test('relays allowed messages, answers denied ones itself and re-sends rewritten ones masked', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const ws = new WebSocket(`ws://127.0.0.1:${proxy.port}/${TOKEN}`);
			const messages: string[] = [];
			// The attach event the browser pushes to hand out a session is not
			// a reply; keep it out of the reply list the assertions index into.
			ws.onmessage = (event) => {
				const data = String(event.data);
				if (!data.includes('Target.attachedToTarget')) messages.push(data);
			};
			await new Promise<void>((resolve, reject) => {
				ws.onopen = () => resolve();
				ws.onerror = () => reject(new Error('the connection failed'));
			});
			// Chromium hands the client a session; the relay records it, so the
			// nested message below is checked by the method policy, not refused
			// for an unknown session.
			browser.announce(
				JSON.stringify({
					method: 'Target.attachedToTarget',
					params: {
						sessionId: 'S1',
						targetInfo: { targetId: 'T1', type: 'page', url: 'about:blank' },
					},
				}),
			);
			await Bun.sleep(50);
			const allowed = JSON.stringify({ id: 1, method: 'Browser.getVersion' });
			const denied = JSON.stringify({ id: 2, method: 'Tracing.start', params: {} });
			const nested = JSON.stringify({
				id: 3,
				sessionId: 'S1',
				method: 'Fetch.enable',
				params: { patterns: [] },
			});
			const rewritten = JSON.stringify({
				id: 4,
				method: 'Target.attachToTarget',
				params: { targetId: 'T', flatten: false },
			});
			const large = JSON.stringify({
				id: 5,
				method: 'Runtime.evaluate',
				params: { expression: 'x'.repeat(300_000) },
			});
			// One at a time: the proxy answers a denied message itself, before
			// the browser's echo of an earlier one could come back.
			for (const [i, m] of [allowed, denied, nested, rewritten, large].entries()) {
				ws.send(m);
				await until(() => messages.length === i + 1);
			}
			expect(messages[0]).toBe(`echo:${allowed}`);
			expect(JSON.parse(messages[1] ?? '')).toEqual({
				id: 2,
				error: { code: METHOD_NOT_FOUND, message: 'koi recorder: Tracing.start is not permitted' },
			});
			// A refusal on a session carries that session id, so the client
			// routes it to the session that asked.
			expect(JSON.parse(messages[2] ?? '')).toEqual({
				id: 3,
				sessionId: 'S1',
				error: { code: METHOD_NOT_FOUND, message: 'koi recorder: Fetch.enable is not permitted' },
			});
			expect(JSON.parse((messages[3] ?? '').slice('echo:'.length))).toEqual({
				id: 4,
				method: 'Target.attachToTarget',
				params: { targetId: 'T', flatten: true },
			});
			expect(messages[4]).toBe(`echo:${large}`);
			expect(browser.received).toHaveLength(3);
			expect(browser.received[0]).toBe(allowed);
			expect(browser.received[2]).toBe(large);
			expect(browser.paths).toEqual(['/devtools/browser/abc']);
			ws.close();
			await until(() => events.page(0, 100).events.some((e) => e.type === 'client-disconnected'));
			expect(events.page(0, 100).events.map((e) => [e.type, e.method, e.reason])).toEqual([
				['client-connected', undefined, undefined],
				['client-denied', 'Tracing.start', 'Tracing.start is not permitted'],
				['client-denied', 'Fetch.enable', 'Fetch.enable is not permitted'],
				['client-rewritten', 'Target.attachToTarget', undefined],
				['client-disconnected', undefined, 'client closed'],
			]);
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test('binds sessions: a message on an announced session is relayed, an unknown one is refused', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const ws = new WebSocket(`ws://127.0.0.1:${proxy.port}/${TOKEN}`);
			const replies: Record<string, unknown>[] = [];
			ws.onmessage = (event) => {
				const data = String(event.data);
				if (data.includes('Target.attachedToTarget')) return;
				try {
					replies.push(JSON.parse(data.startsWith('echo:') ? data.slice(5) : data));
				} catch {
					/* the echo of a forwarded message is not JSON we index */
				}
			};
			await new Promise<void>((resolve, reject) => {
				ws.onopen = () => resolve();
				ws.onerror = () => reject(new Error('the connection failed'));
			});
			// Before any session is announced, a sessionId-bearing message is
			// refused: the relay never handed that handle out.
			ws.send(JSON.stringify({ id: 1, sessionId: 'S9', method: 'Runtime.evaluate', params: {} }));
			await until(() => replies.some((r) => r.id === 1));
			expect(replies.find((r) => r.id === 1)).toEqual({
				id: 1,
				sessionId: 'S9',
				error: {
					code: METHOD_NOT_FOUND,
					message: 'koi recorder: Runtime.evaluate for an unknown session',
				},
			});
			// Chromium announces the session; now the same message is relayed.
			browser.announce(
				JSON.stringify({
					method: 'Target.attachedToTarget',
					params: {
						sessionId: 'S9',
						targetInfo: { targetId: 'T9', type: 'page', url: 'about:blank' },
					},
				}),
			);
			await Bun.sleep(50);
			const good = JSON.stringify({
				id: 2,
				sessionId: 'S9',
				method: 'Runtime.evaluate',
				params: {},
			});
			ws.send(good);
			await until(() => browser.received.includes(good));
			expect(browser.received).toContain(good);
			ws.close();
			await until(() => events.page(0, 100).events.some((e) => e.type === 'client-disconnected'));
			expect(
				events
					.page(0, 100)
					.events.filter((e) => e.type === 'client-denied')
					.map((e) => [e.method, e.reason]),
			).toEqual([['Runtime.evaluate', 'Runtime.evaluate for an unknown session']]);
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test('answers a refusal on the session that asked, so the client can route it', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const client = await connectClient(proxy.port);
			browser.announce(attached('S1'));
			await Bun.sleep(50);
			// The pinned client's newCDPSession path: a refused command on a
			// page session. The reply names the session, as Chromium's own
			// error replies do. Without it the client's root session would get
			// the reply and the command would never settle.
			client.ws.send(
				JSON.stringify({
					id: 1,
					sessionId: 'S1',
					method: 'Page.navigate',
					params: { url: 'javascript:void(0)' },
				}),
			);
			expect(await client.reply(1)).toEqual({
				id: 1,
				sessionId: 'S1',
				error: {
					code: METHOD_NOT_FOUND,
					message: 'koi recorder: Page.navigate to a non-navigable URL',
				},
			});
			// A browser-level refusal carries no session, like the request.
			client.ws.send(JSON.stringify({ id: 2, method: 'Target.closeTarget', params: {} }));
			expect(await client.reply(2)).toEqual({
				id: 2,
				error: {
					code: METHOD_NOT_FOUND,
					message: 'koi recorder: Target.closeTarget is not permitted',
				},
			});
			expect(browser.received).toEqual([]);
			client.ws.close();
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test('follows the newCDPSession path: a browser session, then a page session under it', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const client = await connectClient(proxy.port);
			// The pinned client attaches to the browser target first, then to
			// the page from that session. Chromium announces both; the second
			// event is nested under the first.
			const toBrowser = JSON.stringify({
				id: 1,
				method: 'Target.attachToBrowserTarget',
				params: {},
			});
			client.ws.send(toBrowser);
			await until(() => browser.received.includes(toBrowser));
			browser.announce(attached('S-browser'));
			await Bun.sleep(50);
			client.ws.send(
				JSON.stringify({
					id: 2,
					sessionId: 'S-browser',
					method: 'Target.attachToTarget',
					params: { targetId: 'T-page', flatten: true },
				}),
			);
			await until(() => browser.received.length === 2);
			expect(JSON.parse(browser.received[1] ?? '')).toMatchObject({
				id: 2,
				sessionId: 'S-browser',
				params: { targetId: 'T-page', flatten: true },
			});
			browser.announce(attached('S-page', { parent: 'S-browser' }));
			await Bun.sleep(50);
			// A refusal on the page session comes back on that session.
			client.ws.send(
				JSON.stringify({
					id: 3,
					sessionId: 'S-page',
					method: 'Page.navigate',
					params: { url: 'javascript:void(0)' },
				}),
			);
			expect(await client.reply(3)).toEqual({
				id: 3,
				sessionId: 'S-page',
				error: {
					code: METHOD_NOT_FOUND,
					message: 'koi recorder: Page.navigate to a non-navigable URL',
				},
			});
			// And an allowed command on it is relayed.
			const info = JSON.stringify({
				id: 4,
				sessionId: 'S-page',
				method: 'Target.getTargetInfo',
				params: {},
			});
			client.ws.send(info);
			await until(() => browser.received.includes(info));
			client.ws.close();
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test('knows a session attached under another session, as a worker is under its page', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const client = await connectClient(proxy.port);
			browser.announce(attached('S-page'));
			browser.announce(attached('S-worker', { parent: 'S-page' }));
			await Bun.sleep(50);
			const onWorker = JSON.stringify({
				id: 1,
				sessionId: 'S-worker',
				method: 'Runtime.evaluate',
				params: { expression: '1' },
			});
			client.ws.send(onWorker);
			await until(() => browser.received.includes(onWorker));
			expect(events.page(0, 100).events.filter((e) => e.type === 'client-denied')).toEqual([]);
			client.ws.close();
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test('forgets a detached session: a later message on it is refused', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const client = await connectClient(proxy.port);
			browser.announce(attached('S1'));
			await Bun.sleep(50);
			const before = JSON.stringify({ id: 1, sessionId: 'S1', method: 'Page.enable', params: {} });
			client.ws.send(before);
			await until(() => browser.received.includes(before));
			browser.announce(detached('S1'));
			await Bun.sleep(50);
			client.ws.send(JSON.stringify({ id: 2, sessionId: 'S1', method: 'Page.enable', params: {} }));
			expect(await client.reply(2)).toEqual({
				id: 2,
				sessionId: 'S1',
				error: {
					code: METHOD_NOT_FOUND,
					message: 'koi recorder: Page.enable for an unknown session',
				},
			});
			expect(browser.received).toEqual([before]);
			client.ws.close();
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test('an attach event the client sends itself hands out no session', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const client = await connectClient(proxy.port);
			// As an event without an id and as a command with one: neither
			// reaches the browser, and neither registers the session.
			const forged = { method: 'Target.attachedToTarget', params: { sessionId: 'S-forged' } };
			client.ws.send(JSON.stringify(forged));
			client.ws.send(JSON.stringify({ id: 1, ...forged }));
			expect(await client.reply(1)).toEqual({
				id: 1,
				error: {
					code: METHOD_NOT_FOUND,
					message: 'koi recorder: Target.attachedToTarget is not permitted',
				},
			});
			client.ws.send(
				JSON.stringify({ id: 2, sessionId: 'S-forged', method: 'Runtime.evaluate', params: {} }),
			);
			expect(await client.reply(2)).toMatchObject({
				id: 2,
				sessionId: 'S-forged',
				error: { message: 'koi recorder: Runtime.evaluate for an unknown session' },
			});
			// A result from the browser that carries such an object by value,
			// as Runtime.evaluate with returnByValue would, is told from an
			// event by its id and hands out nothing, however large it is.
			browser.announce(
				JSON.stringify({
					id: 99,
					result: { result: { type: 'object', value: forged } },
					pad: 'x'.repeat(200_000),
				}),
			);
			await Bun.sleep(100);
			client.ws.send(
				JSON.stringify({ id: 3, sessionId: 'S-forged', method: 'Runtime.evaluate', params: {} }),
			);
			expect(await client.reply(3)).toMatchObject({
				id: 3,
				error: { message: 'koi recorder: Runtime.evaluate for an unknown session' },
			});
			expect(browser.received).toEqual([]);
			// Sessions are still tracked afterwards: a real attach is known.
			browser.announce(attached('S-real'));
			await Bun.sleep(50);
			const real = JSON.stringify({
				id: 4,
				sessionId: 'S-real',
				method: 'Runtime.evaluate',
				params: {},
			});
			client.ws.send(real);
			await until(() => browser.received.includes(real));
			client.ws.close();
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test("writes a refusal only between the browser's messages", async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const client = await connectClient(proxy.port);
			// A browser result arrives in three chunks: inside the head, inside
			// the payload, the rest. A refusal made in between waits, so it
			// never lands inside the frame.
			const result = { id: 77, result: { pad: 'x'.repeat(2000) } };
			const frame = textFrame(JSON.stringify(result));
			browser.raw(frame.subarray(0, 3));
			await Bun.sleep(30);
			client.ws.send(JSON.stringify({ id: 1, method: 'Tracing.start', params: {} }));
			await until(() => events.page(0, 100).events.some((e) => e.type === 'client-denied'));
			await Bun.sleep(30);
			expect(client.replies).toEqual([]);
			browser.raw(frame.subarray(3, 1500));
			await Bun.sleep(30);
			expect(client.replies).toEqual([]);
			browser.raw(frame.subarray(1500));
			await client.reply(1);
			expect(client.replies).toEqual([
				result,
				{
					id: 1,
					error: {
						code: METHOD_NOT_FOUND,
						message: 'koi recorder: Tracing.start is not permitted',
					},
				},
			]);
			// With nothing in flight, the next refusal is written at once.
			client.ws.send(JSON.stringify({ id: 2, method: 'Tracing.start', params: {} }));
			expect(await client.reply(2)).toMatchObject({ id: 2 });
			client.ws.close();
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test('knows a session whose attach event is large: a target at a long URL', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		try {
			const client = await connectClient(proxy.port);
			// An allowed URL with a 70 KB fragment: the attach event is one
			// frame over 64 KiB, which the old reader dropped, after which it
			// refused this session as unknown.
			const url = `http://app.abcdefghijklmnop0123.invalid:8080/#${'a'.repeat(70_000)}`;
			browser.announce(attached('S-long', { url }));
			await Bun.sleep(100);
			const shot = JSON.stringify({
				id: 1,
				sessionId: 'S-long',
				method: 'Page.captureScreenshot',
				params: {},
			});
			client.ws.send(shot);
			await until(() => browser.received.includes(shot));
			expect(events.page(0, 100).events.filter((e) => e.type === 'client-denied')).toEqual([]);
			client.ws.close();
		} finally {
			proxy.server.close();
			browser.close();
		}
	});

	test('refuses a wrong token, a plain request, a missing browser and too many clients', async () => {
		const browser = await fakeBrowser();
		const events = new EventLog(100);
		const proxy = await proxyFor(browser.port, events);
		const none = await proxyFor(undefined, events);
		try {
			const wrong = await fetch(`http://127.0.0.1:${proxy.port}/${'b2'.repeat(16)}`, {
				headers: { upgrade: 'websocket' },
			});
			expect(wrong.status).toBe(404);
			const plain = await fetch(`http://127.0.0.1:${proxy.port}/${TOKEN}`);
			expect(plain.status).toBe(426);
			const notReady = await fetch(`http://127.0.0.1:${none.port}/${TOKEN}`, {
				headers: { upgrade: 'websocket', 'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==' },
			});
			expect(notReady.status).toBe(503);
			const first = new WebSocket(`ws://127.0.0.1:${proxy.port}/${TOKEN}`);
			const second = new WebSocket(`ws://127.0.0.1:${proxy.port}/${TOKEN}`);
			await Promise.all(
				[first, second].map(
					(ws) =>
						new Promise<void>((resolve, reject) => {
							ws.onopen = () => resolve();
							ws.onerror = () => reject(new Error('the connection failed'));
						}),
				),
			);
			const third = await fetch(`http://127.0.0.1:${proxy.port}/${TOKEN}`, {
				headers: { upgrade: 'websocket', 'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==' },
			});
			expect(third.status).toBe(503);
			first.close();
			second.close();
			expect(
				events
					.page(0, 100)
					.events.filter((e) => e.type === 'client-rejected')
					.map((e) => e.reason),
			).toEqual([
				'wrong token',
				'not a websocket upgrade',
				'browser not ready',
				'too many clients',
			]);
		} finally {
			proxy.server.close();
			none.server.close();
			browser.close();
		}
	});
});
