import { type Origin, urlAllowed } from './origin.ts';

// What a client of the browser port may say to Chromium. The relay in
// proxy.ts reads every DevTools message and forwards only a method listed
// here, with the rewrites and param checks below applied first; anything
// else gets a DevTools error reply and goes no further. The list is what the
// pinned Playwright client (playwright-core 1.64.1, connectOverCDP and
// ordinary page automation: navigation, evaluation, input, DOM queries,
// screenshots, dialogs, emulation) sends in its Chromium code, read from
// node_modules/playwright-core/lib/coreBundle.js, less what widens the
// recorder's boundary. A method missing here is denied; this file is the
// whole policy.
//
// Nested dispatch: Chromium carries a message for an attached target either
// flattened, as a top-level message with a sessionId, or wrapped in
// Target.sendMessageToTarget. The relay accepts only the first: it rewrites
// every attach to flatten: true and refuses sendMessageToTarget, so the
// method of every message, nested or not, is the top-level `method` field
// and is checked by the same rule.
//
// Sessions are bound to the connection. The relay reads the
// Target.attachedToTarget events Chromium sends back to this client and
// records each sessionId it hands out; a client message carrying a sessionId
// the relay never handed out is refused (inspectMessage, via knownSession).
// A sessionId is the client's handle on a target, so an unknown one is a
// target the relay did not open for this client: a forged or guessed handle,
// or a session on another connection. This is checked before the method, so
// it covers every method, screenshots and evaluation included.

// Audit: allowlisted methods whose params can name a file, a URL or a target
// outside the page, what the relay checks on each, and why that is safe. A
// method absent from the allowlist (DOM.setFileInputFiles,
// Network.loadNetworkResource, Storage.*, Browser window and permission
// methods, Tracing, IO, Fetch, Debugger, Profiler) is refused outright and
// needs no row.
//
//   method                               checked                     why safe
//   -----------------------------------  --------------------------  ----------------------------------------------
//   Page.navigate                        params.url scheme           only http: and about:blank navigate; a
//                                                                     javascript:, data:, blob:, file: or chrome:
//                                                                     URL is refused, so a navigation cannot run
//                                                                     script or read a local file, and the origin of
//                                                                     an http: target is still the guard's call.
//   Target.createTarget                  params.browserContextId,    a page opens only in the run's own context,
//                                        params.url scheme           and only at an http: or about:blank URL; the
//                                                                     client only ever asks for about:blank.
//   Target.attachToTarget                params.targetId not         names a target by id and gives the client a
//                                        checked; flatten forced     session on it. A target id is a 32-hex handle
//                                        (REWRITTEN)                 the client learns only through its own
//                                                                     connection, and every target it can reach is
//                                                                     in the recorder's run context: one in any
//                                                                     other context is closed at once (broker.ts).
//                                                                     The session is no wider than the connection:
//                                                                     the relay records it from Chromium's attach
//                                                                     event, and every message on it meets this
//                                                                     list.
//   Target.attachToBrowserTarget         no params                   gives the client a second session on the
//                                                                     browser target itself. It has the reach of the
//                                                                     connection's root session and every message on
//                                                                     it meets this same list, so it widens nothing.
//                                                                     The pinned client sends it for newCDPSession
//                                                                     and attaches to the page from that session;
//                                                                     Chromium announces both with attach events,
//                                                                     which the relay records like any other.
//   Target.getTargetInfo                 params.targetId not         reads the type, title, URL and context id of a
//                                        checked                     target in the recorder's browser. It loads
//                                                                     nothing and changes nothing; an id Chromium
//                                                                     does not have gets Chromium's error.
//   Target.detachFromTarget              params.sessionId not        ends the client's own handle on a target.
//                                        checked                     Chromium detaches only a session this
//                                                                     connection attached, so the id names the
//                                                                     client's own handle or nothing. The relay
//                                                                     drops the session when Chromium's
//                                                                     detachedFromTarget event comes back.
//   Target.closeTarget                   refused outright            every target the client can reach is in the
//                                                                     recorder's own run context; the recorder owns
//                                                                     page and context lifecycle, so the client does
//                                                                     not close targets in version 1.
//   Page.close                           refused outright            closes the session's page after beforeunload;
//                                                                     the pinned client sends it for page.close({
//                                                                     runBeforeUnload: true }). Refused for the same
//                                                                     reason as Target.closeTarget: the recorder
//                                                                     owns page lifecycle in version 1.
//   Network.setCookie / setCookies       params url and domain       a cookie is set only for the app origin
//                                        (cookieOnOrigin)            (http(s) url on the origin, or the origin's
//                                                                     host as domain); no cookie reaches another
//                                                                     site.
//   Browser.setDownloadBehavior          rewritten to deny           the path the client names is dropped and the
//   Page.setDownloadBehavior             (REWRITTEN)                 behaviour forced to deny, so no file is
//                                                                     written to a client-named directory.
//   Input.dispatchDragEvent              refused outright            data.files delivers host files to the page on
//                                                                     drop; the runner does not need drag-and-drop
//                                                                     in version 1, so the method is off the list.
//   Input.dispatchKeyEvent / Mouse /     none carry a path           keyboard, mouse and touch coordinates and text
//   Touch / insertText /                                             only; no file path or URL. setInterceptDrags
//   setInterceptDrags                                                toggles a flag and delivers nothing by itself.
//   Runtime.evaluate /                   the outer sessionId         the relay checks the session the message names
//   callFunctionOn / getProperties /     (knownSession); objectId    and nothing inside params. An objectId is a
//   releaseObject / releaseObjectGroup   not checked                 handle in that session's own object table;
//                                                                     Chromium resolves it within the session it
//                                                                     arrives on, and every object the client can
//                                                                     reach is in a page it already drives. Script
//                                                                     in the page is allowed by design.
//   Network.setExtraHTTPHeaders,         none carry a path or url    headers, cache and condition toggles that name
//   setCacheDisabled, getResponseBody,                               a requestId or a header map, never a file or
//   emulateNetworkConditions, ...                                    an off-page target.
//   Emulation.* (geolocation, locale,    none carry a path           all change what the page sees of itself; none
//   timezone, media, metrics, ...)                                   name a file or a target.

// Methods forwarded as they are. One comment per domain says why the
// domain is here at all.
export const ALLOWED_METHODS: ReadonlySet<string> = new Set([
	// Browser: the version, which connectOverCDP reads first. Download
	// behaviour is in REWRITTEN below, never forwarded as sent. Closing,
	// crashing, permissions and window bounds are denied.
	'Browser.getVersion',

	// Target: reaching the pages the recorder opened and the frames and
	// workers inside them. Attaching (setAutoAttach, attachToTarget) is in
	// REWRITTEN below, forced to flattened sessions. A session on the browser
	// target itself (attachToBrowserTarget, which the client sends for
	// newCDPSession before it attaches to the page from there) has the reach
	// of the root session and is checked the same way. Creating a page is
	// allowed only in the run's own context and only at an http: or
	// about:blank URL (checked in inspectMessage). Closing a target is
	// refused: the recorder owns page lifecycle. Creating or disposing
	// contexts, exposing the protocol to page scripts, discovering targets
	// and the wrapped message form are denied.
	'Target.attachToBrowserTarget',
	'Target.detachFromTarget',
	'Target.getTargetInfo',
	'Target.createTarget',

	// Page: the frame tree, lifecycle events, navigation and history,
	// screenshots, dialogs, init scripts and isolated worlds, and fonts.
	// Download behaviour is rewritten (REWRITTEN). Page.navigate's URL is
	// checked (inspectMessage). Page.close is refused like Target.closeTarget:
	// the client sends it for page.close({ runBeforeUnload: true }), and the
	// recorder owns page lifecycle in version 1. PDF, screencast, file
	// chooser interception and CSP bypass are denied.
	'Page.enable',
	'Page.disable',
	'Page.getFrameTree',
	'Page.setLifecycleEventsEnabled',
	'Page.navigate',
	'Page.reload',
	'Page.stopLoading',
	'Page.getNavigationHistory',
	'Page.navigateToHistoryEntry',
	'Page.captureScreenshot',
	'Page.getLayoutMetrics',
	'Page.handleJavaScriptDialog',
	'Page.bringToFront',
	'Page.addScriptToEvaluateOnNewDocument',
	'Page.removeScriptToEvaluateOnNewDocument',
	'Page.createIsolatedWorld',
	'Page.setFontFamilies',

	// Runtime: evaluation, which Playwright does everything through, and the
	// bindings its injected script uses. A client can run any script in the
	// page already; the boundary is the network, not the page. The relay
	// checks the session id of each message and refuses an unknown one
	// before the method is read; an objectId inside the params is left to
	// Chromium, which resolves it within the session it is sent on.
	'Runtime.enable',
	'Runtime.disable',
	'Runtime.evaluate',
	'Runtime.callFunctionOn',
	'Runtime.getProperties',
	'Runtime.releaseObject',
	'Runtime.releaseObjectGroup',
	'Runtime.addBinding',
	'Runtime.removeBinding',
	'Runtime.runIfWaitingForDebugger',

	// Network: observing requests and reading bodies the app answered the
	// page with, cache control, extra headers and offline emulation. Setting
	// cookies is allowed for the app origin only; inspectMessage checks each
	// cookie. Interception, Fetch, reading or clearing the cookie jar and
	// loading resources outside a page are denied.
	'Network.enable',
	'Network.disable',
	'Network.setCacheDisabled',
	'Network.clearBrowserCache',
	'Network.setExtraHTTPHeaders',
	'Network.getResponseBody',
	'Network.emulateNetworkConditions',
	'Network.setBypassServiceWorker',
	'Network.setCookie',
	'Network.setCookies',

	// Emulation: the viewport, media, focus, user agent, locale, timezone,
	// touch, script execution, background colour and geolocation a Playwright
	// context sets on its pages. All of it changes what the page sees of
	// itself, not what it can reach.
	'Emulation.setDeviceMetricsOverride',
	'Emulation.clearDeviceMetricsOverride',
	'Emulation.setEmulatedMedia',
	'Emulation.setFocusEmulationEnabled',
	'Emulation.setUserAgentOverride',
	'Emulation.setLocaleOverride',
	'Emulation.setTimezoneOverride',
	'Emulation.setTouchEmulationEnabled',
	'Emulation.setScriptExecutionDisabled',
	'Emulation.setDefaultBackgroundColorOverride',
	'Emulation.setGeolocationOverride',
	'Emulation.clearGeolocationOverride',

	// Input: keyboard, mouse and touch events, drag interception toggle, and
	// text insertion. Input.dispatchDragEvent is not here: its data.files
	// delivers host files to the page, and the runner does not drag-and-drop
	// in version 1.
	'Input.dispatchKeyEvent',
	'Input.dispatchMouseEvent',
	'Input.dispatchTouchEvent',
	'Input.insertText',
	'Input.setInterceptDrags',

	// DOM: the node descriptions, boxes and scrolling Playwright's locators
	// use. Setting a file input's files from the client's filesystem
	// (DOM.setFileInputFiles) is denied.
	'DOM.enable',
	'DOM.disable',
	'DOM.describeNode',
	'DOM.resolveNode',
	'DOM.getBoxModel',
	'DOM.getContentQuads',
	'DOM.scrollIntoViewIfNeeded',
	'DOM.getFrameOwner',

	// Log and Inspector: console entries from the browser and the crash
	// notices Playwright enables on connect. Both only report.
	'Log.enable',
	'Log.disable',
	'Inspector.enable',
]);

// Methods forwarded only after their params are rewritten. The client gets
// the browser's reply to the rewritten message.
export const REWRITTEN_METHODS: ReadonlySet<string> = new Set([
	// Playwright's default context sends this on connect, so it must
	// succeed; what it asks for is replaced by a denial, so no client gains
	// download control.
	'Browser.setDownloadBehavior',
	'Page.setDownloadBehavior',
	// Flattened sessions only, so every nested message is checked here. Only
	// flatten is forced; waitForDebuggerOnStart is left as the client sent
	// it, because the guard (guard.ts) auto-attaches on its own, separate
	// connection with waitForDebuggerOnStart: true and enables Fetch before
	// it resumes a target, so the guard, not the client's flag, decides when
	// a new target may run.
	'Target.setAutoAttach',
	'Target.attachToTarget',
]);

// The DevTools error code for an unknown method, which is what a denied
// method looks like to the client.
export const METHOD_NOT_FOUND = -32601;

export interface Verdict {
	// The message to forward, as text, or undefined when it is refused.
	forward?: string;
	// Why it was refused, when it was.
	denied?: string;
	// The method that was rewritten, when it was.
	rewritten?: string;
	// The method named, when the message had one.
	method?: string;
	// The id to answer, when the message had one.
	id?: number;
	// The session the message named, when it did. A reply to the message
	// must carry it: the client routes replies by session, and a reply
	// without one goes to the root session, where nothing waits for it.
	sessionId?: string;
}

export interface InspectOptions {
	// Whether Chromium's id for a browser context is one the recorder made.
	ownsContext: (browserContextId: string) => boolean;
	origin: Origin;
	// Whether a sessionId is one the relay handed this client, from a
	// Target.attachedToTarget it forwarded. Absent in unit tests that check
	// the method policy alone; the proxy always supplies it.
	knownSession?: (sessionId: string) => boolean;
}

// Decides one client message. The text is parsed once; a forwarded message
// is re-encoded only when it was rewritten.
export function inspectMessage(text: string, options: InspectOptions): Verdict {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return { denied: 'not a JSON message' };
	}
	if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
		return { denied: 'not a DevTools message' };
	}
	const message = parsed as {
		id?: unknown;
		method?: unknown;
		params?: unknown;
		sessionId?: unknown;
	};
	const id = typeof message.id === 'number' ? message.id : undefined;
	const sessionId = typeof message.sessionId === 'string' ? message.sessionId : undefined;
	// Every verdict carries the ids a reply needs, refusals included.
	const withId = {
		...(id === undefined ? {} : { id }),
		...(sessionId === undefined ? {} : { sessionId }),
	};
	if (typeof message.method !== 'string') return { ...withId, denied: 'no method' };
	const method = message.method;
	// A sessionId the relay never handed out is a target this client never
	// opened; refuse it before the method, so the check covers every method.
	if (sessionId !== undefined && options.knownSession !== undefined) {
		if (!options.knownSession(sessionId)) {
			return { ...withId, method, denied: `${method} for an unknown session` };
		}
	}
	const params =
		typeof message.params === 'object' && message.params !== null && !Array.isArray(message.params)
			? (message.params as Record<string, unknown>)
			: {};
	if (REWRITTEN_METHODS.has(method)) {
		const rewritten = { ...message, params: rewriteParams(method, params) };
		return { ...withId, method, rewritten: method, forward: JSON.stringify(rewritten) };
	}
	if (!ALLOWED_METHODS.has(method)) {
		return { ...withId, method, denied: `${method} is not permitted` };
	}
	if (method === 'Target.createTarget') {
		const contextId = params.browserContextId;
		if (typeof contextId !== 'string' || !options.ownsContext(contextId)) {
			return { ...withId, method, denied: 'Target.createTarget outside the run context' };
		}
		if (!navigableUrlAllowed(params.url)) {
			return { ...withId, method, denied: 'Target.createTarget to a non-navigable URL' };
		}
	}
	if (method === 'Page.navigate' && !navigableUrlAllowed(params.url)) {
		return { ...withId, method, denied: 'Page.navigate to a non-navigable URL' };
	}
	if (method === 'Network.setCookie' || method === 'Network.setCookies') {
		const cookies = method === 'Network.setCookie' ? [params] : params.cookies;
		if (!Array.isArray(cookies) || !cookies.every((c) => cookieOnOrigin(c, options.origin))) {
			return { ...withId, method, denied: `${method} for another origin` };
		}
	}
	return { ...withId, method, forward: text };
}

function rewriteParams(method: string, params: Record<string, unknown>): Record<string, unknown> {
	switch (method) {
		case 'Browser.setDownloadBehavior':
		case 'Page.setDownloadBehavior': {
			// The context id and the events flag stay, so the client's own
			// bookkeeping works; the path goes with the behaviour.
			const { downloadPath: _dropped, ...rest } = params;
			return { ...rest, behavior: 'deny' };
		}
		case 'Target.setAutoAttach':
		case 'Target.attachToTarget':
			return { ...params, flatten: true };
		default:
			return params;
	}
}

// A URL a navigation may go to: about:blank, or any http: URL. A navigation
// to any other scheme is refused. javascript: runs script in the page,
// data:, blob: and file: load content the app did not serve, and chrome:
// reaches the browser's own pages; none of these is a request the origin
// guard would see, so the proxy refuses them here. The origin of an http:
// target is left to the guard (guard.ts), which fails a request off the app
// origin; the two layers together are "every navigation off the origin is
// denied and reported".
function navigableUrlAllowed(url: unknown): boolean {
	if (typeof url !== 'string') return false;
	const trimmed = url.trim();
	if (trimmed.toLowerCase() === 'about:blank') return true;
	let parsed: URL;
	try {
		parsed = new URL(trimmed);
	} catch {
		return false;
	}
	return parsed.protocol === 'http:';
}

// A cookie the client may set: one whose url is on the app origin, or whose
// domain is the app's host (with or without a leading dot), and nothing
// else. A cookie with neither has no origin to check and is refused.
function cookieOnOrigin(cookie: unknown, origin: Origin): boolean {
	if (typeof cookie !== 'object' || cookie === null) return false;
	const { url, domain } = cookie as { url?: unknown; domain?: unknown };
	if (typeof url === 'string') {
		if (!urlAllowed(url, origin) || !/^https?:/i.test(url)) return false;
	}
	if (typeof domain === 'string') {
		const host = domain.replace(/^\./, '').toLowerCase();
		if (host !== origin.host.toLowerCase()) return false;
	}
	return typeof url === 'string' || typeof domain === 'string';
}
