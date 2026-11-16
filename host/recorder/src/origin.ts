// The one origin a run's browser may talk to: the app's private name on the
// run network, http://app.<runId>.invalid:<port>. Two layers keep the
// browser there. The readable one is the origin guard (guard.ts), which
// checks every request against urlAllowed below and reports a denial. The
// one under it is Chromium's own proxy setting (proxyArgs): every request
// to any host but the app's goes to a proxy at 127.0.0.1:1, where nothing
// listens, and fails at the network layer. The OS firewall around the run
// network is what keeps packets in; these two are the guards inside the
// browser.

export interface Origin {
	host: string;
	port: number;
}

// The origin of KOI_PREVIEW_URL. Only plain http is served inside the run
// network; anything else is a configuration mistake.
export function parseOrigin(url: string): Origin {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error('KOI_PREVIEW_URL is not a URL');
	}
	if (parsed.protocol !== 'http:') throw new Error('KOI_PREVIEW_URL must be http://');
	if (parsed.username !== '' || parsed.password !== '') {
		throw new Error('KOI_PREVIEW_URL must not carry credentials');
	}
	const port = parsed.port === '' ? 80 : Number(parsed.port);
	return { host: parsed.hostname, port };
}

// The origin as the URL parser spells it: no port when it is the scheme's
// default, so port 80 compares equal however it was written.
export function originUrl(origin: Origin): string {
	return new URL(`http://${origin.host}:${origin.port}`).origin;
}

// Chromium flags that make the network layer refuse every host but the
// app's: a proxy nothing listens on, bypassed for the app's name alone.
// <-loopback> removes Chromium's implicit bypass of localhost and
// link-local addresses, so a navigation to 127.0.0.1, an IP literal or the
// host's own services fails like any other. The resolver rule fails every
// other name before a connection is even tried.
export function proxyArgs(origin: Origin): string[] {
	return [
		'--proxy-server=127.0.0.1:1',
		`--proxy-bypass-list=${origin.host};<-loopback>`,
		`--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE ${origin.host}`,
	];
}

// Whether the browser may fetch or open `url`. Allowed: the private origin
// itself over http or ws (the app's own WebSocket endpoint is on the same
// origin), blank pages, and in-memory data: and blob: resources (a blob URL
// carries the origin that made it, which must be ours). Everything else,
// including https or wss to the same name, another port, an IP literal and
// every other scheme, is denied. Origins are compared in canonical form, so
// a default port written out matches one left off.
export function urlAllowed(url: string, origin: Origin): boolean {
	if (url === 'about:blank') return true;
	if (url.startsWith('data:')) return true;
	if (url.startsWith('blob:')) return urlAllowed(url.slice('blob:'.length), origin);
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return false;
	}
	if (parsed.username !== '' || parsed.password !== '') return false;
	if (parsed.protocol !== 'http:' && parsed.protocol !== 'ws:') return false;
	// ws: and http: share default ports and origin rules; the parser gives
	// a ws: URL a ws: origin, so it is compared as http.
	const canonical =
		parsed.protocol === 'ws:' ? new URL(`http://${parsed.host}`).origin : parsed.origin;
	return canonical === originUrl(origin);
}

// A path for a state read or a first navigation: relative to the origin,
// with no scheme, host or credentials of its own. Returns the full URL.
export function samePath(path: string, origin: Origin): string | undefined {
	if (!path.startsWith('/') || path.startsWith('//')) return undefined;
	for (const char of path) {
		const code = char.charCodeAt(0);
		if (code < 0x20 || code === 0x7f) return undefined;
	}
	const url = `${originUrl(origin)}${path}`;
	return urlAllowed(url, origin) && new URL(url).origin === originUrl(origin) ? url : undefined;
}
