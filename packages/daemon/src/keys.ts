import { isIP } from 'node:net';
import {
	ForgetTokenSchema,
	PREVIEW_LABEL,
	PROVIDERS,
	RegisterKeysSchema,
	TOKEN_PREFIXES,
} from '@koi/shared';
import type { EgressControl } from './egress.ts';
import type { RateLimit, RateLimits } from './ratelimit.ts';

// https://keys.<domain>/?for=<label>: where reviewers give koi their provider
// keys for one preview. The page keeps the keys in this origin's localStorage
// (previews live on other origins and cannot read it) and registers them
// with the egress proxy, which holds them in memory. For each key the proxy
// derives a koi token from the key, its provider and the preview under a
// secret on the box, good for that provider and only in requests from that
// preview's container, and swaps it for the key on the way to the provider.
// The preview's code only ever sees the tokens.
//
// A token is never chosen by the caller: registering a key gets the token
// the proxy derives for it, the same one each time. So knowing a token, as
// the preview's code does, lets a caller only forget it, never bind it to
// another key or preview, and tells nothing about the key.
//
// The proxy forgets every registration when the box sleeps. The page
// registers the keys it last registered for its preview again on its own
// when it opens and when its tab becomes visible (at most once a minute
// across its tabs), gets the same tokens back, and says so; the reviewer
// pastes nothing again. Every registration, re-registration and Forget of
// one browser runs under one Web Locks API lock, so its tabs never overlap.

// Calls per address, and from everyone, in ten minutes. The page registers
// once per save and at most once a minute on its own, and forgets one token
// per provider key when a registration replaces them or the reviewer
// forgets, trying again later when refused (429), so forgetting has more
// room.
export const REGISTER_LIMITS: RateLimits = { perSource: 30, total: 300, windowMs: 10 * 60_000 };
export const FORGET_LIMITS: RateLimits = { perSource: 120, total: 1200, windowMs: 10 * 60_000 };

export interface KeysLimits {
	register: RateLimit;
	forget: RateLimit;
}

// The largest request body the API reads: a label and a 512-character key
// for each provider fit in well under this.
export const MAX_BODY_BYTES = 8 * 1024;

const SECURITY_HEADERS: Record<string, string> = {
	'content-security-policy':
		"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
	'referrer-policy': 'no-referrer',
	'x-content-type-options': 'nosniff',
	'cache-control': 'no-store',
};

export async function handleKeys(
	request: Request,
	egress: EgressControl,
	limits: KeysLimits,
	// Told every key and token that passed through, so the evidence
	// sanitizer knows them (redact.ts, SecretRegistry).
	onSecrets?: (values: string[]) => void,
): Promise<Response> {
	const url = new URL(request.url);
	if (request.method === 'GET' && url.pathname === '/')
		return asset(KEYS_HTML, 'text/html; charset=utf-8');
	if (request.method === 'GET' && url.pathname === '/keys.js')
		return asset(KEYS_JS, 'text/javascript');
	if (request.method === 'GET' && url.pathname === '/keys.css') return asset(KEYS_CSS, 'text/css');
	if (
		request.method === 'POST' &&
		(url.pathname === '/api/register' || url.pathname === '/api/forget')
	) {
		// Only the page itself may call these: a cross-origin form post or
		// fetch from a preview carries a different Origin.
		if (request.headers.get('origin') !== url.origin.replace(/^http:/, 'https:')) {
			return json(403, { error: 'wrong origin' });
		}
		const source = viewerSource(request);
		const registering = url.pathname === '/api/register';
		if (!(registering ? limits.register : limits.forget).take(source)) {
			return json(429, {
				error: `too many ${registering ? 'registrations' : 'requests to forget'}; try again in a few minutes`,
			});
		}
		const text = await smallBody(request);
		if (text === undefined) return json(413, { error: 'the request is too large' });
		let body: unknown;
		try {
			body = JSON.parse(text);
		} catch {
			return json(400, { error: 'expected JSON' });
		}
		try {
			if (url.pathname === '/api/register') {
				const parsed = RegisterKeysSchema.safeParse(body);
				if (!parsed.success) {
					return json(400, { error: 'expected a preview label and provider keys' });
				}
				const keys = Object.fromEntries(
					Object.entries(parsed.data.keys).filter(
						(entry): entry is [string, string] => entry[1] !== undefined,
					),
				);
				const tokens = await egress.register(parsed.data.label, keys, source);
				onSecrets?.([...Object.values(keys), ...Object.values(tokens)]);
				return json(200, { tokens });
			}
			const parsed = ForgetTokenSchema.safeParse(body);
			if (!parsed.success) return json(400, { error: 'expected a koi token' });
			await egress.forget(parsed.data.token);
			return json(200, { ok: true });
		} catch {
			// The proxy's message may echo input; never send it back or log it.
			return json(503, { error: 'the key proxy is not available; try again in a moment' });
		}
	}
	return json(404, { error: 'not found' });
}

// The request's body as text, or undefined when it is larger than
// MAX_BODY_BYTES. A Content-Length over the limit is refused unread; a body
// without one is read only until it passes the limit.
async function smallBody(request: Request): Promise<string | undefined> {
	const declared = request.headers.get('content-length');
	if (declared !== null && !(Number(declared) <= MAX_BODY_BYTES)) return undefined;
	if (request.body === null) return '';
	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > MAX_BODY_BYTES) {
			await reader.cancel();
			return undefined;
		}
		chunks.push(value);
	}
	return new TextDecoder().decode(Buffer.concat(chunks));
}

// Where a request came from, for limits. On the AWS box CloudFront appends
// the viewer's address to X-Forwarded-For, and Caddy passes that header on as
// X-Koi-Forwarded-For (see caddy.ts), so its last entry is the viewer's.
// Entries before it are whatever the client sent. On a host without
// CloudFront, Caddy sets the header to its peer's address alone. An IPv6 address counts by
// its /64, which one subscriber usually holds whole; an IPv4 address written
// as IPv6 (::ffff:...) is that IPv4 address. Without an address, every such
// request shares the source 'unknown'.
export function viewerSource(request: Request): string {
	const entries = (request.headers.get('x-koi-forwarded-for') ?? '').split(',');
	const last = (entries[entries.length - 1] ?? '').trim();
	switch (isIP(last)) {
		case 4:
			return last;
		case 6: {
			const groups = ipv6Groups(last);
			if (groups === undefined) return 'unknown';
			const [a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0] = groups;
			if (a === 0 && b === 0 && c === 0 && d === 0 && e === 0 && f === 0xffff) {
				return [g >> 8, g & 0xff, h >> 8, h & 0xff].join('.');
			}
			return `${[a, b, c, d].map((n) => n.toString(16)).join(':')}::/64`;
		}
		default:
			return 'unknown';
	}
}

// The eight 16-bit groups of an IPv6 address isIP accepted: "::" filled
// with as many zero groups as are missing, wherever it stands, and a dotted
// IPv4 tail (::ffff:1.2.3.4, 64:ff9b::1.2.3.4) as the two groups it is.
function ipv6Groups(address: string): number[] | undefined {
	let text = address.split('%')[0] ?? '';
	const tail = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
	if (tail !== null) {
		const [p, q, r, s] = tail.slice(1).map(Number) as [number, number, number, number];
		text = `${text.slice(0, tail.index)}${((p << 8) | q).toString(16)}:${((r << 8) | s).toString(16)}`;
	}
	const halves = text.split('::');
	if (halves.length > 2) return undefined;
	const part = (half: string | undefined) =>
		half === undefined || half === '' ? [] : half.split(':');
	const head = part(halves[0]);
	const rest = part(halves[1]);
	const groups =
		halves.length === 2
			? [...head, ...Array(8 - head.length - rest.length).fill('0'), ...rest]
			: head;
	if (groups.length !== 8) return undefined;
	return groups.map((g) => Number.parseInt(g, 16));
}

function asset(body: string, type: string): Response {
	return new Response(body, { headers: { ...SECURITY_HEADERS, 'content-type': type } });
}

function json(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { ...SECURITY_HEADERS, 'content-type': 'application/json' },
	});
}

const providerRows = PROVIDERS.map(
	(p) =>
		`<label><span>${p.name}</span><input type="password" name="${p.id}" autocomplete="off" spellcheck="false" placeholder="paste a ${p.name} key"></label>`,
).join('\n      ');

export const KEYS_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>koi keys</title>
<link rel="stylesheet" href="/keys.css">
<script src="/keys.js" defer></script>
</head>
<body>
<main>
  <h1>Your API keys for koi previews</h1>
  <p id="no-preview" hidden>This page registers keys for one preview, named in its address. Open it from the link in the pull request's preview comment; that link ends in <code>?for=</code> and the preview's name.</p>
  <section id="for-preview" hidden>
    <p>For the preview <strong id="label"></strong>. Paste the provider keys you want it to use. They stay in this browser and in the koi box's memory. The preview never sees them: you give it the koi tokens this page shows instead, and koi swaps each for your key on the way to its provider.</p>
    <form id="keys">
      ${providerRows}
      <button type="submit">Register for this preview</button>
    </form>
    <section id="token-box" hidden>
      <h2>Your koi tokens</h2>
      <p>Paste each one where a node in the preview asks for that provider's API key. A token works only for its provider, and only in this preview.</p>
      <ul id="tokens"></ul>
    </section>
  </section>
  <p id="status" role="status"></p>
  <button type="button" id="forget">Forget my keys</button>
  <aside>
    <h2>What this protects, and what it does not</h2>
    <ul>
      <li>The preview runs code from a pull request. It can use your tokens to call the providers above, up to 600 requests an hour each, but it cannot read your keys or send them anywhere else, and the tokens work in no other preview.</li>
      <li>When the koi box sleeps, it forgets your keys. This browser remembers them, and this page registers them again whenever you open or return to it, and gets the same tokens back, so the tokens you pasted into the preview keep working. If a node says its token is not registered, open this page or return to its tab.</li>
      <li>Realtime (WebSocket) APIs do not take koi tokens; nodes that use a provider's HTTP API do.</li>
      <li>Database passwords and other secrets that are not an API key in a request header are not covered. If you type one into a preview, the pull request's code can see it.</li>
    </ul>
  </aside>
</main>
</body>
</html>
`;

export const KEYS_CSS = `body { font: 15px/1.5 system-ui, sans-serif; margin: 0; background: #111; color: #eee; }
main { max-width: 40rem; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
h1 { font-size: 1.5rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
form { display: grid; gap: .6rem; margin-top: 1.5rem; }
label { display: grid; grid-template-columns: 9rem 1fr; align-items: center; gap: .75rem; }
input { font: inherit; padding: .45rem .6rem; border-radius: 6px; border: 1px solid #444; background: #1b1b1b; color: #eee; }
button { font: inherit; padding: .45rem .9rem; border-radius: 6px; border: 1px solid #4a7; background: #1f3a2c; color: #eee; cursor: pointer; justify-self: start; }
code { background: #1b1b1b; padding: .2rem .4rem; border-radius: 4px; color: #9cf; word-break: break-all; }
#status { color: #9c9; } #status.err { color: #f99; }
aside { margin-top: 2.5rem; color: #bbb; }
`;

const providerNames = JSON.stringify(Object.fromEntries(PROVIDERS.map((p) => [p.id, p.name])));
const tokenPrefixes = JSON.stringify(TOKEN_PREFIXES);

export const KEYS_JS = `(function () {
  var STORE = 'koi.keys';
  // How many times this browser has forgotten its keys, from any tab.
  // Never removed. A registration asked for at one count saves nothing,
  // and revokes what it got, if the count has moved by the time it runs or
  // its reply comes; a tab that sees the count move in a storage event
  // shows the keys are gone.
  var FORGOT = 'koi.keys.forgot';
  // Set while a Forget has moved the count but not yet run under the lock
  // (its tab may close meanwhile): the next operation under the lock, in
  // any tab, or the next page to open, finishes it first (finishForget).
  var PENDING = 'koi.keys.forgetting';
  // When this browser last sent a registration for each preview, {label: ms}.
  var SENT = 'koi.keys.sent';
  var LABEL = ${PREVIEW_LABEL};
  var NAMES = ${providerNames};
  // Shown before each provider's token, so nodes that check how a key
  // begins take it (TOKEN_PREFIXES). The box gives and takes tokens without.
  var PREFIXES = ${tokenPrefixes};
  // How long to wait before trying again to revoke tokens the box did not
  // confirm it forgot.
  var RETRY_MS = 10000;
  // The koi box forgets every registration when it sleeps, and gives the
  // same tokens back when the same keys are registered again. So the page
  // registers the keys it last registered for this preview again, on its
  // own, when it opens and whenever its tab becomes visible again, unless a
  // registration was sent within this long: the box sleeps only after ten
  // idle minutes, and koid limits registrations from one address.
  var REGISTER_AGAIN_MS = 60000;
  var HELD = 'Your tokens for this preview. They keep working after the koi box sleeps: this page registers your keys again whenever you open or return to it.';
  var form = document.getElementById('keys');
  var box = document.getElementById('token-box');
  var list = document.getElementById('tokens');
  var statusEl = document.getElementById('status');
  var label = new URLSearchParams(location.search).get('for');
  var retrying = null;
  // Whether the revoke list is a Forget's, of every key and token this
  // browser held, rather than an earlier registration's old tokens.
  var forgetting = false;
  // The Forget count this tab last saw (FORGOT).
  var forgot = count();
  // The tokens this tab shows for its preview, {} while it shows none: a
  // reply is compared with these, and another tab's registration replaces
  // them, so the tab never shows tokens that no longer work.
  var shownTokens = {};
  // Whether the page is for a preview (a valid label).
  var forPreview = false;
  var chain = Promise.resolve();

  // Runs op once no other registration, re-registration or Forget of this
  // browser is running, in any of its tabs (the Web Locks API), or in this
  // tab where the API is missing. Everything that reads storage in order
  // to change it runs under it, so two tabs never overlap, and the
  // once-a-minute check and its mark happen together. A Forget left
  // pending is finished first, and its revocations sent before op, unless
  // op is revokeAll and sends them itself.
  function locked(op) {
    var run = function () {
      if (!finishForget() || op === revokeAll) return op();
      return revokeAll().then(function (done) {
        report(done);
        return op();
      });
    };
    if (navigator.locks) return navigator.locks.request('koi-keys', run);
    var next = chain.then(run);
    chain = next.catch(function () {});
    return next;
  }
  function count() {
    return Number(localStorage.getItem(FORGOT)) || 0;
  }
  function forgetPending() {
    return localStorage.getItem(PENDING) === '1';
  }
  // Finishes a Forget left pending (PENDING): the saved keys and
  // registrations go, their tokens to the revoke list. Under the lock.
  // True if there was one.
  function finishForget() {
    if (!forgetPending()) return false;
    var state = load();
    for (var l in state.previews) toRevoke(state, state.previews[l].tokens);
    state.keys = {};
    state.previews = {};
    save(state);
    localStorage.removeItem(SENT);
    localStorage.removeItem(PENDING);
    return true;
  }
  // { keys: {provider: key}, the keys last registered anywhere, for the
  // form; previews: {label: {keys, tokens}}, the last registration for
  // each preview; revoke: [token], tokens the box has not yet confirmed it
  // forgot, kept until it does, across reloads }.
  function load() {
    var saved = null;
    try { saved = JSON.parse(localStorage.getItem(STORE) || 'null'); } catch (e) {}
    if (!saved || typeof saved !== 'object') saved = {};
    var previews = saved.previews || {};
    // An older page saved each preview's tokens with one set of keys for
    // all of them. The tokens stay, to show and to revoke, but with no
    // keys of their own there is nothing to register again until the
    // reviewer registers once more.
    for (var l in saved.tokens || {}) { if (!previews[l]) previews[l] = { keys: {}, tokens: saved.tokens[l] }; }
    return { keys: saved.keys || {}, previews: previews, revoke: saved.revoke || [] };
  }
  function save(state) {
    var empty = Object.keys(state.keys).length === 0 && Object.keys(state.previews).length === 0 && state.revoke.length === 0;
    if (empty) localStorage.removeItem(STORE);
    else localStorage.setItem(STORE, JSON.stringify(state));
  }
  function sentAt() {
    var sent = null;
    try { sent = JSON.parse(localStorage.getItem(SENT) || 'null'); } catch (e) {}
    return sent && typeof sent === 'object' ? sent : {};
  }
  function markSent() {
    var sent = sentAt();
    sent[label] = Date.now();
    localStorage.setItem(SENT, JSON.stringify(sent));
  }
  function status(text, isError) {
    statusEl.textContent = text;
    statusEl.className = isError ? 'err' : '';
  }
  // True if a and b hold the same values under the same names.
  function same(a, b) {
    a = a || {};
    b = b || {};
    var names = Object.keys(a);
    if (names.length !== Object.keys(b).length) return false;
    for (var i = 0; i < names.length; i++) { if (b[names[i]] !== a[names[i]]) return false; }
    return true;
  }
  // Resolves with the reply; rejects with an error whose status is the
  // HTTP status, or 0 when no answer came.
  function post(path, body) {
    return fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (r.ok) return j;
          var err = new Error(j.error || 'the koi box answered ' + r.status);
          err.status = r.status;
          throw err;
        });
      }, function (e) {
        var err = new Error('the koi box could not be reached (' + e.message + ')');
        err.status = 0;
        throw err;
      });
  }
  // Moves tokens to the revoke list, so they are forgotten even if this
  // page closes first.
  function toRevoke(state, tokens) {
    for (var id in tokens || {}) {
      if (state.revoke.indexOf(tokens[id]) === -1) state.revoke.push(tokens[id]);
    }
  }
  // Every token in the latest registration of any preview: in use, so no
  // cleanup may revoke it.
  function inUse(state) {
    var tokens = {};
    for (var l in state.previews) { for (var id in state.previews[l].tokens) tokens[state.previews[l].tokens[id]] = true; }
    return tokens;
  }
  // Asks the box to forget every token on the revoke list, one at a time,
  // taking each off the list once the box confirms; runs under the lock.
  // A token in use (inUse) comes off without asking: a registration put
  // it back. A token the box calls malformed (400) can never be
  // forgotten, and goes too. Resolves with the tokens left and why the
  // last of them failed.
  function revokeAll() {
    var state = load();
    var used = inUse(state);
    var queue = state.revoke.filter(function (t) { return !used[t]; });
    if (queue.length !== state.revoke.length) {
      state.revoke = queue.slice();
      save(state);
    }
    var why = '';
    function next() {
      if (queue.length === 0) return Promise.resolve({ left: load().revoke.length, why: why });
      var token = queue.shift();
      return post('/api/forget', { token: token }).then(function () { return true; }, function (e) {
        why = e.message;
        return e.status === 400;
      }).then(function (gone) {
        if (gone) {
          var s = load();
          s.revoke = s.revoke.filter(function (t) { return t !== token; });
          save(s);
        }
        return next();
      });
    }
    return next();
  }
  // Tries the revocations left again later. Only a Forget of the keys and
  // tokens this browser holds (forgetting) has the page speak of them:
  // "Forgotten" once the box has confirmed every one, and until then what
  // it has not. Revoking the tokens of an earlier registration, after
  // registering again, goes on quietly; the keys and tokens are still in
  // use.
  function report(done) {
    // Until this browser's Forget has run under the lock (forgetPending),
    // the list is not yet its own, and "Forgetting..." stands: an earlier
    // operation of the tab, cleaning up, must not speak for it.
    var speak = forgetting && !forgetPending();
    if (done.left === 0) {
      if (speak) {
        forgetting = false;
        status('Forgotten. This browser and the koi box no longer hold your keys.');
      }
      return;
    }
    if (speak) {
      status('This browser no longer holds your keys, but the koi box has not confirmed it forgot ' + done.left + ' of your tokens: ' + done.why + '. Trying again in ' + (RETRY_MS / 1000) + ' seconds; leave this page open, or open it again later.', true);
    }
    if (retrying === null) {
      retrying = setTimeout(function () {
        retrying = null;
        locked(revokeAll).then(report);
      }, RETRY_MS);
    }
  }
  function showTokens(tokens) {
    shownTokens = {};
    list.textContent = '';
    for (var id in tokens) {
      shownTokens[id] = tokens[id];
      var item = document.createElement('li');
      var name = document.createElement('span');
      name.textContent = (NAMES[id] || id) + ' ';
      var pasted = (PREFIXES[id] || '') + tokens[id];
      var code = document.createElement('code');
      code.textContent = pasted;
      var copy = document.createElement('button');
      copy.type = 'button';
      copy.textContent = 'Copy';
      copy.addEventListener('click', navigator.clipboard.writeText.bind(navigator.clipboard, pasted));
      item.append(name, code, ' ', copy);
      list.append(item);
    }
    box.hidden = false;
  }
  function hideTokens() {
    shownTokens = {};
    box.hidden = true;
    list.textContent = '';
  }
  // Provider names for a sentence: "OpenAI", "OpenAI and Anthropic",
  // "OpenAI, Anthropic and Groq".
  function names(ids) {
    var shown = ids.map(function (id) { return NAMES[id] || id; });
    if (shown.length < 2) return shown.join('');
    return shown.slice(0, -1).join(', ') + ' and ' + shown[shown.length - 1];
  }

  // Registers keys for this preview, under the lock, and saves them with
  // the tokens the box answers with as the preview's latest registration.
  // The reviewer's own submission (quiet false) shows the tokens. The
  // page's own registration (quiet true) sends the keys last registered
  // for this preview, read under the lock, if any and if none was sent in
  // the last REGISTER_AGAIN_MS; it expects the same tokens back and says
  // so, and shows them only if any changed, naming those providers and
  // asking for those tokens to be pasted. Tokens of the previous
  // registration that are not in the new one go to the revoke list, and
  // the new ones come off it. A Forget after this was asked for (the
  // count moved) wins: nothing is sent, or what the box answered with is
  // revoked and nothing saved. The same goes when this preview's
  // registration changed under it, which another tab can only do without
  // the Web Locks API.
  function register(keys, quiet) {
    var asked = count();
    return locked(function () {
      if (count() !== asked) return;
      var before = load().previews[label] || { keys: {}, tokens: {} };
      if (quiet) {
        keys = before.keys;
        if (Object.keys(keys).length === 0) return;
        if (Date.now() - (sentAt()[label] || 0) < REGISTER_AGAIN_MS) return;
        status('Registering your keys with the koi box again...');
      }
      markSent();
      return post('/api/register', { label: label, keys: keys })
        .then(function (reply) {
          if (!reply.tokens || typeof reply.tokens !== 'object') throw new Error('the koi box sent no tokens');
          var next = load();
          var latest = next.previews[label] || { keys: {}, tokens: {} };
          if (count() !== asked || !same(latest.keys, before.keys) || !same(latest.tokens, before.tokens)) {
            toRevoke(next, reply.tokens);
            save(next);
            if (count() === asked) {
              showTokens(latest.tokens);
              if (quiet) status(HELD);
              else status('Not registered: another tab registered keys for this preview meanwhile.', true);
            }
            return revokeAll().then(report);
          }
          var old = before.tokens;
          var wanted = {};
          for (var id in reply.tokens) wanted[reply.tokens[id]] = true;
          var stale = {};
          for (var oldId in old) { if (!wanted[old[oldId]]) stale[oldId] = old[oldId]; }
          // The form's keys are the reviewer's last registration, not the
          // page's own.
          if (!quiet) next.keys = keys;
          next.previews[label] = { keys: keys, tokens: reply.tokens };
          toRevoke(next, stale);
          next.revoke = next.revoke.filter(function (t) { return !wanted[t]; });
          save(next);
          // Keys are held again: whatever is left to revoke is old tokens.
          forgetting = false;
          // What changed for the reviewer: against what this tab shows,
          // which another tab's registration may have left behind.
          var seen = quiet ? shownTokens : old;
          var changed = [];
          for (var p in reply.tokens) { if (seen[p] !== reply.tokens[p]) changed.push(p); }
          if (changed.length > 0 || !quiet) showTokens(reply.tokens);
          return revokeAll().then(function (done) {
            var pending = done.left > 0 ? ' The koi box has not yet confirmed it forgot ' + done.left + ' token(s) of an earlier registration; this page keeps asking.' : '';
            if (!quiet) status('Registered. Paste these tokens into the preview. They keep working after the koi box sleeps: this page registers your keys again whenever you open or return to it.' + pending);
            else if (changed.length === 1) status('The koi box gave a new token for ' + names(changed) + '. Paste it into the preview in place of the old one; the rest are unchanged.' + pending, true);
            else if (changed.length > 0) status('The koi box gave new tokens for ' + names(changed) + '. Paste them into the preview in place of the old ones; the rest are unchanged.' + pending, true);
            else status('Keys registered again, in case the koi box slept. Your tokens are unchanged.' + pending);
            report(done);
          });
        })
        .catch(function (e) {
          if (count() !== asked) return;
          if (quiet) status('Could not register your keys again: ' + e.message + '. This page tries again when you return to it.', true);
          else status('Not registered: ' + e.message, true);
        });
    });
  }
  // The page's own registration of this preview's keys (register, quiet),
  // if this browser has registered any for it and sent no registration in
  // the last REGISTER_AGAIN_MS. Both are checked again under the lock.
  function registerAgain() {
    var mine = load().previews[label];
    if (!mine || Object.keys(mine.keys).length === 0) return;
    if (Date.now() - (sentAt()[label] || 0) < REGISTER_AGAIN_MS) return;
    register(null, true);
  }

  var saved = load();
  // A Forget a tab clicked and could not finish (it closed before its
  // turn under the lock): this page shows nothing of what is still saved,
  // and finishes it below.
  var pendingForget = forgetPending();
  if (pendingForget) saved = { keys: {}, previews: {}, revoke: saved.revoke };
  for (var id in saved.keys) { if (form.elements[id]) form.elements[id].value = saved.keys[id]; }
  if (label === null || !LABEL.test(label)) {
    document.getElementById('no-preview').hidden = false;
  } else {
    forPreview = true;
    document.getElementById('for-preview').hidden = false;
    document.getElementById('label').textContent = label;
    document.title = 'koi keys for ' + label;
    var mine = saved.previews[label];
    if (mine) {
      showTokens(mine.tokens);
      if (Object.keys(mine.keys).length > 0) status(HELD);
      else status('Your tokens for this preview, from an earlier version of this page. Register your keys once more; after that this page registers them again on its own whenever you open or return to it.');
      registerAgain();
    }
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'visible') registerAgain();
    });
  }
  // A Forget left pending, or revocations an earlier visit could not
  // finish: a Forget's if this browser holds no keys or tokens any more.
  if (pendingForget) {
    forgetting = true;
    status('Forgetting...');
    locked(revokeAll).then(report);
  } else if (saved.revoke.length > 0) {
    forgetting = Object.keys(saved.keys).length === 0 && Object.keys(saved.previews).length === 0;
    locked(revokeAll).then(report);
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var keys = {};
    var any = false;
    for (var i = 0; i < form.elements.length; i++) {
      var el = form.elements[i];
      if (el.name && el.value.trim()) { keys[el.name] = el.value.trim(); any = true; }
    }
    if (!any) { status('Paste at least one key.', true); return; }
    status('Registering with the koi box...');
    register(keys, false);
  });

  document.getElementById('forget').addEventListener('click', function () {
    // This tab's part is done at once: the Forget is recorded as pending
    // and the count moves, so no registration asked for before now saves
    // anything, any tab finishes it if this one closes, and the page shows
    // nothing. The storage and the box's registrations go under the lock,
    // after whatever registration is running, which locked does for any
    // operation; what is left here is to send the revocations, or to find
    // another tab's operation sent them first, and report either way.
    localStorage.setItem(PENDING, '1');
    localStorage.setItem(FORGOT, String(count() + 1));
    forgot = count();
    form.reset();
    hideTokens();
    status('Forgetting...');
    forgetting = true;
    locked(revokeAll).then(report);
  });

  // Another tab of this browser forgot its keys (the count moved): this
  // tab shows they are gone, and a registration it asked for before saves
  // nothing (register). Another tab registered keys for this preview
  // (the store changed): this tab shows the tokens that registration got,
  // not ones it may have revoked. A registration reads storage under the
  // lock when it runs, so nothing else matters here.
  window.addEventListener('storage', function (event) {
    if ((event.key === null || event.key === FORGOT) && count() !== forgot) {
      forgot = count();
      form.reset();
      hideTokens();
      status('Your keys were forgotten in another tab. This browser no longer holds them.');
      return;
    }
    if (!forPreview || (event.key !== null && event.key !== STORE)) return;
    // While a Forget is pending, a save by a registration that gave up
    // (register) still holds the old tokens: nothing is shown until the
    // Forget has cleared them.
    if (forgetPending()) return;
    var current = load().previews[label];
    if (!current) {
      hideTokens();
      return;
    }
    if (same(current.tokens, shownTokens)) return;
    showTokens(current.tokens);
    status('Another tab registered keys for this preview; these are its tokens now.');
  });
})();
`;
