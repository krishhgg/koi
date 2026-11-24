// The page a reviewer sees while the box is starting. CloudFront serves it as
// the error page when the box does not answer, so it carries no state of its
// own: it reads the hostname from the browser and loops. Each round it asks
// the wake API to start the box (idempotent, and it covers a box that was
// still stopping on the first request), then checks the box's health through
// CloudFront and reloads once it answers. Plain HTML, no dependencies.
export const WAKE_POLL_MS = 3000;
export const WAKE_FETCH_TIMEOUT_MS = 10_000;
export const WAKE_GIVE_UP_MS = 5 * 60 * 1000;
// A preview that answers its health check but then serves 502/504 brings the
// reviewer straight back here. After this many such bounces in a row, stop and
// say so. A visit to the wake page counts as a bounce when it comes within
// WAKE_BOUNCE_MS of a reload this page made; any later visit starts afresh.
// The window has to outlast a slow failure: CloudFront waits up to 60 s for
// the origin (origin_read_timeout in infra/modules/koi/cdn.tf) before
// answering 504, so a bounce can take that long to arrive. Two minutes leaves
// room for both.
export const WAKE_MAX_RELOADS = 3;
export const WAKE_BOUNCE_MS = 120_000;

export function wakePage(): string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Waking up koi</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #111; color: #eee; }
  main { max-width: 32rem; padding: 2rem; }
  code { color: #9cf; }
  .dot { display: inline-block; width: .6em; height: .6em; border-radius: 50%; background: #9cf; margin-right: .5em; animation: pulse 1.2s infinite; }
  .dot.err { background: #f88; animation: none; }
  @keyframes pulse { 50% { opacity: .2; } }
</style>
</head>
<body>
<main>
  <h1><span class="dot" id="dot"></span><span id="title">Waking up koi</span></h1>
  <p id="msg">The preview box is starting. This usually takes about a minute.</p>
  <p>You asked for <code id="host"></code>.</p>
</main>
<script>
(function () {
  var POLL_MS = ${WAKE_POLL_MS};
  var FETCH_TIMEOUT_MS = ${WAKE_FETCH_TIMEOUT_MS};
  var GIVE_UP_MS = ${WAKE_GIVE_UP_MS};
  var MAX_RELOADS = ${WAKE_MAX_RELOADS};
  var BOUNCE_MS = ${WAKE_BOUNCE_MS};
  var done = false;
  var host = location.hostname;
  document.getElementById('host').textContent = host;

  // When this page reloads and the preview sends the reviewer straight back
  // here, the deadline and the bounce count carry over, so a preview that keeps
  // failing cannot restart the clock or loop for ever. Any other visit (the
  // preview loaded fine and failed later, or the reviewer came back) starts
  // afresh.
  var KEY = 'koi-wake:' + host;
  var state = null;
  try { state = JSON.parse(sessionStorage.getItem(KEY) || 'null'); } catch (e) { state = null; }
  var now = Date.now();
  var bounced = state && typeof state.start === 'number' && typeof state.reloadedAt === 'number'
    && now - state.reloadedAt < BOUNCE_MS;
  if (!bounced) {
    state = { start: now, reloads: 0, reloadedAt: null };
  }
  function save() { try { sessionStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {} }
  save();

  function show(title, msg, isError) {
    document.getElementById('dot').className = isError ? 'dot err' : 'dot';
    document.getElementById('title').textContent = title;
    document.getElementById('msg').textContent = msg;
  }

  function stop(title, msg) {
    done = true;
    show(title, msg, true);
  }

  // Every request carries its own timeout, so one that stalls cannot stop the
  // loop, and the overall deadline fires on its own timer whatever the
  // requests are doing.
  function get(path) {
    return fetch(path, { cache: 'no-store', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  }

  setTimeout(function () {
    if (!done) { stop('Still not up', 'The box is taking longer than expected. Reload to keep waiting.'); }
  }, Math.max(0, state.start + GIVE_UP_MS - now));

  function round() {
    if (done) { return; }
    get('/__koi-wake/wake?host=' + encodeURIComponent(host))
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (done) { return; }
        // known === false is final (no such preview, or not a preview
        // address); an error without it is temporary and worth retrying.
        if (j.known !== false && j.error) { setTimeout(round, POLL_MS); return; }
        if (!j.known) {
          stop('No preview here', 'Nothing is deployed at this address. Ask the author to run koi up.');
          return;
        }
        return get('/__koi/health')
          .then(function (r) { return r.ok; }, function () { return false; })
          .then(function (ok) {
            if (done) { return; }
            if (!ok) { setTimeout(round, POLL_MS); return; }
            if (state.reloads >= MAX_RELOADS) {
              stop('The preview is not answering', 'The box is up, but the preview keeps failing to load. Ask the author to check koi logs.');
              return;
            }
            state.reloads += 1;
            state.reloadedAt = Date.now();
            save();
            done = true;
            location.reload();
          });
      })
      .catch(function () { if (!done) { setTimeout(round, POLL_MS); } });
  }

  round();
})();
</script>
</body>
</html>
`;
}
