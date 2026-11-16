// Pages koid shows in place of a preview. None uses status 502 or 504:
// CloudFront replaces those with the wake page, which is only right when the
// box itself is down.
export interface PageOptions {
	status: number;
	title: string;
	message: string;
	// Poll /__koi/health while the preview is on its way. The page reloads
	// once the preview answers, or once it reaches a state with a page of its
	// own (a failed build, say), which the reload shows. After `minutes` it
	// stops, says `timeout` and offers a refresh.
	poll?: { minutes: number; timeout: string };
	// Offer a link that loads the page again.
	refresh?: boolean;
}

// Health states in which the preview is still on its way.
const WAITING = ['building', 'stopped', 'running'];

function escapeHtml(text: string): string {
	return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

export function page(options: PageOptions): Response {
	const { poll } = options;
	const script =
		poll === undefined
			? ''
			: `<script>
(function () {
  var giveUp = Date.now() + ${poll.minutes * 60_000};
  var waiting = ${JSON.stringify(WAITING)};
  function stop() {
    document.getElementById('status').textContent = ${JSON.stringify(poll.timeout)};
    document.getElementById('refresh').hidden = false;
  }
  function again() {
    if (Date.now() > giveUp) { stop(); } else { setTimeout(check, 3000); }
  }
  function check() {
    fetch('/__koi/health', { cache: 'no-store', signal: AbortSignal.timeout(10000) })
      .then(function (r) {
        if (r.ok) { location.reload(); return; }
        return r.json().then(function (body) {
          var kind = body && body.preview;
          if (typeof kind === 'string' && waiting.indexOf(kind) < 0) { location.reload(); } else { again(); }
        });
      })
      .catch(again);
  }
  setTimeout(check, 2000);
})();
</script>`;
	const refresh =
		poll !== undefined || options.refresh === true
			? `\n  <p id="status" role="status"></p>\n  <p id="refresh"${poll !== undefined ? ' hidden' : ''}><a href="">Refresh</a></p>`
			: '';
	const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(options.title)}</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #111; color: #eee; }
  main { max-width: 36rem; padding: 2rem; }
  pre { white-space: pre-wrap; color: #f99; font-size: 13px; }
  a { color: #9cf; }
</style>
</head>
<body>
<main>
  <h1>${escapeHtml(options.title)}</h1>
  <p>${escapeHtml(options.message)}</p>${refresh}
</main>
${script}
</body>
</html>
`;
	return new Response(html, {
		status: options.status,
		headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
	});
}
