import { describe, expect, test } from 'bun:test';
import type { PreviewView } from '../src/deployer.ts';
import { DAEMON_VERSION, handle } from '../src/server.ts';

function options(view: PreviewView) {
	const visits: string[] = [];
	const started: string[] = [];
	return {
		visits,
		started,
		opts: {
			port: 0,
			domain: 'previews.example.net',
			deployer: {
				view: async () => view,
				ensureRunning: async (label: string) => {
					started.push(label);
				},
			},
			onVisit: (label: string) => visits.push(label),
			log: () => {},
		},
	};
}

const req = (path: string, host = 'hello.previews.example.net') =>
	new Request(`http://127.0.0.1:7777${path}`, { headers: { host } });

describe('health', () => {
	test('reports the box healthy for a non-preview host', async () => {
		const { opts } = options({ kind: 'unknown' });
		const res = await handle(req('/__koi/health', 'origin.previews.example.net.evil'), opts);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true, version: DAEMON_VERSION });
	});

	test('is ok only when the preview is running, and wakes a stopped one', async () => {
		const running = options({ kind: 'running' });
		expect((await handle(req('/__koi/health'), running.opts)).status).toBe(200);
		const stopped = options({ kind: 'stopped' });
		expect((await handle(req('/__koi/health'), stopped.opts)).status).toBe(503);
		expect(stopped.started).toEqual(['hello']);
		expect((await handle(req('/__koi/health'), options({ kind: 'unknown' }).opts)).status).toBe(
			404,
		);
	});
});

describe('fallback pages', () => {
	const cases: Array<[PreviewView, number, string]> = [
		[{ kind: 'unknown' }, 404, 'No preview here'],
		[{ kind: 'expired' }, 410, 'expired'],
		[{ kind: 'overdue' }, 410, 'expired'],
		[{ kind: 'halted' }, 507, 'stopped for using too much disk'],
		[{ kind: 'failed', error: 'secret build output' }, 500, 'The build failed'],
		[{ kind: 'building' }, 503, 'Building'],
		[{ kind: 'stopped' }, 503, 'Starting the preview'],
		[{ kind: 'running' }, 503, 'Starting the preview'],
	];

	test.each(cases)('%o -> %i', async (view, status, text) => {
		const { opts } = options(view);
		const res = await handle(req('/some/page'), opts);
		expect(res.status).toBe(status);
		const body = await res.text();
		expect(body).toContain(text);
		expect(body).not.toContain('secret build output');
	});

	test('wakes a stopped preview, expires an overdue one, and leaves the rest alone', async () => {
		for (const [view] of cases) {
			const { opts, started } = options(view);
			await handle(req('/'), opts);
			const wakes = view.kind === 'stopped' || view.kind === 'overdue';
			expect(started).toEqual(wakes ? ['hello'] : []);
		}
	});

	test('never answers 502 or 504, which CloudFront would replace with the wake page', async () => {
		for (const [view] of cases) {
			const { opts } = options(view);
			const status = (await handle(req('/'), opts)).status;
			expect([502, 504]).not.toContain(status);
		}
	});

	test('records a visit for preview hosts only', async () => {
		const { opts, visits } = options({ kind: 'running' });
		await handle(req('/'), opts);
		await handle(req('/', 'previews.example.net'), opts);
		await handle(req('/', 'a.b.previews.example.net'), opts);
		expect(visits).toEqual(['hello']);
	});

	test('rejects hosts that are not preview addresses', async () => {
		const { opts } = options({ kind: 'running' });
		const res = await handle(req('/', 'evil.example'), opts);
		expect(res.status).toBe(404);
		expect(await res.text()).toContain('Not a preview address');
	});

	test('names the configured domain, not a built-in one, in that refusal', async () => {
		const { opts } = options({ kind: 'running' });
		const res = await handle(req('/', 'evil.example'), { ...opts, domain: 'previews.example.com' });
		expect(res.status).toBe(404);
		expect(await res.text()).toContain('name.previews.example.com');
	});
});

describe('koi pages', () => {
	test('keys.<domain> goes to the keys page, never to a preview, and is not a visit', async () => {
		const { opts, visits, started } = options({ kind: 'unknown' });
		const seen: string[] = [];
		const withPages = {
			...opts,
			pages: {
				keys: async (request: Request) => {
					seen.push(new URL(request.url).pathname);
					return new Response('keys page');
				},
			},
		};
		const res = await handle(req('/', 'keys.previews.example.net'), withPages);
		expect(await res.text()).toBe('keys page');
		await handle(req('/api/register', 'keys.previews.example.net'), withPages);
		expect(seen).toEqual(['/', '/api/register']);
		expect(visits).toEqual([]);
		expect(started).toEqual([]);
	});

	test('health on keys.<domain> reports the box, so the wake page reloads into the keys page', async () => {
		const { opts } = options({ kind: 'unknown' });
		const res = await handle(req('/__koi/health', 'keys.previews.example.net'), opts);
		expect(res.status).toBe(200);
		expect(((await res.json()) as { ok: boolean }).ok).toBe(true);
	});
});
