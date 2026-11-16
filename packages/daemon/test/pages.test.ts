import { describe, expect, test } from 'bun:test';
import type { PreviewView } from '../src/deployer.ts';
import { BUILD_WAIT_MINUTES, handle, START_WAIT_MINUTES } from '../src/server.ts';

// Runs a page's own script against a fake browser: elements, location,
// fetch and a manual clock. `health` says what /__koi/health answers at a
// given minute.
type Health = { status: number; preview: string } | 'error';

async function render(view: PreviewView): Promise<string> {
	return (
		await handle(
			new Request('http://127.0.0.1:7777/', { headers: { host: 'hello.previews.example.net' } }),
			{
				port: 0,
				domain: 'previews.example.net',
				deployer: { view: async () => view, ensureRunning: async () => {} },
				onVisit: () => {},
				log: () => {},
			},
		)
	).text();
}

async function browse(view: PreviewView, health: (minute: number) => Health) {
	const html = await render(view);
	const els: Record<string, { textContent: string; hidden: boolean }> = {
		status: { textContent: '', hidden: false },
		refresh: { textContent: '', hidden: true },
	};
	let now = 0;
	let timers: Array<{ at: number; fn: () => void }> = [];
	let reloads = 0;
	let checks = 0;
	const env = {
		document: { getElementById: (id: string) => els[id] },
		location: {
			reload: () => {
				reloads += 1;
			},
		},
		fetch: (path: string) => {
			if (path !== '/__koi/health') throw new Error(`unexpected fetch of ${path}`);
			checks += 1;
			const answer = health(now / 60_000);
			if (answer === 'error') return Promise.reject(new Error('network'));
			return Promise.resolve({
				ok: answer.status === 200,
				json: () => Promise.resolve({ ok: answer.status === 200, preview: answer.preview }),
			});
		},
		setTimeout: (fn: () => void, ms: number) => {
			timers.push({ at: now + ms, fn });
		},
		AbortSignal: { timeout: () => ({}) },
		Date: { now: () => now },
	};
	const start = html.indexOf('<script>');
	if (start >= 0) {
		const script = html.slice(start + 8, html.indexOf('</script>'));
		new Function(...Object.keys(env), script)(...Object.values(env));
	}
	const settle = async () => {
		for (let i = 0; i < 20; i++) await Promise.resolve();
	};
	return {
		html,
		els,
		reloads: () => reloads,
		checks: () => checks,
		// Runs the page until `minutes` have passed, or it reloads.
		async run(minutes: number) {
			const until = now + minutes * 60_000;
			await settle();
			while (reloads === 0) {
				timers.sort((a, b) => a.at - b.at);
				const next = timers[0];
				if (next === undefined || next.at > until) break;
				timers = timers.slice(1);
				now = next.at;
				next.fn();
				await settle();
			}
			if (reloads === 0) now = until;
		},
	};
}

describe('the building page', () => {
	test('keeps checking for as long as a build may take, and reloads once the preview answers', async () => {
		const page = await browse({ kind: 'building' }, (minute) =>
			minute < 170 ? { status: 503, preview: 'building' } : { status: 200, preview: 'running' },
		);
		await page.run(169);
		expect(page.reloads()).toBe(0);
		expect(page.els.refresh?.hidden).toBe(true);
		await page.run(2);
		expect(page.reloads()).toBe(1);
	});

	test('keeps checking through network errors and while the preview starts', async () => {
		const page = await browse({ kind: 'building' }, (minute) => {
			if (minute < 30) return 'error';
			if (minute < 60) return { status: 503, preview: 'stopped' };
			return { status: 200, preview: 'running' };
		});
		await page.run(59);
		expect(page.reloads()).toBe(0);
		await page.run(2);
		expect(page.reloads()).toBe(1);
	});

	test.each(['failed', 'expired', 'halted', 'unknown'])(
		'reloads as soon as the preview is %s, to show why',
		async (kind) => {
			const page = await browse({ kind: 'building' }, (minute) =>
				minute < 5 ? { status: 503, preview: 'building' } : { status: 500, preview: kind },
			);
			await page.run(4);
			expect(page.reloads()).toBe(0);
			// The next check after minute 5.
			await page.run(1.1);
			expect(page.reloads()).toBe(1);
		},
	);

	test('stops after the longest build and health check, and says so with a refresh link', async () => {
		const page = await browse({ kind: 'building' }, () => ({ status: 503, preview: 'building' }));
		await page.run(BUILD_WAIT_MINUTES - 1);
		expect(page.els.status?.textContent).toBe('');
		await page.run(2);
		const checks = page.checks();
		await page.run(60);
		expect(page.checks()).toBe(checks);
		expect(page.reloads()).toBe(0);
		expect(page.els.status?.textContent).toContain(
			`This page stopped checking after ${BUILD_WAIT_MINUTES} minutes`,
		);
		expect(page.els.refresh?.hidden).toBe(false);
		expect(page.html).toContain('<p id="refresh" hidden><a href="">Refresh</a></p>');
	});
});

describe('the starting page', () => {
	test('stops after the longest health check, and says so with a refresh link', async () => {
		const page = await browse({ kind: 'stopped' }, () => ({ status: 503, preview: 'stopped' }));
		await page.run(START_WAIT_MINUTES + 1);
		expect(page.reloads()).toBe(0);
		expect(page.els.status?.textContent).toContain(
			`did not answer within ${START_WAIT_MINUTES} minutes`,
		);
		expect(page.els.refresh?.hidden).toBe(false);
	});
});

describe('pages for a preview that is not on its way', () => {
	test.each([
		[{ kind: 'failed', error: 'x' }],
		[{ kind: 'halted' }],
		[{ kind: 'expired' }],
		[{ kind: 'unknown' }],
	] as Array<[PreviewView]>)('%o offers a refresh and does not poll', async (view) => {
		const html = await render(view);
		expect(html).toContain('<p id="refresh"><a href="">Refresh</a></p>');
		expect(html).not.toContain('<script>');
	});
});

test('the building page waits for the longest build and health check a recipe allows', () => {
	expect(BUILD_WAIT_MINUTES).toBe(210);
	expect(START_WAIT_MINUTES).toBe(30);
});
