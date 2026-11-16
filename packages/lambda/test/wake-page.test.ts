import { describe, expect, test } from 'bun:test';
import {
	WAKE_BOUNCE_MS,
	WAKE_FETCH_TIMEOUT_MS,
	WAKE_GIVE_UP_MS,
	WAKE_MAX_RELOADS,
	WAKE_POLL_MS,
	wakePage,
} from '../src/wake-page.ts';

// Runs the page's own script against a fake browser: elements, location,
// fetch and a manual clock. Each test scripts what the wake API and the health
// check answer, then advances time and checks what the reviewer would see.

type Reply = { ok: boolean; json?: unknown } | 'stall' | 'error';

interface Harness {
	els: Record<string, { className: string; textContent: string }>;
	calls: string[];
	reloads: () => number;
	advance: (ms: number) => Promise<void>;
}

// The page's script in a fake browser. `session` stands in for sessionStorage
// and can be shared between runs to simulate the page being reloaded.
function harness(
	answer: (path: string, call: number) => Reply,
	session: Map<string, string> = new Map(),
	startAt = 0,
): Harness {
	const els: Record<string, { className: string; textContent: string }> = {};
	for (const id of ['dot', 'title', 'msg', 'host']) els[id] = { className: 'dot', textContent: '' };
	let now = startAt;
	let timers: Array<{ at: number; fn: () => void }> = [];
	const calls: string[] = [];
	let reloads = 0;
	const later = (ms: number, fn: () => void) => {
		timers.push({ at: now + ms, fn });
	};

	// AbortSignal.timeout on the fake clock: aborts after `ms`.
	const timeout = (ms: number) => {
		const signal = { aborted: false, listeners: [] as Array<() => void> };
		later(ms, () => {
			signal.aborted = true;
			for (const l of signal.listeners) l();
		});
		return signal;
	};

	const fakeFetch = (path: string, init: { signal?: ReturnType<typeof timeout> } = {}) => {
		const name = path.split('?')[0] ?? path;
		const reply = answer(path, calls.filter((c) => c === name).length);
		calls.push(name);
		if (reply === 'error') return Promise.reject(new Error('network'));
		if (reply === 'stall') {
			// Never answers; rejects only when its signal aborts.
			return new Promise((_resolve, reject) => {
				init.signal?.listeners.push(() => reject(new Error('aborted')));
			});
		}
		return Promise.resolve({ ok: reply.ok, json: () => Promise.resolve(reply.json) });
	};
	const env = {
		document: { getElementById: (id: string) => els[id] },
		location: {
			hostname: 'hello.previews.example.net',
			reload: () => {
				reloads += 1;
			},
		},
		fetch: fakeFetch,
		setTimeout: (fn: () => void, ms: number) => later(ms, fn),
		AbortSignal: { timeout },
		sessionStorage: {
			getItem: (k: string) => session.get(k) ?? null,
			setItem: (k: string, v: string) => {
				session.set(k, v);
			},
		},
		Date: { now: () => now },
	};

	const html = wakePage();
	const script = html.slice(html.indexOf('<script>') + 8, html.indexOf('</script>'));
	new Function(...Object.keys(env), script)(...Object.values(env));

	const settle = async () => {
		for (let i = 0; i < 20; i++) await Promise.resolve();
	};

	return {
		els,
		calls,
		reloads: () => reloads,
		async advance(ms: number) {
			const until = now + ms;
			await settle();
			for (;;) {
				timers.sort((a, b) => a.at - b.at);
				const next = timers[0];
				if (next === undefined || next.at > until) break;
				timers = timers.slice(1);
				now = next.at;
				next.fn();
				await settle();
			}
			now = until;
		},
	};
}

describe('wake page script', () => {
	test('keeps calling wake until a stopping box comes back, then reloads', async () => {
		const states = ['stopping', 'stopping', 'pending', 'running'];
		const h = harness((path, n) => {
			if (path.startsWith('/__koi-wake/wake')) {
				return { ok: true, json: { known: true, instance: states[n] ?? 'running' } };
			}
			return { ok: n >= 3 };
		});
		await h.advance(WAKE_POLL_MS * 6);
		expect(h.calls.filter((c) => c === '/__koi-wake/wake').length).toBeGreaterThanOrEqual(4);
		expect(h.reloads()).toBe(1);
		expect(h.els.title?.textContent).toBe('');
	});

	test('stops and says so when there is no preview at the address', async () => {
		const h = harness(() => ({ ok: false, json: { known: false } }));
		await h.advance(WAKE_POLL_MS * 5);
		expect(h.els.title?.textContent).toBe('No preview here');
		expect(h.els.dot?.className).toBe('dot err');
		expect(h.calls).toEqual(['/__koi-wake/wake']);
	});

	test('gives up at the deadline even when a request never answers', async () => {
		const h = harness(() => 'stall');
		await h.advance(WAKE_GIVE_UP_MS - 1);
		expect(h.els.title?.textContent).toBe('');
		await h.advance(2);
		expect(h.els.title?.textContent).toBe('Still not up');
		expect(h.reloads()).toBe(0);
	});

	test('retries after network errors and stops polling once it gives up', async () => {
		const h = harness(() => 'error');
		await h.advance(WAKE_GIVE_UP_MS + WAKE_POLL_MS * 3);
		expect(h.els.title?.textContent).toBe('Still not up');
		const atGiveUp = h.calls.length;
		await h.advance(WAKE_POLL_MS * 10);
		expect(h.calls.length).toBe(atGiveUp);
	});

	test('aborts a hung request and tries again well before the deadline', async () => {
		let first = true;
		const h = harness((path) => {
			if (path.startsWith('/__koi-wake/wake') && first) {
				first = false;
				return 'stall';
			}
			return path.startsWith('/__koi-wake/wake')
				? { ok: true, json: { known: true, instance: 'pending' } }
				: { ok: false };
		});
		await h.advance(WAKE_FETCH_TIMEOUT_MS + WAKE_POLL_MS + 10);
		expect(h.calls.filter((c) => c === '/__koi-wake/wake').length).toBeGreaterThanOrEqual(2);
		expect(h.els.title?.textContent).toBe('');
	});

	test('retries when the wake API says to', async () => {
		let n = 0;
		const h = harness((path) =>
			path.startsWith('/__koi-wake/wake')
				? {
						ok: false,
						json: n++ === 0 ? { error: 'try again' } : { known: true, instance: 'running' },
					}
				: { ok: true },
		);
		await h.advance(WAKE_POLL_MS * 3);
		expect(h.reloads()).toBe(1);
	});

	test('a preview that keeps failing after health says ok stops reloading', async () => {
		const session = new Map<string, string>();
		const healthy = () => ({ ok: true, json: { known: true, instance: 'running' } });
		for (let i = 0; i < WAKE_MAX_RELOADS; i++) {
			const h = harness(healthy, session, i * 1000);
			await h.advance(100);
			expect(h.reloads()).toBe(1);
		}
		const last = harness(healthy, session, WAKE_MAX_RELOADS * 1000);
		await last.advance(100);
		expect(last.reloads()).toBe(0);
		expect(last.els.title?.textContent).toBe('The preview is not answering');
	});

	test('the deadline carries over a bounce instead of starting again', async () => {
		const session = new Map<string, string>();
		const healthy = () => ({ ok: true, json: { known: true, instance: 'running' } });
		const h1 = harness(healthy, session, 0);
		await h1.advance(100);
		expect(h1.reloads()).toBe(1);
		// The preview bounced the reviewer straight back, and now nothing answers.
		const h2 = harness(() => 'stall', session, 1000);
		await h2.advance(WAKE_GIVE_UP_MS - 1000 + 1);
		expect(h2.els.title?.textContent).toBe('Still not up');
	});

	test('a slow failure (a 504 after CloudFront waits 60 s) still counts as a bounce', async () => {
		const session = new Map<string, string>();
		const healthy = () => ({ ok: true, json: { known: true, instance: 'running' } });
		let at = 0;
		for (let i = 0; i < WAKE_MAX_RELOADS; i++) {
			const h = harness(healthy, session, at);
			await h.advance(100);
			expect(h.reloads()).toBe(1);
			at += 61_000;
		}
		const last = harness(healthy, session, at);
		await last.advance(100);
		expect(last.reloads()).toBe(0);
		expect(last.els.title?.textContent).toBe('The preview is not answering');
	});

	test('a visit long after the last reload starts afresh', async () => {
		const session = new Map<string, string>();
		const healthy = () => ({ ok: true, json: { known: true, instance: 'running' } });
		for (let i = 0; i < WAKE_MAX_RELOADS + 2; i++) {
			// Each visit comes well after the previous reload: the preview had
			// loaded fine in between.
			const h = harness(healthy, session, i * (WAKE_BOUNCE_MS + 1000));
			await h.advance(100);
			expect(h.reloads()).toBe(1);
		}
	});

	test('stops at once for an address that is not a preview', async () => {
		const h = harness(() => ({
			ok: false,
			json: { known: false, error: 'host is not a preview address' },
		}));
		await h.advance(WAKE_POLL_MS * 3);
		expect(h.els.title?.textContent).toBe('No preview here');
		expect(h.calls).toEqual(['/__koi-wake/wake']);
	});
});
