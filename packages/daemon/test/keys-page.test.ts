import { describe, expect, test } from 'bun:test';
import { PROVIDERS } from '@koi/shared';
import { KEYS_JS } from '../src/keys.ts';

// The keys page's script, run against a small stand-in for the browser: the
// elements it uses, localStorage, fetch answered by the test, timers the
// test fires, a clock the test moves, the visibility and storage events the
// test raises, and the Web Locks API. A Browser is one tab; the tabs of one
// browser share a Shared: storage, the lock, and the box's token for each
// key.

class El {
	hidden = false;
	className = '';
	type = '';
	value = '';
	name = '';
	visibilityState = 'visible';
	children: unknown[] = [];
	listeners: Record<string, Array<(event: unknown) => void>> = {};
	private text = '';
	get textContent(): string {
		return (
			this.text + this.children.map((c) => (c instanceof El ? c.textContent : String(c))).join('')
		);
	}
	set textContent(value: string) {
		this.text = value;
		this.children = [];
	}
	addEventListener(type: string, fn: (event: unknown) => void) {
		this.listeners[type] = [...(this.listeners[type] ?? []), fn];
	}
	append(...items: unknown[]) {
		this.children.push(...items);
	}
	fire(type: string, event: unknown = { preventDefault() {} }) {
		for (const fn of this.listeners[type] ?? []) fn(event);
	}
}

interface Call {
	tab: string;
	path: string;
	body: Record<string, unknown>;
}

// Answers: a status and JSON body, or 'offline' for a fetch that fails.
type Answer = { status: number; body: unknown } | 'offline';

// navigator.locks, as far as the page uses it: one callback at a time per
// browser, in the order asked.
class Locks {
	private chain: Promise<unknown> = Promise.resolve();
	// A tab that closed before its turn never gets it, and nothing of its
	// runs again: the browser drops its request, and its promise never
	// settles.
	request(name: string, callback: (lock: unknown) => unknown, tab: Browser): Promise<unknown> {
		let settle: (result: unknown) => void = () => {};
		const result = new Promise<unknown>((resolve) => {
			settle = resolve;
		});
		const turn = this.chain.then(async () => {
			if (tab.closed) return;
			settle(await callback({ name }));
		});
		this.chain = turn.catch(() => {});
		return result;
	}
}

class Shared {
	storage = new Map<string, string>();
	known = new Map<string, string>();
	made = 0;
	calls: Call[] = [];
	locks = new Locks();
}

class Browser {
	timers: Array<() => void> = [];
	now = 1_700_000_000_000;
	copied: string[] = [];
	// How the box answers each call; the default accepts everything.
	answer: (call: Call) => Answer | Promise<Answer> = (call) => ({
		status: 200,
		body: call.path === '/api/register' ? { tokens: this.tokensFor(call) } : { ok: true },
	});
	page!: Record<string, El>;
	inputs!: El[];
	document!: El;
	window!: El;
	closed = false;

	constructor(
		readonly shared = new Shared(),
		readonly tab = 'a',
	) {}

	get storage() {
		return this.shared.storage;
	}
	get calls() {
		return this.shared.calls.filter((c) => c.tab === this.tab);
	}

	// Tells the fake box that key is registered already with this token.
	know(provider: string, key: string, token: string) {
		this.shared.known.set(`${provider}:${key}`, token);
	}

	// The box's tokens for a registration: the same token for the same key.
	tokensFor(call: Call): Record<string, string> {
		const keys = call.body.keys as Record<string, string>;
		return Object.fromEntries(
			Object.entries(keys).map(([p, key]) => {
				let token = this.shared.known.get(`${p}:${key}`);
				if (token === undefined) {
					this.shared.made += 1;
					token = `koi_${String(this.shared.made).padStart(32, '0')}`;
					this.shared.known.set(`${p}:${key}`, token);
				}
				return [p, token];
			}),
		);
	}

	// Loads the page, as a new visit with this browser's storage. Without
	// locks, the page finds no Web Locks API and queues within the tab.
	open(label = 'storefront-pr-7', { locks = true } = {}) {
		const ids = [
			'keys',
			'token-box',
			'tokens',
			'status',
			'no-preview',
			'for-preview',
			'label',
			'forget',
		];
		this.page = Object.fromEntries(ids.map((id) => [id, new El()]));
		this.inputs = PROVIDERS.map((p) => Object.assign(new El(), { name: p.id }));
		const form = this.page.keys as El & { elements: unknown; reset: () => void };
		form.elements = Object.assign(
			[...this.inputs, new El()],
			Object.fromEntries(this.inputs.map((i) => [i.name, i])),
		);
		form.reset = () => {
			for (const i of this.inputs) i.value = '';
		};
		this.document = Object.assign(new El(), {
			title: '',
			getElementById: (id: string) => this.page[id],
			createElement: () => new El(),
		});
		this.window = new El();
		const localStorage = {
			getItem: (k: string) => this.storage.get(k) ?? null,
			setItem: (k: string, v: string) => void this.storage.set(k, v),
			removeItem: (k: string) => void this.storage.delete(k),
		};
		const fetch = async (path: string, init: { body: string }) => {
			const call = { tab: this.tab, path, body: JSON.parse(init.body) };
			this.shared.calls.push(call);
			const a = await this.answer(call);
			if (a === 'offline') throw new TypeError('Failed to fetch');
			return { ok: a.status < 300, status: a.status, json: async () => a.body };
		};
		const setTimeout = (fn: () => void) => this.timers.push(fn);
		new Function(
			'document',
			'window',
			'localStorage',
			'fetch',
			'location',
			'navigator',
			'setTimeout',
			'Date',
			KEYS_JS,
		)(
			this.document,
			this.window,
			localStorage,
			fetch,
			{ search: `?for=${label}` },
			{
				clipboard: {
					writeText: async (text: string) => {
						this.copied.push(text);
					},
				},
				...(locks
					? {
							locks: {
								request: (name: string, callback: (lock: unknown) => unknown) =>
									this.shared.locks.request(name, callback, this),
							},
						}
					: {}),
			},
			setTimeout,
			{ now: () => this.now },
		);
	}

	saved() {
		const raw = this.storage.get('koi.keys');
		return raw === undefined ? undefined : JSON.parse(raw);
	}
	status() {
		return this.page.status?.textContent ?? '';
	}
	// The tokens shown, as the box gave them: without the prefix the page
	// shows before some providers' tokens (see pasted).
	shown() {
		return this.pasted().map((t) => t.replace(/^(sk-ant-|sk-|xai-)(?=koi_)/, ''));
	}
	// The tokens as shown, to be pasted into nodes.
	pasted() {
		const list = this.page.tokens;
		if (list === undefined || this.page['token-box']?.hidden) return [];
		return list.children.map((item) => (item as El).children[1]).map((c) => (c as El).textContent);
	}
	// Clicks the Copy button of the token in this row.
	copy(row: number) {
		const item = this.page.tokens?.children[row] as El;
		(item.children[3] as El).fire('click');
	}
	register(keys: Record<string, string>) {
		for (const i of this.inputs) i.value = keys[i.name] ?? '';
		this.page.keys?.fire('submit');
	}
	forget() {
		this.page.forget?.fire('click');
	}
	// The tab becomes visible again.
	visible() {
		this.document.visibilityState = 'visible';
		this.document.fire('visibilitychange');
	}
	// Another tab changed this browser's storage (browsers raise this event
	// in every tab but the one that wrote).
	storageChanged(key: string | null = 'koi.keys.forgot') {
		this.window.fire('storage', { key });
	}
	// The tab closes: whatever it queued for the lock is dropped.
	close() {
		this.closed = true;
		this.timers.splice(0);
	}
	// Fires the timers set so far.
	tick() {
		const due = this.timers.splice(0);
		for (const fn of due) fn();
	}
	registered() {
		return this.calls.filter((c) => c.path === '/api/register').map((c) => c.body.keys);
	}
	forgotten() {
		return this.calls.filter((c) => c.path === '/api/forget').map((c) => c.body.token);
	}
}

const settle = async () => {
	for (let i = 0; i < 5; i++) await Bun.sleep(1);
};

// An answer the test gives when it chooses.
function later() {
	let give: (a: Answer) => void = () => {};
	const answer = new Promise<Answer>((resolve) => {
		give = resolve;
	});
	return { answer, give };
}

const LABEL = 'storefront-pr-7';
const OTHER = 'storefront-pr-8';
const T1 = `koi_${'1'.repeat(32)}`;
const T2 = `koi_${'2'.repeat(32)}`;
const T3 = `koi_${'3'.repeat(32)}`;
const MINUTE = 60_000;
const AGAIN = 'Keys registered again, in case the koi box slept. Your tokens are unchanged.';
const FORGOTTEN = 'Forgotten. This browser and the koi box no longer hold your keys.';
const FORGOTTEN_ELSEWHERE =
	'Your keys were forgotten in another tab. This browser no longer holds them.';
const HELD =
	'Your tokens for this preview. They keep working after the koi box sleeps: this page registers your keys again whenever you open or return to it.';

// What the page saves: the keys last registered anywhere, and each
// preview's last registration.
const state = (
	keys: Record<string, string>,
	previews: Record<string, { keys: Record<string, string>; tokens: Record<string, string> }>,
	revoke: string[] = [],
) => ({ keys, previews, revoke });

// A browser whose last visit registered the given keys for LABEL, and whose
// box knows the tokens it got.
function returning(
	keys: Record<string, string> = { openai: 'sk-1' },
	tokens: Record<string, string> = { openai: T1 },
	shared?: Shared,
) {
	const b = new Browser(shared);
	b.storage.set('koi.keys', JSON.stringify(state(keys, { [LABEL]: { keys, tokens } })));
	for (const p of Object.keys(keys)) b.know(p, keys[p] as string, tokens[p] as string);
	return b;
}

describe('registering again on its own', () => {
	test('a visit registers the keys held again, gets the same tokens, and says so', async () => {
		const b = returning();
		b.open();
		expect(b.shown()).toEqual([T1]);
		expect(b.status()).toBe(HELD);
		await settle();
		expect(b.registered()).toEqual([{ openai: 'sk-1' }]);
		expect(b.forgotten()).toEqual([]);
		expect(b.status()).toBe(AGAIN);
		expect(b.page.status?.className).toBe('');
		expect(b.shown()).toEqual([T1]);
		expect(b.saved()).toEqual(
			state({ openai: 'sk-1' }, { [LABEL]: { keys: { openai: 'sk-1' }, tokens: { openai: T1 } } }),
		);
	});

	test('and when its tab becomes visible, but not within a minute of the last registration', async () => {
		const b = returning();
		b.open();
		await settle();
		b.now += MINUTE / 2;
		b.visible();
		await settle();
		expect(b.registered()).toHaveLength(1);
		b.now += MINUTE / 2 + 1;
		b.visible();
		await settle();
		expect(b.registered()).toHaveLength(2);
		expect(b.status()).toBe(AGAIN);
		// A reload within the minute registers nothing either.
		const again = new Browser(b.shared, 'b');
		again.open();
		await settle();
		expect(again.registered()).toEqual([]);
		expect(again.shown()).toEqual([T1]);
		expect(again.status()).toBe(HELD);
	});

	test('two tabs that open, or come back, at the same time send one registration between them', async () => {
		// The check of the last registration's time and
		// the mark of this one happen under the lock, so the second tab finds
		// the first's mark.
		const a = returning();
		const b = new Browser(a.shared, 'b');
		a.open();
		b.open();
		await settle();
		expect(a.shared.calls.filter((c) => c.path === '/api/register')).toHaveLength(1);
		expect(a.status()).toBe(AGAIN);
		expect(b.status()).toBe(HELD);
		a.now = b.now = a.now + MINUTE + 1;
		b.visible();
		a.visible();
		await settle();
		expect(a.shared.calls.filter((c) => c.path === '/api/register')).toHaveLength(2);
		expect(b.status()).toBe(AGAIN);
	});

	test('a browser with no registration for this preview registers nothing', async () => {
		const b = new Browser();
		b.storage.set(
			'koi.keys',
			JSON.stringify(
				state(
					{ openai: 'sk-1' },
					{ [OTHER]: { keys: { openai: 'sk-1' }, tokens: { openai: T1 } } },
				),
			),
		);
		b.open();
		b.visible();
		await settle();
		expect(b.registered()).toEqual([]);
		expect(b.shown()).toEqual([]);
		expect(b.inputs.find((i) => i.name === 'openai')?.value).toBe('sk-1');
	});

	test('each preview registers the keys last registered for it, not those of another preview', async () => {
		// Key A for preview A, then key B for preview B
		// in another tab, then back to A after a minute.
		const a = returning();
		a.open();
		await settle();
		const b = new Browser(a.shared, 'b');
		b.open(OTHER);
		b.register({ openai: 'sk-B' });
		await settle();
		expect(b.saved().keys).toEqual({ openai: 'sk-B' });
		a.now += MINUTE + 1;
		a.visible();
		await settle();
		expect(a.registered()).toEqual([{ openai: 'sk-1' }, { openai: 'sk-1' }]);
		expect(a.status()).toBe(AGAIN);
		expect(a.shared.calls.filter((c) => c.path === '/api/forget')).toEqual([]);
		expect(a.saved().previews).toEqual({
			[LABEL]: { keys: { openai: 'sk-1' }, tokens: { openai: T1 } },
			[OTHER]: { keys: { openai: 'sk-B' }, tokens: { openai: `koi_${'0'.repeat(31)}1` } },
		});
		// The form of a fresh page for a third preview offers the keys last
		// registered anywhere.
		const c = new Browser(a.shared, 'c');
		c.open('storefront-pr-9');
		expect(c.inputs.find((i) => i.name === 'openai')?.value).toBe('sk-B');
	});

	test('tokens from an earlier version of this page are shown and revoked, but not registered again', async () => {
		const b = new Browser();
		b.storage.set(
			'koi.keys',
			JSON.stringify({ keys: { openai: 'sk-1' }, tokens: { [LABEL]: { openai: T1 } } }),
		);
		b.open();
		b.visible();
		await settle();
		expect(b.shown()).toEqual([T1]);
		expect(b.registered()).toEqual([]);
		expect(b.status()).toContain('Register your keys once more');
		b.know('openai', 'sk-1', T2);
		b.register({ openai: 'sk-1' });
		await settle();
		expect(b.forgotten()).toEqual([T1]);
		expect(b.saved()).toEqual(
			state({ openai: 'sk-1' }, { [LABEL]: { keys: { openai: 'sk-1' }, tokens: { openai: T2 } } }),
		);
	});

	test('a token the box changed replaces the old one, which is revoked, and the page names its provider', async () => {
		// The box's secret changed: sk-1 no longer gives T1.
		const b = returning();
		b.know('openai', 'sk-1', T2);
		b.open();
		await settle();
		expect(b.shown()).toEqual([T2]);
		expect(b.status()).toBe(
			'The koi box gave a new token for OpenAI. Paste it into the preview in place of the old one; the rest are unchanged.',
		);
		expect(b.page.status?.className).toBe('err');
		expect(b.forgotten()).toEqual([T1]);
		expect(b.saved()).toEqual(
			state({ openai: 'sk-1' }, { [LABEL]: { keys: { openai: 'sk-1' }, tokens: { openai: T2 } } }),
		);
	});

	test('only the providers whose token changed are named, and all of them are', async () => {
		const keys = { openai: 'sk-1', anthropic: 'sk-2', groq: 'sk-3' };
		const b = returning(keys, { openai: T1, anthropic: T2, groq: T3 });
		const t4 = `koi_${'4'.repeat(32)}`;
		const t5 = `koi_${'5'.repeat(32)}`;
		b.know('anthropic', 'sk-2', t4);
		b.know('groq', 'sk-3', t5);
		b.open();
		await settle();
		expect(b.status()).toBe(
			'The koi box gave new tokens for Anthropic and Groq. Paste them into the preview in place of the old ones; the rest are unchanged.',
		);
		expect(b.shown()).toEqual([T1, t4, t5]);
		expect(b.forgotten().sort()).toEqual([T2, T3].sort());
		expect(b.saved().previews[LABEL].tokens).toEqual({ openai: T1, anthropic: t4, groq: t5 });
		// Unchanged tokens keep the status green and say nothing of pasting.
		b.now += MINUTE + 1;
		b.visible();
		await settle();
		expect(b.status()).toBe(AGAIN);
		expect(b.page.status?.className).toBe('');
		expect(b.status()).not.toContain('aste');
	});

	test("tokens are shown and copied after their provider's key prefix, so nodes that check it take them", async () => {
		const keys = { openai: 'sk-1', anthropic: 'sk-2', groq: 'sk-3' };
		const b = returning(keys, { openai: T1, anthropic: T2, groq: T3 });
		b.open();
		await settle();
		expect(b.pasted()).toEqual([`sk-${T1}`, `sk-ant-${T2}`, T3]);
		b.copy(1);
		expect(b.copied).toEqual([`sk-ant-${T2}`]);
		// The box gets and keeps the tokens without.
		expect(b.saved().previews[LABEL].tokens).toEqual({ openai: T1, anthropic: T2, groq: T3 });
	});

	test('a failed registration keeps the tokens shown and tries again on the next visit', async () => {
		const b = returning();
		const accept = b.answer;
		b.answer = () => 'offline';
		b.open();
		await settle();
		expect(b.status()).toBe(
			'Could not register your keys again: the koi box could not be reached (Failed to fetch). This page tries again when you return to it.',
		);
		expect(b.page.status?.className).toBe('err');
		expect(b.shown()).toEqual([T1]);
		expect(b.saved().previews[LABEL].tokens).toEqual({ openai: T1 });
		// A reply without tokens (the box is waking up) is a failure too.
		b.answer = () => ({ status: 200, body: {} });
		b.now += MINUTE + 1;
		b.visible();
		await settle();
		expect(b.status()).toContain('Could not register your keys again: the koi box sent no tokens');
		expect(b.saved().previews[LABEL].tokens).toEqual({ openai: T1 });
		b.answer = accept;
		b.now += MINUTE + 1;
		b.visible();
		await settle();
		expect(b.status()).toBe(AGAIN);
		expect(b.registered()).toHaveLength(3);
	});

	test('registering the same keys by hand gives the same tokens and revokes nothing', async () => {
		const b = returning();
		b.open();
		await settle();
		b.register({ openai: 'sk-1' });
		await settle();
		expect(b.registered()).toEqual([{ openai: 'sk-1' }, { openai: 'sk-1' }]);
		expect(b.forgotten()).toEqual([]);
		expect(b.shown()).toEqual([T1]);
		expect(b.status()).toBe(
			'Registered. Paste these tokens into the preview. They keep working after the koi box sleeps: this page registers your keys again whenever you open or return to it.',
		);
		expect(b.saved().revoke).toEqual([]);
	});
});

describe('Forget against registering', () => {
	test('Forget while the page is registering again revokes the tokens the reply brings', async () => {
		const b = returning();
		const reply = later();
		const accept = b.answer;
		b.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		b.open();
		await settle();
		b.forget();
		await settle();
		expect(b.shown()).toEqual([]);
		expect(b.forgotten()).toEqual([]);
		reply.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(b.forgotten()).toEqual([T1]);
		expect(b.saved()).toBeUndefined();
		expect(b.status()).toBe(FORGOTTEN);
		// Nothing is held, so nothing registers again.
		b.now += MINUTE + 1;
		b.visible();
		await settle();
		expect(b.registered()).toHaveLength(1);
	});

	test('Forget during a registration of this tab says "Forgotten" only once the box confirms', async () => {
		// The registration's reply comes after the Forget: it revokes what it
		// got, finds nothing left, and must not report for the Forget, whose
		// own revocations the box then refuses.
		const b = returning();
		const reply = later();
		const accept = b.answer;
		b.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		b.open();
		await settle();
		b.forget();
		b.answer = () => ({ status: 503, body: { error: 'the key proxy is not available' } });
		reply.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(b.forgotten()).toEqual([T1]);
		expect(b.status()).toContain('has not confirmed it forgot 1 of your tokens');
		expect(b.status()).not.toContain('Forgotten.');
		expect(b.page.status?.className).toBe('err');
		expect(b.saved()).toEqual(state({}, {}, [T1]));
		b.answer = accept;
		b.tick();
		await settle();
		expect(b.forgotten()).toEqual([T1, T1]);
		expect(b.saved()).toBeUndefined();
		expect(b.status()).toBe(FORGOTTEN);
	});

	test('Forget before a queued registration starts sends no keys', async () => {
		const b = returning();
		const slow = later();
		const accept = b.answer;
		b.answer = (call) => (call.path === '/api/register' ? slow.answer : accept(call));
		b.open();
		await settle();
		// A minute on, the tab comes back while the first registration is
		// still under way: the second waits behind it.
		b.now += MINUTE + 1;
		b.visible();
		await settle();
		b.forget();
		slow.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(b.registered()).toEqual([{ openai: 'sk-1' }]);
		expect(b.forgotten()).toEqual([T1]);
		expect(b.saved()).toBeUndefined();
		expect(b.status()).toBe(FORGOTTEN);
	});

	test('a Forget in another tab stops this one registering again and clears what it shows', async () => {
		const a = returning();
		a.open();
		await settle();
		expect(a.shown()).toEqual([T1]);
		const b = new Browser(a.shared, 'b');
		b.open();
		b.forget();
		await settle();
		expect(b.forgotten()).toEqual([T1]);
		expect(b.status()).toBe(FORGOTTEN);
		a.storageChanged();
		expect(a.shown()).toEqual([]);
		expect(a.inputs.every((i) => i.value === '')).toBe(true);
		expect(a.status()).toBe(FORGOTTEN_ELSEWHERE);
		a.now += MINUTE + 1;
		a.visible();
		await settle();
		expect(a.registered()).toHaveLength(1);
		expect(a.saved()).toBeUndefined();
		// Other changes in other tabs change nothing here.
		a.storageChanged('koi.keys');
		a.storageChanged('koi.keys.sent');
		a.storageChanged();
		expect(a.status()).toBe(FORGOTTEN_ELSEWHERE);
	});

	test('a Forget in another tab wins against a registration under way here, whether this tab held keys or not', async () => {
		// A tab opened while the browser held nothing
		// makes its first registration while another tab, which registered
		// keys since, forgets. The count of Forgets in storage moved, so the
		// reply is revoked and nothing saved.
		const a = new Browser();
		a.open();
		const b = new Browser(a.shared, 'b');
		b.open();
		b.register({ openai: 'sk-1' });
		await settle();
		expect(b.saved().keys).toEqual({ openai: 'sk-1' });
		const reply = later();
		const accept = a.answer;
		a.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		a.register({ openai: 'sk-new' });
		await settle();
		expect(a.registered()).toEqual([{ openai: 'sk-new' }]);
		b.forget();
		a.storageChanged();
		expect(a.status()).toBe(FORGOTTEN_ELSEWHERE);
		reply.give({ status: 200, body: { tokens: { openai: T3 } } });
		await settle();
		expect(a.forgotten()).toEqual([T3]);
		expect(b.forgotten()).toEqual([`koi_${'0'.repeat(31)}1`]);
		expect(a.saved()).toBeUndefined();
		expect(a.shown()).toEqual([]);
		expect(b.status()).toBe(FORGOTTEN);
	});

	test('a registration saved by another tab replaces the tokens this tab shows', async () => {
		// Tab B registers another key for the preview,
		// which revokes the token tab A shows.
		const a = returning();
		a.open();
		await settle();
		const b = new Browser(a.shared, 'b');
		b.open();
		b.register({ openai: 'sk-2' });
		await settle();
		const t2 = b.saved().previews[LABEL].tokens.openai;
		expect(b.forgotten()).toEqual([T1]);
		expect(a.shown()).toEqual([T1]);
		a.storageChanged('koi.keys');
		expect(a.shown()).toEqual([t2]);
		expect(a.status()).toBe(
			'Another tab registered keys for this preview; these are its tokens now.',
		);
		// The same tokens again change nothing; a later automatic
		// registration finds them unchanged.
		a.storageChanged('koi.keys');
		expect(a.status()).toBe(
			'Another tab registered keys for this preview; these are its tokens now.',
		);
		a.now += MINUTE + 1;
		a.visible();
		await settle();
		expect(a.registered()).toEqual([{ openai: 'sk-1' }, { openai: 'sk-2' }]);
		expect(a.status()).toBe(AGAIN);
		expect(a.shown()).toEqual([t2]);
	});

	test('an automatic reply is compared with the tokens this tab shows, not only the store', async () => {
		// The storage event never came (or the tab missed it): the reply
		// brings the store's token, which is not the one shown.
		const a = returning();
		a.open();
		await settle();
		const b = new Browser(a.shared, 'b');
		b.open();
		b.register({ openai: 'sk-2' });
		await settle();
		const t2 = b.saved().previews[LABEL].tokens.openai;
		a.now += MINUTE + 1;
		a.visible();
		await settle();
		expect(a.registered()).toEqual([{ openai: 'sk-1' }, { openai: 'sk-2' }]);
		expect(a.shown()).toEqual([t2]);
		expect(a.status()).toBe(
			'The koi box gave a new token for OpenAI. Paste it into the preview in place of the old one; the rest are unchanged.',
		);
		expect(a.page.status?.className).toBe('err');
		expect(a.forgotten()).toEqual([]);
	});

	test('a Forget finished by the queued operation of another tab still reports here', async () => {
		// Tab A holds the lock and has another operation
		// queued when tab B clicks Forget. A's queued operation finishes the
		// pending Forget and revokes the token; B's own turn finds nothing
		// pending, yet must say "Forgotten", and ask again if the box refused.
		const a = returning();
		const reply = later();
		const accept = a.answer;
		a.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		a.open();
		await settle();
		a.now += MINUTE + 1;
		a.visible();
		const b = new Browser(a.shared, 'b');
		b.open();
		b.forget();
		const refuse = () => ({ status: 503, body: { error: 'the key proxy is not available' } });
		a.answer = refuse;
		b.answer = refuse;
		reply.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(a.forgotten()).toEqual([T1]);
		expect(a.storage.get('koi.keys.forgetting')).toBeUndefined();
		// A's attempt was refused, so B asks again, and says what is left.
		expect(b.forgotten()).toEqual([T1]);
		expect(b.status()).toContain('has not confirmed it forgot 1 of your tokens');
		b.answer = accept;
		b.tick();
		await settle();
		expect(b.saved()).toBeUndefined();
		expect(b.status()).toBe(FORGOTTEN);
	});

	test('and says "Forgotten" at once when that operation got every revocation confirmed', async () => {
		const a = returning();
		const reply = later();
		const accept = a.answer;
		a.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		a.open();
		await settle();
		a.now += MINUTE + 1;
		a.visible();
		const b = new Browser(a.shared, 'b');
		b.open();
		b.forget();
		expect(b.status()).toBe('Forgetting...');
		reply.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(a.forgotten()).toEqual([T1]);
		expect(b.forgotten()).toEqual([]);
		expect(b.status()).toBe(FORGOTTEN);
	});

	test('tokens stay hidden while a Forget is pending, and go when their preview is cleared', async () => {
		// Tab A is registering another key when tab B
		// clicks Forget. A's reply, under the moved count, saves the store
		// unchanged while it revokes what it got; that save must not bring
		// the old tokens back in B, and the save that clears the preview
		// must take them off any tab that still shows them.
		const a = returning();
		a.open();
		await settle();
		const reply = later();
		const revoked = later();
		const accept = a.answer;
		// A's reply waits for the test, and so does the box's answer to A's
		// revocation after it, which keeps A's turn under the lock open.
		a.answer = (call) =>
			call.path === '/api/register' ? reply.answer : (revoked.answer as Promise<Answer>);
		a.register({ openai: 'sk-2' });
		await settle();
		const b = new Browser(a.shared, 'b');
		b.open();
		expect(b.shown()).toEqual([T1]);
		b.forget();
		expect(b.shown()).toEqual([]);
		reply.give({ status: 200, body: { tokens: { openai: T2 } } });
		await settle();
		expect(a.forgotten()).toEqual([T2]);
		expect(a.saved().previews[LABEL].tokens).toEqual({ openai: T1 });
		expect(a.storage.get('koi.keys.forgetting')).toBe('1');
		b.storageChanged('koi.keys');
		expect(b.shown()).toEqual([]);
		expect(b.status()).toBe('Forgetting...');
		// A tab that missed the Forget's count still shows the tokens until
		// the save that clears the preview reaches it.
		expect(a.shown()).toEqual([T1]);
		a.answer = accept;
		revoked.give({ status: 200, body: { ok: true } });
		await settle();
		expect(b.status()).toBe(FORGOTTEN);
		expect(b.saved()).toBeUndefined();
		a.storageChanged('koi.keys');
		expect(a.shown()).toEqual([]);
	});

	test('a Forget whose tab closes before its turn is finished by the next page to open', async () => {
		// Tab A holds the lock for its registration; tab
		// B clicks Forget, which queues behind it, and closes. The Forget is
		// pending in storage, so the next page finishes it: the saved keys
		// go, the tokens are revoked, and nothing is registered again.
		const a = returning();
		const reply = later();
		const accept = a.answer;
		a.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		a.open();
		await settle();
		const b = new Browser(a.shared, 'b');
		b.open();
		b.forget();
		b.close();
		a.storageChanged();
		reply.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(a.saved().previews[LABEL].keys).toEqual({ openai: 'sk-1' });
		expect(a.storage.get('koi.keys.forgetting')).toBe('1');
		const c = new Browser(a.shared, 'c');
		c.now = a.now + MINUTE + 1;
		c.open();
		expect(c.shown()).toEqual([]);
		expect(c.inputs.every((i) => i.value === '')).toBe(true);
		expect(c.status()).toBe('Forgetting...');
		await settle();
		expect(c.registered()).toEqual([]);
		expect(c.forgotten()).toEqual([T1]);
		expect(c.saved()).toBeUndefined();
		expect(c.storage.get('koi.keys.forgetting')).toBeUndefined();
		expect(c.status()).toBe(FORGOTTEN);
	});

	test('or by the next operation of a tab still open', async () => {
		const a = returning();
		const reply = later();
		const accept = a.answer;
		a.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		a.open();
		await settle();
		const b = new Browser(a.shared, 'b');
		b.open();
		b.forget();
		b.close();
		reply.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		a.answer = accept;
		a.now += MINUTE + 1;
		a.visible();
		await settle();
		expect(a.registered()).toHaveLength(1);
		expect(a.forgotten()).toEqual([T1]);
		expect(a.saved()).toBeUndefined();
		expect(a.storage.get('koi.keys.forgetting')).toBeUndefined();
	});

	test('a Forget in a tab that holds nothing still reaches the others', async () => {
		const a = returning();
		a.open();
		await settle();
		const b = new Browser(a.shared, 'b');
		b.storage.delete('koi.keys');
		b.open();
		b.forget();
		await settle();
		a.storageChanged();
		expect(a.status()).toBe(FORGOTTEN_ELSEWHERE);
		expect(a.shown()).toEqual([]);
	});

	test('keys another tab registered meanwhile are kept, and its live token is never revoked', async () => {
		// Tab A registers OpenAI and Anthropic again;
		// before its reply, tab B registers the same OpenAI key and another
		// Anthropic key. With the lock, B waits for A; the OpenAI token stays,
		// and only A's Anthropic token is revoked.
		const a = returning({ openai: 'sk-1', anthropic: 'sk-2' }, { openai: T1, anthropic: T2 });
		const reply = later();
		const accept = a.answer;
		a.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		a.open();
		await settle();
		const b = new Browser(a.shared, 'b');
		b.open();
		b.register({ openai: 'sk-1', anthropic: 'sk-3' });
		await settle();
		expect(b.registered()).toEqual([]);
		reply.give({ status: 200, body: { tokens: { openai: T1, anthropic: T2 } } });
		await settle();
		const t3 = `koi_${'0'.repeat(31)}1`;
		expect(b.registered()).toEqual([{ openai: 'sk-1', anthropic: 'sk-3' }]);
		expect(a.shared.calls.filter((c) => c.path === '/api/forget').map((c) => c.body.token)).toEqual(
			[T2],
		);
		expect(a.saved()).toEqual(
			state(
				{ openai: 'sk-1', anthropic: 'sk-3' },
				{
					[LABEL]: {
						keys: { openai: 'sk-1', anthropic: 'sk-3' },
						tokens: { openai: T1, anthropic: t3 },
					},
				},
			),
		);
		expect(b.shown()).toEqual([T1, t3]);
	});
});

describe('without the Web Locks API', () => {
	test('a tab still runs its own registrations and Forgets one at a time', async () => {
		const b = new Browser();
		b.open(LABEL, { locks: false });
		const first = later();
		const accept = b.answer;
		b.answer = (call) =>
			call.path === '/api/register' && b.registered().length === 1 ? first.answer : accept(call);
		b.register({ openai: 'sk-1' });
		b.register({ openai: 'sk-2' });
		await settle();
		expect(b.registered()).toHaveLength(1);
		first.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(b.calls.map((c) => c.path)).toEqual(['/api/register', '/api/register', '/api/forget']);
		expect(b.forgotten()).toEqual([T1]);
	});

	test('a late reply after another tab registered keeps the newer registration and never revokes its live token', async () => {
		// With tabs that can overlap, A's reply comes
		// after B saved. A revokes only what B is not using.
		const a = returning({ openai: 'sk-1', anthropic: 'sk-2' }, { openai: T1, anthropic: T2 });
		const reply = later();
		const accept = a.answer;
		a.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		a.open(LABEL, { locks: false });
		await settle();
		const b = new Browser(a.shared, 'b');
		b.open(LABEL, { locks: false });
		b.register({ openai: 'sk-1', anthropic: 'sk-3' });
		await settle();
		const t3 = `koi_${'0'.repeat(31)}1`;
		expect(b.saved().previews[LABEL].tokens).toEqual({ openai: T1, anthropic: t3 });
		expect(b.forgotten()).toEqual([T2]);
		reply.give({ status: 200, body: { tokens: { openai: T1, anthropic: T2 } } });
		await settle();
		expect(a.forgotten()).toEqual([T2]);
		expect(a.saved().previews[LABEL]).toEqual({
			keys: { openai: 'sk-1', anthropic: 'sk-3' },
			tokens: { openai: T1, anthropic: t3 },
		});
		expect(a.saved().revoke).toEqual([]);
		expect(a.shown()).toEqual([T1, t3]);
		expect(a.status()).toBe(HELD);
	});

	test('a Forget in another tab during a registration here still wins', async () => {
		const a = new Browser();
		a.open(LABEL, { locks: false });
		const b = new Browser(a.shared, 'b');
		b.open(LABEL, { locks: false });
		b.register({ openai: 'sk-1' });
		await settle();
		const reply = later();
		const accept = a.answer;
		a.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		a.register({ openai: 'sk-new' });
		await settle();
		b.forget();
		a.storageChanged();
		await settle();
		reply.give({ status: 200, body: { tokens: { openai: T3 } } });
		await settle();
		// This tab revokes what its reply brought (and may retry what the
		// other tab queued); nothing is saved.
		expect(a.forgotten()).toContain(T3);
		expect(a.saved()).toBeUndefined();
		expect(a.shown()).toEqual([]);
	});
});

describe('forgetting', () => {
	test('tokens the box did not confirm stay queued, are tried again, and only then is it forgotten', async () => {
		const b = returning({ openai: 'sk-1' }, { openai: T1, anthropic: T2 });
		b.open();
		b.answer = () => 'offline';
		b.forget();
		await settle();
		// The browser's part is done; the box's is not, and the page says so.
		expect(b.saved()).toEqual(state({}, {}, [T1, T2]));
		expect(b.status()).toContain('has not confirmed it forgot 2 of your tokens');
		expect(b.status()).not.toContain('Forgotten');
		expect(b.page.status?.className).toBe('err');
		// The box answers now, but refuses one: it stays for the next try.
		b.answer = (call) =>
			call.body.token === T1
				? { status: 200, body: { ok: true } }
				: { status: 503, body: { error: 'the key proxy is not available' } };
		b.tick();
		await settle();
		expect(b.saved()).toEqual(state({}, {}, [T2]));
		expect(b.status()).toContain('1 of your tokens: the key proxy is not available');
		b.answer = () => ({ status: 200, body: { ok: true } });
		b.tick();
		await settle();
		expect(b.saved()).toBeUndefined();
		expect(b.status()).toBe(FORGOTTEN);
	});

	test('a later visit revokes what an earlier one could not', async () => {
		const b = new Browser();
		b.storage.set('koi.keys', JSON.stringify(state({}, {}, [T1])));
		b.open();
		await settle();
		expect(b.forgotten()).toEqual([T1]);
		expect(b.saved()).toBeUndefined();
		expect(b.status()).toBe(FORGOTTEN);
	});

	test('a later visit cleans up old tokens quietly while keys are still held', async () => {
		const b = returning({ openai: 'sk-1' }, { openai: T2 });
		b.storage.set('koi.keys', JSON.stringify({ ...b.saved(), revoke: [T1] }));
		b.open();
		await settle();
		expect(b.forgotten()).toEqual([T1]);
		expect(b.saved()).toEqual(
			state({ openai: 'sk-1' }, { [LABEL]: { keys: { openai: 'sk-1' }, tokens: { openai: T2 } } }),
		);
		expect(b.status()).toBe(AGAIN);
	});

	test('a token the box calls malformed leaves the list', async () => {
		const b = new Browser();
		b.storage.set('koi.keys', JSON.stringify(state({}, {}, ['koi_bad'])));
		b.answer = () => ({ status: 400, body: { error: 'expected a koi token' } });
		b.open();
		await settle();
		expect(b.saved()).toBeUndefined();
	});

	test('registering another key keeps the old token queued until the box confirms it forgot it', async () => {
		const b = returning();
		b.open();
		await settle();
		const accept = b.answer;
		b.answer = (call) => (call.path === '/api/forget' ? 'offline' : accept(call));
		b.register({ openai: 'sk-2' });
		await settle();
		const saved = b.saved();
		expect(saved.revoke).toEqual([T1]);
		expect(saved.keys).toEqual({ openai: 'sk-2' });
		expect(saved.previews[LABEL].tokens.openai).not.toBe(T1);
		expect(b.shown()).toEqual([saved.previews[LABEL].tokens.openai]);
		const registered = b.status();
		expect(registered).toStartWith('Registered.');
		expect(registered).toContain(
			'has not yet confirmed it forgot 1 token(s) of an earlier registration',
		);
		expect(b.page.status?.className).toBe('');
		// The old token is revoked on the retry. The new keys and token are
		// still held and in use, so the page does not say "Forgotten".
		b.answer = accept;
		b.tick();
		await settle();
		expect(b.saved().revoke).toEqual([]);
		expect(b.saved().keys).toEqual({ openai: 'sk-2' });
		expect(b.status()).toBe(registered);
		expect(b.status()).not.toContain('Forgotten');
	});

	test('a token in use again is never revoked, however it got on the list', async () => {
		// sk-1 gave T1; the reviewer registered sk-2 while T1 could not be
		// revoked, then registered sk-1 again: T1 is in use once more, and
		// the retry of its revocation finds it so.
		const b = returning({ openai: 'sk-2' }, { openai: T2 });
		b.storage.set('koi.keys', JSON.stringify({ ...b.saved(), revoke: [T1] }));
		b.know('openai', 'sk-1', T1);
		const accept = b.answer;
		b.answer = (call) =>
			call.path === '/api/forget' && call.body.token === T1 ? 'offline' : accept(call);
		b.open();
		await settle();
		expect(b.forgotten().length).toBeGreaterThan(0);
		expect(b.forgotten().every((t) => t === T1)).toBe(true);
		expect(b.saved().revoke).toEqual([T1]);
		const before = b.calls.length;
		b.register({ openai: 'sk-1' });
		await settle();
		b.tick();
		await settle();
		expect(b.calls.slice(before).map((c) => [c.path, c.body.token])).toEqual([
			['/api/register', undefined],
			['/api/forget', T2],
		]);
		expect(b.saved()).toEqual(
			state({ openai: 'sk-1' }, { [LABEL]: { keys: { openai: 'sk-1' }, tokens: { openai: T1 } } }),
		);
	});

	test('"Forgotten" comes only after a Forget of the keys held, even when an old token was pending', async () => {
		const b = returning({ openai: 'sk-1' }, { openai: T2 });
		b.storage.set('koi.keys', JSON.stringify({ ...b.saved(), revoke: [T1] }));
		b.answer = () => 'offline';
		b.open();
		await settle();
		expect(b.status()).not.toContain('Forgotten');
		b.answer = () => ({ status: 200, body: { ok: true } });
		b.forget();
		await settle();
		expect(b.forgotten().slice(-2).sort()).toEqual([T1, T2].sort());
		expect(b.saved()).toBeUndefined();
		expect(b.status()).toBe(FORGOTTEN);
	});
});

describe('registering and forgetting, one at a time', () => {
	test('Forget while a registration is under way revokes the tokens its reply brings', async () => {
		const b = new Browser();
		b.open();
		const reply = later();
		const accept = b.answer;
		b.answer = (call) => (call.path === '/api/register' ? reply.answer : accept(call));
		b.register({ openai: 'sk-1', anthropic: 'sk-2' });
		await settle();
		b.forget();
		await settle();
		// Nothing to revoke yet; the Forget waits for the registration.
		expect(b.forgotten()).toEqual([]);
		const call = b.calls[0] as Call;
		reply.give({ status: 200, body: { tokens: b.tokensFor(call) } });
		await settle();
		expect(b.forgotten().sort()).toEqual([`koi_${'0'.repeat(31)}1`, `koi_${'0'.repeat(31)}2`]);
		expect(b.saved()).toBeUndefined();
		expect(b.inputs.every((i) => i.value === '')).toBe(true);
		expect(b.status()).toBe(FORGOTTEN);
	});

	test('a registration asked for before Forget, and not yet started, sends no keys', async () => {
		const b = new Browser();
		b.open();
		const first = later();
		const accept = b.answer;
		b.answer = (call) =>
			call.path === '/api/register' && b.registered().length === 1 ? first.answer : accept(call);
		b.register({ openai: 'sk-1' });
		b.register({ openai: 'sk-other' });
		await settle();
		b.forget();
		first.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(b.registered()).toHaveLength(1);
		expect(b.forgotten()).toEqual([T1]);
		expect(b.saved()).toBeUndefined();
	});

	test('a second submission waits for the first, then revokes the tokens it replaced', async () => {
		const b = new Browser();
		b.open();
		const first = later();
		const accept = b.answer;
		b.answer = (call) =>
			call.path === '/api/register' && b.registered().length === 1 ? first.answer : accept(call);
		b.register({ openai: 'sk-1' });
		b.register({ openai: 'sk-2' });
		await settle();
		// The second has not been sent while the first is under way.
		expect(b.registered()).toHaveLength(1);
		first.give({ status: 200, body: { tokens: { openai: T1 } } });
		await settle();
		expect(b.calls.map((c) => c.path)).toEqual(['/api/register', '/api/register', '/api/forget']);
		expect(b.forgotten()).toEqual([T1]);
		const saved = b.saved();
		expect(saved.keys).toEqual({ openai: 'sk-2' });
		expect(saved.previews[LABEL].tokens.openai).not.toBe(T1);
		expect(saved.revoke).toEqual([]);
	});

	test('a registration that fails leaves the tokens held before in place', async () => {
		const b = returning();
		b.open();
		await settle();
		b.answer = () => ({ status: 503, body: { error: 'the key proxy is not available' } });
		b.register({ openai: 'sk-2' });
		await settle();
		expect(b.status()).toBe('Not registered: the key proxy is not available');
		expect(b.shown()).toEqual([T1]);
		expect(b.saved()).toEqual(
			state({ openai: 'sk-1' }, { [LABEL]: { keys: { openai: 'sk-1' }, tokens: { openai: T1 } } }),
		);
	});
});
