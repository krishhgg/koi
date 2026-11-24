import { describe, expect, test } from 'bun:test';
import { mkdtemp, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	type HostInfo,
	type LeaseReply,
	type PreviewListPage,
	PreviewListPageSchema,
	type PreviewRecord,
	StatusReplySchema,
} from '@koi/shared';
import { Activity } from '../src/activity.ts';
import { BuildLogs, pageAt, tailAt } from '../src/buildlog.ts';
import { type ControlDeps, control, groupId, startControlServer } from '../src/control.ts';
import {
	CapacityError,
	LeaseError,
	NoSuchLeaseError,
	NoSuchPreviewError,
	OwnershipError,
	UnsupportedRequestError,
} from '../src/deployer.ts';
import { memoryFile } from './fakes.ts';

// The attempt the records here are on, and a later one.
const A = 'a'.repeat(20);
const B = 'b'.repeat(20);

// What the fake deployer answers a lease with.
const LEASE_REPLY: LeaseReply = {
	lease: {
		leaseId: 'l'.repeat(20),
		deploymentId: B,
		holder: 'dev@laptop',
		acquiredAt: '2026-10-06T10:00:00.000Z',
		expiresAt: '2026-10-06T11:00:00.000Z',
	},
	deployment: {
		label: 'hello-pr-7',
		deploymentId: B,
		imageDigest: `sha256:${'1'.repeat(64)}`,
		commit: 'd'.repeat(40),
	},
};

// `buildLog` is attempt A's build log, or each attempt's by id.
function deps(
	overrides: Partial<ControlDeps['deployer']> = {},
	buildLog: string | Record<string, string> = 'build output\n',
	store?: ControlDeps['store'],
): ControlDeps & { calls: string[] } {
	const logs = typeof buildLog === 'string' ? { [A]: buildLog } : buildLog;
	const calls: string[] = [];
	return {
		calls,
		deployer: {
			up: async (id) => {
				calls.push(`up ${id}`);
				return { label: 'hello-pr-7', queued: false };
			},
			down: async (label, options) => {
				calls.push(options?.force === true ? `down ${label} --force` : `down ${label}`);
				return label === 'hello-pr-7';
			},
			acquireLease: async (label, holder, ttlSeconds) => {
				calls.push(`lease ${label} ${holder} ${ttlSeconds}`);
				return LEASE_REPLY;
			},
			releaseLease: async (label, leaseId) => {
				calls.push(`release ${label} ${leaseId}`);
			},
			...overrides,
		},
		store: store ?? {
			get: async (label) =>
				label === 'hello-pr-7'
					? ({ label, attempt: A, deployment: { container: 'c1' } } as never)
					: undefined,
			list: async () => [{ label: 'hello-pr-7' }] as never,
		},
		docker: { logs: async (name, tail) => `${name} last ${tail}` },
		buildLogs: {
			read: (_label, attempt, since, maxLines, maxChars) =>
				pageAt(memoryFile(logs[attempt] ?? ''), since, maxLines, maxChars),
			tail: (_label, attempt, lines, maxBytes) =>
				tailAt(memoryFile(logs[attempt] ?? ''), lines, maxBytes),
		},
		keepAwake: async () => {},
		describe: async () => HOST,
	};
}

// What this koid says of itself.
const HOST: HostInfo = {
	protocol: 1,
	hostId: 'k'.repeat(20),
	domain: 'previews.example.com',
	address: { scheme: 'https', port: 443 },
	capabilities: {
		duplex: false,
		buildLogCursor: true,
		runtimeLogStream: false,
		artifactTransfer: false,
	},
};

const call = (d: ControlDeps, method: string, path: string, body?: unknown) =>
	control(
		new Request(`http://koid${path}`, {
			method,
			...(body === undefined
				? {}
				: { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
		}),
		d,
	);

describe('control API', () => {
	test('GET /health answers ok', async () => {
		const res = await call(deps(), 'GET', '/health');
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true });
	});

	test('GET /host answers the host descriptor', async () => {
		const res = await call(deps(), 'GET', '/host');
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual(HOST);
		const failing = {
			...deps(),
			describe: async () => {
				throw new Error('cannot write host-id');
			},
		};
		const err = await call(failing, 'GET', '/host');
		expect(err.status).toBe(500);
		expect(await err.json()).toEqual({ error: 'cannot write host-id' });
	});

	test('POST /up accepts a request id and answers 202', async () => {
		const d = deps();
		const res = await call(d, 'POST', '/up', { requestId: 'abcdefghij0123456' });
		expect(res.status).toBe(202);
		expect(await res.json()).toEqual({ label: 'hello-pr-7', queued: false });
		expect(d.calls).toEqual(['up abcdefghij0123456']);
	});

	test('rejects a malformed request id or body with 400 and does not call up', async () => {
		const d = deps();
		expect((await call(d, 'POST', '/up', { requestId: '../x' })).status).toBe(400);
		expect((await call(d, 'POST', '/up', 'not json')).status).toBe(400);
		const raw = await control(new Request('http://koid/up', { method: 'POST', body: '{' }), d);
		expect(raw.status).toBe(400);
		expect(d.calls).toEqual([]);
	});

	test('POST /up answers 413 for a body past 128 MiB, as Bun did before uploads raised the server limit, and reads no further', async () => {
		const d = deps();
		let pulled = 0;
		const endless = new ReadableStream<Uint8Array>({
			pull(c) {
				pulled += 1;
				c.enqueue(new Uint8Array(1024 ** 2));
			},
		});
		const res = await control(
			new Request('http://koid/up', {
				method: 'POST',
				body: endless,
				duplex: 'half',
			} as RequestInit),
			d,
		);
		expect(res.status).toBe(413);
		expect(((await res.json()) as { error: string }).error).toBe(
			`the request is over ${128 * 1024 ** 2} bytes`,
		);
		expect(pulled).toBeLessThan(140);
		expect(d.calls).toEqual([]);
	});

	test('POST /up answers 408 for a body that stalls, within its time bound', async () => {
		const d = { ...deps(), limits: { bodyTimeoutMs: 200 } };
		let sent = false;
		const stalled = new ReadableStream<Uint8Array>({
			pull(c) {
				if (sent) return new Promise<void>(() => {});
				sent = true;
				c.enqueue(new TextEncoder().encode('{"requestId":'));
				return undefined;
			},
		});
		const started = Date.now();
		const res = await control(
			new Request('http://koid/up', {
				method: 'POST',
				body: stalled,
				duplex: 'half',
			} as RequestInit),
			d,
		);
		expect(res.status).toBe(408);
		expect(((await res.json()) as { error: string }).error).toBe(
			'the request did not arrive within 0.2 seconds',
		);
		expect(Date.now() - started).toBeLessThan(2000);
		expect(d.calls).toEqual([]);
	});

	test('maps an ownership conflict to 409', async () => {
		const d = deps({
			up: async () => {
				throw new OwnershipError('hello-pr-7 belongs to pull request 7 of github.com/acme/hello');
			},
		});
		const res = await call(d, 'POST', '/up', { requestId: 'abcdefghij0123456' });
		expect(res.status).toBe(409);
		expect(((await res.json()) as { error: string }).error).toContain('belongs to');
	});

	test('answers 400 with the reason when the request asks what its recipe does not do', async () => {
		const d = deps({
			up: async () => {
				throw new UnsupportedRequestError('koi up --keep needs a recipe that reports its slice');
			},
		});
		const res = await call(d, 'POST', '/up', { requestId: 'abcdefghij0123456' });
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toContain('--keep needs a recipe');
	});

	test('answers 507 with the reason when koid has no room for another preview', async () => {
		const d = deps({
			up: async () => {
				throw new CapacityError('koi has 63 live previews, and the list ... cannot take another');
			},
		});
		const res = await call(d, 'POST', '/up', { requestId: 'abcdefghij0123456' });
		expect(res.status).toBe(507);
		expect(((await res.json()) as { error: string }).error).toContain('63 live previews');
	});

	test('lists, shows, tails logs, and removes previews', async () => {
		const d = deps();
		const status = (await (await call(d, 'GET', `/previews/hello-pr-7?attempt=${A}`)).json()) as {
			log: unknown;
		};
		expect(status.log).toEqual({ next: 13, lines: ['build output'] });
		expect(await (await call(d, 'GET', '/previews/hello-pr-7/logs?tail=50')).text()).toBe(
			'c1 last 50',
		);
		expect((await call(d, 'GET', `/previews/nobody?attempt=${A}`)).status).toBe(404);
		expect((await call(d, 'DELETE', '/previews/hello-pr-7')).status).toBe(200);
		expect((await call(d, 'DELETE', '/previews/gone')).status).toBe(404);
	});

	test('lists previews as a few fields each', async () => {
		const records = Array.from({ length: 40 }, (_, i) =>
			fullRecord({
				label: `hello-pr-${i + 1}`,
				pr: i + 1,
				branch: 'b'.repeat(255),
				error: 'e'.repeat(2000),
				lastVisitAt: '2026-10-06T09:30:00.000Z',
			}),
		);
		const d = deps({}, '', {
			get: async () => undefined,
			list: async () => records,
		});
		const page = PreviewListPageSchema.parse(await (await call(d, 'GET', '/previews')).json());
		expect(page.previews[0]).toEqual({
			label: 'hello-pr-1',
			status: 'building',
			commit: 'c'.repeat(40),
			branch: 'b'.repeat(255),
			pr: 1,
			lastVisitAt: '2026-10-06T09:30:00.000Z',
			updatedAt: '2026-10-06T00:00:00.000Z',
		});
	});

	test('status and list carry the identity of the deployment serving, when there is one', async () => {
		const identified = fullRecord({
			deployment: {
				...(fullRecord().deployment as NonNullable<PreviewRecord['deployment']>),
				deploymentId: B,
				imageDigest: `sha256:${'1'.repeat(64)}`,
				merge: { head: 'e'.repeat(40), base: 'f'.repeat(40), baseBranch: 'main' },
			},
		});
		const identity = {
			label: 'hello-pr-7',
			deploymentId: B,
			imageDigest: `sha256:${'1'.repeat(64)}`,
			commit: 'd'.repeat(40),
			merge: { head: 'e'.repeat(40), base: 'f'.repeat(40), baseBranch: 'main' },
		};
		const d = deps({}, '', storeOf(identified));
		const status = StatusReplySchema.parse(
			await (await call(d, 'GET', '/previews/hello-pr-7')).json(),
		);
		expect(status.deployment).toEqual(identity);
		expect('deployment' in status.record).toBe(false);
		const page = PreviewListPageSchema.parse(await (await call(d, 'GET', '/previews')).json());
		expect(page.previews[0]?.deployment).toEqual(identity);
		// A deployment from before koid kept ids has no identity to give.
		const old = deps({}, '', storeOf(fullRecord()));
		const reply = StatusReplySchema.parse(
			await (await call(old, 'GET', '/previews/hello-pr-7')).json(),
		);
		expect('deployment' in reply).toBe(false);
	});

	test("status carries the deployment's slice only in a reply with no log lines, once nothing builds", async () => {
		const slice = { nodes: { core: ['core'] }, apps: ['home'] };
		const serving = (over: Partial<PreviewRecord>) =>
			fullRecord({
				status: 'running',
				deployment: {
					...(fullRecord().deployment as NonNullable<PreviewRecord['deployment']>),
					deploymentId: B,
					imageDigest: `sha256:${'1'.repeat(64)}`,
					slice,
				},
				...over,
			});
		const read = async (d: ControlDeps, path: string) =>
			StatusReplySchema.parse(await (await call(d, 'GET', path)).json());
		const running = deps({}, 'one\ntwo\n', storeOf(serving({})));
		// The record alone, and the read past the end of the log.
		expect((await read(running, '/previews/hello-pr-7')).slice).toEqual(slice);
		const end = Buffer.byteLength('one\ntwo\n');
		expect((await read(running, `/previews/hello-pr-7?attempt=${A}&since=${end}`)).slice).toEqual(
			slice,
		);
		// Not beside log lines, nor while a build is under way.
		const page = await read(running, `/previews/hello-pr-7?attempt=${A}`);
		expect(page.log.lines).toEqual(['one', 'two']);
		expect('slice' in page).toBe(false);
		const building = deps({}, '', storeOf(serving({ status: 'building' })));
		expect('slice' in (await read(building, '/previews/hello-pr-7'))).toBe(false);
		// Nor without a deployment identity to say what it describes.
		const halted = serving({});
		const stopped = deps(
			{},
			'',
			storeOf({
				...halted,
				deployment: {
					...(halted.deployment as NonNullable<PreviewRecord['deployment']>),
					halted: 'disk',
				},
			}),
		);
		expect('slice' in (await read(stopped, '/previews/hello-pr-7'))).toBe(false);
	});

	test('a status reply with the largest slice and record still fits in the 24,000 characters SSM returns', async () => {
		// The most a slice takes: multibyte text counts more in bytes than SSM
		// counts in characters, so ASCII is the worst case for characters.
		const slice = { names: 'n'.repeat(16 * 1024 - '{"names":""}'.length) };
		const record = fullRecord({
			status: 'failed',
			error: '\u001b[31m'.repeat(1000),
			branch: '"'.repeat(255),
			loginKey: `koi-${'a'.repeat(24)}`,
			merge: { head: 'e'.repeat(40), base: 'f'.repeat(40), baseBranch: '"'.repeat(255) },
			lease: {
				leaseId: 'l'.repeat(20),
				deploymentId: B,
				holder: '"'.repeat(200),
				acquiredAt: '2026-10-06T10:00:00.000Z',
				expiresAt: '2026-10-06T11:00:00.000Z',
			},
			deployment: {
				...(fullRecord().deployment as NonNullable<PreviewRecord['deployment']>),
				deploymentId: B,
				imageDigest: `sha256:${'1'.repeat(64)}`,
				merge: { head: 'e'.repeat(40), base: 'f'.repeat(40), baseBranch: '"'.repeat(255) },
				slice,
			},
		});
		const text = await (
			await call(deps({}, '', storeOf(record)), 'GET', '/previews/hello-pr-7')
		).text();
		expect(StatusReplySchema.parse(JSON.parse(text)).slice).toEqual(slice);
		expect(text.length).toBeLessThan(24_000);
	});

	test('takes and releases a lease', async () => {
		const d = deps();
		const taken = await call(d, 'POST', '/previews/hello-pr-7/lease', {
			holder: 'dev@laptop',
			ttlSeconds: 600,
		});
		expect(taken.status).toBe(200);
		expect(await taken.json()).toEqual(LEASE_REPLY);
		const released = await call(d, 'DELETE', `/previews/hello-pr-7/lease/${'l'.repeat(20)}`);
		expect(released.status).toBe(200);
		expect(await released.json()).toEqual({ released: true });
		expect(d.calls).toEqual([
			'lease hello-pr-7 dev@laptop 600',
			`release hello-pr-7 ${'l'.repeat(20)}`,
		]);
	});

	test('refuses a lease request that is not one, asking the deployer nothing', async () => {
		const d = deps();
		for (const body of [
			{ ttlSeconds: 600 },
			{ holder: 'kg', ttlSeconds: 0 },
			{ holder: 'kg', ttlSeconds: 7201 },
			{ holder: 'kg', ttlSeconds: '600' },
			{ holder: 'kg', ttlSeconds: 1.5 },
			{ holder: '', ttlSeconds: 60 },
			{ holder: 'a\u0001b', ttlSeconds: 60 },
			'not json',
		]) {
			expect((await call(d, 'POST', '/previews/hello-pr-7/lease', body)).status).toBe(400);
		}
		expect((await call(d, 'DELETE', '/previews/hello-pr-7/lease/../x')).status).toBe(404);
		expect((await call(d, 'DELETE', '/previews/hello-pr-7/lease/LLLL')).status).toBe(400);
		expect(
			(await call(d, 'POST', '/previews/Bad_Label/lease', { holder: 'kg', ttlSeconds: 60 })).status,
		).toBe(400);
		expect(d.calls).toEqual([]);
	});

	test('maps a lease refusal to 409, and a lease or preview that is not there to 404', async () => {
		const held = deps({
			acquireLease: async () => {
				throw new LeaseError('hello-pr-7 is leased by dev@laptop until 2026-10-06T11:00:00.000Z');
			},
			releaseLease: async () => {
				throw new NoSuchLeaseError('no such lease');
			},
		});
		const refused = await call(held, 'POST', '/previews/hello-pr-7/lease', {
			holder: 'ci',
			ttlSeconds: 60,
		});
		expect(refused.status).toBe(409);
		expect(((await refused.json()) as { error: string }).error).toContain('leased by dev@laptop');
		const gone = await call(held, 'DELETE', `/previews/hello-pr-7/lease/${'x'.repeat(20)}`);
		expect(gone.status).toBe(404);
		expect(await gone.json()).toEqual({ error: 'no such lease' });
		const missing = deps({
			acquireLease: async () => {
				throw new NoSuchPreviewError('no such preview');
			},
			down: async () => {
				throw new LeaseError(
					'hello-pr-7 is leased by dev@laptop until later; run koi down hello-pr-7 --force to remove it anyway',
				);
			},
		});
		expect(
			(await call(missing, 'POST', '/previews/nobody/lease', { holder: 'ci', ttlSeconds: 60 }))
				.status,
		).toBe(404);
		const down = await call(missing, 'DELETE', '/previews/hello-pr-7');
		expect(down.status).toBe(409);
		expect(((await down.json()) as { error: string }).error).toContain('--force');
	});

	test('down passes --force through to the deployer', async () => {
		const d = deps();
		expect((await call(d, 'DELETE', '/previews/hello-pr-7')).status).toBe(200);
		expect((await call(d, 'DELETE', '/previews/hello-pr-7?force=1')).status).toBe(200);
		expect((await call(d, 'DELETE', '/previews/hello-pr-7?force=yes')).status).toBe(200);
		expect(d.calls).toEqual(['down hello-pr-7', 'down hello-pr-7 --force', 'down hello-pr-7']);
	});

	test('lists previews in label order, a page of at most 16,000 characters at a time', async () => {
		// Many small previews, and many as large as koi makes them: a 255
		// character branch of characters JSON escapes to six each.
		for (const branch of ['main', '\u0001'.repeat(255)]) {
			const records = Array.from({ length: 500 }, (_, i) =>
				fullRecord({ label: `hello-pr-${i + 1}`, pr: i + 1, branch }),
			);
			const d = deps({}, '', { get: async () => undefined, list: async () => records });
			const pages = await allPages(d);
			expect(pages.length).toBeGreaterThan(1);
			for (const { text } of pages) expect(Buffer.byteLength(text)).toBeLessThanOrEqual(16_000);
			const labels = pages.flatMap(({ page }) => page.previews.map((p) => p.label));
			expect(labels).toEqual(records.map((r) => r.label).sort());
			expect(pages.at(-1)?.page.next).toBeUndefined();
		}
	});

	test('lists a preview whose branch alone is over a page, with the branch cut', async () => {
		const records = [
			fullRecord({ label: 'a-1', branch: 'x'.repeat(100_000) }),
			fullRecord({ label: 'a-2', branch: '\u0001'.repeat(100_000) }),
			fullRecord({ label: 'a-3' }),
		];
		const d = deps({}, '', { get: async () => undefined, list: async () => records });
		const pages = await allPages(d);
		for (const { text } of pages) expect(Buffer.byteLength(text)).toBeLessThanOrEqual(16_000);
		const listed = pages.flatMap(({ page }) => page.previews);
		expect(listed.map((p) => p.label)).toEqual(['a-1', 'a-2', 'a-3']);
		expect(listed[0]?.branch).toEndWith(' [cut by koid]');
		expect(listed[2]?.branch).toBe('feature/x');
	});

	test('lists the previews after a label, whether or not it still exists', async () => {
		const records = ['b', 'a', 'd'].map((label) => fullRecord({ label }));
		const d = deps({}, '', { get: async () => undefined, list: async () => records });
		const after = async (label: string) =>
			PreviewListPageSchema.parse(await (await call(d, 'GET', `/previews?after=${label}`)).json());
		expect((await after('a')).previews.map((p) => p.label)).toEqual(['b', 'd']);
		expect((await after('c')).previews.map((p) => p.label)).toEqual(['d']);
		expect(await after('d')).toEqual({ previews: [] });
		expect((await call(d, 'GET', '/previews?after=Bad_Label')).status).toBe(400);
	});

	test('status leaves out the deployment and shows the build log from its start', async () => {
		const d = deps({}, numbered(100), storeOf(fullRecord()));
		const res = await call(d, 'GET', `/previews/hello-pr-7?attempt=${A}`);
		const reply = StatusReplySchema.parse(await res.json());
		expect('deployment' in reply.record).toBe(false);
		expect(reply.record.requestId).toBe('a'.repeat(16));
		expect(reply.log.next).toBe(Buffer.byteLength(numbered(100)));
		expect(reply.log.lines).toEqual(Array.from({ length: 100 }, (_, i) => `line ${i + 1}`));
	});

	test('status pages through the build log from an offset, 200 lines at a time', async () => {
		const d = deps({}, numbered(450), storeOf(fullRecord()));
		const shown: string[] = [];
		const nexts: number[] = [];
		let since = 0;
		for (;;) {
			const res = await call(d, 'GET', `/previews/hello-pr-7?attempt=${A}&since=${since}`);
			const { log } = StatusReplySchema.parse(await res.json());
			expect(log.lines.length).toBeLessThanOrEqual(200);
			shown.push(...log.lines);
			nexts.push(log.next);
			if (log.lines.length === 0) break;
			since = log.next;
		}
		expect(nexts).toEqual([200, 400, 450, 450].map((lines) => Buffer.byteLength(numbered(lines))));
		expect(shown).toEqual(Array.from({ length: 450 }, (_, i) => `line ${i + 1}`));
	});

	test('status replies stay far below the 24,000 characters SSM returns', async () => {
		const long = 'x'.repeat(50_000);
		const escaped = '\u001b[31m'.repeat(1000);
		const log = `${Array.from({ length: 30 }, (_, i) => `${i} ${'é'.repeat(900)}`).join('\n')}\n${long}\nlast\n`;
		const d = deps({}, log, storeOf(fullRecord({ error: escaped })));
		let since = 0;
		const shown: string[] = [];
		for (let page = 0; page < 40; page++) {
			const res = await call(d, 'GET', `/previews/hello-pr-7?attempt=${A}&since=${since}`);
			const text = await res.text();
			expect(Buffer.byteLength(text)).toBeLessThan(16_000);
			const reply = StatusReplySchema.parse(JSON.parse(text));
			if (reply.log.lines.length === 0) break;
			shown.push(...reply.log.lines);
			since = reply.log.next;
		}
		expect(since).toBe(Buffer.byteLength(log));
		expect(shown).toHaveLength(32);
		expect(shown[30]).toEndWith('[cut by koid]');
		expect(shown[31]).toBe('last');
	});

	test('buildlog returns the last lines of the build log, whole lines only', async () => {
		const d = deps({}, 'a\nb\nc\nhal', storeOf(fullRecord()));
		expect(await (await call(d, 'GET', '/previews/hello-pr-7/buildlog?tail=2')).text()).toBe(
			'b\nc\n',
		);
		expect(await (await call(d, 'GET', '/previews/hello-pr-7/buildlog')).text()).toBe('a\nb\nc\n');
		expect((await call(d, 'GET', '/previews/nobody/buildlog')).status).toBe(404);
		const empty = deps({}, '', storeOf(fullRecord()));
		expect(await (await call(empty, 'GET', '/previews/hello-pr-7/buildlog?tail=5')).text()).toBe(
			'',
		);
	});

	test('status refuses a since that is not a log offset', async () => {
		const d = deps({}, numbered(3), storeOf(fullRecord()));
		for (const bad of ['-1', '01', 'x', '1.5', '', '1e3']) {
			expect((await call(d, 'GET', `/previews/hello-pr-7?attempt=${A}&since=${bad}`)).status).toBe(
				400,
			);
		}
	});

	test('status refuses an attempt that is malformed', async () => {
		const d = deps({}, numbered(3), storeOf(fullRecord()));
		for (const query of ['?attempt=x', '?attempt=../etc', `?attempt=${A}x/`, '?attempt=']) {
			expect((await call(d, 'GET', `/previews/hello-pr-7${query}`)).status).toBe(400);
		}
	});

	test('status without an attempt shows the record and no log lines', async () => {
		const d = deps({}, numbered(3), storeOf(fullRecord()));
		for (const query of ['', '?since=5']) {
			const reply = StatusReplySchema.parse(
				await (await call(d, 'GET', `/previews/hello-pr-7${query}`)).json(),
			);
			expect(reply.record.attempt).toBe(A);
			expect(reply.log).toEqual({ next: 0, lines: [] });
		}
	});

	test('status shows the build log of the attempt asked about, not the latest', async () => {
		// B replaced A; A's koi up still asks about A.
		const d = deps(
			{},
			{ [A]: 'a 1\na 2\n', [B]: 'b 1\nb 2\nb 3\n' },
			storeOf(fullRecord({ requestId: 'b'.repeat(16), attempt: B })),
		);
		const status = async (id: string) =>
			StatusReplySchema.parse(
				await (await call(d, 'GET', `/previews/hello-pr-7?attempt=${id}&since=0`)).json(),
			);
		const a = await status(A);
		expect(a.record.attempt).toBe(B);
		expect(a.log).toEqual({ next: 8, lines: ['a 1', 'a 2'] });
		expect((await status(B)).log).toEqual({ next: 12, lines: ['b 1', 'b 2', 'b 3'] });
	});

	test("a status reply holds none of a newer attempt's lines when it finishes mid-reply", async () => {
		// koid loads A's record, then B is accepted, builds and finishes, all
		// before koid reads the log for the reply.
		const logs = new BuildLogs(await mkdtemp(join(tmpdir(), 'koi-control-')));
		const a = await logs.open('hello-pr-7', A);
		a.line('A 1');
		a.line('A 2');
		await a.close();
		let record = fullRecord();
		let race = false;
		const d: ControlDeps = {
			...deps({}, '', { get: async () => record, list: async () => [record] }),
			buildLogs: {
				read: async (...args) => {
					if (race) {
						race = false;
						const b = await logs.open('hello-pr-7', B);
						for (let i = 1; i <= 5; i++) b.line(`B ${i}`);
						b.line('ready');
						await b.close();
						record = fullRecord({ requestId: 'b'.repeat(16), attempt: B, status: 'running' });
					}
					return logs.read(...args);
				},
				tail: (...args) => logs.tail(...args),
			},
		};
		const status = async (id: string, since: number) =>
			StatusReplySchema.parse(
				await (await call(d, 'GET', `/previews/hello-pr-7?attempt=${id}&since=${since}`)).json(),
			);
		const first = await status(A, 0);
		expect(first.log.lines.map(untimed)).toEqual(['A 1', 'A 2']);
		race = true;
		const second = await status(A, first.log.next);
		expect(second.record.attempt).toBe(A);
		expect(second.log).toEqual({ next: first.log.next, lines: [] });
		// The next reply shows B's record, and still none of its lines.
		const third = await status(A, second.log.next);
		expect(third.record.attempt).toBe(B);
		expect(third.log.lines).toEqual([]);
		expect((await status(B, 0)).log.lines.map(untimed)).toEqual([
			'B 1',
			'B 2',
			'B 3',
			'B 4',
			'B 5',
			'ready',
		]);
	});

	test("buildlog shows the latest attempt's log", async () => {
		const d = deps({}, { [A]: 'a 1\n', [B]: 'b 1\nb 2\n' }, storeOf(fullRecord({ attempt: B })));
		expect(await (await call(d, 'GET', '/previews/hello-pr-7/buildlog')).text()).toBe('b 1\nb 2\n');
	});

	test('rejects labels that are not labels', async () => {
		expect((await call(deps(), 'GET', '/previews/Bad_Label')).status).toBe(400);
		expect((await call(deps(), 'DELETE', '/previews/-bad')).status).toBe(400);
		// URL parsing resolves ".." (and %2e%2e) before koid sees it, so these
		// reach no preview route at all; either way nothing is removed.
		const d = deps();
		expect((await call(d, 'DELETE', '/previews/..')).status).toBe(404);
		expect((await call(d, 'DELETE', '/previews/%2e%2e')).status).toBe(404);
		expect(d.calls).toEqual([]);
	});

	test('every command keeps the box awake, whatever koid answers', async () => {
		const stamp = join(await mkdtemp(join(tmpdir(), 'koid-activity-')), 'last-activity');
		await writeFile(stamp, '');
		await utimes(stamp, new Date(0), new Date(0));
		let now = 1_000_000;
		const activity = new Activity(stamp, () => now);
		const d = { ...deps(), keepAwake: () => activity.touch() };
		for (const [method, path] of [
			['GET', '/health'],
			['GET', '/previews'],
			['GET', `/previews/hello-pr-7?attempt=${A}&since=0`],
			['GET', '/previews/hello-pr-7/logs?tail=5'],
			['GET', '/previews/hello-pr-7/buildlog?tail=5'],
			['POST', '/previews/hello-pr-7/lease'],
			['DELETE', `/previews/hello-pr-7/lease/${A}`],
			['DELETE', '/previews/hello-pr-7'],
			['GET', '/previews/nope'],
			['GET', '/previews/Bad_Label'],
			['GET', '/nothing-here'],
		] as const) {
			// Further apart than Activity's 30 seconds between touches.
			now += 60_000;
			await call(d, method, path);
			expect((await stat(stamp)).mtimeMs).toBe(now);
		}
	});

	test('a stamp that cannot be written does not stop the command', async () => {
		const d = {
			...deps(),
			keepAwake: async () => {
				throw new Error('EROFS: read-only file system');
			},
		};
		expect((await call(d, 'GET', '/health')).status).toBe(200);
	});
});

// Every page of the preview list, asking for each with the last one's next.
async function allPages(d: ControlDeps): Promise<Array<{ text: string; page: PreviewListPage }>> {
	const pages: Array<{ text: string; page: PreviewListPage }> = [];
	let after: string | undefined;
	for (;;) {
		const res = await call(
			d,
			'GET',
			after === undefined ? '/previews' : `/previews?after=${after}`,
		);
		const text = await res.text();
		const page = PreviewListPageSchema.parse(JSON.parse(text));
		pages.push({ text, page });
		if (page.next === undefined) return pages;
		after = page.next;
	}
}

// A build log line without the timestamp koid writes before it.
function untimed(line: string): string {
	return line.replace(/^\S+ /, '');
}

function numbered(count: number): string {
	return Array.from({ length: count }, (_, i) => `line ${i + 1}\n`).join('');
}

function fullRecord(over: Partial<PreviewRecord> = {}): PreviewRecord {
	return {
		label: 'hello-pr-7',
		project: 'hello',
		repo: 'github.com/acme/hello',
		status: 'building',
		commit: 'c'.repeat(40),
		branch: 'feature/x',
		pr: 7,
		dirty: false,
		requestId: 'a'.repeat(16),
		attempt: A,
		ttlDays: 7,
		createdAt: '2026-10-06T00:00:00.000Z',
		updatedAt: '2026-10-06T00:00:00.000Z',
		deployment: {
			requestId: 'b'.repeat(16),
			commit: 'd'.repeat(40),
			image: 'koi-preview/hello-pr-7:b',
			container: 'koi-hello-pr-7-b',
			port: 8080,
			healthPath: '/',
			healthTimeoutSeconds: 60,
			user: '65534:65534',
			env: { BIG: 'v'.repeat(4096), BIGGER: 'w'.repeat(4096) },
			deployedAt: '2026-10-06T00:00:00.000Z',
		},
		...over,
	};
}

function storeOf(record: PreviewRecord): ControlDeps['store'] {
	return {
		get: async (label) => (label === record.label ? record : undefined),
		list: async () => [record],
	};
}

describe('/v1/uploads', () => {
	test('answers 404 and says where uploads go when the spool is off', async () => {
		const res = await call(deps(), 'POST', '/v1/uploads', { requestId: 'abcdefghij0123456' });
		expect(res.status).toBe(404);
		expect(((await res.json()) as { error: string }).error).toMatch(/reads them from S3/);
	});

	test('hands the request and the path after it to the upload API', async () => {
		const seen: Array<[string, string[]]> = [];
		const d: ControlDeps = {
			...deps(),
			uploadApi: {
				handle: async (request, parts) => {
					seen.push([request.method, parts]);
					return Response.json({ uploadId: 'x' }, { status: 201 });
				},
			},
		};
		expect((await call(d, 'POST', '/v1/uploads', {})).status).toBe(201);
		expect((await call(d, 'PUT', `/v1/uploads/${'a'.repeat(32)}/source`)).status).toBe(201);
		expect(seen).toEqual([
			['POST', []],
			['PUT', ['a'.repeat(32), 'source']],
		]);
	});
});

describe('the control socket and its group', () => {
	test('groupId reads the group file, and is undefined for no file or no group', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-group-'));
		const file = join(dir, 'group');
		await writeFile(
			file,
			'root:x:0:\nkoi-control:x:987:koi-connect,koi\nkoi:x:988:\nbad:x:notanumber:\n',
		);
		expect(await groupId('koi-control', file)).toBe(987);
		expect(await groupId('koi', file)).toBe(988);
		expect(await groupId('docker', file)).toBeUndefined();
		expect(await groupId('bad', file)).toBeUndefined();
		expect(await groupId('koi-control', join(dir, 'missing'))).toBeUndefined();
	});

	test('the socket takes the group it is given, and mode 0660, with every start', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-sock-'));
		const socket = join(dir, 'control.sock');
		// A group this user may give a file: its own.
		const gid = process.getgid?.() ?? 0;
		const server = await startControlServer(socket, deps({}), { gid });
		try {
			const info = await stat(socket);
			expect(info.gid).toBe(gid);
			expect(info.mode & 0o777).toBe(0o660);
		} finally {
			server.stop(true);
		}
		const plain = await startControlServer(socket, deps({}));
		try {
			expect((await stat(socket)).mode & 0o777).toBe(0o660);
		} finally {
			plain.stop(true);
		}
	});

	test('a group koid may not give is logged, and the socket keeps serving with its own group and mode 0660', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-sock-'));
		const socket = join(dir, 'control.sock');
		// The kernel refuses a group this user is not in, as on a box provisioned
		// before koi joined koi-control. Root may give any group, so root gets a
		// gid no chown takes.
		const groups = process.getgroups?.() ?? [];
		let gid = 1;
		while (groups.includes(gid)) gid++;
		const asRoot = process.getuid?.() === 0;
		if (asRoot) gid = 2 ** 32;
		const logged: string[] = [];
		const server = await startControlServer(socket, deps({}), {
			gid,
			log: (message) => logged.push(message),
		});
		try {
			expect(logged).toHaveLength(1);
			expect(logged[0]).toContain(`could not give ${socket} the group ${gid}`);
			expect(logged[0]).toContain("the SSH gateway's account cannot open it");
			expect(logged[0]).toContain('scripts/provision-host.sh');
			if (!asRoot) expect(logged[0]).toContain('EPERM');
			const info = await stat(socket);
			expect(info.gid).not.toBe(gid);
			expect(info.gid).toBe(process.getgid?.() ?? info.gid);
			expect(info.mode & 0o777).toBe(0o660);
			const health = await fetch('http://koid/health', { unix: socket } as RequestInit);
			expect(health.status).toBe(200);
			expect(await health.json()).toEqual({ ok: true });
		} finally {
			server.stop(true);
			await rm(dir, { recursive: true, force: true });
		}
	});
});
