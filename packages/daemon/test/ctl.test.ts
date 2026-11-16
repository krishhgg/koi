import { describe, expect, test } from 'bun:test';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { encodeCtlArgs } from '@koi/shared';
import { type CtlIo, ctl, ctlEncoded } from '../src/ctl.ts';

const ID = 'abcdefghij0123456';

function io(status = 200, body: unknown = { ok: true }) {
	const out: string[] = [];
	const err: string[] = [];
	const requests: Array<{ path: string; method: string; body: string | null }> = [];
	const fakeIo: CtlIo = {
		stdout: (t) => {
			out.push(t);
		},
		stderr: (t) => {
			err.push(t);
		},
		fetch: async (path, init) => {
			requests.push({ path, method: init?.method ?? 'GET', body: (init?.body as string) ?? null });
			return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
		},
	};
	return { out, err, requests, io: fakeIo };
}

describe('koid ctl', () => {
	test('maps commands to control API calls', async () => {
		const cases: Array<[string[], string, string]> = [
			[['ping'], '/health', 'GET'],
			[['describe'], '/host', 'GET'],
			[['up', 'abcdefghij0123456'], '/up', 'POST'],
			[['list'], '/previews', 'GET'],
			[['list', 'hello-pr-7'], '/previews?after=hello-pr-7', 'GET'],
			[['status', 'hello-pr-7'], '/previews/hello-pr-7', 'GET'],
			[['status', 'hello-pr-7', ID], `/previews/hello-pr-7?attempt=${ID}`, 'GET'],
			[['status', 'hello-pr-7', ID, '0'], `/previews/hello-pr-7?attempt=${ID}&since=0`, 'GET'],
			[['status', 'hello-pr-7', ID, '120'], `/previews/hello-pr-7?attempt=${ID}&since=120`, 'GET'],
			[['logs', 'hello-pr-7', '50'], '/previews/hello-pr-7/logs?tail=50', 'GET'],
			[['buildlog', 'hello-pr-7', '1'], '/previews/hello-pr-7/buildlog?tail=1', 'GET'],
			[['logs', 'hello-pr-7', '5000'], '/previews/hello-pr-7/logs?tail=5000', 'GET'],
			[['buildlog', 'hello-pr-7'], '/previews/hello-pr-7/buildlog?tail=200', 'GET'],
			[['down', 'hello-pr-7'], '/previews/hello-pr-7', 'DELETE'],
			[['down', 'hello-pr-7', '--force'], '/previews/hello-pr-7?force=1', 'DELETE'],
			[
				['lease', 'hello-pr-7', '--holder', 'dev@laptop', '--ttl-seconds', '600'],
				'/previews/hello-pr-7/lease',
				'POST',
			],
			[
				['lease', 'hello-pr-7', '--ttl-seconds', '7200', '--holder', 'ci run 42'],
				'/previews/hello-pr-7/lease',
				'POST',
			],
			[['release', 'hello-pr-7', ID], `/previews/hello-pr-7/lease/${ID}`, 'DELETE'],
		];
		for (const [args, path, method] of cases) {
			const t = io();
			expect(await ctl(args, t.io)).toBe(0);
			expect(t.requests).toEqual([expect.objectContaining({ path, method })]);
		}
	});

	test('sends the lease holder and ttl as JSON', async () => {
		const t = io();
		expect(
			await ctl(['lease', 'hello-pr-7', '--holder', 'dev@laptop', '--ttl-seconds', '600'], t.io),
		).toBe(0);
		expect(JSON.parse(t.requests[0]?.body ?? '')).toEqual({
			holder: 'dev@laptop',
			ttlSeconds: 600,
		});
	});

	test('validates arguments before sending anything', async () => {
		for (const args of [
			['up', 'x; rm -rf /'],
			['lease', 'hello-pr-7'],
			['lease', 'hello-pr-7', '--holder', 'kg'],
			['lease', 'hello-pr-7', '--ttl-seconds', '60'],
			['lease', 'hello-pr-7', '--holder', 'kg', '--ttl-seconds', '0'],
			['lease', 'hello-pr-7', '--holder', 'kg', '--ttl-seconds', '7201'],
			['lease', 'hello-pr-7', '--holder', 'kg', '--ttl-seconds', '60', '--holder', 'x'],
			['lease', 'hello-pr-7', '--holder', 'a\u0001b', '--ttl-seconds', '60'],
			['lease', 'hello-pr-7', '--holder', '', '--ttl-seconds', '60'],
			['lease', 'hello-pr-7', '--bogus', 'x', '--holder', 'kg', '--ttl-seconds', '60'],
			['lease', '../etc', '--holder', 'kg', '--ttl-seconds', '60'],
			['release', 'hello-pr-7'],
			['release', 'hello-pr-7', '../x'],
			['release', '../etc', ID],
			['down', 'hello-pr-7', '--nuke'],
			['down', 'hello-pr-7', '--force', 'x'],
			['status', '../etc', ID],
			['status', 'hello', '0'],
			['status', 'hello', 'x; rm -rf /'],
			['list', '../etc'],
			['logs', 'hello', '-1'],
			['status', 'hello', ID, '-1'],
			['buildlog', 'hello', '0'],
			['buildlog', 'hello', '5001'],
			['logs', 'hello', '5001'],
			['buildlog', '../etc', '5'],
			['status', 'hello', ID, '01'],
			['status', 'hello', ID, 'x'],
			['bogus'],
			[],
		]) {
			const t = io();
			expect(await ctl(args, t.io)).toBe(2);
			expect(t.requests).toEqual([]);
		}
	});

	test('prints errors to stderr and exits 1', async () => {
		const t = io(409, { error: 'nope' });
		expect(await ctl(['up', 'abcdefghij0123456'], t.io)).toBe(1);
		expect(t.err.join('')).toContain('nope');
	});

	test('keeps a long container log under 16,000 characters, from its end', async () => {
		const log = Array.from({ length: 5000 }, (_, i) => `line ${i + 1} ${'é'.repeat(20)}`).join(
			'\n',
		);
		const t = io(200, log);
		expect(await ctl(['logs', 'hello-pr-7', '5000'], t.io)).toBe(0);
		const out = t.out.join('');
		expect(Buffer.byteLength(out)).toBeLessThanOrEqual(16_000);
		const lines = out.split('\n');
		expect(lines[0]).toStartWith('[koid: earlier output cut');
		expect(lines[1]).toMatch(/^line \d+ é{20}$/);
		expect(lines.at(-2)).toBe(`line 5000 ${'é'.repeat(20)}`);
		expect(lines.at(-1)).toBe('');
	});

	test('keeps a long build log under 16,000 characters too', async () => {
		const t = io(200, 'x'.repeat(40_000));
		expect(await ctl(['buildlog', 'hello-pr-7', '5000'], t.io)).toBe(0);
		expect(Buffer.byteLength(t.out.join(''))).toBeLessThanOrEqual(16_000);
	});

	test('passes a short container log and JSON replies through whole', async () => {
		const t = io(200, 'container says hi\n');
		expect(await ctl(['logs', 'hello-pr-7'], t.io)).toBe(0);
		expect(t.out.join('')).toBe('container says hi\n');
		const big = { record: 'x'.repeat(20_000) };
		const s = io(200, big);
		expect(await ctl(['status', 'hello-pr-7', ID], s.io)).toBe(0);
		expect(JSON.parse(s.out.join(''))).toEqual(big);
	});

	test('ping prints what koid says and gives up on a koid that does not answer', async () => {
		const t = io(200, { ok: true });
		expect(await ctl(['ping'], t.io)).toBe(0);
		expect(JSON.parse(t.out.join(''))).toEqual({ ok: true });
		let signal: AbortSignal | undefined;
		t.io.fetch = async (_path, init) => {
			signal = init?.signal ?? undefined;
			throw new Error('timed out');
		};
		expect(await ctl(['ping'], t.io)).toBe(3);
		expect(signal).toBeInstanceOf(AbortSignal);
	});

	test('exits 3 when koid cannot be reached', async () => {
		const t = io();
		t.io.fetch = async () => {
			throw new Error('ENOENT /run/koi/control.sock');
		};
		expect(await ctl(['list'], t.io)).toBe(3);
		expect(t.err.join('')).toContain('cannot reach koid');
	});
});

describe('koid ctl-b64', () => {
	test('runs the command the blob encodes', async () => {
		const t = io();
		expect(await ctlEncoded([encodeCtlArgs(['status', 'hello-pr-7', ID, '120'])], t.io)).toBe(0);
		expect(t.requests).toEqual([
			expect.objectContaining({ path: `/previews/hello-pr-7?attempt=${ID}&since=120` }),
		]);
	});

	test('checks the decoded arguments as koid ctl does', async () => {
		const t = io();
		expect(await ctlEncoded([encodeCtlArgs(['status', 'x; rm -rf /'])], t.io)).toBe(2);
		expect(t.requests).toEqual([]);
	});

	test('refuses anything but one blob of arguments, sending nothing', async () => {
		for (const args of [
			[],
			['status', 'hello-pr-7'],
			['not base64!'],
			[encodeCtlArgs(['ping']), 'x'],
		]) {
			const t = io();
			expect(await ctlEncoded(args, t.io)).toBe(2);
			expect(t.err.join('')).toStartWith('koid ctl-b64:');
			expect(t.requests).toEqual([]);
		}
	});

	test("koid's entry point decodes the blob and asks the control socket", async () => {
		const socket = join(await mkdtemp(join(tmpdir(), 'koid-ctl-')), 'control.sock');
		const paths: string[] = [];
		const server = Bun.serve({
			unix: socket,
			fetch: (request) => {
				paths.push(new URL(request.url).pathname);
				return Response.json({ ok: true });
			},
		});
		try {
			const koid = (...args: string[]) =>
				Bun.spawn([process.execPath, join(import.meta.dir, '../src/main.ts'), ...args], {
					env: { ...process.env, KOID_CONTROL_SOCKET: socket },
					stdout: 'pipe',
					stderr: 'pipe',
				});
			const ok = koid('ctl-b64', encodeCtlArgs(['status', 'hello-pr-7']));
			expect(await ok.exited).toBe(0);
			expect(await new Response(ok.stdout).text()).toBe('{"ok":true}\n');
			const refused = koid('ctl-b64', encodeCtlArgs(['status', '$(id)']));
			expect(await refused.exited).toBe(2);
			// An unknown command is refused, never taken as a request to run the
			// daemon, which would touch the box's containers.
			const unknown = koid('ctl-json', '[]');
			expect(await unknown.exited).toBe(2);
			expect(await new Response(unknown.stderr).text()).toStartWith('koid: unknown command');
			expect(paths).toEqual(['/previews/hello-pr-7']);
		} finally {
			server.stop(true);
		}
	});
});

describe('koid ctl verify', () => {
	const PLAN = 'p'.repeat(20);
	const RUN = 'r'.repeat(20);
	const DIGEST = `sha256:${'1'.repeat(64)}`;

	test('maps the verify subcommands to the verification routes', async () => {
		const cases: Array<[string[], string, string, unknown?]> = [
			[
				['verify', 'plan', 'hello-pr-7', '--profile', 'pr'],
				'/v1/verification-plans',
				'POST',
				{ version: 1, label: 'hello-pr-7', profile: 'pr' },
			],
			[['verify', 'plan-page', PLAN], `/v1/verification-plans/${PLAN}`, 'GET'],
			[
				['verify', 'plan-page', PLAN, 'uncovered:12'],
				`/v1/verification-plans/${PLAN}?after=uncovered:12`,
				'GET',
			],
			[
				['verify', 'run', PLAN, DIGEST],
				'/v1/verification-runs',
				'POST',
				{ version: 1, planId: PLAN, planDigest: DIGEST, mode: 'runner' },
			],
			[['verify', 'status', RUN], `/v1/verification-runs/${RUN}/status`, 'GET'],
			[['verify', 'status', RUN, '40'], `/v1/verification-runs/${RUN}/status?after=40`, 'GET'],
			[['verify', 'events', RUN], `/v1/verification-runs/${RUN}/events?after=0&limit=200`, 'GET'],
			[
				['verify', 'events', RUN, '17', '50'],
				`/v1/verification-runs/${RUN}/events?after=17&limit=50`,
				'GET',
			],
			[['verify', 'evidence', RUN], `/v1/verification-runs/${RUN}/evidence`, 'GET'],
			[['verify', 'evidence', RUN, '4'], `/v1/verification-runs/${RUN}/evidence?after=4`, 'GET'],
			[
				['verify', 'artifact', RUN, 'recorder:aria:2'],
				`/v1/verification-runs/${RUN}/artifacts/recorder%3Aaria%3A2?offset=0&length=6144`,
				'GET',
			],
			[
				['verify', 'artifact', RUN, 'recorder:aria:2', '6144', '100'],
				`/v1/verification-runs/${RUN}/artifacts/recorder%3Aaria%3A2?offset=6144&length=100`,
				'GET',
			],
			[['verify', 'cancel', RUN], `/v1/verification-runs/${RUN}/cancel`, 'POST'],
		];
		for (const [args, path, method, body] of cases) {
			const t = io();
			expect(await ctl(args, t.io)).toBe(0);
			expect(t.requests).toEqual([
				{ path, method, body: body === undefined ? null : JSON.stringify(body) },
			]);
		}
	});

	test('checks every argument before sending anything', async () => {
		const bad: string[][] = [
			['verify'],
			['verify', 'act', RUN],
			['verify', 'plan', 'Bad_Label', '--profile', 'pr'],
			['verify', 'plan', 'hello-pr-7'],
			['verify', 'plan', 'hello-pr-7', '--profile', 'Not A Slug'],
			['verify', 'plan', 'hello-pr-7', '--profile', 'pr', '--points', 'x'],
			['verify', 'plan-page', 'short'],
			['verify', 'plan-page', PLAN, 'points:x'],
			['verify', 'run', PLAN],
			['verify', 'run', PLAN, 'sha256:short'],
			['verify', 'run', PLAN, DIGEST, 'extra'],
			['verify', 'status', 'not-an-id'],
			['verify', 'status', RUN, '-1'],
			['verify', 'events', RUN, '0', '0'],
			['verify', 'events', RUN, '0', '201'],
			['verify', 'artifact', RUN, '../../etc/passwd'],
			['verify', 'artifact', RUN, 'recorder:aria:2', '0', '7000'],
			['verify', 'artifact', RUN, 'recorder:aria:2', 'x'],
			['verify', 'cancel', RUN, 'extra'],
		];
		for (const args of bad) {
			const t = io();
			expect(await ctl(args, t.io)).toBe(2);
			expect(t.requests).toEqual([]);
			expect(t.err.join('')).toStartWith('koid ctl: ');
		}
	});

	test('prints a versioned refusal on stderr and exits 1', async () => {
		const t = io(409, {
			version: 1,
			error: { code: 'plan_stale', message: 'plan again', retryable: false },
		});
		expect(await ctl(['verify', 'run', PLAN, DIGEST], t.io)).toBe(1);
		expect(JSON.parse(t.err.join(''))).toEqual({
			version: 1,
			error: { code: 'plan_stale', message: 'plan again', retryable: false },
		});
	});
});
