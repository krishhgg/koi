import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { egressControl, proxyPreviews } from '../src/egress.ts';

const TOKEN = `koi_${'a'.repeat(32)}`;
const LABEL = 'storefront-pr-7';

const servers: Server[] = [];
const sockets: Socket[] = [];
afterEach(async () => {
	for (const socket of sockets.splice(0)) socket.destroy();
	for (const server of servers.splice(0)) await new Promise((done) => server.close(done));
});

// A stand-in for the egress proxy's control socket: a real unix socket that
// collects each request line and hands it, with the connection, to `answer`.
// `connected` sees each connection first. `closed` has a promise per
// connection that settles when it closes.
async function proxy(
	answer: (line: string, socket: Socket) => void,
	connected: (socket: Socket) => void = () => {},
) {
	const path = join(await mkdtemp(join(tmpdir(), 'koid-egress-')), 'control.sock');
	const requests: unknown[] = [];
	const closed: Array<Promise<void>> = [];
	const server = createServer((socket) => {
		sockets.push(socket);
		closed.push(new Promise((done) => socket.on('close', () => done())));
		socket.on('error', () => {});
		socket.setEncoding('utf8');
		let text = '';
		socket.on('data', (chunk: string) => {
			text += chunk;
			const end = text.indexOf('\n');
			if (end === -1) return;
			const line = text.slice(0, end);
			text = text.slice(end + 1);
			requests.push(JSON.parse(line));
			answer(line, socket);
		});
		connected(socket);
	});
	servers.push(server);
	await new Promise<void>((listening) => server.listen(path, listening));
	return { path, requests, closed };
}

const replyWith = (reply: string) => (_line: string, socket: Socket) => socket.end(reply);

describe('egressControl replies', () => {
	test('sends one request line and takes {"ok": true}', async () => {
		const p = await proxy(replyWith('{"ok": true}\n'));
		const egress = egressControl(p.path);
		await egress.forget(TOKEN);
		await egress.previews({ '172.19.0.5': LABEL });
		expect(p.requests).toEqual([
			{ op: 'forget', token: TOKEN },
			{ op: 'previews', previews: { '172.19.0.5': LABEL } },
		]);
	});

	test('registers keys for a preview and returns the tokens the proxy made', async () => {
		const p = await proxy(replyWith(`{"ok": true, "tokens": {"openai": "${TOKEN}"}}\n`));
		const tokens = await egressControl(p.path).register(LABEL, { openai: 'sk-1' }, '198.51.100.7');
		expect(tokens).toEqual({ openai: TOKEN });
		expect(p.requests).toEqual([
			{ op: 'register', label: LABEL, keys: { openai: 'sk-1' }, source: '198.51.100.7' },
		]);
	});

	test.each([
		'{"ok": true}',
		'{"ok": true, "tokens": {}}',
		`{"ok": true, "tokens": {"anthropic": "${TOKEN}"}}`,
		`{"ok": true, "tokens": {"openai": "${TOKEN}", "anthropic": "${TOKEN}"}}`,
		'{"ok": true, "tokens": {"openai": "sk-not-a-token"}}',
	])('refuses a registration reply without exactly one token per key: %p', async (reply) => {
		const p = await proxy(replyWith(`${reply}\n`));
		await expect(egressControl(p.path).register(LABEL, { openai: 'sk-1' }, 'x')).rejects.toThrow(
			'the egress proxy sent an unreadable reply',
		);
	});

	test("rejects with the proxy's error when it refuses", async () => {
		const p = await proxy(replyWith('{"ok": false, "error": "bad token"}\n'));
		await expect(egressControl(p.path).forget(TOKEN)).rejects.toThrow('bad token');
	});

	test.each([
		'[]',
		'null',
		'{"ok": "true"}',
		'{"ok": 1}',
		'{"ok": false}',
		'{"ok": false, "error": {"why": "x"}}',
		'not json',
		'',
	])("rejects a reply that is not the proxy's shape: %p", async (reply) => {
		const p = await proxy(replyWith(`${reply}\n`));
		await expect(egressControl(p.path).forget(TOKEN)).rejects.toThrow(
			'the egress proxy sent an unreadable reply',
		);
	});
});

describe('egressControl connections', () => {
	test('takes a reply that arrives in pieces, one cut inside a character', async () => {
		const reply = Buffer.from('{"ok": false, "error": "refus\u00e9"}\n');
		const inside = reply.indexOf(0xc3) + 1;
		const p = await proxy((_line, socket) => {
			socket.write(reply.subarray(0, 6));
			setTimeout(() => socket.write(reply.subarray(6, inside)), 30);
			setTimeout(() => socket.end(reply.subarray(inside)), 60);
		});
		await expect(egressControl(p.path).forget(TOKEN)).rejects.toThrow(/^refus\u00e9$/);
	});

	test('answers once the reply line is in, without waiting for the proxy to hang up', async () => {
		const p = await proxy((_line, socket) => socket.write('{"ok": true}\n'));
		await egressControl(p.path, { timeoutMs: 3_000 }).forget(TOKEN);
		await p.closed[0];
	});

	test('sends a request too large for one write whole', async () => {
		const p = await proxy((_line, socket) =>
			socket.end(`{"ok": true, "tokens": {"openai": "${TOKEN}"}}\n`),
		);
		const key = 'k'.repeat(8 * 1024 * 1024);
		await egressControl(p.path, { timeoutMs: 3_000 }).register(LABEL, { openai: key }, 'unknown');
		expect(p.requests).toEqual([
			{ op: 'register', label: LABEL, keys: { openai: key }, source: 'unknown' },
		]);
	});

	test('rejects at once when the proxy hangs up before the request is written', async () => {
		const p = await proxy(
			() => {},
			(socket) => socket.destroy(),
		);
		const started = Date.now();
		await expect(
			egressControl(p.path, { timeoutMs: 3_000 }).register(
				LABEL,
				{ openai: 'k'.repeat(8 * 1024 * 1024) },
				'unknown',
			),
		).rejects.toThrow();
		expect(Date.now() - started).toBeLessThan(2_000);
	});

	test('rejects at once when the proxy hangs up without answering', async () => {
		const p = await proxy((_line, socket) => socket.destroy());
		const started = Date.now();
		await expect(egressControl(p.path, { timeoutMs: 3_000 }).forget(TOKEN)).rejects.toThrow(
			'the egress proxy sent an unreadable reply',
		);
		expect(Date.now() - started).toBeLessThan(2_000);
	});

	test('rejects at once when the socket is missing or refuses the connection', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-egress-'));
		// A file that is not a listening socket refuses connections, as a
		// socket left behind by a proxy that has exited does.
		const refusing = join(dir, 'plain');
		await writeFile(refusing, '');
		for (const [path, code] of [
			[join(dir, 'missing.sock'), 'ENOENT'],
			[refusing, 'ECONNREFUSED'],
		] as const) {
			const started = Date.now();
			const error = await egressControl(path, { timeoutMs: 3_000 })
				.forget(TOKEN)
				.then(
					() => undefined,
					(err: unknown) => err,
				);
			expect((error as NodeJS.ErrnoException | undefined)?.code).toBe(code);
			expect(Date.now() - started).toBeLessThan(2_000);
		}
	});

	test('gives up after the time limit and hangs up', async () => {
		const p = await proxy(() => {});
		await expect(egressControl(p.path, { timeoutMs: 200 }).forget(TOKEN)).rejects.toThrow(
			'the egress proxy did not answer',
		);
		await p.closed[0];
	});
});

describe('proxyPreviews', () => {
	const MAP = { '172.19.0.5': LABEL };

	test('resolves once the proxy has taken the map', async () => {
		const p = await proxy(replyWith('{"ok": true}\n'));
		await proxyPreviews(egressControl(p.path))(MAP);
		expect(p.requests).toEqual([{ op: 'previews', previews: MAP }]);
	});

	test('resolves when nothing listens: no policy is loaded, and no map with it', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-egress-'));
		const refusing = join(dir, 'plain');
		await writeFile(refusing, '');
		for (const path of [join(dir, 'missing.sock'), refusing]) {
			await proxyPreviews(egressControl(path, { timeoutMs: 3_000 }))(MAP);
		}
	});

	test('rejects when the proxy refuses the map or does not answer', async () => {
		const refuses = await proxy(
			replyWith('{"ok": false, "error": "bad preview address or label"}\n'),
		);
		await expect(proxyPreviews(egressControl(refuses.path))(MAP)).rejects.toThrow('bad preview');
		const silent = await proxy(() => {});
		await expect(
			proxyPreviews(egressControl(silent.path, { timeoutMs: 200 }))(MAP),
		).rejects.toThrow('did not answer');
	});
});
