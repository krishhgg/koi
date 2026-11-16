import { describe, expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { CTL_EXIT, encodeCtlArgs, type HostInfo } from '../../../packages/shared/src/index.ts';
import {
	CONTROL_SOCKET,
	gateway,
	parseCommand,
	RefusedError,
	relay,
	sanitizeEnvironment,
	socketFromArgv,
} from '../koi-ssh-gateway.ts';

const PING = `ctl-b64 ${encodeCtlArgs(['ping'])}`;

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

describe('parseCommand', () => {
	test('takes exactly tunnel-v1 and ctl-b64 with one blob koid would decode', () => {
		expect(parseCommand('tunnel-v1')).toEqual({ verb: 'tunnel-v1' });
		const blob = encodeCtlArgs(['status', 'hello-pr-7', 'b'.repeat(20), '0']);
		expect(parseCommand(`ctl-b64 ${blob}`)).toEqual({ verb: 'ctl-b64', blob });
	});

	test('refuses everything else, and names file transfer for what it is', () => {
		const refused = (command: string | undefined) => {
			const err = (() => {
				try {
					parseCommand(command);
					return undefined;
				} catch (e) {
					return e;
				}
			})();
			expect(err).toBeInstanceOf(RefusedError);
			return (err as Error).message;
		};
		// A shell: no command at all.
		expect(refused(undefined)).toContain('runs no shell');
		expect(refused('')).toContain('runs no shell');
		// Surrounding or extra whitespace, a second word, another case.
		for (const c of [
			' tunnel-v1',
			'tunnel-v1 ',
			'tunnel-v1\n',
			'TUNNEL-V1',
			'tunnel-v1 extra',
			'tunnel-v2',
			'tunnel-v1; sh',
		]) {
			expect(refused(c)).toContain('is not a command of this account');
		}
		// A blob that is missing, doubled, badly encoded, or not an argument list.
		expect(refused('ctl-b64')).toContain('is not a command');
		expect(refused('ctl-b64 ')).toContain('is not a command');
		expect(refused('ctl-b64  abc')).toContain('is not a command');
		expect(refused(`ctl-b64\t${encodeCtlArgs(['ping'])}`)).toContain('is not a command');
		expect(refused(`ctl-b64 ${encodeCtlArgs(['ping'])} ${encodeCtlArgs(['ping'])}`)).toContain(
			'is not a command',
		);
		expect(refused('ctl-b64 not*base64')).toContain('is not a command');
		expect(refused(`ctl-b64 ${Buffer.from('"a string"').toString('base64')}`)).toContain(
			'ctl-b64:',
		);
		expect(refused(`ctl-b64 ${Buffer.from('[]').toString('base64')}`)).toContain('ctl-b64:');
		expect(refused(`ctl-b64 ${Buffer.from('{"a":1}').toString('base64')}`)).toContain('ctl-b64:');
		expect(refused(`ctl-b64 ${'A'.repeat(20_000)}`)).toContain('ctl-b64:');
		expect(refused(`ctl-b64 ${'A'.repeat(40_000)}`)).toContain('too long');
		// File transfer and friends.
		for (const c of [
			'scp -t /tmp/x',
			'scp -f /etc/passwd',
			'sftp',
			'internal-sftp',
			'rsync --server -e.LsfxC . /',
			'sftp-server',
		]) {
			expect(refused(c)).toContain('file transfer is not available on this account');
		}
		// Environment and shells.
		for (const c of [
			'env LD_PRELOAD=/x tunnel-v1',
			'LD_PRELOAD=/x tunnel-v1',
			'bash',
			'sh -c tunnel-v1',
			'/bin/sh',
			'koid ctl ping',
			`exec ${PING}`,
		]) {
			expect(refused(c)).toContain('is not a command of this account');
		}
	});
});

describe('socketFromArgv and sanitizeEnvironment', () => {
	test('the socket is the fixed path, or the one the sshd configuration gives', () => {
		expect(socketFromArgv([])).toBe(CONTROL_SOCKET);
		expect(CONTROL_SOCKET).toBe('/run/koi/control.sock');
		expect(socketFromArgv(['--socket', '/tmp/k.sock'])).toBe('/tmp/k.sock');
		for (const argv of [
			['--socket'],
			['--socket', 'relative'],
			['--socket', '/a', '/b'],
			['--other'],
			['/a'],
		]) {
			expect(() => socketFromArgv(argv)).toThrow('usage: koi-ssh-gateway');
		}
	});

	test('the environment is emptied, whatever it held', () => {
		const env: NodeJS.ProcessEnv = {
			PATH: '/usr/bin',
			KOID_CONTROL_SOCKET: '/elsewhere.sock',
			LD_PRELOAD: '/x.so',
			HTTP_PROXY: 'http://proxy',
			SSH_ORIGINAL_COMMAND: 'tunnel-v1',
		};
		sanitizeEnvironment(env);
		expect(Object.keys(env)).toEqual([]);
	});
});

// koid's control API, as far as the gateway tests need it.
async function koid() {
	const dir = await mkdtemp(join(tmpdir(), 'koi-gw-'));
	const socket = join(dir, 'control.sock');
	const seen: string[] = [];
	const server = Bun.serve({
		unix: socket,
		idleTimeout: 0,
		async fetch(req: Request) {
			const path = new URL(req.url).pathname;
			seen.push(`${req.method} ${path}`);
			if (path === '/health') return Response.json({ ok: true });
			if (path === '/host') return Response.json(HOST);
			if (req.method === 'PUT') {
				let bytes = 0;
				for await (const chunk of req.body as ReadableStream<Uint8Array>) bytes += chunk.byteLength;
				return Response.json({ bytes });
			}
			return Response.json({ error: 'not found' }, { status: 404 });
		},
	} as never);
	return {
		socket,
		seen,
		stop: async () => {
			server.stop(true);
			await rm(dir, { recursive: true, force: true });
		},
	};
}

function streams() {
	const stdin = new PassThrough();
	const stdout = new PassThrough();
	let out = '';
	let err = '';
	stdout.on('data', (d: Buffer) => {
		out += d.toString();
	});
	return {
		stdin,
		stdout,
		stderr: (t: string) => {
			err += t;
		},
		out: () => out,
		err: () => err,
	};
}

describe('gateway', () => {
	test('ctl-b64 runs koid ctl against the socket and exits as it does', async () => {
		const k = await koid();
		try {
			const s = streams();
			expect(await gateway(PING, [], k.socket, s)).toBe(CTL_EXIT.ok);
			expect(s.out()).toBe('{"ok":true}\n');
			expect(s.err()).toBe('');
			const d = streams();
			expect(await gateway(`ctl-b64 ${encodeCtlArgs(['describe'])}`, [], k.socket, d)).toBe(0);
			expect(JSON.parse(d.out())).toEqual(HOST);
			// A command koid ctl refuses is refused by it, with its status.
			const r = streams();
			expect(await gateway(`ctl-b64 ${encodeCtlArgs(['down', 'nothing'])}`, [], k.socket, r)).toBe(
				CTL_EXIT.refused,
			);
			expect(r.err()).toContain('not found');
			expect(k.seen).toEqual(['GET /health', 'GET /host', 'DELETE /previews/nothing']);
		} finally {
			await k.stop();
		}
	});

	test('a refused request runs nothing and reaches koid with nothing', async () => {
		const k = await koid();
		try {
			for (const command of [undefined, 'scp -t /tmp', 'bash', 'tunnel-v1 x']) {
				const s = streams();
				expect(await gateway(command, [], k.socket, s)).toBe(CTL_EXIT.usage);
				expect(s.out()).toBe('');
				expect(s.err()).toStartWith('koi-ssh-gateway: ');
			}
			expect(k.seen).toEqual([]);
		} finally {
			await k.stop();
		}
	});

	test('without koid, ctl-b64 and tunnel-v1 say so and exit as koid ctl does', async () => {
		const c = streams();
		expect(await gateway(PING, [], '/nonexistent/control.sock', c)).toBe(CTL_EXIT.unavailable);
		expect(c.err()).toContain('cannot reach koid');
		const t = streams();
		expect(await gateway('tunnel-v1', [], '/nonexistent/control.sock', t)).toBe(
			CTL_EXIT.unavailable,
		);
		expect(t.err()).toContain('cannot reach koid at /nonexistent/control.sock');
		expect(t.out()).toBe('');
	});

	test('the fixed socket is used however the environment is set', async () => {
		const k = await koid();
		try {
			process.env.KOID_CONTROL_SOCKET = k.socket;
			const s = streams();
			expect(await gateway(PING, [], socketFromArgv([]), s)).toBe(CTL_EXIT.unavailable);
			expect(k.seen).toEqual([]);
		} finally {
			delete process.env.KOID_CONTROL_SOCKET;
			await k.stop();
		}
	});
});

describe('relay', () => {
	test('copies bytes both ways and ends with the session, parsing nothing', async () => {
		const k = await koid();
		try {
			const s = streams();
			const done = relay(k.socket, s.stdin, s.stdout, s.stderr);
			const body = new Uint8Array(300_000);
			s.stdin.write(
				`PUT /v1/uploads/x/source HTTP/1.1\r\nHost: koid\r\nContent-Length: ${body.byteLength}\r\n\r\n`,
			);
			for (let at = 0; at < body.byteLength; at += 65536)
				s.stdin.write(body.subarray(at, at + 65536));
			s.stdin.write('GET /health HTTP/1.1\r\nHost: koid\r\n\r\n');
			for (let i = 0; i < 200 && !s.out().includes('{"ok":true}'); i++) await Bun.sleep(10);
			expect(s.out()).toContain('{"bytes":300000}');
			expect(s.out()).toContain('{"ok":true}');
			expect(k.seen).toEqual(['PUT /v1/uploads/x/source', 'GET /health']);
			// The session's input ends: koid sees the end and closes, the relay ends.
			s.stdin.end();
			expect(await done).toBe(0);
			expect(s.err()).toBe('');
		} finally {
			await k.stop();
		}
	});

	test('ends when koid closes first, leaving the session to the gateway', async () => {
		const k = await koid();
		try {
			const s = streams();
			const done = relay(k.socket, s.stdin, s.stdout, s.stderr);
			// A request Bun answers and then closes on.
			s.stdin.write('GET /health HTTP/1.0\r\nHost: koid\r\n\r\n');
			expect(await done).toBe(0);
			expect(s.out()).toContain('{"ok":true}');
			// stdin was unpiped and is still open: the process ends it, not the relay.
			expect(s.stdin.destroyed).toBe(false);
		} finally {
			await k.stop();
		}
	});
});
