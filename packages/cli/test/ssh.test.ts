import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { connect as netConnect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { CTL_EXIT, decodeCtlArgs, type UpRequest } from '@koi/shared';
import { CTL_USAGE } from '../../daemon/src/ctl.ts';
import {
	CONTROL_PERSIST_S,
	quoteSshValue,
	type SpawnRequest,
	SshClient,
	type SshProcess,
	type SshSpawn,
	type SshTarget,
	sshArgs,
	sshEnv,
	sshPathProblem,
} from '../src/ssh.ts';
import {
	BoxUnavailableError,
	HostMismatchError,
	UnknownOutcomeError,
	UnsupportedCapabilityError,
} from '../src/transport.ts';
import {
	digestFile,
	HostKeyError,
	SSH_DEFAULT_LIMITS,
	type SshLimits,
	sshFailureIsTransient,
	sshTransport,
} from '../src/transports/ssh.ts';
import { hostInfoFor, previewRecord } from './koid.ts';

const TARGET: SshTarget = {
	host: '203.0.113.10',
	port: 22,
	user: 'koi-connect',
	identityFile: '/home/operator/.ssh/koi_team_ed25519',
	knownHostsFile: '/home/operator/.config/koi/known_hosts',
	hostKeyAlias: 'team',
};

const AGENT_TARGET: SshTarget = {
	...TARGET,
	identityFile: undefined,
	identityPublicKey: '/home/operator/.ssh/koi_team_ed25519.pub',
};

// Shell metacharacters, quotes, a newline and text outside ASCII.
const NASTY = `x'; rm -rf / $(id) \`id\` "q" \\ | & > < * ?\n é😀`;

// An environment variable as ssh reads one in an option value.
// biome-ignore lint/suspicious/noTemplateCurlyInString: ssh's syntax, not a template of this file
const ENV_REF = '${UNSET}';

const encode = (text: string) => new TextEncoder().encode(text);

function textStream(text = ''): ReadableStream<Uint8Array> {
	return new ReadableStream({
		start(c) {
			if (text !== '') c.enqueue(encode(text));
			c.close();
		},
	});
}

interface Script {
	code?: number;
	stdout?: string;
	stderr?: string;
	// Never exits until killed.
	hang?: boolean;
}

// A process that prints the script and exits, or hangs until killed.
function scripted(s: Script): SshProcess & { killed: boolean } {
	let resolveExit!: (code: number) => void;
	const exited = new Promise<number>((r) => {
		resolveExit = r;
	});
	let out!: ReadableStreamDefaultController<Uint8Array>;
	const stdout = new ReadableStream<Uint8Array>({
		start(c) {
			out = c;
			if (s.stdout !== undefined && s.stdout !== '') c.enqueue(encode(s.stdout));
			if (!s.hang) c.close();
		},
	});
	if (!s.hang) resolveExit(s.code ?? 0);
	const proc = {
		killed: false,
		write: async () => {},
		end: async () => {},
		stdout,
		stderr: textStream(s.stderr),
		exited,
		kill() {
			proc.killed = true;
			try {
				out.close();
			} catch {}
			resolveExit(137);
		},
	};
	return proc;
}

function fakeSsh(script: (req: SpawnRequest) => SshProcess) {
	const requests: SpawnRequest[] = [];
	const spawn: SshSpawn = (req) => {
		requests.push(req);
		return script(req);
	};
	return { requests, spawn };
}

// The command a spawn request asks the host to run.
const commandOf = (req: SpawnRequest) => req.cmd.at(-1) ?? '';
const ctlArgsOf = (req: SpawnRequest) => decodeCtlArgs(commandOf(req).split(' ')[1] ?? '');

// Every option in `args` as "Name=value", and the flags before them.
function options(args: string[]): string[] {
	const out: string[] = [];
	for (let i = 0; i < args.length; i++) {
		if (args[i] === '-o') out.push(args[++i] ?? '');
	}
	return out;
}

function client(spawn: SshSpawn, target: SshTarget = TARGET, env: Record<string, string> = {}) {
	return new SshClient({
		target,
		env: { PATH: '/usr/bin', ...env },
		spawn,
		controlDir: async () => '/tmp/koi-ssh-test',
	});
}

describe('sshArgs', () => {
	test('is the full hardened command line for a private key file, and nothing else', () => {
		expect(sshArgs(TARGET, '/tmp/koi-ssh-x/m', 'tunnel-v1')).toEqual([
			'ssh',
			'-F',
			'none',
			'-o',
			'BatchMode=yes',
			'-o',
			'IdentitiesOnly=yes',
			'-o',
			'IdentityFile="/home/operator/.ssh/koi_team_ed25519"',
			'-o',
			'IdentityAgent=none',
			'-o',
			'PubkeyAuthentication=yes',
			'-o',
			'PreferredAuthentications=publickey',
			'-o',
			'PasswordAuthentication=no',
			'-o',
			'KbdInteractiveAuthentication=no',
			'-o',
			'HostbasedAuthentication=no',
			'-o',
			'GSSAPIAuthentication=no',
			'-o',
			'NumberOfPasswordPrompts=0',
			'-o',
			'StrictHostKeyChecking=yes',
			'-o',
			'UserKnownHostsFile="/home/operator/.config/koi/known_hosts"',
			'-o',
			'GlobalKnownHostsFile=/dev/null',
			'-o',
			'HostKeyAlias=team',
			'-o',
			'CheckHostIP=no',
			'-o',
			'UpdateHostKeys=no',
			'-o',
			'HashKnownHosts=no',
			'-o',
			'RequestTTY=no',
			'-o',
			'ForwardAgent=no',
			'-o',
			'ForwardX11=no',
			'-o',
			'ForwardX11Trusted=no',
			'-o',
			'ClearAllForwardings=yes',
			'-o',
			'PermitLocalCommand=no',
			'-o',
			'ProxyCommand=none',
			'-o',
			'ProxyJump=none',
			'-o',
			'ConnectTimeout=30',
			'-o',
			'ServerAliveInterval=15',
			'-o',
			'ServerAliveCountMax=4',
			'-o',
			'ControlMaster=auto',
			'-o',
			'ControlPath="/tmp/koi-ssh-x/m"',
			'-o',
			`ControlPersist=${CONTROL_PERSIST_S}`,
			'-o',
			'LogLevel=ERROR',
			'-o',
			'Port=22',
			'-o',
			'User=koi-connect',
			'--',
			'203.0.113.10',
			'tunnel-v1',
		]);
	});

	test('a key in ssh-agent is named by its public half, and the agent is left on', () => {
		const opts = options(sshArgs(AGENT_TARGET, '/tmp/c/m', 'tunnel-v1'));
		expect(opts).toContain('IdentityFile="/home/operator/.ssh/koi_team_ed25519.pub"');
		expect(opts).toContain('IdentitiesOnly=yes');
		expect(opts.some((o) => o.startsWith('IdentityAgent='))).toBe(false);
	});

	test('the port, user, alias and known_hosts file come from the target', () => {
		const opts = options(
			sshArgs(
				{ ...TARGET, port: 2222, user: 'kg', hostKeyAlias: 'lab', knownHostsFile: '/k/h' },
				'/tmp/c/m',
			),
		);
		expect(opts).toContain('Port=2222');
		expect(opts).toContain('User=kg');
		expect(opts).toContain('HostKeyAlias=lab');
		expect(opts).toContain('UserKnownHostsFile="/k/h"');
	});

	test('without a command the session asks for nothing, which the gateway refuses', () => {
		const args = sshArgs(TARGET, '/tmp/c/m');
		expect(args.slice(-2)).toEqual(['--', '203.0.113.10']);
	});

	test('refuses a target with no identity', () => {
		expect(() => sshArgs({ ...TARGET, identityFile: undefined }, '/tmp/c/m')).toThrow(
			'an SSH target needs an identity',
		);
	});

	test('quotes each path so that ssh reads it whole, whatever it holds', () => {
		// ssh splits an unquoted value on whitespace, and reads \" and \\
		// inside quotes as the characters themselves.
		expect(quoteSshValue('/a b/c')).toBe('"/a b/c"');
		expect(quoteSshValue('/q"b\\s/kh')).toBe('"/q\\"b\\\\s/kh"');
		const opts = options(
			sshArgs(
				{
					...TARGET,
					identityFile: '/keys/with space/id',
					knownHostsFile: `/known/${NASTY.replace(/\n|%/g, '')}`,
				},
				'/tmp/c d/m',
			),
		);
		expect(opts).toContain('IdentityFile="/keys/with space/id"');
		expect(opts).toContain(
			`UserKnownHostsFile=${quoteSshValue(`/known/${NASTY.replace(/\n|%/g, '')}`)}`,
		);
		expect(opts).toContain('ControlPath="/tmp/c d/m"');
	});

	test('refuses a path ssh could not read back as the same path', () => {
		expect(sshPathProblem('/plain/path')).toBeUndefined();
		expect(sshPathProblem('/with space/and "quote"')).toBeUndefined();
		expect(sshPathProblem('/known_hosts.%d')).toContain('%');
		// ssh reads ${NAME} as an environment variable, quoted or not; a
		// lone $ is a character.
		expect(sshPathProblem(`/tmp/${ENV_REF}/known_hosts`)).toContain('environment variable');
		expect(sshPathProblem('/tmp/$5/known_hosts')).toBeUndefined();
		expect(sshPathProblem('/a\nb')).toContain('line break');
		expect(sshPathProblem('/a\rb')).toContain('line break');
		expect(sshPathProblem('/a\u0001b')).toContain('control character');
		expect(sshPathProblem('/a\u007fb')).toContain('control character');
		for (const [field, path] of [
			['knownHostsFile', '/k/%h'],
			['knownHostsFile', `/k/${ENV_REF}/known_hosts`],
			['identityFile', '/k/a\nb'],
			['identityPublicKey', '/k/a\tb'],
		] as const) {
			const target =
				field === 'identityPublicKey'
					? { ...AGENT_TARGET, [field]: path }
					: { ...TARGET, [field]: path };
			expect(() => sshArgs(target, '/tmp/c/m')).toThrow('cannot be given to ssh');
		}
		expect(() => sshArgs(TARGET, '/tmp/%d/m')).toThrow('cannot be given to ssh');
	});
});

describe('sshEnv', () => {
	const noisy = {
		PATH: '/usr/bin:/bin',
		HOME: '/home/operator',
		SSH_AUTH_SOCK: '/run/user/1000/agent',
		SSH_OPTS: '-o ProxyCommand=evil',
		LD_PRELOAD: '/evil.so',
		KOI_TARGET: 'team',
		SSH_ASKPASS: '/evil',
		DISPLAY: ':0',
	};

	test('hands ssh its PATH and nothing else for a private key file', () => {
		expect(sshEnv(TARGET, noisy)).toEqual({ PATH: '/usr/bin:/bin' });
	});

	test('adds the agent socket only for a key the agent holds', () => {
		expect(sshEnv(AGENT_TARGET, noisy)).toEqual({
			PATH: '/usr/bin:/bin',
			SSH_AUTH_SOCK: '/run/user/1000/agent',
		});
		expect(sshEnv(AGENT_TARGET, { PATH: '/bin' })).toEqual({ PATH: '/bin' });
	});
});

describe('SshClient', () => {
	test('runs a command with no stdin, the hardened arguments and the minimal environment', async () => {
		const f = fakeSsh(() => scripted({ stdout: '{"ok":true}\n' }));
		const c = client(f.spawn, TARGET, { LD_PRELOAD: '/evil.so' });
		const r = await c.run('ctl-b64 WyJwaW5nIl0=');
		expect(r).toEqual({ code: 0, stdout: '{"ok":true}\n', stderr: '' });
		expect(f.requests).toHaveLength(1);
		const req = f.requests[0] as SpawnRequest;
		expect(req.stdin).toBe(false);
		expect(req.env).toEqual({ PATH: '/usr/bin' });
		expect(req.cmd).toEqual(sshArgs(TARGET, '/tmp/koi-ssh-test/m', 'ctl-b64 WyJwaW5nIl0='));
	});

	test('makes the control directory itself, mode 0700, and removes it on close', async () => {
		const f = fakeSsh(() => scripted({ code: 0 }));
		const c = new SshClient({ target: TARGET, env: { PATH: '/usr/bin' }, spawn: f.spawn });
		await c.run('tunnel-v1');
		const quoted = options(f.requests[0]?.cmd ?? [])
			.find((o) => o.startsWith('ControlPath='))
			?.slice('ControlPath='.length);
		if (quoted === undefined) throw new Error('no ControlPath');
		// The value is quoted for ssh; the quoting is JSON's for a plain path.
		const path = JSON.parse(quoted) as string;
		const dir = dirname(path);
		expect((await stat(dir)).mode & 0o777).toBe(0o700);
		// Every session shares the one socket.
		await c.run('tunnel-v1');
		expect(options(f.requests[1]?.cmd ?? [])).toContain(`ControlPath=${quoted}`);
		await c.close();
		// The master was told to exit, through the same socket and no shell.
		expect(f.requests[2]?.cmd).toEqual([
			'ssh',
			'-F',
			'none',
			'-o',
			`ControlPath=${quoted}`,
			'-O',
			'exit',
			'--',
			'203.0.113.10',
		]);
		await expect(stat(dir)).rejects.toThrow();
		// Closed is closed.
		await c.close();
		expect(f.requests).toHaveLength(3);
		await expect(c.run('tunnel-v1')).rejects.toThrow('the SSH connection is closed');
	});

	test('close kills a session still running, then ends the master', async () => {
		const procs: Array<ReturnType<typeof scripted>> = [];
		const f = fakeSsh(() => {
			const p = scripted(procs.length === 0 ? { hang: true } : { code: 0 });
			procs.push(p);
			return p;
		});
		const c = client(f.spawn);
		const running = c.run('tunnel-v1');
		await Bun.sleep(10);
		expect(procs[0]?.killed).toBe(false);
		await c.close();
		expect(procs[0]?.killed).toBe(true);
		expect((await running).code).toBe(137);
		// The exit request went to the master after the session was ended.
		expect(f.requests[1]?.cmd.slice(-3)).toEqual(['exit', '--', '203.0.113.10']);
	});

	test('close without a session started spawns nothing', async () => {
		const f = fakeSsh(() => scripted({}));
		await client(f.spawn).close();
		expect(f.requests).toHaveLength(0);
	});

	test('a close whose ssh hangs is cut off', async () => {
		const procs: Array<ReturnType<typeof scripted>> = [];
		const f = fakeSsh(() => {
			const p = scripted(procs.length === 0 ? { code: 0 } : { hang: true });
			procs.push(p);
			return p;
		});
		const c = new SshClient({ target: TARGET, env: { PATH: '/usr/bin' }, spawn: f.spawn });
		await c.run('tunnel-v1');
		const closed = c.close();
		// The exit request hangs; close kills it after its grace and returns.
		await Bun.sleep(50);
		expect(procs[1]?.killed).toBe(false);
		procs[1]?.kill();
		await closed;
	});

	test('refuses output past the bound rather than use part of it', async () => {
		const f = fakeSsh(() => scripted({ stdout: 'x'.repeat(2000) }));
		await expect(client(f.spawn).run('ctl-b64 abc', undefined, 1000)).rejects.toThrow(
			'passed 1000 bytes; koi does not use part of a reply',
		);
	});

	test('kills a command the moment its output passes the bound, without waiting for it to end', async () => {
		// A command that printed past the bound and never ends: its stderr
		// and exit would be waited for forever if the kill came after them.
		const p = scripted({ hang: true, stdout: 'x'.repeat(2000) });
		const f = fakeSsh(() => p);
		await expect(client(f.spawn).run('ctl-b64 abc', undefined, 1000)).rejects.toThrow(
			'passed 1000 bytes',
		);
		expect(p.killed).toBe(true);
	});

	test('a signal kills the process', async () => {
		const p = scripted({ hang: true });
		const f = fakeSsh(() => p);
		const stop = new AbortController();
		const running = client(f.spawn).run('tunnel-v1', stop.signal);
		while (f.requests.length === 0) await Bun.sleep(1);
		stop.abort();
		expect((await running).code).toBe(137);
		expect(p.killed).toBe(true);
	});

	test('an aborted signal spawns nothing', async () => {
		const f = fakeSsh(() => scripted({}));
		const stop = new AbortController();
		stop.abort();
		await expect(client(f.spawn).run('tunnel-v1', stop.signal)).rejects.toThrow();
		expect(f.requests).toHaveLength(0);
	});

	// A client whose control directory is made only when the test says so:
	// open waits on it, and what happens in that wait is the point.
	function gated(spawn: SshSpawn) {
		let release!: () => void;
		const made = new Promise<void>((r) => {
			release = r;
		});
		const c = new SshClient({
			target: TARGET,
			env: { PATH: '/usr/bin' },
			spawn,
			controlDir: async () => {
				await made;
				return '/tmp/koi-ssh-test';
			},
		});
		return { c, release };
	}

	test('a close during an open ends the open, and nothing is spawned after the close', async () => {
		// Whatever is spawned ends at once, so a session would be seen in the
		// requests and the master's exit does not hold close up.
		const f = fakeSsh(() => scripted({ code: 0 }));
		const { c, release } = gated(f.spawn);
		const opening = c.open('tunnel-v1', true);
		const closing = c.close();
		// close waits for the open in flight rather than sweep an empty set
		// and let the open spawn afterwards.
		await Bun.sleep(20);
		expect(f.requests).toHaveLength(0);
		release();
		await expect(opening).rejects.toThrow('the SSH connection is closed');
		await closing;
		// The one ssh run was the master's exit: no session, before or after.
		expect(f.requests.map((r) => r.cmd.slice(-3))).toEqual([['exit', '--', '203.0.113.10']]);
		await expect(c.open('tunnel-v1', true)).rejects.toThrow('the SSH connection is closed');
		expect(f.requests).toHaveLength(1);
	});

	test('a signal that fires during an open spawns nothing', async () => {
		const f = fakeSsh(() => scripted({ code: 0 }));
		const { c, release } = gated(f.spawn);
		const stop = new AbortController();
		const opening = c.open('tunnel-v1', true, stop.signal);
		stop.abort(new Error('the user pressed ctrl-c'));
		release();
		await expect(opening).rejects.toThrow('the user pressed ctrl-c');
		expect(f.requests).toHaveLength(0);
		await c.close();
	});

	test('every call of close waits for the one close', async () => {
		const procs: Array<ReturnType<typeof scripted>> = [];
		const f = fakeSsh(() => {
			const p = scripted(procs.length === 0 ? { code: 0 } : { hang: true });
			procs.push(p);
			return p;
		});
		const c = client(f.spawn);
		await c.run('tunnel-v1');
		const first = c.close();
		const second = c.close();
		let secondDone = false;
		void second.then(() => {
			secondDone = true;
		});
		// The master's exit hangs, so the close is still running; the
		// second call is the same close, not a return while it runs.
		await Bun.sleep(20);
		expect(secondDone).toBe(false);
		procs[1]?.kill();
		await Promise.all([first, second]);
		expect(f.requests).toHaveLength(2);
	});
});

const HOST = {
	name: 'team',
	host: '203.0.113.10',
	user: 'koi-connect',
	domain: 'previews.example.com',
};

function transport(
	script: (req: SpawnRequest) => SshProcess,
	o: {
		sleep?: (ms: number) => Promise<void>;
		now?: () => number;
		progress?: (message: string) => void;
		limits?: Partial<SshLimits>;
	} = {},
) {
	const f = fakeSsh(script);
	const t = sshTransport(HOST, client(f.spawn), {
		sleep: o.sleep ?? (async () => {}),
		now: o.now ?? Date.now,
		progress: o.progress,
		limits: o.limits,
	});
	return { t, requests: f.requests };
}

describe('sshTransport ctl', () => {
	test('sends the arguments as ctl-b64 with a blob koid decodes to the same list', async () => {
		const { t, requests } = transport(() => scripted({ stdout: '{"ok":true}\n' }));
		const r = await t.ctl(['status', NASTY, '-rf', '']);
		expect(r).toEqual({ code: 0, stdout: '{"ok":true}\n', stderr: '' });
		const command = commandOf(requests[0] as SpawnRequest);
		expect(command).toMatch(/^ctl-b64 [A-Za-z0-9+/]+=*$/);
		expect(ctlArgsOf(requests[0] as SpawnRequest)).toEqual(['status', NASTY, '-rf', '']);
	});

	test("returns koid ctl's own exit status and output, whatever it is", async () => {
		for (const code of [CTL_EXIT.ok, CTL_EXIT.refused, CTL_EXIT.usage, CTL_EXIT.unavailable, 127]) {
			const { t } = transport(() => scripted({ code, stdout: 'out', stderr: 'err' }));
			expect(await t.ctl(['list'])).toEqual({ code, stdout: 'out', stderr: 'err' });
		}
	});

	test("a host key koi does not trust is the operator's to fix, with the command to do it", async () => {
		for (const text of [
			'Host key verification failed.',
			'@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.',
			'No ED25519 host key is known for team and you have requested strict checking.\nHost key verification failed.',
		]) {
			const { t } = transport(() => scripted({ code: 255, stderr: text }));
			const err = await t.ctl(['ping']).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(HostKeyError);
			expect((err as Error).message).toContain('koi target trust team --fingerprint SHA256:...');
			expect((err as Error).message).toContain('203.0.113.10');
		}
	});

	test('a key the host refuses names the authorized keys file', async () => {
		const { t } = transport(() =>
			scripted({ code: 255, stderr: 'koi-connect@203.0.113.10: Permission denied (publickey).' }),
		);
		const err = await t.ctl(['ping']).catch((e: unknown) => e);
		expect(err).not.toBeInstanceOf(BoxUnavailableError);
		expect((err as Error).message).toContain('/etc/ssh/koi-connect/authorized_keys');
		expect((err as Error).message).toContain('Permission denied (publickey)');
	});

	test('any other ssh failure can pass', async () => {
		for (const text of [
			'ssh: connect to host 203.0.113.10 port 22: Connection refused',
			'ssh: connect to host 203.0.113.10 port 22: Connection timed out',
			'kex_exchange_identification: Connection closed by remote host',
			'',
		]) {
			const { t } = transport(() => scripted({ code: 255, stderr: text }));
			const err = await t.ctl(['ping']).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(BoxUnavailableError);
			expect((err as Error).message).toContain('cannot connect to 203.0.113.10 as koi-connect');
		}
	});

	test('an aborted signal sends nothing', async () => {
		const { t, requests } = transport(() => scripted({}));
		const stop = new AbortController();
		stop.abort();
		await expect(t.ctl(['down', 'x'], { signal: stop.signal })).rejects.toThrow();
		expect(requests).toHaveLength(0);
	});

	test('stopping after the command went out kills ssh and reports an unknown outcome', async () => {
		const p = scripted({ hang: true });
		const { t } = transport(() => p);
		const stop = new AbortController();
		const call = t.ctl(['down', 'x'], { signal: stop.signal });
		await Bun.sleep(10);
		stop.abort();
		const err = await call.catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect((err as Error).message).toContain('koid ctl down may have run on 203.0.113.10');
		expect(p.killed).toBe(true);
	});

	test('a time limit does the same', async () => {
		const p = scripted({ hang: true });
		const { t } = transport(() => p);
		const err = await t.ctl(['up', 'a'.repeat(16)], { timeoutMs: 50 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect(p.killed).toBe(true);
	});

	test('a ctl with no limit of its own ends at the default, naming it', async () => {
		// ssh keeps the session up for as long as sshd does, so a koid that
		// hangs would hold the call for good. The default, shortened here,
		// ends it; the defaults as shipped are pinned below.
		const p = scripted({ hang: true });
		const { t } = transport(() => p, { limits: { ctlMs: 50 } });
		const err = await t.ctl(['list']).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect((err as Error).message).toBe(
			'koid ctl list may have run on 203.0.113.10 (target team): koi stopped waiting for its result after 50 ms, so its outcome is unknown',
		);
		expect(p.killed).toBe(true);
		expect(SSH_DEFAULT_LIMITS).toEqual({
			ctlMs: 5 * 60_000,
			describeMs: 60_000,
			uploadMs: 30 * 60_000,
			tunnelIdleMs: 2 * 60_000,
		});
	});

	test("a caller's limit stands in place of the default, shorter or longer", async () => {
		const p = scripted({ hang: true });
		const { t } = transport(() => p, { limits: { ctlMs: 60_000 } });
		const err = await t.ctl(['list'], { timeoutMs: 50 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect((err as Error).message).toContain('after 50 ms');
	});
});

describe('sshTransport describe and ensureAwake', () => {
	const info = hostInfoFor('previews.example.com');

	test("describe returns koid's descriptor, and reports an old koid as a missing capability", async () => {
		const { t, requests } = transport(() => scripted({ stdout: `${JSON.stringify(info)}\n` }));
		expect(await t.describe()).toEqual(info);
		expect(ctlArgsOf(requests[0] as SpawnRequest)).toEqual(['describe']);
		const old = transport(() => scripted({ code: CTL_EXIT.usage, stderr: CTL_USAGE }));
		const err = await old.t.describe().catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnsupportedCapabilityError);
	});

	test('describe with no limit of its own ends at the default', async () => {
		const p = scripted({ hang: true });
		const { t } = transport(() => p, { limits: { describeMs: 50 } });
		await expect(t.describe()).rejects.toBeInstanceOf(UnknownOutcomeError);
		expect(p.killed).toBe(true);
	});

	test('ensureAwake asks for the descriptor and returns once koid answers', async () => {
		const progress: string[] = [];
		const { t, requests } = transport(() => scripted({ stdout: `${JSON.stringify(info)}\n` }));
		await t.ensureAwake((m) => progress.push(m));
		expect(requests.map(ctlArgsOf)).toEqual([['describe']]);
		expect(progress).toEqual([]);
	});

	test('waits for a koid that is starting, every 3 seconds, saying so once', async () => {
		const progress: string[] = [];
		const slept: number[] = [];
		let calls = 0;
		const { t } = transport(
			() =>
				scripted(
					calls++ < 2
						? { code: CTL_EXIT.unavailable, stderr: 'koid ctl: cannot reach koid: ECONNREFUSED\n' }
						: { stdout: `${JSON.stringify(info)}\n` },
				),
			{
				sleep: async (ms) => {
					slept.push(ms);
				},
			},
		);
		await t.ensureAwake((m) => progress.push(m));
		expect(calls).toBe(3);
		expect(slept).toEqual([3000, 3000]);
		expect(progress).toEqual(['waiting for koid on 203.0.113.10 to start']);
	});

	test('a host that does not take the connection is for its operator to start', async () => {
		const { t } = transport(() =>
			scripted({
				code: 255,
				stderr: 'ssh: connect to host 203.0.113.10 port 22: Connection refused',
			}),
		);
		const err = await t.ensureAwake(() => {}).catch((e: unknown) => e);
		expect(err).not.toBeInstanceOf(BoxUnavailableError);
		expect((err as Error).message).toBe(
			"cannot connect to 203.0.113.10 as koi-connect: ssh: connect to host 203.0.113.10 port 22: Connection refused; target team does not manage the host's power (power: always-on), so koi cannot start it; its operator must",
		);
	});

	test('gives up after five minutes, saying why', async () => {
		let clock = 0;
		const { t } = transport(
			() => scripted({ code: CTL_EXIT.unavailable, stderr: '{"error":"starting"}' }),
			{
				sleep: async (ms) => {
					clock += ms;
				},
				now: () => clock,
			},
		);
		await expect(t.ensureAwake(() => {})).rejects.toThrow(
			'koid on 203.0.113.10 (target team) did not answer within 5 minutes: starting',
		);
	});

	test('a time limit on the wake ends it', async () => {
		let clock = 0;
		const { t } = transport(() => scripted({ code: CTL_EXIT.unavailable, stderr: 'not yet' }), {
			sleep: async (ms) => {
				clock += ms;
			},
			now: () => clock,
		});
		await expect(t.ensureAwake(() => {}, { timeoutMs: 10_000 })).rejects.toThrow(
			'the box did not come awake within 10 seconds',
		);
	});

	test('checks the first descriptor against the target, and stops on another domain', async () => {
		const other = hostInfoFor('other.example.com');
		const { t, requests } = transport(() => scripted({ stdout: `${JSON.stringify(other)}\n` }));
		const err = await t.ensureAwake(() => {}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(HostMismatchError);
		expect((err as Error).message).toContain(
			'the host behind target "team" serves previews under other.example.com, not previews.example.com as configured',
		);
		expect(requests).toHaveLength(1);
		// A failed check is not a verdict: the next wake checks again.
		await expect(t.ensureAwake(() => {})).rejects.toThrow(HostMismatchError);
		expect(requests).toHaveLength(2);
		const port = transport(() =>
			scripted({
				stdout: `${JSON.stringify({ ...info, address: { scheme: 'https', port: 8443 } })}\n`,
			}),
		);
		await expect(port.t.ensureAwake(() => {})).rejects.toThrow(
			'serves previews on https port 8443',
		);
	});

	test('a koid from before the descriptor is refused, not taken at its word', async () => {
		const { t } = transport(() => scripted({ code: CTL_EXIT.usage, stderr: CTL_USAGE }));
		const err = await t.ensureAwake(() => {}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnsupportedCapabilityError);
		expect((err as Error).message).toContain('an SSH target needs the current koid');
	});

	test('a refusal from koid is not waited out', async () => {
		const { t } = transport(() =>
			scripted({ code: CTL_EXIT.refused, stderr: '{"error":"no such thing"}' }),
		);
		await expect(t.ensureAwake(() => {})).rejects.toThrow('no such thing');
	});
});

describe('sshTransport logs and channel', () => {
	test('follows a build log by polling status, as the AWS transport does', async () => {
		const record = previewRecord({ status: 'running', attempt: 'b'.repeat(20) });
		// Two lines from offset 0, then nothing past them, as koid pages.
		const { t, requests } = transport((req) =>
			scripted({
				stdout: JSON.stringify({
					record,
					log:
						ctlArgsOf(req)[3] === '0'
							? { next: 10, lines: ['one', 'two'] }
							: { next: 10, lines: [] },
				}),
			}),
		);
		const events = [];
		for await (const e of t.streamLogs({
			label: 'hello-pr-7',
			kind: 'build',
			attempt: 'b'.repeat(20),
		})) {
			events.push(e);
		}
		expect(events).toEqual([
			{ type: 'line', cursor: '0:1', text: 'one' },
			{ type: 'line', cursor: '0:2', text: 'two' },
			{ type: 'end' },
		]);
		expect(ctlArgsOf(requests[0] as SpawnRequest)).toEqual([
			'status',
			'hello-pr-7',
			'b'.repeat(20),
			'0',
		]);
	});

	test('cannot follow a container log, and has no channel', async () => {
		const { t } = transport(() => scripted({}));
		expect(() => t.streamLogs({ label: 'x', kind: 'runtime' })).toThrow(UnsupportedCapabilityError);
		const err = await t.openChannel().catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnsupportedCapabilityError);
		expect((err as UnsupportedCapabilityError).capability).toBe('duplex');
	});
});

// A relay to a unix socket, as a tunnel-v1 session is to koid's control
// socket: bytes written go to the socket, bytes from it come out of stdout.
// `code` and `stderr` are what the process reports once the socket closes.
// With `breakAfterReplies` the connection drops once that many replies
// have come through, as a tunnel that dies part way.
function relayTo(
	socketPath: string,
	code = 0,
	stderr = '',
	breakAfterReplies = Number.POSITIVE_INFINITY,
): SshProcess & { killed: boolean } {
	const conn = netConnect({ path: socketPath, allowHalfOpen: true });
	let replies = 0;
	let out!: ReadableStreamDefaultController<Uint8Array>;
	let closed = false;
	const stdout = new ReadableStream<Uint8Array>({
		start(c) {
			out = c;
		},
	});
	const closeOut = () => {
		if (closed) return;
		closed = true;
		try {
			out.close();
		} catch {}
	};
	let resolveExit!: (code: number) => void;
	const exited = new Promise<number>((r) => {
		resolveExit = r;
	});
	conn.on('data', (d: Buffer) => {
		out.enqueue(new Uint8Array(d));
		replies += (d.toString('latin1').match(/HTTP\/1\.1 /g) ?? []).length;
		if (replies >= breakAfterReplies) conn.destroy();
	});
	conn.on('end', closeOut);
	conn.on('close', () => {
		closeOut();
		resolveExit(code);
	});
	conn.on('error', closeOut);
	const ready = new Promise<void>((resolve, reject) => {
		conn.once('connect', resolve);
		conn.once('error', reject);
	});
	const proc = {
		killed: false,
		async write(chunk: Uint8Array) {
			await ready;
			await new Promise<void>((resolve, reject) =>
				conn.write(chunk, (err) => (err ? reject(err) : resolve())),
			);
		},
		async end() {
			await ready;
			conn.end();
		},
		stdout,
		stderr: textStream(stderr),
		exited,
		kill() {
			proc.killed = true;
			conn.destroy();
		},
	};
	return proc;
}

// A tunnel whose stdout ends at once: ssh or the gateway refused it.
function refusedTunnel(code: number, stderr: string): SshProcess & { killed: boolean } {
	return scripted({ code, stderr });
}

type Handler = (req: Request) => Promise<Response> | Response;

// koid's upload API as a script: each request takes the next handler.
async function koid(handlers: Handler[]) {
	const dir = await mkdtemp(join(tmpdir(), 'koi-ssh-koid-'));
	const sock = join(dir, 'k.sock');
	const seen: string[] = [];
	const server = Bun.serve({
		unix: sock,
		idleTimeout: 0,
		maxRequestBodySize: 64 * 1024 ** 2,
		fetch(req: Request) {
			seen.push(`${req.method} ${new URL(req.url).pathname}`);
			const handler = handlers.shift();
			if (handler === undefined) return Response.json({ error: 'unexpected' }, { status: 500 });
			return handler(req);
		},
	} as never);
	return {
		sock,
		seen,
		stop: async () => {
			server.stop(true);
			await rm(dir, { recursive: true, force: true });
		},
	};
}

const ID = 'abcdefghij0123456789';
const UPLOAD_ID = 'f'.repeat(32);

function request(): UpRequest {
	return {
		version: 1,
		id: ID,
		label: 'hello-pr-7',
		project: 'hello',
		repo: 'github.com/acme/hello',
		commit: 'a'.repeat(40),
		branch: 'feature/x',
		pr: 7,
		dirty: false,
		recipe: { kind: 'builtin', name: 'hello' },
		createdAt: '2026-10-06T00:00:00.000Z',
	} as UpRequest;
}

async function tarball(size = 3 * 1024 ** 2 + 123) {
	const dir = await mkdtemp(join(tmpdir(), 'koi-ssh-src-'));
	const bytes = Buffer.alloc(size);
	for (let i = 0; i < size; i++) bytes[i] = (i * 7) & 0xff;
	const path = join(dir, 'source.tar.gz');
	await writeFile(path, bytes);
	return { path, size, sha256: createHash('sha256').update(bytes).digest('hex'), dir };
}

const ticket: Handler = async (req) => {
	const body = (await req.json()) as { requestId: string; sizeBytes: number; sha256: string };
	expect(body.requestId).toBe(ID);
	return Response.json(
		{ uploadId: UPLOAD_ID, expiresAt: '2026-10-06T01:00:00.000Z' },
		{ status: 201 },
	);
};

// Reads the body a chunk at a time and answers as the PUT does; `chunks`
// counts how many pieces it came in.
function receive(chunks: number[]): Handler {
	return async (req) => {
		const hash = createHash('sha256');
		let n = 0;
		let size = 0;
		for await (const chunk of req.body as ReadableStream<Uint8Array>) {
			hash.update(chunk);
			n++;
			size += chunk.byteLength;
		}
		chunks.push(n);
		return Response.json({ sizeBytes: size, sha256: hash.digest('hex') });
	};
}

const commit: Handler = async (req) => {
	const body = (await req.json()) as UpRequest;
	return Response.json({ requestId: body.id, label: body.label });
};

// The descriptor koid answers describe with: the upload checks it against
// the target before it opens a tunnel.
const DESCRIPTOR = `${JSON.stringify(hostInfoFor('previews.example.com'))}\n`;

// A transport for uploads: the ctl-b64 sessions (the describe that comes
// before the tunnel) answer with the descriptor, or as `describe` says, and
// the tunnel-v1 sessions come from `tunnel`. `tunnels` lists the latter.
function uploader(
	tunnel: (req: SpawnRequest) => SshProcess,
	o: {
		describe?: () => SshProcess;
		sleep?: (ms: number) => Promise<void>;
		now?: () => number;
		progress?: (message: string) => void;
		limits?: Partial<SshLimits>;
	} = {},
) {
	const describe = o.describe ?? (() => scripted({ stdout: DESCRIPTOR }));
	const { t, requests } = transport(
		(req) => (commandOf(req).startsWith('ctl-b64') ? describe() : tunnel(req)),
		o,
	);
	return { t, requests, tunnels: () => requests.filter((r) => commandOf(r) === 'tunnel-v1') };
}

describe('sshTransport upload', () => {
	test('asks koid for its descriptor, and checks it, before any of the source goes out', async () => {
		const order: string[] = [];
		const k = await koid([
			(req) => {
				order.push('POST /v1/uploads');
				return ticket(req);
			},
			receive([]),
			commit,
			// The second upload finds its content committed.
			() => Response.json({ committed: true, requestId: ID }),
		]);
		const src = await tarball(1000);
		try {
			const { t, requests } = uploader(() => relayTo(k.sock), {
				describe: () => {
					order.push('describe');
					return scripted({ stdout: DESCRIPTOR });
				},
			});
			await t.upload(request(), src.path);
			expect(order).toEqual(['describe', 'POST /v1/uploads']);
			expect(requests.map(commandOf)[0]).toStartWith('ctl-b64 ');
			expect(ctlArgsOf(requests[0] as SpawnRequest)).toEqual(['describe']);
			// Checked once: the next upload describes again (koid must be up)
			// but is not held to a second check, and a wake after it neither.
			await t.upload(request(), src.path);
			await t.ensureAwake(() => {});
			expect(requests.filter((r) => commandOf(r).startsWith('ctl-b64'))).toHaveLength(3);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a host that serves another domain gets no source, and no tunnel is opened', async () => {
		const k = await koid([ticket]);
		const src = await tarball(1000);
		try {
			const other = `${JSON.stringify(hostInfoFor('other.example.com'))}\n`;
			const { t, tunnels } = uploader(() => relayTo(k.sock), {
				describe: () => scripted({ stdout: other }),
			});
			const err = await t.upload(request(), src.path).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(HostMismatchError);
			expect((err as Error).message).toContain(
				'the host behind target "team" serves previews under other.example.com, not previews.example.com as configured',
			);
			expect(tunnels()).toEqual([]);
			expect(k.seen).toEqual([]);
			// A failed check is not a verdict: the next upload asks again.
			await expect(t.upload(request(), src.path)).rejects.toThrow(HostMismatchError);
			expect(k.seen).toEqual([]);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('waits for a koid that is starting before it uploads, and says so', async () => {
		const k = await koid([() => Response.json({ committed: true, requestId: ID })]);
		const src = await tarball(1000);
		try {
			const progress: string[] = [];
			let calls = 0;
			const { t } = uploader(() => relayTo(k.sock), {
				describe: () =>
					scripted(
						calls++ === 0
							? { code: CTL_EXIT.unavailable, stderr: 'koid ctl: cannot reach koid\n' }
							: { stdout: DESCRIPTOR },
					),
				progress: (m) => progress.push(m),
			});
			await t.upload(request(), src.path);
			expect(calls).toBe(2);
			expect(progress).toEqual(['waiting for koid on 203.0.113.10 to start']);
			expect(k.seen).toEqual(['POST /v1/uploads']);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a ticket, the archive streamed in pieces, then the commit, over one tunnel', async () => {
		const chunks: number[] = [];
		const k = await koid([ticket, receive(chunks), commit]);
		const src = await tarball();
		try {
			const { t, tunnels } = uploader(() => relayTo(k.sock));
			await t.upload(request(), src.path);
			expect(tunnels().map(commandOf)).toEqual(['tunnel-v1']);
			expect(tunnels()[0]?.stdin).toBe(true);
			expect(k.seen).toEqual([
				'POST /v1/uploads',
				`PUT /v1/uploads/${UPLOAD_ID}/source`,
				`POST /v1/uploads/${UPLOAD_ID}/commit`,
			]);
			// The archive went out as it was read, not as one piece.
			expect(chunks[0]).toBeGreaterThan(1);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('content the host already holds is not sent again', async () => {
		const k = await koid([() => Response.json({ committed: true, requestId: ID })]);
		const src = await tarball(1000);
		try {
			const { t } = uploader(() => relayTo(k.sock));
			await t.upload(request(), src.path);
			expect(k.seen).toEqual(['POST /v1/uploads']);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('each refusal of the ticket is reported in its own words', async () => {
		const src = await tarball(1000);
		try {
			for (const [status, error, expected] of [
				[409, 'request x was already uploaded with different content', 'already holds request'],
				[413, 'the source is 5 bytes; koid takes at most 2', 'refuses the source of hello-pr-7'],
				[507, 'the upload spool has 9 of its 10 bytes in use', 'has no room for the source'],
				[418, 'teapot', 'answered POST /v1/uploads with 418: teapot'],
			] as const) {
				const k = await koid([() => Response.json({ error }, { status })]);
				try {
					const { t } = uploader(() => relayTo(k.sock));
					const err = await t.upload(request(), src.path).catch((e: unknown) => e);
					expect((err as Error).message).toContain(expected);
					expect((err as Error).message).toContain(error);
					expect(k.seen).toEqual(['POST /v1/uploads']);
				} finally {
					await k.stop();
				}
			}
		} finally {
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a source the host does not take, or takes as something else, stops the upload', async () => {
		const src = await tarball(1000);
		try {
			for (const [handler, expected] of [
				[
					() => Response.json({ error: 'digest is wrong' }, { status: 422 }),
					'did not take the source of hello-pr-7 (422): digest is wrong',
				],
				[
					() => Response.json({ error: 'no such upload' }, { status: 404 }),
					'(404): no such upload',
				],
				[
					() => Response.json({ sizeBytes: 999, sha256: 'a'.repeat(64) }),
					'received 999 bytes with digest aaaa',
				],
			] as const) {
				const k = await koid([ticket, handler]);
				try {
					const { t } = uploader(() => relayTo(k.sock));
					const err = await t.upload(request(), src.path).catch((e: unknown) => e);
					expect((err as Error).message).toContain(expected);
					expect(k.seen).toHaveLength(2);
				} finally {
					await k.stop();
				}
			}
		} finally {
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a commit koid could not make durable is sent again, then given up', async () => {
		const src = await tarball(1000);
		const notDurable = () =>
			Response.json(
				{ error: 'the commit is on the disk but not durable yet; try again' },
				{ status: 500 },
			);
		try {
			const ok = await koid([ticket, receive([]), notDurable, notDurable, commit]);
			try {
				const { t } = uploader(() => relayTo(ok.sock));
				await t.upload(request(), src.path);
				expect(ok.seen.filter((s) => s.endsWith('/commit'))).toHaveLength(3);
			} finally {
				await ok.stop();
			}
			const never = await koid([ticket, receive([]), notDurable, notDurable, notDurable]);
			try {
				const { t } = uploader(() => relayTo(never.sock));
				await expect(t.upload(request(), src.path)).rejects.toThrow(
					'did not commit the upload of hello-pr-7 (500): the commit is on the disk but not durable yet; try again',
				);
				expect(never.seen.filter((s) => s.endsWith('/commit'))).toHaveLength(3);
			} finally {
				await never.stop();
			}
		} finally {
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a commit refused for good is not repeated', async () => {
		const src = await tarball(1000);
		const k = await koid([
			ticket,
			receive([]),
			() => Response.json({ error: 'committed with different content' }, { status: 409 }),
		]);
		try {
			const { t } = uploader(() => relayTo(k.sock));
			await expect(t.upload(request(), src.path)).rejects.toThrow(
				'did not commit the upload of hello-pr-7 (409): committed with different content',
			);
			expect(k.seen).toHaveLength(3);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a tunnel that breaks part way is opened again once, from the ticket', async () => {
		const src = await tarball(1000);
		// The first tunnel drops once the source is received, so its commit
		// never goes out; the second starts over from the ticket.
		const k = await koid([ticket, receive([]), ticket, receive([]), commit]);
		try {
			let opened = 0;
			const { t, tunnels } = uploader(() =>
				relayTo(k.sock, 0, '', opened++ === 0 ? 2 : Number.POSITIVE_INFINITY),
			);
			await t.upload(request(), src.path);
			expect(tunnels().map(commandOf)).toEqual(['tunnel-v1', 'tunnel-v1']);
			expect(k.seen).toEqual([
				'POST /v1/uploads',
				`PUT /v1/uploads/${UPLOAD_ID}/source`,
				'POST /v1/uploads',
				`PUT /v1/uploads/${UPLOAD_ID}/source`,
				`POST /v1/uploads/${UPLOAD_ID}/commit`,
			]);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a tunnel that breaks twice can pass', async () => {
		const src = await tarball(1000);
		const k = await koid([ticket, ticket]);
		try {
			const { t } = uploader(() => relayTo(k.sock, 0, '', 1));
			const err = await t.upload(request(), src.path).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(BoxUnavailableError);
			expect((err as Error).message).toContain(
				'the connection to 203.0.113.10 ended during the upload of hello-pr-7',
			);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a tunnel ssh or the gateway refused is reported for what it is, without a retry', async () => {
		const src = await tarball(1000);
		try {
			for (const [code, stderr, check] of [
				[
					255,
					'Host key verification failed.',
					(e: unknown) => expect(e).toBeInstanceOf(HostKeyError),
				],
				[
					CTL_EXIT.unavailable,
					'koi-ssh-gateway: cannot reach koid at /run/koi/control.sock: ENOENT',
					(e: unknown) => {
						expect(e).toBeInstanceOf(BoxUnavailableError);
						expect((e as Error).message).toContain('is not taking uploads: koi-ssh-gateway');
					},
				],
				[
					CTL_EXIT.usage,
					'koi-ssh-gateway: "tunnel-v1" is not a command of this account',
					(e: unknown) => expect((e as Error).message).toContain('refused tunnel-v1'),
				],
			] as const) {
				const { t, tunnels } = uploader(() => refusedTunnel(code, stderr));
				const err = await t.upload(request(), src.path).catch((e: unknown) => e);
				check(err);
				expect(tunnels()).toHaveLength(1);
			}
		} finally {
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a tunnel whose ssh lost the connection is opened again, from the ticket', async () => {
		const src = await tarball(1000);
		for (const lost of [
			'client_loop: send disconnect: Broken pipe',
			'Connection reset by peer',
			'kex_exchange_identification: Connection closed by remote host',
			'ssh: connect to host 203.0.113.10 port 22: Connection timed out',
		]) {
			// The first tunnel's ssh exits 255 after the ticket; the second
			// starts over from the ticket, which says nothing was committed.
			const k = await koid([ticket, ticket, receive([]), commit]);
			try {
				let tunnels = 0;
				const { t, tunnels: opened } = uploader(() =>
					tunnels++ === 0 ? relayTo(k.sock, 255, lost, 1) : relayTo(k.sock),
				);
				await t.upload(request(), src.path);
				expect(opened()).toHaveLength(2);
				expect(k.seen).toEqual([
					'POST /v1/uploads',
					'POST /v1/uploads',
					`PUT /v1/uploads/${UPLOAD_ID}/source`,
					`POST /v1/uploads/${UPLOAD_ID}/commit`,
				]);
			} finally {
				await k.stop();
			}
		}
		// Lost every time: given up after the retry, as a connection that ended.
		const k = await koid([ticket, ticket]);
		try {
			const { t, tunnels: opened } = uploader(() =>
				relayTo(k.sock, 255, 'client_loop: send disconnect: Broken pipe', 1),
			);
			const err = await t.upload(request(), src.path).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(BoxUnavailableError);
			expect((err as Error).message).toContain('ended during the upload of hello-pr-7');
			expect((err as Error).message).toContain('Broken pipe');
			expect(opened()).toHaveLength(2);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a tunnel whose ssh was refused is not opened again', async () => {
		const src = await tarball(1000);
		try {
			for (const [stderr, check] of [
				[
					'koi-connect@203.0.113.10: Permission denied (publickey).',
					(e: unknown) => expect((e as Error).message).toContain("refused koi's key"),
				],
				[
					'ssh: Could not resolve hostname box.example.com: Name or service not known',
					(e: unknown) => expect(e).toBeInstanceOf(BoxUnavailableError),
				],
				[
					'@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@',
					(e: unknown) => expect(e).toBeInstanceOf(HostKeyError),
				],
			] as const) {
				const k = await koid([ticket]);
				try {
					const { t, tunnels } = uploader(() => relayTo(k.sock, 255, stderr, 1));
					const err = await t.upload(request(), src.path).catch((e: unknown) => e);
					check(err);
					expect(tunnels()).toHaveLength(1);
				} finally {
					await k.stop();
				}
			}
		} finally {
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('sshFailureIsTransient tells a lost connection from a refusal', () => {
		for (const lost of [
			'client_loop: send disconnect: Broken pipe',
			'Connection reset by peer',
			'kex_exchange_identification: Connection closed by remote host',
			'Connection closed by 203.0.113.10 port 22',
			'ssh: connect to host 203.0.113.10 port 22: Connection timed out',
			'Timeout, server 203.0.113.10 not responding.',
		]) {
			expect(sshFailureIsTransient(lost)).toBe(true);
		}
		for (const stays of [
			'koi-connect@203.0.113.10: Permission denied (publickey).',
			'Host key verification failed.',
			'No ED25519 host key is known for team and you have requested strict checking.',
			'ssh: Could not resolve hostname box: Name or service not known',
			'ssh: connect to host 203.0.113.10 port 22: Connection refused',
			// A key refused by a host whose connection also closed stays refused.
			'Permission denied (publickey).\nConnection closed by 203.0.113.10 port 22',
			'',
		]) {
			expect(sshFailureIsTransient(stays)).toBe(false);
		}
	});

	test('the archive is sized and hashed within the time limit, before any tunnel', async () => {
		const k = await koid([ticket]);
		const src = await tarball(16 * 1024 ** 2);
		try {
			const { t, tunnels } = uploader(() => relayTo(k.sock));
			await expect(t.upload(request(), src.path, { timeoutMs: 1 })).rejects.toThrow(
				'uploading the source of hello-pr-7 did not finish within 1 ms',
			);
			expect(tunnels()).toEqual([]);
			expect(k.seen).toEqual([]);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a limit the clock says has passed stops before ssh is started, timer or no timer', async () => {
		const k = await koid([ticket]);
		const src = await tarball(1000);
		try {
			// The clock jumps past the limit while koid answers describe, so
			// by the time the archive is hashed the deadline has passed, with
			// the timer that would enforce it still a minute away.
			let clock = 0;
			const { t, tunnels } = uploader(() => relayTo(k.sock), {
				describe: () => {
					clock = 10 ** 9;
					return scripted({ stdout: DESCRIPTOR });
				},
				now: () => clock,
			});
			await expect(t.upload(request(), src.path, { timeoutMs: 60_000 })).rejects.toThrow(
				'uploading the source of hello-pr-7 did not finish within 1 minute',
			);
			expect(tunnels()).toEqual([]);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('hashing stops at the signal rather than read the archive to the end', async () => {
		const src = await tarball(8 * 1024 ** 2);
		try {
			const stop = new AbortController();
			const hashing = digestFile(src.path, stop.signal);
			stop.abort(new Error('the user pressed ctrl-c'));
			await expect(hashing).rejects.toThrow('the user pressed ctrl-c');
			const early = new AbortController();
			early.abort(new Error('before the file was opened'));
			await expect(digestFile(src.path, early.signal)).rejects.toThrow(
				'before the file was opened',
			);
			expect(await digestFile(src.path)).toBe(src.sha256);
		} finally {
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a time limit kills the tunnel and reports the upload unfinished', async () => {
		const src = await tarball(1000);
		const k = await koid([ticket, () => new Promise<Response>(() => {})]);
		try {
			const tunnels: Array<ReturnType<typeof relayTo>> = [];
			const { t } = uploader(() => {
				const p = relayTo(k.sock);
				tunnels.push(p);
				return p;
			});
			await expect(t.upload(request(), src.path, { timeoutMs: 300 })).rejects.toThrow(
				'uploading the source of hello-pr-7 did not finish within 300 ms',
			);
			expect(tunnels[0]?.killed).toBe(true);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('an upload with no limit of its own ends at the default', async () => {
		const src = await tarball(1000);
		const k = await koid([ticket, () => new Promise<Response>(() => {})]);
		try {
			const tunnels: Array<ReturnType<typeof relayTo>> = [];
			const { t } = uploader(
				() => {
					const p = relayTo(k.sock);
					tunnels.push(p);
					return p;
				},
				{ limits: { uploadMs: 300 } },
			);
			await expect(t.upload(request(), src.path)).rejects.toThrow(
				'uploading the source of hello-pr-7 did not finish within 300 ms',
			);
			expect(tunnels[0]?.killed).toBe(true);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a tunnel that carries nothing for the idle limit is koid not answering: reported, not tried again', async () => {
		// koid takes the ticket and the whole archive, then never answers,
		// with the session up. Nothing crosses the tunnel after the last
		// chunk went out, so the idle limit ends the upload, well inside
		// the upload's own limit, and no second tunnel is opened: it would
		// stall the same way.
		const src = await tarball(1000);
		const k = await koid([ticket, () => new Promise<Response>(() => {})]);
		try {
			const { t, tunnels } = uploader(() => relayTo(k.sock), {
				limits: { tunnelIdleMs: 200 },
			});
			const err = await t.upload(request(), src.path).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(BoxUnavailableError);
			expect((err as Error).message).toBe(
				'koid on 203.0.113.10 stopped answering during the upload of hello-pr-7: nothing crossed the tunnel for 200 ms',
			);
			expect(tunnels()).toHaveLength(1);
			expect(k.seen).toEqual(['POST /v1/uploads', `PUT /v1/uploads/${UPLOAD_ID}/source`]);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});

	test('a signal stops the upload with its own reason', async () => {
		const src = await tarball(1000);
		const k = await koid([ticket, () => new Promise<Response>(() => {})]);
		try {
			const tunnels: Array<ReturnType<typeof relayTo>> = [];
			const { t } = uploader(() => {
				const p = relayTo(k.sock);
				tunnels.push(p);
				return p;
			});
			const stop = new AbortController();
			const upload = t.upload(request(), src.path, { signal: stop.signal });
			await Bun.sleep(100);
			stop.abort(new Error('the user pressed ctrl-c'));
			await expect(upload).rejects.toThrow('the user pressed ctrl-c');
			expect(tunnels[0]?.killed).toBe(true);
		} finally {
			await k.stop();
			await rm(src.dir, { recursive: true, force: true });
		}
	});
});
