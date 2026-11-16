import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
	chmod,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	stat,
	symlink,
	writeFile,
} from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { UploadTicketSchema, type UpRequest } from '@koi/shared';
import { type ControlDeps, startControlServer } from '../../daemon/src/control.ts';
import { REQUEST_FILE, SOURCE_FILE } from '../../daemon/src/spool-uploads.ts';
import { UploadApi } from '../../daemon/src/upload-api.ts';
import { request as upRequest } from '../../daemon/test/fakes.ts';
import { toYaml } from '../src/config-command.ts';
import { exec, execOk } from '../src/exec.ts';
import { HttpRelayClient } from '../src/http1.ts';
import { run } from '../src/main.ts';
import { SshClient, type SshTarget, sshArgs, sshEnv } from '../src/ssh.ts';
import { fingerprint, trustedKeys } from '../src/target-command.ts';
import { HostKeyError, sshTransport } from '../src/transports/ssh.ts';
import { hostInfoFor } from './koid.ts';

// The SSH transport, the gateway, the installer's sshd configuration and
// `koi target trust` against a throwaway sshd: started here as the current
// user on a loopback port, with its own host key, a client key of its own,
// and the Match block the installer writes (host/ssh/sshd.sh, shared with
// host/ssh/install.sh) for the current user, whose ForceCommand runs the
// gateway from source against a koid stand-in on a unix socket. The
// stand-in serves the real control API with the real upload API behind it.
// The installer's checks run against the fixture as they run on a host.
// Nothing here touches the system sshd or the user's ssh files.
//
// What a sshd of the current user cannot show: the koi-connect account
// itself (sshd switches to no other user), so the account's groups, home
// and shell, and the koi-control group on the control socket, are the
// installer's alone to get right; and StrictModes, which refuses a keys
// file under a world-writable /tmp, so the fixture turns it off.

const which = (name: string, ...fallbacks: string[]) =>
	Bun.which(name) ?? fallbacks.find((p) => existsSync(p));
const SSHD = which('sshd', '/usr/sbin/sshd', '/usr/local/sbin/sshd');
const SSH = which('ssh');
const KEYGEN = which('ssh-keygen');
const KEYSCAN = which('ssh-keyscan');
const SCP = which('scp');
const SFTP = which('sftp');
const PGREP = which('pgrep');
const BASH = which('bash');
const available =
	process.platform === 'linux' &&
	SSHD !== undefined &&
	SSH !== undefined &&
	KEYGEN !== undefined &&
	KEYSCAN !== undefined &&
	BASH !== undefined;

const HOST_SSH = join(import.meta.dir, '..', '..', '..', 'host', 'ssh');
const GATEWAY = join(HOST_SSH, 'koi-ssh-gateway.ts');
const SSHD_LIB = join(HOST_SSH, 'sshd.sh');
const ALIAS = 'throwaway';
const DOMAIN = 'previews.example.com';

async function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const srv = createServer();
		srv.on('error', reject);
		srv.listen(0, '127.0.0.1', () => {
			const address = srv.address();
			const port = typeof address === 'object' && address !== null ? address.port : 0;
			srv.close(() => resolve(port));
		});
	});
}

async function waitForPort(port: number, stderr: () => Promise<string>): Promise<void> {
	for (let i = 0; i < 100; i++) {
		const open = await new Promise<boolean>((resolve) => {
			const c = connect({ host: '127.0.0.1', port });
			c.once('connect', () => {
				c.destroy();
				resolve(true);
			});
			c.once('error', () => resolve(false));
		});
		if (open) return;
		await Bun.sleep(50);
	}
	throw new Error(`sshd did not listen on ${port}: ${await stderr()}`);
}

// Runs one function of host/ssh/sshd.sh with these arguments, as the
// installer does.
async function sshdLib(fn: string, ...args: string[]) {
	return exec([BASH as string, '-c', `source "$0" && ${fn} "$@"`, SSHD_LIB, ...args], {
		timeoutMs: 20_000,
	});
}

// One word for a POSIX shell, whatever it holds. Inside single quotes the
// shell expands nothing, and `'\''` ends the quote, adds a quote and starts
// again. The double quotes of JSON.stringify leave $() and backticks live.
const shellQuote = (word: string) => `'${word.replaceAll("'", `'\\''`)}'`;

// The gateway as the box runs it, a plain path for ForceCommand: here a wrapper
// that notes its environment in `sessions` and runs the gateway from source
// against `socket`. The paths come from the temporary directory, which is
// whatever the machine says it is.
const gatewayWrapper = (sessions: string, bun: string, gateway: string, socket: string) =>
	`#!/bin/sh\nenv > ${shellQuote(sessions)}/$$.env\nexec ${shellQuote(bun)} ${shellQuote(gateway)} --socket ${shellQuote(socket)}\n`;

describe('the gateway wrapper of the fixture', () => {
	test('keeps $(), backticks and quotes in its paths as they are', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-wrapper-'));
		try {
			// Each form would run `touch pwned` in `dir` if the shell read it.
			const hostile = `a$(touch pwned)\`touch pwned\`'b"$HOME c`;
			const sessions = join(dir, `sessions ${hostile}`);
			await mkdir(sessions);
			// Stands for the runtime: prints the arguments it was given.
			const bun = join(dir, `bun ${hostile}`);
			await writeFile(bun, '#!/bin/sh\nfor a in "$@"; do printf \'%s\\n\' "$a"; done\n', {
				mode: 0o755,
			});
			const gateway = join(dir, `gateway ${hostile}`);
			const socket = join(dir, `socket ${hostile}`);
			const wrapper = join(dir, 'wrapper');
			await writeFile(wrapper, gatewayWrapper(sessions, bun, gateway, socket), { mode: 0o755 });
			const proc = Bun.spawn([wrapper], { cwd: dir, stdout: 'pipe', stderr: 'pipe' });
			const stdout = await new Response(proc.stdout).text();
			const stderr = await new Response(proc.stderr).text();
			expect(stderr).toBe('');
			expect(await proc.exited).toBe(0);
			expect(stdout).toBe(`${gateway}\n--socket\n${socket}\n`);
			expect((await readdir(sessions)).length).toBe(1);
			expect(existsSync(join(dir, 'pwned'))).toBe(false);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});

// Starts a sshd on `config`, which listens on `port`, and waits until it
// does. `logged` is what it has written so far, read as it comes: the sshd
// of a session inherits the pipe and lives as long as the session, so the
// end of the pipe is not waited for. `stop` ends the listener; the caller
// closes its ssh clients first, which ends the sessions.
async function startSshd(config: string, port: number) {
	const proc = Bun.spawn([SSHD as string, '-f', config, '-D', '-e'], {
		stdin: 'ignore',
		stdout: 'ignore',
		stderr: 'pipe',
	});
	let logged = '';
	const decoder = new TextDecoder();
	(async () => {
		for await (const chunk of proc.stderr as ReadableStream<Uint8Array>) {
			logged += decoder.decode(chunk, { stream: true });
		}
	})().catch(() => {});
	await waitForPort(port, async () => logged);
	return {
		logged: () => logged,
		stop: async () => {
			proc.kill();
			await proc.exited;
		},
	};
}

describe.skipIf(!available)('the SSH transport against a throwaway sshd', () => {
	let dir: string;
	let home: string;
	let port: number;
	let socket: string;
	let sshd: Awaited<ReturnType<typeof startSshd>> | undefined;
	let server: Awaited<ReturnType<typeof startControlServer>> | undefined;
	let api: UploadApi;
	let hostKeyFingerprint: string;
	let hostKeyLine: string;
	let target: SshTarget;
	let user: string;
	let gateway: string;
	let keys: string;
	let mainConfig: string;
	let blockFile: string;
	const ups: string[] = [];
	const env = { PATH: process.env.PATH ?? '/usr/bin:/bin' };
	// The ssh clients started here, each with its control directory; closed
	// at the end.
	const clients = new Map<SshClient, string>();

	const client = (over: Partial<SshTarget> = {}) => {
		const d = join(dir, `ctl-${clients.size}`);
		const c = new SshClient({
			target: { ...target, ...over },
			env,
			controlDir: async () => {
				await mkdir(d, { mode: 0o700 });
				return d;
			},
		});
		clients.set(c, d);
		return c;
	};
	const transport = (over: Partial<SshTarget> = {}) =>
		sshTransport(
			{ name: ALIAS, host: '127.0.0.1', user: target.user, domain: DOMAIN },
			client(over),
		);

	// One koid ping over a strict connection, against this known_hosts file.
	const ping = async (knownHostsFile: string, over: Partial<SshTarget> = {}) => {
		const t = transport({ knownHostsFile, ...over });
		try {
			return await t.ctl(['ping']);
		} finally {
			await t.close();
		}
	};

	// A config file with one target, this known_hosts file and this sshd.
	const configFor = async (name: string, knownHostsFile: string, sshPort: number) => {
		const config = join(dir, `config.${name}.yaml`);
		await writeFile(
			config,
			toYaml({
				version: 1,
				targets: {
					[ALIAS]: {
						domain: DOMAIN,
						transport: {
							kind: 'ssh',
							endpoint: {
								host: '127.0.0.1',
								port: sshPort,
								user: 'koi-connect',
								identityFile: join(dir, 'client_key'),
								knownHostsFile,
								hostKeyAlias: ALIAS,
							},
						},
						power: { kind: 'always-on' },
					},
				},
			}),
			{ mode: 0o600 },
		);
		return config;
	};

	// The `-o Name=value` pairs of the hardened command line, minus `drop`,
	// for ssh, scp and sftp run by hand.
	const optionPairs = (drop: string[] = []) => {
		const args = sshArgs(target, join(dir, 'ctl-direct'));
		const out: string[] = [];
		for (let i = 0; i < args.length; i++) {
			if (args[i] !== '-o') continue;
			const value = args[++i] ?? '';
			if (!drop.some((d) => value.startsWith(`${d}=`))) out.push('-o', value);
		}
		return out;
	};

	// The sshd configuration of the fixture: the globals a throwaway sshd
	// needs, then the Include of the directory that holds the installer's
	// block, as Ubuntu's sshd_config includes /etc/ssh/sshd_config.d. The
	// global AcceptEnv is deliberately the worst case: the block must
	// replace it for the account.
	const sshdConfig = (port: number, includeDir: string) =>
		[
			`Port ${port}`,
			'ListenAddress 127.0.0.1',
			`HostKey ${join(dir, 'host_key')}`,
			'PidFile none',
			'StrictModes no',
			'UsePAM no',
			'Subsystem sftp internal-sftp',
			'AcceptEnv LANG LC_* LD_PRELOAD',
			`Include ${includeDir}/*.conf`,
			'LogLevel ERROR',
			'',
		].join('\n');

	// The environments the gateway was started with, by session, as the
	// wrapper the ForceCommand runs dumps them.
	const sessionEnvs = async () => {
		const names = await readdir(join(dir, 'sessions'));
		const out = new Map<string, string>();
		for (const n of names) out.set(n, await readFile(join(dir, 'sessions', n), 'utf8'));
		return out;
	};

	beforeAll(async () => {
		if (SSHD === undefined || KEYGEN === undefined) return;
		dir = await mkdtemp(join(tmpdir(), 'koi-sshd-'));
		await chmod(dir, 0o700);
		home = join(dir, 'home');
		await mkdir(join(home, '.config', 'koi'), { recursive: true, mode: 0o700 });
		await mkdir(join(dir, 'sessions'));
		await execOk([KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'host_key')]);
		await execOk([KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'client_key')]);
		keys = join(dir, 'authorized_keys');
		await writeFile(keys, await readFile(join(dir, 'client_key.pub')));
		const hostKey = (await readFile(join(dir, 'host_key.pub'), 'utf8')).split(' ')[1] ?? '';
		hostKeyFingerprint = fingerprint(hostKey);
		hostKeyLine = `${ALIAS} ssh-ed25519 ${hostKey}\n`;
		user = userInfo().username;

		// The koid stand-in: the real control API with the real upload API.
		socket = join(dir, 'control.sock');
		api = new UploadApi({
			spoolDir: join(dir, 'spool'),
			budgetBytes: 100 * 1024 ** 2,
			log: () => {},
			// This machine's disk, whatever its state, is not what is tested.
			diskSpace: async () => ({ free: 100 * 1024 ** 3, size: 200 * 1024 ** 3 }),
		});
		await api.init();
		const unused = () => {
			throw new Error('not used in this test');
		};
		const deps: ControlDeps = {
			deployer: {
				up: async (id) => {
					ups.push(id);
					return { label: 'hello-pr-7', queued: false };
				},
				down: unused,
				acquireLease: unused,
				releaseLease: unused,
			},
			store: { get: async () => undefined, list: async () => [] },
			docker: { logs: unused },
			buildLogs: { read: unused, tail: unused },
			keepAwake: async () => {},
			describe: async () => hostInfoFor(DOMAIN),
			uploadApi: api,
		};
		server = await startControlServer(socket, deps);

		gateway = join(dir, 'gateway');
		await writeFile(
			gateway,
			gatewayWrapper(join(dir, 'sessions'), process.execPath, GATEWAY, socket),
			{ mode: 0o755 },
		);

		// The installer's Match block for the current user, from the same
		// function install.sh writes it with, in a directory the main file
		// includes; and the main file.
		const includeDir = join(dir, 'sshd_config.d');
		await mkdir(includeDir);
		blockFile = join(includeDir, '00-koi-connect.conf');
		const block = await sshdLib('koi_match_block', user, gateway, keys);
		expect(block.code).toBe(0);
		await writeFile(blockFile, block.stdout);
		port = await freePort();
		mainConfig = join(dir, 'sshd_config');
		await writeFile(mainConfig, sshdConfig(port, includeDir));
		sshd = await startSshd(mainConfig, port);

		target = {
			host: '127.0.0.1',
			port,
			user,
			identityFile: join(dir, 'client_key'),
			knownHostsFile: join(dir, 'known_hosts'),
			hostKeyAlias: ALIAS,
		};
		await writeFile(
			join(home, '.config', 'koi', 'config.yaml'),
			toYaml({
				version: 1,
				targets: {
					[ALIAS]: {
						domain: DOMAIN,
						transport: {
							kind: 'ssh',
							endpoint: {
								host: '127.0.0.1',
								port,
								user: 'koi-connect',
								identityFile: join(dir, 'client_key'),
								knownHostsFile: join(dir, 'known_hosts'),
								hostKeyAlias: ALIAS,
							},
						},
						power: { kind: 'always-on' },
					},
				},
			}),
			{ mode: 0o600 },
		);
	});

	afterAll(async () => {
		for (const c of clients.keys()) await c.close();
		await sshd?.stop();
		server?.stop(true);
		if (dir !== undefined) await rm(dir, { recursive: true, force: true });
	});

	async function koi(argv: string[]) {
		let stdout = '';
		let stderr = '';
		const code = await run(
			argv,
			{
				stdout: (s) => {
					stdout += s;
				},
				stderr: (s) => {
					stderr += s;
				},
			},
			{
				cwd: dir,
				env: { HOME: home, PATH: env.PATH },
				box: async () => {
					throw new Error('no host is opened here');
				},
			},
		);
		return { code, stdout, stderr };
	}

	test('the installed block is the first Match sshd reads, and binds the account as written', async () => {
		// The block is byte for byte what the installer writes for the box,
		// with its paths.
		const written = await readFile(blockFile, 'utf8');
		expect(written).toContain(`Match User ${user}\n`);
		expect(written).toContain(`    ForceCommand ${gateway}\n`);
		expect(written).toContain(`    AuthorizedKeysFile ${keys}\n`);
		expect(written).toContain('    ChrootDirectory none\n');
		expect(written).toContain('    TrustedUserCAKeys none\n');
		expect(written).toContain('    AcceptEnv KOI_NO_CLIENT_ENV\n');
		expect(written).toContain('    SetEnv KOI_NO_SERVER_ENV=\n');
		const blocks = await sshdLib('koi_check_match_blocks', mainConfig, blockFile, dir);
		expect(blocks.stderr).toBe('');
		expect(blocks.code).toBe(0);
		const global = await sshdLib('koi_check_global', SSHD as string, mainConfig);
		expect(global.stderr).toBe('');
		expect(global.code).toBe(0);
		const effective = await sshdLib(
			'koi_check_effective',
			SSHD as string,
			mainConfig,
			user,
			gateway,
			keys,
		);
		expect(effective.stderr).toBe('');
		expect(effective.code).toBe(0);
		// sshd itself agrees: the block replaced the global AcceptEnv.
		const shown = await execOk([
			SSHD as string,
			'-T',
			'-f',
			mainConfig,
			'-C',
			`user=${user},host=localhost,addr=127.0.0.1`,
		]);
		expect(shown.stdout.split('\n').filter((l) => l.startsWith('acceptenv '))).toEqual([
			'acceptenv KOI_NO_CLIENT_ENV',
		]);
		expect(shown.stdout).toContain(`forcecommand ${gateway}\n`);
	});

	test("the installer's checks refuse a Match before the block, AcceptEnv in any other block, a global PermitUserEnvironment yes, and lines they cannot read", async () => {
		// A Match block in the main file, before the Include. It would set
		// ForceCommand for the clients it matches, whatever the block says;
		// and since a Match block runs to the next Match, the Include falls
		// inside it, so no other client meets the block at all.
		const early = join(dir, 'sshd_config.early');
		await writeFile(
			early,
			sshdConfig(port, join(dir, 'sshd_config.d')).replace(
				'Include ',
				'Match Address 10.0.0.0/8\n    ForceCommand /bin/false\nInclude ',
			),
		);
		const first = await sshdLib('koi_check_match_blocks', early, blockFile, dir);
		expect(first.code).toBe(1);
		expect(first.stderr).toContain(
			`sshd reads a Match block at ${early}:9 before the one in ${blockFile}`,
		);
		// sshd -T agrees: the account gets no ForceCommand from loopback.
		const effectiveEarly = await sshdLib(
			'koi_check_effective',
			SSHD as string,
			early,
			user,
			gateway,
			keys,
		);
		expect(effectiveEarly.code).toBe(1);
		expect(effectiveEarly.stderr).toContain(
			"for a client at 127.0.0.1, sshd would apply 'forcecommand none'",
		);

		// PermitUserEnvironment cannot be set in a Match block, so the
		// global value is read, and anything but no is refused by name.
		const permissive = join(dir, 'sshd_config.env');
		await writeFile(
			permissive,
			sshdConfig(port, join(dir, 'sshd_config.d')).replace(
				'Include ',
				'PermitUserEnvironment yes\nInclude ',
			),
		);
		const global = await sshdLib('koi_check_global', SSHD as string, permissive);
		expect(global.code).toBe(1);
		expect(global.stderr).toContain("sshd's global PermitUserEnvironment is 'yes'");

		// A directory with the block first and one file after it, whose text
		// each case below writes; a main file includes the directory. Each
		// case is first given to sshd -t, so that what the walker reads is a
		// configuration sshd takes (or, where noted, refuses as well).
		const later = join(dir, 'sshd_config.d-later');
		await mkdir(later);
		const laterBlock = join(later, '00-koi-connect.conf');
		await writeFile(laterBlock, await readFile(blockFile));
		const laterFile = join(later, '50-later.conf');
		const laterConfig = join(dir, 'sshd_config.later');
		await writeFile(laterConfig, sshdConfig(port, later));
		const check = async (text: string, sshdTakesIt = true) => {
			await writeFile(laterFile, text);
			const syntax = await exec([SSHD as string, '-t', '-f', laterConfig], { timeoutMs: 20_000 });
			expect(syntax.code === 0).toBe(sshdTakesIt);
			return sshdLib('koi_check_match_blocks', laterConfig, laterBlock, dir);
		};
		const refusal = (block: string, where: string) =>
			`the Match block at ${block} sets AcceptEnv at ${where}`;
		const effectiveLater = () =>
			sshdLib('koi_check_effective', SSHD as string, laterConfig, user, gateway, keys);

		// A block after ours that adds LD_PRELOAD to AcceptEnv for one
		// address, with a User list written to leave the account out. sshd
		// reads the list by rules of its own, under which the quotes stay
		// part of the pattern and exclude nobody: sshd -T for that address
		// shows both names accepted. The walker refuses the block without
		// reading its criteria, so it is right whatever sshd makes of them.
		// koi_check_effective, which probes other addresses, sees nothing.
		const preload = await check(
			`Match Address 198.51.100.23 User *,!'${user}'\n    AcceptEnv LD_PRELOAD\n`,
		);
		expect(preload.code).toBe(1);
		expect(preload.stderr).toContain(refusal(`${laterFile}:1`, `${laterFile}:2`));
		const shown = await execOk([
			SSHD as string,
			'-T',
			'-f',
			laterConfig,
			'-C',
			`user=${user},host=localhost,addr=198.51.100.23`,
		]);
		expect(shown.stdout.split('\n').filter((l) => l.startsWith('acceptenv '))).toEqual([
			'acceptenv KOI_NO_CLIENT_ENV',
			'acceptenv LD_PRELOAD',
		]);
		expect((await effectiveLater()).code).toBe(0);
		// Whatever the criteria: a list in double quotes, a user the account
		// is not, a group, all, the user=NAME form.
		for (const criteria of [
			`User "*,!${user}"`,
			'User nobody',
			'Group wheel',
			'all',
			`Address 10.0.0.0/8 user=${user}`,
		]) {
			const other = await check(`Match ${criteria}\n    AcceptEnv LD_PRELOAD\n`);
			expect(other.code).toBe(1);
			expect(other.stderr).toContain(refusal(`${laterFile}:1`, `${laterFile}:2`));
		}

		// Any other keyword in a later block is left to sshd's rule: the
		// block set it first, so the first value obtained is the block's,
		// as sshd -T shows for each probed address.
		for (const line of [
			'ForceCommand /bin/false',
			'SetEnv LD_PRELOAD=/nonexistent/x.so',
			'PermitTTY yes',
			'AuthorizedKeysCommand /bin/true\n    AuthorizedKeysCommandUser nobody',
			'TrustedUserCAKeys /nonexistent/ca.pub',
			'ChrootDirectory /elsewhere',
			'PermitTunnel yes',
			'X11Forwarding yes',
		]) {
			const settled = await check(`Match all\n    ${line}\n`);
			expect(settled.stderr).toBe('');
			expect(settled.code).toBe(0);
			const probe = await effectiveLater();
			expect(probe.stderr).toBe('');
			expect(probe.code).toBe(0);
		}

		// A block in a file that an Include names in quotes, with a space
		// and an escaped quote in the path, which word splitting would miss:
		// it is found, and named. In single quotes as well.
		const spaced = join(dir, 'inc luded');
		await mkdir(spaced);
		const quoted = join(spaced, 'a"b.conf');
		await writeFile(quoted, 'Match Address 198.51.100.23\n    AcceptEnv LD_PRELOAD\n');
		for (const include of [`"${spaced}/a\\"b.conf"`, `'${spaced}/a"b.conf'`]) {
			const found = await check(`Include ${include}\n`);
			expect(found.code).toBe(1);
			expect(found.stderr).toContain(refusal(`${quoted}:1`, `${quoted}:2`));
		}
		// A file with no Match of its own is read inside the block that
		// includes it, so its AcceptEnv is that block's. Included from the
		// global section it is global AcceptEnv, which the block replaces.
		const plain = join(spaced, 'plain.conf');
		await writeFile(plain, 'AcceptEnv LD_PRELOAD\n');
		const nested = await check(`Match User nobody\n    Include "${plain}"\n`);
		expect(nested.code).toBe(1);
		expect(nested.stderr).toContain(refusal(`${laterFile}:1`, `${plain}:1`));
		expect((await check(`Include "${plain}"\n`)).code).toBe(0);

		// A line the walker cannot read as sshd would is refused with its
		// file and line, never skipped: a quote never closed (sshd refuses
		// it too), a keyword sshd reads around a quote or an `=`, an Include
		// from sshd's working directory, an Include of a directory (sshd
		// opens it and reads nothing) or of a link to nothing (sshd stops).
		const adir = join(dir, 'adir.conf');
		await mkdir(adir);
		const dangling = join(dir, 'dangling.conf');
		await symlink(join(dir, 'no-such-file.conf'), dangling);
		for (const [text, reason, sshdTakesIt] of [
			[`Include "${spaced}/a.conf\n`, 'has a quote that is never closed', false],
			[
				'"Match" User nobody\n    AcceptEnv LD_PRELOAD\n',
				'cannot be read as a keyword and its arguments',
				true,
			],
			[
				'=Match User nobody\n    AcceptEnv LD_PRELOAD\n',
				'cannot be read as a keyword and its arguments',
				true,
			],
			['Include ~/x.conf\n', "a path from sshd's working directory", true],
			[`Include ${adir}\n`, `includes ${adir}, a directory and not a regular file`, true],
			[`Include ${dangling}\n`, `includes ${dangling}, a symbolic link to nothing`, false],
		] as const) {
			const unread = await check(text, sshdTakesIt);
			expect(unread.code).toBe(1);
			expect(unread.stderr).toContain(`${laterFile}:1 `);
			expect(unread.stderr).toContain(reason);
		}

		// An Include of a named pipe. sshd opens an Include target with
		// fopen, whatever it is, and reads a pipe as it is fed: here a block
		// that takes LD_PRELOAD for one address, which sshd -T shows once the
		// pipe is fed again. The walker used to skip what was not a regular
		// file and pass; it refuses the pipe by name and kind without
		// opening it, which would wait for a writer as sshd -t does.
		const pipe = join(dir, 'pipe.conf');
		await execOk(['mkfifo', pipe]);
		const feed = () =>
			Bun.spawn(
				[
					BASH as string,
					'-c',
					'printf %s "$1" > "$0"',
					pipe,
					'Match Address 198.51.100.23\n    AcceptEnv LD_PRELOAD\n',
				],
				{ stdin: 'ignore', stdout: 'ignore', stderr: 'ignore' },
			);
		let feeder = feed();
		try {
			const piped = await check(`Include ${pipe}\n`);
			expect(piped.code).toBe(1);
			expect(piped.stderr).toContain(`${laterFile}:1 includes ${pipe}, a named pipe`);
			await feeder.exited;
			feeder = feed();
			const fed = await execOk([
				SSHD as string,
				'-T',
				'-f',
				laterConfig,
				'-C',
				`user=${user},host=localhost,addr=198.51.100.23`,
			]);
			await feeder.exited;
			expect(fed.stdout.split('\n').filter((l) => l.startsWith('acceptenv '))).toEqual([
				'acceptenv KOI_NO_CLIENT_ENV',
				'acceptenv LD_PRELOAD',
			]);
		} finally {
			feeder.kill();
		}

		// A NUL byte. sshd copies each line up to its first NUL, newline
		// included, so `Include FILE<NUL>junk` followed by an empty line
		// includes FILE, as sshd -T shows; bash's read drops the byte and
		// keeps the rest, so the walker looked for FILEjunk, found nothing,
		// and passed. A NUL anywhere is refused by file and line before the
		// file is read: in an included file, and in the main file.
		const hidden = join(dir, 'hidden.conf');
		await writeFile(hidden, 'Match Address 198.51.100.23\n    AcceptEnv LD_PRELOAD\n');
		const nulled = await check(`Include ${hidden}\0junk\n\n`);
		expect(nulled.code).toBe(1);
		expect(nulled.stderr).toContain(`${laterFile}:1 has a NUL byte`);
		const throughNul = await execOk([
			SSHD as string,
			'-T',
			'-f',
			laterConfig,
			'-C',
			`user=${user},host=localhost,addr=198.51.100.23`,
		]);
		expect(throughNul.stdout.split('\n').filter((l) => l.startsWith('acceptenv '))).toEqual([
			'acceptenv KOI_NO_CLIENT_ENV',
			'acceptenv LD_PRELOAD',
		]);
		const nulMain = join(dir, 'sshd_config.nul');
		await writeFile(
			nulMain,
			sshdConfig(port, join(dir, 'sshd_config.d')).replace(
				'LogLevel ERROR',
				`Include ${hidden}\0junk\n\nLogLevel ERROR`,
			),
		);
		expect((await exec([SSHD as string, '-t', '-f', nulMain], { timeoutMs: 20_000 })).code).toBe(0);
		const nulFirst = await sshdLib('koi_check_match_blocks', nulMain, blockFile, dir);
		expect(nulFirst.code).toBe(1);
		expect(nulFirst.stderr).toContain(`${nulMain}:10 has a NUL byte`);

		// A file sorting before ours with a Match in it, and a main file that
		// never includes ours.
		const before = join(dir, 'sshd_config.d-before');
		await mkdir(before);
		await writeFile(join(before, '00-koi-connect.conf'), await readFile(blockFile));
		await writeFile(join(before, '00-aaa.conf'), 'match user nobody\n    PermitTTY yes\n');
		const beforeConfig = join(dir, 'sshd_config.before');
		await writeFile(beforeConfig, sshdConfig(port, before));
		const beforeFirst = await sshdLib(
			'koi_check_match_blocks',
			beforeConfig,
			join(before, '00-koi-connect.conf'),
			dir,
		);
		expect(beforeFirst.code).toBe(1);
		expect(beforeFirst.stderr).toContain(`Match block at ${join(before, '00-aaa.conf')}:1 before`);
		const none = join(dir, 'sshd_config.none');
		await writeFile(none, sshdConfig(port, join(dir, 'no-such-dir')));
		const noneFirst = await sshdLib('koi_check_match_blocks', none, blockFile, dir);
		expect(noneFirst.code).toBe(1);
		expect(noneFirst.stderr).toContain(`never meets the Match block in ${blockFile}`);
	});

	test('the checks read the files before sshd runs on them: an Include of a pipe with no writer is refused, not waited on', async () => {
		// sshd opens an Include target with fopen, with -t as with -T, and
		// a named pipe with no writer holds it for good. The walker
		// refuses the pipe by name and kind without opening it, so the
		// installer's sequence, which runs the walker first, returns at
		// once with the walker's reason.
		const pipe = join(dir, 'silent.conf');
		await execOk(['mkfifo', pipe]);
		const config = join(dir, 'sshd_config.pipe');
		await writeFile(
			config,
			sshdConfig(port, join(dir, 'sshd_config.d')).replace(
				'LogLevel ERROR',
				`Include ${pipe}\nLogLevel ERROR`,
			),
		);
		const hung = await exec([SSHD as string, '-t', '-f', config], { timeoutMs: 1000 });
		expect(hung.timedOut).toBe(true);
		const checked = await sshdLib(
			'koi_check_sshd',
			SSHD as string,
			config,
			blockFile,
			dir,
			user,
			gateway,
			keys,
		);
		expect(checked.timedOut).toBe(false);
		expect(checked.code).toBe(1);
		expect(checked.stderr).toContain(`${config}:10 includes ${pipe}, a named pipe`);

		// The sequence passes on the fixture, and sshd's own refusal of a
		// file the walker has nothing against is reported after the walk.
		const good = await sshdLib(
			'koi_check_sshd',
			SSHD as string,
			mainConfig,
			blockFile,
			dir,
			user,
			gateway,
			keys,
		);
		expect(good.stderr).toBe('');
		expect(good.code).toBe(0);
		const bad = join(dir, 'sshd_config.bad');
		await writeFile(bad, `${sshdConfig(port, join(dir, 'sshd_config.d'))}NoSuchKeyword yes\n`);
		const refused = await sshdLib(
			'koi_check_sshd',
			SSHD as string,
			bad,
			blockFile,
			dir,
			user,
			gateway,
			keys,
		);
		expect(refused.code).toBe(1);
		expect(refused.stderr).toContain(
			`sshd refuses its configuration with ${blockFile} in place: ${bad}: line 11: Bad configuration option: NoSuchKeyword`,
		);

		// The installer runs that sequence and no sshd -t of its own, so
		// the walker sees the files first there too.
		const installer = await readFile(join(HOST_SSH, 'install.sh'), 'utf8');
		expect(installer).toContain('koi_check_sshd "$SSHD" "$SSHD_MAIN" "$SSHD_CONF"');
		expect(installer).not.toMatch(/\$SSHD" -[tT]\b/);
	}, 15_000);

	test('a global ChrootDirectory and a later TrustedUserCAKeys change nothing for the account: the block set both first', async () => {
		// A CA, and a certificate it signs for the current user. The key the
		// certificate is for is in no keys file: only the CA could let it in.
		const ca = join(dir, 'ca');
		const certKey = join(dir, 'cert_key');
		await execOk([KEYGEN as string, '-q', '-t', 'ed25519', '-N', '', '-f', ca]);
		await execOk([KEYGEN as string, '-q', '-t', 'ed25519', '-N', '', '-f', certKey]);
		await execOk([KEYGEN as string, '-q', '-s', ca, '-I', 'koi-test', '-n', user, certKey]);
		const knownHosts = join(dir, 'known_hosts.jail');
		await writeFile(knownHosts, hostKeyLine);
		const certLogin = (p: number) =>
			exec(
				[
					SSH as string,
					'-F',
					'none',
					...optionPairs([
						'IdentityFile',
						'UserKnownHostsFile',
						'Port',
						'ControlMaster',
						'ControlPath',
						'ControlPersist',
					]),
					'-o',
					`IdentityFile=${certKey}`,
					'-o',
					`CertificateFile=${certKey}-cert.pub`,
					'-o',
					`UserKnownHostsFile=${knownHosts}`,
					'-p',
					String(p),
					'--',
					'127.0.0.1',
					'ping',
				],
				{ timeoutMs: 20_000 },
			);
		const noKeys = join(dir, 'no_keys');
		await writeFile(noKeys, '');

		// The jail and the CA in the global section, the block, then a later
		// block for this very address that sets both again.
		const jailPort = await freePort();
		const jailConfig = join(dir, 'sshd_config.jail');
		await writeFile(
			jailConfig,
			`${sshdConfig(jailPort, join(dir, 'sshd_config.d')).replace(
				'Include ',
				`ChrootDirectory /srv/jails/%u\nTrustedUserCAKeys ${ca}.pub\nInclude `,
			)}Match Address 127.0.0.1\n    ChrootDirectory /elsewhere\n    TrustedUserCAKeys ${ca}.pub\n`,
		);
		// The installer's checks take it: the later block sets no AcceptEnv,
		// and sshd -T shows the block's value in force for each keyword.
		expect((await sshdLib('koi_check_match_blocks', jailConfig, blockFile, dir)).code).toBe(0);
		expect((await sshdLib('koi_check_global', SSHD as string, jailConfig)).code).toBe(0);
		const effective = await sshdLib(
			'koi_check_effective',
			SSHD as string,
			jailConfig,
			user,
			gateway,
			keys,
		);
		expect(effective.stderr).toBe('');
		expect(effective.code).toBe(0);
		const global = await execOk([SSHD as string, '-T', '-f', jailConfig]);
		expect(global.stdout).toContain('chrootdirectory /srv/jails/%u\n');
		expect(global.stdout).toContain(`trustedusercakeys ${ca}.pub\n`);
		const account = await execOk([
			SSHD as string,
			'-T',
			'-f',
			jailConfig,
			'-C',
			`user=${user},host=localhost,addr=127.0.0.1`,
		]);
		expect(account.stdout).toContain('chrootdirectory none\n');
		expect(account.stdout).toContain('trustedusercakeys none\n');

		// Against a running sshd: the key in the file gets in and the
		// gateway answers, and the certificate is refused.
		const host = { name: ALIAS, host: '127.0.0.1', user: target.user, domain: DOMAIN };
		const jailed = await startSshd(jailConfig, jailPort);
		const jailedClient = client({ port: jailPort, knownHostsFile: knownHosts });
		try {
			const t = sshTransport(host, jailedClient);
			expect((await t.ctl(['ping'])).code).toBe(0);
			const refused = await certLogin(jailPort);
			expect(refused.code).toBe(255);
			expect(refused.stderr).toContain('Permission denied (publickey)');
		} finally {
			await jailedClient.close();
			await jailed.stop();
		}

		// The controls, without the block. A sshd of the current user cannot
		// chroot at all, so the jail ends the session of the same key: the
		// login above worked because the block took the jail away. And the
		// same CA, trusted by the global section alone, lets the certificate
		// in.
		const jailControlPort = await freePort();
		const jailControl = join(dir, 'sshd_config.jail-control');
		await writeFile(
			jailControl,
			`${sshdConfig(jailControlPort, join(dir, 'no-such-dir'))}ChrootDirectory /srv/jails/%u\nAuthorizedKeysFile ${keys}\nForceCommand ${gateway}\n`,
		);
		const jailing = await startSshd(jailControl, jailControlPort);
		const jailingClient = client({ port: jailControlPort, knownHostsFile: knownHosts });
		try {
			const t = sshTransport(host, jailingClient);
			const err = await t.ctl(['ping']).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(Error);
			for (let i = 0; i < 40 && !jailing.logged().includes('chroot'); i++) await Bun.sleep(50);
			expect(jailing.logged()).toContain('lacks privileges to chroot');
		} finally {
			await jailingClient.close();
			await jailing.stop();
		}
		const caPort = await freePort();
		const caConfig = join(dir, 'sshd_config.ca');
		await writeFile(
			caConfig,
			`${sshdConfig(caPort, join(dir, 'no-such-dir'))}TrustedUserCAKeys ${ca}.pub\nAuthorizedKeysFile ${noKeys}\nForceCommand /bin/echo cert-accepted\n`,
		);
		const trusting = await startSshd(caConfig, caPort);
		try {
			const accepted = await certLogin(caPort);
			expect(accepted.stderr).toBe('');
			expect(accepted.stdout).toBe('cert-accepted\n');
			expect(accepted.code).toBe(0);
		} finally {
			await trusting.stop();
		}
	}, 60_000);

	test('refuses a host whose key koi does not trust, and sends nothing', async () => {
		const t = transport({ knownHostsFile: join(dir, 'known_hosts.none') });
		const err = await t.ctl(['ping']).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(HostKeyError);
		expect((err as Error).message).toContain(`koi target trust ${ALIAS} --fingerprint SHA256:...`);
		expect(await t.ensureAwake(() => {}).catch((e: unknown) => e)).toBeInstanceOf(HostKeyError);
	});

	test('a known_hosts path with a space names one file; nothing in the working directory counts', async () => {
		// Unquoted, ssh would read this as two files: `.../known` and a
		// relative `hosts`, which the working directory could supply. The
		// configured file holds no key, the stray one holds the right key.
		const spaced = join(dir, 'known hosts');
		const cwd = join(dir, 'cwd');
		await mkdir(cwd);
		await writeFile(join(cwd, 'hosts'), hostKeyLine);
		const before = process.cwd();
		process.chdir(cwd);
		try {
			const untrusted = transport({ knownHostsFile: spaced });
			const err = await untrusted.ctl(['ping']).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(HostKeyError);
			// The configured file holds the key, the stray one a wrong key:
			// the connection is made.
			await writeFile(spaced, hostKeyLine);
			await writeFile(join(cwd, 'hosts'), `${ALIAS} ssh-ed25519 ${'A'.repeat(68)}\n`);
			const trusted = transport({ knownHostsFile: spaced });
			expect((await trusted.ctl(['ping'])).code).toBe(0);
		} finally {
			process.chdir(before);
		}
	});

	test('koi target trust refuses a wrong fingerprint and enrolls the right one', async () => {
		// The fingerprint koi computes is the one ssh-keygen prints.
		const shown = await execOk([KEYGEN as string, '-lf', join(dir, 'host_key.pub')]);
		expect(shown.stdout).toContain(hostKeyFingerprint);

		const wrong = await koi([
			'target',
			'trust',
			ALIAS,
			'--fingerprint',
			'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
		]);
		expect(wrong.code).toBe(1);
		expect(wrong.stderr).toContain('so koi trusts nothing');
		expect(wrong.stderr).toContain(hostKeyFingerprint);
		expect(existsSync(join(dir, 'known_hosts'))).toBe(false);

		const right = await koi(['target', 'trust', ALIAS, '--fingerprint', hostKeyFingerprint]);
		expect(right.stderr).toBe('');
		expect(right.code).toBe(0);
		expect(right.stdout).toBe(
			`trusted 127.0.0.1:${port} as ${ALIAS} in ${join(dir, 'known_hosts')}: ssh-ed25519 ${hostKeyFingerprint}\n`,
		);
		const written = await readFile(join(dir, 'known_hosts'), 'utf8');
		expect(written).toMatch(new RegExp(`^${ALIAS} ssh-ed25519 [A-Za-z0-9+/=]+\n$`));
		expect((await stat(join(dir, 'known_hosts'))).mode & 0o777).toBe(0o600);

		const show = await koi(['target', 'show', ALIAS]);
		expect(show.stdout).toContain(`host key: ${hostKeyFingerprint} (ssh-ed25519) as ${ALIAS}`);
	});

	test('after a rotation a strict connection refuses the old key, wherever the file held it', async () => {
		// The fixture's sshd goes on offering the old key. A second sshd, with a
		// new key, stands for the host after its rotation.
		const newKey = join(dir, 'host_key.rotated');
		await execOk([KEYGEN as string, '-q', '-t', 'ed25519', '-N', '', '-f', newKey]);
		const newBase64 = (await readFile(`${newKey}.pub`, 'utf8')).split(' ')[1] ?? '';
		const newPort = await freePort();
		const newConfig = join(dir, 'sshd_config.rotated');
		await writeFile(
			newConfig,
			sshdConfig(newPort, join(dir, 'sshd_config.d')).replace(
				`HostKey ${join(dir, 'host_key')}`,
				`HostKey ${newKey}`,
			),
		);
		const rotated = await startSshd(newConfig, newPort);
		const oldEntry = hostKeyLine.slice(ALIAS.length).trimEnd();
		const newLine = `${ALIAS} ssh-ed25519 ${newBase64}`;
		try {
			const cases: [string, string, (file: string) => Promise<void>, string[]][] = [
				[
					'wildcard',
					`${ALIAS},*${oldEntry}\n`,
					async () => {},
					[`*,!${ALIAS}${oldEntry}`, newLine],
				],
				['shared', `${ALIAS},other${oldEntry}\n`, async () => {}, [`other${oldEntry}`, newLine]],
				[
					'hashed',
					hostKeyLine,
					async (file) => {
						await execOk([KEYGEN as string, '-q', '-H', '-f', file]);
					},
					[newLine],
				],
			];
			for (const [name, text, prepare, after] of cases) {
				const file = join(dir, `known_hosts.rotate-${name}`);
				await writeFile(file, text);
				await prepare(file);
				// Before the rotation the file trusts the old key.
				expect((await ping(file)).code).toBe(0);

				const config = await configFor(`rotate-${name}`, file, newPort);
				const trusted = await koi([
					'target',
					'trust',
					ALIAS,
					'--fingerprint',
					fingerprint(newBase64),
					'--config',
					config,
				]);
				expect(trusted.stderr).toBe('');
				expect(trusted.code).toBe(0);
				expect(trusted.stdout).toStartWith('replaced the host key of');
				expect((await readFile(file, 'utf8')).trimEnd().split('\n')).toEqual(after);

				// ssh refuses the host that still offers the old key, and takes
				// the host with the new one.
				const err = await ping(file).catch((e: unknown) => e);
				expect(err).toBeInstanceOf(HostKeyError);
				expect((await ping(file, { port: newPort })).code).toBe(0);
			}
		} finally {
			await rotated.stop();
		}
	}, 30_000);

	describe('revocations, and what a strict connection does with them', () => {
		const CERT = 'ssh-ed25519-cert-v01@openssh.com';
		let plain = '';
		let cert = '';
		let caKey = '';

		beforeAll(async () => {
			if (KEYGEN === undefined || !available) return;
			// A real certificate of the key the fixture's sshd offers. It is signed
			// from a copy, so no file lands beside the key sshd reads.
			const ca = join(dir, 'revocations_ca');
			await execOk([KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-f', ca]);
			const copy = join(dir, 'revocations_host.pub');
			await writeFile(copy, await readFile(join(dir, 'host_key.pub')));
			await execOk([KEYGEN, '-q', '-s', ca, '-h', '-I', 'koi-test', '-n', ALIAS, copy]);
			plain = hostKeyLine.trimEnd().split(' ')[2] ?? '';
			cert = (await readFile(join(dir, 'revocations_host-cert.pub'), 'utf8')).split(' ')[1] ?? '';
			caKey = (await readFile(`${ca}.pub`, 'utf8')).split(' ')[1] ?? '';
		});

		test('koi target trust refuses a key a certificate entry revokes, which strict ssh would refuse', async () => {
			const revocation = `@revoked * ${CERT} ${cert}\n`;
			const file = join(dir, 'known_hosts.revoked-cert');
			await writeFile(file, revocation);
			const r = await koi([
				'target',
				'trust',
				ALIAS,
				'--fingerprint',
				hostKeyFingerprint,
				'--config',
				await configFor('revoked-cert', file, port),
			]);
			expect(r.code).toBe(1);
			expect(r.stderr).toContain(`${file} revokes the key ${hostKeyFingerprint} for ${ALIAS}`);
			expect(await readFile(file, 'utf8')).toBe(revocation);

			// A successful trust would have left this file, and ssh refuses the key.
			await writeFile(file, `${revocation}${hostKeyLine}`);
			const err = await ping(file).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(HostKeyError);
			expect((err as Error).message).toContain('REVOKED HOST KEY DETECTED');
		});

		test('koi target show lists the key exactly when a strict connection takes it', async () => {
			const trusted = hostKeyLine;
			const cases: [string, string, boolean][] = [
				['the plain line', trusted, true],
				['revoked by its own line', `${trusted}@revoked * ssh-ed25519 ${plain}\n`, false],
				['revoked by a certificate', `${trusted}@revoked * ${CERT} ${cert}\n`, false],
				['revoked first', `@revoked * ${CERT} ${cert}\n${trusted}`, false],
				['revoked for the alias by name', `${trusted}@revoked ${ALIAS} ${CERT} ${cert}\n`, false],
				['revoked for another name', `${trusted}@revoked prod ${CERT} ${cert}\n`, true],
				['revoked except for the alias', `${trusted}@revoked *,!${ALIAS} ${CERT} ${cert}\n`, true],
				['the CA revoked, not the key', `${trusted}@revoked * ssh-ed25519 ${caKey}\n`, true],
				[
					'a revocation of the wrong type',
					`${trusted}@revoked * ecdsa-sha2-nistp256 ${plain}\n`,
					true,
				],
				['a tab after the marker', `${trusted}@revoked\t* ${CERT} ${cert}\n`, true],
				['tabs and no space', `${trusted}@revoked\t*\t${CERT}\t${cert}\n`, false],
				['a certificate with no marker', `${ALIAS} ${CERT} ${cert}\n`, false],
				['a key of the wrong type', `${ALIAS} ecdsa-sha2-nistp256 ${plain}\n`, false],
			];
			const file = join(dir, 'known_hosts.show');
			for (const [name, text, accepted] of cases) {
				await writeFile(file, text);
				const connected = await ping(file).then(
					(r) => r.code === 0,
					(e: unknown) => {
						expect(e).toBeInstanceOf(HostKeyError);
						return false;
					},
				);
				const shown = (await trustedKeys(file, ALIAS)).map((k) => k.fingerprint);
				expect([name, connected]).toEqual([name, accepted]);
				expect([name, shown]).toEqual([name, accepted ? [hostKeyFingerprint] : []]);
			}
		}, 30_000);
	});

	test('describe, ping and up go through ctl-b64, several sessions at once', async () => {
		const t = transport();
		expect(await t.describe()).toEqual(hostInfoFor(DOMAIN));
		await t.ensureAwake(() => {
			throw new Error('koid answers at once');
		});
		const pings = await Promise.all([t.ctl(['ping']), t.ctl(['ping']), t.ctl(['ping'])]);
		expect(pings.map((p) => [p.code, p.stdout])).toEqual([
			[0, '{"ok":true}\n'],
			[0, '{"ok":true}\n'],
			[0, '{"ok":true}\n'],
		]);
		const id = 'abcdefghij0123456789';
		const up = await t.ctl(['up', id]);
		expect(up.code).toBe(0);
		expect(JSON.parse(up.stdout)).toEqual({ label: 'hello-pr-7', queued: false });
		expect(ups).toEqual([id]);
		// koid's refusal comes back as koid ctl's exit status and error.
		const refused = await t.ctl(['status', 'nothing-here']);
		expect(refused.code).toBe(1);
		expect(refused.stderr).toContain('no such preview');
	});

	test('a host that serves another domain than the target gets no source', async () => {
		const t = sshTransport(
			{ name: ALIAS, host: '127.0.0.1', user: target.user, domain: 'other.example.com' },
			client(),
		);
		const request: UpRequest = upRequest({ createdAt: new Date().toISOString() });
		const tarball = join(dir, 'unsent.tar.gz');
		await writeFile(tarball, Buffer.alloc(1000, 1));
		await expect(t.upload(request, tarball)).rejects.toThrow(
			`serves previews under ${DOMAIN}, not other.example.com as configured`,
		);
		expect(existsSync(join(dir, 'spool', 'ready', request.id))).toBe(false);
		expect(await readdir(join(dir, 'spool', 'incoming'))).toEqual([]);
	});

	test('uploads the source through tunnel-v1 to the real upload API', async () => {
		const t = transport();
		const request: UpRequest = upRequest({ createdAt: new Date().toISOString() });
		const size = 2 * 1024 ** 2 + 77;
		const bytes = Buffer.alloc(size);
		for (let i = 0; i < size; i++) bytes[i] = (i * 13) & 0xff;
		const tarball = join(dir, 'source.tar.gz');
		await writeFile(tarball, bytes);
		await t.upload(request, tarball);
		const ready = join(dir, 'spool', 'ready', request.id);
		expect(await readFile(join(ready, SOURCE_FILE))).toEqual(bytes);
		expect(JSON.parse(await readFile(join(ready, REQUEST_FILE), 'utf8'))).toEqual(request);
		// The same upload again finds its content committed and sends nothing.
		await t.upload(request, tarball);
		// Then the request is built from the spool.
		const up = await t.ctl(['up', request.id]);
		expect(up.code).toBe(0);
	});

	test('a request outside the grammar runs nothing: a shell, a verb, scp, sftp', async () => {
		const c = client();
		const bogus = await c.run('bogus');
		expect(bogus.code).toBe(2);
		expect(bogus.stdout).toBe('');
		expect(bogus.stderr).toContain('"bogus" is not a command of this account');

		// No command at all is a request for a shell.
		const shell = await exec(sshArgs(target, join(dir, 'ctl-shell')), { timeoutMs: 20_000 });
		expect(shell.code).toBe(2);
		expect(shell.stderr).toContain('this account runs no shell');

		// scp and sftp hand the same options to ssh, so the account's port and
		// user come from them.
		const common = [
			'-F',
			'none',
			...optionPairs(['ControlMaster', 'ControlPath', 'ControlPersist']),
		];
		if (SCP !== undefined) {
			const scp = await exec(
				[SCP, '-O', ...common, join(dir, 'authorized_keys'), '127.0.0.1:/tmp/x'],
				{ timeoutMs: 20_000 },
			);
			expect(scp.code).not.toBe(0);
			expect(scp.stderr).toContain('file transfer is not available on this account');
		}
		if (SFTP !== undefined) {
			// sftp keeps its ssh's stderr to itself, so the refusal shows only
			// as a subsystem that answered nothing and closed.
			const sftp = await exec([SFTP, ...common, '127.0.0.1'], { timeoutMs: 20_000 });
			expect(sftp.code).not.toBe(0);
			expect(sftp.stderr).toContain('Connection closed');
		}
	});

	test('sshd refuses a forwarding and a PTY for this account', async () => {
		const common = [
			SSH as string,
			'-F',
			'none',
			...optionPairs(['ClearAllForwardings', 'ControlMaster', 'ControlPath', 'ControlPersist']),
		];
		const forward = await exec(
			[...common, '-o', 'ExitOnForwardFailure=yes', '-N', '-R', '0:127.0.0.1:1', '--', '127.0.0.1'],
			{ timeoutMs: 20_000 },
		);
		expect(forward.code).toBe(255);
		expect(forward.stderr).toMatch(/forwarding failed|administratively prohibited/);
		// -tt asks for a PTY even without a terminal; the block permits none.
		const pty = await exec(
			[
				SSH as string,
				'-F',
				'none',
				...optionPairs(['RequestTTY', 'ControlMaster', 'ControlPath', 'ControlPersist']),
				'-tt',
				'--',
				'127.0.0.1',
			],
			{ timeoutMs: 20_000 },
		);
		expect(pty.code).not.toBe(0);
		expect(`${pty.stdout}${pty.stderr}`).toMatch(/PTY allocation request failed/);
	});

	test('a variable the client sends does not reach the gateway, whatever the global AcceptEnv', async () => {
		// The fixture's global AcceptEnv takes LD_PRELOAD; the block replaces
		// it for the account with a name nothing reads. The client sends
		// both: only the placeholder arrives, so the mechanism is live and
		// that is all it lets through. The library named does not exist, so
		// nothing would load even where it got through.
		const marker = `sent-${Date.now()}`;
		const r = await exec(
			[
				SSH as string,
				'-F',
				'none',
				...optionPairs(['ControlMaster', 'ControlPath', 'ControlPersist']),
				'-o',
				`SetEnv=LD_PRELOAD=/nonexistent/koi-test.so KOI_NO_CLIENT_ENV=${marker}`,
				'--',
				'127.0.0.1',
				'tunnel-v1',
			],
			{ timeoutMs: 20_000, stdin: '' },
		);
		expect(r.stderr).not.toContain('cannot be preloaded');
		// This session's environment, found by the marker it sent.
		const envs = [...(await sessionEnvs()).values()].filter((e) =>
			e.includes(`KOI_NO_CLIENT_ENV=${marker}\n`),
		);
		expect(envs).toHaveLength(1);
		const seen = (envs[0] ?? '').split('\n');
		expect(seen).toContain('KOI_NO_SERVER_ENV=');
		expect(seen.some((l) => l.startsWith('LD_PRELOAD='))).toBe(false);
		expect(seen).toContain('SSH_ORIGINAL_COMMAND=tunnel-v1');
	});

	test('a session killed in the middle of an upload leaves no gateway behind, and close ends the master', async () => {
		const c = client();
		const request: UpRequest = upRequest({
			id: 'killed0123456789abcd',
			createdAt: new Date().toISOString(),
		});
		const bytes = Buffer.alloc(512 * 1024, 7);
		const sha256 = createHash('sha256').update(bytes).digest('hex');
		// A valid ticket, then half the source, then the session is killed.
		const tunnel = await c.open('tunnel-v1', true);
		const http = new HttpRelayClient({ write: (b) => tunnel.write(b), readable: tunnel.stdout });
		const ticket = await http.request({
			method: 'POST',
			path: '/v1/uploads',
			headers: { 'content-type': 'application/json' },
			body: new TextEncoder().encode(
				JSON.stringify({ requestId: request.id, sizeBytes: bytes.length, sha256 }),
			),
		});
		expect(ticket.status).toBe(201);
		const { uploadId } = UploadTicketSchema.parse(
			JSON.parse(new TextDecoder().decode(ticket.body)),
		);
		await tunnel.write(
			new TextEncoder().encode(
				`PUT /v1/uploads/${uploadId}/source HTTP/1.1\r\nHost: koid\r\nContent-Type: application/gzip\r\nContent-Length: ${bytes.length}\r\n\r\n`,
			),
		);
		await tunnel.write(bytes.subarray(0, bytes.length / 2));
		await Bun.sleep(200);
		tunnel.kill();
		await tunnel.exited;
		if (PGREP !== undefined) {
			let left = '';
			for (let i = 0; i < 40; i++) {
				const r = await exec([PGREP, '-f', `--socket '?${socket}`]);
				left = r.stdout.trim();
				if (left === '') break;
				await Bun.sleep(50);
			}
			expect(left).toBe('');
		}
		// Nothing of it is committed, and the request can still be uploaded
		// whole afterwards.
		expect(existsSync(join(dir, 'spool', 'ready', request.id))).toBe(false);
		const tarball = join(dir, 'resumed.tar.gz');
		await writeFile(tarball, bytes);
		await transport().upload(request, tarball);
		expect(await readFile(join(dir, 'spool', 'ready', request.id, SOURCE_FILE))).toEqual(bytes);
		// The master's socket is there while the client is open, and gone after.
		const controlPath = join(clients.get(c) as string, 'm');
		expect(existsSync(controlPath)).toBe(true);
		await c.close();
		expect(existsSync(controlPath)).toBe(false);
	});

	test('the environment reaches ssh only as PATH', () => {
		expect(Object.keys(sshEnv(target, { ...process.env, SSH_AUTH_SOCK: '/x' }))).toEqual(['PATH']);
	});
});
