import { beforeAll, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCli } from '../src/args.ts';
import { toYaml } from '../src/config-command.ts';
import { exec, execOk } from '../src/exec.ts';
import { type Runtime, run } from '../src/main.ts';
import {
	fingerprint,
	knownHostsLines,
	parseKeyscan,
	targetCommand,
	trustedKeys,
} from '../src/target-command.ts';

// Two host keys as ssh-keyscan prints them (the keys of a throwaway sshd,
// nothing deployed).
const ED25519 = 'AAAAC3NzaC1lZDI1NTE5AAAAIOLFJmrcTAKe8TPgLUo8yr8eQQ2aGRSPOiRfvJFynqph';
const ED25519_FP = 'SHA256:yafprXjNqGAiu4TRle+qC+BurNOzHuZM6xevfySqbqk';
const ECDSA =
	'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHR0pQ2M0Z7c8KX3h8b3j8Yw4G8kq1VxH1ZkqGk0o4O5jzYc2mRtv2yXb0w9p0bWJ1xqk1OZ2XPf8Y0F3E0y1gE=';
const SCAN = `# 203.0.113.10:22 SSH-2.0-OpenSSH_9.6\n[203.0.113.10]:22 ssh-ed25519 ${ED25519}\n[203.0.113.10]:22 ecdsa-sha2-nistp256 ${ECDSA}\n`;
// The key a host offers after its key was rotated. OpenSSH reads any 32 bytes
// as an ed25519 key, so these need not come from a real key pair.
const ROTATED = `${ED25519.slice(0, -4)}AAAA`;
const SCAN_ROTATED = `[203.0.113.10]:22 ssh-ed25519 ${ROTATED}\n`;

async function home(targets: Record<string, unknown>) {
	const dir = await mkdtemp(join(tmpdir(), 'koi-home-'));
	await mkdir(join(dir, '.config', 'koi'), { recursive: true, mode: 0o700 });
	await writeFile(join(dir, '.config', 'koi', 'config.yaml'), toYaml({ version: 1, targets }), {
		mode: 0o600,
	});
	return dir;
}

function sshTarget(dir: string, over: Record<string, unknown> = {}) {
	return {
		domain: 'previews.example.com',
		transport: {
			kind: 'ssh',
			endpoint: {
				host: '203.0.113.10',
				port: 2222,
				user: 'koi-connect',
				identityFile: '/home/operator/.ssh/koi_team_ed25519',
				knownHostsFile: join(dir, 'known_hosts'),
				hostKeyAlias: 'team',
				...over,
			},
		},
		power: { kind: 'always-on' },
	};
}

const AWS = {
	domain: 'previews.example.net',
	transport: { kind: 'aws-ssm' },
	aws: { instanceId: 'i-0abc', uploadsBucket: 'koi-uploads-123456789012' },
	power: { kind: 'ec2' },
};

async function capture(
	argv: string[],
	env: Record<string, string>,
	keyscan?: () => Promise<string>,
	sleep?: (ms: number) => Promise<void>,
	findHost?: (alias: string, file: string) => Promise<string>,
	listKeys?: (keys: string) => Promise<string>,
) {
	let stdout = '';
	let stderr = '';
	const io = {
		stdout: (s: string) => {
			stdout += s;
		},
		stderr: (s: string) => {
			stderr += s;
		},
	};
	try {
		const code = await targetCommand(parseCli(argv), io, {
			env,
			notice: () => {},
			keyscan,
			sleep,
			findHost,
			listKeys,
		});
		return { code, stdout, stderr };
	} catch (err) {
		return { code: 1, stdout, stderr: `koi: ${(err as Error).message}\n` };
	}
}

describe('fingerprint and keyscan', () => {
	test('is SHA256: and the digest in base64 without padding, as ssh-keygen -l prints it', () => {
		expect(fingerprint(ED25519)).toBe(ED25519_FP);
	});

	test('reads keys off ssh-keyscan output and skips what is not one', () => {
		const keys = parseKeyscan(`${SCAN}garbage line\n\n# comment\n`);
		expect(keys.map((k) => [k.type, k.fingerprint])).toEqual([
			['ssh-ed25519', ED25519_FP],
			['ecdsa-sha2-nistp256', fingerprint(ECDSA)],
		]);
		expect(parseKeyscan('')).toEqual([]);
	});
});

describe('koi target trust', () => {
	test('enrolls the key whose fingerprint matches, under the alias, in a private file', async () => {
		const h = await home({ team: sshTarget(h0) });
		const r = await capture(
			['target', 'trust', 'team', '--fingerprint', ED25519_FP],
			{ HOME: h },
			async () => SCAN,
		);
		expect(r).toEqual({
			code: 0,
			stdout: `trusted 203.0.113.10:2222 as team in ${join(h0, 'known_hosts')}: ssh-ed25519 ${ED25519_FP}\n`,
			stderr: '',
		});
		const file = join(h0, 'known_hosts');
		expect(await readFile(file, 'utf8')).toBe(`team ssh-ed25519 ${ED25519}\n`);
		expect((await stat(file)).mode & 0o777).toBe(0o600);
		expect(await trustedKeys(file, 'team')).toEqual([
			{ type: 'ssh-ed25519', key: ED25519, fingerprint: ED25519_FP },
		]);
	});

	test('refuses when no offered key has the fingerprint, and writes nothing', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
		const h = await home({ team: sshTarget(dir) });
		const wrong = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
		const r = await capture(
			['target', 'trust', 'team', '--fingerprint', wrong],
			{ HOME: h },
			async () => SCAN,
		);
		expect(r.code).toBe(1);
		expect(r.stderr).toContain(
			`none of the 2 host keys 203.0.113.10:2222 offers has the fingerprint ${wrong}, so koi trusts nothing`,
		);
		expect(r.stderr).toContain(
			`Offered: ${ED25519_FP} (ssh-ed25519), ${fingerprint(ECDSA)} (ecdsa-sha2-nistp256)`,
		);
		await expect(stat(join(dir, 'known_hosts'))).rejects.toThrow();
	});

	test("replaces the alias's old key and keeps every other line", async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
		const file = join(dir, 'known_hosts');
		await writeFile(
			file,
			`# kept\nother ssh-ed25519 ${ECDSA}\nteam ssh-rsa AAAAB3NzaC1yc2E=\n@cert-authority *.example ssh-ed25519 ${ED25519}\n`,
		);
		const h = await home({ team: sshTarget(dir) });
		const r = await capture(
			['target', 'trust', 'team', '--fingerprint', ED25519_FP],
			{ HOME: h },
			async () => SCAN,
		);
		expect(r.code).toBe(0);
		expect(r.stdout).toStartWith('replaced the host key of 203.0.113.10:2222 as team');
		expect(await readFile(file, 'utf8')).toBe(
			`# kept\nother ssh-ed25519 ${ECDSA}\n@cert-authority *.example ssh-ed25519 ${ED25519}\nteam ssh-ed25519 ${ED25519}\n`,
		);
	});

	test('an entry the alias shares with other names keeps them; the alias gets a line of its own', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
		const file = join(dir, 'known_hosts');
		// A plain shared entry, and a marked one with a comment after the key.
		await writeFile(
			file,
			`team,prod ssh-ed25519 ${ROTATED}\n@cert-authority team,*.example ssh-ed25519 ${ROTATED} ca\n`,
		);
		const h = await home({ team: sshTarget(dir) });
		const r = await capture(
			['target', 'trust', 'team', '--fingerprint', ED25519_FP],
			{ HOME: h },
			async () => SCAN,
		);
		expect(r.code).toBe(0);
		expect(r.stdout).toStartWith('replaced the host key of 203.0.113.10:2222 as team');
		expect(await readFile(file, 'utf8')).toBe(
			`prod ssh-ed25519 ${ROTATED}\n@cert-authority *.example ssh-ed25519 ${ROTATED} ca\nteam ssh-ed25519 ${ED25519}\n`,
		);
		expect(await trustedKeys(file, 'prod')).toEqual([
			{ type: 'ssh-ed25519', key: ROTATED, fingerprint: fingerprint(ROTATED) },
		]);
		expect(await trustedKeys(file, 'team')).toEqual([
			{ type: 'ssh-ed25519', key: ED25519, fingerprint: ED25519_FP },
		]);
	});

	test("rotating the alias's key leaves it one line, and the names it shared an entry with their key", async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
		const file = join(dir, 'known_hosts');
		await writeFile(file, `team,prod ssh-ed25519 ${ECDSA}\n`);
		const h = await home({ team: sshTarget(dir) });
		const first = await capture(
			['target', 'trust', 'team', '--fingerprint', ED25519_FP],
			{ HOME: h },
			async () => SCAN,
		);
		expect(first.code).toBe(0);
		const second = await capture(
			['target', 'trust', 'team', '--fingerprint', fingerprint(ROTATED)],
			{ HOME: h },
			async () => SCAN_ROTATED,
		);
		expect(second.code).toBe(0);
		expect(second.stdout).toBe(
			`replaced the host key of 203.0.113.10:2222 as team in ${file}: ssh-ed25519 ${fingerprint(ROTATED)}\n`,
		);
		expect(await readFile(file, 'utf8')).toBe(
			`prod ssh-ed25519 ${ECDSA}\nteam ssh-ed25519 ${ROTATED}\n`,
		);
	});

	describe('no line the alias still matches keeps an old key', () => {
		// The lines the real ssh-keygen finds for a name, without its comments.
		const found = async (name: string, file: string) => {
			const r = await exec(['ssh-keygen', '-F', name, '-f', file]);
			return r.stdout.split('\n').filter((l) => l !== '' && !l.startsWith('#'));
		};
		const trustNew = async (dir: string, findHost?: (a: string, f: string) => Promise<string>) => {
			const h = await home({ team: sshTarget(dir) });
			return capture(
				['target', 'trust', 'team', '--fingerprint', ED25519_FP],
				{ HOME: h },
				async () => SCAN,
				undefined,
				findHost,
			);
		};
		const NEW_LINE = `team ssh-ed25519 ${ED25519}`;
		const knownHosts = async (text: string) => {
			const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
			const file = join(dir, 'known_hosts');
			await writeFile(file, text);
			return { dir, file };
		};

		test('a wildcard the alias shared gets a negation: the name stays out, other names keep the key', async () => {
			const { dir, file } = await knownHosts(`team,* ssh-ed25519 ${ECDSA}\n`);
			// Before the rotation ssh-keygen finds this line for the alias.
			expect(await found('team', file)).toEqual([`team,* ssh-ed25519 ${ECDSA}`]);
			const r = await trustNew(dir);
			expect(r.stderr).toBe('');
			expect(r.code).toBe(0);
			expect(r.stdout).toStartWith('replaced the host key of 203.0.113.10:2222 as team');
			expect(await readFile(file, 'utf8')).toBe(`*,!team ssh-ed25519 ${ECDSA}\n${NEW_LINE}\n`);
			expect(await found('team', file)).toEqual([NEW_LINE]);
			expect(await found('other', file)).toEqual([`*,!team ssh-ed25519 ${ECDSA}`]);
			expect(await trustedKeys(file, 'team')).toEqual([
				{ type: 'ssh-ed25519', key: ED25519, fingerprint: ED25519_FP },
			]);
		});

		test('every pattern that matches the alias counts, without regard to case, and a second rotation adds nothing', async () => {
			const { dir, file } = await knownHosts(
				[
					`T?AM ssh-ed25519 ${ECDSA}`,
					`te*,prod ssh-ed25519 ${ECDSA}`,
					`*,!prod ssh-ed25519 ${ECDSA}`,
					`TEAM,prod ssh-ed25519 ${ECDSA}`,
					// Out of the alias's reach already, or never in it: untouched.
					`*,!team ssh-ed25519 ${ECDSA}`,
					`tea,[team]:2222,team-2 ssh-ed25519 ${ECDSA}`,
					'',
				].join('\n'),
			);
			expect((await trustNew(dir)).code).toBe(0);
			const once = [
				`T?AM,!team ssh-ed25519 ${ECDSA}`,
				`te*,prod,!team ssh-ed25519 ${ECDSA}`,
				`*,!prod,!team ssh-ed25519 ${ECDSA}`,
				`prod ssh-ed25519 ${ECDSA}`,
				`*,!team ssh-ed25519 ${ECDSA}`,
				`tea,[team]:2222,team-2 ssh-ed25519 ${ECDSA}`,
				NEW_LINE,
				'',
			].join('\n');
			expect(await readFile(file, 'utf8')).toBe(once);
			expect(await found('team', file)).toEqual([NEW_LINE]);
			expect((await trustNew(dir)).code).toBe(0);
			expect(await readFile(file, 'utf8')).toBe(once);
		});

		test('a hashed entry of the alias goes; a hashed entry of another name stays', async () => {
			const { dir, file } = await knownHosts(
				`team ssh-ed25519 ${ROTATED}\nprod ssh-ed25519 ${ROTATED}\n`,
			);
			await execOk(['ssh-keygen', '-q', '-H', '-f', file]);
			const hashed = (await readFile(file, 'utf8')).split('\n');
			expect(hashed[0]).toStartWith('|1|');
			expect(await found('team', file)).toEqual([hashed[0] as string]);
			const before = await trustedKeys(file, 'team');
			expect(before.map((k) => k.key)).toEqual([ROTATED]);
			const r = await trustNew(dir);
			expect(r.code).toBe(0);
			expect(r.stdout).toStartWith('replaced the host key');
			expect(await readFile(file, 'utf8')).toBe(`${hashed[1]}\n${NEW_LINE}\n`);
			expect(await found('team', file)).toEqual([NEW_LINE]);
			expect(await found('prod', file)).toEqual([hashed[1] as string]);
		});

		test('a hash in a list does what OpenSSH does with it, and gives no other name new trust', async () => {
			const seed = await knownHosts(`team ssh-ed25519 ${ECDSA}\n`);
			await execOk(['ssh-keygen', '-q', '-H', '-f', seed.file]);
			const hash = (await readFile(seed.file, 'utf8')).split(' ')[0] as string;
			// First in the field, OpenSSH compares the whole field with one hash,
			// so the line matches nobody. Taking the hash out would hand the key
			// to prod, which does not have it today. The line stays.
			const first = await knownHosts(`${hash},prod ssh-ed25519 ${ECDSA}\n`);
			expect(await found('team', first.file)).toEqual([]);
			expect(await found('prod', first.file)).toEqual([]);
			const firstRun = await trustNew(first.dir);
			expect(firstRun.code).toBe(0);
			expect(firstRun.stdout).toStartWith('trusted ');
			expect(await readFile(first.file, 'utf8')).toBe(
				`${hash},prod ssh-ed25519 ${ECDSA}\n${NEW_LINE}\n`,
			);
			expect(await found('prod', first.file)).toEqual([]);
			// Later in the field it is a literal name that no host has. Moved to
			// the front it would count as a hash again, so it leaves with the
			// alias.
			const later = await knownHosts(
				`team,${hash} ssh-ed25519 ${ECDSA}\nteam,${hash},prod ssh-ed25519 ${ECDSA}\n`,
			);
			expect((await trustNew(later.dir)).code).toBe(0);
			expect(await readFile(later.file, 'utf8')).toBe(`prod ssh-ed25519 ${ECDSA}\n${NEW_LINE}\n`);
		});

		test('a @cert-authority line the alias matches loses the alias too', async () => {
			const { dir, file } = await knownHosts(
				`@cert-authority * ssh-ed25519 ${ECDSA} ca\n@cert-authority team,prod ssh-ed25519 ${ECDSA}\n`,
			);
			expect((await trustNew(dir)).code).toBe(0);
			expect(await readFile(file, 'utf8')).toBe(
				`@cert-authority *,!team ssh-ed25519 ${ECDSA} ca\n@cert-authority prod ssh-ed25519 ${ECDSA}\n${NEW_LINE}\n`,
			);
			expect(await found('team', file)).toEqual([NEW_LINE]);
		});

		test('a @revoked line stays as it is: a revocation takes trust away, and never counts as trust', async () => {
			const lines = [
				`@revoked team,prod ssh-ed25519 ${ECDSA}`,
				`@revoked * ssh-ed25519 ${ROTATED}`,
				'',
			].join('\n');
			const { dir, file } = await knownHosts(lines);
			expect(await trustedKeys(file, 'team')).toEqual([]);
			const r = await trustNew(dir);
			expect(r.stderr).toBe('');
			expect(r.code).toBe(0);
			// Nothing was trusted before, so nothing was replaced.
			expect(r.stdout).toStartWith('trusted ');
			expect(await readFile(file, 'utf8')).toBe(`${lines}${NEW_LINE}\n`);
			expect(await trustedKeys(file, 'team')).toEqual([
				{ type: 'ssh-ed25519', key: ED25519, fingerprint: ED25519_FP },
			]);
		});

		test('a key the file revokes for the alias is refused, and the file stays as it was', async () => {
			const text = `team ssh-ed25519 ${ECDSA}\n@revoked t* ssh-ed25519 ${ED25519}\n`;
			const { dir, file } = await knownHosts(text);
			const r = await trustNew(dir);
			expect(r.code).toBe(1);
			expect(r.stderr).toContain(`${file} revokes the key ${ED25519_FP} for team`);
			expect(await readFile(file, 'utf8')).toBe(text);
			expect((await readdir(dir)).sort()).toEqual(['known_hosts']);
		});

		test('a line with a marker OpenSSH does not know, and a comment, stay and do not count', async () => {
			const text = `@bogus team ssh-ed25519 ${ECDSA}\n  # team ssh-ed25519 ${ECDSA}\n`;
			const { dir, file } = await knownHosts(text);
			expect(await found('team', file)).toEqual([]);
			expect(await trustedKeys(file, 'team')).toEqual([]);
			const r = await trustNew(dir);
			expect(r.code).toBe(0);
			expect(r.stdout).toStartWith('trusted ');
			expect(await readFile(file, 'utf8')).toBe(`${text}${NEW_LINE}\n`);
		});

		test('fails and changes nothing when ssh-keygen still finds another key for the alias', async () => {
			// Stands for any line koi's reading and OpenSSH's disagree on.
			const text = `team,* ssh-ed25519 ${ECDSA}\n`;
			const { dir, file } = await knownHosts(text);
			const seen: string[] = [];
			const r = await trustNew(dir, async (alias, written) => {
				seen.push(alias, await readFile(written, 'utf8'));
				return `# Host team found: line 1 \nsomething ssh-ed25519 ${ECDSA}\n# Host team found: line 2 \n${NEW_LINE}\n`;
			});
			expect(r.code).toBe(1);
			expect(r.stderr).toContain(
				`after the rewrite ${file} would still trust ${fingerprint(ECDSA)} for team`,
			);
			// It looked at the new text, and that text never reached the file.
			expect(seen).toEqual(['team', `*,!team ssh-ed25519 ${ECDSA}\n${NEW_LINE}\n`]);
			expect(await readFile(file, 'utf8')).toBe(text);
			expect((await readdir(dir)).sort()).toEqual(['known_hosts']);
		});

		test('fails and changes nothing when ssh-keygen does not find the new key, or cannot run', async () => {
			const text = `team ssh-ed25519 ${ECDSA}\n`;
			const { dir, file } = await knownHosts(text);
			const none = await trustNew(dir, async () => '');
			expect(none.code).toBe(1);
			expect(none.stderr).toContain(`ssh-keygen does not find the key koi wrote for team`);
			expect(await readFile(file, 'utf8')).toBe(text);
			const broken = await trustNew(dir, async () => {
				throw new Error('cannot run ssh-keygen');
			});
			expect(broken.code).toBe(1);
			expect(broken.stderr).toContain('cannot run ssh-keygen');
			expect(await readFile(file, 'utf8')).toBe(text);
			expect((await readdir(dir)).sort()).toEqual(['known_hosts']);
		});
	});

	test('two trusts that share a known_hosts file take its lock in turn, and both keys are kept', async () => {
		// Two targets, one file. Each trust reads the file and writes it
		// back whole; without the lock the last rename would erase the
		// other's key. Several rounds, since the race is decided by timing.
		for (let round = 0; round < 5; round++) {
			const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
			const file = join(dir, 'known_hosts');
			const h = await home({
				team: sshTarget(dir),
				prod: sshTarget(dir, { host: '203.0.113.11', hostKeyAlias: 'prod' }),
			});
			const slow = (ms: number) => Bun.sleep(ms);
			const results = await Promise.all([
				capture(
					['target', 'trust', 'team', '--fingerprint', ED25519_FP],
					{ HOME: h },
					async () => SCAN,
					slow,
				),
				capture(
					['target', 'trust', 'prod', '--fingerprint', fingerprint(ROTATED)],
					{ HOME: h },
					async () => SCAN_ROTATED,
					slow,
				),
			]);
			expect(results.map((r) => r.code)).toEqual([0, 0]);
			const lines = (await readFile(file, 'utf8')).split('\n').filter((l) => l !== '');
			expect(lines.sort()).toEqual([`prod ssh-ed25519 ${ROTATED}`, `team ssh-ed25519 ${ED25519}`]);
			// No lock and nothing half written is left behind.
			expect(await readdir(dir)).toEqual(['known_hosts']);
		}
	});

	test('a host that offers no key, a target without SSH, and a missing target are errors', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
		const h = await home({ team: sshTarget(dir), aws: AWS });
		const none = await capture(
			['target', 'trust', 'team', '--fingerprint', ED25519_FP],
			{ HOME: h },
			async () => '# nothing\n',
		);
		expect(none.stderr).toContain('ssh-keyscan got no host key from 203.0.113.10:2222');
		const aws = await capture(
			['target', 'trust', 'aws', '--fingerprint', ED25519_FP],
			{ HOME: h },
			async () => SCAN,
		);
		expect(aws.stderr).toContain(
			'uses the aws-ssm transport; only an ssh target has a host key to trust',
		);
		const missing = await capture(
			['target', 'trust', 'nope', '--fingerprint', ED25519_FP],
			{ HOME: h },
			async () => SCAN,
		);
		expect(missing.stderr).toContain('has no target "nope"; it has team, aws');
		const noFile = await capture(
			['target', 'trust', 'team', '--fingerprint', ED25519_FP],
			{ HOME: '/nonexistent' },
			async () => SCAN,
		);
		expect(noFile.stderr).toContain('no config file at /nonexistent/.config/koi/config.yaml');
	});

	test('--json says what was written', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
		const h = await home({ team: sshTarget(dir) });
		const r = await capture(
			['target', 'trust', 'team', '--fingerprint', ED25519_FP, '--json'],
			{ HOME: h },
			async () => SCAN,
		);
		expect(JSON.parse(r.stdout)).toEqual({
			file: join(dir, 'known_hosts'),
			target: 'team',
			alias: 'team',
			host: '203.0.113.10',
			port: 2222,
			type: 'ssh-ed25519',
			fingerprint: ED25519_FP,
			replaced: false,
		});
	});
});

describe('a known_hosts file with a NUL byte', () => {
	test('stops trust and show, and leaves the file as it was', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-nul-'));
		const file = join(dir, 'known_hosts');
		const text = '@revoked *\0ssh-ed25519-cert-v01@openssh.com AAAA\n';
		await writeFile(file, text);
		await expect(knownHostsLines(file)).rejects.toThrow(/has a NUL byte/);
		expect(await readFile(file, 'utf8')).toBe(text);
	});
});

describe('koi target show', () => {
	test("prints an SSH target's endpoint and whether a host key is trusted", async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
		const h = await home({ team: sshTarget(dir) });
		const before = await capture(['target', 'show', 'team'], { HOME: h });
		expect(before.code).toBe(0);
		expect(before.stdout).toStartWith(
			`target team in ${join(h, '.config', 'koi', 'config.yaml')}:\n`,
		);
		expect(before.stdout).toContain('    host: 203.0.113.10\n');
		expect(before.stdout).toContain('    port: 2222\n');
		expect(before.stdout).toContain('    identityFile: /home/operator/.ssh/koi_team_ed25519\n');
		expect(before.stdout).toContain(
			`  host key: none trusted for team in ${join(dir, 'known_hosts')}; run koi target trust team --fingerprint SHA256:...`,
		);
		await writeFile(join(dir, 'known_hosts'), `team ssh-ed25519 ${ED25519}\n`);
		const after = await capture(['target', 'show', 'team'], { HOME: h });
		expect(after.stdout).toContain(
			`  host key: ${ED25519_FP} (ssh-ed25519) as team in ${join(dir, 'known_hosts')}\n`,
		);
		const json = await capture(['target', 'show', 'team', '--json'], { HOME: h });
		const parsed = JSON.parse(json.stdout) as {
			target: string;
			hostKeys: unknown;
			settings: unknown;
		};
		expect(parsed.target).toBe('team');
		expect(parsed.hostKeys).toEqual([
			{ type: 'ssh-ed25519', key: ED25519, fingerprint: ED25519_FP },
		]);
	});

	test('prints an AWS target without a host key line', async () => {
		const h = await home({ aws: AWS });
		const r = await capture(['target', 'show', 'aws'], { HOME: h });
		expect(r.code).toBe(0);
		expect(r.stdout).toContain('    instanceId: i-0abc\n');
		expect(r.stdout).not.toContain('host key');
		const json = await capture(['target', 'show', 'aws', '--json'], { HOME: h });
		expect((JSON.parse(json.stdout) as { hostKeys: unknown }).hostKeys).toBeNull();
	});

	test('is reachable from the command line', async () => {
		const h = await home({ aws: AWS });
		const runtime: Runtime = {
			cwd: '/nonexistent',
			env: { HOME: h },
			box: async () => {
				throw new Error('target show opens no host');
			},
		};
		let stdout = '';
		const code = await run(
			['target', 'show', 'aws'],
			{
				stdout: (s) => {
					stdout += s;
				},
				stderr: () => {},
			},
			runtime,
		);
		expect(code).toBe(0);
		expect(stdout).toContain('domain: previews.example.net');
	});
});

describe('revocations and certificates, with keys from the real ssh-keygen', () => {
	const CERT = 'ssh-ed25519-cert-v01@openssh.com';
	// The host's key, another host's key, the CA that signs them, and the base64
	// of a certificate of each key. The fingerprints are OpenSSH's own.
	let hostKey = '';
	let otherKey = '';
	let caKey = '';
	let hostCert = '';
	let otherCert = '';
	let hostFp = '';
	let otherFp = '';

	const base64 = async (file: string) => (await readFile(file, 'utf8')).split(' ')[1] ?? '';

	beforeAll(async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-certs-'));
		const makeKey = async (name: string) => {
			const path = join(dir, name);
			await execOk(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', path]);
			return path;
		};
		const ca = await makeKey('ca');
		const certify = async (name: string) => {
			const path = await makeKey(name);
			await execOk(['ssh-keygen', '-q', '-s', ca, '-h', '-I', name, '-n', 'team', `${path}.pub`]);
			return {
				key: await base64(`${path}.pub`),
				cert: await base64(`${path}-cert.pub`),
				fp: (await execOk(['ssh-keygen', '-lf', `${path}.pub`])).stdout.split(' ')[1] ?? '',
			};
		};
		const host = await certify('host');
		const other = await certify('other');
		caKey = await base64(`${ca}.pub`);
		hostKey = host.key;
		hostCert = host.cert;
		hostFp = host.fp;
		otherKey = other.key;
		otherCert = other.cert;
		otherFp = other.fp;
	});

	const knownHosts = async (text: string) => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-kh-'));
		const file = join(dir, 'known_hosts');
		await writeFile(file, text);
		return { dir, file };
	};
	const trustHost = async (dir: string, listKeys?: (keys: string) => Promise<string>) =>
		capture(
			['target', 'trust', 'team', '--fingerprint', hostFp],
			{ HOME: await home({ team: sshTarget(dir) }) },
			async () => `[203.0.113.10]:22 ssh-ed25519 ${hostKey}\n`,
			undefined,
			undefined,
			listKeys,
		);
	const trustedFor = async (text: string, alias = 'team') =>
		(await trustedKeys((await knownHosts(text)).file, alias)).map((k) => k.fingerprint);

	test('a certificate hashes differently from its key, and OpenSSH gives both one fingerprint', async () => {
		expect(fingerprint(hostKey)).toBe(hostFp);
		expect(fingerprint(hostCert)).not.toBe(hostFp);
		const { file } = await knownHosts(
			`@revoked * ${CERT} ${hostCert}\nteam ssh-ed25519 ${hostKey}\n`,
		);
		const listed = await execOk(['ssh-keygen', '-F', 'team', '-l', '-f', file]);
		expect(listed.stdout).toContain(`team ED25519-CERT ${hostFp}\n`);
		expect(listed.stdout).toContain(`team ED25519 ${hostFp}\n`);
	});

	describe('koi target trust', () => {
		test.each([
			['a wildcard', '@revoked *'],
			['the alias among other names', '@revoked team,prod'],
		])(
			'refuses a key that a certificate entry revokes through %s, and changes nothing',
			async (_, prefix) => {
				const text = `# kept\nteam ssh-ed25519 ${otherKey}\n${prefix} ${CERT} ${hostCert} a comment\n`;
				const { dir, file } = await knownHosts(text);
				const r = await trustHost(dir);
				expect(r.code).toBe(1);
				expect(r.stdout).toBe('');
				expect(r.stderr).toContain(
					`${file} revokes the key ${hostFp} for team, on the line "${prefix}`,
				);
				expect(r.stderr).toContain('so ssh would refuse it. koi changed nothing');
				expect(await readFile(file, 'utf8')).toBe(text);
				expect(await readdir(dir)).toEqual(['known_hosts']);
			},
		);

		test('a hashed revocation counts, and so does a plain one', async () => {
			const seed = await knownHosts(`team ssh-ed25519 ${hostKey}\n`);
			await execOk(['ssh-keygen', '-q', '-H', '-f', seed.file]);
			const hash = (await readFile(seed.file, 'utf8')).split(' ')[0] as string;
			for (const line of [
				`@revoked ${hash} ${CERT} ${hostCert}`,
				`@revoked t* ssh-ed25519 ${hostKey}`,
			]) {
				const { dir, file } = await knownHosts(`${line}\n`);
				const r = await trustHost(dir);
				expect(r.code).toBe(1);
				expect(r.stderr).toContain(`revokes the key ${hostFp} for team`);
				expect(await readFile(file, 'utf8')).toBe(`${line}\n`);
			}
		});

		test('a tab after the marker revokes only on a line with no space, as OpenSSH reads it', async () => {
			const unread = `@revoked\t* ${CERT} ${hostCert}\n`;
			const skipped = await knownHosts(unread);
			const r = await trustHost(skipped.dir);
			expect(r.stderr).toBe('');
			expect(r.code).toBe(0);
			expect(await readFile(skipped.file, 'utf8')).toBe(`${unread}team ssh-ed25519 ${hostKey}\n`);
			const read = await knownHosts(`@revoked\t*\t${CERT}\t${hostCert}\n`);
			const refused = await trustHost(read.dir);
			expect(refused.code).toBe(1);
			expect(refused.stderr).toContain(`revokes the key ${hostFp} for team`);
		});

		test('what does not revoke the new key for the alias stays, and the key is trusted', async () => {
			const lines = [
				// Another key's certificate, and the CA of the host's certificate.
				`@revoked * ${CERT} ${otherCert}`,
				`@revoked * ssh-ed25519 ${caKey}`,
				// The host's certificate, for other names only.
				`@revoked prod ${CERT} ${hostCert}`,
				`@revoked *,!team ${CERT} ${hostCert}`,
				// OpenSSH reads no key here, so it revokes nothing.
				`@revoked * ecdsa-sha2-nistp256 ${hostKey}`,
				'',
			].join('\n');
			const { dir, file } = await knownHosts(lines);
			const r = await trustHost(dir);
			expect(r.stderr).toBe('');
			expect(r.code).toBe(0);
			expect(await readFile(file, 'utf8')).toBe(`${lines}team ssh-ed25519 ${hostKey}\n`);
			expect(await trustedKeys(file, 'team')).toEqual([
				{ type: 'ssh-ed25519', key: hostKey, fingerprint: hostFp },
			]);
		});

		test('fails and changes nothing when ssh-keygen -l cannot read the revocations', async () => {
			const text = `@revoked * ${CERT} ${hostCert}\n`;
			const { dir, file } = await knownHosts(text);
			const r = await trustHost(dir, async () => {
				throw new Error('ssh-keygen -l exited 1: out of memory');
			});
			expect(r.code).toBe(1);
			expect(r.stderr).toContain('ssh-keygen -l exited 1');
			expect(await readFile(file, 'utf8')).toBe(text);
			expect(await readdir(dir)).toEqual(['known_hosts']);
		});

		test('asks ssh-keygen -l about revocations only, once for all of them', async () => {
			const { dir } = await knownHosts(
				`@revoked * ${CERT} ${otherCert}\nteam ssh-ed25519 ${otherKey}\n`,
			);
			const asked: string[] = [];
			const r = await trustHost(dir, async (keys) => {
				asked.push(keys);
				return `256 ${otherFp} 0 (ED25519-CERT)\n`;
			});
			expect(r.code).toBe(0);
			expect(asked).toEqual([`${CERT} ${otherCert} 0\n`]);
		});
	});

	describe('koi target show', () => {
		test('a key the file revokes for the alias is not listed, by its own line or a certificate, before or after', async () => {
			const trusted = `team ssh-ed25519 ${hostKey}`;
			for (const revocation of [
				`@revoked * ssh-ed25519 ${hostKey}`,
				`@revoked * ${CERT} ${hostCert}`,
				`@revoked team,prod ${CERT} ${hostCert} a comment`,
			]) {
				expect(await trustedFor(`${trusted}\n${revocation}\n`)).toEqual([]);
				expect(await trustedFor(`${revocation}\n${trusted}\n`)).toEqual([]);
			}
		});

		test('a revocation takes only the key it names, and only for the names it applies to', async () => {
			const both = `team ssh-ed25519 ${hostKey}\nteam ssh-ed25519 ${otherKey}\n`;
			expect(await trustedFor(`${both}@revoked * ${CERT} ${hostCert}\n`)).toEqual([otherFp]);
			const text = `prod,team ssh-ed25519 ${hostKey}\n@revoked prod ${CERT} ${hostCert}\n`;
			expect(await trustedFor(text, 'team')).toEqual([hostFp]);
			expect(await trustedFor(text, 'prod')).toEqual([]);
			expect(
				await trustedFor(`team ssh-ed25519 ${hostKey}\n@revoked *,!team ${CERT} ${hostCert}\n`),
			).toEqual([hostFp]);
		});

		test('a tab after the marker revokes only on a line with no space, as OpenSSH reads it', async () => {
			const trusted = `team ssh-ed25519 ${hostKey}\n`;
			expect(await trustedFor(`${trusted}@revoked\t* ${CERT} ${hostCert}\n`)).toEqual([hostFp]);
			expect(await trustedFor(`${trusted}@revoked\t * ${CERT} ${hostCert}\n`)).toEqual([hostFp]);
			expect(await trustedFor(`${trusted}@revoked\t*\t${CERT}\t${hostCert}\n`)).toEqual([]);
			expect(await trustedFor(`${trusted}@revoked *\t${CERT}\t${hostCert}\n`)).toEqual([]);
			expect(await trustedFor(`@cert-authority\tteam ssh-ed25519 ${caKey}\n`)).toEqual([]);
		});

		test('a revoked certificate authority is not listed, and the CA of a key does not revoke the key', async () => {
			const ca = `@cert-authority team ssh-ed25519 ${caKey}`;
			expect(await trustedFor(`${ca}\n`)).toHaveLength(1);
			expect(await trustedFor(`${ca}\n@revoked * ssh-ed25519 ${caKey}\n`)).toEqual([]);
			expect(
				await trustedFor(`team ssh-ed25519 ${hostKey}\n@revoked * ssh-ed25519 ${caKey}\n`),
			).toEqual([hostFp]);
		});

		test('a certificate on a line without a marker trusts nothing', async () => {
			expect(await trustedFor(`team ${CERT} ${hostCert}\n`)).toEqual([]);
			expect(await trustedFor(`team ${CERT} ${hostCert}\nteam ssh-ed25519 ${hostKey}\n`)).toEqual([
				hostFp,
			]);
		});

		test('a line OpenSSH cannot parse neither trusts nor revokes', async () => {
			const garbage = 'AAAAB3NzaC1yc2E=';
			// With no key it can parse, ssh-keygen -l exits 255.
			expect(await trustedFor(`team ssh-ed25519 ${garbage}\n`)).toEqual([]);
			expect(await trustedFor(`team ecdsa-sha2-nistp256 ${hostKey}\n`)).toEqual([]);
			expect(
				await trustedFor(
					`team ssh-ed25519 ${garbage}\nteam ssh-ed25519 ${hostKey}\n@revoked * ssh-ed25519 ${garbage}\n@revoked * ecdsa-sha2-nistp256 ${hostKey}\n`,
				),
			).toEqual([hostFp]);
		});

		test('says none is trusted, as text and as JSON, and points to trust', async () => {
			const { dir } = await knownHosts(
				`team ssh-ed25519 ${hostKey}\n@revoked * ${CERT} ${hostCert}\n`,
			);
			const h = await home({ team: sshTarget(dir) });
			const text = await capture(['target', 'show', 'team'], { HOME: h });
			expect(text.code).toBe(0);
			expect(text.stdout).toContain('  host key: none trusted for team in ');
			const json = await capture(['target', 'show', 'team', '--json'], { HOME: h });
			expect((JSON.parse(json.stdout) as { hostKeys: unknown }).hostKeys).toEqual([]);
		});

		test('fails rather than list a key when ssh-keygen -l cannot read the file', async () => {
			const { dir } = await knownHosts(`team ssh-ed25519 ${hostKey}\n`);
			const r = await capture(
				['target', 'show', 'team'],
				{ HOME: await home({ team: sshTarget(dir) }) },
				undefined,
				undefined,
				undefined,
				async () => {
					throw new Error('cannot run ssh-keygen');
				},
			);
			expect(r.code).toBe(1);
			expect(r.stderr).toContain('cannot run ssh-keygen');
		});

		test('does not run ssh-keygen for a file with no line for the alias', async () => {
			const { file } = await knownHosts(`prod ssh-ed25519 ${hostKey}\n`);
			const unused = async () => {
				throw new Error('nothing to ask');
			};
			expect(await trustedKeys(file, 'team', unused)).toEqual([]);
			expect(await trustedKeys(`${file}.none`, 'team', unused)).toEqual([]);
		});
	});
});

// The directory the first trust test writes its known_hosts into.
const h0 = await mkdtemp(join(tmpdir(), 'koi-kh-'));
