import { afterAll, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The accounts section of host/ssh/install.sh, run as written, with stand-ins
// on PATH for the commands that need root. The stand-ins keep the account's
// shadow password field in a file and act on it as the real commands do:
// useradd leaves a lone `!`, usermod -L puts a `!` in front, usermod -p sets the
// field.
//
// Why the field matters: on a host with UsePAM no, sshd refuses an account
// whose field starts with `!` before it looks at any key, and takes one whose
// field is `*`. That was tried against the real sshd 9.6p1 with a getspnam shim,
// which is no part of this suite: it needs a C compiler.

const INSTALL = join(import.meta.dir, '..', '..', '..', 'host', 'ssh', 'install.sh');
const COMMANDS = ['getent', 'groupadd', 'gpasswd', 'id', 'install', 'useradd', 'usermod'];

const STAND_IN = `#!/bin/bash
name=\${0##*/}
printf '%s\\n' "$name $*" >> "$STATE/log"
case $name in
getent)
	if [ "$1" = shadow ]; then
		[ -f "$STATE/password" ] || exit 2
		printf '%s:%s:20000:0:99999:7:::\\n' "$2" "$(cat "$STATE/password")"
	fi
	;;
id)
	case $1 in
	-nG) echo 'koi-connect koi-control' ;;
	koi-connect) [ -f "$STATE/password" ] ;;
	*) exit 1 ;;
	esac
	;;
useradd) printf '!' > "$STATE/password" ;;
usermod)
	case $1 in
	-L) printf '!%s' "$(cat "$STATE/password")" > "$STATE/password" ;;
	-p)
		[ ! -f "$STATE/refuse" ] || exit 1
		printf '%s' "$2" > "$STATE/password"
		;;
	esac
	;;
esac
`;

// The lines from the accounts header up to the next section's.
async function accountsSection(): Promise<string> {
	const script = await readFile(INSTALL, 'utf8');
	const start = script.indexOf('# --- Accounts ');
	const end = script.indexOf('# --- Gateway ');
	expect(start).toBeGreaterThan(0);
	expect(end).toBeGreaterThan(start);
	return script.slice(start, end);
}

const roots: string[] = [];

// A scratch box: the stand-ins, and the account's field, or no account at all.
async function box(password: string | undefined) {
	const root = await mkdtemp(join(tmpdir(), 'koi-install-'));
	roots.push(root);
	const bin = join(root, 'bin');
	await mkdir(bin);
	for (const name of COMMANDS) await writeFile(join(bin, name), STAND_IN, { mode: 0o755 });
	if (password !== undefined) await writeFile(join(root, 'password'), password);
	const run = async () => {
		const section = await accountsSection();
		const script = `set -euo pipefail\nHOME_DIR=/var/lib/koi-connect\n${section}`;
		const proc = Bun.spawn(['bash', '-c', script], {
			env: { PATH: `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`, STATE: root },
			stdin: 'ignore',
			stdout: 'pipe',
			stderr: 'pipe',
		});
		const stderr = await new Response(proc.stderr).text();
		return { code: await proc.exited, stderr };
	};
	const log = async () => (await readFile(join(root, 'log'), 'utf8')).trimEnd().split('\n');
	const field = () => readFile(join(root, 'password'), 'utf8');
	return { root, run, log, field };
}

describe('host/ssh/install.sh and the password of koi-connect', () => {
	afterAll(async () => {
		for (const root of roots) await rm(root, { recursive: true, force: true });
	});

	test('nothing in the script locks the account', async () => {
		const script = await readFile(INSTALL, 'utf8');
		expect(script).not.toMatch(/^[^#\n]*\busermod\b[^\n]*\s-(L|-lock)\b/m);
		expect(script).not.toMatch(/^[^#\n]*\bpasswd\b[^\n]*\s-(l|-lock)\b/m);
	});

	test('a new account gets `*`, not the `!` useradd leaves', async () => {
		const b = await box(undefined);
		const r = await b.run();
		expect(r.stderr).toBe('');
		expect(r.code).toBe(0);
		expect(await b.field()).toBe('*');
		expect(await b.log()).toContain('usermod -p * koi-connect');
	});

	for (const locked of ['!', '!*', '!!', '!$6$salt$hash', '$6$salt$hash']) {
		test(`an account with the field ${locked} comes out with \`*\``, async () => {
			const b = await box(locked);
			const r = await b.run();
			expect(r.stderr).toBe('');
			expect(r.code).toBe(0);
			expect(await b.field()).toBe('*');
			expect(await b.log()).not.toContain('usermod -L koi-connect');
		});
	}

	test('an account that already has `*` is not written again, and a second run changes nothing', async () => {
		const b = await box('!');
		expect((await b.run()).code).toBe(0);
		const once = await b.log();
		expect(once.filter((l) => l.startsWith('usermod -p'))).toEqual(['usermod -p * koi-connect']);
		expect((await b.run()).code).toBe(0);
		expect(await b.field()).toBe('*');
		const twice = await b.log();
		expect(twice.filter((l) => l.startsWith('usermod -p'))).toEqual(['usermod -p * koi-connect']);
		expect(twice.length).toBeGreaterThan(once.length);
	});

	test('a usermod that fails stops the installer: it does not carry on with a locked account', async () => {
		const b = await box('!');
		await writeFile(join(b.root, 'refuse'), '');
		expect((await b.run()).code).not.toBe(0);
		expect(await b.field()).toBe('!');
	});
});
