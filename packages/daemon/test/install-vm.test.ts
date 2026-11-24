import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { exec } from '../src/exec.ts';

// host/install-vm.sh, sourced in bash as its own guard allows, with every
// path it writes moved under a directory of this test's and the commands
// that would change the machine replaced by functions that log their calls:
// systemctl, usermod, journalctl and the health check's curl. The bundle is
// one of this test's: a host/cloud-init.sh that notes the settings it was
// run with, and bundles whose installers note that they ran.
const script = resolve(import.meta.dir, '../../../host/install-vm.sh');

interface Box {
	dir: string;
	bundle: string;
	calls: string;
}

// A bundle as scripts/host-bundle.sh lays it out, with its SHA256SUMS.
async function box(): Promise<Box> {
	const dir = await mkdtemp(join(tmpdir(), 'koi-install-vm-'));
	const bundle = join(dir, 'bundle');
	const calls = join(dir, 'calls');
	for (const d of ['bundle', 'etc/koi/egress', 'bin', 'share', 'src']) {
		await mkdir(join(dir, d), { recursive: true });
	}
	await writeFile(calls, '');
	await writeFile(
		join(bundle, 'cloud-init.sh'),
		`env | grep '^KOI_' | sort > '${dir}/cloud-init.env'\necho "cloud-init" >> '${calls}'\n`,
	);
	await writeFile(join(bundle, 'koid'), '#!/bin/sh\necho koid\n');
	await writeFile(join(bundle, 'koi-ssh-gateway'), '#!/bin/sh\necho gateway\n');
	const installers: Record<string, string> = {
		recipes: '',
		egress: `printf 'KOI_EGRESS_HOST=172.18.0.1\\nKOI_EGRESS_PORT=3128\\n' > '${dir}/etc/koi/egress/env'\n`,
		verify: '',
		ssh: '',
	};
	for (const [name, extra] of Object.entries(installers)) {
		const src = join(dir, 'src', name);
		await mkdir(src);
		await writeFile(join(src, 'install.sh'), `echo "${name} install $*" >> '${calls}'\n${extra}`);
		const tar = await exec(['tar', '-czf', join(bundle, `${name}.tar.gz`), '-C', src, '.']);
		expect(tar.code).toBe(0);
	}
	const sums = await exec([
		'bash',
		'-c',
		'cd "$0" && sha256sum koid koi-ssh-gateway recipes.tar.gz egress.tar.gz ssh.tar.gz verify.tar.gz cloud-init.sh > SHA256SUMS',
		bundle,
	]);
	expect(sums.code).toBe(0);
	return { dir, bundle, calls };
}

// Sources the script, moves its paths into `b`, stubs the machine, and runs
// `body`. `stubs` replaces any of the stubs.
async function run(b: Box, body: string, stubs = '') {
	const file = join(b.dir, 'run.sh');
	await writeFile(
		file,
		[
			`source '${script}'`,
			`BUNDLE='${b.bundle}'`,
			`OS_RELEASE='${b.dir}/os-release'`,
			`BIN_DIR='${b.dir}/bin'`,
			`SHARE='${b.dir}/share'`,
			`KOI_ENV='${b.dir}/etc/koi/env'`,
			`EGRESS_ENV='${b.dir}/etc/koi/egress/env'`,
			`CADDY_DIR='${b.dir}/etc/koi/caddy'`,
			`CADDY_ENV='${b.dir}/etc/koi/caddy/env'`,
			`DNS_FILE='${b.dir}/etc/koi/caddy/dns.caddy'`,
			`STOCK_CADDYFILE='${b.dir}/etc/caddy/Caddyfile'`,
			`CADDY_UNIT='${b.dir}/etc/systemd/system/caddy.service'`,
			`calls='${b.calls}'`,
			`printf 'ID=ubuntu\\nVERSION_ID="24.04"\\n' > "$OS_RELEASE"`,
			'id() { case "$1" in -u) echo 0 ;; alice | bob) return 0 ;; *) return 1 ;; esac; }',
			'uname() { echo x86_64; }',
			// Owners are root's and caddy's on the host; here the test's own.
			// biome-ignore lint/suspicious/noTemplateCurlyInString: bash's syntax, not a template of this file
			'install() { local a=(); while [ $# -gt 0 ]; do case $1 in -o | -g) shift 2 ;; *) a+=("$1"); shift ;; esac; done; command install "${a[@]}"; }',
			'systemctl() { echo "systemctl $*" >> "$calls"; }',
			'usermod() { echo "usermod $*" >> "$calls"; }',
			'journalctl() { echo "journalctl $*" >> "$calls"; echo "koid: the box is not provisioned"; }',
			'curl() { echo "curl $*" >> "$calls"; }',
			'sleep() { :; }',
			// No caddy package; a test that wants one says so.
			'dpkg-query() { return 1; }',
			stubs,
			body,
		].join('\n'),
	);
	const r = await exec(['env', '-i', 'PATH=/usr/bin:/bin', 'bash', file], { timeoutMs: 30_000 });
	const lines = (await readFile(b.calls, 'utf8')).split('\n').filter((l) => l !== '');
	const read = (path: string) => readFile(join(b.dir, path), 'utf8').catch(() => undefined);
	return { code: r.code, stdout: r.stdout, stderr: r.stderr, calls: lines, read };
}

describe('host/install-vm.sh arguments', () => {
	const parse = async (args: string) => {
		const b = await box();
		return run(b, `parse_args ${args}\necho "$DOMAIN|$TLS|$LOCAL|$POOL|\${USERS[*]}"`);
	};

	test('takes a domain and a TLS mode, and --local defaults them for this machine', async () => {
		expect((await parse('--domain previews.example.com --tls acme-http')).stdout).toBe(
			'previews.example.com|acme-http|false||\n',
		);
		expect(
			(await parse('--domain p.example.com --tls acme-dns:cloudflare --user alice --user bob'))
				.stdout,
		).toBe('p.example.com|acme-dns:cloudflare|false||alice bob\n');
		expect((await parse('--local --user alice --verify-pool 10.99.0.0/20')).stdout).toBe(
			'koi.test|internal|true|10.99.0.0/20|alice\n',
		);
		expect((await parse('--local --domain dev.koi.test --tls acme-http')).stdout).toBe(
			'dev.koi.test|acme-http|true||\n',
		);
	});

	test('refuses what it cannot write into a unit, an environment file or a Caddyfile', async () => {
		for (const [args, why] of [
			['--tls internal', '--domain is required'],
			['--domain previews.example.com', '--tls is required'],
			["--domain 'x$(reboot).example.com' --tls internal", 'is not a bare domain'],
			['--domain Previews.example.com --tls internal', 'is not a bare domain'],
			['--domain com --tls internal', 'is not a bare domain'],
			['--domain p.example.com --tls route53', "--tls 'route53' is not internal"],
			['--domain p.example.com --tls acme-dns:', "--tls 'acme-dns:' is not internal"],
			["--domain p.example.com --tls 'acme-dns:a b'", 'is not internal, acme-http'],
			['--local --verify-pool 10.0.0.0/8', 'is not an IPv4 network between /16 and /28'],
			["--local --user 'root;id'", "--user 'root;id' is not an account name"],
			['--local --ssh', "unknown argument '--ssh'"],
		] as const) {
			const r = await parse(args);
			expect([args, r.code, r.stdout]).toEqual([args, 1, '']);
			expect(r.stderr).toContain(why);
		}
	});
});

describe('host/install-vm.sh checks', () => {
	test('runs only as root, on Ubuntu 24.04 on x86_64', async () => {
		const b = await box();
		expect((await run(b, 'check_platform && echo ok')).stdout).toBe('ok\n');
		for (const [stubs, why] of [
			['id() { echo 1000; }', 'run this as root'],
			[`printf 'ID=ubuntu\\nVERSION_ID="22.04"\\n' > "$OS_RELEASE"`, 'this host runs ubuntu 22.04'],
			[`printf 'ID=debian\\nVERSION_ID="12"\\n' > "$OS_RELEASE"`, 'this host runs debian 12'],
			['uname() { echo aarch64; }', 'this host is aarch64'],
		] as const) {
			const r = await run(b, `${stubs}\ncheck_platform && echo went on`);
			expect([stubs, r.code, r.stdout]).toEqual([stubs, 1, '']);
			expect(r.stderr).toContain(why);
		}
	});

	test('takes the bundle only whole, as host-bundle.sh built it', async () => {
		const b = await box();
		expect((await run(b, 'check_bundle && echo ok')).stdout).toBe('ok\n');
		await writeFile(join(b.bundle, 'koid'), '#!/bin/sh\necho something else\n');
		const changed = await run(b, 'check_bundle && echo went on');
		expect(changed.code).toBe(1);
		expect(changed.stderr).toContain('does not match its SHA256SUMS; copy it again');
		const none = await run(b, `rm '${b.bundle}/SHA256SUMS'\ncheck_bundle && echo went on`);
		expect(none.stderr).toContain(
			'has no SHA256SUMS; build the bundle with scripts/host-bundle.sh',
		);
	});

	test('takes no SHA256SUMS that lost the line of a file it reads, or has a line it cannot read', async () => {
		const b = await box();
		const sums = join(b.bundle, 'SHA256SUMS');
		const whole = await readFile(sums, 'utf8');
		const without = (name: string) =>
			whole
				.split('\n')
				.filter((line) => !line.endsWith(`  ${name}`))
				.join('\n');
		for (const name of [
			'cloud-init.sh',
			'koid',
			'recipes.tar.gz',
			'egress.tar.gz',
			'verify.tar.gz',
			'ssh.tar.gz',
			'koi-ssh-gateway',
		]) {
			await writeFile(sums, without(name));
			const r = await run(b, 'check_bundle && echo went on');
			expect([name, r.code, r.stdout]).toEqual([name, 1, '']);
			expect(r.stderr).toContain(`the SHA256SUMS in ${b.bundle} has no line for ${name};`);
		}
		// --local reads neither of the SSH gateway's files.
		await writeFile(sums, without('ssh.tar.gz').replace(/^.* {2}koi-ssh-gateway\n/m, ''));
		expect((await run(b, 'LOCAL=true\ncheck_bundle && echo ok')).stdout).toBe('ok\n');
		await writeFile(sums, `${whole}not a line of sha256sum\n`);
		const bad = await run(b, 'check_bundle && echo went on');
		expect(bad.code).toBe(1);
		expect(bad.stderr).toContain('does not match its SHA256SUMS; copy it again');
	});
});

describe('host/install-vm.sh, run whole', () => {
	test('a VM: cloud-init.sh without the AWS parts, the bundles in deploy-host.sh order, the spool and the gateway', async () => {
		const b = await box();
		const args = 'main --domain previews.example.com --tls acme-dns:cloudflare --user alice';
		// The first run stops for the provider's token before koid starts.
		const first = await run(b, args);
		expect(first.code).toBe(2);
		expect(first.stderr).toBe(
			[
				"koi: the DNS provider's API token is not set. Caddy refuses koid's config without",
				'  it, so koid was not started. Put the token in',
				`  ${b.dir}/etc/koi/caddy/env (KOI_DNS_API_TOKEN=...), check the provider line`,
				`  in ${b.dir}/etc/koi/caddy/dns.caddy, then run install-vm.sh again with the same arguments.`,
				'',
			].join('\n'),
		);
		expect(first.calls).toEqual([
			'cloud-init',
			'egress install ',
			'verify install ',
			`ssh install ${b.bundle}/koi-ssh-gateway`,
			'usermod -aG koi-control alice',
		]);
		expect(await first.read('etc/koi/caddy/env')).toEndWith('\nKOI_DNS_API_TOKEN=\n');
		const env = join(b.dir, 'etc/koi/caddy/env');
		await writeFile(env, `${await readFile(env, 'utf8')}KOI_DNS_API_TOKEN=cf-123\n`);
		await writeFile(b.calls, '');
		const r = await run(b, args);
		expect(r.stderr).toBe('');
		expect(r.code).toBe(0);
		expect(await r.read('cloud-init.env')).toBe(
			'KOI_DOMAIN=previews.example.com\nKOI_POWER=always-on\nKOI_TLS=acme-dns:cloudflare\n',
		);
		expect(r.calls).toEqual([
			'cloud-init',
			'egress install ',
			'verify install ',
			`ssh install ${b.bundle}/koi-ssh-gateway`,
			'usermod -aG koi-control alice',
			'systemctl daemon-reload',
			'systemctl enable koid.service',
			'systemctl restart koid.service',
			'curl -fsS http://127.0.0.1:7777/__koi/health',
		]);
		expect(await r.read('bin/koid')).toBe('#!/bin/sh\necho koid\n');
		expect(await r.read('share/recipes/install.sh')).toContain('recipes install');
		// koid takes uploads through its socket and the TLS mode's kind; the
		// provider stays Caddy's.
		expect(await r.read('etc/koi/env')).toBe(
			[
				'KOI_DOMAIN=previews.example.com',
				'KOI_UPLOADS=spool',
				'KOI_LIVE=file',
				'KOI_TLS=acme-dns',
				'KOI_EGRESS_PROXY=http://172.18.0.1:3128',
				'KOI_EGRESS_CA=/etc/koi/egress/ca.pem',
				'',
			].join('\n'),
		);
		expect(await r.read('etc/koi/caddy/dns.caddy')).toContain(
			'\ndns cloudflare {env.KOI_DNS_API_TOKEN}\n',
		);
		expect(await r.read('etc/koi/caddy/env')).toEndWith(
			'\nKOI_DNS_API_TOKEN=\nKOI_DNS_API_TOKEN=cf-123\n',
		);
		// root:caddy, root:caddy and root:root on the host: only root makes
		// entries there, Caddy reads the provider's line, and systemd the token.
		const mode = async (path: string) =>
			((await stat(join(b.dir, path))).mode & 0o7777).toString(8);
		expect(await mode('etc/koi/caddy')).toBe('750');
		expect(await mode('etc/koi/caddy/dns.caddy')).toBe('640');
		expect(await mode('etc/koi/caddy/env')).toBe('600');
		expect(readFileSync(script, 'utf8')).toContain(
			'install -d -o root -g caddy -m 0750 "$CADDY_DIR"',
		);
		expect(r.stdout).toContain('a DNS record *.previews.example.com pointing at');
		expect(r.stdout).not.toContain('token');
		expect(r.stdout).toContain('Open port 443 to whoever visits previews.');
		expect(r.stdout).toContain('Authorize each CLI');
	});

	test('stops for a token that is empty however it is written, and not for a provider line that names none', async () => {
		for (const [line, code] of [
			['KOI_DNS_API_TOKEN=""', 2],
			["KOI_DNS_API_TOKEN=''", 2],
			['  KOI_DNS_API_TOKEN=   ', 2],
			['KOI_DNS_API_TOKEN=x\nKOI_DNS_API_TOKEN=', 2],
			['KOI_DNS_API_TOKEN=\nKOI_DNS_API_TOKEN="x"', 0],
			["KOI_DNS_API_TOKEN='x'", 0],
		] as const) {
			const b = await box();
			await mkdir(join(b.dir, 'etc/koi/caddy'));
			await writeFile(join(b.dir, 'etc/koi/caddy/env'), `${line}\n`);
			const r = await run(b, 'main --domain previews.example.com --tls acme-dns:cloudflare');
			expect([line, r.code]).toEqual([line, code]);
			expect([line, r.calls.includes('systemctl restart koid.service')]).toEqual([
				line,
				code === 0,
			]);
		}
		const b = await box();
		await mkdir(join(b.dir, 'etc/koi/caddy'));
		await writeFile(join(b.dir, 'etc/koi/caddy/dns.caddy'), 'dns porkbun {\n\tapi_key x\n}\n');
		const r = await run(b, 'main --domain previews.example.com --tls acme-dns:porkbun');
		expect(r.code).toBe(0);
		expect(await r.read('etc/koi/caddy/env')).toEndWith('\nKOI_DNS_API_TOKEN=\n');
	});

	test("a run again keeps the operator's provider line and token", async () => {
		const b = await box();
		await mkdir(join(b.dir, 'etc/koi/caddy'));
		await writeFile(join(b.dir, 'etc/koi/caddy/dns.caddy'), 'dns porkbun {\n\tapi_key x\n}\n');
		await writeFile(join(b.dir, 'etc/koi/caddy/env'), 'KOI_DNS_API_TOKEN=secret\n');
		const r = await run(b, 'main --domain previews.example.com --tls acme-dns:porkbun');
		expect(r.code).toBe(0);
		expect(await r.read('etc/koi/caddy/dns.caddy')).toBe('dns porkbun {\n\tapi_key x\n}\n');
		expect(await r.read('etc/koi/caddy/env')).toBe('KOI_DNS_API_TOKEN=secret\n');
	});

	test('this machine with --local: no SSH gateway, the internal CA, and what to do once', async () => {
		const b = await box();
		const r = await run(b, 'main --local --user alice --verify-pool 10.99.0.0/20');
		expect(r.stderr).toBe('');
		expect(r.code).toBe(0);
		expect(await r.read('cloud-init.env')).toBe(
			'KOI_DOMAIN=koi.test\nKOI_POWER=always-on\nKOI_TLS=internal\nKOI_VERIFY_POOL=10.99.0.0/20\n',
		);
		expect(r.calls.filter((c) => c.startsWith('ssh '))).toEqual([]);
		expect(await r.read('share/ssh/install.sh')).toBeUndefined();
		expect(await r.read('etc/koi/env')).toContain('\nKOI_TLS=internal\n');
		expect(await r.read('etc/koi/caddy/dns.caddy')).toBeUndefined();
		expect(r.stdout).toContain('127.0.0.1 hello.koi.test');
		expect(r.stdout).toContain('sudo caddy trust');
		expect(r.stdout).toContain('alice: log out and in again (or run newgrp koi-control)');
		expect(r.stdout).toContain('koi up --local');
	});

	test('stops on an account the host does not have, before anything is changed', async () => {
		const b = await box();
		const r = await run(b, 'main --local --user mallory');
		expect(r.code).toBe(1);
		expect(r.stderr).toContain("there is no account 'mallory' on this host");
		expect(r.calls).toEqual([]);
	});

	test('leaves a Caddy that koi did not set up alone, before anything is changed', async () => {
		for (const [setup, why] of [
			[
				'mkdir -p "$(dirname "$STOCK_CADDYFILE")" && echo \':80\' > "$STOCK_CADDYFILE"',
				'/etc/caddy/Caddyfile is there',
			],
			[
				// biome-ignore lint/suspicious/noTemplateCurlyInString: bash's syntax, not a template of this file
				'dpkg-query() { [ "$*" = \'-W -f=${db:Status-Status} caddy\' ] && echo installed; }',
				'the caddy package is installed',
			],
			[
				'mkdir -p "$(dirname "$CADDY_UNIT")" && printf \'[Service]\\nExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile\\n\' > "$CADDY_UNIT"',
				'/etc/systemd/system/caddy.service runs another config',
			],
		] as const) {
			const b = await box();
			const r = await run(b, `${setup}\nmain --local`);
			expect([setup, r.code, r.calls]).toEqual([setup, 1, []]);
			expect(r.stderr).toContain('this machine has a Caddy that koi did not set up (');
			expect(r.stderr).toContain(`${why}). koi's setup replaces caddy.service`);
			expect(r.stderr).toContain('install koi in a VM instead');
		}
	});

	test("runs again on a koi host, whose Caddy is koi's", async () => {
		const b = await box();
		await mkdir(join(b.dir, 'etc/systemd/system'), { recursive: true });
		await writeFile(
			join(b.dir, 'etc/systemd/system/caddy.service'),
			'[Service]\nExecStart=/usr/local/bin/caddy run --config /var/lib/koi-caddy/Caddyfile --adapter caddyfile\n',
		);
		// A package removed with its files left is not a Caddy that runs.
		const r = await run(b, 'main --local', 'dpkg-query() { echo config-files; }');
		expect(r.stderr).toBe('');
		expect(r.code).toBe(0);
		expect(r.calls).toContain('systemctl restart koid.service');
	});

	test('a koid that never answers fails the install with its log', async () => {
		const b = await box();
		const r = await run(b, 'main --local', 'curl() { echo "curl $*" >> "$calls"; return 7; }');
		expect(r.code).toBe(1);
		expect(r.calls.filter((c) => c.startsWith('curl'))).toHaveLength(300);
		expect(r.calls).toContain('journalctl -u koid --no-pager -n 50');
		expect(r.stdout).toContain('koid: the box is not provisioned');
		expect(r.stderr).toContain('koid did not answer; its log is above');
	});
});

describe('scripts/host-bundle.sh', () => {
	const repo = resolve(import.meta.dir, '../../..');
	const bundle = readFileSync(join(repo, 'scripts/host-bundle.sh'), 'utf8');
	const deploy = readFileSync(join(repo, 'scripts/deploy-host.sh'), 'utf8');
	const installer = readFileSync(script, 'utf8');
	const built = new Set([...bundle.matchAll(/"\$out\/([\w.-]+)"/g)].map((m) => m[1] ?? ''));
	const summed = /sha256sum ([^>]+) > SHA256SUMS/.exec(bundle)?.[1]?.trim().split(/\s+/) ?? [];

	test('is the one build deploy-host.sh uploads for the AWS box', () => {
		expect(deploy).toContain('"$repo/scripts/host-bundle.sh" "$work"');
		expect(deploy).not.toContain('bun build');
		const uploaded = [...deploy.matchAll(/aws s3 cp [^\n]*"\$work\/([\w.-]+)"/g)].map(
			(m) => m[1] ?? '',
		);
		expect(uploaded.length).toBe(6);
		for (const name of uploaded) expect(built).toContain(name);
	});

	test('sums every file install-vm.sh reads from the bundle', () => {
		const read = new Set(
			[...installer.matchAll(/\$BUNDLE\/([\w.-]+)/g)]
				.map((m) => m[1] ?? '')
				.filter((name) => name !== 'SHA256SUMS'),
		);
		for (const name of ['recipes.tar.gz', 'egress.tar.gz', 'verify.tar.gz', 'ssh.tar.gz']) {
			// unpack takes the bundle's name, not a path.
			expect(installer).toContain(`unpack ${name} `);
			read.add(name);
		}
		expect([...read].sort()).toEqual(
			[
				'cloud-init.sh',
				'egress.tar.gz',
				'koi-ssh-gateway',
				'koid',
				'recipes.tar.gz',
				'ssh.tar.gz',
				'verify.tar.gz',
			].sort(),
		);
		for (const name of read) expect(summed).toContain(name);
		expect(summed).toContain('install-vm.sh');
	});
});
