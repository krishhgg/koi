import { afterAll, beforeAll, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { Subprocess } from 'bun';
import { toYaml } from '../src/config-command.ts';

// `koi up --local` from end to end, opt in with KOI_DOCKER_TESTS=1 like the
// daemon's Docker tests: the CLI from source in a checkout of examples/hello,
// koid from source as this user, the Docker networks and BuildKit builder
// provisioning makes, and Caddy with its internal CA, so that the preview
// answers at https://<label>.koi.test/ with a certificate the CA signed.
// Then koi list and koi down, through --local and through a configured
// local target.
//
// Caddy runs in a container on the host's network, the only way a test
// without root can bind 443 there; koid and the previews are on the host's
// side of it as on a real host. It runs as this user, so that its admin API,
// a unix socket of mode 0660 as on a host outside AWS, is one koid may open,
// as koid opens it through the caddy group there. koid's startup check wants
// the bridges provisioning names (koi-previews0, koi-build0), so the test
// needs a machine where they are free, and port 443 with them. The firewall
// rules, the slice and the egress proxy need root and are not set up: the
// preview has no way out, which hello does not need.
const enabled = process.env.KOI_DOCKER_TESTS === '1';
const run = randomUUID().replace(/-/g, '').slice(0, 10);
const network = `koi-it-local-${run}`;
const buildNetwork = `koi-it-local-build-${run}`;
const builder = `koi-it-local-${run}`;
const caddy = `koi-it-caddy-${run}`;
const CADDY_IMAGE = 'caddy:2.10.2';
const DOMAIN = 'koi.test';
const repo = resolve(import.meta.dir, '../../..');

let dir = '';
let socket = '';
let adminSocket = '';
let koid: Subprocess<'ignore', 'pipe', 'pipe'> | undefined;
let koidLog = '';

interface Ran {
	code: number;
	stdout: string;
	stderr: string;
}

async function sh(
	cmd: string[],
	o: { cwd?: string; env?: Record<string, string>; timeoutMs?: number } = {},
): Promise<Ran> {
	const proc = Bun.spawn(cmd, {
		...(o.cwd === undefined ? {} : { cwd: o.cwd }),
		env: o.env ?? (process.env as Record<string, string>),
		stdout: 'pipe',
		stderr: 'pipe',
	});
	const timer = setTimeout(() => proc.kill(), o.timeoutMs ?? 180_000);
	const [stdout, stderr] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
	]);
	const code = await proc.exited;
	clearTimeout(timer);
	return { code, stdout, stderr };
}

async function must(cmd: string[], o: Parameters<typeof sh>[1] = {}): Promise<string> {
	const r = await sh(cmd, o);
	if (r.code !== 0) throw new Error(`${cmd.join(' ')} exited ${r.code}: ${r.stderr || r.stdout}`);
	return r.stdout;
}

function listening(port: number): Promise<boolean> {
	return new Promise((done) => {
		const c = connect({ host: '127.0.0.1', port });
		c.once('connect', () => {
			c.destroy();
			done(true);
		});
		c.once('error', () => done(false));
	});
}

function connectable(path: string): Promise<boolean> {
	return new Promise((done) => {
		const c = connect({ path });
		c.once('connect', () => {
			c.destroy();
			done(true);
		});
		c.once('error', () => done(false));
	});
}

async function freePort(): Promise<number> {
	return new Promise((done, fail) => {
		const srv = createServer();
		srv.on('error', fail);
		srv.listen(0, '127.0.0.1', () => {
			const address = srv.address();
			srv.close(() => done(typeof address === 'object' && address !== null ? address.port : 0));
		});
	});
}

async function until(what: string, check: () => Promise<boolean>, ms = 120_000): Promise<void> {
	const end = Date.now() + ms;
	while (Date.now() < end) {
		if (await check()) return;
		await Bun.sleep(250);
	}
	throw new Error(`${what} did not happen within ${ms / 1000}s\nkoid:\n${koidLog.slice(-4000)}`);
}

// The CLI from source, in `cwd`, with a home of its own and `env` over it.
function koi(args: string[], cwd: string, env: Record<string, string> = {}) {
	return sh(['bun', join(repo, 'packages/cli/src/main.ts'), ...args], {
		cwd,
		env: { PATH: process.env.PATH ?? '', HOME: join(dir, 'home'), ...env },
		timeoutMs: 600_000,
	});
}

beforeAll(async () => {
	if (!enabled) return;
	for (const bridge of ['koi-previews0', 'koi-build0']) {
		const r = await sh(['ip', 'link', 'show', bridge]);
		if (r.code === 0) {
			throw new Error(
				`the bridge ${bridge} exists, as on a koi host; this test makes its own and needs a machine without one`,
			);
		}
	}
	if (await listening(443)) throw new Error('port 443 is taken; Caddy needs it here');
	dir = await mkdtemp(join(tmpdir(), 'koi-local-it-'));
	await mkdir(join(dir, 'home'));
	await mkdir(join(dir, 'run'), { mode: 0o750 });
	socket = join(dir, 'run', 'control.sock');
	// As caddy.service's RuntimeDirectory, /run/caddy, and Caddy's own data.
	await mkdir(join(dir, 'caddy'), { mode: 0o750 });
	await mkdir(join(dir, 'caddy-data'));
	await mkdir(join(dir, 'caddy-config'));
	adminSocket = join(dir, 'caddy', 'admin.sock');

	const confined = ['-o', 'com.docker.network.bridge.enable_icc=false'];
	await must([
		'docker',
		'network',
		'create',
		'--internal',
		...confined,
		'-o',
		'com.docker.network.bridge.name=koi-previews0',
		network,
	]);
	await must([
		'docker',
		'network',
		'create',
		...confined,
		'-o',
		'com.docker.network.bridge.name=koi-build0',
		buildNetwork,
	]);
	// As host/cloud-init.sh makes koi-builder.
	await must([
		'docker',
		'buildx',
		'create',
		'--name',
		builder,
		'--driver',
		'docker-container',
		'--driver-opt',
		`network=${buildNetwork}`,
		'--driver-opt',
		'memory=8g',
		'--driver-opt',
		'cpu-quota=300000',
		'--bootstrap',
	]);

	// Caddy as provisioning leaves it before koid starts: its admin API on a
	// unix socket and nothing served (cloud-init.sh, outside AWS).
	await writeFile(
		join(dir, 'Caddyfile.first'),
		`{\n\tauto_https disable_redirects\n\tadmin unix/${adminSocket}|0660\n}\n`,
	);
	await must([
		'docker',
		'run',
		'-d',
		'--name',
		caddy,
		'--network',
		'host',
		'--user',
		`${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`,
		'-v',
		`${join(dir, 'caddy')}:${join(dir, 'caddy')}`,
		'-v',
		`${join(dir, 'caddy-data')}:/data`,
		'-v',
		`${join(dir, 'caddy-config')}:/config`,
		'-v',
		`${join(dir, 'Caddyfile.first')}:/etc/caddy/Caddyfile:ro`,
		CADDY_IMAGE,
		'caddy',
		'run',
		'--config',
		'/etc/caddy/Caddyfile',
		'--adapter',
		'caddyfile',
	]);
	await until('Caddy listening on its admin socket', () => connectable(adminSocket));

	const httpPort = await freePort();
	const logPort = await freePort();
	koid = Bun.spawn(['bun', join(repo, 'packages/daemon/src/main.ts')], {
		cwd: dir,
		env: {
			PATH: process.env.PATH ?? '',
			HOME: process.env.HOME ?? '',
			KOI_DOMAIN: DOMAIN,
			KOI_TLS: 'internal',
			KOI_UPLOADS: 'spool',
			KOI_SPOOL_DIR: join(dir, 'spool'),
			KOI_LIVE: 'file',
			KOI_STATE_DIR: join(dir, 'state'),
			KOI_RECIPES_DIR: join(repo, 'recipes'),
			KOI_CADDYFILE: join(dir, 'Caddyfile'),
			KOI_CADDY_ADMIN: `unix/${adminSocket}`,
			KOI_PREVIEW_NETWORK: network,
			KOI_BUILD_NETWORK: buildNetwork,
			KOI_BUILDER: builder,
			KOI_SLICE: '',
			KOI_EGRESS_CONTROL: join(dir, 'egress.sock'),
			KOI_VERIFY_HELPER: join(dir, 'no-helper'),
			KOID_PORT: String(httpPort),
			KOID_LOG_PORT: String(logPort),
			KOID_CONTROL_SOCKET: socket,
		},
		stdin: 'ignore',
		stdout: 'pipe',
		stderr: 'pipe',
	});
	for (const stream of [koid.stdout, koid.stderr]) {
		void (async () => {
			for await (const chunk of stream) koidLog += new TextDecoder().decode(chunk);
		})();
	}
	await until('koid listening on its control socket', async () => {
		if (koid?.exitCode !== null) throw new Error(`koid exited ${koid?.exitCode}:\n${koidLog}`);
		return koidLog.includes('koid listening');
	});
}, 600_000);

afterAll(async () => {
	if (!enabled) return;
	koid?.kill('SIGTERM');
	await koid?.exited;
	// Whatever koi down did not remove: containers on the preview network.
	const left = (await sh(['docker', 'ps', '-aq', '--filter', `network=${network}`])).stdout
		.split('\n')
		.filter((id) => id !== '');
	if (left.length > 0) await sh(['docker', 'rm', '-f', ...left]);
	await sh(['docker', 'rm', '-f', caddy]);
	await sh(['docker', 'buildx', 'rm', '--force', builder]);
	await sh(['docker', 'network', 'rm', network, buildNetwork]);
	if (dir !== '') await rm(dir, { recursive: true, force: true });
}, 300_000);

test.skipIf(!enabled)(
	'koi up --local builds examples/hello and serves it over https with the internal CA',
	async () => {
		// A checkout of examples/hello with an origin koi never contacts.
		const checkout = join(dir, 'hello');
		await cp(join(repo, 'examples', 'hello'), checkout, { recursive: true });
		const git = (...args: string[]) =>
			must([
				'git',
				'-C',
				checkout,
				'-c',
				'user.name=koi',
				'-c',
				'user.email=koi@example.com',
				...args,
			]);
		await git('init', '-q', '-b', 'main');
		await git('add', '.');
		await git('commit', '-q', '-m', 'hello');
		await git('remote', 'add', 'origin', 'https://github.com/acme/hello.git');
		await git('update-ref', 'refs/remotes/origin/main', 'HEAD');

		const env = { KOID_CONTROL_SOCKET: socket };
		const up = await koi(['up', '--local', '--json'], checkout, env);
		expect({ code: up.code, stderr: up.code === 0 ? '' : up.stderr }).toEqual({
			code: 0,
			stderr: '',
		});
		expect(up.stderr).toContain(
			`target local (--local, built in): local, koid at ${socket}, previews under koi.test`,
		);
		const result = JSON.parse(up.stdout) as { status: string; label: string; url: string };
		expect(result.status).toBe('running');
		const host = `${result.label}.${DOMAIN}`;
		expect(result.url).toBe(`https://${host}`);

		// The preview over https, with the name resolved to this machine as
		// an /etc/hosts line would, and Caddy's root as the only trust.
		const root = join(dir, 'root.crt');
		await writeFile(
			root,
			await must(['docker', 'exec', caddy, 'cat', '/data/caddy/pki/authorities/local/root.crt']),
		);
		let page: Ran = { code: -1, stdout: '', stderr: '' };
		await until('the preview answering over https', async () => {
			page = await sh([
				'curl',
				'-sS',
				'--max-time',
				'10',
				'--resolve',
				`${host}:443:127.0.0.1`,
				'--cacert',
				root,
				`https://${host}/`,
			]);
			return page.code === 0;
		});
		expect(page.stdout).toContain('<h1>hello from koi</h1>');
		// The certificate is the internal CA's wildcard for the domain.
		const cert = await sh([
			'curl',
			'-sS',
			'-o',
			'/dev/null',
			'-w',
			'%{ssl_verify_result}',
			'--resolve',
			`${host}:443:127.0.0.1`,
			'--cacert',
			root,
			`https://${host}/`,
		]);
		expect(cert.stdout).toBe('0');
		const caddyfile = await readFile(join(dir, 'Caddyfile'), 'utf8');
		expect(caddyfile).toContain(`*.${DOMAIN} {\n\ttls internal\n`);
		// koid loaded it through the socket, which stays mode 0660, and Caddy
		// listens on no admin port.
		expect(caddyfile).toContain(`\tadmin unix/${adminSocket}|0660\n`);
		expect((await stat(adminSocket)).mode & 0o777).toBe(0o660);
		expect(await listening(2019)).toBe(false);

		// The same koid through a target in the config file.
		await mkdir(join(dir, 'home', '.config', 'koi'), { recursive: true, mode: 0o700 });
		await writeFile(
			join(dir, 'home', '.config', 'koi', 'config.yaml'),
			toYaml({
				version: 1,
				targets: {
					dev: {
						domain: DOMAIN,
						transport: { kind: 'local', controlSocket: socket },
						power: { kind: 'always-on' },
					},
				},
			}),
			{ mode: 0o600 },
		);
		const listed = await koi(['list', '--target', 'dev', '--json'], checkout);
		expect(listed.code).toBe(0);
		const previews = JSON.parse(listed.stdout) as Array<{ label: string; status: string }>;
		expect(previews.map((p) => [p.label, p.status])).toEqual([[result.label, 'running']]);

		const down = await koi(['down', result.label, '--local'], checkout, env);
		expect({ code: down.code, stderr: down.code === 0 ? '' : down.stderr }).toEqual({
			code: 0,
			stderr: '',
		});
		const after = await koi(['list', '--local', '--json'], checkout, env);
		expect(JSON.parse(after.stdout)).toEqual([]);
	},
	900_000,
);
