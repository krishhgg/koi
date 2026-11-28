import { describe, expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LoginKeySchema, RecipeSchema } from '@koi/shared';
import { loadConfig } from '../src/config.ts';
import { cliDocker, runArgs } from '../src/docker.ts';
import {
	CA_BUNDLE_PATH,
	CA_CERT_PATH,
	egressDns,
	egressEnv,
	loadEgress,
	previewRoute,
} from '../src/egress-config.ts';
import type { ExecResult } from '../src/exec.ts';
import { request, setup } from './fakes.ts';

const loginRecipe = (over: Record<string, unknown> = {}) => ({
	kind: 'repo' as const,
	recipe: {
		port: 8080,
		healthPath: '/',
		env: {},
		ttlDays: 7,
		buildTimeoutMinutes: 45,
		healthTimeoutSeconds: 5,
		loginKeyEnv: 'APP_LOGIN_KEY',
		build: {
			kind: 'dockerfile' as const,
			from: 'source' as const,
			path: 'Dockerfile',
			context: '.',
		},
		...over,
	},
});

const EGRESS = {
	proxy: 'http://172.19.0.1:3128',
	caBundle: 'SYSTEM\nKOI-CA\n',
	caCert: 'KOI-CA\n',
};

describe('login keys', () => {
	test('a recipe with loginKeyEnv gets a random key, recorded and passed to the container', async () => {
		const t = await setup();
		await t.up(request({ recipe: loginRecipe() }));
		const record = await t.store.get('hello-pr-7');
		const key = record?.loginKey ?? '';
		expect(LoginKeySchema.safeParse(key).success).toBe(true);
		expect(t.docker.runs[0]?.env.APP_LOGIN_KEY).toBe(key);
		expect(record?.deployment?.env.APP_LOGIN_KEY).toBe(key);
	});

	test('the key stays the same across redeploys of the same preview', async () => {
		const t = await setup();
		await t.up(request({ recipe: loginRecipe() }));
		const first = (await t.store.get('hello-pr-7'))?.loginKey;
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', commit: 'b'.repeat(40), recipe: loginRecipe() }));
		expect((await t.store.get('hello-pr-7'))?.loginKey).toBe(first);
		expect(t.docker.runs[1]?.env.APP_LOGIN_KEY).toBe(first);
	});

	test('a preview that expired gets a new key', async () => {
		const t = await setup();
		await t.up(request({ recipe: loginRecipe() }));
		const first = (await t.store.get('hello-pr-7'))?.loginKey;
		t.advance(8 * 86_400_000);
		await t.deployer.expire();
		await t.up(request({ id: 'cccccccccccccccc3', recipe: loginRecipe() }));
		const second = (await t.store.get('hello-pr-7'))?.loginKey;
		expect(second).toBeDefined();
		expect(second).not.toBe(first);
	});

	test('a failed update without loginKeyEnv keeps the key the running deployment uses', async () => {
		const t = await setup();
		await t.up(request({ recipe: loginRecipe() }));
		const first = await t.store.get('hello-pr-7');
		const key = first?.loginKey ?? '';
		expect(LoginKeySchema.safeParse(key).success).toBe(true);
		const { loginKeyEnv: _, ...keyless } = loginRecipe().recipe;
		t.docker.buildError = 'the build broke';
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', recipe: { kind: 'repo', recipe: keyless } }));
		const failed = await t.store.get('hello-pr-7');
		expect(failed?.status).toBe('failed');
		// The old deployment still runs with the old key, and the record says so.
		expect(failed?.deployment?.container).toBe(first?.deployment?.container);
		expect(failed?.deployment?.env.APP_LOGIN_KEY).toBe(key);
		expect(failed?.loginKey).toBe(key);
		// Asking for a login key again gets the same one.
		t.docker.buildError = undefined;
		await t.up(request({ id: 'cccccccccccccccc3', recipe: loginRecipe() }));
		expect((await t.store.get('hello-pr-7'))?.loginKey).toBe(key);
		expect(t.docker.runs.at(-1)?.env.APP_LOGIN_KEY).toBe(key);
	});

	test('the key goes once a deployment without loginKeyEnv cuts over', async () => {
		const t = await setup();
		await t.up(request({ recipe: loginRecipe() }));
		const { loginKeyEnv: _, ...keyless } = loginRecipe().recipe;
		await t.up(request({ id: 'bbbbbbbbbbbbbbbb2', recipe: { kind: 'repo', recipe: keyless } }));
		const record = await t.store.get('hello-pr-7');
		expect(record?.status).toBe('running');
		expect(record?.loginKey).toBeUndefined();
		expect(record?.deployment?.env.APP_LOGIN_KEY).toBeUndefined();
	});

	test('no key without loginKeyEnv', async () => {
		const t = await setup();
		await t.up(request());
		expect((await t.store.get('hello-pr-7'))?.loginKey).toBeUndefined();
	});
});

describe('built-in recipe build context', () => {
	test('a recipe that brings its Dockerfile gets a copy of its directory as the "recipe" context', async () => {
		const builtin = RecipeSchema.parse({
			name: 'hello',
			port: 9000,
			build: { kind: 'dockerfile', from: 'recipe', path: 'Dockerfile', context: '.' },
		});
		const t = await setup({ builtin });
		await t.up(request({ recipe: { kind: 'builtin', name: 'hello' } }));
		// The build reads a copy made in its own directory, so a deploy that
		// replaces the installed recipe meanwhile does not change the build.
		expect(t.docker.builds[0]?.contexts?.recipe).toEndWith(
			join('builds', 'hello-pr-7', 'aaaaaaaaaaaaaaaa1', 'recipe'),
		);
		expect(t.docker.builds[0]?.contexts?.recipe).not.toContain(join(t.root, 'recipes'));
	});

	test('a repo recipe gets no extra context', async () => {
		const t = await setup();
		await t.up(request());
		expect(t.docker.builds[0]?.contexts).toEqual({});
	});
});

describe('egress', () => {
	test('containers get the proxy settings and the CA files; the deployment records only app env', async () => {
		const t = await setup({ egress: EGRESS });
		await t.up(request());
		const run = t.docker.runs[0];
		expect(run?.env.HTTPS_PROXY).toBe(EGRESS.proxy);
		expect(run?.env.SSL_CERT_FILE).toBe(CA_BUNDLE_PATH);
		expect(run?.files).toEqual([
			{ path: CA_BUNDLE_PATH, content: EGRESS.caBundle },
			{ path: CA_CERT_PATH, content: EGRESS.caCert },
		]);
		const recorded = (await t.store.get('hello-pr-7'))?.deployment?.env ?? {};
		expect(recorded.HTTPS_PROXY).toBeUndefined();
	});

	test('a container recreated on wake gets them too', async () => {
		const t = await setup({ egress: EGRESS });
		await t.up(request());
		const d = (await t.store.get('hello-pr-7'))?.deployment;
		await t.docker.remove(d?.container ?? '');
		await t.deployer.ensureRunning('hello-pr-7');
		const rerun = t.docker.runs.at(-1);
		expect(rerun?.env.HTTPS_PROXY).toBe(EGRESS.proxy);
		expect(rerun?.files?.length).toBe(2);
	});

	test('containers resolve names through the egress proxy, at the address it listens on', async () => {
		const t = await setup({ egress: EGRESS });
		await t.up(request());
		expect(t.docker.runs[0]?.dns).toBe('172.19.0.1');
		expect(egressDns(EGRESS)).toBe('172.19.0.1');
	});

	test('every start of a preview, a wake included, gets its route to the proxy after Docker starts it', async () => {
		const routed: Array<[string, number]> = [];
		const t = await setup({
			egress: EGRESS,
			routeOut: async (container) => {
				routed.push([container, t.docker.starts.length + t.docker.runs.length]);
			},
		});
		await t.up(request());
		const d = (await t.store.get('hello-pr-7'))?.deployment;
		expect(routed.map(([c]) => c)).toEqual([d?.container ?? '']);
		await t.docker.stop(d?.container ?? '');
		await t.deployer.ensureRunning('hello-pr-7');
		expect(routed.map(([c]) => c)).toEqual([d?.container ?? '', d?.container ?? '']);
		// Each after its start: a new start makes a new network namespace.
		expect(routed[1]?.[1]).toBeGreaterThan(routed[0]?.[1] ?? 0);
	});

	test('a preview the route helper fails for still starts, and the failure is logged', async () => {
		const t = await setup({
			egress: EGRESS,
			routeOut: async () => {
				throw new Error('sudo: a password is required');
			},
		});
		await t.up(request());
		expect((await t.store.get('hello-pr-7'))?.status).toBe('running');
		expect(t.logs).toContainEqual(expect.stringContaining('no route to the egress proxy'));
	});

	test('previewRoute runs the helper through sudo -n with the container alone, and throws when it fails', async () => {
		const calls: string[][] = [];
		const ok = previewRoute('/usr/local/libexec/koi-preview-route', async (cmd) => {
			calls.push(cmd);
			return { code: 0, stdout: '', stderr: '', timedOut: false } as ExecResult;
		});
		await ok('koi-hello-abc');
		expect(calls).toEqual([
			['sudo', '-n', '/usr/local/libexec/koi-preview-route', 'koi-hello-abc'],
		]);
		const failing = previewRoute(
			'/x',
			async () => ({ code: 1, stdout: '', stderr: 'no', timedOut: false }) as ExecResult,
		);
		await expect(failing('c')).rejects.toThrow();
	});

	test('without egress, containers get neither', async () => {
		const t = await setup();
		await t.up(request());
		expect(t.docker.runs[0]?.env.HTTPS_PROXY).toBeUndefined();
		expect(t.docker.runs[0]?.files).toBeUndefined();
	});

	test('loadEgress joins the system bundle and the proxy CA, and refuses non-PEM', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-eg-'));
		await writeFile(
			join(dir, 'ca.pem'),
			'-----BEGIN CERTIFICATE-----\nKOI\n-----END CERTIFICATE-----\n',
		);
		await writeFile(
			join(dir, 'system.pem'),
			'-----BEGIN CERTIFICATE-----\nSYS\n-----END CERTIFICATE-----\n',
		);
		const e = await loadEgress(
			'http://172.19.0.1:3128',
			join(dir, 'ca.pem'),
			join(dir, 'system.pem'),
		);
		expect(e.caBundle).toContain('SYS');
		expect(e.caBundle).toContain('KOI');
		expect(e.caCert).not.toContain('SYS');
		await writeFile(join(dir, 'bad.pem'), 'not a cert');
		await expect(
			loadEgress('http://x:1', join(dir, 'bad.pem'), join(dir, 'system.pem')),
		).rejects.toThrow(/PEM/);
	});

	test('egressEnv sets both spellings of the proxy variables', () => {
		const env = egressEnv(EGRESS);
		for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'])
			expect(env[k]).toBe(EGRESS.proxy);
		expect(env.NO_PROXY).toContain('localhost');
		expect(env.NODE_EXTRA_CA_CERTS).toBe(CA_CERT_PATH);
	});

	test('egressEnv points every TLS client a preview may use at the bundle with the proxy CA', () => {
		const env = egressEnv(EGRESS);
		for (const k of [
			'SSL_CERT_FILE',
			'REQUESTS_CA_BUNDLE',
			'CURL_CA_BUNDLE',
			'PIP_CERT',
			'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH',
		])
			expect(env[k]).toBe(CA_BUNDLE_PATH);
	});

	test('config reads the egress settings, or leaves them out', () => {
		const base = { KOI_UPLOADS_BUCKET: 'koi-uploads-1', KOI_DOMAIN: 'previews.example.net' };
		expect(loadConfig(base).egressProxy).toBeUndefined();
		const c = loadConfig({
			...base,
			KOI_EGRESS_PROXY: 'http://172.19.0.1:3128',
			KOI_EGRESS_CA: '/etc/koi/egress/ca.pem',
		});
		expect(c.egressProxy).toBe('http://172.19.0.1:3128');
		expect(c.egressCa).toBe('/etc/koi/egress/ca.pem');
		expect(() => loadConfig({ ...base, KOI_EGRESS_PROXY: 'not a url' })).toThrow();
	});
});

describe('docker CLI', () => {
	function recorder(slice?: string) {
		const cmds: string[][] = [];
		const exec = async (cmd: string[]): Promise<ExecResult> => {
			cmds.push(cmd);
			return { code: 0, stdout: '', stderr: '', timedOut: false };
		};
		return { cmds, docker: cliDocker({ builder: 'koi-builder', slice, exec }) };
	}

	test('build passes named contexts', async () => {
		const r = recorder();
		await r.docker.build({
			dockerfile: '/r/Dockerfile',
			context: '/src',
			contexts: { recipe: '/r' },
			tag: 't',
			labels: {},
			timeoutMs: 1000,
			onLine: () => {},
		});
		const cmd = r.cmds[0] ?? [];
		expect(cmd).toContain('--build-context');
		expect(cmd[cmd.indexOf('--build-context') + 1]).toBe('recipe=/r');
		expect(cmd.at(-1)).toBe('/src');
	});

	test('run with files creates under a temporary name, copies each file in, renames, then starts', async () => {
		const r = recorder();
		await r.docker.run({
			name: 'c1',
			image: 'img',
			network: 'koi-previews',
			user: '1:1',
			env: {},
			labels: {},
			files: [{ path: '/etc/koi-ca.pem', content: 'X' }],
		});
		expect(r.cmds.map((c) => c.slice(0, 2).join(' '))).toEqual([
			'docker rm',
			'docker create',
			'docker cp',
			'docker rename',
			'docker start',
		]);
		expect(r.cmds[0]?.at(-1)).toBe('c1.creating');
		const create = r.cmds[1] ?? [];
		expect(create[create.indexOf('--name') + 1]).toBe('c1.creating');
		expect(create).not.toContain('--detach');
		expect(r.cmds[2]?.at(-1)).toBe('c1.creating:/etc/koi-ca.pem');
		expect(r.cmds[3]?.slice(2)).toEqual(['c1.creating', 'c1']);
		expect(r.cmds[4]?.at(-1)).toBe('c1');
	});

	test('a failed copy removes the half-made container and starts nothing', async () => {
		const cmds: string[][] = [];
		const exec = async (cmd: string[]): Promise<ExecResult> => {
			cmds.push(cmd);
			const fails = cmd[1] === 'cp';
			return { code: fails ? 1 : 0, stdout: '', stderr: fails ? 'no space' : '', timedOut: false };
		};
		const docker = cliDocker({ builder: 'koi-builder', exec });
		await expect(
			docker.run({
				name: 'c1',
				image: 'img',
				network: 'koi-previews',
				user: '1:1',
				env: {},
				labels: {},
				files: [{ path: '/etc/koi-ca.pem', content: 'X' }],
			}),
		).rejects.toThrow();
		expect(cmds.map((c) => c.slice(0, 2).join(' '))).toEqual([
			'docker rm',
			'docker create',
			'docker cp',
			'docker rm',
		]);
		expect(cmds.at(-1)?.at(-1)).toBe('c1.creating');
	});

	test('a preview created with files runs in the slice, as one run without them does', async () => {
		const o = {
			name: 'c1',
			image: 'img',
			network: 'koi-previews',
			user: '1:1',
			env: {},
			labels: {},
		};
		for (const files of [[{ path: '/etc/koi-ca.pem', content: 'X' }], undefined]) {
			const r = recorder('koi.slice');
			await r.docker.run({ ...o, ...(files !== undefined ? { files } : {}) });
			const first = r.cmds.find((c) => c[1] === 'run' || c[1] === 'create') ?? [];
			expect(first[first.indexOf('--cgroup-parent') + 1]).toBe('koi.slice');
		}
	});

	test('run without files is a single detached docker run', async () => {
		const r = recorder();
		await r.docker.run({
			name: 'c1',
			image: 'img',
			network: 'n',
			user: '1:1',
			env: {},
			labels: {},
		});
		expect(r.cmds.length).toBe(1);
		expect(r.cmds[0]?.slice(0, 3)).toEqual(['docker', 'run', '--detach']);
	});

	test('create keeps every confinement flag that run has, the slice included', () => {
		const o = { name: 'c', image: 'i', network: 'n', user: '1:1', env: {}, labels: {} };
		const run = runArgs(o, 'koi.slice').slice(3);
		const create = runArgs(o, 'koi.slice', 'create').slice(2);
		expect(create).toEqual(run);
		expect(create).toContain('--cgroup-parent');
	});
});
