import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
	Deployment,
	DeploymentIdentity,
	LeaseReply,
	PreviewRecord,
	UpRequest,
} from '@koi/shared';
import { BuildLogs } from '../../daemon/src/buildlog.ts';
import { CapacityError } from '../../daemon/src/deployer.ts';
import { USAGE } from '../src/args.ts';
import { awsBox, type Box, type CtlResult } from '../src/box.ts';
import { toYaml } from '../src/config-command.ts';
import { exec } from '../src/exec.ts';
import { cliGit } from '../src/git.ts';
import type { GitHub } from '../src/github.ts';
import { type HostContext, type Runtime, run, table, VERSION } from '../src/main.ts';
import { type HealthAnswer, WAKE_POLL_MS, WAKE_WAIT_MS } from '../src/up.ts';
import { koidClients, koidDeps, previewRecord, settings } from './koid.ts';
import { schemaErrors } from './output-schemas.ts';
import { asGitHub, pullRequestOrigin } from './pulls.ts';

// A box whose koid ctl answers from `replies` by command. `health` is what
// each request to a preview's health URL gets, in order, the last one
// repeating; by default the preview is running. `events` has every probe
// and every ctl command in the order they were made.
function fakeRuntime(
	replies: Record<string, CtlResult>,
	options: { health?: HealthAnswer[] } = {},
): Runtime & {
	calls: string[][];
	probed: string[];
	events: string[];
	woke: () => number;
	closed: () => number;
} {
	const calls: string[][] = [];
	const probed: string[] = [];
	const events: string[] = [];
	const health = options.health ?? [{ status: 200 }];
	let woke = 0;
	let closed = 0;
	let clock = Date.parse('2026-10-06T10:00:00.000Z');
	const box: Box = {
		upload: async () => {},
		ensureAwake: async () => {
			woke += 1;
		},
		ctl: async (args) => {
			calls.push(args);
			events.push(`ctl ${args[0] ?? ''}`);
			return replies[args[0] ?? ''] ?? { code: 1, stdout: '', stderr: '{"error":"unexpected"}' };
		},
		close: async () => {
			closed += 1;
		},
	};
	return {
		cwd: '/nonexistent',
		env: {},
		box: async () => ({ box, domain: 'previews.example.net' }),
		probe: async (url) => {
			probed.push(url);
			events.push(`probe ${url}`);
			return health[Math.min(probed.length, health.length) - 1] ?? { status: 200 };
		},
		sleep: async (ms) => {
			clock += ms;
		},
		now: () => new Date(clock),
		clock: () => clock,
		calls,
		probed,
		events,
		woke: () => woke,
		closed: () => closed,
	};
}

async function capture(argv: string[], runtime?: Runtime) {
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
		runtime,
	);
	return { code, stdout, stderr };
}

const record = {
	label: 'hello-pr-7',
	project: 'hello',
	repo: 'github.com/acme/hello',
	status: 'running',
	commit: 'abcdef0123456789abcdef0123456789abcdef01',
	branch: 'feature/x',
	pr: 7,
	dirty: false,
	requestId: 'a'.repeat(16),
	attempt: 'b'.repeat(20),
	ttlDays: 7,
	createdAt: '2026-10-06T00:00:00.000Z',
	updatedAt: '2026-10-06T00:00:00.000Z',
	lastVisitAt: '2026-10-06T09:30:00.000Z',
};

const identity: DeploymentIdentity = {
	label: 'hello-pr-7',
	deploymentId: 'b'.repeat(20),
	imageDigest: `sha256:${'1'.repeat(64)}`,
	commit: record.commit,
	merge: { head: 'd'.repeat(40), base: 'e'.repeat(40), baseBranch: 'main' },
};

const leaseReply: LeaseReply = {
	lease: {
		leaseId: 'l'.repeat(20),
		deploymentId: identity.deploymentId,
		holder: 'dev@laptop',
		acquiredAt: '2026-10-06T10:00:00.000Z',
		expiresAt: '2026-10-06T10:30:00.000Z',
	},
	deployment: identity,
};

describe('run', () => {
	test('prints usage to stdout and exits 0 with no arguments', async () => {
		expect(await capture([])).toEqual({ code: 0, stdout: USAGE, stderr: '' });
	});

	test('prints the version', async () => {
		expect(await capture(['version'])).toEqual({ code: 0, stdout: `koi ${VERSION}\n`, stderr: '' });
	});

	test('prints the version as JSON with --json', async () => {
		const { code, stdout, stderr } = await capture(['version', '--json']);
		expect(code).toBe(0);
		expect(stderr).toBe('');
		expect(JSON.parse(stdout)).toEqual({ version: VERSION });
	});

	test('writes the error and usage to stderr and exits 2 for an unknown command', async () => {
		const { code, stdout, stderr } = await capture(['bogus']);
		expect(code).toBe(2);
		expect(stdout).toBe('');
		expect(stderr).toStartWith('koi: unknown command "bogus"');
		expect(stderr).toEndWith(USAGE);
	});

	test('list wakes the box and prints a table, or JSON with --json', async () => {
		const summary = {
			label: record.label,
			status: record.status,
			commit: record.commit,
			branch: record.branch,
			pr: record.pr,
			lastVisitAt: record.lastVisitAt,
			updatedAt: record.updatedAt,
		};
		const runtime = fakeRuntime({
			list: { code: 0, stdout: JSON.stringify({ previews: [summary] }), stderr: '' },
		});
		const plain = await capture(['list'], runtime);
		expect(plain.code).toBe(0);
		expect(plain.stdout).toContain('hello-pr-7');
		expect(plain.stdout).toContain('https://hello-pr-7.previews.example.net');
		expect(runtime.woke()).toBe(1);
		const json = await capture(['list', '--json'], runtime);
		expect(JSON.parse(json.stdout)).toEqual([
			{ ...summary, keysUrl: 'https://keys.previews.example.net/?for=hello-pr-7' },
		]);
	});

	test('list --json carries the deployment serving each preview and its keys page', async () => {
		const summary = {
			label: record.label,
			status: record.status,
			commit: record.commit,
			branch: record.branch,
			pr: record.pr,
			updatedAt: record.updatedAt,
			deployment: identity,
		};
		const runtime = fakeRuntime({
			list: { code: 0, stdout: JSON.stringify({ previews: [summary] }), stderr: '' },
		});
		const json = await capture(['list', '--json'], runtime);
		expect(json.code).toBe(0);
		expect(JSON.parse(json.stdout)).toEqual([
			{ ...summary, keysUrl: 'https://keys.previews.example.net/?for=hello-pr-7' },
		]);
		// The table is as before.
		const plain = await capture(['list'], runtime);
		expect(plain.stdout).not.toContain('sha256');
	});

	test('lease asks koid to hold the preview and prints the lease, or JSON with --json', async () => {
		const runtime = fakeRuntime({
			lease: { code: 0, stdout: JSON.stringify(leaseReply), stderr: '' },
		});
		const plain = await capture(
			['lease', 'hello-pr-7', '--minutes', '30', '--holder', 'dev@laptop'],
			runtime,
		);
		expect(plain.code).toBe(0);
		expect(plain.stderr).toBe('');
		expect(runtime.woke()).toBe(1);
		expect(runtime.calls.at(-1)).toEqual([
			'lease',
			'hello-pr-7',
			'--holder',
			'dev@laptop',
			'--ttl-seconds',
			'1800',
		]);
		expect(plain.stdout).toBe(
			'leased hello-pr-7 until 2026-10-06T10:30:00.000Z\n' +
				`  lease       ${'l'.repeat(20)}\n` +
				'  holder      dev@laptop\n' +
				`  deployment  ${'b'.repeat(20)}\n` +
				`  image       sha256:${'1'.repeat(64)}\n` +
				`  commit      ${record.commit}\n`,
		);
		const json = await capture(
			['lease', 'hello-pr-7', '--minutes', '30', '--holder', 'dev@laptop', '--json'],
			runtime,
		);
		expect(json.code).toBe(0);
		expect(JSON.parse(json.stdout)).toEqual({ schemaVersion: 1, ...leaseReply });
	});

	test('lease names the local user and host as the holder when none is given', async () => {
		const runtime = fakeRuntime({
			lease: { code: 0, stdout: JSON.stringify(leaseReply), stderr: '' },
		});
		expect((await capture(['lease', 'hello-pr-7', '--minutes', '5'], runtime)).code).toBe(0);
		const holder = runtime.calls.at(-1)?.[3] ?? '';
		expect(holder).toMatch(/^[^@\s]+@\S+$/);
		expect(runtime.calls.at(-1)?.[5]).toBe('300');
	});

	test('lease visits the preview first, as a browser would, and asks koid once it answers 200', async () => {
		const health = 'https://hello-pr-7.previews.example.net/__koi/health';
		const runtime = fakeRuntime(
			{ lease: { code: 0, stdout: JSON.stringify(leaseReply), stderr: '' } },
			{ health: [{ status: 503 }, { error: 'connection reset' }, { status: 200 }] },
		);
		const r = await capture(['lease', 'hello-pr-7', '--minutes', '30', '--json'], runtime);
		expect(r.code).toBe(0);
		expect(JSON.parse(r.stdout)).toEqual({ schemaVersion: 1, ...leaseReply });
		// The visit goes to koid's health check for the preview, which starts
		// a stopped one, until it answers 200; only then is the lease asked
		// for. The wait is said on stderr.
		expect(runtime.events).toEqual([
			`probe ${health}`,
			`probe ${health}`,
			`probe ${health}`,
			'ctl lease',
		]);
		expect(r.stderr).toBe('koi  waking hello-pr-7\n');
	});

	test('lease gives up when the preview does not answer within 90 seconds, and asks koid for nothing', async () => {
		const runtime = fakeRuntime(
			{ lease: { code: 0, stdout: JSON.stringify(leaseReply), stderr: '' } },
			{ health: [{ status: 503 }] },
		);
		const r = await capture(['lease', 'hello-pr-7', '--minutes', '30'], runtime);
		expect(r.code).toBe(1);
		expect(r.stdout).toBe('');
		expect(r.stderr).toStartWith('koi  waking hello-pr-7\n');
		expect(r.stderr).toContain('koi  still waiting for hello-pr-7 to start (HTTP 503 after 15s)\n');
		expect(r.stderr).toEndWith(
			'koi: hello-pr-7 did not start within 90 seconds; the last check of https://hello-pr-7.previews.example.net/__koi/health got HTTP 503. See koi list, or koi logs hello-pr-7\n',
		);
		// One check every WAKE_POLL_MS until WAKE_WAIT_MS has passed.
		expect(runtime.probed).toHaveLength(WAKE_WAIT_MS / WAKE_POLL_MS + 1);
		expect(runtime.calls).toEqual([]);
		// A preview that never answers reads the same, with the error.
		const silent = fakeRuntime({}, { health: [{ error: 'connect ECONNREFUSED' }] });
		const s = await capture(['lease', 'hello-pr-7', '--minutes', '30'], silent);
		expect(s.code).toBe(1);
		expect(s.stderr).toEndWith(
			'got no answer (connect ECONNREFUSED). See koi list, or koi logs hello-pr-7\n',
		);
	});

	test('lease stops at once when koid has no such preview', async () => {
		const runtime = fakeRuntime({}, { health: [{ status: 404 }] });
		const r = await capture(['lease', 'nobody-pr-1', '--minutes', '5'], runtime);
		expect(r).toEqual({
			code: 1,
			stdout: '',
			stderr: 'koi: koid has no preview named nobody-pr-1; see koi list\n',
		});
		expect(runtime.probed).toHaveLength(1);
		expect(runtime.calls).toEqual([]);
	});

	test('lease reports the refusal koid gives and exits 1', async () => {
		const runtime = fakeRuntime({
			lease: {
				code: 1,
				stdout: '',
				stderr: '{"error":"hello-pr-7 is leased by ci run 42 until 2026-10-06T11:00:00.000Z"}',
			},
		});
		const r = await capture(['lease', 'hello-pr-7', '--minutes', '5', '--json'], runtime);
		expect(r.code).toBe(1);
		expect(r.stdout).toBe('');
		expect(r.stderr).toBe(
			'koi: hello-pr-7 is leased by ci run 42 until 2026-10-06T11:00:00.000Z\n',
		);
	});

	test('release ends a lease, and says so as JSON with --json', async () => {
		const runtime = fakeRuntime({ release: { code: 0, stdout: '{"released":true}', stderr: '' } });
		const id = 'l'.repeat(20);
		const plain = await capture(['release', 'hello-pr-7', id], runtime);
		expect(plain).toEqual({ code: 0, stdout: `released ${id} on hello-pr-7\n`, stderr: '' });
		expect(runtime.calls.at(-1)).toEqual(['release', 'hello-pr-7', id]);
		const json = await capture(['release', 'hello-pr-7', id, '--json'], runtime);
		expect(JSON.parse(json.stdout)).toEqual({
			schemaVersion: 1,
			label: 'hello-pr-7',
			leaseId: id,
			released: true,
		});
		const gone = fakeRuntime({
			release: { code: 1, stdout: '', stderr: '{"error":"no such lease"}' },
		});
		const r = await capture(['release', 'hello-pr-7', id], gone);
		expect(r.code).toBe(1);
		expect(r.stderr).toBe('koi: no such lease\n');
	});

	test('down --force asks koid to remove the preview whatever lease holds it', async () => {
		const runtime = fakeRuntime({ down: { code: 0, stdout: '{"removed":true}', stderr: '' } });
		expect((await capture(['down', 'hello-pr-7'], runtime)).stdout).toBe('removed hello-pr-7\n');
		expect(runtime.calls.at(-1)).toEqual(['down', 'hello-pr-7']);
		const forced = await capture(['down', 'hello-pr-7', '--force', '--json'], runtime);
		expect(JSON.parse(forced.stdout)).toEqual({ removed: 'hello-pr-7' });
		expect(runtime.calls.at(-1)).toEqual(['down', 'hello-pr-7', '--force']);
		const leased = fakeRuntime({
			down: {
				code: 1,
				stdout: '',
				stderr:
					'{"error":"hello-pr-7 is leased by dev@laptop until later; run koi down hello-pr-7 --force to remove it anyway"}',
			},
		});
		const r = await capture(['down', 'hello-pr-7'], leased);
		expect(r.code).toBe(1);
		expect(r.stderr).toContain('--force');
	});

	test('closes the host once the command is done, on success and on failure', async () => {
		const ok = fakeRuntime({ list: { code: 0, stdout: '{"previews":[]}', stderr: '' } });
		expect((await capture(['list'], ok)).code).toBe(0);
		expect(ok.closed()).toBe(1);
		const failing = fakeRuntime({ list: { code: 1, stdout: '', stderr: '{"error":"no"}' } });
		expect((await capture(['list'], failing)).code).toBe(1);
		expect(failing.closed()).toBe(1);
		const thrown: Runtime = {
			...failing,
			box: async () => ({
				box: {
					...(await failing.box({} as never)).box,
					ensureAwake: async () => {
						throw new Error('the host is gone');
					},
				},
				domain: 'previews.example.net',
			}),
		};
		const r = await capture(['list'], thrown);
		expect(r.code).toBe(1);
		expect(r.stderr).toBe('koi: the host is gone\n');
		expect(failing.closed()).toBe(2);
		// The host opened is reported to the runtime, for a signal to close.
		const seen: Box[] = [];
		const told = fakeRuntime({ list: { code: 0, stdout: '{"previews":[]}', stderr: '' } });
		await capture(['list'], { ...told, opened: (box) => void seen.push(box) });
		expect(seen).toHaveLength(1);
		expect(told.closed()).toBe(1);
		// A command that opens no host closes nothing.
		const none = fakeRuntime({});
		await capture(['version'], none);
		expect(none.closed()).toBe(0);
	});

	test('logs asks for the container log, or the build log with --build', async () => {
		const runtime = fakeRuntime({
			logs: { code: 0, stdout: 'container says hi', stderr: '' },
			buildlog: { code: 0, stdout: 'b\nc\n', stderr: '' },
		});
		expect((await capture(['logs', 'hello-pr-7', '--tail', '50'], runtime)).stdout).toBe(
			'container says hi\n',
		);
		expect(runtime.calls.at(-1)).toEqual(['logs', 'hello-pr-7', '50']);
		expect((await capture(['logs', 'hello-pr-7', '--build', '--tail', '2'], runtime)).stdout).toBe(
			'b\nc\n',
		);
		expect(runtime.calls.at(-1)).toEqual(['buildlog', 'hello-pr-7', '2']);
		const empty = fakeRuntime({ buildlog: { code: 0, stdout: '', stderr: '' } });
		expect((await capture(['logs', 'hello-pr-7', '--build'], empty)).stdout).toBe('');
	});

	test('logs --json prints the log as JSON', async () => {
		const runtime = fakeRuntime({
			logs: { code: 0, stdout: 'container says hi\n', stderr: '' },
			buildlog: { code: 0, stdout: 'b\nc\n', stderr: '' },
		});
		const plain = await capture(['logs', 'hello-pr-7', '--json'], runtime);
		expect(plain.code).toBe(0);
		expect(plain.stdout.endsWith('\n')).toBe(true);
		expect(JSON.parse(plain.stdout)).toEqual({
			label: 'hello-pr-7',
			build: false,
			text: 'container says hi\n',
			truncated: false,
		});
		const build = await capture(['logs', 'hello-pr-7', '--build', '--json'], runtime);
		expect(JSON.parse(build.stdout)).toEqual({
			label: 'hello-pr-7',
			build: true,
			text: 'b\nc\n',
			truncated: false,
		});
	});

	test('down reports the error the box gives', async () => {
		const runtime = fakeRuntime({ down: { code: 1, stdout: '', stderr: '{"removed":false}' } });
		const r = await capture(['down', 'hello-pr-7'], runtime);
		expect(r.code).toBe(1);
		expect(r.stderr).toContain('koi:');
	});

	test('rejects a preview name that is not a label before touching the box', async () => {
		const runtime = fakeRuntime({});
		const r = await capture(['down', '../etc'], runtime);
		expect(r.code).toBe(2);
		expect(runtime.calls).toEqual([]);
	});

	test('hands the target selectors, the environment and the checkout to whatever opens the host', async () => {
		const seen: HostContext[] = [];
		const inner = fakeRuntime({ list: { code: 0, stdout: '{"previews":[]}', stderr: '' } });
		const runtime: Runtime = {
			cwd: '/nonexistent',
			env: { HOME: '/home/u', KOI_TARGET: 'team' },
			git: { ...(await cliGit('/nonexistent')), root: async () => '/checkout' } as never,
			box: async (ctx) => {
				seen.push(ctx);
				// A notice given while the host opens lands on stderr as progress.
				ctx.notice('hello');
				return inner.box(ctx);
			},
		};
		const r = await capture(
			['list', '--target', 'team', '--config', '/tmp/k.yaml', '--domain', 'd.example.com'],
			runtime,
		);
		expect(r.code).toBe(0);
		expect(seen).toHaveLength(1);
		expect(seen[0]?.flags).toEqual({
			target: 'team',
			config: '/tmp/k.yaml',
			domain: 'd.example.com',
		});
		expect(seen[0]?.env).toEqual({ HOME: '/home/u', KOI_TARGET: 'team' });
		expect(seen[0]?.checkoutDir).toBe('/checkout');
		expect(r.stderr).toBe('koi  hello\n');
		// Outside a checkout, the working directory stands in.
		const { git: _git, ...noGit } = runtime;
		const plain = await capture(['list'], noGit);
		expect(plain.code).toBe(0);
		expect(seen[1]?.flags).toEqual({ target: undefined, config: undefined, domain: undefined });
		expect(seen[1]?.checkoutDir).toBe('/nonexistent');
	});

	test('config show prints the target from the config file the environment names', async () => {
		const home = await mkdtemp(join(tmpdir(), 'koi-home-'));
		await mkdir(join(home, '.config', 'koi'), { recursive: true, mode: 0o700 });
		await writeFile(
			join(home, '.config', 'koi', 'config.yaml'),
			toYaml({
				version: 1,
				defaultTarget: 'owner-aws',
				targets: {
					'owner-aws': {
						domain: 'previews.example.net',
						transport: { kind: 'aws-ssm' },
						aws: { instanceId: 'i-0abc', uploadsBucket: 'koi-uploads-123456789012' },
						power: { kind: 'ec2' },
					},
				},
			}),
			{ mode: 0o600 },
		);
		const runtime: Runtime = {
			cwd: '/nonexistent',
			env: { HOME: home },
			box: async () => {
				throw new Error('config show opens no host');
			},
		};
		const r = await capture(['config', 'show'], runtime);
		expect(r.code).toBe(0);
		expect(r.stderr).toBe('');
		expect(r.stdout).toStartWith('target owner-aws (from defaultTarget) in ');
		expect(r.stdout).toContain('domain: previews.example.net');
		expect(r.stdout).toContain('profile: koi-cli');
		const missing = await capture(['config', 'show', '--target', 'nope'], runtime);
		expect(missing.code).toBe(1);
		expect(missing.stderr).toContain('koi: --target names "nope", but');
		const legacy = await capture(['config', 'show'], { ...runtime, env: { HOME: '/nonexistent' } });
		expect(legacy.code).toBe(0);
		expect(legacy.stdout).toContain('no target: there is no config file at');
	});

	test('config without a subcommand is a usage error', async () => {
		const r = await capture(['config']);
		expect(r.code).toBe(2);
		expect(r.stderr).toStartWith('koi: config needs a subcommand');
		expect(r.stderr).toEndWith(USAGE);
	});
});

// A git repository with a koi.yaml, committed, whose origin is on GitHub.
async function gitRepo(): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), 'koi-repo-'));
	const git = (...args: string[]) =>
		exec(['git', '-C', dir, '-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args]);
	await git('init', '-q', '-b', 'main');
	await git('remote', 'add', 'origin', 'git@github.com:acme/hello.git');
	await writeFile(join(dir, 'Dockerfile'), 'FROM scratch\n');
	await writeFile(join(dir, 'koi.yaml'), 'port: 8080\nbuild:\n  kind: dockerfile\n');
	await git('add', '.');
	await git('commit', '-q', '-m', 'init');
	// As a clone has it: origin's main, fetched, to compare the tree with.
	await git('update-ref', 'refs/remotes/origin/main', 'HEAD');
	return dir;
}

// koi and koid as on the box: awsBox runs koid ctl through an SSM client
// that returns at most the first 24,000 characters of its output.
function koidRuntime(clients: ReturnType<typeof koidClients>): Runtime {
	return {
		cwd: '/nonexistent',
		box: async () => ({
			box: awsBox(settings, clients, async () => {}),
			domain: 'previews.example.net',
		}),
	};
}

describe('run against koid through SSM', () => {
	test('list collects every page of a list too long for one SSM reply', async () => {
		// Many small previews, and many as large as koi makes them.
		for (const branch of ['main', 'é'.repeat(255), '\u0001'.repeat(255)]) {
			const records = Array.from({ length: 300 }, (_, i) =>
				previewRecord({ label: `hello-pr-${i + 1}`, pr: i + 1, branch }),
			);
			const summaries = records
				.map((r) => ({
					label: r.label,
					status: r.status,
					commit: r.commit,
					branch: r.branch,
					pr: r.pr,
					updatedAt: r.updatedAt,
				}))
				.sort((a, b) => (a.label < b.label ? -1 : 1));
			// One reply with them all would be cut by SSM.
			expect(JSON.stringify(summaries).length).toBeGreaterThan(24_000);
			const clients = koidClients(
				koidDeps({ store: { get: async () => undefined, list: async () => records } }),
			);
			const r = await capture(['list', '--json'], koidRuntime(clients));
			expect(r.stderr).toBe('');
			expect(r.code).toBe(0);
			expect(JSON.parse(r.stdout)).toEqual(
				summaries.map((s) => ({
					...s,
					keysUrl: `https://keys.previews.example.net/?for=${s.label}`,
				})),
			);
			const lists = clients.commands.filter((c) => c[0] === 'list');
			expect(lists.length).toBeGreaterThan(1);
			expect(lists[0]).toEqual(['list']);
		}
	});

	test("up prints the keys page of the box's own domain", async () => {
		const dir = await gitRepo();
		let request: UpRequest | undefined;
		const box: Box = {
			upload: async (r) => {
				request = r;
			},
			ensureAwake: async () => {},
			ctl: async (args) => {
				if (args[0] === 'up') {
					return {
						code: 0,
						stdout: JSON.stringify({ label: request?.label, queued: false }),
						stderr: '',
					};
				}
				const status = {
					record: { ...record, label: request?.label, requestId: request?.id, status: 'running' },
					log: { next: 0, lines: [] },
				};
				return { code: 0, stdout: JSON.stringify(status), stderr: '' };
			},
		};
		const r = await capture(['up'], {
			cwd: dir,
			box: async () => ({ box, domain: 'example.dev' }),
			sleep: async () => {},
		});
		expect(r.code).toBe(0);
		expect(r.stdout).toContain(`  preview   https://${request?.label}.example.dev\n`);
		expect(r.stdout).toContain(`  keys      https://keys.example.dev/?for=${request?.label}\n`);
		expect(r.stdout).not.toContain('previews.example.net');
	});

	test('up --json carries the deployment serving and the keys page', async () => {
		const dir = await gitRepo();
		let request: UpRequest | undefined;
		const box: Box = {
			upload: async (r) => {
				request = r;
			},
			ensureAwake: async () => {},
			ctl: async (args) => {
				if (args[0] === 'up') {
					return {
						code: 0,
						stdout: JSON.stringify({ label: request?.label, queued: false }),
						stderr: '',
					};
				}
				const status = {
					record: { ...record, label: request?.label, requestId: request?.id, status: 'running' },
					log: { next: 0, lines: [] },
					deployment: { ...identity, label: request?.label },
				};
				return { code: 0, stdout: JSON.stringify(status), stderr: '' };
			},
		};
		const r = await capture(['up', '--json'], {
			cwd: dir,
			box: async () => ({ box, domain: 'example.dev' }),
			sleep: async () => {},
		});
		expect(r.code).toBe(0);
		expect(JSON.parse(r.stdout)).toEqual({
			schemaVersion: 1,
			label: request?.label,
			url: `https://${request?.label}.example.dev`,
			status: 'running',
			commit: expect.stringMatching(/^[0-9a-f]{40}$/),
			deployment: { ...identity, label: request?.label },
			keysUrl: `https://keys.example.dev/?for=${request?.label}`,
		});
	});

	test('up --pr says what it built, in words, and as fields with --json', async () => {
		const o = await pullRequestOrigin();
		let request: UpRequest | undefined;
		const box: Box = {
			upload: async (r) => {
				request = r;
			},
			ensureAwake: async () => {},
			ctl: async (args) => {
				if (args[0] === 'up') {
					return {
						code: 0,
						stdout: JSON.stringify({ label: request?.label, queued: false }),
						stderr: '',
					};
				}
				const status = {
					record: {
						...record,
						label: request?.label,
						requestId: request?.id,
						commit: request?.commit,
						status: 'running',
					},
					log: { next: 0, lines: [] },
				};
				return { code: 0, stdout: JSON.stringify(status), stderr: '' };
			},
		};
		const github: GitHub = {
			pullRequestBranches: async () => ({ head: 'feature', base: 'main' }),
			pullRequestFiles: async () => ['pr.txt'],
			pullRequestMergeState: async () => {
				throw new Error('the merge is current; there is nothing to recompute');
			},
			upsertComment: async () => {
				throw new Error('no comment in this test');
			},
		};
		const runtime: Runtime = {
			cwd: o.user,
			box: async () => ({ box, domain: 'example.dev' }),
			sleep: async () => {},
			git: cliGit(o.user, asGitHub()),
			github: () => github,
		};
		const short = (c: string) => c.slice(0, 7);
		const r = await capture(['up', '--pr', '7'], runtime);
		expect(r.code).toBe(0);
		expect(r.stdout).toContain('  preview   https://hello-pr-7.example.dev\n');
		expect(r.stdout).toContain(
			`  built     #7 (${short(o.head7)}) merged into main (${short(o.base)}), merge commit ${short(o.merge7)}\n`,
		);
		expect(r.stdout).not.toContain('  commit ');
		expect(r.stderr).toContain(
			`koi  building #7 (${short(o.head7)}) merged into main (${short(o.base)}), merge commit ${short(o.merge7)}\n`,
		);
		const j = await capture(['up', '--pr', '7', '--json'], runtime);
		expect(j.code).toBe(0);
		expect(JSON.parse(j.stdout)).toMatchObject({
			schemaVersion: 1,
			label: 'hello-pr-7',
			commit: o.merge7,
			pr: 7,
			merge: { head: o.head7, base: o.base, baseBranch: 'main' },
		});
		expect(schemaErrors('koi-up', JSON.parse(j.stdout))).toEqual([]);
		// The head as pushed, with --head.
		const h = await capture(['up', '--pr', '7', '--head'], runtime);
		expect(h.code).toBe(0);
		expect(h.stdout).toContain(
			`  built     #7 (${short(o.head7)}), its head as pushed, not merged into its base\n`,
		);
	});

	test('up prints why koid has no room for another preview, and exits 1', async () => {
		const dir = await gitRepo();
		const reason =
			'koi has 63 live previews, and the list that lets a visit wake the box cannot take hello-main-abcdefgh as well';
		const clients = koidClients(
			koidDeps({
				deployer: {
					...koidDeps({}).deployer,
					up: async () => {
						throw new CapacityError(reason);
					},
					down: async () => false,
				},
			}),
		);
		const box: Box = { ...awsBox(settings, clients, async () => {}), upload: async () => {} };
		const r = await capture(['up'], {
			cwd: dir,
			box: async () => ({ box, domain: 'previews.example.net' }),
		});
		expect(r.code).toBe(1);
		expect(r.stdout).toBe('');
		expect(r.stderr).toEndWith(`koi: ${reason}\n`);
		expect(clients.commands.map((c) => c[0])).toEqual(['ping', 'up']);
	});

	test('logs --build --tail N prints the last N lines, or koid saying it cut them', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koi-state-'));
		const logs = new BuildLogs(state);
		const write = async (lines: string[]) => {
			const log = await logs.open('hello-pr-7', previewRecord().attempt);
			for (const line of lines) log.line(line);
			await log.close();
		};
		const clients = koidClients(
			koidDeps({
				store: { get: async () => previewRecord(), list: async () => [] },
				buildLogs: logs,
			}),
		);
		const tail = (n: string) =>
			capture(['logs', 'hello-pr-7', '--build', '--tail', n], koidRuntime(clients));
		const untimed = (text: string) => text.replace(/^\S+ /gm, '');

		await write(['a', 'b', 'c']);
		const last = await tail('1');
		expect(last.code).toBe(0);
		expect(untimed(last.stdout)).toBe('c\n');
		expect(untimed((await tail('2')).stdout)).toBe('b\nc\n');

		// Lines longer together than SSM returns: koid ctl keeps their end and
		// says so.
		await write(Array.from({ length: 5 }, (_, i) => `${i} ${'x'.repeat(4000)}`));
		for (const n of ['5', '1']) {
			// The second time, one line longer than that, as a log written
			// before koid cut lines can hold.
			if (n === '1') {
				const file = join(state, 'logs', 'hello-pr-7', `${previewRecord().attempt}.build.log`);
				await writeFile(file, `${'x'.repeat(20_000)}\n`);
			}
			const cut = await tail(n);
			const printed = clients.outputs.at(-1) ?? '';
			expect(printed).toStartWith('[koid: earlier output cut');
			expect(Buffer.byteLength(printed)).toBeLessThanOrEqual(16_000);
			expect(cut).toEqual({ code: 0, stdout: printed, stderr: '' });
			// With --json, the line koid put first says so in `truncated`.
			const json = await capture(
				['logs', 'hello-pr-7', '--build', '--tail', n, '--json'],
				koidRuntime(clients),
			);
			expect(JSON.parse(json.stdout)).toEqual({
				label: 'hello-pr-7',
				build: true,
				text: printed.slice(printed.indexOf('\n') + 1),
				truncated: true,
			});
		}
		await write(['a', 'b', 'c']);
		const whole = await capture(
			['logs', 'hello-pr-7', '--build', '--tail', '2', '--json'],
			koidRuntime(clients),
		);
		expect(JSON.parse(whole.stdout)).toMatchObject({ truncated: false });
		expect(untimed(JSON.parse(whole.stdout).text)).toBe('b\nc\n');
	});
});

// A deployment as koid records it, built from the request `requestId`.
function deployment(over: Partial<Deployment> = {}): Deployment {
	return {
		requestId: 'a'.repeat(16),
		deploymentId: 'b'.repeat(20),
		imageDigest: `sha256:${'1'.repeat(64)}`,
		commit: 'c'.repeat(40),
		image: 'koi-preview/hello:a',
		container: 'koi-hello-a',
		port: 8080,
		healthPath: '/',
		healthTimeoutSeconds: 60,
		user: '65534:65534',
		env: {},
		deployedAt: '2026-10-06T00:00:00.000Z',
		...over,
	};
}

// koi up --json in a git repository, against the real koid ctl and control
// API behind SSM. Once koi up has uploaded its request, koid's record for the
// label is what `record` makes of the request, and the build log is empty.
async function upThroughKoid(record: (request: UpRequest) => PreviewRecord) {
	const dir = await gitRepo();
	let request: UpRequest | undefined;
	const clients = koidClients(
		koidDeps({
			deployer: {
				...koidDeps({}).deployer,
				up: async () => ({ label: request?.label ?? '', queued: false }),
			},
			store: {
				get: async () => (request === undefined ? undefined : record(request)),
				list: async () => [],
			},
			buildLogs: { read: async () => ({ next: 0, lines: [] }), tail: async () => '' },
		}),
	);
	const box: Box = {
		...awsBox(settings, clients, async () => {}),
		upload: async (r) => {
			request = r;
		},
	};
	const r = await capture(['up', '--json'], {
		cwd: dir,
		box: async () => ({ box, domain: 'previews.example.net' }),
		sleep: async () => {},
	});
	if (request === undefined) throw new Error(`koi up uploaded nothing: ${r.stderr}`);
	return { ...r, request };
}

describe('--json output matches the JSON Schemas in schemas/', () => {
	test('up, for a preview that runs the build it asked for', async () => {
		const loginKey = `koi-${'k'.repeat(24)}`;
		const r = await upThroughKoid((request) =>
			previewRecord({
				label: request.label,
				requestId: request.id,
				commit: request.commit,
				status: 'running',
				loginKey,
				deployment: deployment({ requestId: request.id, commit: request.commit }),
			}),
		);
		expect(r.code).toBe(0);
		const out = JSON.parse(r.stdout);
		expect(schemaErrors('koi-up', out)).toEqual([]);
		const { label, commit } = r.request;
		expect(out).toEqual({
			schemaVersion: 1,
			label,
			url: `https://${label}.previews.example.net`,
			status: 'running',
			commit,
			deployment: {
				label,
				deploymentId: 'b'.repeat(20),
				imageDigest: `sha256:${'1'.repeat(64)}`,
				commit,
			},
			loginKey,
			keysUrl: `https://keys.previews.example.net/?for=${label}`,
		});
		// Output without schemaVersion, as koi printed it before, does not match.
		const { schemaVersion: _, ...unversioned } = out;
		expect(schemaErrors('koi-up', unversioned)).toContainEqual(
			expect.objectContaining({
				keyword: 'required',
				params: { missingProperty: 'schemaVersion' },
			}),
		);
	});

	test('up, for a failed build while the previous deployment serves', async () => {
		const previous = 'b'.repeat(40);
		const r = await upThroughKoid((request) =>
			previewRecord({
				label: request.label,
				requestId: request.id,
				commit: request.commit,
				status: 'failed',
				error: 'RUN npm ci failed',
				deployment: deployment({
					requestId: 'p'.repeat(16),
					deploymentId: 'p'.repeat(20),
					commit: previous,
				}),
			}),
		);
		expect(r.code).toBe(1);
		const out = JSON.parse(r.stdout);
		expect(schemaErrors('koi-up', out)).toEqual([]);
		expect(out).toMatchObject({
			schemaVersion: 1,
			status: 'failed',
			commit: r.request.commit,
			error: 'RUN npm ci failed',
			deployment: { deploymentId: 'p'.repeat(20), commit: previous },
		});
		expect(out.deployment.commit).not.toBe(out.commit);
	});

	test('lease and release', async () => {
		const clients = koidClients(
			koidDeps({
				deployer: {
					...koidDeps({}).deployer,
					acquireLease: async () => leaseReply,
					releaseLease: async () => {},
				},
			}),
		);
		const runtime: Runtime = {
			...koidRuntime(clients),
			probe: async () => ({ status: 200 }),
			sleep: async () => {},
		};
		const lease = await capture(
			['lease', 'hello-pr-7', '--minutes', '30', '--holder', 'dev@laptop', '--json'],
			runtime,
		);
		expect(lease.code).toBe(0);
		const leased = JSON.parse(lease.stdout);
		expect(schemaErrors('koi-lease', leased)).toEqual([]);
		expect(leased).toEqual({ schemaVersion: 1, ...leaseReply });

		const id = leaseReply.lease.leaseId;
		const release = await capture(['release', 'hello-pr-7', id, '--json'], runtime);
		expect(release.code).toBe(0);
		const released = JSON.parse(release.stdout);
		expect(schemaErrors('koi-release', released)).toEqual([]);
		expect(released).toEqual({
			schemaVersion: 1,
			label: 'hello-pr-7',
			leaseId: id,
			released: true,
		});
		// Each command reached koid, after the ping that checks it is up.
		expect(clients.commands.map((c) => c[0])).toEqual(['ping', 'lease', 'ping', 'release']);
	});
});

describe('table', () => {
	test('lines up columns', () => {
		const out = table([record as never], 'previews.example.net');
		const [head, row] = out.split('\n');
		expect(head?.indexOf('STATUS')).toBe(row?.indexOf('running'));
		expect(table([], 'previews.example.net')).toBe('no previews\n');
	});
});

describe('koi executable', () => {
	const repoRoot = join(import.meta.dir, '../../..');
	const koi = (...args: string[]) =>
		Bun.spawnSync([process.execPath, 'packages/cli/src/main.ts', ...args], { cwd: repoRoot });

	test('prints the version and exits 0', () => {
		const result = koi('version');
		expect(result.stdout.toString()).toBe(`koi ${VERSION}\n`);
		expect(result.stderr.toString()).toBe('');
		expect(result.exitCode).toBe(0);
	});

	// SIGINT ends the command and closes the host first: the SSH master's
	// directory is removed and no ssh is left connecting. The target is a
	// port that accepts the connection and never speaks, so ssh would wait
	// its 30 seconds; the control directory under TMPDIR shows that it was
	// started.
	test.skipIf(process.platform !== 'linux' || Bun.which('ssh') === null)(
		'SIGINT closes the host the command opened and exits 130',
		async () => {
			const dir = await mkdtemp(join(tmpdir(), 'koi-signal-'));
			const home = join(dir, 'home');
			const tmp = join(dir, 'tmp');
			await mkdir(join(home, '.config', 'koi'), { recursive: true, mode: 0o700 });
			await mkdir(tmp);
			await writeFile(join(dir, 'id'), 'not a key\n', { mode: 0o600 });
			const silent = createServer(() => {});
			const port = await new Promise<number>((resolve) =>
				silent.listen(0, '127.0.0.1', () => {
					const a = silent.address();
					resolve(typeof a === 'object' && a !== null ? a.port : 0);
				}),
			);
			try {
				await writeFile(
					join(home, '.config', 'koi', 'config.yaml'),
					toYaml({
						version: 1,
						defaultTarget: 'silent',
						targets: {
							silent: {
								domain: 'silent.example.com',
								transport: {
									kind: 'ssh',
									endpoint: {
										host: '127.0.0.1',
										port,
										user: 'koi-connect',
										identityFile: join(dir, 'id'),
										knownHostsFile: join(dir, 'known_hosts'),
										hostKeyAlias: 'silent',
									},
								},
								power: { kind: 'always-on' },
							},
						},
					}),
					{ mode: 0o600 },
				);
				const proc = Bun.spawn(
					[process.execPath, join(repoRoot, 'packages/cli/src/main.ts'), 'list'],
					{
						cwd: dir,
						env: { PATH: process.env.PATH ?? '', HOME: home, TMPDIR: tmp },
						stdin: 'ignore',
						stdout: 'pipe',
						stderr: 'pipe',
					},
				);
				let started: string[] = [];
				for (let i = 0; i < 400 && started.length === 0; i++) {
					await Bun.sleep(25);
					started = (await readdir(tmp)).filter((n) => n.startsWith('koi-ssh-'));
				}
				expect(started).toHaveLength(1);
				const began = Date.now();
				proc.kill('SIGINT');
				const code = await proc.exited;
				const stderr = await new Response(proc.stderr as ReadableStream).text();
				expect(code).toBe(130);
				expect(Date.now() - began).toBeLessThan(10_000);
				expect(await readdir(tmp)).toEqual([]);
				expect(stderr).toContain('target silent');
			} finally {
				silent.close();
			}
		},
		20_000,
	);

	test('exits 2 for an unknown command', () => {
		const result = koi('bogus');
		expect(result.stdout.toString()).toBe('');
		expect(result.stderr.toString()).toContain('unknown command');
		expect(result.exitCode).toBe(2);
	});

	// Run from source, koi cannot undo what the runtime loaded from the
	// checkout, so it refuses to go on. The compiled binary loads nothing and
	// is exercised in environ.test.ts.
	test('from source, a checkout with a .env is refused unless the shell trusts it', async () => {
		const target = (domain: string) => ({
			domain,
			transport: { kind: 'aws-ssm' },
			aws: { instanceId: 'i-0abc', uploadsBucket: 'koi-uploads-123456789012' },
			power: { kind: 'ec2' },
		});
		const home = await mkdtemp(join(tmpdir(), 'koi-home-'));
		await mkdir(join(home, '.config', 'koi'), { recursive: true, mode: 0o700 });
		await writeFile(
			join(home, '.config', 'koi', 'config.yaml'),
			toYaml({
				version: 1,
				defaultTarget: 'mine',
				targets: { mine: target('mine.example.com') },
			}),
			{ mode: 0o600 },
		);
		// A checkout that tries to pick the file, the target and the instance.
		const checkout = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
		const injected = join(checkout, 'injected.yaml');
		await writeFile(
			injected,
			toYaml({
				version: 1,
				defaultTarget: 'evil',
				targets: { evil: target('evil.example.com') },
			}),
			{ mode: 0o600 },
		);
		await writeFile(
			join(checkout, '.env'),
			`KOI_CONFIG=${injected}\nKOI_TARGET=evil\nKOI_INSTANCE_ID=i-0bad\n`,
		);
		const env = { PATH: process.env.PATH ?? '', HOME: home };
		// The runtime does load that file into the environment before koi runs.
		const probe = join(await mkdtemp(join(tmpdir(), 'koi-probe-')), 'probe.ts');
		await writeFile(probe, 'console.log(process.env.KOI_CONFIG ?? "unset");\n');
		const loaded = Bun.spawnSync([process.execPath, 'run', probe], { cwd: checkout, env });
		expect(loaded.stdout.toString().trim()).toBe(injected);

		const show = (extra: Record<string, string> = {}) =>
			Bun.spawnSync(
				[process.execPath, join(repoRoot, 'packages/cli/src/main.ts'), 'config', 'show', '--json'],
				{ cwd: checkout, env: { ...env, ...extra } },
			);
		const refused = show();
		expect(refused.stdout.toString()).toBe('');
		expect(refused.stderr.toString()).toBe(
			`koi: koi was started from source in a checkout that has dotenv or bunfig files: .env in ${checkout}. Bun loads these files before koi runs, so they already took effect before koi could check them, and koi cannot tell what they changed. Run the compiled koi binary instead (bun run --filter @koi/cli build writes packages/cli/dist/koi), which loads neither, or run koi from a directory without such files. To run from source in a checkout you trust, export KOI_TRUST_CHECKOUT=1 in the shell before starting koi.\n`,
		);
		expect(refused.exitCode).toBe(1);

		// A developer who trusts the checkout: koi runs, with whatever the
		// checkout's .env set, which is that developer's choice.
		const trusted = show({ KOI_TRUST_CHECKOUT: '1' });
		expect(trusted.stderr.toString()).toBe('');
		expect(trusted.exitCode).toBe(0);
		expect(JSON.parse(trusted.stdout.toString())).toMatchObject({
			file: injected,
			target: 'evil',
			settings: { domain: 'evil.example.com', aws: { instanceId: 'i-0bad' } },
		});

		// help and version read nothing and run anywhere.
		const version = Bun.spawnSync(
			[process.execPath, join(repoRoot, 'packages/cli/src/main.ts'), 'version'],
			{ cwd: checkout, env },
		);
		expect(version.stdout.toString()).toBe(`koi ${VERSION}\n`);
		expect(version.exitCode).toBe(0);
	});

	// A call the transport stopped waiting for leaves the SDK's work behind:
	// the credential_process it spawned keeps running, and the runtime stays
	// alive for it. koi ends the process itself once its output is out. No
	// koi command puts a time limit on its operations yet. So this koi is
	// main() with one change: the wake is stopped as soon as the helper is
	// seen running. A timer could end the wake before the helper starts, and
	// then the test would prove nothing.
	test('ends once the command is done, while a credential helper it stopped waiting for still runs', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-helper-'));
		const home = join(dir, 'home');
		await mkdir(join(home, '.config', 'koi'), { recursive: true, mode: 0o700 });
		await writeFile(
			join(home, '.config', 'koi', 'config.yaml'),
			toYaml({
				version: 1,
				defaultTarget: 'mine',
				targets: {
					mine: {
						domain: 'mine.example.com',
						transport: { kind: 'aws-ssm' },
						aws: {
							profile: 'slow',
							instanceId: 'i-0abc',
							uploadsBucket: 'koi-uploads-123456789012',
						},
						power: { kind: 'ec2' },
					},
				},
			}),
			{ mode: 0o600 },
		);
		// The helper notes its pid, then sleeps far longer than the test allows.
		const pidFile = join(dir, 'helper.pid');
		const helper = join(dir, 'helper.sh');
		// The pid lands in one rename, so a reader never sees an empty file.
		await writeFile(
			helper,
			`#!/bin/sh\necho $$ > ${JSON.stringify(`${pidFile}.tmp`)}\nmv ${JSON.stringify(`${pidFile}.tmp`)} ${JSON.stringify(pidFile)}\nexec sleep 30\n`,
			{ mode: 0o755 },
		);
		await writeFile(join(dir, 'aws-config'), `[profile slow]\ncredential_process = ${helper}\n`);
		const koi = join(dir, 'koi-stopping.ts');
		await writeFile(
			koi,
			[
				`import { openHost } from ${JSON.stringify(join(repoRoot, 'packages/cli/src/host.ts'))};`,
				`import { main } from ${JSON.stringify(join(repoRoot, 'packages/cli/src/main.ts'))};`,
				'const stop = new AbortController();',
				`const pidFile = ${JSON.stringify(pidFile)};`,
				'void (async () => {',
				'	for (let i = 0; i < 1000; i++) {',
				'		const text = (await Bun.file(pidFile).exists()) ? await Bun.file(pidFile).text() : "";',
				'		if (/^[0-9]+\\n?$/.test(text) && Number(text) > 1) break;',
				'		await Bun.sleep(5);',
				'	}',
				"	stop.abort(new Error('stopped while the credential helper was running'));",
				'})();',
				'await main(process.argv.slice(2), {',
				'	cwd: process.cwd(),',
				'	box: async (ctx) => {',
				'		const { box, domain } = await openHost(ctx);',
				'		const ensureAwake: typeof box.ensureAwake = (progress, o) =>',
				'			box.ensureAwake(progress, { ...o, signal: stop.signal });',
				'		return { box: { ...box, ensureAwake }, domain };',
				'	},',
				'});',
			].join('\n'),
		);
		const began = Date.now();
		const result = Bun.spawnSync([process.execPath, koi, 'list'], {
			cwd: dir,
			env: {
				PATH: process.env.PATH ?? '',
				HOME: home,
				AWS_CONFIG_FILE: join(dir, 'aws-config'),
				AWS_SHARED_CREDENTIALS_FILE: join(dir, 'no-such-file'),
			},
			// Well above a prompt exit, and below the helper's sleep.
			timeout: 10_000,
		});
		const elapsed = Date.now() - began;
		// The helper was started, and still sleeps: koi did not wait for it.
		const pid = Number((await readFile(pidFile, 'utf8')).trim());
		// Never signal pid 0 (the whole process group) or 1 if the file is odd.
		expect(Number.isInteger(pid) && pid > 1).toBe(true);
		try {
			expect(result.stderr.toString()).toEndWith(
				'koi: stopped while the credential helper was running\n',
			);
			expect(result.stdout.toString()).toBe('');
			expect(result.exitCode).toBe(1);
			expect(elapsed).toBeLessThan(5000);
			expect(process.kill(pid, 0)).toBe(true);
		} finally {
			if (Number.isInteger(pid) && pid > 1) {
				try {
					process.kill(pid);
				} catch {}
			}
		}
	}, 15_000);

	test.skipIf(process.platform !== 'linux')(
		'a .env cannot grant itself KOI_TRUST_CHECKOUT: on Linux only the shell can',
		async () => {
			const checkout = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
			await writeFile(join(checkout, '.env'), 'KOI_TRUST_CHECKOUT=1\nKOI_TARGET=evil\n');
			const env = { PATH: process.env.PATH ?? '', HOME: '/nonexistent' };
			const result = Bun.spawnSync(
				[process.execPath, join(repoRoot, 'packages/cli/src/main.ts'), 'config', 'show'],
				{ cwd: checkout, env },
			);
			expect(result.stderr.toString()).toStartWith(
				`koi: koi was started from source in a checkout that has dotenv or bunfig files: .env in ${checkout}.`,
			);
			expect(result.exitCode).toBe(1);
		},
	);
});
