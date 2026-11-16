import { afterEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { closeSync, constants, openSync, read as readFd } from 'node:fs';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Artifact, Point, RunNetworkRecord } from '@koi/shared';
import { exec } from '../src/exec.ts';
import { RecorderDeadlineError } from '../src/recorder.ts';
import { SecretRegistry } from '../src/redact.ts';
import { judgePoint } from '../src/verdict.ts';
import { SNAPSHOT_LIMITS, snapshotInputs } from '../src/verification-snapshot.ts';
import { EvidenceStore, type RunWriter } from '../src/verification-store.ts';
import {
	classifyLine,
	IMAGE_ENV_ALLOWLIST,
	imageEnvProblems,
	inputVolumes,
	LineSplitter,
	mountProblems,
	type OutputItem,
	OutputReader,
	type PointExecution,
	type PointRecorder,
	type PointRun,
	PROTOCOL_LIMITS,
	ProtocolBudget,
	pointInputs,
	resolveRunnerImage,
	SUPERVISOR_SOURCE,
	supervisorExitCode,
	tarball,
	VerifierRunner,
	verifierEnv,
} from '../src/verifier.ts';
import {
	declaredSteps,
	FakeDocker,
	type FakeVerifier,
	Gate,
	request,
	signedSupervisorLine,
	supervisorExit,
	supervisorLine,
} from './fakes.ts';

const RUN = 'abcdefghijklmnop0123';
const AT = '2026-10-06T12:00:00.000Z';
const DEFAULT = `sha256:${'6'.repeat(64)}`;
const CURL = `sha256:${'7'.repeat(64)}`;
const sha = (bytes: Uint8Array | string) =>
	`sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const record: RunNetworkRecord = {
	version: 1,
	runId: RUN,
	network: `koi-v-${RUN}`,
	bridge: 'kv0123456789ab',
	subnet: '10.213.0.0/28',
	gateway: '10.213.0.1',
	appContainer: 'koi-hello-pr-7-aaaaaaaaaaaaaaaa1',
	appPort: 8080,
	state: 'ready',
	endpoints: [
		{
			role: 'app',
			container: 'koi-hello-pr-7-aaaaaaaaaaaaaaaa1',
			ip: '10.213.0.2',
			mac: '02:42:0a:d5:00:02',
		},
		{
			role: 'recorder',
			container: `koi-verify-${RUN}-recorder`,
			ip: '10.213.0.3',
			mac: '02:4b:0a:d5:00:03',
		},
		{
			role: 'verifier',
			container: `koi-verify-${RUN}-verifier`,
			ip: '10.213.0.4',
			mac: '02:4b:0a:d5:00:04',
		},
	],
	createdAt: AT,
};

const POINT: Point = {
	id: 'hello.home',
	revision: 1,
	claim: 'The home page says hello.',
	select: { paths: ['Dockerfile'] },
	requires: { fixtures: ['fixtures/probe.txt'] },
	setup: { command: ['sh', '-c', 'true'] },
	run: { command: ['python3', '.koi/runners/home.py'] },
	cleanup: { command: ['sh', '.koi/runners/clean.sh'] },
	assertions: [
		{ name: 'home-says-hello', description: 'GET / says hello.', evidence: ['screenshot'] },
	],
};

describe('image policy', () => {
	const docker = new FakeDocker();
	docker.imageInfos.set(DEFAULT, { id: DEFAULT, env: ['PATH=/usr/local/bin', 'LANG=C.UTF-8'] });
	docker.imageInfos.set('curlimages/curl:8.11.1', { id: CURL, env: ['PATH=/usr/bin'] });
	docker.imageInfos.set(`ghcr.io/acme/curl@${CURL}`, { id: CURL, env: ['PATH=/usr/bin'] });
	docker.imageInfos.set('acme/proxied:1', {
		id: `sha256:${'8'.repeat(64)}`,
		env: ['PATH=/usr/bin', 'HTTP_PROXY=http://proxy:3128', 'NPM_TOKEN=x'],
	});

	test('the default image resolves by its name, whatever the allowlist says', async () => {
		expect(
			await resolveRunnerImage(docker, 'koi-verifier', { defaultImageId: DEFAULT, allowed: [] }),
		).toEqual({ ok: true, digest: DEFAULT });
		expect(
			await resolveRunnerImage(docker, 'koi-verifier', {
				defaultImageId: `sha256:${'0'.repeat(64)}`,
				allowed: [],
			}),
		).toEqual({
			ok: false,
			reason: `verifier_unavailable: the default verifier image sha256:${'0'.repeat(64)} is not on the box`,
		});
	});

	test('another image must be on the box and on the allowlist, by reference, id or pinned reference', async () => {
		const policy = { defaultImageId: DEFAULT, allowed: [] as string[] };
		expect(await resolveRunnerImage(docker, 'curlimages/curl:8.11.1', policy)).toEqual({
			ok: false,
			reason: `image_not_allowed: curlimages/curl:8.11.1 (${CURL}) is not on this host's allowlist (KOI_VERIFIER_IMAGES)`,
		});
		for (const allowed of [
			['curlimages/curl:8.11.1'],
			[CURL],
			[`ghcr.io/acme/curl@${CURL}`],
			['other:1', CURL],
		]) {
			expect(
				await resolveRunnerImage(docker, 'curlimages/curl:8.11.1', { ...policy, allowed }),
			).toEqual({ ok: true, digest: CURL });
		}
		expect(
			await resolveRunnerImage(docker, 'curlimages/curl:8.11.1', {
				...policy,
				allowed: [`ghcr.io/acme/other@sha256:${'9'.repeat(64)}`],
			}),
		).toMatchObject({ ok: false });
		expect(await resolveRunnerImage(docker, 'nobody/runner:1', policy)).toEqual({
			ok: false,
			reason:
				'image_missing: nobody/runner:1 is not on the box; koid never pulls an image a pull request names',
		});
	});

	test('an image whose environment declares what a runtime does not need is refused', async () => {
		expect(
			await resolveRunnerImage(docker, 'acme/proxied:1', {
				defaultImageId: DEFAULT,
				allowed: ['acme/proxied:1'],
			}),
		).toEqual({
			ok: false,
			reason:
				'image_env_not_allowed: acme/proxied:1 declares HTTP_PROXY, NPM_TOKEN, which a runner image may not set',
		});
		expect(imageEnvProblems(['PATH=/x', 'PYTHON_VERSION=3.13.13', 'GPG_KEY=abc'])).toEqual([]);
		expect(
			imageEnvProblems(['AWS_SECRET_ACCESS_KEY=x', 'PATH=/x', 'AWS_SECRET_ACCESS_KEY=y']),
		).toEqual(['AWS_SECRET_ACCESS_KEY']);
		expect(IMAGE_ENV_ALLOWLIST.has('HTTP_PROXY')).toBe(false);
	});
});

describe('verifierEnv', () => {
	test('is exactly the design table, with the login key only when given', () => {
		const env = verifierEnv({
			runId: RUN,
			pointId: 'hello.home',
			attempt: 1,
			previewUrl: `http://app.${RUN}.invalid:8080`,
			recorderIp: '10.213.0.3',
			browserToken: 'a'.repeat(64),
			fixtures: { 'fixtures/probe.txt': '/fixtures/fixtures/probe.txt' },
			timeoutSeconds: 300,
			maxRequests: 20,
		});
		expect(env).toEqual({
			PATH: '/usr/local/bin:/usr/bin:/bin',
			HOME: '/tmp/home',
			TMPDIR: '/tmp',
			LANG: 'C.UTF-8',
			TZ: 'UTC',
			KOI_PROTOCOL_VERSION: '1',
			KOI_RUN_ID: RUN,
			KOI_POINT_ID: 'hello.home',
			KOI_ATTEMPT: '1',
			KOI_PREVIEW_URL: `http://app.${RUN}.invalid:8080`,
			KOI_RECORDER_WS: `ws://10.213.0.3:4317/${'a'.repeat(64)}`,
			KOI_FIXTURES: '{"fixtures/probe.txt":"/fixtures/fixtures/probe.txt"}',
			KOI_TIMEOUT_SECONDS: '300',
			KOI_MAX_REQUESTS: '20',
		});
		for (const name of Object.keys(env)) {
			expect(name).not.toMatch(/PROXY|AWS|GITHUB|DOCKER|SSH|LEASE|SOCKET/i);
		}
		expect(
			verifierEnv({
				runId: RUN,
				pointId: 'hello.home',
				attempt: 2,
				previewUrl: 'http://x',
				recorderIp: '10.213.0.3',
				browserToken: 't',
				fixtures: {},
				timeoutSeconds: 1,
				maxRequests: 0,
				loginKey: 'koi-abcdefghijklmnopqrstuvwx',
			}).KOI_LOGIN_KEY,
		).toBe('koi-abcdefghijklmnopqrstuvwx');
	});
});

describe('the tar stream', () => {
	test('is a ustar archive tar reads back, root-owned, with the modes given and long names', async () => {
		const long = `workspace/${'d'.repeat(60)}/${'e'.repeat(60)}/${'f'.repeat(60)}/file.txt`;
		const tar = tarball([
			{ path: 'koi', type: 'dir', mode: 0o555 },
			{
				path: 'koi/point.json',
				type: 'file',
				mode: 0o444,
				content: new TextEncoder().encode('{}\n'),
			},
			{ path: long, type: 'file', mode: 0o444, content: new TextEncoder().encode('deep') },
			{ path: 'workspace/empty', type: 'file', mode: 0o444 },
		]);
		expect(tar.length % 512).toBe(0);
		const dir = await mkdtemp(join(tmpdir(), 'koid-tar-'));
		await writeFile(join(dir, 'in.tar'), tar);
		const listed = await exec(['tar', '-tvf', join(dir, 'in.tar')], { timeoutMs: 15_000 });
		expect(listed.code).toBe(0);
		const lines = listed.stdout.trim().split('\n');
		expect(lines[0]).toMatch(/^dr-xr-xr-x root\/root\s+0 .* koi\/$/);
		expect(lines[1]).toMatch(/^-r--r--r-- root\/root\s+3 .* koi\/point\.json$/);
		expect(lines[2]).toMatch(new RegExp(`${'f'.repeat(60)}/file\\.txt$`));
		const extracted = await exec(['tar', '-xf', join(dir, 'in.tar'), '-C', dir], {
			timeoutMs: 15_000,
		});
		expect(extracted.code).toBe(0);
		expect(await Bun.file(join(dir, long)).text()).toBe('deep');
		expect(await Bun.file(join(dir, 'koi/point.json')).text()).toBe('{}\n');
		// Deterministic: the same entries make the same bytes.
		expect(sha(tarball([{ path: 'a', type: 'dir', mode: 0o555 }]))).toBe(
			sha(tarball([{ path: 'a', type: 'dir', mode: 0o555 }])),
		);
		for (const path of ['/abs', 'a/../b', 'a//b', 'a\\b']) {
			expect(() => tarball([{ path, type: 'file', mode: 0o444 }])).toThrow();
		}
		// The archive's read-only directories would otherwise outlive the test.
		await exec(['chmod', '-R', 'u+w', dir], { timeoutMs: 15_000 });
		await rm(dir, { recursive: true, force: true });
	});
});

// A snapshot source tree as the deployer leaves it.
async function sourceTree(): Promise<{
	source: string;
	fixtures: Array<{ path: string; digest: string }>;
}> {
	const source = await mkdtemp(join(tmpdir(), 'koid-verifier-src-'));
	for (const dir of ['points', 'runners', 'fixtures']) {
		await mkdir(join(source, '.koi', dir), { recursive: true });
	}
	await writeFile(join(source, '.koi/verify.yaml'), 'version: 1\n');
	await writeFile(join(source, '.koi/points/home.yaml'), 'id: hello.home\n');
	await writeFile(join(source, '.koi/runners/home.py'), 'print("hi")\n');
	await writeFile(join(source, '.koi/fixtures/probe.txt'), 'probe');
	await writeFile(join(source, 'koi.yaml'), 'port: 8080\n');
	return { source, fixtures: [{ path: '.koi/fixtures/probe.txt', digest: sha('probe') }] };
}

describe('pointInputs', () => {
	test('copies the supervisor, the point file, the snapshot and the fixtures, read-only and root-owned', async () => {
		const { source, fixtures } = await sourceTree();
		const inputs = await pointInputs({
			source,
			fixtures,
			point: POINT,
			runnerCommand: ['python3'],
			timeoutSeconds: 300,
		});
		const { tarEntries } = await import('./fakes.ts');
		const files = tarEntries(inputs.tar);
		expect([...files.keys()]).toEqual([
			'koi',
			'koi/supervisor.py',
			'koi/point.json',
			'workspace',
			'workspace/.koi',
			'workspace/.koi/fixtures',
			'workspace/.koi/fixtures/probe.txt',
			'workspace/.koi/points',
			'workspace/.koi/points/home.yaml',
			'workspace/.koi/runners',
			'workspace/.koi/runners/home.py',
			'workspace/.koi/verify.yaml',
			'workspace/koi.yaml',
			'fixtures',
			'fixtures/fixtures',
			'fixtures/fixtures/probe.txt',
		]);
		expect(files.get('koi/supervisor.py')?.content).toBe(SUPERVISOR_SOURCE);
		expect(JSON.parse(files.get('koi/point.json')?.content ?? '')).toEqual({
			version: 1,
			runner: ['python3'],
			steps: {
				setup: ['sh', '-c', 'true'],
				run: ['python3', '.koi/runners/home.py'],
				cleanup: ['sh', '.koi/runners/clean.sh'],
			},
			timeoutSeconds: 300,
		});
		for (const [path, entry] of files) {
			expect([path, entry.mode]).toEqual([path, entry.type === 'dir' ? 0o555 : 0o444]);
		}
		expect(inputs.fixtures).toEqual({ 'fixtures/probe.txt': '/fixtures/fixtures/probe.txt' });
		// The fixture's five bytes count once, though it is in both volumes.
		expect(inputs.bytes).toBe(
			'version: 1\n'.length +
				'id: hello.home\n'.length +
				'print("hi")\n'.length +
				5 +
				'port: 8080\n'.length,
		);
	});

	test('a script executable in the snapshot is 0555 in the archive, and every other file 0444', async () => {
		const { source, fixtures } = await sourceTree();
		await writeFile(join(source, '.koi/runners/check.sh'), '#!/bin/sh\necho checked\n', {
			mode: 0o700,
		});
		await chmod(join(source, '.koi/fixtures/probe.txt'), 0o755);
		const inputs = await pointInputs({
			source,
			fixtures,
			point: POINT,
			runnerCommand: undefined,
			timeoutSeconds: 1,
		});
		const { tarEntries } = await import('./fakes.ts');
		const files = tarEntries(inputs.tar);
		expect(files.get('workspace/.koi/runners/check.sh')?.mode).toBe(0o555);
		expect(files.get('workspace/.koi/fixtures/probe.txt')?.mode).toBe(0o555);
		expect(files.get('fixtures/fixtures/probe.txt')?.mode).toBe(0o555);
		expect(files.get('workspace/.koi/runners/home.py')?.mode).toBe(0o444);
		expect(files.get('koi/supervisor.py')?.mode).toBe(0o444);
		// No file a runner can write, whatever it was.
		for (const [path, entry] of files) {
			expect([path, entry.mode & 0o222]).toEqual([path, 0]);
		}
	});

	test('a script that was executable in the tree runs by its path from the archive', async () => {
		// What the reviewer saw: a valid command of a script by its path failed
		// with EACCES. Through the snapshot and the archive to a real exec.
		const root = await mkdtemp(join(tmpdir(), 'koid-verifier-exec-'));
		try {
			const tree = join(root, 'tree');
			await mkdir(join(tree, '.koi/points'), { recursive: true });
			await mkdir(join(tree, '.koi/runners'), { recursive: true });
			await writeFile(
				join(tree, '.koi/verify.yaml'),
				'version: 1\npoints:\n  - points/*.yaml\nprofiles:\n  pr:\n    always: [hello.check]\nrunner:\n  image: koi-verifier\n',
			);
			await writeFile(
				join(tree, '.koi/points/check.yaml'),
				`id: hello.check
revision: 1
claim: The check runs.
select:
  paths: [Dockerfile]
run:
  command: [.koi/runners/check.sh]
assertions:
  - name: checked
    description: The script ran.
    evidence: [aria]
`,
			);
			await writeFile(join(tree, '.koi/runners/check.sh'), '#!/bin/sh\necho checked\n', {
				mode: 0o755,
			});
			await writeFile(join(root, 'source.tar.gz'), 'tarball');
			const kept = join(root, 'kept');
			await snapshotInputs(kept, {
				deploymentId: 'd'.repeat(20),
				request: request({ label: 'hello-pr-7' }),
				source: tree,
				tarball: join(root, 'source.tar.gz'),
			});
			const inputs = await pointInputs({
				source: join(kept, 'source'),
				fixtures: [],
				point: { ...POINT, requires: undefined },
				runnerCommand: undefined,
				timeoutSeconds: 1,
			});
			const out = join(root, 'out');
			await mkdir(out);
			await writeFile(join(root, 'inputs.tar'), inputs.tar);
			await exec(['tar', '-xf', join(root, 'inputs.tar'), '-C', out]);
			const ran = Bun.spawn(['./.koi/runners/check.sh'], {
				cwd: join(out, 'workspace'),
				stdout: 'pipe',
			});
			expect(await ran.exited).toBe(0);
			expect(await new Response(ran.stdout).text()).toBe('checked\n');
		} finally {
			// The extracted directories are 0555, which rm cannot empty.
			await exec(['chmod', '-R', 'u+w', root]);
			await rm(root, { recursive: true, force: true });
		}
	});

	test('names /fixtures even when the point has no fixtures, so its mode reaches the volume', async () => {
		const { source, fixtures } = await sourceTree();
		const { requires: _requires, ...bare } = POINT;
		const { tar, fixtures: map } = await pointInputs({
			source,
			fixtures,
			point: bare,
			runnerCommand: undefined,
			timeoutSeconds: 1,
		});
		const { tarEntries } = await import('./fakes.ts');
		expect(tarEntries(tar).get('fixtures')).toMatchObject({ type: 'dir', mode: 0o555 });
		expect(map).toEqual({});
	});

	describe('the 64 MiB limit', () => {
		// A tree of three fixtures of 12 MiB each, under the limit a snapshot holds.
		const bigFixtures = async (mib: number[]) => {
			const { source } = await sourceTree();
			const names = mib.map((_, i) => `fixtures/big-${i}.bin`);
			const fixtures: Array<{ path: string; digest: string }> = [];
			for (const [i, name] of names.entries()) {
				const body = new Uint8Array((mib[i] as number) * 1024 ** 2).fill(i + 1);
				await writeFile(join(source, '.koi', name), body);
				fixtures.push({ path: `.koi/${name}`, digest: sha(body) });
			}
			return { source, fixtures, names };
		};
		const needing = (fixtures: string[]) => ({ ...POINT, requires: { fixtures } });

		test('counts a fixture once, so a snapshot that fits runs', async () => {
			const { source, fixtures, names } = await bigFixtures([12, 12, 12]);
			const inputs = await pointInputs({
				source,
				fixtures,
				point: needing(names),
				runnerCommand: undefined,
				timeoutSeconds: 1,
			});
			const { tarEntries } = await import('./fakes.ts');
			const files = tarEntries(inputs.tar);
			const unique = 36 * 1024 ** 2;
			expect(inputs.bytes).toBeGreaterThanOrEqual(unique);
			expect(inputs.bytes).toBeLessThan(unique + 1024);
			for (const name of names) {
				expect(files.get(`workspace/.koi/${name}`)?.content?.length).toBe(12 * 1024 ** 2);
				expect(files.get(`fixtures/${name}`)?.content?.length).toBe(12 * 1024 ** 2);
			}
			// What the volumes take: every fixture twice, and little else.
			expect(inputs.tar.length).toBeLessThan(2 * SNAPSHOT_LIMITS.totalBytes);
			expect(inputs.tar.length).toBeGreaterThan(2 * unique);
		}, 60_000);

		test('still refuses a tree past the limit', async () => {
			const { source, fixtures, names } = await bigFixtures([16, 16, 16, 16, 1]);
			await expect(
				pointInputs({
					source,
					fixtures,
					point: needing(names),
					runnerCommand: undefined,
					timeoutSeconds: 1,
				}),
			).rejects.toThrow('inputs_too_large');
		}, 60_000);

		test('a fixture listed many times is one copy, so a point cannot grow the archive', async () => {
			const { source, fixtures, names } = await bigFixtures([12]);
			const name = names[0] as string;
			const inputs = await pointInputs({
				source,
				fixtures,
				point: needing(Array.from({ length: 1000 }, () => name)),
				runnerCommand: undefined,
				timeoutSeconds: 1,
			});
			expect(inputs.tar.length).toBeLessThan(25 * 1024 ** 2);
			expect(inputs.fixtures).toEqual({ [name]: `/fixtures/${name}` });
		}, 60_000);
	});

	test('refuses a fixture the snapshot did not record, or whose bytes changed', async () => {
		const { source, fixtures } = await sourceTree();
		await expect(
			pointInputs({
				source,
				fixtures: [],
				point: POINT,
				runnerCommand: undefined,
				timeoutSeconds: 1,
			}),
		).rejects.toThrow('fixture_missing');
		await writeFile(join(source, '.koi/fixtures/probe.txt'), 'changed');
		await expect(
			pointInputs({ source, fixtures, point: POINT, runnerCommand: undefined, timeoutSeconds: 1 }),
		).rejects.toThrow('fixture_mismatch');
	});
});

describe('reading the protocol', () => {
	const KEY = 'k'.repeat(64);

	test('classifies a log line, an event, a supervisor line and what is malformed', () => {
		expect(classifyLine('plain text', KEY)).toEqual({ kind: 'log', text: 'plain text' });
		expect(classifyLine('{"type":"note","text":"hi"}\r', KEY)).toEqual({
			kind: 'event',
			event: { type: 'note', text: 'hi' },
		});
		expect(classifyLine(signedSupervisorLine(KEY, 1, { event: 'started' }), KEY)).toEqual({
			kind: 'supervisor',
			line: { version: 1, type: 'supervisor', event: 'started' },
			seq: 1,
		});
		expect(classifyLine('{not json', KEY)).toEqual({
			kind: 'malformed',
			reason: 'a line that starts with a brace is not JSON',
		});
		expect(classifyLine('{"type":"verdict","outcome":"pass"}', KEY)).toEqual({
			kind: 'malformed',
			reason: 'an event the protocol does not read (type)',
		});
		expect(classifyLine('{"type":"note","text":"x","extra":1}', KEY)).toMatchObject({
			kind: 'malformed',
		});
		expect(classifyLine('[1,2]', KEY)).toEqual({ kind: 'log', text: '[1,2]' });
	});

	test('a line that says it is the supervisor is believed only when the key signed it', () => {
		const line = signedSupervisorLine(KEY, 2, {
			event: 'exit',
			step: 'run',
			status: 'exited',
			code: 0,
			steps: [{ step: 'run', status: 'exited', code: 0 }],
		});
		expect(classifyLine(line, KEY)).toMatchObject({ kind: 'supervisor', seq: 2 });
		const forged = {
			kind: 'malformed' as const,
			reason: "a supervisor line without the point's signature",
		};
		// No MAC at all, as a runner would print one.
		expect(
			classifyLine(
				'{"version":1,"type":"supervisor","event":"exit","status":"exited","steps":[]}',
				KEY,
			),
		).toEqual(forged);
		expect(classifyLine('{"type":"supervisor","event":"exit"}', KEY)).toEqual(forged);
		// Signed with any other key.
		expect(classifyLine(line, 'x'.repeat(64))).toEqual(forged);
		// A real line with a word changed: the MAC covers the text.
		expect(classifyLine(line.replace('"code":0,"steps"', '"code":1,"steps"'), KEY)).toEqual(forged);
		// Signed, but not what a supervisor prints.
		expect(classifyLine(signedSupervisorLine(KEY, 1, { event: 'nope' }), KEY)).toEqual({
			kind: 'malformed',
			reason: 'a supervisor line of the wrong shape',
		});
	});

	test('a line over the bound is discarded whole, and the rest still read', () => {
		const s = new LineSplitter(16);
		const encode = (t: string) => new TextEncoder().encode(t);
		expect(s.push(encode('short\n'))).toEqual([{ text: 'short' }]);
		expect(s.push(encode('x'.repeat(20)))).toEqual([{ discarded: true }]);
		expect(s.push(encode('y'.repeat(20)))).toEqual([]);
		expect(s.push(encode('\nafter\n'))).toEqual([{ text: 'after' }]);
		expect(s.push(encode('a'))).toEqual([]);
		expect(s.end()).toEqual([{ text: 'a' }]);
		expect(s.push(encode(`${'z'.repeat(17)}\nok\n`))).toEqual([
			{ discarded: true },
			{ text: 'ok' },
		]);
	});

	test('a line with no end holds no more than the bound, however much of it comes', () => {
		const s = new LineSplitter(16);
		const held = () => (s as unknown as { pending: string }).pending.length;
		const piece = new TextEncoder().encode('x'.repeat(1024));
		expect(s.push(piece)).toEqual([{ discarded: true }]);
		for (let i = 0; i < 10; i++) {
			expect(s.push(piece)).toEqual([]);
			expect(held()).toBeLessThanOrEqual(16);
		}
		expect(s.push(new TextEncoder().encode('\nok\n'))).toEqual([{ text: 'ok' }]);
	});

	test('the budget stops on the total, the event rate and malformed lines', () => {
		let at = 0;
		const b = new ProtocolBudget(
			{
				bytesPerPoint: 10_000,
				eventsPerSecond: 2,
				eventsBurst: 3,
				malformedPerPoint: 2,
			},
			() => at,
		);
		expect(b.countBytes(10_000)).toBeUndefined();
		expect(b.countBytes(1)).toBe('the runner wrote more than 10000 bytes');
		expect(b.bytes).toBe(10_001);
		expect(b.countEvent()).toBeUndefined();
		expect(b.countEvent()).toBeUndefined();
		expect(b.countEvent()).toBeUndefined();
		expect(b.countEvent()).toBe('the runner sent more than 2 events per second');
		at += 1000;
		expect(b.countEvent()).toBeUndefined();
		expect(b.countMalformed()).toBeUndefined();
		expect(b.countMalformed()).toBeUndefined();
		expect(b.countMalformed()).toBe(
			'the runner printed more than 2 lines that look like protocol lines and are not',
		);
		expect(b.malformed).toBe(3);
	});

	test('the supervisor exit code follows the worst step, as supervisor.py computes it', () => {
		const line = (steps: Array<Record<string, unknown>>, status = 'exited') =>
			({ version: 1, type: 'supervisor', event: 'exit', status, steps }) as never;
		expect(supervisorExitCode(line([{ step: 'run', status: 'exited', code: 0 }]))).toBe(0);
		expect(supervisorExitCode(line([{ step: 'run', status: 'exited', code: 1 }]))).toBe(1);
		expect(supervisorExitCode(line([{ step: 'run', status: 'signalled', signal: 9 }]))).toBe(1);
		expect(
			supervisorExitCode(
				line([
					{ step: 'run', status: 'exited', code: 1 },
					{ step: 'cleanup', status: 'timeout' },
				]),
			),
		).toBe(2);
		expect(supervisorExitCode(line([{ step: 'run', status: 'failed' }]))).toBe(3);
		expect(supervisorExitCode(line([], 'failed'))).toBe(3);
		expect(supervisorExitCode(line([], 'not-started'))).toBe(4);
	});
});

// A recorder that answers captures from memory, as the session would.
class FakeRecorder implements PointRecorder {
	calls: string[] = [];
	// Captures of these kinds come back withheld, as the session withholds
	// them in version 1.
	withheld = new Set<string>(['trace', 'har', 'file']);
	constructor(
		private readonly writer: RunWriter,
		private readonly pointId: string,
	) {}
	private async entry(kind: Artifact['kind'], label: string): Promise<Artifact> {
		this.calls.push(`${kind} ${label}`);
		if (this.withheld.has(kind)) {
			return this.writer.recordArtifact({
				pointId: this.pointId,
				attempt: 1,
				kind,
				capturedAt: AT,
				eventRange: { first: 0, last: 0 },
				redaction: {
					status: 'withheld',
					policyDigest: sha('policy'),
					removedFields: [],
					limitations: ['not in version 1'],
				},
			});
		}
		return this.writer.writeArtifact(
			{
				pointId: this.pointId,
				attempt: 1,
				kind,
				mediaType: 'text/plain',
				capturedAt: AT,
				eventRange: { first: 0, last: 0 },
				redaction: {
					status: 'sanitized',
					policyDigest: sha('policy'),
					removedFields: [],
					limitations: [],
				},
			},
			new TextEncoder().encode(`${kind} ${label}`),
		);
	}
	capture(r: { kind: Artifact['kind']; label: string }) {
		return this.entry(r.kind, r.label);
	}
	read(r: { path: string }) {
		return this.entry('http-response', `read ${r.path}`);
	}
}

// Writers the tests opened, closed after each.
const open: RunWriter[] = [];
afterEach(async () => {
	for (const writer of open.splice(0)) await writer.abandon().catch(() => {});
});

async function setup(
	options: {
		pollMs?: number;
		limits?: Record<string, number>;
		sleep?: (ms: number) => Promise<void>;
		// Runs as the firewall is reapplied, with the options koid gave. A test that
		// ignores the signal is the helper holding on after the point stopped.
		reapply?: (o?: { signal?: AbortSignal | undefined }) => Promise<void>;
	} = {},
) {
	const { source, fixtures } = await sourceTree();
	const root = await mkdtemp(join(tmpdir(), 'koid-verifier-'));
	let clock = Date.parse(AT);
	const now = () => new Date(clock);
	const evidence = new EvidenceStore({
		stateDir: root,
		now,
		diskSpace: async () => ({ free: 60 * 1024 ** 3, size: 80 * 1024 ** 3 }),
	});
	await evidence.init();
	const writer = await evidence.openRun(RUN);
	open.push(writer);
	const docker = new FakeDocker();
	await docker.createNetwork({
		name: record.network,
		bridge: record.bridge,
		subnet: record.subnet,
		gateway: record.gateway,
		labels: { 'koi.run': RUN },
	});
	// The placeholder the run network made.
	await docker.createVerifier({
		name: `koi-verify-${RUN}-verifier`,
		image: DEFAULT,
		network: record.network,
		ip: '10.213.0.4',
		mac: '02:4b:0a:d5:00:04',
		runId: RUN,
		appHost: { name: `app.${RUN}.invalid`, ip: '10.213.0.2' },
		dns: record.gateway,
		env: {},
	});
	const reapplied: string[] = [];
	const reapplies: Array<{ bound: unknown; running: boolean | undefined }> = [];
	const logs: string[] = [];
	const secrets = new SecretRegistry();
	const runner = new VerifierRunner({
		docker,
		network: {
			async reapply(runId, o) {
				reapplied.push(runId);
				reapplies.push({
					bound: o?.bound,
					running: docker.containers.get(`koi-verify-${RUN}-verifier`)?.running,
				});
				await options.reapply?.(o);
			},
		},
		secrets,
		now,
		sleep:
			options.sleep ??
			(async (ms) => {
				clock += ms;
			}),
		log: (m) => logs.push(m),
		pollMs: options.pollMs ?? 5,
		limits: options.limits,
	});
	const recorder = new FakeRecorder(writer, POINT.id);
	let cancel: string | undefined;
	const events = async () => {
		const text = await Bun.file(join(writer.dir, 'events.ndjson')).text();
		return text
			.split('\n')
			.filter((l) => l !== '')
			.map((l) => JSON.parse(l) as Record<string, unknown>);
	};
	const execution: PointExecution = {
		runId: RUN,
		pointId: POINT.id,
		attempt: 1,
		point: POINT,
		runnerCommand: undefined,
		image: CURL,
		record,
		browserToken: 'b'.repeat(64),
		source,
		fixtures,
		timeoutSeconds: 300,
		maxRequests: 20,
		pointDeadline: clock + 300_000,
		deadline: clock + 900_000,
	};
	return {
		docker,
		writer,
		recorder,
		runner,
		secrets,
		logs,
		reapplied,
		reapplies,
		execution,
		advance: (ms: number) => {
			clock += ms;
		},
		cancel: (why: string) => {
			cancel = why;
		},
		run: (more: Partial<PointExecution> = {}) =>
			runner.run({ ...execution, ...more }, recorder, writer, { stopRequested: () => cancel }),
		events,
		// Resolves once koid has read a log line of the runner's and kept it.
		logged: async (text: string) => {
			while (!(await events()).some((e) => e.type === 'runner-log' && e.text === text)) {
				await Bun.sleep(1);
			}
		},
	};
}

// Budgets far past anything a test reaches on its fake clock.
const FAR_BUDGET = {
	timeoutSeconds: 86_400,
	pointDeadline: Date.parse(AT) + 86_400_000,
	deadline: Date.parse(AT) + 2 * 86_400_000,
};

// Moves the fake clock until `running` settles. The drain stamps its start when
// it sees the exit, which a test cannot observe, and a single advance made before
// the stamp would never reach the limit. Time that keeps passing reaches it either
// way. Use it with FAR_BUDGET, so that only the drain can end the point.
async function whileTimePasses<T>(t: { advance(ms: number): void }, running: Promise<T>) {
	const clock = setInterval(() => t.advance(1_000), 1);
	try {
		return await running;
	} finally {
		clearInterval(clock);
	}
}

// A recorder call that never answers: pending until its signal ends it. A signal
// already over ends it at once, as the real calls do (recorder.ts, guarded).
function endedBy(signal: AbortSignal | undefined, why: string): Promise<Artifact> {
	return new Promise<Artifact>((_, reject) => {
		if (signal?.aborted) reject(new Error(why));
		signal?.addEventListener('abort', () => reject(new Error(why)), { once: true });
	});
}

describe('OutputReader', () => {
	const encode = (text: string) => new TextEncoder().encode(text);
	// A stream that gives `chunks` as fast as they are asked for, and counts
	// what was taken. Nothing handles what the reader holds in these tests, as
	// when the handler is stuck on a capture.
	const given = (chunks: Iterable<Uint8Array>) => {
		const source = chunks[Symbol.iterator]();
		const seen = { chunks: 0 };
		const stream = new ReadableStream<Uint8Array>(
			{
				pull(controller) {
					const next = source.next();
					if (next.done) {
						controller.close();
						return;
					}
					seen.chunks += 1;
					controller.enqueue(next.value);
				},
			},
			{ highWaterMark: 0 },
		);
		return { stream, seen };
	};
	const none = () => given([]).stream;
	function* repeat(chunk: Uint8Array, times: number) {
		for (let i = 0; i < times; i++) yield chunk;
	}
	const reader = (
		stdout: ReadableStream<Uint8Array>,
		limits: Partial<typeof PROTOCOL_LIMITS>,
		stderr = none(),
	) => {
		const limited: string[] = [];
		const ending = new AbortController();
		const budget = new ProtocolBudget(limits, () => 0);
		const output = new OutputReader(
			{ stdout, stderr },
			budget,
			() => 0,
			ending.signal,
			(why) => limited.push(why),
			() => undefined,
		);
		return { output, limited, budget, ending };
	};
	// A handler that keeps up: takes everything until both streams have ended.
	const ended = async (output: OutputReader) => {
		const seen: OutputItem[] = [];
		let open = 2;
		while (open > 0) {
			const item = output.next();
			if (item === undefined) await Promise.race([output.arrival(), Bun.sleep(5)]);
			else {
				seen.push(item);
				if (item.kind === 'end') open -= 1;
			}
		}
		return seen;
	};
	// A handler that takes nothing, until the reader has had all of the stream.
	const stalledUntilTaken = async (seen: { chunks: number }, chunks: number) => {
		while (seen.chunks < chunks) await Bun.sleep(1);
		await Bun.sleep(1);
	};

	test('counts each complete line as it arrives, and over a bound stops and keeps nothing more', async () => {
		const limited: string[] = [];
		const counted: string[] = [];
		const out = given([encode('one\ntwo\nthree\nfour\n')]);
		const output = new OutputReader(
			{ stdout: out.stream, stderr: none() },
			new ProtocolBudget({}, () => 0),
			() => 0,
			new AbortController().signal,
			(why) => limited.push(why),
			(_stream, line) => {
				const text = 'text' in line ? line.text : '';
				counted.push(text);
				return text === 'two' ? 'over a bound' : undefined;
			},
		);
		const items = await ended(output);
		expect(limited).toEqual(['over a bound']);
		expect(counted).toEqual(['one', 'two']);
		expect(items.filter((i) => i.kind === 'line')).toHaveLength(1);
	});

	test('hands over complete lines of both streams in the order read, and the end of each stream', async () => {
		const out = given([encode('one\ntw'), encode('o\nno newline')]);
		const err = given([encode('oops\n')]);
		const { output } = reader(out.stream, {}, err.stream);
		const items = await ended(output);
		const of = (stream: string) =>
			items.flatMap((i) => (i.stream === stream && i.kind === 'line' ? [i.line] : []));
		expect(of('stdout')).toEqual([{ text: 'one' }, { text: 'two' }, { text: 'no newline' }]);
		expect(of('stderr')).toEqual([{ text: 'oops' }]);
		expect(items.filter((i) => i.kind === 'end')).toEqual([
			{ kind: 'end', stream: 'stderr', failed: false },
			{ kind: 'end', stream: 'stdout', failed: false },
		]);
	});

	test('a stream that breaks is an end that failed', async () => {
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.error(new Error('the client went away'));
			},
		});
		const { output } = reader(stream, {});
		const items = await ended(output);
		expect(items).toContainEqual({ kind: 'end', stream: 'stdout', failed: true });
	});

	test('past the total it stops once, keeps nothing more, and reads on to the end of the stream', async () => {
		const line = encode(`${'x'.repeat(1023)}\n`);
		const out = given(repeat(line, 64));
		const { output, limited, budget } = reader(out.stream, { bytesPerPoint: 8 * 1024 });
		await stalledUntilTaken(out.seen, 64);
		expect(limited).toEqual(['the runner wrote more than 8192 bytes']);
		// Every chunk was taken, so a process still writing does not block or build
		// up in the pipe, and none past the limit was counted or kept.
		expect(out.seen.chunks).toBe(64);
		expect(budget.bytes).toBe(9 * 1024);
		expect(output.peakBytes).toBeLessThanOrEqual(8 * (1024 + 128));
	});

	test('past the queue bound it stops, however little of the total was used', async () => {
		const line = encode(`${'x'.repeat(1023)}\n`);
		const out = given(repeat(line, 64));
		const { output, limited, budget } = reader(out.stream, { queueBytes: 4096 });
		await stalledUntilTaken(out.seen, 64);
		expect(limited).toEqual([
			"the runner's output outran koid: over 4096 bytes waited to be handled",
		]);
		expect(output.peakBytes).toBeLessThanOrEqual(4096);
		expect(budget.bytes).toBeLessThan(8 * 1024);
		expect(out.seen.chunks).toBe(64);
	});

	test('a flood of empty lines reaches the queue bound through what each line costs', async () => {
		const out = given(repeat(encode('\n'.repeat(1024)), 1024));
		const { output, limited, budget } = reader(out.stream, {});
		await stalledUntilTaken(out.seen, 1024);
		expect(limited[0]).toContain('outran koid');
		// Under the bytes bound by far: a queue that counted only bytes would have
		// taken every one of the million lines here.
		expect(budget.bytes).toBeLessThan(PROTOCOL_LIMITS.queueBytes / 64);
		const held = output.drain().filter((i) => i.kind === 'line');
		expect(held.length * 129).toBeLessThanOrEqual(PROTOCOL_LIMITS.queueBytes);
		expect(held.length * 129).toBeGreaterThan(PROTOCOL_LIMITS.queueBytes - 129);
	});

	test('what the handler takes makes room, so a runner that koid keeps up with is never stopped', async () => {
		const line = encode(`${'x'.repeat(1023)}\n`);
		const out = given(repeat(line, 256));
		const { output, limited, budget } = reader(out.stream, {
			queueBytes: 8 * 1024,
			bytesPerPoint: 1024 ** 2,
		});
		await ended(output);
		expect(limited).toEqual([]);
		expect(budget.bytes).toBe(256 * 1024);
	});

	test('after the signal it keeps nothing, and what was queued stays until it is drained', async () => {
		let send = (_chunk: Uint8Array) => {};
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				send = (chunk) => controller.enqueue(chunk);
			},
		});
		const { output, ending, limited } = reader(stream, { bytesPerPoint: 16 });
		send(encode('before\n'));
		await output.arrival();
		ending.abort();
		send(encode('after, and past the total\n'));
		await Bun.sleep(1);
		expect(limited).toEqual([]);
		expect(output.drain().filter((i) => i.kind === 'line')).toEqual([
			{ kind: 'line', stream: 'stdout', line: { text: 'before' }, bytes: 7 },
		]);
		expect(output.next()).toBeUndefined();
		output.close();
	});
});

describe('VerifierRunner', () => {
	test('creates the verifier from the image with the supervisor as entrypoint, copies the inputs, starts it, reapplies the permits, and sends start', async () => {
		const t = await setup();
		let created: FakeVerifier | undefined;
		t.docker.verifierScript = async (v) => {
			created = v;
			const start = JSON.parse(await v.nextLine());
			expect(start).toEqual({
				version: 1,
				type: 'start',
				key: expect.any(String),
				timeoutSeconds: 300,
			});
			expect(start.key).toMatch(/^[0-9a-f]{64}$/);
			// The firewall was reapplied before start was sent.
			expect(t.reapplied).toEqual([RUN]);
			v.out(supervisorLine({ event: 'started' }));
			for (const line of supervisorExit([
				{ step: 'setup', status: 'exited', code: 0 },
				{ step: 'run', status: 'exited', code: 0 },
				{ step: 'cleanup', status: 'exited', code: 0 },
			]))
				v.out(line);
			return 0;
		};
		const result = await t.run();
		expect(result.stopped).toBe('exited');
		expect(result.blocked).toBeUndefined();
		expect(result.failures).toEqual([]);
		expect(result.cleanup).toBe('succeeded');
		expect(result.exit).toEqual({ status: 'exited', exitCode: 0, oomKilled: false });
		const v = created as FakeVerifier;
		expect(v.options.image).toBe(CURL);
		expect(v.options.entrypoint).toBe('python3');
		expect(v.options.command).toEqual(['-I', '/koi/supervisor.py', '/koi/point.json']);
		expect(v.options.workdir).toBe('/workspace');
		expect(v.options.ip).toBe('10.213.0.4');
		expect(v.options.appHost).toEqual({ name: `app.${RUN}.invalid`, ip: '10.213.0.2' });
		expect(v.env).toEqual(
			verifierEnv({
				runId: RUN,
				pointId: 'hello.home',
				attempt: 1,
				previewUrl: `http://app.${RUN}.invalid:8080`,
				recorderIp: '10.213.0.3',
				browserToken: 'b'.repeat(64),
				fixtures: { 'fixtures/probe.txt': '/fixtures/fixtures/probe.txt' },
				timeoutSeconds: 300,
				maxRequests: 20,
			}),
		);
		expect(v.files.get('koi/supervisor.py')?.content).toBe(SUPERVISOR_SOURCE);
		expect(v.files.get('fixtures/fixtures/probe.txt')?.content).toBe('probe');
		// The inputs reached it through volumes it mounts read-only, filled
		// through a staging container that went first. Nothing was copied into
		// the verifier, whose root is read-only.
		const verifier = `koi-verify-${RUN}-verifier`;
		const staging = `koi-verify-${RUN}-staging`;
		const volumes = ['koi', 'workspace', 'fixtures'].map((p) => `koi-verify-${RUN}-inputs-${p}`);
		expect(v.options.volumes).toEqual([
			{ name: volumes[0] as string, destination: '/koi' },
			{ name: volumes[1] as string, destination: '/workspace' },
			{ name: volumes[2] as string, destination: '/fixtures' },
		]);
		expect(t.docker.stagings).toEqual([
			{ name: staging, image: CURL, runId: RUN, volumes: v.options.volumes ?? [] },
		]);
		expect(t.docker.events.filter((e) => /verifier|staging|volume/.test(e))).toEqual([
			`created verifier ${verifier}`,
			`removed ${verifier}`,
			...volumes.map((n) => `created volume ${n}`),
			`created staging ${staging}`,
			`copied into ${staging}:/`,
			`removed ${staging}`,
			`created verifier ${verifier}`,
			`started ${verifier} 172.19.0.2`,
			`exited ${verifier} 0`,
			`removed ${verifier}`,
			...volumes.map((n) => `removed volume ${n}`),
		]);
		expect(t.docker.containers.has(verifier)).toBe(false);
		expect(t.docker.containers.has(staging)).toBe(false);
		expect(t.docker.volumes.size).toBe(0);
		expect((await t.events()).map((e) => e.type)).toEqual([
			'verifier-created',
			'verifier-started',
			'supervisor-started',
			'supervisor-step',
			'supervisor-step',
			'supervisor-step',
			'supervisor-exit',
			'verifier-stopped',
		]);
	});

	test('answers captures and reads with the artifact, refuses a repeated label, and keeps the events scrubbed', async () => {
		const t = await setup();
		t.secrets.add('b'.repeat(64));
		const acks: string[] = [];
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out('{"type":"capture","kind":"screenshot","label":"home"}');
			acks.push(await v.nextLine());
			v.out('{"type":"read","label":"state","path":"/api/state"}');
			acks.push(await v.nextLine());
			v.out('{"type":"capture","kind":"aria","label":"home"}');
			acks.push(await v.nextLine());
			v.out('{"type":"capture","kind":"trace","label":"trace"}');
			acks.push(await v.nextLine());
			v.out(`{"type":"note","text":"the token is ${'b'.repeat(64)}"}`);
			v.out('{"type":"phase","name":"journey","state":"end"}');
			v.out(
				'{"type":"assertion","point":"hello.home","name":"home-says-hello","outcome":"pass","evidence":["recorder:screenshot:1","capture:state"],"detail":"saw it"}',
			);
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const result = await t.run();
		expect(acks).toEqual([
			'{"version":1,"type":"capture-result","label":"home","status":"ready","artifact":"recorder:screenshot:1"}',
			'{"version":1,"type":"capture-result","label":"state","status":"ready","artifact":"recorder:http-response:2"}',
			'{"version":1,"type":"capture-result","label":"home","status":"failed","error":"duplicate_label"}',
			'{"version":1,"type":"capture-result","label":"trace","status":"failed","error":"withheld"}',
		]);
		expect(t.recorder.calls).toEqual([
			'screenshot home',
			'http-response read /api/state',
			'trace trace',
		]);
		expect(result.artifacts).toEqual({
			home: 'recorder:screenshot:1',
			state: 'recorder:http-response:2',
		});
		expect(result.reports).toEqual([
			{
				name: 'home-says-hello',
				outcome: 'pass',
				evidence: ['recorder:screenshot:1', 'capture:state'],
				detail: 'saw it',
			},
		]);
		expect(result.recovery).toBe(false);
		expect(result.counts).toMatchObject({ events: 7, captures: 3, malformed: 0 });
		const events = await t.events();
		const note = events.find((e) => e.type === 'runner-note');
		expect(note?.text).toBe('the token is [redacted]');
		expect(events.some((e) => JSON.stringify(e).includes('b'.repeat(64)))).toBe(false);
		expect(events.filter((e) => e.type === 'runner-capture-answered').map((e) => e.status)).toEqual(
			['ready', 'failed', 'failed'],
		);
	});

	test('an assertion for another point or an undeclared one is a protocol diagnostic, not a report', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(
				'{"type":"assertion","point":"other.point","name":"home-says-hello","outcome":"pass","evidence":[]}',
			);
			v.out(
				'{"type":"assertion","point":"hello.home","name":"made-up","outcome":"pass","evidence":[]}',
			);
			v.out('{"type":"verdict","outcome":"pass"}');
			v.out(`{"type":"note","text":"${'x'.repeat(9000)}"}`);
			v.out('log line');
			v.err('an error line');
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const result = await t.run();
		expect(result.reports).toEqual([]);
		expect(result.counts.malformed).toBe(4);
		expect(result.failures).toEqual([]);
		const diagnostics = (await t.events())
			.filter((e) => e.type === 'runner-protocol-diagnostic')
			.map((e) => e.reason);
		expect(diagnostics).toEqual([
			'an assertion for point other.point, not the active point',
			'an assertion made-up the point does not declare',
			'an event the protocol does not read (type)',
			'a stdout line over 8192 bytes was discarded',
		]);
		// The two streams are read as they come; their order is not fixed.
		const logs = (await t.events()).filter((e) => e.type === 'runner-log');
		expect(logs.map((e) => `${e.stream}: ${e.text}`).sort()).toEqual([
			'stderr: an error line',
			'stdout: log line',
		]);
	});

	test('an assertion citing too many references is a failure, so nothing can hide past a cut', async () => {
		const t = await setup();
		const refs = (count: number) => Array.from({ length: count }, () => 'capture:shot');
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			const assertion = (evidence: string[]) =>
				JSON.stringify({
					type: 'assertion',
					point: 'hello.home',
					name: 'home-says-hello',
					outcome: 'pass',
					evidence,
				});
			v.out(assertion([...refs(100), 'capture:nothing']));
			v.out(assertion(refs(100)));
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const result = await t.run();
		// The report at the limit counts as it was sent, whole. The one past it is a failure,
		// and a pass reported after it does not take that back.
		expect(result.reports.map((r) => [r.outcome, r.evidence.length])).toEqual([
			['fail', 0],
			['pass', 100],
		]);
		expect(result.counts.malformed).toBe(0);
		const diagnostics = (await t.events())
			.filter((e) => e.type === 'runner-protocol-diagnostic')
			.map((e) => e.reason);
		expect(diagnostics).toEqual([
			'the report of home-says-hello: it cites 101 references, over the 100 allowed',
		]);
	});

	test('a flood of malformed lines or events stops the verifier with runner_protocol_limit', async () => {
		const t = await setup({ limits: { malformedPerPoint: 3 } });
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (let i = 0; i < 10; i++) v.out('{"type":"nope"}');
			await v.stopped;
			return 137;
		};
		const result = await t.run();
		expect(result.stopped).toBe('protocol-limit');
		expect(result.failures).toEqual([
			'runner_protocol_limit: the runner printed more than 3 lines that look like protocol lines and are not',
		]);
		expect(t.docker.verifiers[0]?.detached).toBe(true);

		const u = await setup({ limits: { eventsPerSecond: 1, eventsBurst: 2 } });
		u.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (let i = 0; i < 10; i++) v.out('{"type":"note","text":"n"}');
			await v.stopped;
			return 137;
		};
		const flood = await u.run();
		expect(flood.stopped).toBe('protocol-limit');
		expect(flood.failures[0]).toBe(
			'runner_protocol_limit: the runner sent more than 1 events per second',
		);

		const w = await setup({ limits: { bytesPerPoint: 100 } });
		w.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out('x'.repeat(200));
			await v.stopped;
			return 137;
		};
		const bytes = await w.run();
		expect(bytes.stopped).toBe('protocol-limit');
		expect(bytes.failures[0]).toBe('runner_protocol_limit: the runner wrote more than 100 bytes');
	});

	test('a burst under the bounds is handled with no wait, whatever its rate', async () => {
		let waits = 0;
		const t = await setup({
			limits: { bytesPerPoint: 10_000 },
			sleep: async () => {
				waits += 1;
			},
		});
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (let i = 0; i < 5; i++) v.out('y'.repeat(90));
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const result = await t.run();
		expect(result.stopped).toBe('exited');
		expect(result.counts.logLines).toBe(5);
		expect(result.counts.bytes).toBeGreaterThan(450);
		expect(waits).toBe(0);
	});

	describe('koid handling what the runner wrote', () => {
		const CAPTURE = '{"type":"capture","kind":"screenshot","label":"slow"}';
		const HANDLING =
			'handling_timeout: the verifier exited in time, and koid ran out of time handling what it wrote';
		const NOTE = '{"type":"note","text":"n"}';
		// Runs `hook` as the first event of a type is about to be recorded.
		const onEvent = (
			t: Awaited<ReturnType<typeof setup>>,
			type: string,
			hook: () => Promise<void>,
		) => {
			const appendEvent = t.writer.appendEvent.bind(t.writer);
			let seen = false;
			t.writer.appendEvent = async (event) => {
				if (event.type === type && !seen) {
					seen = true;
					await hook();
				}
				return appendEvent(event);
			};
		};

		test('4 MiB of log, a passing assertion and an exit in time pass, with koid past the watchdog on the queue', async () => {
			const t = await setup({ limits: { logLinesPerPoint: 10 } });
			const exited = Promise.withResolvers<void>();
			// Slow disk: past the point's budget and its stop grace, the time the
			// watchdog gives a runner that has not exited.
			onEvent(t, 'runner-log', async () => {
				await exited.promise;
				await Bun.sleep(2);
				t.advance(20_000);
			});
			const line = new TextEncoder().encode(`${'y'.repeat(1023)}\n`);
			let artifact = '';
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out('{"type":"capture","kind":"screenshot","label":"shot"}');
				artifact = (JSON.parse(await v.nextLine()) as { artifact: string }).artifact;
				// Five seconds of the point are left.
				t.advance(295_000);
				for (let i = 0; i < 4096; i++) v.write(line);
				v.out(
					JSON.stringify({
						type: 'assertion',
						point: POINT.id,
						name: 'home-says-hello',
						outcome: 'pass',
						evidence: [artifact],
					}),
				);
				for (const l of supervisorExit(declaredSteps(v))) v.out(l);
				exited.resolve();
				return 0;
			};
			const result = await t.run();
			expect(result.stopped).toBe('exited');
			expect(result.blocked).toBeUndefined();
			expect(result.failures).toEqual([]);
			expect(result.exit?.exitCode).toBe(0);
			expect(result.counts.logLines).toBe(4096);
			expect(result.counts.bytes).toBeGreaterThan(4 * 1024 ** 2);
			expect(result.reports.map((r) => r.outcome)).toEqual(['pass']);
			const verdict = judgePoint({
				id: POINT.id,
				assertions: POINT.assertions.map((a) => ({ name: a.name, evidence: a.evidence })),
				reports: result.reports,
				resolve: await t.writer.resolveEvidence([artifact]),
				blocked: result.blocked,
				cleanup: result.cleanup,
				recovery: result.recovery,
				failures: result.failures,
			});
			expect(verdict.outcome).toBe('pass');
		});

		test('a signed failure koid is recording when the watchdog fires still counts', async () => {
			const t = await setup();
			const recording = new Gate();
			onEvent(t, 'supervisor-step', () => recording.pass());
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				// More than a burst of 128 KiB, the most the old allowance gave.
				for (let i = 0; i < 40; i++) v.out('x'.repeat(8000));
				v.out(supervisorLine({ event: 'started' }));
				v.out(
					supervisorLine({ event: 'step', step: 'run', status: 'exited', code: 1, seconds: 1 }),
				);
				await recording.reached;
				t.advance(316_000);
				await v.stopped;
				recording.release();
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('timeout');
			expect(result.steps.map((s) => s.step)).toEqual(['run']);
			expect(result.failures).toEqual(['runner_failed: the run step exited 1']);
			expect(result.blocked).toStartWith('point_timeout: ');
		});

		test('a signed failure still queued when the watchdog fires during handling counts', async () => {
			const t = await setup();
			const logging = new Gate();
			onEvent(t, 'runner-log', () => logging.pass());
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out('a line koid is writing when the watchdog fires');
				v.out(supervisorLine({ event: 'started' }));
				v.out(
					supervisorLine({ event: 'step', step: 'run', status: 'exited', code: 1, seconds: 1 }),
				);
				await logging.reached;
				await Bun.sleep(2);
				t.advance(316_000);
				await v.stopped;
				logging.release();
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('timeout');
			expect(result.failures).toEqual(['runner_failed: the run step exited 1']);
		});

		test('a signed line that cannot be recorded does not lose the ones queued behind it', async () => {
			const t = await setup();
			const logging = new Gate();
			onEvent(t, 'runner-log', () => logging.pass());
			onEvent(t, 'supervisor-started', async () => {
				throw new Error('ENOSPC: no space left on device');
			});
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out('a line koid is writing when the watchdog fires');
				v.out(supervisorLine({ event: 'started' }));
				v.out(
					supervisorLine({ event: 'step', step: 'run', status: 'exited', code: 1, seconds: 1 }),
				);
				await logging.reached;
				await Bun.sleep(2);
				t.advance(316_000);
				await v.stopped;
				logging.release();
				return 137;
			};
			const result = await t.run();
			expect(result.failures).toEqual(['runner_failed: the run step exited 1']);
			expect(t.logs.join('\n')).toContain('ENOSPC');
		});

		test('a stuck capture after the exit has an end, and the time is not the runner', async () => {
			const t = await setup();
			const out = new Gate();
			t.recorder.capture = ((_r: unknown, o?: { signal?: AbortSignal | undefined }) => {
				void out.pass();
				return endedBy(o?.signal, 'the signal ended it');
			}) as typeof t.recorder.capture;
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				// Near the end of its budget, so koid's time is what ends the point.
				t.advance(295_000);
				v.out(CAPTURE);
				for (const l of supervisorExit(declaredSteps(v))) v.out(l);
				await out.reached;
				// Past koid's time on the queue, once the exit is noted.
				void Bun.sleep(5).then(() => t.advance(61_000));
				return 0;
			};
			const result = await t.run();
			expect(result.blocked).toBe(HANDLING);
			expect(result.stopped).toBe('exited');
			// The signed lines behind the capture count all the same.
			expect(result.supervisor?.steps.map((s) => s.step)).toEqual(['setup', 'run', 'cleanup']);
			expect(result.cleanup).toBe('succeeded');
			expect((await t.events()).at(-1)).toMatchObject({ type: 'verifier-stopped', how: 'exited' });
		});

		test('the exit does not shorten the time the point had for what is queued', async () => {
			const t = await setup();
			const out = new Gate();
			const capture = t.recorder.capture.bind(t.recorder);
			t.recorder.capture = async (r) => {
				await out.pass();
				return capture(r);
			};
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(CAPTURE);
				for (const l of supervisorExit(declaredSteps(v))) v.out(l);
				await out.reached;
				// Well past 60 seconds from the exit, and well inside the budget.
				void Bun.sleep(5).then(() => {
					t.advance(120_000);
					void Bun.sleep(20).then(() => out.release());
				});
				return 0;
			};
			const result = await t.run();
			expect(result.blocked).toBeUndefined();
			expect(result.artifacts.slow).toBeDefined();
			expect(result.failures).toEqual([]);
		});

		test('a capture the recorder refuses past the budget, asked for by a runner that exited in time, is koid running out', async () => {
			const t = await setup();
			const exited = Promise.withResolvers<void>();
			onEvent(t, 'runner-log', async () => {
				await exited.promise;
				await Bun.sleep(2);
			});
			t.recorder.capture = (async () => {
				throw new RecorderDeadlineError("the point's time is up");
			}) as typeof t.recorder.capture;
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out('a line ahead of the capture');
				v.out(CAPTURE);
				for (const l of supervisorExit(declaredSteps(v))) v.out(l);
				exited.resolve();
				return 0;
			};
			const result = await t.run();
			expect(result.blocked).toBe(HANDLING);
			expect(result.stopped).toBe('exited');
		});

		test('events queued behind a long capture are not a burst the runner made', async () => {
			const t = await setup({ limits: { eventsPerSecond: 2, eventsBurst: 3 } });
			const gate = new Gate();
			const capture = t.recorder.capture.bind(t.recorder);
			t.recorder.capture = async (r) => {
				await gate.pass();
				return capture(r);
			};
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(CAPTURE);
				await gate.reached;
				// One a second, within the rate, and all handled at once below.
				for (let i = 0; i < 10; i++) {
					v.out(NOTE);
					await Bun.sleep(1);
					t.advance(1_000);
				}
				gate.release();
				await v.nextLine();
				for (const l of supervisorExit(declaredSteps(v))) v.out(l);
				return 0;
			};
			const result = await t.run();
			expect(result.stopped).toBe('exited');
			expect(result.failures).toEqual([]);
			expect(result.counts.events).toBe(11);
		});

		test('a flood of events stops the point on arrival, however busy the handler is', async () => {
			const t = await setup({ limits: { eventsPerSecond: 2, eventsBurst: 3 } });
			const out = new Gate();
			t.recorder.capture = ((_r: unknown, o?: { signal?: AbortSignal | undefined }) => {
				void out.pass();
				return endedBy(o?.signal, 'the signal ended it');
			}) as typeof t.recorder.capture;
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(CAPTURE);
				await out.reached;
				for (let i = 0; i < 10; i++) v.out(NOTE);
				await v.stopped;
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('protocol-limit');
			expect(result.failures).toEqual([
				'runner_protocol_limit: the runner sent more than 2 events per second',
			]);
			// None of the notes was handled: the capture held the handler to the end.
			expect(result.counts.events).toBe(1);
		});

		test('lines that are not protocol lines stop the point on arrival, however busy the handler is', async () => {
			const t = await setup({ limits: { malformedPerPoint: 2 } });
			const out = new Gate();
			t.recorder.capture = ((_r: unknown, o?: { signal?: AbortSignal | undefined }) => {
				void out.pass();
				return endedBy(o?.signal, 'the signal ended it');
			}) as typeof t.recorder.capture;
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(CAPTURE);
				await out.reached;
				v.out('{not json');
				v.out('{"type":"nope"}');
				v.out(
					'{"type":"assertion","point":"other.point","name":"home-says-hello","outcome":"pass","evidence":[]}',
				);
				await v.stopped;
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('protocol-limit');
			expect(result.failures).toEqual([
				'runner_protocol_limit: the runner printed more than 2 lines that look like protocol lines and are not',
			]);
			expect(result.reports).toEqual([]);
		});
	});

	test('a Docker that does not answer in the cleanup costs the point nothing it read', async () => {
		const t = await setup();
		const gate = new Gate();
		t.docker.onStop = () => gate.pass();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(supervisorLine({ event: 'started' }));
			v.out(supervisorLine({ event: 'step', step: 'run', status: 'exited', code: 1, seconds: 1 }));
			return 1;
		};
		const running = t.run();
		await gate.reached;
		t.advance(61_000);
		const result = await running;
		expect(result.stuck).toBe(true);
		expect(result.failures).toContain('runner_failed: the run step exited 1');
		expect(t.docker.verifiers[0]?.detached).toBe(true);
		expect((await t.events()).at(-1)).toMatchObject({ type: 'verifier-stopped', how: 'exited' });
		gate.release();
	});

	describe('a firewall reapply that does not come back', () => {
		const verifier = `koi-verify-${RUN}-verifier`;
		const stuck = async () => {
			const gate = new Gate();
			let signal: AbortSignal | undefined;
			const t = await setup({
				reapply: async (o) => {
					signal = o?.signal;
					await gate.pass();
				},
			});
			t.docker.verifierScript = async (v) => {
				await v.stopped;
				return 137;
			};
			return { t, gate, signal: () => signal };
		};

		test('a cancel ends the wait, the verifier goes, and no start is sent', async () => {
			const { t, gate, signal } = await stuck();
			const running = t.run();
			await gate.reached;
			t.cancel('the run was cancelled');
			const result = await running;
			expect(result.stopped).toBe('cancelled');
			expect(result.blocked).toBe('cancelled: the run was cancelled');
			expect(t.docker.containers.has(verifier)).toBe(false);
			expect(t.docker.verifiers[0]?.key).toBeUndefined();
			// The network has the signal, so one still queued for the lock is dropped.
			expect(signal()?.aborted).toBe(true);
			gate.release();
			await Bun.sleep(1);
			expect(t.logs.join('\n')).toContain('finished after the point stopped waiting');
		});

		test("the point's deadline ends the wait the same way", async () => {
			const { t, gate } = await stuck();
			const running = t.run();
			await gate.reached;
			t.advance(316_000);
			const result = await running;
			expect(result.stopped).toBe('timeout');
			expect(result.blocked).toBe(
				'point_timeout: the point reached its budget of 300 seconds before the runner ended',
			);
			expect(t.docker.containers.has(verifier)).toBe(false);
			expect(t.docker.verifiers[0]?.key).toBeUndefined();
			gate.release();
		});

		test("the run's deadline ends the wait the same way", async () => {
			const { t, gate } = await stuck();
			const running = t.run({ deadline: Date.parse(AT) + 10_000 });
			await gate.reached;
			t.advance(10_000);
			const result = await running;
			expect(result.stopped).toBe('timeout');
			expect(result.blocked).toStartWith('point_timeout: ');
			expect(t.docker.containers.has(verifier)).toBe(false);
			gate.release();
		});
	});

	test('the point budget stops a runner that does not end, and the point is blocked', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(supervisorLine({ event: 'started' }));
			t.advance(316_000);
			await v.stopped;
			return 137;
		};
		const result = await t.run();
		expect(result.stopped).toBe('timeout');
		expect(result.blocked).toBe(
			'point_timeout: the point reached its budget of 300 seconds before the runner ended',
		);
		expect(result.failures).toEqual([]);
		expect(result.cleanup).toBe('not-run');
		expect(result.exit?.exitCode).toBe(137);
		expect(t.docker.containers.has(`koi-verify-${RUN}-verifier`)).toBe(false);
		expect((await t.events()).at(-1)).toMatchObject({ type: 'verifier-stopped', how: 'timeout' });
	});

	describe('one deadline for the point', () => {
		// Time passes on the test's clock as the inputs are staged.
		const slowStaging = (t: Awaited<ReturnType<typeof setup>>, ms: number) => {
			const createStaging = t.docker.createStaging.bind(t.docker);
			t.docker.createStaging = async (o) => {
				t.advance(ms);
				return createStaging(o);
			};
		};

		test('the supervisor gets what is left when the verifier starts, and the watchdog works to it', async () => {
			const t = await setup();
			slowStaging(t, 40_000);
			let told: Record<string, unknown> = {};
			let env: string | undefined;
			t.docker.verifierScript = async (v) => {
				told = JSON.parse(await v.nextLine());
				env = v.env.KOI_TIMEOUT_SECONDS;
				// Past what is left and its grace, and nowhere near a fresh 300
				// seconds from here, which is what a clock started now would give.
				t.advance(100_000 - 40_000 + 15_000 + 1);
				await v.stopped;
				return 137;
			};
			const result = await t.run({ pointDeadline: Date.parse(AT) + 100_000 });
			expect(told.timeoutSeconds).toBe(60);
			expect(env).toBe('60');
			expect(result.stopped).toBe('timeout');
			expect(result.blocked).toBe(
				'point_timeout: the point reached its budget of 300 seconds before the runner ended',
			);
		});

		test('the time the firewall and a slow start took comes off too', async () => {
			const t = await setup({ reapply: async () => t.advance(10_000) });
			let told: Record<string, unknown> = {};
			t.docker.verifierScript = async (v) => {
				told = JSON.parse(await v.nextLine());
				for (const line of supervisorExit(declaredSteps(v))) v.out(line);
				return 0;
			};
			await t.run({ pointDeadline: Date.parse(AT) + 30_000 });
			expect(told.timeoutSeconds).toBe(20);
		});

		test('a part of a second left is told as it is, and rounded up for the steps', async () => {
			const t = await setup();
			let told: Record<string, unknown> = {};
			let env: string | undefined;
			t.docker.verifierScript = async (v) => {
				told = JSON.parse(await v.nextLine());
				env = v.env.KOI_TIMEOUT_SECONDS;
				for (const line of supervisorExit(declaredSteps(v))) v.out(line);
				return 0;
			};
			await t.run({ pointDeadline: Date.parse(AT) + 1_500 });
			expect(told.timeoutSeconds).toBe(1.5);
			expect(env).toBe('2');
		});

		test('nothing left blocks the point without a verifier', async () => {
			const t = await setup();
			const result = await t.run({ pointDeadline: Date.parse(AT) });
			expect(result.stopped).toBe('timeout');
			expect(result.blocked).toBe(
				'point_timeout: the point reached its budget of 300 seconds before its verifier started',
			);
			expect(t.docker.stagings).toEqual([]);
			expect(t.docker.verifiers).toEqual([]);
			expect(result.cleanup).toBe('not-run');
		});

		test('nothing left once the inputs are staged blocks it too, and they go', async () => {
			const t = await setup();
			slowStaging(t, 100_000);
			const result = await t.run({ pointDeadline: Date.parse(AT) + 100_000 });
			expect(result.blocked).toBe(
				'point_timeout: the point reached its budget of 300 seconds before its verifier started',
			);
			expect(t.docker.stagings).toHaveLength(1);
			expect(t.docker.verifiers).toEqual([]);
			expect(t.docker.containers.has(`koi-verify-${RUN}-staging`)).toBe(false);
			expect(t.docker.volumes.size).toBe(0);
		});

		test('nothing left once the firewall is bound sends no start', async () => {
			const t = await setup({ reapply: async () => t.advance(30_000) });
			t.docker.verifierScript = async (v) => {
				await v.stopped;
				return 137;
			};
			const result = await t.run({ pointDeadline: Date.parse(AT) + 30_000 });
			expect(result.stopped).toBe('timeout');
			expect(result.blocked).toContain('point_timeout: ');
			expect(t.docker.verifiers[0]?.key).toBeUndefined();
			expect(t.docker.containers.has(`koi-verify-${RUN}-verifier`)).toBe(false);
		});
	});

	describe('the preparation under the signal', () => {
		const staging = `koi-verify-${RUN}-staging`;
		const verifierName = `koi-verify-${RUN}-verifier`;
		const inTeardown = (t: Awaited<ReturnType<typeof setup>>) => {
			expect(t.docker.containers.has(staging)).toBe(false);
			expect(t.docker.containers.has(verifierName)).toBe(false);
			expect(t.docker.volumes.size).toBe(0);
			expect(t.docker.verifiers).toEqual([]);
		};

		test('a cancel during staging ends the copy, and the staging container and volumes go', async () => {
			const t = await setup();
			const gate = new Gate();
			t.docker.copyGate = gate;
			const running = t.run();
			await gate.reached;
			// Mid-copy, the staging container and the volumes are there.
			expect(t.docker.containers.has(staging)).toBe(true);
			expect(t.docker.volumes.size).toBe(3);
			t.cancel('the run was cancelled');
			// The gate never opens: only the signal can end this copy.
			const result = await running;
			expect(result.stopped).toBe('cancelled');
			expect(result.blocked).toBe('cancelled: the run was cancelled');
			inTeardown(t);
			expect(t.docker.prepareSignals.at(-1)?.aborted).toBe(true);
		});

		test('the point deadline during staging ends the copy with no grace, and everything goes', async () => {
			const t = await setup();
			const gate = new Gate();
			t.docker.copyGate = gate;
			const running = t.run({ pointDeadline: Date.parse(AT) + 10_000 });
			await gate.reached;
			t.advance(10_000);
			const result = await running;
			expect(result.stopped).toBe('timeout');
			expect(result.blocked).toBe(
				'point_timeout: the point reached its budget of 300 seconds before its verifier started',
			);
			inTeardown(t);
		});

		test("every Docker call of the preparation holds the point's signal", async () => {
			const t = await setup();
			const signals: Record<string, AbortSignal | undefined> = {};
			const remove = t.docker.remove.bind(t.docker);
			t.docker.remove = async (name, signal) => {
				signals[`remove ${name}`] ??= signal;
				return remove(name, signal);
			};
			const removeVolume = t.docker.removeVolume.bind(t.docker);
			t.docker.removeVolume = async (name, signal) => {
				signals[`remove volume ${name}`] ??= signal;
				return removeVolume(name, signal);
			};
			const createVerifier = t.docker.createVerifier.bind(t.docker);
			t.docker.createVerifier = async (o, signal) => {
				signals.createVerifier = signal;
				return createVerifier(o);
			};
			const mounts = t.docker.mounts.bind(t.docker);
			t.docker.mounts = async (name, signal) => {
				signals.mounts = signal;
				return mounts(name);
			};
			const result = await t.run();
			expect(result.stopped).toBe('exited');
			const held = [...Object.values(signals), ...t.docker.prepareSignals];
			expect(held.length).toBeGreaterThan(8);
			for (const signal of held) expect(signal).toBeInstanceOf(AbortSignal);
			expect(new Set(held).size).toBe(1);
		});

		test('a cancel that comes as the last call of the preparation returns starts nothing', async () => {
			const t = await setup({ pollMs: 3_600_000 });
			const mounts = t.docker.mounts.bind(t.docker);
			t.docker.mounts = async (name) => {
				// Ahead of the timer, which is too far off to see it.
				t.cancel('the run was cancelled');
				return mounts(name);
			};
			const result = await t.run();
			expect(result.stopped).toBe('cancelled');
			expect(result.blocked).toBe('cancelled: the run was cancelled');
			inTeardown(t);
		});

		test('a run that is already cancelled prepares nothing', async () => {
			const t = await setup();
			t.cancel('the run was cancelled');
			const result = await t.run();
			expect(result.blocked).toBe('cancelled: the run was cancelled');
			expect(t.docker.stagings).toEqual([]);
			expect(t.docker.verifiers).toEqual([]);
		});

		test('a teardown Docker call holds no signal, so the stop cannot end it', async () => {
			const t = await setup();
			const gate = new Gate();
			t.docker.copyGate = gate;
			const after: Array<AbortSignal | undefined> = [];
			const running = t.run();
			await gate.reached;
			const removeVolume = t.docker.removeVolume.bind(t.docker);
			t.docker.removeVolume = async (name, signal) => {
				after.push(signal);
				return removeVolume(name, signal);
			};
			t.cancel('the run was cancelled');
			await running;
			expect(after).toEqual([undefined, undefined, undefined]);
		});
	});

	test("the run's deadline bounds the point before its own budget does", async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			t.advance(20_000);
			await v.stopped;
			return 137;
		};
		const result = await t.run({ deadline: Date.parse(AT) + 10_000 });
		expect(result.stopped).toBe('timeout');
	});

	test('a cancel stops the verifier', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			t.cancel('the run was cancelled');
			await v.stopped;
			return 137;
		};
		const result = await t.run();
		expect(result.stopped).toBe('cancelled');
		expect(result.blocked).toBe('cancelled: the run was cancelled');
	});

	test('a step that fails, a cleanup that fails, and a supervisor that lies are failures', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit([
				{ step: 'setup', status: 'exited', code: 0 },
				{ step: 'run', status: 'exited', code: 2 },
				{ step: 'cleanup', status: 'timeout' },
			]))
				v.out(line);
			return 2;
		};
		const failed = await t.run();
		// A real failure, and then a cleanup out of time: the failure stands,
		// and the cleanup reads as under the watchdog's stop.
		expect(failed.failures).toEqual(['runner_failed: the run step exited 2']);
		expect(failed.blocked).toContain('point_timeout: the cleanup step');
		expect(failed.cleanup).toBe('not-run');

		const u = await setup();
		u.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit([
				{ step: 'setup', status: 'failed', reason: 'sh: not found' },
				{ step: 'run', status: 'skipped', reason: 'setup did not exit 0' },
				{ step: 'cleanup', status: 'exited', code: 0 },
			]))
				v.out(line);
			return 3;
		};
		const skipped = await u.run();
		expect(skipped.failures).toEqual([
			'setup_failed: the setup step could not start: sh: not found',
			'runner_failed: the run step was skipped: setup did not exit 0',
		]);
		expect(skipped.cleanup).toBe('succeeded');

		// A runner that prints an exit line claiming success and exits 1: the
		// container's exit code says otherwise.
		const w = await setup();
		w.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 1;
		};
		const lied = await w.run();
		expect(lied.failures).toEqual([
			"supervisor_mismatch: the supervisor's exit line implies exit code 0, and the container exited 1",
		]);

		// The other way round: an account of a failure and a container that
		// says all went well.
		const y = await setup();
		y.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit([
				{ step: 'setup', status: 'exited', code: 0 },
				{ step: 'run', status: 'exited', code: 1 },
				{ step: 'cleanup', status: 'exited', code: 0 },
			]))
				v.out(line);
			return 0;
		};
		expect((await y.run()).failures).toEqual([
			'runner_failed: the run step exited 1',
			"supervisor_mismatch: the supervisor's exit line implies exit code 1, and the container exited 0",
		]);

		// Exit 0 with no exit line at all.
		const x = await setup();
		x.docker.verifierScript = async (v) => {
			await v.nextLine();
			return 0;
		};
		expect((await x.run()).failures).toEqual([
			'supervisor_missing: the verifier exited 0 without the supervisor reporting how its steps ended',
		]);
	});

	test('a verifier that exits before the supervisor reports is blocked with its stderr', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.err('python3: not found');
			return 127;
		};
		const result = await t.run();
		expect(result.stopped).toBe('exited');
		expect(result.blocked).toBe(
			'verifier_failed: the verifier exited 127 before the supervisor reported: python3: not found',
		);
		expect(result.failures).toEqual([]);
	});

	test('a verifier killed for its memory, a volume in the image, a failed start and a failed reapply are reported, and the container never stays', async () => {
		const oom = await setup();
		oom.docker.verifierScript = async (v) => {
			await v.nextLine();
			oom.docker.exits.set(v.name, { status: 'exited', exitCode: 137, oomKilled: true });
			return 137;
		};
		const killed = await oom.run();
		expect(killed.failures).toContain(
			'verifier_oom_killed: the verifier was killed for exceeding its memory limit',
		);

		const volume = await setup();
		volume.docker.helperMounts = [{ type: 'volume', destination: '/data' }];
		const mounted = await volume.run();
		expect(mounted.stopped).toBe('failed');
		expect(mounted.blocked).toBe(
			`image_mounts: koi-verify-${RUN}-verifier has mounts koi did not ask for: volume at /data`,
		);
		expect(volume.docker.verifiers).toEqual([]);
		expect(volume.docker.containers.has(`koi-verify-${RUN}-verifier`)).toBe(false);

		const start = await setup();
		start.docker.attachError = 'docker start exited 125: oci runtime error';
		const unstarted = await start.run();
		expect(unstarted.blocked).toBe('verifier_failed: docker start exited 125: oci runtime error');
		expect(start.docker.containers.has(`koi-verify-${RUN}-verifier`)).toBe(false);

		const net = await setup();
		net.runner = new VerifierRunner({
			docker: net.docker,
			network: {
				async reapply() {
					throw new Error('iptables is busy');
				},
			},
			secrets: net.secrets,
			now: () => new Date(AT),
			sleep: async () => {},
			log: () => {},
			pollMs: 5,
		});
		const unpermitted = await net.runner.run(net.execution, net.recorder, net.writer, {
			stopRequested: () => undefined,
		});
		expect(unpermitted.blocked).toBe('network_reapply_failed: iptables is busy');
		expect(net.docker.containers.has(`koi-verify-${RUN}-verifier`)).toBe(false);
		// The script never got start.
		expect(net.docker.verifiers[0]?.detached).toBe(true);
	});

	test('docker cp is refused on a read-only root and in a read-only volume, and a writable volume takes it', async () => {
		const t = await setup();
		const verifier = `koi-verify-${RUN}-verifier`;
		const tar = tarball([{ path: 'koi', type: 'dir', mode: 0o555 }]);
		// The placeholder: read-only, as every verifier is.
		await expect(t.docker.copyIn(verifier, tar, '/')).rejects.toThrow(
			'container rootfs is marked read-only',
		);
		// The refusal looks at the destination: an archive whose every entry
		// would land in a volume is still refused at the read-only root.
		await t.docker.remove(verifier);
		await t.docker.createVolume('v', {});
		await t.docker.createVerifier({
			name: verifier,
			image: CURL,
			network: record.network,
			ip: '10.213.0.4',
			mac: '02:4b:0a:d5:00:04',
			runId: RUN,
			appHost: { name: `app.${RUN}.invalid`, ip: '10.213.0.2' },
			dns: record.gateway,
			env: {},
			volumes: [{ name: 'v', destination: '/koi' }],
		});
		await expect(t.docker.copyIn(verifier, tar, '/')).rejects.toThrow(
			'container rootfs is marked read-only',
		);
		await expect(t.docker.copyIn(verifier, tar, '/koi')).rejects.toThrow(
			'mounted volume is marked read-only',
		);
		// Docker refuses a volume a container mounts, even one never started.
		await expect(t.docker.removeVolume('v')).rejects.toThrow('is in use');
		await t.docker.remove(verifier);
		await t.docker.createStaging({
			name: 's',
			image: CURL,
			runId: RUN,
			volumes: [{ name: 'v', destination: '/koi' }],
		});
		await t.docker.copyIn('s', tar, '/');
		expect(t.docker.volumes.get('v')?.files.get('')?.type).toBe('dir');
	});

	test('a mount the verifier should not have, or an input volume writable, blocks the point before it starts', async () => {
		const extra = await setup();
		extra.docker.helperMounts = [{ type: 'bind', destination: '/host' }];
		const refused = await extra.run();
		expect(refused.stopped).toBe('failed');
		expect(refused.blocked).toBe(
			`image_mounts: koi-verify-${RUN}-verifier has mounts koi did not ask for: bind at /host`,
		);
		expect(extra.docker.verifiers).toEqual([]);

		const volumes = inputVolumes(RUN);
		const read = (destination: string) => ({
			type: 'volume',
			destination,
			name: volumes.find((v) => v.destination === destination)?.name,
			readOnly: true,
		});
		expect(mountProblems(['/koi', '/workspace', '/fixtures'].map(read), volumes)).toEqual([]);
		expect(
			mountProblems(
				[read('/koi'), read('/workspace'), { ...read('/fixtures'), readOnly: false }],
				volumes,
			),
		).toEqual([
			'has mounts koi did not ask for: volume at /fixtures',
			'lacks its input volumes at /fixtures',
		]);
		expect(mountProblems([read('/koi')], volumes)).toEqual([
			'lacks its input volumes at /workspace, /fixtures',
		]);
	});

	test('each point gets fresh volumes, so a fixture of the last point is not there', async () => {
		const t = await setup();
		const seen: string[][] = [];
		t.docker.verifierScript = async (v) => {
			seen.push([...v.files.keys()].filter((path) => path.startsWith('fixtures/')));
			await v.nextLine();
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		await t.run();
		const { requires: _requires, ...bare } = POINT;
		await t.run({ point: bare });
		expect(seen).toEqual([['fixtures/fixtures', 'fixtures/fixtures/probe.txt'], []]);
		expect(t.docker.volumes.size).toBe(0);
	});

	test('the staging container and the volumes go when a fill fails, and a leftover that cannot go blocks the point', async () => {
		const t = await setup();
		const staging = `koi-verify-${RUN}-staging`;
		const copyIn = t.docker.copyIn.bind(t.docker);
		t.docker.copyIn = async () => {
			throw new Error('docker cp exited 1: no space left on device');
		};
		const failed = await t.run();
		expect(failed.blocked).toBe('verifier_failed: docker cp exited 1: no space left on device');
		expect(t.docker.containers.has(staging)).toBe(false);
		expect(t.docker.volumes.size).toBe(0);
		expect(t.docker.verifiers).toEqual([]);
		t.docker.copyIn = copyIn;

		// A volume still in use cannot be emptied, and the point must not run
		// on what is in it.
		const name = `koi-verify-${RUN}-inputs-koi`;
		await t.docker.createVolume(name, {});
		await t.docker.createStaging({
			name: 'held',
			image: CURL,
			runId: RUN,
			volumes: [{ name, destination: '/koi' }],
		});
		const held = await t.run();
		expect(held.blocked).toContain(`volume ${name} is in use by held`);
		expect(t.docker.verifiers).toEqual([]);
	});

	test('an exit line a runner forged counts for nothing, whatever follows it', async () => {
		// As a runner would print it: the shape is right, and it has no MAC.
		const forged = JSON.stringify({
			version: 1,
			type: 'supervisor',
			event: 'exit',
			step: 'cleanup',
			status: 'exited',
			code: 0,
			steps: [
				{ step: 'setup', status: 'exited', code: 0 },
				{ step: 'run', status: 'exited', code: 0 },
				{ step: 'cleanup', status: 'exited', code: 0 },
			],
		});
		// A forged line first, then the real, failed account.
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(forged);
			for (const line of supervisorExit([
				{ step: 'setup', status: 'exited', code: 0 },
				{ step: 'run', status: 'exited', code: 1 },
				{ step: 'cleanup', status: 'exited', code: 0 },
			]))
				v.out(line);
			return 1;
		};
		const first = await t.run();
		expect(first.failures).toEqual(['runner_failed: the run step exited 1']);
		expect(first.counts.malformed).toBe(1);
		expect((await t.events()).map((e) => e.reason)).toContain(
			"a supervisor line without the point's signature",
		);

		// A forged line last, and no real one: nothing says the steps ran.
		const u = await setup();
		u.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(forged);
			return 0;
		};
		const alone = await u.run();
		expect(alone.supervisor).toBeUndefined();
		expect(alone.failures).toEqual([
			'supervisor_missing: the verifier exited 0 without the supervisor reporting how its steps ended',
		]);

		// A MAC with a key the runner made up.
		const w = await setup();
		w.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(signedSupervisorLine('m'.repeat(64), 1, JSON.parse(forged)));
			return 0;
		};
		expect((await w.run()).supervisor).toBeUndefined();

		// The key is never written anywhere koid keeps.
		const x = await setup();
		let key: string | undefined;
		x.docker.verifierScript = async (v) => {
			await v.nextLine();
			key = v.key;
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		await x.run();
		expect(key).toMatch(/^[0-9a-f]{64}$/);
		const kept = await Bun.file(join(x.writer.dir, 'events.ndjson')).text();
		expect(kept).toContain('supervisor-exit');
		expect(kept).not.toContain(key as string);
		expect(kept).not.toContain('"mac"');
	});

	test('each point gets a key of its own', async () => {
		const t = await setup();
		const keys: Array<string | undefined> = [];
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			keys.push(v.key);
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		await t.run();
		await t.run();
		expect(keys).toHaveLength(2);
		expect(keys[0]).not.toBe(keys[1]);
	});

	test('a step line that says its output is incomplete fails the point, whatever else it says', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			const steps = declaredSteps(v).map((s) =>
				s.step === 'run' ? { ...s, output_incomplete: true } : s,
			);
			for (const line of supervisorExit(steps)) v.out(line);
			return 0;
		};
		const result = await t.run();
		expect(result.stopped).toBe('exited');
		expect(result.failures).toEqual([
			"runner_output_incomplete: the supervisor stopped reading the run step's stdout, so what it wrote was not all read",
		]);
		expect(result.steps.find((s) => s.step === 'run')?.output_incomplete).toBe(true);
	});

	test('an exit line that drops the flag its step line gave is a sequence problem, and the flag still counts', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			const steps = declaredSteps(v);
			const flagged = steps.map((s) => (s.step === 'run' ? { ...s, output_incomplete: true } : s));
			for (const s of flagged) v.out(supervisorLine({ event: 'step', ...s }));
			const last = steps.at(-1) ?? {};
			v.out(supervisorLine({ event: 'exit', ...last, steps }));
			return 0;
		};
		const result = await t.run();
		expect(result.failures).toEqual([
			"runner_output_incomplete: the supervisor stopped reading the run step's stdout, so what it wrote was not all read",
			'supervisor_sequence: its exit line does not repeat its step lines',
		]);
	});

	test('output unread when the drain gives up fails the point, even with a full account', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			// The exit line is in; the stream never ends, so what came after it
			// is unknown.
			v.keepOutputOpen = true;
			return 0;
		};
		const result = await whileTimePasses(t, t.run(FAR_BUDGET));
		expect(result.stopped).toBe('exited');
		expect(result.failures).toEqual([
			'runner_output_incomplete: the output streams did not end after the verifier exited, so what it wrote was not all read',
		]);
		expect(result.supervisor).toBeDefined();
	});

	test('a forged summary over truncated output fails, and is not read as a pass', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(
				JSON.stringify({
					version: 1,
					type: 'supervisor',
					event: 'exit',
					step: 'run',
					status: 'exited',
					code: 0,
					steps: [{ step: 'run', status: 'exited', code: 0 }],
				}),
			);
			v.out(
				'{"type":"assertion","point":"hello.home","name":"home-says-hello","outcome":"pass","evidence":[]}',
			);
			v.keepOutputOpen = true;
			return 0;
		};
		const result = await whileTimePasses(t, t.run(FAR_BUDGET));
		expect(result.failures).toEqual([
			'runner_output_incomplete: the output streams did not end after the verifier exited, so what it wrote was not all read',
			'supervisor_missing: the verifier exited 0 without the supervisor reporting how its steps ended',
		]);
	});

	test('output still arriving after the exit is read to its end, past the drain limit', async () => {
		const t = await setup({ limits: { logLinesPerPoint: 100 } });
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			v.keepOutputOpen = true;
			// Each silence is under the limit, and together they are over it. The
			// clock waits for koid to have read each line, or two silences would
			// count as one.
			const late = async () => {
				for (let i = 0; i < 3; i++) {
					t.advance(3_000);
					v.out(`late ${i}`);
					await t.logged(`late ${i}`);
				}
				v.closeOutput();
			};
			void late();
			return 0;
		};
		const result = await t.run();
		expect(result.failures).toEqual([]);
		expect(result.counts.logLines).toBe(3);
	});

	test('a stdout that breaks is output unread, not output ended', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			v.keepOutputOpen = true;
			await Bun.sleep(5);
			v.failOutput();
			v.closeErrors();
			return 0;
		};
		const result = await t.run();
		expect(result.failures).toContain(
			"runner_output_incomplete: reading the verifier's stdout failed, so what it wrote was not all read",
		);
	});

	test('the steps must be those the point declares, in order, each once', async () => {
		const ran = (step: string) => ({ step, status: 'exited', code: 0 });
		const declared = 'the point declares setup, run, cleanup';
		const account = async (printed: Array<Record<string, unknown>>) => {
			const t = await setup();
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				for (const line of supervisorExit(printed)) v.out(line);
				return 0;
			};
			return (await t.run()).failures;
		};
		// No run step at all: exit 0 and every line in shape.
		expect(await account([ran('setup'), ran('cleanup')])).toEqual([
			`supervisor_sequence: it printed steps setup, cleanup, and ${declared}`,
		]);
		// Out of order.
		expect(await account([ran('run'), ran('setup'), ran('cleanup')])).toEqual([
			`supervisor_sequence: it printed steps run, setup, cleanup, and ${declared}`,
		]);
		// A declared step missing.
		expect(await account([ran('run')])).toEqual([
			`supervisor_sequence: it printed steps run, and ${declared}`,
		]);

		// A step twice, with an exit line that lists it once.
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(supervisorLine({ event: 'step', ...ran('setup') }));
			v.out(supervisorLine({ event: 'step', ...ran('run') }));
			v.out(supervisorLine({ event: 'step', ...ran('run') }));
			for (const line of supervisorExit([ran('setup'), ran('run'), ran('cleanup')])) v.out(line);
			return 0;
		};
		expect((await t.run()).failures).toEqual([
			`supervisor_sequence: it printed steps setup, run, run, setup, run, cleanup, and ${declared}`,
			'supervisor_sequence: its exit line does not repeat its step lines',
		]);

		// A point with no setup or cleanup declares run alone.
		const { setup: _setup, cleanup: _cleanup, ...bare } = POINT;
		const u = await setup();
		u.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit([ran('run')])) v.out(line);
			return 0;
		};
		const alone = await u.run({ point: bare });
		expect(alone.failures).toEqual([]);
		expect(alone.cleanup).toBe('none');
	});

	test('a skipped run step fails the point, with no setup failure to account for it', async () => {
		const t = await setup();
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit([
				{ step: 'setup', status: 'exited', code: 0 },
				{ step: 'run', status: 'skipped', reason: 'no reason' },
				{ step: 'cleanup', status: 'exited', code: 0 },
			]))
				v.out(line);
			return 1;
		};
		expect((await t.run()).failures).toEqual([
			'runner_failed: the run step was skipped: no reason',
		]);
	});

	test('a signed line printed again, or one that went missing, fails the point', async () => {
		const ran = (step: string) => ({ step, status: 'exited', code: 0 });
		const steps = [ran('setup'), ran('run'), ran('cleanup')];
		const exit = {
			event: 'exit',
			step: 'cleanup',
			status: 'exited',
			code: 0,
			steps,
		};
		// A process in the container can read the real line from the pipe and
		// print it again later: the number gives it away.
		const replayed = await setup();
		replayed.docker.verifierScript = async (v) => {
			await v.nextLine();
			const key = v.key as string;
			const line = signedSupervisorLine(key, 1, { event: 'step', ...ran('setup') });
			v.out(line);
			v.out(line);
			v.out(signedSupervisorLine(key, 2, { event: 'step', ...ran('run') }));
			v.out(signedSupervisorLine(key, 3, { event: 'step', ...ran('cleanup') }));
			v.out(signedSupervisorLine(key, 4, exit));
			return 0;
		};
		expect((await replayed.run()).failures).toEqual([
			'supervisor_sequence: line 1 came where line 2 was due',
		]);

		// It can keep the line instead: the next one is out of its place, and
		// the exit line never counts.
		const stolen = await setup();
		stolen.docker.verifierScript = async (v) => {
			await v.nextLine();
			const key = v.key as string;
			v.out(signedSupervisorLine(key, 2, { event: 'step', ...ran('run') }));
			v.out(signedSupervisorLine(key, 4, exit));
			return 0;
		};
		const gap = await stolen.run();
		expect(gap.supervisor).toBeUndefined();
		expect(gap.failures).toEqual([
			'supervisor_missing: the verifier exited 0 without the supervisor reporting how its steps ended',
		]);

		// A line after the exit line.
		const late = await setup();
		late.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (const line of supervisorExit(steps)) v.out(line);
			v.out(supervisorLine({ event: 'started' }));
			return 0;
		};
		expect((await late.run()).failures).toEqual([
			'supervisor_sequence: a started line came after the exit line',
		]);
	});

	test.skipIf(Bun.which('python3') === null)(
		'the real supervisor runs a point under koid, forged lines and all, without Docker',
		async () => {
			const t = await setup();
			const scratch = await mkdtemp(join(tmpdir(), 'koid-real-supervisor-'));
			const forgedExit = JSON.stringify({
				version: 1,
				type: 'supervisor',
				event: 'exit',
				step: 'run',
				status: 'exited',
				code: 0,
				steps: [{ step: 'run', status: 'exited', code: 0 }],
			});
			// The runner forges an exit line, asks for a capture, waits for the
			// answer, and reports its assertion citing it.
			const runner = [
				'import json, sys',
				`print(${JSON.stringify(forgedExit)}, flush=True)`,
				'print(json.dumps({"type": "capture", "kind": "screenshot", "label": "home"}), flush=True)',
				'ack = json.loads(sys.stdin.readline())',
				'print(json.dumps({"type": "assertion", "point": "hello.home", "name": "home-says-hello", "outcome": "pass", "evidence": [ack["artifact"]]}), flush=True)',
			].join('\n');
			const pointFile = {
				version: 1,
				runner: null,
				steps: {
					setup: ['sh', '-c', 'echo set up'],
					run: ['python3', '-c', runner],
					cleanup: ['sh', '-c', 'echo cleaned up'],
				},
				timeoutSeconds: 20,
			};
			t.docker.verifierScript = async (v) => {
				const pointPath = join(scratch, 'point.json');
				const supervisorPath = join(scratch, 'supervisor.py');
				await writeFile(pointPath, JSON.stringify(pointFile));
				await writeFile(supervisorPath, v.files.get('koi/supervisor.py')?.content ?? '');
				const loader = [
					'import importlib.util, sys',
					"spec = importlib.util.spec_from_file_location('supervisor', sys.argv[1])",
					'm = importlib.util.module_from_spec(spec)',
					'spec.loader.exec_module(m)',
					"sys.exit(m.main(['supervisor.py', sys.argv[2]], cwd=sys.argv[3]))",
				].join('\n');
				const proc = Bun.spawn(
					['python3', '-I', '-c', loader, supervisorPath, pointPath, scratch],
					{
						stdin: 'pipe',
						stdout: 'pipe',
						stderr: 'ignore',
						env: { ...v.env, PATH: process.env.PATH ?? '' },
					},
				);
				const forwarding = (async () => {
					for (;;) {
						const line = await v.nextLine();
						proc.stdin.write(`${line}\n`);
						await proc.stdin.flush();
					}
				})();
				void forwarding;
				for await (const chunk of proc.stdout) v.write(chunk);
				return proc.exited;
			};
			const result = await t.run();
			expect(result.failures).toEqual([]);
			expect(result.blocked).toBeUndefined();
			expect(result.stopped).toBe('exited');
			expect(result.supervisor?.steps.map((s) => s.step)).toEqual(['setup', 'run', 'cleanup']);
			expect(result.cleanup).toBe('succeeded');
			expect(result.exit?.exitCode).toBe(0);
			expect(result.reports).toEqual([
				{
					name: 'home-says-hello',
					outcome: 'pass',
					evidence: ['recorder:screenshot:1'],
				},
			]);
			// The forgery was seen and did not count.
			expect(result.counts.malformed).toBe(1);
		},
		30_000,
	);

	test('the budget stops the container while a capture is still out, and the capture ends with it', async () => {
		const t = await setup();
		let signal: AbortSignal | undefined;
		const out = new Gate();
		t.recorder.capture = ((_r: unknown, o?: { signal?: AbortSignal | undefined }) => {
			signal = o?.signal;
			void out.pass();
			return endedBy(o?.signal, 'the signal ended it');
		}) as typeof t.recorder.capture;
		let stoppedWhileOut = false;
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			// A queue of captures: the reader is on the first, and each later
			// one would keep it from a check of its own.
			for (let i = 0; i < 5; i++) {
				v.out(`{"type":"capture","kind":"screenshot","label":"c${i}"}`);
			}
			await out.reached;
			t.advance(316_000);
			await v.stopped;
			stoppedWhileOut = signal?.aborted === true;
			return 137;
		};
		const result = await t.run();
		expect(stoppedWhileOut).toBe(true);
		expect(result.stopped).toBe('timeout');
		expect(result.blocked).toBe(
			'point_timeout: the point reached its budget of 300 seconds before the runner ended',
		);
		// The reader stopped at the first and read no further.
		expect(result.counts.captures).toBe(1);
		expect(t.docker.containers.has(`koi-verify-${RUN}-verifier`)).toBe(false);
	});

	test("a capture refused at the point's budget ends the point there, blocked, and what the runner says next does not count", async () => {
		const t = await setup();
		t.recorder.capture = () =>
			Promise.reject(new RecorderDeadlineError("capturing: the point's time is up"));
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out('{"type":"capture","kind":"screenshot","label":"shot"}');
			v.out(
				'{"type":"assertion","point":"hello.home","name":"home-says-hello","outcome":"fail","evidence":[],"detail":"my capture failed"}',
			);
			await v.stopped;
			return 137;
		};
		const result = await t.run();
		expect(result.stopped).toBe('timeout');
		expect(result.blocked).toBe(
			'point_timeout: the point reached its budget of 300 seconds before the runner ended',
		);
		expect(result.reports).toEqual([]);
		expect(result.failures).toEqual([]);
	});

	describe('a flood of output while the handler is stuck', () => {
		// The point as the controller judges it from what the verifier returned.
		const verdict = async (t: Awaited<ReturnType<typeof setup>>, run: PointRun) =>
			judgePoint({
				id: POINT.id,
				assertions: POINT.assertions.map((a) => ({ name: a.name, evidence: a.evidence })),
				reports: run.reports,
				resolve: await t.writer.resolveEvidence([]),
				blocked: run.blocked,
				cleanup: run.cleanup,
				recovery: run.recovery,
				failures: run.failures,
			});
		// A recorder call that is out until the point ends it, with a gate that
		// opens when it is asked for.
		const stuck = (t: Awaited<ReturnType<typeof setup>>) => {
			const out = new Gate();
			const calls: Array<AbortSignal | undefined> = [];
			t.recorder.capture = ((_r: unknown, o?: { signal?: AbortSignal | undefined }) => {
				calls.push(o?.signal);
				void out.pass();
				return endedBy(o?.signal, 'the signal ended it');
			}) as typeof t.recorder.capture;
			return { out, calls };
		};
		const CAPTURE = '{"type":"capture","kind":"screenshot","label":"slow"}';
		const CHUNK = 64 * 1024;

		// Writes until the container stops, without waiting on koid for anything.
		const flood = async (v: FakeVerifier, chunk: Uint8Array) => {
			let stopped = false;
			void v.stopped.then(() => {
				stopped = true;
			});
			while (!stopped) {
				v.write(chunk);
				await Bun.sleep(0);
			}
		};

		test.each([
			[
				'one line with no end',
				new Uint8Array(CHUNK).fill(0x78),
				{},
				`runner_protocol_limit: the runner wrote more than ${PROTOCOL_LIMITS.bytesPerPoint} bytes`,
			],
			[
				'long lines',
				Uint8Array.from({ length: CHUNK }, (_, i) => (i % 4096 === 4095 ? 0x0a : 0x78)),
				{ queueBytes: 1024 ** 2 },
				`runner_protocol_limit: the runner's output outran koid: over ${1024 ** 2} bytes waited to be handled`,
			],
			[
				'empty lines',
				new Uint8Array(CHUNK).fill(0x0a),
				{},
				`runner_protocol_limit: the runner's output outran koid: over ${PROTOCOL_LIMITS.queueBytes} bytes waited to be handled`,
			],
		])(
			'of %s stops the container, fails the point, and holds no more than the bound',
			async (_n, chunk, limits, failure) => {
				const t = await setup({ limits });
				const { out, calls } = stuck(t);
				t.docker.verifierScript = async (v) => {
					await v.nextLine();
					v.out(CAPTURE);
					await out.reached;
					await flood(v, chunk);
					return 137;
				};
				const result = await t.run();
				expect(result.stopped).toBe('protocol-limit');
				expect(result.failures).toEqual([failure]);
				// The stop did not wait for the handler: it ended the capture.
				expect(calls[0]?.aborted).toBe(true);
				const bound = (limits as { queueBytes?: number }).queueBytes ?? PROTOCOL_LIMITS.queueBytes;
				expect(result.counts.queuedBytes).toBeLessThanOrEqual(bound);
				// The total stops at the first chunk past it.
				expect(result.counts.bytes).toBeLessThanOrEqual(PROTOCOL_LIMITS.bytesPerPoint + CHUNK);
				expect(t.docker.containers.has(`koi-verify-${RUN}-verifier`)).toBe(false);
				expect((await t.events()).at(-1)).toMatchObject({
					type: 'verifier-stopped',
					how: 'protocol-limit',
				});
				expect((await verdict(t, result)).outcome).toBe('fail');
			},
		);

		test('before the handler has started at all, while the firewall is being bound', async () => {
			const reapply = new Gate();
			const t = await setup({ reapply: () => reapply.pass() });
			t.docker.verifierScript = async (v) => {
				// A process in the image that does not wait for start.
				await flood(v, new Uint8Array(CHUNK).fill(0x78));
				reapply.release();
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('protocol-limit');
			expect(result.failures).toEqual([
				`runner_protocol_limit: the runner wrote more than ${PROTOCOL_LIMITS.bytesPerPoint} bytes`,
			]);
			expect(result.counts.bytes).toBeLessThanOrEqual(PROTOCOL_LIMITS.bytesPerPoint + CHUNK);
			// koid stopped it before it was ever told to go.
			expect(t.docker.verifiers[0]?.key).toBeUndefined();
			expect((await verdict(t, result)).outcome).toBe('fail');
		});

		test('a runner that writes much but under the total passes', async () => {
			// Few lines are kept as events, so the disk does not set this test's pace.
			const t = await setup({ limits: { logLinesPerPoint: 10 } });
			const line = `${'y'.repeat(1023)}\n`;
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				for (let i = 0; i < 4096; i++) v.write(new TextEncoder().encode(line));
				for (const l of supervisorExit(declaredSteps(v))) v.out(l);
				return 0;
			};
			const result = await t.run(FAR_BUDGET);
			expect(result.stopped).toBe('exited');
			expect(result.failures).toEqual([]);
			expect(result.counts.logLines).toBe(4096);
			expect(result.counts.bytes).toBeGreaterThan(4 * 1024 ** 2);
		});

		test('a signed step failure read while the handler was stuck still counts', async () => {
			const t = await setup();
			const { out } = stuck(t);
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(CAPTURE);
				await out.reached;
				v.out(supervisorLine({ event: 'started' }));
				v.out(
					supervisorLine({ event: 'step', step: 'run', status: 'exited', code: 1, seconds: 1 }),
				);
				// A runner's own word in the same queue is over with the point.
				v.out(
					'{"type":"assertion","point":"hello.home","name":"home-says-hello","outcome":"pass","evidence":[]}',
				);
				await Bun.sleep(5);
				t.advance(316_000);
				await v.stopped;
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('timeout');
			expect(result.failures).toEqual(['runner_failed: the run step exited 1']);
			expect(result.reports).toEqual([]);
			expect((await verdict(t, result)).outcome).toBe('fail');
		});

		// Real pipes and a real process. The fake streams above show the bookkeeping;
		// this shows what Bun holds. A stop that takes as long as the flood does is
		// the case of a runner that ignores SIGTERM during `docker stop`, so the
		// reader has to go on reading past the limit too.
		test.each([
			['no newline', 'cat'],
			['nothing but newlines', "tr '\\000' '\\n'"],
		])(
			'a real process writing 512 MiB of %s holds koid near the bound',
			async (_name, filter) => {
				const t = await setup();
				stuck(t);
				const FLOOD = 512 * 1024 ** 2;
				let child: Promise<number> = Promise.resolve(0);
				t.docker.onStop = async () => {
					await child;
				};
				t.docker.attach = async (name) => {
					await t.docker.start(name);
					const script = `printf '%s\n' '${CAPTURE}'; head -c ${FLOOD} /dev/zero | ${filter}`;
					const proc = Bun.spawn(['sh', '-c', script], {
						stdin: 'pipe',
						stdout: 'pipe',
						stderr: 'pipe',
					});
					child = proc.exited;
					return {
						async write(data) {
							proc.stdin.write(data);
							await proc.stdin.flush();
						},
						stdout: proc.stdout,
						stderr: proc.stderr,
						exited: proc.exited,
						detach() {
							proc.kill('SIGKILL');
						},
					};
				};
				Bun.gc(true);
				const before = process.memoryUsage().rss;
				let peak = before;
				const sampler = setInterval(() => {
					peak = Math.max(peak, process.memoryUsage().rss);
				}, 2);
				try {
					const result = await t.run();
					peak = Math.max(peak, process.memoryUsage().rss);
					expect(result.stopped).toBe('protocol-limit');
					expect(result.failures).toHaveLength(1);
					expect(result.failures[0]).toStartWith('runner_protocol_limit: ');
					expect(result.counts.queuedBytes).toBeLessThanOrEqual(PROTOCOL_LIMITS.queueBytes);
					// The process finished, so all 512 MiB left the pipe.
					expect(await child).toBe(0);
					// Allocation noise and a lazy collector are in this number. A reader that
					// let the stream sit would show the whole flood, 2.5 times this.
					expect(peak - before).toBeLessThan(200 * 1024 ** 2);
					expect((await verdict(t, result)).outcome).toBe('fail');
				} finally {
					clearInterval(sampler);
				}
			},
			60_000,
		);
	});

	describe('a signed step failure followed by a stop', () => {
		const stepLine = (step: string, status: Record<string, unknown>) =>
			supervisorLine({ event: 'step', step, seconds: 1, ...status });
		const failedRun = [
			stepLine('setup', { status: 'exited', code: 0 }),
			stepLine('run', { status: 'exited', code: 1 }),
		];
		const failedSetup = [
			stepLine('setup', { status: 'exited', code: 3 }),
			stepLine('run', { status: 'skipped', reason: 'setup did not exit 0' }),
		];
		// The point as the controller judges it from what the verifier returned.
		const verdict = async (t: Awaited<ReturnType<typeof setup>>, run: PointRun) =>
			judgePoint({
				id: POINT.id,
				assertions: POINT.assertions.map((a) => ({ name: a.name, evidence: a.evidence })),
				reports: run.reports,
				resolve: await t.writer.resolveEvidence([]),
				blocked: run.blocked,
				cleanup: run.cleanup,
				recovery: run.recovery,
				failures: run.failures,
			});
		const TIMEOUT =
			'point_timeout: the point reached its budget of 300 seconds before the runner ended';

		// The cleanup step's capture is what reaches the recorder's deadline, so
		// the point stops with the earlier steps already reported.
		test.each([
			['a failed run', failedRun, ['runner_failed: the run step exited 1']],
			[
				'a failed setup',
				failedSetup,
				[
					'setup_failed: the setup step exited 3',
					'runner_failed: the run step was skipped: setup did not exit 0',
				],
			],
		])(
			'%s then a cleanup at the recorder deadline fails the point',
			async (_name, lines, failures) => {
				const t = await setup();
				t.recorder.capture = () =>
					Promise.reject(new RecorderDeadlineError("capturing: the point's time is up"));
				t.docker.verifierScript = async (v) => {
					await v.nextLine();
					v.out(supervisorLine({ event: 'started' }));
					for (const line of lines) v.out(line);
					v.out('{"type":"capture","kind":"screenshot","label":"after-cleanup"}');
					await v.stopped;
					return 137;
				};
				const result = await t.run();
				expect(result.stopped).toBe('timeout');
				expect(result.blocked).toBe(TIMEOUT);
				expect(result.failures).toEqual(failures);
				expect(result.cleanup).toBe('not-run');
				const judged = await verdict(t, result);
				expect(judged.outcome).toBe('fail');
				expect(judged.reasons.slice(0, failures.length)).toEqual(failures);
			},
		);

		test('a failed run then a cleanup the watchdog stops at the budget fails the point', async () => {
			const t = await setup();
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(supervisorLine({ event: 'started' }));
				for (const line of failedRun) v.out(line);
				v.out('reported');
				await t.logged('reported');
				t.advance(316_000);
				await v.stopped;
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('timeout');
			expect(result.failures).toEqual(['runner_failed: the run step exited 1']);
			expect((await verdict(t, result)).outcome).toBe('fail');
		});

		test('a failed run then a cancel fails the point', async () => {
			const t = await setup();
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(supervisorLine({ event: 'started' }));
				for (const line of failedRun) v.out(line);
				v.out('reported');
				await t.logged('reported');
				t.cancel('the run was cancelled');
				await v.stopped;
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('cancelled');
			expect(result.failures).toEqual(['runner_failed: the run step exited 1']);
			expect((await verdict(t, result)).outcome).toBe('fail');
		});

		test("a step koid's own stop killed is no failure: the point is blocked", async () => {
			const t = await setup();
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				v.out(supervisorLine({ event: 'started' }));
				v.out('running');
				await t.logged('running');
				t.advance(316_000);
				await v.stopped;
				// What the supervisor says as the stop reaches the step.
				v.out(stepLine('setup', { status: 'signalled', signal: 15 }));
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('timeout');
			expect(result.failures).toEqual([]);
			expect((await verdict(t, result)).outcome).toBe('blocked');
		});
	});

	test('a read gets the same signal as a capture', async () => {
		const t = await setup();
		const signals: Array<AbortSignal | undefined> = [];
		const read = t.recorder.read.bind(t.recorder);
		t.recorder.read = ((r: { path: string }, o?: { signal?: AbortSignal | undefined }) => {
			signals.push(o?.signal);
			return read(r);
		}) as typeof t.recorder.read;
		const capture = t.recorder.capture.bind(t.recorder);
		t.recorder.capture = ((
			r: { kind: Artifact['kind']; label: string },
			o?: { signal?: AbortSignal | undefined },
		) => {
			signals.push(o?.signal);
			return capture(r);
		}) as typeof t.recorder.capture;
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out('{"type":"capture","kind":"screenshot","label":"a"}');
			await v.nextLine();
			v.out('{"type":"read","label":"b","path":"/"}');
			await v.nextLine();
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		await t.run();
		expect(signals).toHaveLength(2);
		expect(signals[0]).toBeInstanceOf(AbortSignal);
		expect(signals[1]).toBe(signals[0]);
	});

	test('the budget stops the container while an acknowledgment sits on a full stdin', async () => {
		const t = await setup();
		// Start goes in; the answer to the capture never does.
		t.docker.stdinLines = 1;
		const out = new Gate();
		const capture = t.recorder.capture.bind(t.recorder);
		t.recorder.capture = (r) => {
			void out.pass();
			return capture(r);
		};
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out('{"type":"capture","kind":"screenshot","label":"home"}');
			await out.reached;
			t.advance(316_000);
			await v.stopped;
			return 137;
		};
		const result = await t.run();
		expect(result.stopped).toBe('timeout');
		expect(t.recorder.calls).toEqual(['screenshot home']);
		expect(t.logs.join('\n')).toContain('the write to the container was abandoned');
	});

	test('a cancel stops the container while a capture is out', async () => {
		const t = await setup();
		const out = new Gate();
		t.recorder.capture = ((_r: unknown, o?: { signal?: AbortSignal | undefined }) => {
			void out.pass();
			return endedBy(o?.signal, 'ended');
		}) as typeof t.recorder.capture;
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out('{"type":"capture","kind":"screenshot","label":"home"}');
			await out.reached;
			t.cancel('the run was cancelled');
			await v.stopped;
			return 137;
		};
		const result = await t.run();
		expect(result.stopped).toBe('cancelled');
		expect(result.blocked).toBe('cancelled: the run was cancelled');
	});

	test('start waits for the container to run, then for the permits, and the reapply asks for the port', async () => {
		const t = await setup();
		t.docker.runningAfterInspects = 3;
		const verifier = `koi-verify-${RUN}-verifier`;
		let order: string[] = [];
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			order = t.docker.events.filter((e) => e === `running ${verifier}`);
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const result = await t.run();
		expect(result.failures).toEqual([]);
		// Reapplied once, on a container that ran, asking for its bound port.
		expect(t.reapplies).toEqual([{ bound: ['verifier'], running: true }]);
		expect(order).toEqual([`running ${verifier}`]);
	});

	test('a container that never runs blocks the point, and no start goes out', async () => {
		const t = await setup();
		t.docker.runningAfterInspects = 1_000_000;
		let started = false;
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			started = true;
			return 0;
		};
		const result = await t.run();
		expect(result.blocked).toBe(
			`verifier_not_running: koi-verify-${RUN}-verifier was not running 30 seconds after its start`,
		);
		expect(t.reapplied).toEqual([]);
		expect(started).toBe(false);
	});

	test('a container that ends before it is seen running gets no reapply and no start', async () => {
		const t = await setup();
		t.docker.runningAfterInspects = 5;
		t.docker.verifierScript = async (v) => {
			v.err('exec: python3: not found');
			return 127;
		};
		const result = await t.run();
		expect(t.reapplied).toEqual([]);
		expect(result.blocked).toBe(
			'verifier_failed: the verifier exited 127 before the supervisor reported: exec: python3: not found',
		);
	});

	test('a step the supervisor stopped at its share blocks the point as the watchdog would', async () => {
		const timedOut =
			(steps: Array<Record<string, unknown>>, exitCode = 2) =>
			async () => {
				const t = await setup();
				t.docker.verifierScript = async (v) => {
					await v.nextLine();
					for (const line of supervisorExit(steps)) v.out(line);
					return exitCode;
				};
				return t.run();
			};
		const ran = (step: string) => ({ step, status: 'exited', code: 0 });
		const out = (step: string) => ({ step, status: 'timeout', seconds: 270 });

		const run = await timedOut([ran('setup'), out('run'), ran('cleanup')])();
		expect(run.failures).toEqual([]);
		expect(run.blocked).toBe(
			"point_timeout: the run step reached its share of the point's budget of 300 seconds",
		);
		expect(run.stopped).toBe('timeout');
		expect(run.cleanup).toBe('succeeded');

		// A setup out of time leaves run skipped, and that is the budget too.
		const first = await timedOut([
			out('setup'),
			{ step: 'run', status: 'skipped', reason: 'setup did not exit 0' },
			ran('cleanup'),
		])();
		expect(first.failures).toEqual([]);
		expect(first.blocked).toContain('point_timeout: the setup step');

		// Nothing left for run or cleanup after setup used its share.
		const none = await timedOut([
			ran('setup'),
			{ step: 'run', status: 'timeout', reason: "no time left in the point's budget" },
			{ step: 'cleanup', status: 'timeout', reason: "no time left in the point's budget" },
		])();
		expect(none.failures).toEqual([]);
		expect(none.blocked).toContain('point_timeout: the run step');
		expect(none.cleanup).toBe('not-run');

		// A run and a cleanup both out of time are blocked, not failed.
		const both = await timedOut([ran('setup'), out('run'), out('cleanup')])();
		expect(both.failures).toEqual([]);
		expect(both.blocked).toContain('point_timeout: the run step');
		expect(both.cleanup).toBe('not-run');

		// The exit code must still agree.
		const lied = await timedOut([ran('setup'), out('run'), ran('cleanup')], 0)();
		expect(lied.failures).toEqual([
			"supervisor_mismatch: the supervisor's exit line implies exit code 2, and the container exited 0",
		]);
	});

	test('assertions for the wrong point or undeclared ones reach the malformed limit and stop the verifier', async () => {
		for (const assertion of [
			'{"type":"assertion","point":"other.point","name":"home-says-hello","outcome":"pass","evidence":[]}',
			'{"type":"assertion","point":"hello.home","name":"made-up","outcome":"pass","evidence":[]}',
		]) {
			const t = await setup({ limits: { malformedPerPoint: 3 } });
			t.docker.verifierScript = async (v) => {
				await v.nextLine();
				for (let i = 0; i < 10; i++) v.out(assertion);
				// Nothing past the limit is read.
				v.out('{"type":"capture","kind":"screenshot","label":"late"}');
				await v.stopped;
				return 137;
			};
			const result = await t.run();
			expect(result.stopped).toBe('protocol-limit');
			expect(result.failures).toEqual([
				'runner_protocol_limit: the runner printed more than 3 lines that look like protocol lines and are not',
			]);
			expect(result.counts.malformed).toBe(4);
			expect(t.recorder.calls).toEqual([]);
		}
	});

	test('a secret cited as a reference or used as a label stays out of the events, and the point can still use it', async () => {
		const t = await setup();
		const token = 'b'.repeat(64);
		t.secrets.add(token);
		const acks: string[] = [];
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			v.out(`{"type":"capture","kind":"screenshot","label":"${token}"}`);
			acks.push(await v.nextLine());
			v.out(
				`{"type":"assertion","point":"hello.home","name":"home-says-hello","outcome":"pass","evidence":["${token}","capture:${token}","recorder:screenshot:9"],"detail":"got ${token}"}`,
			);
			for (const line of supervisorExit([
				{ step: 'setup', status: 'exited', code: 0 },
				{ step: 'run', status: 'failed', reason: `${token}: not found` },
				{ step: 'cleanup', status: 'exited', code: 0 },
			]))
				v.out(line);
			return 3;
		};
		const result = await t.run();
		// The capture is made: a word on the keys page must not cost a point its
		// evidence. The runner gets its own label back.
		expect(acks.map((a) => JSON.parse(a).status)).toEqual(['ready']);
		const artifact = result.artifacts[token];
		expect(artifact).toBeDefined();
		// The judge reads what the runner sent, so a reference still names its
		// artifact. What is kept of it goes through the run's sanitizer, and
		// verification.test.ts follows it to the records.
		expect(result.reports[0]?.evidence).toEqual([
			token,
			`capture:${token}`,
			'recorder:screenshot:9',
		]);
		expect(JSON.stringify(await t.events())).not.toContain(token);
		expect(result.failures[0]).toBe(
			`runner_failed: the run step could not start: ${token}: not found`,
		);
	});

	test('runner log lines are kept up to the cap, then counted', async () => {
		const t = await setup({ limits: { logLinesPerPoint: 3 } });
		t.docker.verifierScript = async (v) => {
			await v.nextLine();
			for (let i = 0; i < 6; i++) v.out(`line ${i}`);
			for (const line of supervisorExit(declaredSteps(v))) v.out(line);
			return 0;
		};
		const result = await t.run();
		expect(result.counts.logLines).toBe(6);
		const events = await t.events();
		expect(events.filter((e) => e.type === 'runner-log')).toHaveLength(3);
		expect(events.filter((e) => e.type === 'runner-log-capped')).toHaveLength(1);
		expect(PROTOCOL_LIMITS.logLinesPerPoint).toBe(2000);
	});
});

describe('the real supervisor under VerifierRunner', () => {
	const SUPERVISOR = join(import.meta.dir, '../../../host/verifier/supervisor.py');
	// main() with a working directory of the test's, since /workspace is the
	// container's. Everything else is the file koid puts in the verifier.
	const BOOT = `
import importlib.util, sys
spec = importlib.util.spec_from_file_location('supervisor', sys.argv[1])
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)
sys.exit(supervisor.main(['supervisor.py', sys.argv[2]], cwd=sys.argv[3]))
`;

	// The read side of a kernel pipe as a stream that reads only when asked, so
	// the test holds what is read and not Bun, which reads a pipe Bun.spawn
	// made into memory until a reader holds it. Non-blocking, since a blocking
	// read would hold a thread of the pool. The caller has the write end to pass
	// on, and closes its own copy.
	async function unbufferedPipe(dir: string): Promise<{
		stream: ReadableStream<Uint8Array>;
		writeEnd: number;
	}> {
		const path = join(dir, 'stdout.fifo');
		await exec(['mkfifo', path]);
		const readEnd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
		const writeEnd = openSync(path, constants.O_WRONLY);
		const stream = new ReadableStream<Uint8Array>(
			{
				async pull(controller) {
					for (;;) {
						const chunk = new Uint8Array(64 * 1024);
						const n = await new Promise<number | 'again'>((resolve, reject) => {
							readFd(readEnd, chunk, 0, chunk.length, null, (err, bytes) => {
								if (err === null) resolve(bytes);
								else if (err.code === 'EAGAIN') resolve('again');
								else reject(err);
							});
						});
						if (n === 'again') {
							await Bun.sleep(5);
							continue;
						}
						if (n === 0) {
							closeSync(readEnd);
							controller.close();
							return;
						}
						controller.enqueue(chunk.subarray(0, n));
						return;
					}
				},
			},
			{ highWaterMark: 0 },
		);
		return { stream, writeEnd };
	}

	// In place of `docker start --attach`: the same streams, from a process on
	// this box, with the point file koid would have written.
	async function attachForReal(t: Awaited<ReturnType<typeof setup>>, point: Point) {
		const dir = await mkdtemp(join(tmpdir(), 'koid-real-supervisor-'));
		const pointFile = join(dir, 'point.json');
		await writeFile(
			pointFile,
			JSON.stringify({
				version: 1,
				runner: null,
				steps: { setup: null, run: point.run.command, cleanup: null },
				timeoutSeconds: 60,
			}),
		);
		t.docker.attach = async (name) => {
			await t.docker.start(name);
			const stdout = await unbufferedPipe(dir);
			const proc = Bun.spawn(['python3', '-I', '-c', BOOT, SUPERVISOR, pointFile, dir], {
				stdin: 'pipe',
				stdout: stdout.writeEnd,
				stderr: 'pipe',
				env: { PATH: process.env.PATH ?? '' },
			});
			closeSync(stdout.writeEnd);
			return {
				async write(data) {
					proc.stdin.write(data);
					await proc.stdin.flush();
				},
				stdout: stdout.stream,
				stderr: proc.stderr,
				exited: proc.exited.then((exitCode) => {
					t.docker.exits.set(name, { status: 'exited', exitCode, oomKilled: false });
					const container = t.docker.containers.get(name);
					if (container !== undefined) container.running = false;
					return exitCode;
				}),
				detach() {
					proc.kill('SIGKILL');
				},
			};
		};
		return dir;
	}

	const point = (command: string[], assertions: string[]): Point => ({
		id: POINT.id,
		revision: 1,
		claim: POINT.claim,
		select: POINT.select,
		run: { command },
		assertions: assertions.map((name) => ({ name, description: name, evidence: ['aria'] })),
	});

	test('a capture that stalls past the supervisor limit loses nothing: the failing assertion arrives, and the verdict is fail', async () => {
		const t = await setup();
		const capture = t.recorder.capture.bind(t.recorder);
		// koid handles nothing from the verifier while it waits on this, and the
		// supervisor's own limit on a silent pipe was 5 seconds.
		t.recorder.capture = async (r) => {
			await Bun.sleep(7_000);
			return capture(r);
		};
		// More than a pipe holds, and little enough that the step can finish and
		// exit 0 with the failing assertion behind the capture in koid's queue.
		const step = `
import json
def say(event):
    print(json.dumps({"point": ${JSON.stringify(POINT.id)}, **event}), flush=True)
print(json.dumps({"type": "capture", "kind": "aria", "label": "slow"}), flush=True)
say({"type": "assertion", "name": "first", "outcome": "pass", "evidence": ["capture:slow"]})
for i in range(2500):
    print("log %06d " % i + "x" * 40, flush=True)
say({"type": "assertion", "name": "second", "outcome": "fail", "evidence": [], "detail": "the last thing it said"})
`;
		const executed = point(['python3', '-c', step], ['first', 'second']);
		const dir = await attachForReal(t, executed);
		try {
			const result = await t.run({ point: executed });
			expect(result.reports.map((r) => [r.name, r.outcome])).toEqual([
				['first', 'pass'],
				['second', 'fail'],
			]);
			expect(result.failures).toEqual([]);
			expect(result.supervisor?.steps[0]).toMatchObject({ status: 'exited', code: 0 });
			expect(result.supervisor?.steps[0]?.output_incomplete).toBeUndefined();
			const artifact = result.artifacts.slow ?? '';
			const verdict = judgePoint({
				id: executed.id,
				assertions: executed.assertions.map((a) => ({ name: a.name, evidence: a.evidence })),
				reports: result.reports.map((r) => ({
					...r,
					evidence: r.evidence.map((ref) => (ref === 'capture:slow' ? artifact : ref)),
				})),
				resolve: await t.writer.resolveEvidence([artifact]),
				blocked: result.blocked,
				cleanup: result.cleanup,
				recovery: result.recovery,
				failures: result.failures,
			});
			expect(verdict.outcome).toBe('fail');
			expect(verdict.reasons).toEqual(['second failed: the last thing it said']);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	}, 30_000);

	test("a descendant left holding the step's stdout is a signed output_incomplete, and fails the point", async () => {
		const t = await setup();
		// It leaves the step's session and outlasts the idle limit, then ends
		// on its own, so the test leaves nothing behind.
		const holder = 'import os, time\nos.setsid()\ntime.sleep(8)\n';
		const executed = point(['sh', '-c', `python3 -c '${holder}' & echo done`], ['first']);
		const dir = await attachForReal(t, executed);
		try {
			const result = await t.run({ point: executed });
			expect(result.stopped).toBe('exited');
			expect(result.supervisor?.steps[0]).toMatchObject({
				status: 'exited',
				code: 0,
				output_incomplete: true,
			});
			expect(result.failures).toEqual([
				"runner_output_incomplete: the supervisor stopped reading the run step's stdout, so what it wrote was not all read",
			]);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	}, 30_000);
});
