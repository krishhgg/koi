import { afterAll, expect, test } from 'bun:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { type RunNetworkRecord, stagingName } from '@koi/shared';
import { cliDocker } from '../src/docker.ts';
import { exec } from '../src/exec.ts';
import { newRecorderTokens, RecorderSession, recorderEnv } from '../src/recorder.ts';
import { SecretRegistry } from '../src/redact.ts';
import { judgePoint, type ResolvedEvidence } from '../src/verdict.ts';
import { helperMac, helperName, privateHost } from '../src/verification-network.ts';
import { EvidenceStore } from '../src/verification-store.ts';
import {
	inputVolumes,
	type PointRun,
	resolveRunnerImage,
	VerifierRunner,
} from '../src/verifier.ts';

// Real Docker, opt in with KOI_DOCKER_TESTS=1. Builds examples/hello, the
// recorder (host/recorder) and the default verifier (host/verifier), which
// takes minutes and downloads the pinned bases and packages, then does for
// the hello point what `koi verify run` does for each point of a plan: the
// recorder's context opened at /, a verifier created from the resolved
// image with the frozen inputs and the supervisor, the point's runner
// executed under the protocol against the recorder's browser, and the
// point judged from what it reported against what the recorder kept. The
// point must pass with a screenshot and an http-response state read, and
// fail against a hello app whose heading says something else.
//
// The controller itself is not driven here: its run network needs the
// root-owned firewall helper for the verifier to reach the recorder at all
// (inter-container traffic is off on a run network), and this test runs as
// whoever runs it. The controller's path over this same runner is covered
// with fakes in verification.test.ts. The network here is a plain one, not
// kv+, so a provisioned box's rules do not drop it; the subnet is in
// TEST-NET-3, which nothing routes.
const enabled = process.env.KOI_DOCKER_TESTS === '1';
const run = randomUUID().replace(/-/g, '').slice(0, 10);
const runId = `it${run}${run}`;
const network = `koi-it-ver-${run}`;
const bridge = `ke${run}00`;
const subnet = '203.0.113.0/28';
const gateway = '203.0.113.1';
const appIp = '203.0.113.2';
const recorderIp = '203.0.113.3';
const verifierIp = '203.0.113.4';
const recorderImage = `koi-it-recorder:${run}`;
const verifierImage = `koi-it-verifier:${run}`;
const helloImage = `koi-it-hello:${run}`;
const appName = `koi-it-ver-app-${run}`;
const recorderName = helperName(runId, 'recorder');
const verifierName = helperName(runId, 'verifier');
const repo = resolve(import.meta.dir, '../../..');
const docker = cliDocker({ builder: 'unused' });
const tokens = newRecorderTokens();
const appHost = privateHost(runId);

async function must(cmd: string[], timeoutMs = 180_000): Promise<string> {
	const r = await exec(cmd, { timeoutMs });
	if (r.code !== 0) throw new Error(`${cmd.join(' ')}: ${r.stderr}`);
	return r.stdout;
}

afterAll(async () => {
	if (!enabled) return;
	await exec(['docker', 'rm', '--force', verifierName, stagingName(runId), recorderName, appName], {
		timeoutMs: 60_000,
	});
	await exec(['docker', 'volume', 'rm', ...inputVolumes(runId).map((v) => v.name)], {
		timeoutMs: 60_000,
	});
	await exec(['docker', 'network', 'rm', network], { timeoutMs: 60_000 });
	await exec(['docker', 'image', 'rm', '--force', recorderImage, verifierImage, helloImage], {
		timeoutMs: 60_000,
	});
});

// The hello app, or one with another heading, at the app's address.
async function startApp(heading: string | undefined): Promise<void> {
	await exec(['docker', 'rm', '--force', appName], { timeoutMs: 60_000 });
	if (heading === undefined) {
		await must([
			'docker',
			'run',
			'--detach',
			'--name',
			appName,
			'--network',
			network,
			'--ip',
			appIp,
			helloImage,
		]);
		return;
	}
	await must([
		'docker',
		'run',
		'--detach',
		'--name',
		appName,
		'--network',
		network,
		'--ip',
		appIp,
		'busybox:1.37',
		'sh',
		'-c',
		`mkdir -p /www && printf '<!doctype html><title>hello</title><h1>${heading}</h1>' > /www/index.html && exec httpd -f -p 8080 -h /www`,
	]);
}

test.skipIf(!enabled)(
	'the hello point passes in the verifier against the recorder, and fails against a mutated app',
	async () => {
		await must(
			['docker', 'build', '--tag', helloImage, resolve(repo, 'examples/hello')],
			10 * 60_000,
		);
		await must(
			['docker', 'build', '--tag', recorderImage, resolve(repo, 'host/recorder')],
			20 * 60_000,
		);
		await must(
			['docker', 'build', '--tag', verifierImage, resolve(repo, 'host/verifier')],
			20 * 60_000,
		);
		await must([
			'docker',
			'network',
			'create',
			'--driver',
			'bridge',
			'--internal',
			'--subnet',
			subnet,
			'--gateway',
			gateway,
			'--opt',
			`com.docker.network.bridge.name=${bridge}`,
			network,
		]);
		await startApp(undefined);

		// The run network's record, as koid would have it for this network.
		const record: RunNetworkRecord = {
			version: 1,
			runId,
			network,
			bridge,
			subnet,
			gateway,
			appContainer: appName,
			appPort: 8080,
			state: 'ready',
			endpoints: [
				{ role: 'app', container: appName, ip: appIp, mac: '02:42:cb:00:71:02' },
				{ role: 'recorder', container: recorderName, ip: recorderIp, mac: helperMac(recorderIp) },
				{ role: 'verifier', container: verifierName, ip: verifierIp, mac: helperMac(verifierIp) },
			],
			createdAt: new Date().toISOString(),
		};
		const common = {
			network,
			runId,
			appHost: { name: appHost, ip: appIp },
			dns: gateway,
			env: { KOI_RUN_ID: runId, KOI_PREVIEW_URL: `http://${appHost}:8080` },
		};
		await docker.createRecorder({
			...common,
			name: recorderName,
			image: recorderImage,
			ip: recorderIp,
			mac: helperMac(recorderIp),
			env: { ...common.env, ...recorderEnv(tokens) },
			seccompProfile: resolve(repo, 'host/recorder/seccomp.json'),
		});
		// The placeholder the run network would have made.
		await docker.createVerifier({
			...common,
			name: verifierName,
			image: verifierImage,
			ip: verifierIp,
			mac: helperMac(verifierIp),
		});

		// The image policy: the manifest names the default image.
		const info = await docker.imageInfo(verifierImage);
		if (info === undefined) throw new Error('the verifier image was not built');
		const image = await resolveRunnerImage(docker, 'koi-verifier', {
			defaultImageId: info.id,
			allowed: [],
		});
		if (!image.ok) throw new Error(image.reason);

		const state = await mkdtemp(join(tmpdir(), 'koid-it-verifier-'));
		const evidence = new EvidenceStore({ stateDir: state, now: () => new Date() });
		await evidence.init();
		const writer = await evidence.openRun(runId);
		const secrets = new SecretRegistry();
		secrets.add(tokens.control);
		secrets.add(tokens.browser);
		const logs: string[] = [];
		const log = (m: string) => {
			logs.push(m);
			console.log(m);
		};
		const deps = {
			docker,
			network: { reapply: async () => {} },
			secrets,
			now: () => new Date(),
			sleep: (ms: number) => Bun.sleep(ms),
			log,
		};
		const session = await RecorderSession.start(deps, { record, tokens, run: writer });
		const runner = new VerifierRunner(deps);
		const { loadVerifyConfig } = await import('@koi/shared');
		const config = await loadVerifyConfig(resolve(repo, 'examples/hello'));
		const loaded = config.points[0];
		if (loaded === undefined) throw new Error('no hello point');

		// One point against one app, as the controller runs it.
		const runPoint = async (
			attempt: number,
		): Promise<PointRun & { outcome: string; reasons: string[]; evidence: string[] }> => {
			await session.openPoint(loaded.point.id, attempt, '/');
			let result: PointRun;
			try {
				result = await runner.run(
					{
						runId,
						pointId: loaded.point.id,
						attempt,
						point: loaded.point,
						runnerCommand: config.manifest.runner.command,
						image: image.digest,
						record,
						browserToken: tokens.browser,
						source: resolve(repo, 'examples/hello'),
						fixtures: [],
						timeoutSeconds: 120,
						maxRequests: 20,
						pointDeadline: Date.now() + 120_000,
						deadline: Date.now() + 300_000,
					},
					session,
					writer,
					{ stopRequested: () => undefined },
				);
			} finally {
				await session.closePoint();
			}
			const reports = result.reports.map((r) => ({
				...r,
				evidence: r.evidence.map((ref) =>
					ref.startsWith('capture:') ? (result.artifacts[ref.slice(8)] ?? ref) : ref,
				),
			}));
			// Each cited artifact, with its bytes on disk hashed against the
			// manifest, as the controller resolves them.
			const cited = new Map<string, ResolvedEvidence>();
			for (const ref of new Set(reports.flatMap((r) => r.evidence))) {
				const entry = writer.artifacts.find(
					(a) => a.id === ref && a.pointId === loaded.point.id && a.attempt === attempt,
				);
				if (entry === undefined) continue;
				let integrity: ResolvedEvidence['integrity'] = 'missing';
				if (entry.availability === 'available') {
					const bytes = await readFile(join(writer.dir, 'artifacts', entry.id));
					const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
					integrity = digest === entry.sha256 ? 'verified' : 'corrupt';
				}
				cited.set(ref, {
					kind: entry.kind,
					availability: entry.availability,
					redaction: entry.redaction.status,
					integrity,
				});
			}
			const verdict = judgePoint({
				id: loaded.point.id,
				assertions: loaded.point.assertions.map((a) => ({ name: a.name, evidence: a.evidence })),
				reports,
				resolve: (ref) => cited.get(ref),
				blocked: result.blocked,
				cleanup: result.cleanup,
				recovery: result.recovery,
				failures: result.failures,
			});
			return {
				...result,
				outcome: verdict.outcome,
				reasons: verdict.reasons,
				evidence: verdict.evidence,
			};
		};

		try {
			const passed = await runPoint(1);
			expect(passed.stopped).toBe('exited');
			expect(passed.blocked).toBeUndefined();
			expect(passed.failures).toEqual([]);
			expect(passed.supervisor?.status).toBe('exited');
			expect(passed.exit).toEqual({ status: 'exited', exitCode: 0, oomKilled: false });
			expect(passed.reasons).toEqual([]);
			expect(passed.outcome).toBe('pass');
			expect(passed.reports).toHaveLength(1);
			expect(passed.reports[0]?.detail).toBe('the heading reads "hello from koi"');
			// A screenshot and the recorder's own read of /, both kept.
			const kinds = passed.evidence.map((id) => writer.artifacts.find((a) => a.id === id)?.kind);
			expect(kinds.sort()).toEqual(['http-response', 'screenshot']);
			const read = writer.artifacts.find((a) => a.kind === 'http-response' && a.attempt === 1);
			const state = JSON.parse(
				await readFile(join(writer.dir, 'artifacts', read?.id ?? ''), 'utf8'),
			) as { response: { status: number; body?: string } };
			expect(state.response.status).toBe(200);
			expect(state.response.body).toContain('hello from koi');
			const shot = writer.artifacts.find((a) => a.kind === 'screenshot' && a.attempt === 1);
			expect(shot?.availability).toBe('available');
			expect(shot?.size).toBeGreaterThan(1000);
			// The verifier is gone once the point is, and so is what held its
			// inputs.
			const gone = await exec(['docker', 'container', 'inspect', verifierName], {
				timeoutMs: 15_000,
			});
			expect(gone.code).not.toBe(0);
			const staging = await exec(['docker', 'container', 'inspect', stagingName(runId)], {
				timeoutMs: 15_000,
			});
			expect(staging.code).not.toBe(0);
			// One inspect at a time: an inspect of several exits nonzero when any
			// one is missing, so removing only the first would satisfy it.
			for (const { name } of inputVolumes(runId)) {
				const volume = await exec(['docker', 'volume', 'inspect', name], { timeoutMs: 15_000 });
				expect([name, volume.code === 0]).toEqual([name, false]);
			}

			// The same point against an app that says something else.
			await startApp('hello from nobody');
			const failed = await runPoint(2);
			expect(failed.stopped).toBe('exited');
			expect(failed.failures).toEqual([]);
			expect(failed.outcome).toBe('fail');
			expect(failed.reasons).toEqual([
				'home-says-hello failed: the heading reads "hello from nobody", not "hello from koi"',
			]);
			// The events hold the runner's words, scrubbed, and never the token.
			const events = await readFile(join(writer.dir, 'events.ndjson'), 'utf8');
			expect(events).toContain('"type":"runner-assertion"');
			expect(events).toContain('"type":"supervisor-exit"');
			expect(events).not.toContain(tokens.browser);
		} finally {
			await session.stop();
			await writer.finalize({ limitations: [] }).catch(() => {});
		}
	},
	40 * 60_000,
);
