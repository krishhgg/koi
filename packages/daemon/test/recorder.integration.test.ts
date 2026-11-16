import { afterAll, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { RECORDER_BROWSER_PORT, RECORDER_CONTROL_PORT } from '@koi/shared';
import { cliDocker, sandboxProbeArgs } from '../src/docker.ts';
import { exec } from '../src/exec.ts';
import { httpRecorder, newRecorderTokens, recorderEnv } from '../src/recorder.ts';
import { helperMac, privateHost } from '../src/verification-network.ts';

// Real Docker, opt in with KOI_DOCKER_TESTS=1. Builds the recorder image
// from host/recorder (minutes, and it downloads the pinned base image and
// packages), runs the sandbox probe koid runs before it calls verification
// available, starts it with the production flags on a throwaway network
// next to a tiny static app, and checks the control port: health, a
// context opened at the app's root, a screenshot and an aria snapshot of
// it, acknowledgment, and that no capture ever touched the recorder's
// filesystem. Then it does what the verifier will: connects a Playwright
// client over the browser port with the run's token, drives the same page,
// asks it to leave the origin by name, by IP literal and by loopback, which
// must be denied and show up in the event feed, and tries what the
// allowlist refuses: a route (Fetch), a new context, tracing, a script-URL
// and a file-URL navigation, a drag with host files, and closing the
// recorder's own page.
//
// Every name is unique to this run, and cleanup removes only what this run
// created. The subnet is in TEST-NET-2, which nothing routes.
const enabled = process.env.KOI_DOCKER_TESTS === '1';
const run = randomUUID().replace(/-/g, '').slice(0, 10);
const runId = `it${run}${run}`;
const network = `koi-it-rec-${run}`;
// Not kv+: a provisioned box drops traffic on those bridges from everyone
// but koid, and this test runs as whoever runs it.
const bridge = `kr${run}00`;
const subnet = '198.51.100.0/28';
const gateway = '198.51.100.1';
const appIp = '198.51.100.2';
const recorderIp = '198.51.100.3';
const image = `koi-it-recorder:${run}`;
const appName = `koi-it-rec-app-${run}`;
const recorderName = `koi-verify-${runId}-recorder`;
const probeNames = ['ok', 'nochroot', 'noclone'].map((p) => `koi-sandbox-probe-it${run}${p}`) as [
	string,
	string,
	string,
];
const repo = resolve(import.meta.dir, '../../..');
const docker = cliDocker({ builder: 'unused' });
const tokens = newRecorderTokens();
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

async function must(cmd: string[], timeoutMs = 180_000): Promise<string> {
	const r = await exec(cmd, { timeoutMs });
	if (r.code !== 0) throw new Error(`${cmd.join(' ')}: ${r.stderr}`);
	return r.stdout;
}

afterAll(async () => {
	if (!enabled) return;
	await exec(['docker', 'rm', '--force', recorderName, appName, ...probeNames], {
		timeoutMs: 60_000,
	});
	await exec(['docker', 'network', 'rm', network], { timeoutMs: 60_000 });
	await exec(['docker', 'image', 'rm', '--force', image], { timeoutMs: 60_000 });
});

test.skipIf(!enabled)(
	'the recorder image serves captures of the app and denies everything outside its origin',
	async () => {
		await must(['docker', 'build', '--tag', image, resolve(repo, 'host/recorder')], 20 * 60_000);
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
		// A password field in the page and one in a child frame, both painted
		// red, so the pixel check below tells the mask from the field. The
		// frame's document has no quotes: the page goes through sh in single
		// quotes.
		const page =
			'<!doctype html><title>hello</title><body style="margin:0"><h1 style="position:absolute;left:10px;top:200px;margin:0">hello from koi</h1>' +
			'<input type="password" value="secret-value-123" style="position:absolute;left:10px;top:10px;width:100px;height:20px;border:0;color:#f00;background:#f00">' +
			'<iframe style="position:absolute;left:10px;top:100px;width:300px;height:60px;border:0" srcdoc="<body style=margin:0><input type=password value=secret-in-frame style=position:absolute;left:10px;top:10px;width:100px;height:20px;border:0;color:#f00;background:#f00>"></iframe></body>';
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
			`mkdir -p /www && printf '%s' '${page}' > /www/index.html && exec httpd -f -p 8080 -h /www`,
		]);
		const appHost = privateHost(runId);
		// The check koid makes before it calls verification available: Chromium
		// starts with its sandbox under the recorder's confinement, and does not
		// under a seccomp profile that refuses chroot, as this one did before, or
		// one that allows namespaces through unshare but not through clone,
		// which is how Chromium makes them.
		const seccomp = resolve(repo, 'host/recorder/seccomp.json');
		const probed = await exec(sandboxProbeArgs(probeNames[0], image, seccomp), {
			timeoutMs: 120_000,
		});
		expect(probed.stderr).toBe('');
		expect(probed.code).toBe(0);
		const without = async (name: string, syscall: string, rules: 'all' | 'first') => {
			const profile = JSON.parse(await readFile(seccomp, 'utf8')) as {
				syscalls: Array<{ names: string[] }>;
			};
			for (const [i, rule] of profile.syscalls.entries()) {
				if (rules === 'all' || i === 0) rule.names = rule.names.filter((n) => n !== syscall);
			}
			const path = join(tmpdir(), `koi-it-seccomp-${run}-${syscall}.json`);
			await writeFile(path, JSON.stringify(profile));
			return exec(sandboxProbeArgs(name, image, path), { timeoutMs: 120_000 });
		};
		const noChroot = await without(probeNames[1], 'chroot', 'all');
		expect(noChroot.code).toBe(1);
		expect(noChroot.stderr).toContain('chroot');
		// The rules after the first still allow clone without namespace flags.
		const noClone = await without(probeNames[2], 'clone', 'first');
		expect(noClone.code).toBe(1);
		expect(noClone.stderr.trim()).not.toBe('');

		await docker.createRecorder({
			name: recorderName,
			image,
			network,
			ip: recorderIp,
			mac: helperMac(recorderIp),
			runId,
			appHost: { name: appHost, ip: appIp },
			dns: gateway,
			env: { KOI_RUN_ID: runId, KOI_PREVIEW_URL: `http://${appHost}:8080`, ...recorderEnv(tokens) },
			seccompProfile: seccomp,
		});
		await docker.start(recorderName);
		expect((await must(['docker', 'exec', recorderName, 'id', '-u'])).trim()).toBe('10001');
		const touch = await exec(['docker', 'exec', recorderName, 'sh', '-c', 'touch /app/x'], {
			timeoutMs: 30_000,
		});
		expect(touch.code).not.toBe(0);

		const control = `http://${recorderIp}:${RECORDER_CONTROL_PORT}`;
		const api = httpRecorder(control, tokens.control);
		const deadline = Date.now() + 120_000;
		let ready = false;
		let last = 'no answer';
		while (Date.now() < deadline) {
			try {
				const health = await api.health();
				if (health.ok) {
					expect(health.runId).toBe(runId);
					expect(health.browser.name).toBe('chromium');
					expect(health.playwright).toBe('1.64.1');
					expect(health.origin).toBe(`http://${appHost}:8080`);
					ready = true;
					break;
				}
				last = health.reason;
			} catch (err) {
				last = err instanceof Error ? err.message : String(err);
			}
			await Bun.sleep(1_000);
		}
		if (!ready) throw new Error(`the recorder did not become ready: ${last}`);
		const wrong = await fetch(`${control}/health`, { headers: { authorization: 'Bearer nope' } });
		expect(wrong.status).toBe(401);

		const context = await api.openContext({ pointId: 'it.home', attempt: 1, open: '/' });
		expect(context.url).toBe(`http://${appHost}:8080/`);
		const shot = await api.capture(context.contextId, { kind: 'screenshot', label: 'home' });
		const png = Buffer.from(await new Response(await api.bytes(shot.captureId)).arrayBuffer());
		expect([...png.subarray(0, 8)]).toEqual(PNG_SIGNATURE);
		expect(png.length).toBe(shot.size);
		const aria = await api.capture(context.contextId, { kind: 'aria', label: 'tree' });
		const tree = await new Response(await api.bytes(aria.captureId)).text();
		expect(tree).toContain('hello from koi');
		// Raw captures live in the recorder's memory, never under /tmp, which
		// Chromium shares.
		const tmp = await must(['docker', 'exec', recorderName, 'find', '/tmp', '-type', 'f']);
		expect(tmp.split('\n').filter((f) => f.includes('koi-recorder/captures'))).toEqual([]);
		await api.acknowledge(shot.captureId);
		await api.acknowledge(aria.captureId);
		await expect(api.bytes(shot.captureId)).rejects.toThrow();
		const read = await api.read(context.contextId, {
			method: 'GET',
			path: '/',
			maxBodyBytes: 4096,
		});
		const state = JSON.parse(await new Response(await api.bytes(read.captureId)).text()) as {
			response: { status: number; bodyBase64: string };
		};
		expect(state.response.status).toBe(200);
		expect(Buffer.from(state.response.bodyBase64, 'base64').toString()).toContain('hello from koi');
		await api.acknowledge(read.captureId);

		// The verifier's path.
		const bad = await fetch(`http://${recorderIp}:${RECORDER_BROWSER_PORT}/nope`, {
			headers: { upgrade: 'websocket' },
		});
		expect(bad.status).toBe(404);
		const { chromium } = await import('playwright-core');
		const browser = await chromium.connectOverCDP(
			`ws://${recorderIp}:${RECORDER_BROWSER_PORT}/${tokens.browser}`,
			{ timeout: 30_000 },
		);
		try {
			const pages = browser.contexts().flatMap((c) => c.pages());
			const home = pages.find((p) => p.url().startsWith(`http://${appHost}:8080`));
			if (home === undefined)
				throw new Error(`no page of the app among ${pages.map((p) => p.url()).join(', ')}`);
			expect(await home.textContent('h1')).toBe('hello from koi');
			// The screenshot taken above, read back pixel by pixel in the page:
			// the password field in the page and the one in the child frame are
			// both black, which only the mask paints; the page beside them is
			// not.
			const points: Array<[number, number]> = [
				[60, 20],
				[70, 120],
				[300, 20],
			];
			const pixels = await home.evaluate(
				async ({ b64, points }) => {
					// The page's globals, typed here: this file is compiled without
					// the DOM library.
					const win = globalThis as unknown as {
						Image: new () => {
							src: string;
							width: number;
							height: number;
							decode(): Promise<void>;
						};
						document: {
							createElement(tag: 'canvas'): {
								width: number;
								height: number;
								getContext(kind: '2d'): {
									drawImage(image: unknown, x: number, y: number): void;
									getImageData(
										x: number,
										y: number,
										w: number,
										h: number,
									): { data: ArrayLike<number> };
								} | null;
							};
						};
					};
					const img = new win.Image();
					img.src = `data:image/png;base64,${b64}`;
					await img.decode();
					const canvas = win.document.createElement('canvas');
					canvas.width = img.width;
					canvas.height = img.height;
					const ctx = canvas.getContext('2d');
					if (ctx === null) throw new Error('no canvas');
					ctx.drawImage(img, 0, 0);
					return points.map(([x, y]) => Array.from(ctx.getImageData(x, y, 1, 1).data).slice(0, 3));
				},
				{ b64: png.toString('base64'), points },
			);
			expect(pixels).toEqual([
				[0, 0, 0],
				[0, 0, 0],
				[255, 255, 255],
			]);
			expect(shot.limitations).toBeUndefined();
			await expect(home.goto('http://example.com/', { timeout: 15_000 })).rejects.toThrow();
			// A denied navigation leaves Chromium's error page in the tab, though
			// Playwright still reports the app's URL. Back to the app, so the
			// requests below come from its origin and reach the guard.
			await home.goto(`http://${appHost}:8080/`, { timeout: 15_000 });
			expect(await home.title()).toBe('hello');
			// An IP literal and loopback: the guard denies them, and the proxy
			// layer under it has nowhere to send them either.
			for (const url of [
				'http://203.0.113.1/',
				`http://127.0.0.1:${RECORDER_CONTROL_PORT}/health`,
			]) {
				const fetched = await home.evaluate(
					(u) =>
						fetch(u).then(
							() => 'ok',
							(err: Error) => `failed: ${err.message}`,
						),
					url,
				);
				expect(fetched).toStartWith('failed');
			}
			// A script URL does not navigate, a drag with files is refused, and
			// the recorder's own page cannot be closed from the client, neither
			// by target (Target.closeTarget) nor from inside its session
			// (Page.close). These go through a raw CDP session, which the proxy
			// checks like any other message; the session is known because the
			// proxy saw it attach, and each refusal comes back on that session,
			// which is why the send rejects instead of hanging.
			const cdp = await home.context().newCDPSession(home);
			try {
				const { targetInfo } = (await cdp.send('Target.getTargetInfo')) as {
					targetInfo: { targetId: string };
				};
				await expect(cdp.send('Page.navigate', { url: 'javascript:void(0)' })).rejects.toThrow(
					'non-navigable',
				);
				await expect(cdp.send('Page.navigate', { url: 'file:///etc/hostname' })).rejects.toThrow(
					'non-navigable',
				);
				await expect(
					cdp.send('Input.dispatchDragEvent', {
						type: 'drop',
						x: 1,
						y: 1,
						data: { items: [], files: ['/etc/hostname'], dragOperationsMask: 1 },
					}),
				).rejects.toThrow('not permitted');
				await expect(
					cdp.send('Target.closeTarget', { targetId: targetInfo.targetId }),
				).rejects.toThrow('not permitted');
				await expect(cdp.send('Page.close')).rejects.toThrow('not permitted');
			} finally {
				await cdp.detach().catch(() => {});
			}
			// The recorder's page is still open and driveable.
			expect(await home.title()).toBe('hello');
			// What the allowlist refuses: a route needs Fetch, a new context
			// needs Target.createBrowserContext, and the protocol's Tracing domain
			// is refused outright. Playwright's own tracing records on the client
			// and sends the browser nothing of it, so it is sent here raw.
			await expect(home.route('**/*', (route) => route.continue())).rejects.toThrow(
				'not permitted',
			);
			await expect(browser.newContext()).rejects.toThrow('not permitted');
			const raw = await home.context().newCDPSession(home);
			try {
				await expect(raw.send('Tracing.start')).rejects.toThrow('not permitted');
			} finally {
				await raw.detach().catch(() => {});
			}
			// Still driving the page afterwards.
			expect(await home.title()).toBe('hello');
		} finally {
			await browser.close();
		}
		const feed = await api.events(0, 1000);
		const types = feed.events.map((e) => e.type);
		expect(types).toContain('client-connected');
		expect(types).toContain('client-rewritten');
		expect(
			feed.events.some(
				(e) => e.type === 'denied' && String(e.url).startsWith('http://example.com/'),
			),
		).toBe(true);
		expect(
			feed.events.some((e) => e.type === 'denied' && String(e.url).startsWith('http://127.0.0.1')),
		).toBe(true);
		expect(feed.events.filter((e) => e.type === 'client-denied').map((e) => e.method)).toEqual(
			expect.arrayContaining([
				'Fetch.enable',
				'Target.createBrowserContext',
				'Page.navigate',
				'Input.dispatchDragEvent',
				'Target.closeTarget',
				'Page.close',
				'Tracing.start',
			]),
		);
		expect(feed.events.some((e) => e.type === 'foreign-target')).toBe(false);
		expect(feed.events.some((e) => e.type === 'guard-unavailable')).toBe(false);
		await api.closeContext(context.contextId);
		expect((await api.health()).ok && (await api.health())).toMatchObject({ contexts: 0 });
	},
	30 * 60_000,
);
