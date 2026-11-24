import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { verifyPoolProblem } from '@koi/shared';
import { Activity, hasEstablishedConnections, startLogSink } from './activity.ts';
import { buildAdapters } from './adapters.ts';
import { BuildLogs } from './buildlog.ts';
import { caddyApplier } from './caddy.ts';
import { type Config, loadConfig } from './config.ts';
import { groupId, startControlServer } from './control.ts';
import { type CtlIo, ctl, ctlEncoded, socketFetch } from './ctl.ts';
import { Deployer } from './deployer.ts';
import { cliDocker, watchDeaths } from './docker.ts';
import { egressControl, proxyPreviews } from './egress.ts';
import { loadEgress } from './egress-config.ts';
import { diskSpace, extractTarball, resolveInside } from './fsutil.ts';
import { hostSpec, verificationCapability, verifyHost } from './host.ts';
import { hostDescriber } from './host-info.ts';
import { FORGET_LIMITS, handleKeys, REGISTER_LIMITS } from './keys.ts';
import { RateLimit } from './ratelimit.ts';
import { loadBuiltinRecipe, readRecipe } from './recipes.ts';
import { MAX_SECRET_VALUES, SecretRegistry } from './redact.ts';
import { createHttpServer } from './server.ts';
import { PreviewStore } from './store.ts';
import { Verification } from './verification.ts';
import { sudoHelper, VerificationNetwork } from './verification-network.ts';
import { snapshotInputs } from './verification-snapshot.ts';
import { EvidenceStore } from './verification-store.ts';

// The exact secret values koid has seen while running: login keys, and the
// keys and tokens of the keys page. In memory only; the sanitizers and the
// log use them. Bounded (MAX_SECRET_VALUES): the keys page registers values
// for anyone the egress proxy lets through, and past the bound the oldest
// go, which the log says, since a sanitizer may then miss one of them.
const secrets = new SecretRegistry({
	onEvict: (count) =>
		log(
			`secret registry: at its bound of ${MAX_SECRET_VALUES} values; forgot the oldest ${count}, which the evidence sanitizers may now miss`,
		),
});

// Messages can carry a build's or a container's output.
function log(message: string): void {
	console.log(secrets.redact(message));
}

async function probe(url: string): Promise<boolean> {
	try {
		const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(3_000) });
		return res.status < 500;
	} catch {
		return false;
	}
}

// Logs a failure of something that repeats once, until it fails another way
// or works again (failure undefined).
function logOnce(log: (message: string) => void) {
	let last: string | undefined;
	return (failure: string | undefined, text: string) => {
		if (failure !== undefined && failure !== last) log(text);
		last = failure;
	};
}

function errorText(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

// The settings from the environment, or exit saying which one is missing and
// where it is set.
function configOrExit(): Config {
	try {
		return loadConfig();
	} catch (err) {
		log(`koid: ${errorText(err)}`);
		process.exit(1);
	}
}

// Startup runs in this order, and nothing listens until it is done, so the
// health endpoint answers only once koid is ready (scripts/deploy-host.sh
// waits for it):
// 1. check the networks, builder and slice provisioning made, and exit if
//    they are missing or wrong (systemd restarts koid);
// 2. open the record store and the evidence store, and move build logs koid
//    kept before logs were per attempt;
// 3. reconcile records with what Docker has, and route what runs; remove
//    what verification runs left behind, then check what verification
//    needs, which only decides whether it is available;
// 4. expire previews whose ttl passed while the box slept;
// 5. stop and block previews over their disk limit, stopped ones included;
// 6. start every other preview that serves, in the background: Docker
//    leaves them stopped when the box stops (Deployer.restore);
// 7. start the log sink, the HTTP server and the control socket;
// 8. start the timers.
async function daemon(): Promise<void> {
	const config = configOrExit();
	const problems = await verifyHost(hostSpec(config));
	if (problems.length > 0) {
		log(
			`koid: the box is not provisioned as koid needs; run scripts/provision-host.sh\n  ${problems.join('\n  ')}`,
		);
		process.exit(1);
	}
	const store = new PreviewStore(config.stateDir);
	await store.init();
	for (const record of await store.list()) {
		if (record.loginKey !== undefined) secrets.add(record.loginKey);
	}
	const evidence = new EvidenceStore({
		stateDir: config.stateDir,
		now: () => new Date(),
		log,
		scrub: (text) => secrets.redact(text),
	});
	await evidence.init();
	const buildLogs = new BuildLogs(config.stateDir);
	await buildLogs
		.upgrade(await store.list())
		.catch((err: unknown) => log(`moving old build logs: ${errorText(err)}`));
	const docker = cliDocker({ builder: config.builder, slice: config.slice });
	// Where uploads come from and where the live list goes: S3 and SSM on
	// AWS, a spool on this host and a file elsewhere (adapters.ts).
	const adapters = buildAdapters(config, { log });
	log(
		`uploads: ${config.uploads === 's3' ? `s3 bucket ${config.uploadsBucket}` : `spool ${config.spoolDir}`}; live list: ${config.live === 'ssm' ? `ssm parameter ${config.previewsParam}` : `file ${config.liveFile}`}`,
	);
	// Visits count only for live previews. Nothing can visit before the
	// deployer below exists and has read its records.
	const activity = new Activity(join(config.stateDir, 'last-activity'), Date.now, 30_000, (label) =>
		deployer.isLive(label),
	);
	// Without the egress proxy, previews have no way out at all; with it, they
	// get its address and its CA (host/egress, installed by deploy-host.sh).
	const egress =
		config.egressProxy !== undefined && config.egressCa !== undefined
			? await loadEgress(config.egressProxy, config.egressCa)
			: undefined;
	log(egress === undefined ? 'egress proxy: none' : `egress proxy: ${config.egressProxy}`);
	// The proxy's control socket: the keys page registers keys there, and the
	// deployer tells it which preview each container address runs with every
	// change of routes, so a koi token works only from its own preview.
	const proxyControl = egressControl(config.egressControl);
	const deployer = new Deployer({
		domain: config.domain,
		network: config.network,
		slice: config.slice,
		stateDir: config.stateDir,
		store,
		docker,
		uploads: adapters.uploads,
		caddy: caddyApplier({
			domain: config.domain,
			httpPort: config.httpPort,
			logPort: config.logPort,
			file: config.caddyfile,
			adminUrl: config.caddyAdmin,
		}),
		...(egress !== undefined ? { previews: proxyPreviews(proxyControl) } : {}),
		live: adapters.live,
		buildLogs,
		builtinRecipe: (name) => loadBuiltinRecipe(config.recipesDir, name),
		readRecipe,
		keepAwake: () => activity.touch(true),
		extract: extractTarball,
		resolveInside,
		diskSpace: () => diskSpace(config.dockerRoot),
		probe,
		snapshotInputs: async (input) => {
			await snapshotInputs(evidence.inputsDir(input.deploymentId), input);
		},
		// A login key made after startup is known to the sanitizers before
		// the preview is started with it; the loop above covers the ones
		// made before.
		registerSecret: (value) => secrets.add(value),
		...(egress !== undefined ? { egress } : {}),
		drainVisits: () => activity.drainVisits(),
		now: () => new Date(),
		sleep: (ms) => Bun.sleep(ms),
		log,
	});

	await deployer.reconcile();
	// Verification is a capability, not a requirement: a box provisioned
	// before it keeps serving previews and reports it unavailable. Run
	// networks, their helpers and their firewall permits from before this
	// start all go, since no run outlives koid. The check removes them once
	// it has found the helper safe to call, and judges the box only after
	// that; host.ts says why in that order. A leftover the cleanup could not
	// remove is one of the reasons it reports. A pool of the wrong shape is
	// another: no run network is made from it, and the capability check
	// names the problem (host.ts) instead of koid stopping over it.
	const pool =
		config.verifyPool !== undefined && verifyPoolProblem(config.verifyPool) === undefined
			? config.verifyPool
			: undefined;
	const runNetworks =
		pool !== undefined
			? new VerificationNetwork({
					docker,
					helper: sudoHelper(config.verifyHelper),
					pool,
					previewNetwork: config.network,
					stateDir: config.stateDir,
					slice: config.slice,
					now: () => new Date(),
					log,
				})
			: undefined;
	const verification = await verificationCapability({
		pool: config.verifyPool,
		helper: config.verifyHelper,
		slice: config.slice,
		recorderImage: config.recorderImage,
		recorderSeccomp: config.recorderSeccomp,
		verifierImage: config.verifierImage,
		cleanup: runNetworks === undefined ? undefined : () => runNetworks.cleanupOrphans(),
	});
	log(
		verification.available
			? 'verification: available'
			: `verification: unavailable (${verification.reason})`,
	);
	// The run controller. Before anything can ask for a run: every run the
	// last koid left running is marked interrupted; it never becomes passed.
	// Its lease goes only when the cleanup above is known to have run.
	const runs = new Verification({
		evidence,
		store,
		deployer,
		capability: verification,
		network: verification.available ? runNetworks : undefined,
		docker,
		recorderImage: config.recorderImage,
		recorderSeccomp: config.recorderSeccomp,
		verifierImages: config.verifierImages,
		secrets,
		keepAwake: () => activity.touch(true),
		now: () => new Date(),
		sleep: (ms) => Bun.sleep(ms),
		log,
	});
	await runs.recover({ releaseLeases: verification.available });
	const expired = await deployer.expire();
	if (expired.length > 0) log(`expired ${expired.join(', ')}`);
	await sweepEvidence(evidence);
	// Before anything can visit: a preview stopped for disk use stays
	// stopped, even if its record could not say so. If this run fails,
	// visits start no stopped container until the five-minute timer below
	// has measured them.
	await deployer.stopOversized().catch((err: unknown) => log(`disk watchdog: ${errorText(err)}`));
	// After expiry and the disk watchdog, so that neither a preview past its
	// ttl nor one over its disk limit starts. If the watchdog's run above
	// failed, restore waits for the first run of the timer below that
	// succeeds. Not awaited: health checks can take minutes, and a visit that
	// comes meanwhile shares its preview's start.
	void deployer
		.restore()
		.then((labels) => labels.length > 0 && log(`started ${labels.join(', ')}`))
		.catch((err: unknown) => log(`starting previews: ${errorText(err)}`));

	const onVisit = (label: string) => activity.visit(label);
	const keysLimits = {
		register: new RateLimit(REGISTER_LIMITS),
		forget: new RateLimit(FORGET_LIMITS),
	};
	startLogSink(config.logPort, config.domain, onVisit);
	createHttpServer({
		port: config.httpPort,
		domain: config.domain,
		deployer,
		onVisit,
		log,
		pages: {
			keys: (request) =>
				handleKeys(request, proxyControl, keysLimits, (values) => {
					for (const value of values) secrets.add(value);
				}),
		},
	});
	// The spool's directories exist and its leftovers are gone before the
	// socket that fills it listens.
	await adapters.spool?.init();
	await mkdir(join(config.controlSocket, '..'), { recursive: true });
	const gid = await groupId(config.controlGroup);
	if (gid === undefined) {
		log(
			`control socket: this host has no group ${config.controlGroup}, so only root and koi can open it`,
		);
	}
	await startControlServer(
		config.controlSocket,
		{
			deployer,
			store,
			docker,
			buildLogs,
			keepAwake: () => activity.touch(),
			describe: hostDescriber(config.stateDir, config.domain),
			uploadApi: adapters.spool,
			verification: runs,
		},
		{ gid, log },
	);
	log(`koid listening on 127.0.0.1:${config.httpPort}, control ${config.controlSocket}`);

	// A preview container that dies on its own frees its address, which
	// Docker gives to the next container it starts; a sync takes it out of
	// the routes and the egress proxy's map at once. A sync also follows each
	// (re)start of the watch, for deaths it missed.
	const syncFailed = logOnce(log);
	const resync = (why: string) =>
		void deployer.sync().then(
			() => syncFailed(undefined, ''),
			(err: unknown) => syncFailed(errorText(err), `sync after ${why}: ${errorText(err)}`),
		);
	watchDeaths((name) => resync(name === undefined ? 'watching Docker' : `${name} stopped`), log);

	// Every 30 seconds: a sync, which inspects the containers and tells
	// Caddy and the egress proxy again (one that restarted has no map), then
	// write visits to records, and count an open connection to any routed
	// preview (a WebSocket that will only be logged when it closes) as
	// activity.
	setInterval(async () => {
		resync('the 30-second timer');
		try {
			await deployer.flushVisits();
			for (const route of deployer.runningUpstreams()) {
				const ip = route.upstream.split(':')[0] ?? '';
				if (await hasEstablishedConnections(ip)) activity.visit(route.label);
			}
		} catch (err) {
			log(`activity: ${errorText(err)}`);
		}
	}, 30_000);

	// Every 5 minutes: stop previews that wrote too much to their disk, and
	// try again to stop previews found outside the slice.
	setInterval(() => {
		void deployer.stopOversized().catch((err: unknown) => log(`disk watchdog: ${errorText(err)}`));
		void deployer.stopMisplaced().catch((err: unknown) => log(`slice watchdog: ${errorText(err)}`));
	}, 5 * 60_000);

	// Every 10 minutes: remove previews past their ttl. An idle box stops
	// after 10 minutes, so an hourly run might never happen; the run at
	// startup covers a box that stops first.
	setInterval(
		() =>
			void deployer
				.expire()
				.then((labels) => labels.length > 0 && log(`expired ${labels.join(', ')}`))
				.catch((err: unknown) => log(`expiry: ${errorText(err)}`)),
		10 * 60_000,
	);

	// Every 10 minutes with the spool: drop tickets past their hour and
	// entries past their day that no accepted request holds a claim on.
	const spool = adapters.spool;
	if (spool !== undefined) {
		setInterval(
			() => void spool.cleanup().catch((err: unknown) => log(`upload spool: ${errorText(err)}`)),
			10 * 60_000,
		);
	}

	// Every hour: evidence past its retention.
	setInterval(() => void sweepEvidence(evidence), 60 * 60_000);
}

// Retention of run evidence, input snapshots and plans, logged when it
// removed something.
async function sweepEvidence(evidence: EvidenceStore): Promise<void> {
	try {
		const swept = await evidence.sweep();
		const parts = [
			swept.expired.length > 0 ? `expired the evidence of ${swept.expired.join(', ')}` : '',
			swept.removed.length > 0 ? `removed runs ${swept.removed.join(', ')}` : '',
			swept.inputs.length > 0 ? `removed the inputs of ${swept.inputs.join(', ')}` : '',
			swept.pendingInputs.length > 0
				? `removed the unfinished inputs of ${swept.pendingInputs.join(', ')}`
				: '',
			swept.plans.length > 0 ? `removed plans ${swept.plans.join(', ')}` : '',
		].filter((p) => p !== '');
		if (parts.length > 0) log(`evidence: ${parts.join('; ')}`);
	} catch (err) {
		log(`evidence sweep: ${errorText(err)}`);
	}
}

// `koid ctl <args>` for a person on the box; `koid ctl-b64 <blob>` for the
// CLI, through SSM.
const args = process.argv.slice(2);
if (args[0] === 'ctl' || args[0] === 'ctl-b64') {
	const config = { socket: process.env.KOID_CONTROL_SOCKET ?? '/run/koi/control.sock' };
	const io: CtlIo = {
		stdout: (t) => process.stdout.write(t),
		stderr: (t) => process.stderr.write(t),
		fetch: socketFetch(config.socket),
	};
	process.exitCode = await (args[0] === 'ctl' ? ctl : ctlEncoded)(args.slice(1), io);
} else if (args.length === 0) {
	await daemon();
} else {
	// Never the daemon: a second one would reconcile the box's containers
	// before it failed to bind its ports.
	process.stderr.write(
		'koid: unknown command\nusage: koid | koid ctl <command> [args] | koid ctl-b64 <blob>\n',
	);
	process.exitCode = 2;
}
