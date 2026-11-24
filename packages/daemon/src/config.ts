import { join } from 'node:path';
import { ImageRefSchema } from '@koi/shared';
import { z } from 'zod';

const DockerName = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/);

// An image by content: the id Docker gives a local build, or a registry
// reference pinned with @sha256:<64 hex>.
const ImageIdSchema = z.string().regex(/^(?:[A-Za-z0-9][A-Za-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$/);

// Everything the daemon needs to know about where it runs. Read once at start
// from the environment (systemd's EnvironmentFile=/etc/koi/env on the box,
// which scripts/deploy-host.sh writes).
const ConfigSchema = z.object({
	// The base domain previews live under, as <label>.<domain>. The operator's
	// own; there is no default.
	domain: z.string().regex(/^[a-z0-9.-]+$/),
	httpPort: z.coerce.number().int().min(1).max(65535),
	logPort: z.coerce.number().int().min(1).max(65535),
	controlSocket: z.string().startsWith('/'),
	// The group the control socket is given, when the host has it: the SSH
	// gateway's account is in it (host/ssh).
	controlGroup: z.string().min(1),
	stateDir: z.string().startsWith('/'),
	recipesDir: z.string().startsWith('/'),
	caddyfile: z.string().startsWith('/'),
	// Caddy's admin API: an http URL, as on the AWS box, or unix//PATH, Caddy's
	// own way to write a unix socket, which host/install-vm.sh sets so that no
	// other account on the host can change Caddy's config (caddy.ts). The path
	// goes into the Caddyfile as one token.
	caddyAdmin: z.union([z.url(), z.string().regex(/^unix\/\/[A-Za-z0-9._/-]+$/)]),
	// How Caddy gets certificates (caddy.ts, CaddyTls): route53 on the AWS
	// box, which sets nothing; host/install-vm.sh sets another for a host
	// outside AWS. With acme-dns, the file that holds the provider's `dns`
	// line, which Caddy reads and koid never does.
	tls: z.enum(['route53', 'internal', 'acme-http', 'acme-dns']),
	tlsDnsFile: z.string().regex(/^\/[A-Za-z0-9._/-]+$/),
	// Docker's data root. Images, containers, volumes and the build cache
	// all live on the filesystem that holds it.
	dockerRoot: z.string().startsWith('/'),
	network: DockerName,
	buildNetwork: DockerName,
	builder: DockerName,
	// The systemd slice the builder and every preview run in, under one
	// memory ceiling (host/cloud-init.sh). Unset to run without one, as on a
	// workstation.
	slice: z
		.string()
		.regex(/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*\.slice$/)
		.optional(),
	// Where source uploads come from: the S3 bucket the CLI writes to on
	// AWS, or a spool on this host that the CLI fills through the control
	// socket (upload-api.ts). The fields of the other store are absent.
	uploads: z.enum(['s3', 'spool']),
	uploadsBucket: z.string().min(3).optional(),
	spoolDir: z.string().startsWith('/').optional(),
	spoolBudgetBytes: z.coerce.number().int().positive().optional(),
	// Where the labels allowed to wake the box are published: the SSM
	// parameter the wake function reads on AWS, or a file on this host.
	live: z.enum(['ssm', 'file']),
	previewsParam: z.string().startsWith('/').optional(),
	liveFile: z.string().startsWith('/').optional(),
	region: z.string().min(1),
	// The egress proxy previews reach the internet through (host/egress), and
	// its CA certificate. Both unset: previews have no way out at all.
	egressProxy: z.url().optional(),
	egressCa: z.string().startsWith('/').optional(),
	// The egress proxy's control socket, where the keys page registers tokens.
	egressControl: z.string().startsWith('/'),
	// The addresses verification run networks are carved from, a /28 each,
	// reserved by the operator (host/cloud-init.sh writes it to
	// /etc/koi/verify/env from var.verify_pool). Kept as written: the
	// capability check (host.ts, verifyPoolProblem) judges its shape and
	// reports a wrong value as a reason verification is unavailable, so a
	// typo there never stops koid from serving previews. Unset:
	// verification is unavailable on this host, and previews work as before.
	verifyPool: z.string().optional(),
	// The root-owned helper that installs a run's firewall permits
	// (host/verify/koi_verify_net.py). Missing from the box: verification is
	// unavailable.
	verifyHelper: z.string().startsWith('/'),
	// The recorder image (host/recorder), as the id Docker gives a local
	// build or a registry reference pinned with @sha256:<64 hex>
	// (KOI_RECORDER_IMAGE). Unset: verification is unavailable.
	recorderImage: ImageIdSchema.optional(),
	// The seccomp profile the recorder runs under, which lets Chromium's own
	// sandbox make its user namespace (host/recorder/seccomp.json). Missing
	// from the box: verification is unavailable.
	recorderSeccomp: z.string().startsWith('/'),
	// The default verifier image (host/verifier), in the same forms as the
	// recorder's (KOI_VERIFIER_IMAGE). A manifest names it as koi-verifier.
	// Unset: verification is unavailable.
	verifierImage: ImageIdSchema.optional(),
	// Runner images a manifest may name besides the default, as references
	// or digests (KOI_VERIFIER_IMAGES, separated by spaces or commas). An
	// image outside this list blocks the points that would run in it.
	verifierImages: z.array(z.union([ImageRefSchema, ImageIdSchema])),
});

export type Config = z.infer<typeof ConfigSchema>;

// The most the spool holds unless KOI_SPOOL_BUDGET_BYTES says otherwise:
// five sources of the largest size the daemon takes.
const DEFAULT_SPOOL_BUDGET_BYTES = 10 * 1024 ** 3;

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
	if (env.KOI_DOMAIN === undefined || env.KOI_DOMAIN === '') {
		throw new Error(
			'KOI_DOMAIN is not set. koid serves previews at <label>.<domain> and needs that domain. On the box, scripts/deploy-host.sh writes it to /etc/koi/env from KOI_DOMAIN or the domain output of infra/ (var.domain, set in infra/koi.auto.tfvars); elsewhere, set KOI_DOMAIN in the environment.',
		);
	}
	const stateDir = env.KOI_STATE_DIR ?? '/var/lib/koi';
	return ConfigSchema.parse({
		domain: env.KOI_DOMAIN,
		httpPort: env.KOID_PORT ?? '7777',
		logPort: env.KOID_LOG_PORT ?? '7778',
		controlSocket: env.KOID_CONTROL_SOCKET ?? '/run/koi/control.sock',
		controlGroup: env.KOID_CONTROL_GROUP ?? 'koi-control',
		stateDir,
		recipesDir: env.KOI_RECIPES_DIR ?? '/usr/local/share/koi/recipes',
		caddyfile: env.KOI_CADDYFILE ?? '/var/lib/koi-caddy/Caddyfile',
		caddyAdmin: env.KOI_CADDY_ADMIN ?? 'http://127.0.0.1:2019',
		tls: env.KOI_TLS || 'route53',
		tlsDnsFile: env.KOI_TLS_DNS_FILE ?? '/etc/koi/caddy/dns.caddy',
		dockerRoot: env.KOI_DOCKER_ROOT ?? '/var/lib/docker',
		network: env.KOI_PREVIEW_NETWORK ?? 'koi-previews',
		buildNetwork: env.KOI_BUILD_NETWORK ?? 'koi-build',
		builder: env.KOI_BUILDER ?? 'koi-builder',
		slice: env.KOI_SLICE === '' ? undefined : (env.KOI_SLICE ?? 'koi.slice'),
		...chooseStores(env, stateDir),
		region: env.AWS_REGION ?? 'us-east-1',
		egressControl: env.KOI_EGRESS_CONTROL ?? '/run/koi-egress/control.sock',
		...(env.KOI_EGRESS_PROXY ? { egressProxy: env.KOI_EGRESS_PROXY } : {}),
		...(env.KOI_EGRESS_CA ? { egressCa: env.KOI_EGRESS_CA } : {}),
		...(env.KOI_VERIFY_POOL ? { verifyPool: env.KOI_VERIFY_POOL } : {}),
		verifyHelper: env.KOI_VERIFY_HELPER ?? '/usr/local/libexec/koi-verify-net',
		...(env.KOI_RECORDER_IMAGE ? { recorderImage: env.KOI_RECORDER_IMAGE } : {}),
		recorderSeccomp: env.KOI_RECORDER_SECCOMP ?? '/usr/local/share/koi/recorder-seccomp.json',
		...(env.KOI_VERIFIER_IMAGE ? { verifierImage: env.KOI_VERIFIER_IMAGE } : {}),
		verifierImages: (env.KOI_VERIFIER_IMAGES ?? '').split(/[\s,]+/).filter((s) => s !== ''),
	});
}

// The store settings as ConfigSchema takes them, numbers still as text.
interface StoreInput {
	uploads: 's3' | 'spool';
	uploadsBucket?: string;
	spoolDir?: string;
	spoolBudgetBytes?: string;
	live: 'ssm' | 'file';
	previewsParam?: string;
	liveFile?: string;
}

// Which upload store and live list to use, and their settings. The AWS
// deployment sets KOI_UPLOADS_BUCKET and KOI_PREVIEWS_PARAM and nothing
// else, so those alone select S3 and SSM, as they always have. A plain Linux
// host sets KOI_UPLOADS=spool, and its live list is a file unless
// KOI_LIVE says otherwise. Every failure names the variable to set or unset.
function chooseStores(env: Record<string, string | undefined>, stateDir: string): StoreInput {
	const bucket = given(env.KOI_UPLOADS_BUCKET);
	const uploadsVar = given(env.KOI_UPLOADS);
	if (uploadsVar !== undefined && uploadsVar !== 's3' && uploadsVar !== 'spool') {
		throw new Error(`KOI_UPLOADS is ${JSON.stringify(uploadsVar)}; it must be s3 or spool`);
	}
	const uploads = uploadsVar ?? (bucket === undefined ? undefined : 's3');
	if (uploads === undefined) {
		throw new Error(
			'KOI_UPLOADS_BUCKET is not set and KOI_UPLOADS is not set. koid reads source uploads from an S3 bucket (KOI_UPLOADS_BUCKET, which scripts/deploy-host.sh writes to /etc/koi/env on the box) or from a spool on this host (KOI_UPLOADS=spool); set one.',
		);
	}
	// Not through given(): an empty parameter name is a mistake to report,
	// as it always was, not a request for the default.
	const param = env.KOI_PREVIEWS_PARAM;
	const liveVar = given(env.KOI_LIVE);
	if (liveVar !== undefined && liveVar !== 'ssm' && liveVar !== 'file') {
		throw new Error(`KOI_LIVE is ${JSON.stringify(liveVar)}; it must be ssm or file`);
	}
	const live = liveVar ?? (param !== undefined || uploads === 's3' ? 'ssm' : 'file');
	const stores: StoreInput = { uploads, live };

	if (uploads === 's3') {
		if (bucket === undefined) {
			throw new Error(
				'KOI_UPLOADS=s3 but KOI_UPLOADS_BUCKET is not set; set the bucket to read from.',
			);
		}
		for (const name of ['KOI_SPOOL_DIR', 'KOI_SPOOL_BUDGET_BYTES']) {
			if (given(env[name]) !== undefined) {
				throw new Error(`${name} is set but uploads come from S3 (KOI_UPLOADS_BUCKET); unset it.`);
			}
		}
		stores.uploadsBucket = bucket;
	} else {
		if (bucket !== undefined) {
			throw new Error(
				'KOI_UPLOADS=spool but KOI_UPLOADS_BUCKET is set; koid reads uploads from one store, so unset one of them.',
			);
		}
		stores.spoolDir = env.KOI_SPOOL_DIR ?? '/var/lib/koi/uploads';
		stores.spoolBudgetBytes = env.KOI_SPOOL_BUDGET_BYTES ?? String(DEFAULT_SPOOL_BUDGET_BYTES);
	}

	if (live === 'ssm') {
		if (given(env.KOI_LIVE_FILE) !== undefined) {
			throw new Error(
				'KOI_LIVE_FILE is set but the live list goes to SSM (KOI_PREVIEWS_PARAM or KOI_LIVE=ssm); unset it.',
			);
		}
		stores.previewsParam = param ?? '/koi/previews';
	} else {
		if (param !== undefined) {
			throw new Error(
				'KOI_LIVE=file but KOI_PREVIEWS_PARAM is set; the live list goes to one place, so unset one of them.',
			);
		}
		stores.liveFile = env.KOI_LIVE_FILE ?? join(stateDir, 'live-previews.json');
	}
	return stores;
}

// A variable's value, or undefined when unset or empty.
function given(value: string | undefined): string | undefined {
	return value === undefined || value === '' ? undefined : value;
}
