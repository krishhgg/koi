import { describe, expect, test } from 'bun:test';
import { loadConfig } from '../src/config.ts';

// What koid cannot guess: the upload bucket and the operator's domain.
const REQUIRED = { KOI_UPLOADS_BUCKET: 'koi-uploads-123', KOI_DOMAIN: 'previews.example.net' };

// A plain host: uploads through the control socket, no bucket.
const SPOOL = { KOI_UPLOADS: 'spool', KOI_DOMAIN: 'previews.example.net' };

describe('loadConfig', () => {
	test('fills the box defaults when only the bucket and domain are set', () => {
		expect(loadConfig(REQUIRED)).toEqual({
			domain: 'previews.example.net',
			httpPort: 7777,
			logPort: 7778,
			controlSocket: '/run/koi/control.sock',
			controlGroup: 'koi-control',
			stateDir: '/var/lib/koi',
			recipesDir: '/usr/local/share/koi/recipes',
			caddyfile: '/var/lib/koi-caddy/Caddyfile',
			caddyAdmin: 'http://127.0.0.1:2019',
			tls: 'route53',
			tlsDnsFile: '/etc/koi/caddy/dns.caddy',
			dockerRoot: '/var/lib/docker',
			network: 'koi-previews',
			buildNetwork: 'koi-build',
			builder: 'koi-builder',
			slice: 'koi.slice',
			uploads: 's3',
			uploadsBucket: 'koi-uploads-123',
			live: 'ssm',
			previewsParam: '/koi/previews',
			region: 'us-east-1',
			egressControl: '/run/koi-egress/control.sock',
			verifyHelper: '/usr/local/libexec/koi-verify-net',
			previewRouteHelper: '/usr/local/libexec/koi-preview-route',
			recorderSeccomp: '/usr/local/share/koi/recorder-seccomp.json',
			verifierImages: [],
		});
	});

	test('takes how Caddy gets certificates from KOI_TLS, Route 53 when unset or empty', () => {
		expect(loadConfig({ ...SPOOL, KOI_TLS: '' }).tls).toBe('route53');
		for (const tls of ['route53', 'internal', 'acme-http', 'acme-dns'] as const) {
			expect(loadConfig({ ...SPOOL, KOI_TLS: tls }).tls).toBe(tls);
		}
		expect(() => loadConfig({ ...SPOOL, KOI_TLS: 'letsencrypt' })).toThrow();
		const dns = loadConfig({ ...SPOOL, KOI_TLS: 'acme-dns', KOI_TLS_DNS_FILE: '/srv/dns.caddy' });
		expect(dns.tlsDnsFile).toBe('/srv/dns.caddy');
		// The path goes into the Caddyfile as one token.
		expect(() => loadConfig({ ...SPOOL, KOI_TLS_DNS_FILE: '/srv/a b.caddy' })).toThrow();
		expect(() => loadConfig({ ...SPOOL, KOI_TLS_DNS_FILE: '/srv/x}\n:80 {' })).toThrow();
	});

	test("takes Caddy's admin API as an http URL or a unix socket in Caddy's own form", () => {
		expect(loadConfig({ ...SPOOL, KOI_CADDY_ADMIN: 'unix//run/caddy/admin.sock' }).caddyAdmin).toBe(
			'unix//run/caddy/admin.sock',
		);
		// The path goes into the Caddyfile as one token.
		for (const admin of ['unix/run/caddy/admin.sock', 'unix//run/a b.sock', 'unix//x}\n:80 {']) {
			expect(() => loadConfig({ ...SPOOL, KOI_CADDY_ADMIN: admin })).toThrow();
		}
	});

	test('reads every setting from the environment, ports as numbers', () => {
		const config = loadConfig({
			KOI_DOMAIN: 'example.test',
			KOID_PORT: '8000',
			KOID_LOG_PORT: '8001',
			KOID_CONTROL_SOCKET: '/tmp/koi.sock',
			KOI_STATE_DIR: '/srv/koi',
			KOI_RECIPES_DIR: '/srv/recipes',
			KOI_CADDYFILE: '/srv/Caddyfile',
			KOI_CADDY_ADMIN: 'http://127.0.0.1:3019',
			KOI_DOCKER_ROOT: '/data/docker',
			KOI_PREVIEW_NETWORK: 'p',
			KOI_BUILD_NETWORK: 'b',
			KOI_BUILDER: 'bk',
			KOI_UPLOADS_BUCKET: 'bucket',
			KOI_PREVIEWS_PARAM: '/x/previews',
			AWS_REGION: 'eu-west-1',
			KOI_RECORDER_IMAGE: `sha256:${'a'.repeat(64)}`,
			KOI_RECORDER_SECCOMP: '/srv/seccomp.json',
			KOI_VERIFIER_IMAGE: `sha256:${'b'.repeat(64)}`,
			KOI_VERIFIER_IMAGES: `curlimages/curl:8.11.1, ghcr.io/acme/runner@sha256:${'c'.repeat(64)}\nsha256:${'d'.repeat(64)}`,
		});
		expect(config.httpPort).toBe(8000);
		expect(config.logPort).toBe(8001);
		expect(config.domain).toBe('example.test');
		expect(config.stateDir).toBe('/srv/koi');
		expect(config.network).toBe('p');
		expect(config.previewsParam).toBe('/x/previews');
		expect(config.region).toBe('eu-west-1');
		expect(config.recorderImage).toBe(`sha256:${'a'.repeat(64)}`);
		expect(config.recorderSeccomp).toBe('/srv/seccomp.json');
		expect(config.verifierImage).toBe(`sha256:${'b'.repeat(64)}`);
		expect(config.verifierImages).toEqual([
			'curlimages/curl:8.11.1',
			`ghcr.io/acme/runner@sha256:${'c'.repeat(64)}`,
			`sha256:${'d'.repeat(64)}`,
		]);
	});

	test('the verifier image is pinned like the recorder, and the allowlist holds references or digests', () => {
		expect(loadConfig(REQUIRED).verifierImage).toBeUndefined();
		for (const image of ['koi-verifier:1', 'sha256:abc']) {
			expect(() => loadConfig({ ...REQUIRED, KOI_VERIFIER_IMAGE: image })).toThrow();
		}
		expect(() => loadConfig({ ...REQUIRED, KOI_VERIFIER_IMAGES: 'not an image!' })).toThrow();
		expect(loadConfig({ ...REQUIRED, KOI_VERIFIER_IMAGES: '  ' }).verifierImages).toEqual([]);
	});

	test('takes the recorder image by local id or by registry digest, nothing less pinned', () => {
		expect(loadConfig(REQUIRED).recorderImage).toBeUndefined();
		const digest = `sha256:${'0f'.repeat(32)}`;
		expect(
			loadConfig({ ...REQUIRED, KOI_RECORDER_IMAGE: `ghcr.io/acme/koi-recorder@${digest}` })
				.recorderImage,
		).toBe(`ghcr.io/acme/koi-recorder@${digest}`);
		for (const image of ['koi-recorder:1', 'koi-recorder@sha256:abc', 'sha256:ABC']) {
			expect(() => loadConfig({ ...REQUIRED, KOI_RECORDER_IMAGE: image })).toThrow();
		}
	});

	test.each([
		['a port of 0', { ...REQUIRED, KOID_PORT: '0' }],
		['a port past 65535', { ...REQUIRED, KOID_LOG_PORT: '70000' }],
		['a port that is not a number', { ...REQUIRED, KOID_PORT: 'http' }],
		['a relative state directory', { ...REQUIRED, KOI_STATE_DIR: 'var/lib/koi' }],
		['a domain with a slash', { ...REQUIRED, KOI_DOMAIN: 'previews.example.net/x' }],
		['a network name with a space', { ...REQUIRED, KOI_PREVIEW_NETWORK: 'koi previews' }],
		[
			'a parameter name without a leading slash',
			{ ...REQUIRED, KOI_PREVIEWS_PARAM: 'koi/previews' },
		],
		['an empty parameter name', { ...REQUIRED, KOI_PREVIEWS_PARAM: '' }],
		['an empty parameter name with the spool', { ...SPOOL, KOI_PREVIEWS_PARAM: '' }],
		['a caddy admin address that is not a URL', { ...REQUIRED, KOI_CADDY_ADMIN: '127.0.0.1:2019' }],
		['a relative spool directory', { ...SPOOL, KOI_SPOOL_DIR: 'var/lib/koi/uploads' }],
		['a spool budget that is not a number', { ...SPOOL, KOI_SPOOL_BUDGET_BYTES: 'lots' }],
		['a spool budget of 0', { ...SPOOL, KOI_SPOOL_BUDGET_BYTES: '0' }],
		['a relative live file', { ...SPOOL, KOI_LIVE_FILE: 'live.json' }],
	])('refuses %s', (_what, env) => {
		expect(() => loadConfig(env)).toThrow();
	});

	test('refuses to start without a domain, saying where it is set', () => {
		for (const env of [
			{ KOI_UPLOADS_BUCKET: 'koi-uploads-123' },
			{ ...REQUIRED, KOI_DOMAIN: '' },
		]) {
			expect(() => loadConfig(env)).toThrow(/KOI_DOMAIN is not set.*\/etc\/koi\/env/);
		}
	});

	test('runs builds and previews in koi.slice unless told otherwise', () => {
		expect(loadConfig(REQUIRED).slice).toBe('koi.slice');
		expect(loadConfig({ ...REQUIRED, KOI_SLICE: 'other.slice' }).slice).toBe('other.slice');
	});

	test('runs without a slice when KOI_SLICE is empty, as on a workstation', () => {
		expect(loadConfig({ ...REQUIRED, KOI_SLICE: '' }).slice).toBeUndefined();
	});

	test('refuses a slice name that is not a systemd slice', () => {
		expect(() => loadConfig({ ...REQUIRED, KOI_SLICE: '/koi' })).toThrow();
		expect(() => loadConfig({ ...REQUIRED, KOI_SLICE: 'koi' })).toThrow();
	});

	test('has no verification pool unless the operator reserved one', () => {
		expect(loadConfig(REQUIRED).verifyPool).toBeUndefined();
		expect(loadConfig({ ...REQUIRED, KOI_VERIFY_POOL: '' }).verifyPool).toBeUndefined();
		expect(loadConfig({ ...REQUIRED, KOI_VERIFY_POOL: '10.213.0.0/20' }).verifyPool).toBe(
			'10.213.0.0/20',
		);
		expect(loadConfig({ ...REQUIRED, KOI_VERIFY_HELPER: '/opt/koi/verify-net' }).verifyHelper).toBe(
			'/opt/koi/verify-net',
		);
	});

	// A wrong pool makes verification unavailable (host.ts names it as the
	// reason); koid still starts and serves previews.
	test.each([
		['host bits set', '10.213.0.1/20'],
		['too large a pool', '10.0.0.0/8'],
		['too small a pool', '10.213.0.0/29'],
		['IPv6', 'fd00::/64'],
		['not a network', 'pool'],
	])('keeps a verification pool with %s for the capability check to refuse', (_what, pool) => {
		expect(loadConfig({ ...REQUIRED, KOI_VERIFY_POOL: pool }).verifyPool).toBe(pool);
	});

	test('refuses a relative helper path', () => {
		expect(() => loadConfig({ ...REQUIRED, KOI_VERIFY_HELPER: 'koi-verify-net' })).toThrow();
	});

	describe('upload store and live list', () => {
		test('a bucket alone selects S3 and SSM, as the AWS box has always run', () => {
			const config = loadConfig(REQUIRED);
			expect(config.uploads).toBe('s3');
			expect(config.live).toBe('ssm');
			expect(config.spoolDir).toBeUndefined();
			expect(config.spoolBudgetBytes).toBeUndefined();
			expect(config.liveFile).toBeUndefined();
		});

		test('KOI_UPLOADS=spool selects the spool with its defaults and a file live list', () => {
			const config = loadConfig(SPOOL);
			expect(config.uploads).toBe('spool');
			expect(config.spoolDir).toBe('/var/lib/koi/uploads');
			expect(config.spoolBudgetBytes).toBe(10 * 1024 ** 3);
			expect(config.uploadsBucket).toBeUndefined();
			expect(config.live).toBe('file');
			expect(config.liveFile).toBe('/var/lib/koi/live-previews.json');
			expect(config.previewsParam).toBeUndefined();
		});

		test('the live file follows the state directory unless KOI_LIVE_FILE names one', () => {
			expect(loadConfig({ ...SPOOL, KOI_STATE_DIR: '/srv/koi' }).liveFile).toBe(
				'/srv/koi/live-previews.json',
			);
			expect(loadConfig({ ...SPOOL, KOI_LIVE_FILE: '/run/koi/live.json' }).liveFile).toBe(
				'/run/koi/live.json',
			);
		});

		test('reads the spool directory and budget from the environment, the budget as a number', () => {
			const config = loadConfig({
				...SPOOL,
				KOI_SPOOL_DIR: '/data/uploads',
				KOI_SPOOL_BUDGET_BYTES: '5368709120',
			});
			expect(config.spoolDir).toBe('/data/uploads');
			expect(config.spoolBudgetBytes).toBe(5 * 1024 ** 3);
		});

		test('a parameter name selects SSM for the live list even with the spool', () => {
			const config = loadConfig({ ...SPOOL, KOI_PREVIEWS_PARAM: '/koi/previews' });
			expect(config.live).toBe('ssm');
			expect(config.previewsParam).toBe('/koi/previews');
			expect(config.liveFile).toBeUndefined();
		});

		test('KOI_LIVE=file with S3 uploads writes the file and leaves the parameter out', () => {
			const config = loadConfig({ ...REQUIRED, KOI_LIVE: 'file' });
			expect(config.uploads).toBe('s3');
			expect(config.live).toBe('file');
			expect(config.liveFile).toBe('/var/lib/koi/live-previews.json');
			expect(config.previewsParam).toBeUndefined();
		});

		test('KOI_UPLOADS=s3 may be said outright', () => {
			expect(loadConfig({ ...REQUIRED, KOI_UPLOADS: 's3' }).uploads).toBe('s3');
			expect(loadConfig({ ...REQUIRED, KOI_UPLOADS: 's3', KOI_LIVE: 'ssm' }).live).toBe('ssm');
		});

		test.each([
			[
				'neither a bucket nor a store',
				{ KOI_DOMAIN: 'previews.example.net' },
				/KOI_UPLOADS_BUCKET is not set and KOI_UPLOADS is not set/,
			],
			[
				'KOI_UPLOADS=s3 without a bucket',
				{ KOI_DOMAIN: 'previews.example.net', KOI_UPLOADS: 's3' },
				/KOI_UPLOADS=s3 but KOI_UPLOADS_BUCKET is not set/,
			],
			[
				'a bucket with the spool',
				{ ...SPOOL, KOI_UPLOADS_BUCKET: 'bucket' },
				/KOI_UPLOADS=spool but KOI_UPLOADS_BUCKET is set/,
			],
			[
				'an unknown upload store',
				{ KOI_DOMAIN: 'previews.example.net', KOI_UPLOADS: 'ftp' },
				/KOI_UPLOADS is "ftp"; it must be s3 or spool/,
			],
			[
				'a spool directory with S3',
				{ ...REQUIRED, KOI_SPOOL_DIR: '/data/uploads' },
				/KOI_SPOOL_DIR is set but uploads come from S3/,
			],
			[
				'a spool budget with S3',
				{ ...REQUIRED, KOI_SPOOL_BUDGET_BYTES: '1' },
				/KOI_SPOOL_BUDGET_BYTES is set but uploads come from S3/,
			],
			[
				'an unknown live list',
				{ ...REQUIRED, KOI_LIVE: 'redis' },
				/KOI_LIVE is "redis"; it must be ssm or file/,
			],
			[
				'a parameter with a file live list',
				{ ...REQUIRED, KOI_LIVE: 'file', KOI_PREVIEWS_PARAM: '/koi/previews' },
				/KOI_LIVE=file but KOI_PREVIEWS_PARAM is set/,
			],
			[
				'a live file with SSM',
				{ ...REQUIRED, KOI_LIVE_FILE: '/var/lib/koi/live.json' },
				/KOI_LIVE_FILE is set but the live list goes to SSM/,
			],
		])('names the variable when given %s', (_what, env, message) => {
			expect(() => loadConfig(env)).toThrow(message);
		});
	});
});
