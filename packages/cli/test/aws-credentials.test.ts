import { afterEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { clients } from '../src/transports/aws.ts';

// The CLI builds its AWS clients with fromIni({ profile }) (clients() in
// transports/aws.ts). These tests resolve credentials through those clients
// from a fake ~/.aws, for the two kinds of profile koi is used with: static
// keys (the personal account's koi-cli user) and IAM Identity Center (SSO),
// which an account managed with permission sets gives people instead.
//
// The SSO case runs offline. `aws sso login` leaves an access token in
// ~/.aws/sso/cache, named for the sso-session; the SDK reads it and trades it
// for role credentials at the portal's GetRoleCredentials endpoint, which
// AWS_ENDPOINT_URL_SSO points at a server of this test's.

const VARS = [
	'HOME',
	'AWS_CONFIG_FILE',
	'AWS_SHARED_CREDENTIALS_FILE',
	'AWS_ENDPOINT_URL_SSO',
	'AWS_PROFILE',
	'AWS_ACCESS_KEY_ID',
	'AWS_SECRET_ACCESS_KEY',
	'AWS_SESSION_TOKEN',
	'AWS_REGION',
	'AWS_DEFAULT_REGION',
] as const;
const saved = Object.fromEntries(VARS.map((v) => [v, process.env[v]]));
const servers: Array<{ stop: (closeActive?: boolean) => void }> = [];

afterEach(() => {
	for (const v of VARS) {
		const value = saved[v];
		if (value === undefined) delete process.env[v];
		else process.env[v] = value;
	}
	for (const s of servers.splice(0)) s.stop(true);
});

// A fresh home with ~/.aws/config and ~/.aws/credentials as given, and the
// environment pointed at it with no credentials of its own.
async function awsHome(config: string, credentials = ''): Promise<string> {
	const home = await mkdtemp(join(tmpdir(), 'koi-aws-home-'));
	await mkdir(join(home, '.aws'), { mode: 0o700 });
	await writeFile(join(home, '.aws', 'config'), config, { mode: 0o600 });
	await writeFile(join(home, '.aws', 'credentials'), credentials, { mode: 0o600 });
	for (const v of VARS) delete process.env[v];
	process.env.HOME = home;
	process.env.AWS_CONFIG_FILE = join(home, '.aws', 'config');
	process.env.AWS_SHARED_CREDENTIALS_FILE = join(home, '.aws', 'credentials');
	return home;
}

describe('AWS credentials through the CLI clients', () => {
	test('a profile with static keys, as the personal koi-cli user has', async () => {
		await awsHome(
			'[profile koi-cli]\nregion = us-east-1\n',
			'[koi-cli]\naws_access_key_id = AKIAEXAMPLESTATIC01\naws_secret_access_key = static-secret\n',
		);
		const c = clients('koi-cli', 'us-east-1');
		const creds = await c.ssm.config.credentials();
		expect(creds.accessKeyId).toBe('AKIAEXAMPLESTATIC01');
		expect(creds.secretAccessKey).toBe('static-secret');
		expect(creds.sessionToken).toBeUndefined();
	});

	test('an IAM Identity Center profile with an sso-session, after aws sso login', async () => {
		const home = await awsHome(
			[
				'[profile koi-sso]',
				'sso_session = company',
				'sso_account_id = 111122223333',
				'sso_role_name = KoiOperator',
				'region = us-east-1',
				'',
				'[sso-session company]',
				'sso_start_url = https://example.awsapps.com/start',
				'sso_region = us-east-1',
				'sso_registration_scopes = sso:account:access',
				'',
			].join('\n'),
		);
		// What `aws sso login --profile koi-sso` writes: the cache file is named
		// for the SHA-1 of the sso-session's name.
		const cache = join(home, '.aws', 'sso', 'cache');
		await mkdir(cache, { recursive: true, mode: 0o700 });
		const name = createHash('sha1').update('company').digest('hex');
		const later = (ms: number) => new Date(Date.now() + ms).toISOString();
		await writeFile(
			join(cache, `${name}.json`),
			JSON.stringify({
				startUrl: 'https://example.awsapps.com/start',
				region: 'us-east-1',
				accessToken: 'sso-access-token',
				expiresAt: later(3_600_000),
				clientId: 'client-id',
				clientSecret: 'client-secret',
				registrationExpiresAt: later(86_400_000),
				refreshToken: 'refresh-token',
			}),
		);

		const asked: Array<{ path: string; query: string; token: string | null }> = [];
		const expiration = Date.now() + 3_600_000;
		const server = Bun.serve({
			hostname: '127.0.0.1',
			port: 0,
			fetch(req) {
				const url = new URL(req.url);
				asked.push({
					path: url.pathname,
					query: url.search,
					token: req.headers.get('x-amz-sso_bearer_token'),
				});
				return Response.json({
					roleCredentials: {
						accessKeyId: 'ASIAEXAMPLESSO00001',
						secretAccessKey: 'sso-secret',
						sessionToken: 'sso-session-token',
						expiration,
					},
				});
			},
		});
		servers.push(server);
		process.env.AWS_ENDPOINT_URL_SSO = `http://127.0.0.1:${server.port}`;

		const c = clients('koi-sso', 'us-east-1');
		const creds = await c.ec2.config.credentials();
		expect(creds.accessKeyId).toBe('ASIAEXAMPLESSO00001');
		expect(creds.secretAccessKey).toBe('sso-secret');
		expect(creds.sessionToken).toBe('sso-session-token');
		expect(creds.expiration?.getTime()).toBe(expiration);
		// The SDK traded the cached token for the profile's account and role.
		expect(asked).toHaveLength(1);
		expect(asked[0]?.path).toBe('/federation/credentials');
		expect(new URLSearchParams(asked[0]?.query).get('account_id')).toBe('111122223333');
		expect(new URLSearchParams(asked[0]?.query).get('role_name')).toBe('KoiOperator');
		expect(asked[0]?.token).toBe('sso-access-token');
	});

	test('an Identity Center profile with no login says to run aws sso login', async () => {
		await awsHome(
			[
				'[profile koi-sso]',
				'sso_session = company',
				'sso_account_id = 111122223333',
				'sso_role_name = KoiOperator',
				'',
				'[sso-session company]',
				'sso_start_url = https://example.awsapps.com/start',
				'sso_region = us-east-1',
				'',
			].join('\n'),
		);
		const c = clients('koi-sso', 'us-east-1');
		await expect(c.ssm.config.credentials()).rejects.toThrow(/aws sso login/);
	});
});
