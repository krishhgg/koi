import { describe, expect, test } from 'bun:test';
import {
	chmod,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rmdir,
	stat,
	symlink,
	utimes,
	writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { parseCli } from '../src/args.ts';
import type { Clients } from '../src/box.ts';
import {
	AbsPathSchema,
	configPath,
	loadRepoAlias,
	loadUserConfig,
	MAX_REPO_ALIAS_BYTES,
	REPO_TARGET_FILE,
	RepoTargetSchema,
	resolveTarget,
	SshEndpointSchema,
	SshPathSchema,
	TargetNameSchema,
	TargetSchema,
	UserConfigSchema,
} from '../src/config.ts';
import {
	CONFIG_LOCK_WAIT_MS,
	configCommand,
	toYaml,
	withConfigLock,
} from '../src/config-command.ts';
import type { Io } from '../src/main.ts';

// An environment variable as ssh reads one in an option value.
// biome-ignore lint/suspicious/noTemplateCurlyInString: ssh's syntax, not a template of this file
const ENV_REF = '${UNSET}';

const AWS_TARGET = {
	domain: 'previews.example.net',
	transport: { kind: 'aws-ssm' },
	aws: {
		profile: 'koi-cli',
		region: 'us-east-1',
		instanceId: 'i-0123456789abcdef0',
		uploadsBucket: 'koi-uploads-123456789012',
	},
	power: { kind: 'ec2' },
};

const SSH_TARGET = {
	domain: 'previews.example.com',
	transport: {
		kind: 'ssh',
		endpoint: {
			host: '203.0.113.10',
			user: 'koi-connect',
			identityFile: '/home/operator/.ssh/koi_team_ed25519',
			knownHostsFile: '/home/operator/.config/koi/known_hosts',
			hostKeyAlias: 'team',
		},
	},
	power: { kind: 'always-on' },
};

const LOCAL_TARGET = {
	domain: 'koi.test',
	address: { scheme: 'https', port: 443 },
	transport: { kind: 'local', controlSocket: '/run/koi-local/control.sock' },
	power: { kind: 'always-on' },
};

describe('schemas', () => {
	test('a target name is lowercase letters, digits and dashes', () => {
		for (const ok of ['team', 'owner-aws', 'a', 'x1-2']) {
			expect(TargetNameSchema.safeParse(ok).success).toBe(true);
		}
		for (const bad of ['', 'Team', '-a', 'a b', 'a/b', 'a'.repeat(64), '../x']) {
			expect(TargetNameSchema.safeParse(bad).success).toBe(false);
		}
	});

	test('a domain is bare: labels and dots, nothing else', () => {
		for (const ok of ['previews.example.net', 'previews.example.com', 'a-b.c']) {
			expect(TargetSchema.safeParse({ ...SSH_TARGET, domain: ok }).success).toBe(true);
		}
		for (const bad of [
			'',
			'example',
			'https://example.com',
			'example.com:443',
			'example.com/',
			'*.example.com',
			'example..com',
			'-a.example.com',
			'a-.example.com',
			'example.com.',
			'Example.com',
			`${'a'.repeat(64)}.com`,
			`${'a.'.repeat(130)}com`,
		]) {
			expect(TargetSchema.safeParse({ ...SSH_TARGET, domain: bad }).success).toBe(false);
		}
	});

	test('a path in the user file is absolute, or under the home directory as ~/', () => {
		expect(AbsPathSchema.parse('/etc/koi/x')).toBe('/etc/koi/x');
		expect(AbsPathSchema.parse('/a/../b')).toBe('/b');
		expect(AbsPathSchema.parse('~/.ssh/key')).toMatch(/^\/.*\/\.ssh\/key$/);
		expect(AbsPathSchema.parse('~/.ssh/key').startsWith('~')).toBe(false);
		for (const bad of ['', 'relative/key', './key', '~user/key']) {
			expect(AbsPathSchema.safeParse(bad).success).toBe(false);
		}
	});

	test('a path for ssh has no %, ${, line break or control character', () => {
		expect(SshPathSchema.parse('/keys/with space/id')).toBe('/keys/with space/id');
		expect(SshPathSchema.parse('/keys/a"b\\c')).toBe('/keys/a"b\\c');
		for (const [bad, why] of [
			['/keys/%d/id', '%'],
			[`/tmp/${ENV_REF}/known_hosts`, 'environment variable'],
			['/keys/a\nb', 'line break'],
			['/keys/a\u0001b', 'control character'],
			['relative', 'absolute'],
		] as const) {
			const parsed = SshPathSchema.safeParse(bad);
			expect(parsed.success).toBe(false);
			expect(parsed.error?.issues[0]?.message).toContain(why);
		}
		const endpoint = SSH_TARGET.transport.endpoint;
		for (const field of ['identityFile', 'knownHostsFile'] as const) {
			const bad = {
				...SSH_TARGET,
				transport: { kind: 'ssh', endpoint: { ...endpoint, [field]: '/x/%h' } },
			};
			const parsed = TargetSchema.safeParse(bad);
			expect(parsed.success).toBe(false);
			expect(JSON.stringify(parsed.error?.issues)).toContain('cannot be given to ssh');
		}
	});

	test('the three example targets parse, with defaults filled in', () => {
		const aws = TargetSchema.parse(AWS_TARGET);
		expect(aws.address).toEqual({ scheme: 'https', port: 443 });
		expect(aws.transport).toEqual({ kind: 'aws-ssm' });
		const ssh = TargetSchema.parse(SSH_TARGET);
		expect(ssh.transport.kind === 'ssh' && ssh.transport.endpoint.port).toBe(22);
		expect(TargetSchema.parse(LOCAL_TARGET).transport.kind).toBe('local');
	});

	test('aws goes with aws-ssm or ec2 power, and nowhere else', () => {
		const { aws: _aws, ...noAws } = AWS_TARGET;
		expect(TargetSchema.safeParse(noAws).success).toBe(false);
		expect(
			TargetSchema.safeParse({
				...noAws,
				transport: { kind: 'aws-ssm' },
				power: { kind: 'always-on' },
			}).success,
		).toBe(false);
		expect(TargetSchema.safeParse({ ...SSH_TARGET, power: { kind: 'ec2' } }).success).toBe(false);
		expect(TargetSchema.safeParse({ ...SSH_TARGET, aws: AWS_TARGET.aws }).success).toBe(false);
		expect(TargetSchema.safeParse({ ...LOCAL_TARGET, aws: AWS_TARGET.aws }).success).toBe(false);
	});

	test('an SSH endpoint selects exactly one identity', () => {
		const endpoint = SSH_TARGET.transport.endpoint;
		expect(SshEndpointSchema.safeParse(endpoint).success).toBe(true);
		const { identityFile: _file, ...none } = endpoint;
		expect(SshEndpointSchema.safeParse(none).success).toBe(false);
		expect(
			SshEndpointSchema.safeParse({ ...none, identityPublicKey: '/home/operator/.ssh/k.pub' })
				.success,
		).toBe(true);
		expect(
			SshEndpointSchema.safeParse({ ...endpoint, identityPublicKey: '/home/operator/.ssh/k.pub' })
				.success,
		).toBe(false);
		expect(SshEndpointSchema.safeParse({ ...endpoint, user: 'root' }).success).toBe(false);
		expect(SshEndpointSchema.safeParse({ ...endpoint, host: 'not a host' }).success).toBe(false);
		expect(SshEndpointSchema.safeParse({ ...endpoint, host: '2001:db8::10' }).success).toBe(true);
	});

	test('unknown fields and other versions are errors', () => {
		expect(UserConfigSchema.safeParse({ version: 1, targets: {} }).success).toBe(true);
		expect(UserConfigSchema.safeParse({ version: 2, targets: {} }).success).toBe(false);
		expect(UserConfigSchema.safeParse({ version: 1, targets: {}, extra: 1 }).success).toBe(false);
		expect(TargetSchema.safeParse({ ...AWS_TARGET, hooks: ['rm -rf /'] }).success).toBe(false);
		expect(
			TargetSchema.safeParse({ ...AWS_TARGET, aws: { ...AWS_TARGET.aws, secretKey: 'x' } }).success,
		).toBe(false);
		expect(
			UserConfigSchema.safeParse({ version: 1, targets: { Bad_Name: AWS_TARGET } }).success,
		).toBe(false);
	});

	test('defaultTarget must name a target', () => {
		expect(
			UserConfigSchema.safeParse({
				version: 1,
				defaultTarget: 'team',
				targets: { team: SSH_TARGET },
			}).success,
		).toBe(true);
		const r = UserConfigSchema.safeParse({
			version: 1,
			defaultTarget: 'other',
			targets: { team: SSH_TARGET },
		});
		expect(r.success).toBe(false);
		// A target of its own, not a property every object has.
		expect(
			UserConfigSchema.safeParse({
				version: 1,
				defaultTarget: 'constructor',
				targets: { team: SSH_TARGET },
			}).success,
		).toBe(false);
		expect(
			UserConfigSchema.safeParse({
				version: 1,
				defaultTarget: 'constructor',
				targets: { constructor: SSH_TARGET },
			}).success,
		).toBe(true);
	});

	test('a repository alias is a version and a name, nothing more', () => {
		expect(RepoTargetSchema.safeParse({ version: 1, target: 'team' }).success).toBe(true);
		for (const bad of [
			{ version: 1, target: 'team', endpoint: { host: 'evil.example' } },
			{ version: 1, target: 'team', domain: 'evil.example' },
			{ version: 1, target: 'team', identityFile: '/root/.ssh/id' },
			{ version: 1 },
			{ version: 2, target: 'team' },
			{ version: 1, target: '../x' },
		]) {
			expect(RepoTargetSchema.safeParse(bad).success).toBe(false);
		}
	});
});

// A home directory of its own, so the default config path lands in it.
async function home(): Promise<string> {
	return mkdtemp(join(tmpdir(), 'koi-home-'));
}

async function writeConfig(dir: string, config: unknown, mode = 0o600): Promise<string> {
	const path = join(dir, '.config', 'koi', 'config.yaml');
	await mkdir(join(dir, '.config', 'koi'), { recursive: true });
	await writeFile(path, typeof config === 'string' ? config : toYaml(config), { mode });
	await chmod(path, mode);
	return path;
}

async function checkout(alias?: string): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
	if (alias !== undefined) {
		await mkdir(join(dir, '.koi'), { recursive: true });
		await writeFile(join(dir, REPO_TARGET_FILE), alias);
	}
	return dir;
}

function notices() {
	const lines: string[] = [];
	return { lines, notice: (m: string) => void lines.push(m) };
}

describe('configPath', () => {
	test('--config, then KOI_CONFIG, then XDG_CONFIG_HOME, then ~/.config', () => {
		const env = { HOME: '/home/u', XDG_CONFIG_HOME: '/xdg', KOI_CONFIG: '/env/k.yaml' };
		expect(configPath({ config: '/flag/k.yaml' }, env)).toEqual({
			path: '/flag/k.yaml',
			explicit: true,
		});
		expect(configPath({}, env)).toEqual({ path: '/env/k.yaml', explicit: true });
		expect(configPath({}, { HOME: '/home/u', XDG_CONFIG_HOME: '/xdg' })).toEqual({
			path: '/xdg/koi/config.yaml',
			explicit: false,
		});
		expect(configPath({}, { HOME: '/home/u', XDG_CONFIG_HOME: '' })).toEqual({
			path: '/home/u/.config/koi/config.yaml',
			explicit: false,
		});
	});

	test('an empty selector is an error, not an absence', () => {
		expect(() => configPath({ config: '' }, {})).toThrow('--config is empty');
		expect(() => configPath({}, { KOI_CONFIG: '' })).toThrow('KOI_CONFIG is empty');
	});

	test('expands a leading ~/ in --config and KOI_CONFIG to the home directory', () => {
		expect(configPath({ config: '~/k.yaml' }, { HOME: '/home/u' })).toEqual({
			path: '/home/u/k.yaml',
			explicit: true,
		});
		expect(configPath({}, { HOME: '/home/u', KOI_CONFIG: '~/.config/koi/config.yaml' })).toEqual({
			path: '/home/u/.config/koi/config.yaml',
			explicit: true,
		});
		// Only ~/ is the home directory; ~name is a path like any other.
		expect(configPath({}, { HOME: '/home/u', KOI_CONFIG: '~other/k.yaml' }).path).toBe(
			resolve('~other/k.yaml'),
		);
	});

	test('ignores a relative XDG_CONFIG_HOME, as the XDG specification says to', () => {
		for (const xdg of ['rel/xdg', './.config', '.']) {
			expect(configPath({}, { HOME: '/home/u', XDG_CONFIG_HOME: xdg })).toEqual({
				path: '/home/u/.config/koi/config.yaml',
				explicit: false,
			});
		}
	});
});

describe('loadUserConfig', () => {
	test('reads a valid file and keeps what the user wrote', async () => {
		const h = await home();
		const path = await writeConfig(h, {
			version: 1,
			defaultTarget: 'owner-aws',
			targets: { 'owner-aws': AWS_TARGET },
		});
		const n = notices();
		const loaded = await loadUserConfig(path, false, n.notice);
		expect(loaded?.config.defaultTarget).toBe('owner-aws');
		expect(loaded?.config.targets['owner-aws']?.aws?.instanceId).toBe(AWS_TARGET.aws.instanceId);
		// The raw copy has no defaults filled in.
		const rawTargets = loaded?.raw.targets as Record<string, Record<string, unknown>> | undefined;
		expect(rawTargets?.['owner-aws']).toEqual(AWS_TARGET);
		expect(n.lines).toEqual([]);
	});

	test('a missing default file is allowed; a missing explicit one is not', async () => {
		const path = join(await home(), '.config', 'koi', 'config.yaml');
		expect(await loadUserConfig(path, false, () => {})).toBeUndefined();
		await expect(loadUserConfig(path, true, () => {})).rejects.toThrow(`no config file at ${path}`);
	});

	test('warns about a file other users can read', async () => {
		const h = await home();
		const path = await writeConfig(h, { version: 1, targets: {} }, 0o644);
		const n = notices();
		await loadUserConfig(path, false, n.notice);
		expect(n.lines).toEqual([`${path} is open to other users (mode 0644); run chmod 600 ${path}`]);
	});

	test('rejects YAML that is not a config, saying what is wrong', async () => {
		const h = await home();
		for (const [text, why] of [
			['version: 1\ntargets: {}\nhooks: [x]\n', /Unrecognized key/],
			['version: 2\ntargets: {}\n', /version/],
			['- a\n- b\n', /expected a mapping/],
			['', /expected a mapping/],
			['a: [\n', /cannot read/],
			[
				`version: 1\ntargets:\n  t:\n${toYaml({ ...AWS_TARGET, aws: undefined }).replace(/^/gm, '    ')}`,
				/aws is required/,
			],
		] as const) {
			const path = await writeConfig(h, text);
			await expect(loadUserConfig(path, false, () => {})).rejects.toThrow(why);
		}
	});
});

describe('loadRepoAlias', () => {
	test('reads the alias, or nothing without the file', async () => {
		const n = notices();
		expect(await loadRepoAlias(await checkout('version: 1\ntarget: team\n'), n.notice)).toBe(
			'team',
		);
		expect(await loadRepoAlias(await checkout(), n.notice)).toBeUndefined();
		expect(await loadRepoAlias('/nonexistent', n.notice)).toBeUndefined();
		expect(n.lines).toEqual([]);
	});

	test('refuses anything but an alias in a checkout', async () => {
		for (const text of [
			'version: 1\ntarget: team\nendpoint:\n  host: evil.example\n',
			'version: 1\ntarget: team\ndomain: evil.example\n',
			'version: 1\n',
			'target: team\n',
		]) {
			await expect(loadRepoAlias(await checkout(text), () => {})).rejects.toThrow(
				/alias and nothing else/,
			);
		}
	});

	test('ignores a symlink with a warning, even one to a valid alias', async () => {
		// A checkout may commit the file as a link to anything on the user's
		// machine, /dev/zero included. koi must not open what the link names.
		const dir = await checkout();
		await mkdir(join(dir, '.koi'));
		await writeFile(join(dir, 'real.yaml'), 'version: 1\ntarget: team\n');
		const path = join(dir, REPO_TARGET_FILE);
		await symlink(join(dir, 'real.yaml'), path);
		const n = notices();
		expect(await loadRepoAlias(dir, n.notice)).toBeUndefined();
		expect(n.lines).toEqual([
			`${path} is a symlink; koi ignores it. An alias file must be a regular file`,
		]);
	});

	test('refuses a file over the size bound, and reads one at it', async () => {
		const alias = 'version: 1\ntarget: team\n';
		const padded = (size: number) => `${alias}#${'x'.repeat(size - alias.length - 2)}\n`;
		const n = notices();
		expect(await loadRepoAlias(await checkout(padded(MAX_REPO_ALIAS_BYTES)), n.notice)).toBe(
			'team',
		);
		const over = await checkout(padded(MAX_REPO_ALIAS_BYTES + 1));
		await expect(loadRepoAlias(over, n.notice)).rejects.toThrow(
			`${join(over, REPO_TARGET_FILE)} is ${MAX_REPO_ALIAS_BYTES + 1} bytes; an alias file holds a version and a target name, and koi reads at most ${MAX_REPO_ALIAS_BYTES}`,
		);
		const huge = await checkout(padded(1024 * 1024));
		await expect(loadRepoAlias(huge, n.notice)).rejects.toThrow(/is 1048576 bytes/);
		expect(n.lines).toEqual([]);
	});
});

describe('resolveTarget', () => {
	// A file with every target the tests below select among.
	async function configured(defaultTarget?: string) {
		const h = await home();
		await writeConfig(h, {
			version: 1,
			...(defaultTarget === undefined ? {} : { defaultTarget }),
			targets: {
				flagged: AWS_TARGET,
				fromenv: { ...AWS_TARGET, domain: 'env.example.com' },
				aliased: { ...AWS_TARGET, domain: 'alias.example.com' },
				fallback: { ...AWS_TARGET, domain: 'default.example.com' },
				team: SSH_TARGET,
				// Reached over SSH, woken through EC2: it carries an aws section.
				sshwake: { ...SSH_TARGET, power: { kind: 'ec2' }, aws: AWS_TARGET.aws },
			},
		});
		return h;
	}

	test('--target, then KOI_TARGET, then .koi/target.yaml, then defaultTarget', async () => {
		const h = await configured('fallback');
		const repo = await checkout('version: 1\ntarget: aliased\n');
		const env = { HOME: h, KOI_TARGET: 'fromenv' };
		const n = notices();
		const pick = (flags: { target?: string }, e: Record<string, string>, dir = repo) =>
			resolveTarget({ flags, env: e, checkoutDir: dir, notice: n.notice });

		const flag = await pick({ target: 'flagged' }, env);
		expect(flag.kind === 'target' && [flag.name, flag.source]).toEqual(['flagged', 'flag']);
		const fromEnv = await pick({}, env);
		expect(fromEnv.kind === 'target' && [fromEnv.name, fromEnv.source]).toEqual(['fromenv', 'env']);
		const alias = await pick({}, { HOME: h });
		expect(alias.kind === 'target' && [alias.name, alias.source]).toEqual(['aliased', 'repo']);
		const fallback = await pick({}, { HOME: h }, await checkout());
		expect(fallback.kind === 'target' && [fallback.name, fallback.source]).toEqual([
			'fallback',
			'default',
		]);
		expect(n.lines).toEqual([]);
	});

	test('no config file and nothing selected is the legacy AWS path', async () => {
		const h = await home();
		const r = await resolveTarget({
			flags: {},
			env: { HOME: h },
			checkoutDir: await checkout(),
			notice: () => {},
		});
		expect(r).toEqual({
			kind: 'legacy',
			configPath: join(h, '.config', 'koi', 'config.yaml'),
			domain: undefined,
		});
		// --domain and KOI_DOMAIN name the expected domain there too.
		const d = await resolveTarget({
			flags: { domain: 'flag.example.com' },
			env: { HOME: h, KOI_DOMAIN: 'env.example.com' },
			checkoutDir: await checkout(),
			notice: () => {},
		});
		expect(d.kind === 'legacy' && d.domain).toBe('flag.example.com');
	});

	test('a config file that selects nothing is an error, not the legacy path', async () => {
		const h = await configured();
		await expect(
			resolveTarget({
				flags: {},
				env: { HOME: h },
				checkoutDir: await checkout(),
				notice: () => {},
			}),
		).rejects.toThrow(/selects no target.*flagged, fromenv.*no defaultTarget/);
	});

	test('a selection without a config file points at koi config import-aws', async () => {
		const h = await home();
		await expect(
			resolveTarget({
				flags: { target: 'team' },
				env: { HOME: h },
				checkoutDir: await checkout(),
				notice: () => {},
			}),
		).rejects.toThrow(
			/--target names "team", but there is no config file at .*import-aws --name team/,
		);
		await expect(
			resolveTarget({
				flags: {},
				env: { HOME: h },
				checkoutDir: await checkout('version: 1\ntarget: team\n'),
				notice: () => {},
			}),
		).rejects.toThrow(/target\.yaml names the target "team", but there is no config file/);
	});

	test('a repository alias that names no target in the file is an error', async () => {
		const h = await configured('fallback');
		await expect(
			resolveTarget({
				flags: {},
				env: { HOME: h },
				checkoutDir: await checkout('version: 1\ntarget: stranger\n'),
				notice: () => {},
			}),
		).rejects.toThrow(/names the target "stranger", but .* has only flagged, fromenv/);
	});

	test('--domain, then KOI_DOMAIN, then the target, set the expected domain', async () => {
		const h = await configured('fallback');
		const dir = await checkout();
		const domainOf = async (flags: { domain?: string }, env: Record<string, string>) => {
			const r = await resolveTarget({ flags, env, checkoutDir: dir, notice: () => {} });
			return r.kind === 'target' ? r.target.domain : undefined;
		};
		expect(
			await domainOf({ domain: 'flag.example.com' }, { HOME: h, KOI_DOMAIN: 'env.example.com' }),
		).toBe('flag.example.com');
		expect(await domainOf({}, { HOME: h, KOI_DOMAIN: 'env.example.com' })).toBe('env.example.com');
		expect(await domainOf({}, { HOME: h })).toBe('default.example.com');
		// On any target, SSH included: it changes the expected domain, not the host.
		const ssh = await resolveTarget({
			flags: { target: 'team' },
			env: { HOME: h, KOI_DOMAIN: 'env.example.com' },
			checkoutDir: dir,
			notice: () => {},
		});
		expect(ssh.kind === 'target' && ssh.target.domain).toBe('env.example.com');
		expect(ssh.kind === 'target' && ssh.target.transport).toEqual(
			TargetSchema.parse(SSH_TARGET).transport,
		);
		await expect(domainOf({}, { HOME: h, KOI_DOMAIN: 'https://x.example.com' })).rejects.toThrow(
			/overrides applied is not valid: domain/,
		);
	});

	test('the AWS variables override an AWS target, and are refused on an SSH one', async () => {
		const h = await configured('fallback');
		const dir = await checkout();
		const r = await resolveTarget({
			flags: {},
			env: {
				HOME: h,
				KOI_AWS_PROFILE: 'other',
				KOI_AWS_REGION: 'eu-west-1',
				KOI_INSTANCE_ID: 'i-0fedcba',
				KOI_BUCKET: 'my-bucket',
			},
			checkoutDir: dir,
			notice: () => {},
		});
		expect(r.kind === 'target' && r.target.aws).toEqual({
			profile: 'other',
			region: 'eu-west-1',
			instanceId: 'i-0fedcba',
			uploadsBucket: 'my-bucket',
		});
		await expect(
			resolveTarget({
				flags: { target: 'team' },
				env: { HOME: h, KOI_INSTANCE_ID: 'i-0fedcba' },
				checkoutDir: dir,
				notice: () => {},
			}),
		).rejects.toThrow(
			'KOI_INSTANCE_ID applies to AWS targets only, and "team" uses the ssh transport',
		);
		// An SSH target with EC2 power has an aws section, and is still not an
		// AWS target: the overrides could point wake at another instance than
		// the one SSH connects to.
		await expect(
			resolveTarget({
				flags: { target: 'sshwake' },
				env: { HOME: h, KOI_INSTANCE_ID: 'i-0fedcba', KOI_AWS_PROFILE: 'other' },
				checkoutDir: dir,
				notice: () => {},
			}),
		).rejects.toThrow(
			'KOI_AWS_PROFILE, KOI_INSTANCE_ID apply to AWS targets only, and "sshwake" uses the ssh transport',
		);
		await expect(
			resolveTarget({
				flags: {},
				env: { HOME: h, KOI_INSTANCE_ID: 'not-an-instance' },
				checkoutDir: dir,
				notice: () => {},
			}),
		).rejects.toThrow(/overrides applied is not valid: aws.instanceId/);
	});

	test('a target named constructor is looked up as the file has it', async () => {
		const h = await configured('fallback');
		const dir = await checkout();
		await expect(
			resolveTarget({
				flags: { target: 'constructor' },
				env: { HOME: h },
				checkoutDir: dir,
				notice: () => {},
			}),
		).rejects.toThrow(/--target names "constructor", but .* has only flagged, fromenv/);
		const own = await home();
		await writeConfig(own, { version: 1, targets: { constructor: SSH_TARGET } });
		const r = await resolveTarget({
			flags: { target: 'constructor' },
			env: { HOME: own },
			checkoutDir: dir,
			notice: () => {},
		});
		expect(r.kind === 'target' && r.name).toBe('constructor');
	});

	test('empty values are errors', async () => {
		const h = await configured('fallback');
		const dir = await checkout();
		for (const [flags, env, what] of [
			[{ target: '' }, {}, '--target'],
			[{}, { KOI_TARGET: '' }, 'KOI_TARGET'],
			[{ domain: '' }, {}, '--domain'],
			[{}, { KOI_DOMAIN: '' }, 'KOI_DOMAIN'],
			[{}, { KOI_BUCKET: '' }, 'KOI_BUCKET'],
			[{}, { KOI_AWS_PROFILE: '' }, 'KOI_AWS_PROFILE'],
		] as const) {
			await expect(
				resolveTarget({ flags, env: { HOME: h, ...env }, checkoutDir: dir, notice: () => {} }),
			).rejects.toThrow(`${what} is empty`);
		}
	});

	test('does not search parent directories for an alias', async () => {
		const h = await configured('fallback');
		const parent = await checkout('version: 1\ntarget: aliased\n');
		const child = join(parent, 'sub');
		await mkdir(child);
		const r = await resolveTarget({
			flags: {},
			env: { HOME: h },
			checkoutDir: child,
			notice: () => {},
		});
		expect(r.kind === 'target' && r.name).toBe('fallback');
	});
});

// EC2 and STS as koi config import-aws discovers the deployment: one box
// tagged with the domain, and the account id. Every call is recorded.
function discoveryClients(domainTag: string | null = 'previews.example.net') {
	const calls: string[] = [];
	const send = async (cmd: { constructor: { name: string }; input: unknown }) => {
		calls.push(cmd.constructor.name);
		if (cmd.constructor.name === 'DescribeInstancesCommand') {
			const Tags = domainTag === null ? [] : [{ Key: 'Domain', Value: domainTag }];
			return { Reservations: [{ Instances: [{ InstanceId: 'i-0123456789abcdef0', Tags }] }] };
		}
		if (cmd.constructor.name === 'GetCallerIdentityCommand') return { Account: '123456789012' };
		throw new Error(`unexpected ${cmd.constructor.name}`);
	};
	const client = { send } as never;
	const made: string[] = [];
	return {
		calls,
		made,
		make: (profile: string, region: string): Clients => {
			made.push(`${profile}@${region}`);
			return { s3: client, ec2: client, ssm: client, sts: client };
		},
	};
}

function io() {
	let stdout = '';
	let stderr = '';
	const target: Io = {
		stdout: (s) => {
			stdout += s;
		},
		stderr: (s) => {
			stderr += s;
		},
	};
	return { io: target, stdout: () => stdout, stderr: () => stderr };
}

describe('koi config import-aws', () => {
	test('writes the discovered deployment as a target, 0600 in a 0700 directory', async () => {
		const h = await home();
		const aws = discoveryClients();
		const out = io();
		const code = await configCommand(
			parseCli(['config', 'import-aws', '--name', 'owner-aws']),
			out.io,
			{
				env: { HOME: h },
				checkoutDir: await checkout(),
				notice: () => {},
				awsClients: aws.make,
			},
		);
		expect(code).toBe(0);
		const path = join(h, '.config', 'koi', 'config.yaml');
		expect((await stat(path)).mode & 0o777).toBe(0o600);
		expect((await stat(join(h, '.config', 'koi'))).mode & 0o777).toBe(0o700);
		const written = Bun.YAML.parse(await readFile(path, 'utf8'));
		expect(written).toEqual({
			version: 1,
			defaultTarget: 'owner-aws',
			targets: { 'owner-aws': AWS_TARGET },
		});
		expect(UserConfigSchema.safeParse(written).success).toBe(true);
		expect(out.stdout()).toContain(`wrote target owner-aws in ${path} and made it the default:`);
		expect(out.stdout()).toContain('instanceId: i-0123456789abcdef0');
		expect(out.stdout()).toContain('domain: previews.example.net');
		expect(aws.made).toEqual(['koi-cli@us-east-1']);
		expect(aws.calls).toEqual([
			'DescribeInstancesCommand',
			'DescribeInstancesCommand',
			'GetCallerIdentityCommand',
		]);
	});

	test('takes the domain from --domain, then KOI_DOMAIN, then the Domain tag', async () => {
		const h = await home();
		const run = (argv: string[], env: Record<string, string>, tag: string | null) =>
			configCommand(parseCli(argv), io().io, {
				env: { HOME: h, ...env },
				checkoutDir: '/nonexistent',
				notice: () => {},
				awsClients: discoveryClients(tag).make,
			});
		const domainOf = async () => {
			const written = Bun.YAML.parse(
				await readFile(join(h, '.config/koi/config.yaml'), 'utf8'),
			) as {
				targets: Record<string, { domain: string }>;
			};
			return written.targets.x?.domain;
		};
		await run(
			['config', 'import-aws', '--name', 'x', '--domain', 'flag.example.com'],
			{ KOI_DOMAIN: 'env.example.com' },
			null,
		);
		expect(await domainOf()).toBe('flag.example.com');
		await run(
			['config', 'import-aws', '--name', 'x', '--replace'],
			{ KOI_DOMAIN: 'env.example.com' },
			null,
		);
		expect(await domainOf()).toBe('env.example.com');
		await run(['config', 'import-aws', '--name', 'x', '--replace'], {}, 'tag.example.com');
		expect(await domainOf()).toBe('tag.example.com');
		await expect(run(['config', 'import-aws', '--name', 'y'], {}, null)).rejects.toThrow(
			/no Domain tag.*KOI_DOMAIN/,
		);
		await expect(
			run(['config', 'import-aws', '--name', 'y', '--domain', 'https://x.example.com'], {}, null),
		).rejects.toThrow(/domain/);
	});

	test('refuses to overwrite a target without --replace, and keeps other targets', async () => {
		const h = await home();
		const path = await writeConfig(h, {
			version: 1,
			defaultTarget: 'team',
			targets: { team: SSH_TARGET, 'owner-aws': { ...AWS_TARGET, domain: 'old.example.com' } },
		});
		const deps = {
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: () => {},
			awsClients: discoveryClients().make,
		};
		await expect(
			configCommand(parseCli(['config', 'import-aws', '--name', 'owner-aws']), io().io, deps),
		).rejects.toThrow(`${path} already has a target "owner-aws"; pass --replace`);
		expect(Bun.YAML.parse(await readFile(path, 'utf8'))).toMatchObject({
			targets: { 'owner-aws': { domain: 'old.example.com' } },
		});
		const out = io();
		await configCommand(
			parseCli(['config', 'import-aws', '--name', 'owner-aws', '--replace', '--json']),
			out.io,
			deps,
		);
		expect(JSON.parse(out.stdout())).toEqual({
			file: path,
			target: 'owner-aws',
			replaced: true,
			default: false,
			settings: AWS_TARGET,
		});
		expect(Bun.YAML.parse(await readFile(path, 'utf8'))).toEqual({
			version: 1,
			defaultTarget: 'team',
			targets: { team: SSH_TARGET, 'owner-aws': AWS_TARGET },
		});
		expect((await stat(path)).mode & 0o777).toBe(0o600);
	});

	test('a target named constructor is absent until written, like any other', async () => {
		const h = await home();
		const deps = {
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: () => {},
			awsClients: discoveryClients().make,
		};
		const out = io();
		await configCommand(
			parseCli(['config', 'import-aws', '--name', 'constructor', '--json']),
			out.io,
			deps,
		);
		expect(JSON.parse(out.stdout())).toMatchObject({ target: 'constructor', replaced: false });
		const path = join(h, '.config', 'koi', 'config.yaml');
		expect(Bun.YAML.parse(await readFile(path, 'utf8'))).toEqual({
			version: 1,
			defaultTarget: 'constructor',
			targets: { constructor: AWS_TARGET },
		});
		await expect(
			configCommand(parseCli(['config', 'import-aws', '--name', 'constructor']), io().io, deps),
		).rejects.toThrow('already has a target "constructor"');
	});

	test('imports that start together take the lock in turn and keep every target', async () => {
		// Eight imports start together. Each must make the lock or wait for
		// it, and the file must end up with every target. Several rounds,
		// since the race is decided by timing.
		const names = Array.from({ length: 8 }, (_, i) => `t${i}`);
		for (let round = 0; round < 5; round++) {
			const h = await home();
			const path = join(h, '.config', 'koi', 'config.yaml');
			const codes = await Promise.all(
				names.map((name) =>
					configCommand(parseCli(['config', 'import-aws', '--name', name]), io().io, {
						env: { HOME: h },
						checkoutDir: '/nonexistent',
						notice: () => {},
						awsClients: discoveryClients().make,
						sleep: () => Bun.sleep(5),
					}),
				),
			);
			expect(codes).toEqual(names.map(() => 0));
			const written = Bun.YAML.parse(await readFile(path, 'utf8')) as {
				targets: Record<string, unknown>;
			};
			expect(Object.keys(written.targets).sort()).toEqual([...names].sort());
			expect(UserConfigSchema.safeParse(written).success).toBe(true);
			// No lock and nothing half written is left behind.
			expect(await readdir(dirname(path))).toEqual(['config.yaml']);
		}
	});

	test('a held lock makes an import wait, and it goes on once the lock is released', async () => {
		const h = await home();
		const path = join(h, '.config', 'koi', 'config.yaml');
		const lock = `${path}.lock`;
		await mkdir(lock, { recursive: true, mode: 0o700 });
		const slept: number[] = [];
		expect(
			await configCommand(parseCli(['config', 'import-aws', '--name', 'x']), io().io, {
				env: { HOME: h },
				checkoutDir: '/nonexistent',
				notice: () => {},
				awsClients: discoveryClients().make,
				sleep: async (ms) => {
					slept.push(ms);
					// The holder finishes after the second look.
					if (slept.length === 2) await rmdir(lock);
				},
			}),
		).toBe(0);
		expect(slept).toEqual([200, 200]);
		expect(await exists(lock)).toBe(false);
		expect(Bun.YAML.parse(await readFile(path, 'utf8'))).toMatchObject({ targets: { x: {} } });
	});

	test('never removes a lock it did not make, however old, and says what to do', async () => {
		const h = await home();
		const path = join(h, '.config', 'koi', 'config.yaml');
		const lock = `${path}.lock`;
		await mkdir(lock, { recursive: true, mode: 0o700 });
		// Left behind by a koi that died minutes ago.
		const old = new Date(Date.now() - 3 * CONFIG_LOCK_WAIT_MS);
		await utimes(lock, old, old);
		const slept: number[] = [];
		await expect(
			configCommand(parseCli(['config', 'import-aws', '--name', 'x']), io().io, {
				env: { HOME: h },
				checkoutDir: '/nonexistent',
				notice: () => {},
				awsClients: discoveryClients().make,
				sleep: async (ms) => {
					slept.push(ms);
				},
			}),
		).rejects.toThrow(
			`another koi config holds the lock ${lock}, and did not release it within 60 seconds. A previous koi config run may have crashed and left it behind. Check that no other koi config is running, then remove the directory ${lock} by hand and try again.`,
		);
		// It waited the whole minute, in the sleeps it asked for, and the
		// old lock is still the old lock.
		expect(slept.reduce((sum, ms) => sum + ms, 0)).toBe(CONFIG_LOCK_WAIT_MS);
		const left = await stat(lock);
		expect(left.isDirectory()).toBe(true);
		expect(left.mtimeMs).toBeLessThan(Date.now() - 2 * CONFIG_LOCK_WAIT_MS);
		expect(await exists(path)).toBe(false);
	});

	test('does not rewrite a file it cannot read', async () => {
		const h = await home();
		const path = await writeConfig(h, 'version: 1\ntargets: {}\nhooks: [x]\n');
		const before = await readFile(path, 'utf8');
		await expect(
			configCommand(parseCli(['config', 'import-aws', '--name', 'x']), io().io, {
				env: { HOME: h },
				checkoutDir: '/nonexistent',
				notice: () => {},
				awsClients: discoveryClients().make,
			}),
		).rejects.toThrow(/not a koi config file/);
		expect(await readFile(path, 'utf8')).toBe(before);
	});

	test('honours --config and KOI_CONFIG for where to write', async () => {
		const h = await home();
		const path = join(h, 'elsewhere', 'k.yaml');
		await configCommand(
			parseCli(['config', 'import-aws', '--name', 'x', '--config', path]),
			io().io,
			{
				env: { HOME: h },
				checkoutDir: '/nonexistent',
				notice: () => {},
				awsClients: discoveryClients().make,
			},
		);
		expect((await stat(path)).mode & 0o777).toBe(0o600);
		expect((await stat(join(h, 'elsewhere'))).mode & 0o777).toBe(0o700);
	});
});

async function exists(path: string): Promise<boolean> {
	return stat(path).then(
		() => true,
		() => false,
	);
}

describe('withConfigLock', () => {
	test('runs one task at a time, in the order the lock was taken', async () => {
		const path = join(await home(), '.config', 'koi', 'config.yaml');
		const lock = `${path}.lock`;
		const order: string[] = [];
		let release!: () => void;
		const held = new Promise<void>((r) => {
			release = r;
		});
		const first = withConfigLock(
			path,
			async () => {},
			async () => {
				order.push('first starts');
				await held;
				order.push('first ends');
			},
		);
		while (!(await exists(lock))) await Bun.sleep(5);
		expect((await stat(lock)).isDirectory()).toBe(true);
		const second = withConfigLock(
			path,
			async () => {
				// Polled until the first task's lock is gone; one wait is the point.
				if (!order.includes('second waits')) order.push('second waits');
				release();
			},
			async () => {
				order.push('second runs');
			},
		);
		await Promise.all([first, second]);
		expect(order).toEqual(['first starts', 'second waits', 'first ends', 'second runs']);
		expect(await exists(lock)).toBe(false);
	});

	test('releases the lock when the task fails', async () => {
		const path = join(await home(), '.config', 'koi', 'config.yaml');
		await expect(
			withConfigLock(
				path,
				async () => {},
				async () => {
					throw new Error('no');
				},
			),
		).rejects.toThrow('no');
		expect(await exists(`${path}.lock`)).toBe(false);
	});
});

describe('koi config show', () => {
	test('prints the resolved target and where it came from, without AWS calls', async () => {
		const h = await home();
		const path = await writeConfig(h, {
			version: 1,
			defaultTarget: 'owner-aws',
			targets: { 'owner-aws': AWS_TARGET },
		});
		const out = io();
		const code = await configCommand(parseCli(['config', 'show']), out.io, {
			env: { HOME: h, KOI_INSTANCE_ID: 'i-0fedcba' },
			checkoutDir: '/nonexistent',
			notice: () => {},
			awsClients: () => {
				throw new Error('no AWS calls for show');
			},
		});
		expect(code).toBe(0);
		expect(out.stdout()).toStartWith(`target owner-aws (from defaultTarget) in ${path}:\n`);
		expect(out.stdout()).toContain('  instanceId: i-0fedcba\n');
		const json = io();
		await configCommand(parseCli(['config', 'show', '--json', '--target', 'owner-aws']), json.io, {
			env: { HOME: h },
			checkoutDir: '/nonexistent',
			notice: () => {},
		});
		expect(JSON.parse(json.stdout())).toEqual({
			file: path,
			target: 'owner-aws',
			source: 'flag',
			settings: TargetSchema.parse(AWS_TARGET),
		});
	});

	test('says what the legacy path would do, naming what it discovers', async () => {
		const h = await home();
		const out = io();
		await configCommand(parseCli(['config', 'show']), out.io, {
			env: { HOME: h, KOI_BUCKET: 'b' },
			checkoutDir: '/nonexistent',
			notice: () => {},
		});
		expect(out.stdout()).toContain('no target: there is no config file at');
		expect(out.stdout()).toContain('uploadsBucket  b\n');
		expect(out.stdout()).toContain('instanceId     (discovered at run time');
		expect(out.stdout()).toContain('koi config import-aws --name NAME');
		const json = io();
		await configCommand(parseCli(['config', 'show', '--json']), json.io, {
			env: { HOME: h, KOI_BUCKET: 'b' },
			checkoutDir: '/nonexistent',
			notice: () => {},
		});
		expect(JSON.parse(json.stdout())).toEqual({
			file: join(h, '.config/koi/config.yaml'),
			target: null,
			legacy: {
				profile: 'koi-cli',
				region: 'us-east-1',
				instanceId: null,
				uploadsBucket: 'b',
				domain: null,
			},
		});
	});
});
