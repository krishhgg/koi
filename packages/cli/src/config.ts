import { constants } from 'node:fs';
import { type FileHandle, open, readFile, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { BareDomainSchema } from '@koi/shared';
import { z } from 'zod';
import { sshPathProblem } from './ssh.ts';

// The CLI's connection settings: which hosts (targets) koi can send previews
// to, and under which domain each serves them. One file per user, at
// $XDG_CONFIG_HOME/koi/config.yaml or ~/.config/koi/config.yaml. A repository
// may commit .koi/target.yaml naming one of the user's targets by alias, and
// nothing more: a checkout cannot define an endpoint, pick a domain or name
// an identity file. The file holds references (a profile name, a key path),
// never a key, a token or a command.

// A target's name, as the config file keys it and --target takes it.
export const TargetNameSchema = z
	.string()
	.regex(/^[a-z0-9][a-z0-9-]{0,62}$/, 'a target name: lowercase letters, digits and dashes');

// A path in the user's file: absolute, or under the home directory as ~/...
// A relative path would mean something else from every directory koi runs
// in. Repository aliases never carry paths.
export const AbsPathSchema = z
	.string()
	.min(1)
	.transform((p, ctx) => {
		if (p === '~' || p.startsWith('~/')) return join(homedir(), p.slice(1));
		if (!isAbsolute(p)) {
			ctx.addIssue({ code: 'custom', message: `${JSON.stringify(p)} is not an absolute path` });
			return z.NEVER;
		}
		return resolve(p);
	});

// A path koi hands to ssh as an option value. ssh reads the value back with
// its ssh_config parser; a `%`, a `${`, a line break or a control character
// in the path would not come back as the same path (ssh.ts,
// sshPathProblem), so the file refuses them with the reason.
export const SshPathSchema = AbsPathSchema.superRefine((p, ctx) => {
	const problem = sshPathProblem(p);
	if (problem !== undefined) {
		ctx.addIssue({
			code: 'custom',
			message: `${JSON.stringify(p)} cannot be given to ssh: ${problem}`,
		});
	}
});

const HOSTNAME =
	/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

const HostnameOrIpSchema = z
	.string()
	.min(1)
	.refine((s) => isIP(s) !== 0 || HOSTNAME.test(s), { message: 'a hostname or IP address' });

export const AwsContextSchema = z.strictObject({
	profile: z.string().min(1).default('koi-cli'),
	region: z.string().min(1).default('us-east-1'),
	instanceId: z.string().regex(/^i-[a-f0-9]+$/, 'an EC2 instance id'),
	uploadsBucket: z.string().min(3),
});

// Where and as whom to reach a host over SSH. Exactly one identity: a private
// key file koi hands to ssh, or the public half of a key ssh-agent holds, so
// that ssh offers that one key and no other. The host key is pinned in a
// known_hosts file of koi's own under the target's alias.
export const SshEndpointSchema = z
	.strictObject({
		host: HostnameOrIpSchema,
		port: z.number().int().min(1).max(65535).default(22),
		user: z.literal('koi-connect'),
		identityFile: SshPathSchema.optional(),
		identityPublicKey: SshPathSchema.optional(),
		knownHostsFile: SshPathSchema,
		hostKeyAlias: TargetNameSchema,
	})
	.refine((e) => (e.identityFile === undefined) !== (e.identityPublicKey === undefined), {
		message: 'exactly one of identityFile and identityPublicKey',
		path: ['identityFile'],
	});

export const TransportSchema = z.discriminatedUnion('kind', [
	z.strictObject({
		kind: z.literal('aws-ssm'),
		// A separate SSH path for verification, next to SSM. Not supported yet.
		channel: SshEndpointSchema.optional(),
	}),
	z.strictObject({ kind: z.literal('ssh'), endpoint: SshEndpointSchema }),
	z.strictObject({ kind: z.literal('local'), controlSocket: AbsPathSchema }),
]);

export const PowerSchema = z.discriminatedUnion('kind', [
	// koi never stops the host and cannot start it.
	z.strictObject({ kind: z.literal('always-on') }),
	// An EC2 instance koi starts before use; it stops itself when idle.
	z.strictObject({ kind: z.literal('ec2') }),
]);

export const TargetSchema = z
	.strictObject({
		domain: BareDomainSchema,
		address: z
			.strictObject({
				scheme: z.literal('https').default('https'),
				port: z.number().int().min(1).max(65535).default(443),
			})
			.default({ scheme: 'https', port: 443 }),
		aws: AwsContextSchema.optional(),
		transport: TransportSchema,
		power: PowerSchema,
	})
	.superRefine((t, ctx) => {
		// SSM commands and EC2 wake address the same instance, so one AWS
		// context serves both; a target that uses neither must not carry one.
		const needsAws = t.transport.kind === 'aws-ssm' || t.power.kind === 'ec2';
		if (needsAws && t.aws === undefined) {
			ctx.addIssue({
				code: 'custom',
				path: ['aws'],
				message: `aws is required with transport ${t.transport.kind} and power ${t.power.kind}`,
			});
		}
		if (!needsAws && t.aws !== undefined) {
			ctx.addIssue({
				code: 'custom',
				path: ['aws'],
				message: `aws is not used with transport ${t.transport.kind} and power ${t.power.kind}`,
			});
		}
	});

export const UserConfigSchema = z
	.strictObject({
		version: z.literal(1),
		defaultTarget: TargetNameSchema.optional(),
		targets: z.record(TargetNameSchema, TargetSchema),
	})
	.superRefine((c, ctx) => {
		if (c.defaultTarget !== undefined && !Object.hasOwn(c.targets, c.defaultTarget)) {
			ctx.addIssue({
				code: 'custom',
				path: ['defaultTarget'],
				message: `no target named ${JSON.stringify(c.defaultTarget)}`,
			});
		}
	});

// .koi/target.yaml in a checkout: an alias into the user's file, and nothing
// else, so that a pull request cannot point koi at a host of its choosing.
export const RepoTargetSchema = z.strictObject({
	version: z.literal(1),
	target: TargetNameSchema,
});

export type UserConfig = z.infer<typeof UserConfigSchema>;
export type Target = z.infer<typeof TargetSchema>;
export type Transport = z.infer<typeof TransportSchema>;
export type AwsContext = z.infer<typeof AwsContextSchema>;
export type SshEndpoint = z.infer<typeof SshEndpointSchema>;

export const REPO_TARGET_FILE = '.koi/target.yaml';

// The most koi reads from .koi/target.yaml. An alias is two short lines; the
// bound keeps a checkout from handing koi a file it cannot hold in memory.
export const MAX_REPO_ALIAS_BYTES = 4096;

// The selectors the command line gives: which file, which target, and the
// domain to expect of the host instead of the target's own. `local` is
// --local, the built-in local target.
export interface TargetFlags {
	target?: string | undefined;
	config?: string | undefined;
	domain?: string | undefined;
	local?: boolean | undefined;
}

// The socket koid makes on a host set up by host/install-vm.sh, and the
// domain the docs set up for a local host.
export const LOCAL_SOCKET = '/run/koi/control.sock';
export const LOCAL_DOMAIN = 'koi.test';

// What --local stands for: koid on this machine at its usual socket, or at
// KOID_CONTROL_SOCKET, which `koid ctl` reads too, serving previews under
// koi.test. No config file is needed or read for it.
export function localTarget(env: Env): Target {
	const socket =
		env.KOID_CONTROL_SOCKET === undefined
			? LOCAL_SOCKET
			: nonEmpty(env.KOID_CONTROL_SOCKET, 'KOID_CONTROL_SOCKET');
	return TargetSchema.parse({
		domain: LOCAL_DOMAIN,
		transport: { kind: 'local', controlSocket: socket },
		power: { kind: 'always-on' },
	});
}

export type Env = Record<string, string | undefined>;

// The variables the environment may set. KOI_TARGET and KOI_CONFIG select;
// the rest override one field of the selected target, and the AWS ones only
// on an AWS target.
export const AWS_ENV = [
	'KOI_AWS_PROFILE',
	'KOI_AWS_REGION',
	'KOI_INSTANCE_ID',
	'KOI_BUCKET',
] as const;

// Where the user's file is: --config, then KOI_CONFIG, then the XDG path.
// `explicit` says the caller named it, so its absence is an error rather
// than permission for the legacy AWS path. A path may start with ~/, which
// is the home directory, as a shell would not expand it inside a quoted
// value. A relative XDG_CONFIG_HOME is invalid by the XDG specification and
// is ignored, so the default file cannot end up under the checkout.
export function configPath(flags: TargetFlags, env: Env): { path: string; explicit: boolean } {
	const home = env.HOME || homedir();
	if (flags.config !== undefined) {
		return { path: expandHome(nonEmpty(flags.config, '--config'), home), explicit: true };
	}
	if (env.KOI_CONFIG !== undefined) {
		return { path: expandHome(nonEmpty(env.KOI_CONFIG, 'KOI_CONFIG'), home), explicit: true };
	}
	const xdg = env.XDG_CONFIG_HOME;
	const base = xdg !== undefined && isAbsolute(xdg) ? xdg : join(home, '.config');
	return { path: join(base, 'koi', 'config.yaml'), explicit: false };
}

function expandHome(path: string, home: string): string {
	if (path === '~' || path.startsWith('~/')) return resolve(join(home, path.slice(1)));
	return resolve(path);
}

export interface LoadedConfig {
	path: string;
	config: UserConfig;
	// The file as parsed, for a writer to change and write back without
	// filling in defaults the user did not write.
	raw: Record<string, unknown>;
}

// The user's file, validated, or undefined when the default file is absent.
// The file holds no secrets, but it does say where koi sends source, so a
// file others can write to is a problem, and one others can read is a hint
// of that; both get a warning rather than a refusal.
export async function loadUserConfig(
	path: string,
	explicit: boolean,
	notice: (message: string) => void,
): Promise<LoadedConfig | undefined> {
	let mode: number;
	try {
		mode = (await stat(path)).mode & 0o777;
	} catch (err) {
		if (!isNotFound(err)) throw err;
		if (explicit) throw new Error(`no config file at ${path}`);
		return undefined;
	}
	if ((mode & 0o077) !== 0) {
		notice(
			`${path} is open to other users (mode ${mode.toString(8).padStart(4, '0')}); run chmod 600 ${path}`,
		);
	}
	const raw = parseYaml(await readFile(path, 'utf8'), path);
	if (!isRecord(raw)) throw new Error(`${path} is not a koi config file: expected a mapping`);
	const parsed = UserConfigSchema.safeParse(raw);
	if (!parsed.success) throw new Error(`${path} is not a koi config file: ${issues(parsed.error)}`);
	return { path, config: parsed.data, raw };
}

// The alias in <checkoutDir>/.koi/target.yaml, or undefined without one.
// A pull request controls that file, so koi reads it as untrusted input.
// The open does not follow a symlink: a link to /dev/zero would otherwise
// be read until memory ran out. The kind, the size and the bytes all come
// from the one open descriptor, so what was checked is what is read, and
// the read stops one byte past the bound, so a file that grows after the
// size check is refused rather than read whole. A symlink counts as no
// alias file, with a warning, since the user may still have a
// defaultTarget. A file that is too large or not a regular file is an
// error: koi was asked to read it and cannot.
export async function loadRepoAlias(
	checkoutDir: string,
	notice: (message: string) => void,
): Promise<string | undefined> {
	const path = join(checkoutDir, REPO_TARGET_FILE);
	let handle: FileHandle;
	try {
		handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
	} catch (err) {
		if (isNotFound(err)) return undefined;
		if (errorCode(err) === 'ELOOP') {
			notice(`${path} is a symlink; koi ignores it. An alias file must be a regular file`);
			return undefined;
		}
		throw err;
	}
	let text: string;
	try {
		const info = await handle.stat();
		if (!info.isFile()) throw new Error(`${path} is not a regular file`);
		if (info.size > MAX_REPO_ALIAS_BYTES) {
			throw new Error(
				`${path} is ${info.size} bytes; an alias file holds a version and a target name, and koi reads at most ${MAX_REPO_ALIAS_BYTES}`,
			);
		}
		const buffer = Buffer.alloc(MAX_REPO_ALIAS_BYTES + 1);
		let length = 0;
		while (length < buffer.length) {
			const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
			if (bytesRead === 0) break;
			length += bytesRead;
		}
		if (length > MAX_REPO_ALIAS_BYTES) {
			throw new Error(`${path} is over ${MAX_REPO_ALIAS_BYTES} bytes; it grew while koi read it`);
		}
		text = buffer.toString('utf8', 0, length);
	} finally {
		await handle.close();
	}
	const parsed = RepoTargetSchema.safeParse(parseYaml(text, path));
	if (!parsed.success) {
		throw new Error(
			`${path} may name a target alias and nothing else (version: 1, target: NAME): ${issues(parsed.error)}`,
		);
	}
	return parsed.data.target;
}

export type TargetSource = 'flag' | 'env' | 'repo' | 'default' | 'local';

export type ResolvedTarget =
	// No config file and nothing selected: the AWS deployment as the
	// environment and discovery describe it. `domain` is --domain or
	// KOI_DOMAIN when given.
	| { kind: 'legacy'; configPath: string; domain: string | undefined }
	| {
			kind: 'target';
			name: string;
			source: TargetSource;
			target: Target;
			configPath: string;
	  };

export interface ResolveOptions {
	flags: TargetFlags;
	env: Env;
	// The checkout koi runs in, where .koi/target.yaml may be.
	checkoutDir: string;
	notice: (message: string) => void;
}

// Which target koi uses, and with what overrides. The target comes from
// --local, which needs no file, or --target, then KOI_TARGET, then the
// checkout's .koi/target.yaml, then the file's defaultTarget. With no config
// file and none of those, the legacy AWS path. A config file that selects
// nothing is an error, not legacy: the user has targets and must pick one.
// Then field overrides: command line flags, then the documented environment
// variables, over the target.
export async function resolveTarget(o: ResolveOptions): Promise<ResolvedTarget> {
	const { path, explicit } = configPath(o.flags, o.env);
	for (const v of AWS_ENV) if (o.env[v] !== undefined) nonEmpty(o.env[v], v);
	const domainOverride =
		o.flags.domain !== undefined
			? nonEmpty(o.flags.domain, '--domain')
			: o.env.KOI_DOMAIN !== undefined
				? nonEmpty(o.env.KOI_DOMAIN, 'KOI_DOMAIN')
				: undefined;
	if (o.flags.local) {
		if (o.flags.target !== undefined) {
			throw new Error('--local and --target both pick a target; pass one of them');
		}
		return {
			kind: 'target',
			name: 'local',
			source: 'local',
			target: withOverrides(localTarget(o.env), 'local', domainOverride, o.env),
			configPath: path,
		};
	}
	const loaded = await loadUserConfig(path, explicit, o.notice);

	let selected: { name: string; source: TargetSource } | undefined;
	if (o.flags.target !== undefined) {
		selected = { name: nonEmpty(o.flags.target, '--target'), source: 'flag' };
	} else if (o.env.KOI_TARGET !== undefined) {
		selected = { name: nonEmpty(o.env.KOI_TARGET, 'KOI_TARGET'), source: 'env' };
	} else {
		const alias = await loadRepoAlias(o.checkoutDir, o.notice);
		if (alias !== undefined) selected = { name: alias, source: 'repo' };
		else if (loaded?.config.defaultTarget !== undefined) {
			selected = { name: loaded.config.defaultTarget, source: 'default' };
		}
	}

	if (loaded === undefined) {
		if (selected !== undefined) {
			throw new Error(
				`${describeSelection(selected, o.checkoutDir)}, but there is no config file at ${path}. Run koi config import-aws --name ${selected.name} to write the existing AWS deployment there, or see docs/configuration.md`,
			);
		}
		return { kind: 'legacy', configPath: path, domain: domainOverride };
	}
	const names = Object.keys(loaded.config.targets);
	if (selected === undefined) {
		throw new Error(
			`${path} selects no target: it has ${names.length === 0 ? 'no targets' : `targets ${names.join(', ')}`} and no defaultTarget. Pass --target NAME, set KOI_TARGET, or add defaultTarget to the file`,
		);
	}
	// Own properties only: a target named constructor is not Object's.
	const target = Object.hasOwn(loaded.config.targets, selected.name)
		? loaded.config.targets[selected.name]
		: undefined;
	if (target === undefined) {
		throw new Error(
			`${describeSelection(selected, o.checkoutDir)}, but ${path} has ${names.length === 0 ? 'no targets' : `only ${names.join(', ')}`}`,
		);
	}
	return {
		kind: 'target',
		name: selected.name,
		source: selected.source,
		target: withOverrides(target, selected.name, domainOverride, o.env),
		configPath: path,
	};
}

function describeSelection(s: { name: string; source: TargetSource }, checkoutDir: string): string {
	const quoted = JSON.stringify(s.name);
	switch (s.source) {
		case 'flag':
			return `--target names ${quoted}`;
		case 'env':
			return `KOI_TARGET names ${quoted}`;
		case 'repo':
			return `${join(checkoutDir, REPO_TARGET_FILE)} names the target ${quoted}`;
		case 'default':
			return `defaultTarget names ${quoted}`;
		case 'local':
			return '--local names the built-in local target';
	}
}

// The target with the command line and environment applied: the domain to
// expect, and on an AWS target the AWS fields. The result is validated
// whole, so an override is held to the same rules as the file. An AWS
// target is one reached over SSM; an SSH target with EC2 power carries an
// aws section for wake alone, and the overrides are refused there too, so
// that they cannot point wake at another instance than the one the target
// connects to.
function withOverrides(target: Target, name: string, domain: string | undefined, env: Env): Target {
	const aws = { ...target.aws };
	const awsSet = AWS_ENV.filter((v) => env[v] !== undefined);
	if (awsSet.length > 0 && target.transport.kind !== 'aws-ssm') {
		throw new Error(
			`${awsSet.join(', ')} ${awsSet.length === 1 ? 'applies' : 'apply'} to AWS targets only, and ${JSON.stringify(name)} uses the ${target.transport.kind} transport`,
		);
	}
	if (env.KOI_AWS_PROFILE !== undefined)
		aws.profile = nonEmpty(env.KOI_AWS_PROFILE, 'KOI_AWS_PROFILE');
	if (env.KOI_AWS_REGION !== undefined) aws.region = nonEmpty(env.KOI_AWS_REGION, 'KOI_AWS_REGION');
	if (env.KOI_INSTANCE_ID !== undefined) {
		aws.instanceId = nonEmpty(env.KOI_INSTANCE_ID, 'KOI_INSTANCE_ID');
	}
	if (env.KOI_BUCKET !== undefined) aws.uploadsBucket = nonEmpty(env.KOI_BUCKET, 'KOI_BUCKET');
	const merged = {
		...target,
		...(domain !== undefined ? { domain } : {}),
		...(target.aws !== undefined ? { aws } : {}),
	};
	const parsed = TargetSchema.safeParse(merged);
	if (!parsed.success) {
		throw new Error(
			`target ${JSON.stringify(name)} with the overrides applied is not valid: ${issues(parsed.error)}`,
		);
	}
	return parsed.data;
}

// A value from a flag or the environment, which must say something: an empty
// one is a mistake, not a way to unset.
export function nonEmpty(value: string, what: string): string {
	if (value === '') throw new Error(`${what} is empty`);
	return value;
}

export function parseYaml(text: string, path: string): unknown {
	try {
		return Bun.YAML.parse(text);
	} catch (err) {
		throw new Error(`cannot read ${path}: ${err instanceof Error ? err.message : String(err)}`);
	}
}

export function issues(err: z.ZodError): string {
	return err.issues
		.map((i) => (i.path.length === 0 ? i.message : `${i.path.join('.')}: ${i.message}`))
		.join('; ');
}

export function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNotFound(err: unknown): boolean {
	return errorCode(err) === 'ENOENT';
}

function errorCode(err: unknown): unknown {
	return err instanceof Error && 'code' in err ? err.code : undefined;
}
