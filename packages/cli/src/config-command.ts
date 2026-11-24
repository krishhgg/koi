import { randomUUID } from 'node:crypto';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { ParsedCli } from './args.ts';
import {
	AWS_ENV,
	configPath,
	type Env,
	isRecord,
	loadUserConfig,
	resolveTarget,
	type Target,
	TargetNameSchema,
	TargetSchema,
} from './config.ts';
import { LOCK_WAIT_MS, withFileLock } from './lock.ts';
import type { Io } from './main.ts';
import { type Clients, clients, resolveSettings } from './transports/aws.ts';

// `koi config`: show the target koi would use, or write the existing AWS
// deployment into the user's file as a named target.

export interface ConfigCommandDeps {
	env: Env;
	checkoutDir: string;
	notice: (message: string) => void;
	awsClients?: ((profile: string, region: string) => Clients) | undefined;
	// How import-aws waits for another import's lock; Bun.sleep unless a test
	// passes its own.
	sleep?: ((ms: number) => Promise<void>) | undefined;
}

export async function configCommand(
	cli: ParsedCli,
	io: Io,
	deps: ConfigCommandDeps,
): Promise<number> {
	switch (cli.sub) {
		case 'show':
			return show(cli, io, deps);
		case 'import-aws':
			return importAws(cli, io, deps);
		default:
			throw new Error('koi config needs a subcommand: show or import-aws');
	}
}

// The resolved target, as koi up would use it. The file holds no secrets by
// design (references only), so the target prints whole; a field that ever
// carries one must be left out here.
async function show(cli: ParsedCli, io: Io, deps: ConfigCommandDeps): Promise<number> {
	const flags = { target: cli.target, config: cli.config, domain: cli.domain };
	const resolved = await resolveTarget({
		flags,
		env: deps.env,
		checkoutDir: deps.checkoutDir,
		notice: deps.notice,
	});
	if (resolved.kind === 'legacy') {
		const env = deps.env;
		const legacy = {
			profile: env.KOI_AWS_PROFILE ?? 'koi-cli',
			region: env.KOI_AWS_REGION ?? 'us-east-1',
			instanceId: env.KOI_INSTANCE_ID ?? null,
			uploadsBucket: env.KOI_BUCKET ?? null,
			domain: resolved.domain ?? null,
		};
		if (cli.json) {
			io.stdout(`${JSON.stringify({ file: resolved.configPath, target: null, legacy })}\n`);
			return 0;
		}
		const discovered = (what: string) => `(discovered at run time: ${what})`;
		io.stdout(
			[
				`no target: there is no config file at ${resolved.configPath}, so koi uses the AWS deployment as the environment and discovery describe it`,
				`  profile        ${legacy.profile}`,
				`  region         ${legacy.region}`,
				`  instanceId     ${legacy.instanceId ?? discovered('the one instance tagged koi:role=box, else Project=koi and Name=koi-box')}`,
				`  uploadsBucket  ${legacy.uploadsBucket ?? discovered('koi-uploads-<account id>')}`,
				`  domain         ${legacy.domain ?? discovered("the instance's Domain tag")}`,
				`run koi config import-aws --name NAME to write these to ${resolved.configPath}`,
				'',
			].join('\n'),
		);
		return 0;
	}
	if (cli.json) {
		io.stdout(
			`${JSON.stringify({
				file: resolved.configPath,
				target: resolved.name,
				source: resolved.source,
				settings: resolved.target,
			})}\n`,
		);
		return 0;
	}
	io.stdout(
		`target ${resolved.name} (from ${sourceWords(resolved.source)}) in ${resolved.configPath}:\n${indent(toYaml(resolved.target))}`,
	);
	return 0;
}

function sourceWords(source: 'flag' | 'env' | 'repo' | 'default'): string {
	return {
		flag: '--target',
		env: 'KOI_TARGET',
		repo: '.koi/target.yaml',
		default: 'defaultTarget',
	}[source];
}

// Writes the AWS deployment as a target: the same discovery as the legacy
// path (profile, region, one tagged instance, the bucket from the account,
// the domain from --domain, KOI_DOMAIN or the instance's Domain tag), then
// the per-user file, replaced in one step with mode 0600 in a 0700
// directory. An existing target of the name stays unless --replace. The
// file is read once before discovery, so a bad file or a taken name fails
// before AWS is asked, and again under the lock before it is written, so
// an import that ran in between is kept. The lock is a directory beside the
// file; see withConfigLock.
async function importAws(cli: ParsedCli, io: Io, deps: ConfigCommandDeps): Promise<number> {
	const name = TargetNameSchema.parse(cli.name);
	const { path } = configPath({ config: cli.config }, deps.env);
	for (const v of AWS_ENV) {
		if (deps.env[v] === '') throw new Error(`${v} is empty`);
	}
	if (cli.domain === '') throw new Error('--domain is empty');
	const env = cli.domain === undefined ? deps.env : { ...deps.env, KOI_DOMAIN: cli.domain };
	const taken = (loaded: Awaited<ReturnType<typeof loadUserConfig>>) =>
		loaded !== undefined && Object.hasOwn(loaded.config.targets, name) && !cli.replace;
	const alreadyThere = () =>
		new Error(
			`${path} already has a target ${JSON.stringify(name)}; pass --replace to overwrite it, or choose another --name`,
		);
	// A file that is already there must be valid before it is rewritten,
	// and must not already have the target.
	if (taken(await loadUserConfig(path, false, deps.notice))) throw alreadyThere();
	const { settings } = await resolveSettings(env, deps.awsClients ?? clients);
	const target: Target = TargetSchema.parse({
		domain: settings.domain,
		transport: { kind: 'aws-ssm' },
		aws: {
			profile: settings.profile,
			region: settings.region,
			instanceId: settings.instanceId,
			uploadsBucket: settings.bucket,
		},
		power: { kind: 'ec2' },
	});
	// What goes in the file: the fields as resolved, without the defaults
	// the schema fills in (address), so the file stays as short as the
	// example in docs/configuration.md.
	const written = {
		domain: target.domain,
		transport: { kind: 'aws-ssm' },
		aws: target.aws,
		power: { kind: 'ec2' },
	};
	return withConfigLock(path, deps.sleep ?? Bun.sleep, async () => {
		// Read again under the lock: an import that ran in between must be
		// kept. The mode warning was given by the first read.
		const loaded = await loadUserConfig(path, false, () => {});
		if (taken(loaded)) throw alreadyThere();
		const raw: Record<string, unknown> = loaded?.raw ?? { version: 1, targets: {} };
		const targets = isRecord(raw.targets) ? raw.targets : {};
		const replaced = Object.hasOwn(targets, name);
		targets[name] = written;
		raw.targets = targets;
		const madeDefault = raw.defaultTarget === undefined;
		if (madeDefault) raw.defaultTarget = name;
		await writePrivate(path, toYaml(raw));
		if (cli.json) {
			io.stdout(
				`${JSON.stringify({ file: path, target: name, replaced, default: madeDefault, settings: written })}\n`,
			);
			return 0;
		}
		io.stdout(
			`${replaced ? 'replaced' : 'wrote'} target ${name} in ${path}${madeDefault ? ' and made it the default' : ''}:\n${indent(toYaml(written))}`,
		);
		return 0;
	});
}

// How long an import waits for another to release the lock before it gives
// up, as the sum of its sleeps between looks.
export const CONFIG_LOCK_WAIT_MS = LOCK_WAIT_MS;

// Runs `task` while holding <path>.lock (lock.ts), so that two imports
// cannot both read the file and write it back, each without the other's
// target.
export function withConfigLock<T>(
	path: string,
	sleep: (ms: number) => Promise<void>,
	task: () => Promise<T>,
): Promise<T> {
	return withFileLock(path, 'koi config', sleep, task);
}

// Replaces the file in one step: the new text goes to a temporary file
// beside it, mode 0600, which is then renamed over it, so a reader sees the
// old file or the new one, never half of one. The directory is made with
// mode 0700 when it does not exist.
export async function writePrivate(
	path: string,
	text: string,
	// Looks at the written file before it takes the place of `path`. If it
	// throws, the old file stays as it was.
	check?: (temp: string) => Promise<void>,
): Promise<void> {
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });
	const temp = `${path}.${randomUUID()}.tmp`;
	try {
		await writeFile(temp, text, { mode: 0o600 });
		await check?.(temp);
		await rename(temp, path);
	} catch (err) {
		await rm(temp, { force: true });
		throw err;
	}
}

// YAML as Bun writes it, without the space it leaves after a mapping key.
export function toYaml(value: unknown): string {
	const text = Bun.YAML.stringify(value, null, 2).replace(/: $/gm, ':');
	return text.endsWith('\n') ? text : `${text}\n`;
}

function indent(text: string): string {
	return text
		.split('\n')
		.map((line) => (line === '' ? line : `  ${line}`))
		.join('\n');
}
