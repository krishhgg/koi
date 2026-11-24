import { parseArgs } from 'node:util';
import {
	LEASE_MAX_SECONDS,
	LeaseHolderSchema,
	LeaseIdSchema,
	LOG_TAIL_MAX_LINES,
	PreviewLabelSchema,
	PrNumberSchema,
	SlugSchema,
	VerifyIdSchema,
} from '@koi/shared';
import { z } from 'zod';
import { TargetNameSchema } from './config.ts';

export const COMMANDS = [
	'up',
	'list',
	'logs',
	'lease',
	'release',
	'down',
	'verify',
	'config',
	'target',
	'version',
	'help',
] as const;
export type Command = (typeof COMMANDS)[number];

export const VERIFY_COMMANDS = ['plan', 'run', 'status', 'evidence', 'cancel'] as const;
export type VerifyCommand = (typeof VERIFY_COMMANDS)[number];

// The profile koi verify plans and runs when --profile is not given.
export const DEFAULT_PROFILE = 'pr';

// What koi verify does: plan and run take a preview name and a profile;
// status, evidence and cancel take a run id; evidence takes --out.
export interface VerifyArgs {
	command: VerifyCommand;
	target: string;
	profile: string;
	out: string | undefined;
}
export const CONFIG_SUBCOMMANDS = ['show', 'import-aws'] as const;
export type ConfigSubcommand = (typeof CONFIG_SUBCOMMANDS)[number];

export const TARGET_SUBCOMMANDS = ['show', 'trust'] as const;
export type TargetSubcommand = (typeof TARGET_SUBCOMMANDS)[number];

// A host key fingerprint as ssh-keygen -l prints it: SHA256: and the digest
// in base64 without padding.
export const FingerprintSchema = z
	.string()
	.regex(/^SHA256:[A-Za-z0-9+/]{43}$/, 'a SHA256: fingerprint as ssh-keygen -l prints it');

// The most `koi lease --minutes` takes: koid's cap on a lease.
export const LEASE_MAX_MINUTES = LEASE_MAX_SECONDS / 60;

export interface ParsedCli {
	command: Command;
	label: string | undefined;
	// With release: the lease to end.
	leaseId: string | undefined;
	json: boolean;
	pr: number | undefined;
	comment: boolean;
	// With pr: build the pull request's head as pushed, not GitHub's merge of
	// it into its base.
	head: boolean;
	build: boolean;
	tail: number;
	// Which target and config file (config.ts), and the domain to expect of
	// the host instead of the target's own. --domain never changes which
	// host is used.
	target: string | undefined;
	config: string | undefined;
	domain: string | undefined;
	// --local: koid on this machine, with no config file (config.ts,
	// localTarget).
	local: boolean;
	// With config or target: the subcommand. `name` is import-aws's --name,
	// or the target named on the command line of a target command.
	sub: ConfigSubcommand | TargetSubcommand | undefined;
	name: string | undefined;
	replace: boolean;
	// With target trust: the host key's fingerprint, from the host's operator.
	fingerprint: string | undefined;
	// With lease: how long to hold the preview, and who holds it (undefined
	// for the local user and host).
	minutes: number | undefined;
	holder: string | undefined;
	// With down: remove the preview even while a lease holds it.
	force: boolean;
	// With verify: the subcommand and its arguments.
	verify: VerifyArgs | undefined;
}

export function parseCli(argv: string[]): ParsedCli {
	const { values, positionals } = parseArgs({
		args: argv,
		allowPositionals: true,
		strict: true,
		options: {
			json: { type: 'boolean', default: false },
			pr: { type: 'string' },
			comment: { type: 'boolean', default: false },
			head: { type: 'boolean', default: false },
			build: { type: 'boolean', default: false },
			tail: { type: 'string' },
			target: { type: 'string' },
			config: { type: 'string' },
			domain: { type: 'string' },
			local: { type: 'boolean', default: false },
			name: { type: 'string' },
			replace: { type: 'boolean', default: false },
			fingerprint: { type: 'string' },
			minutes: { type: 'string' },
			holder: { type: 'string' },
			force: { type: 'boolean', default: false },
			profile: { type: 'string' },
			out: { type: 'string' },
		},
	});
	const [first, second, third, ...rest] = positionals;
	const command: Command = first === undefined ? 'help' : toCommand(first);
	// A target command names its target after the subcommand, and release
	// names the lease after the preview; nothing takes a fourth word.
	if (rest.length > 0) throw new Error(`unexpected arguments: ${rest.join(' ')}`);

	let verify: VerifyArgs | undefined;
	if (command === 'verify') {
		verify = parseVerify(second, third, values.profile, values.out);
	} else {
		if (values.profile !== undefined)
			throw new Error('--profile is for verify plan and verify run');
		if (values.out !== undefined) throw new Error('--out is for verify evidence');
	}

	let label: string | undefined;
	let sub: ConfigSubcommand | TargetSubcommand | undefined;
	let name = values.name;
	if (command === 'logs' || command === 'down' || command === 'lease' || command === 'release') {
		if (second === undefined) throw new Error(`${command} needs a preview name`);
		const parsed = PreviewLabelSchema.safeParse(second);
		if (!parsed.success) throw new Error(`${JSON.stringify(second)} is not a preview name`);
		label = parsed.data;
	} else if (command === 'config') {
		sub = CONFIG_SUBCOMMANDS.find((c) => c === second);
		if (sub === undefined) {
			throw new Error(`config needs a subcommand: ${CONFIG_SUBCOMMANDS.join(' or ')}`);
		}
	} else if (command === 'target') {
		sub = TARGET_SUBCOMMANDS.find((c) => c === second);
		if (sub === undefined) {
			throw new Error(`target needs a subcommand: ${TARGET_SUBCOMMANDS.join(' or ')}`);
		}
		const given = third;
		if (given === undefined) throw new Error(`target ${sub} needs a target name`);
		if (!TargetNameSchema.safeParse(given).success) {
			throw new Error(
				`${JSON.stringify(given)} is not a target name (lowercase letters, digits and dashes)`,
			);
		}
		name = given;
	} else if (second !== undefined && command !== 'verify') {
		throw new Error(`${command} takes no arguments`);
	}

	let leaseId: string | undefined;
	if (command === 'release') {
		if (third === undefined) throw new Error('release needs a preview name and a lease id');
		const parsed = LeaseIdSchema.safeParse(third);
		if (!parsed.success) throw new Error(`${JSON.stringify(third)} is not a lease id`);
		leaseId = parsed.data;
	} else if (third !== undefined && command !== 'verify' && command !== 'target') {
		throw new Error(`unexpected arguments: ${third}`);
	}

	let pr: number | undefined;
	if (values.pr !== undefined) {
		// Plain digits, at most nine, so the string converts to Number exactly.
		const parsed = /^[1-9][0-9]{0,8}$/.test(values.pr)
			? PrNumberSchema.safeParse(Number(values.pr))
			: undefined;
		if (!parsed?.success) {
			throw new Error(
				`--pr expects a pull request number (1 to 9 digits), got ${JSON.stringify(values.pr)}`,
			);
		}
		pr = parsed.data;
	}
	if (values.comment && pr === undefined) throw new Error('--comment needs --pr');
	if (values.head && pr === undefined) throw new Error('--head needs --pr');

	let tail = 200;
	if (values.tail !== undefined) {
		// No more than koid gives, so that koi never shows fewer lines than asked
		// without saying so.
		if (!/^[1-9][0-9]{0,8}$/.test(values.tail) || Number(values.tail) > LOG_TAIL_MAX_LINES) {
			throw new Error(`--tail expects 1 to ${LOG_TAIL_MAX_LINES}`);
		}
		tail = Number(values.tail);
	}

	// Selectors are words, never empty: an empty one would mean "unset", and
	// koi must not guess which.
	for (const [flag, value] of [
		['--target', values.target],
		['--config', values.config],
		['--domain', values.domain],
		['--name', values.name],
		['--fingerprint', values.fingerprint],
	] as const) {
		if (value === '') throw new Error(`${flag} needs a value`);
	}
	if (values.local) {
		if (values.target !== undefined) {
			throw new Error('--local and --target both pick a target; pass one of them');
		}
		if (command === 'target' || sub === 'import-aws') {
			throw new Error(`--local does not go with ${command} ${sub}`);
		}
	}
	if (values.name !== undefined && sub !== 'import-aws') {
		throw new Error('--name goes with config import-aws');
	}
	if (values.replace && sub !== 'import-aws')
		throw new Error('--replace goes with config import-aws');
	if (values.fingerprint !== undefined && !(command === 'target' && sub === 'trust')) {
		throw new Error('--fingerprint goes with target trust');
	}
	if (command === 'target' && sub === 'trust') {
		if (values.fingerprint === undefined) {
			throw new Error('target trust needs --fingerprint SHA256:..., the host key fingerprint');
		}
		if (!FingerprintSchema.safeParse(values.fingerprint).success) {
			throw new Error(
				`--fingerprint expects SHA256: followed by 43 base64 characters, as ssh-keygen -l prints it, got ${JSON.stringify(values.fingerprint)}`,
			);
		}
	}
	if (sub === 'import-aws') {
		if (values.name === undefined) throw new Error('config import-aws needs --name NAME');
		if (!TargetNameSchema.safeParse(values.name).success) {
			throw new Error(
				`--name expects a target name (lowercase letters, digits and dashes), got ${JSON.stringify(values.name)}`,
			);
		}
	}
	let minutes: number | undefined;
	if (values.minutes !== undefined) {
		if (!/^[1-9][0-9]{0,8}$/.test(values.minutes) || Number(values.minutes) > LEASE_MAX_MINUTES) {
			throw new Error(`--minutes expects 1 to ${LEASE_MAX_MINUTES}`);
		}
		minutes = Number(values.minutes);
	}
	if (command === 'lease' && minutes === undefined) throw new Error('lease needs --minutes');
	if (values.holder !== undefined && !LeaseHolderSchema.safeParse(values.holder).success) {
		throw new Error('--holder expects 1 to 200 characters with no control characters');
	}

	return {
		command,
		label,
		leaseId,
		json: values.json,
		pr,
		comment: values.comment,
		head: values.head,
		build: values.build,
		tail,
		target: values.target,
		config: values.config,
		domain: values.domain,
		local: values.local,
		sub,
		name,
		replace: values.replace,
		fingerprint: values.fingerprint,
		minutes,
		holder: values.holder,
		force: values.force,
		verify,
	};
}

function parseVerify(
	sub: string | undefined,
	target: string | undefined,
	profile: string | undefined,
	out: string | undefined,
): VerifyArgs {
	const command = VERIFY_COMMANDS.find((c) => c === sub);
	if (command === undefined) {
		throw new Error(
			`verify needs one of ${VERIFY_COMMANDS.join(', ')}${sub === undefined ? '' : `, not ${JSON.stringify(sub)}`}`,
		);
	}
	if (command === 'plan' || command === 'run') {
		if (target === undefined) throw new Error(`verify ${command} needs a preview name`);
		if (!PreviewLabelSchema.safeParse(target).success) {
			throw new Error(`${JSON.stringify(target)} is not a preview name`);
		}
		if (out !== undefined) throw new Error('--out is for verify evidence');
	} else {
		if (target === undefined) throw new Error(`verify ${command} needs a run id`);
		if (!VerifyIdSchema.safeParse(target).success) {
			throw new Error(`${JSON.stringify(target)} is not a run id`);
		}
		if (profile !== undefined) throw new Error('--profile is for verify plan and verify run');
		if (command === 'evidence' && (out === undefined || out === '')) {
			throw new Error('verify evidence needs --out DIR');
		}
		if (command !== 'evidence' && out !== undefined)
			throw new Error('--out is for verify evidence');
	}
	const name = profile ?? DEFAULT_PROFILE;
	if (!SlugSchema.safeParse(name).success) {
		throw new Error(`${JSON.stringify(name)} is not a profile name`);
	}
	return { command, target, profile: name, out };
}

function toCommand(word: string): Command {
	const found = COMMANDS.find((c) => c === word);
	if (found === undefined) {
		throw new Error(
			`unknown command ${JSON.stringify(word)}; expected one of ${COMMANDS.join(', ')}`,
		);
	}
	return found;
}

export const USAGE = `koi: one-command preview environments

usage: koi <command> [options]

commands:
  up              build the working tree (or --pr N) and run it as a preview
  list            list previews on the box
  logs NAME       a preview's container log (--build for its last build log)
  down NAME       remove a preview
  config show     print the target koi would use, and where it comes from
  config import-aws --name NAME [--domain D] [--replace]
                  write the existing AWS deployment to the config file as a target
  target show NAME
                  print a target's endpoint and, for an SSH target, the host key
                  koi trusts
  target trust NAME --fingerprint SHA256:...
                  trust an SSH target's host key, once its fingerprint matches
  lease NAME      hold a preview so no build replaces it (--minutes N)
  release NAME LEASE
                  end a lease
  down NAME       remove a preview (--force while a lease holds it)
  verify plan NAME
                  plan a verification of the preview: the points taken and
                  why, the ones blocked and why, the changed files no point
                  covers (--profile NAME, default pr)
  verify run NAME run a verification: plan, lease, record, judge; exit 0 when
                  it passed, 1 when it failed or is incomplete
  verify status RUN
                  a run's state, outcome and points
  verify evidence RUN --out DIR
                  export a finished run's manifest, events and artifacts
  verify cancel RUN
                  stop a run
  version         print the version

options:
  --pr N          preview pull request N instead of the working tree: GitHub's
                  merge of it into its base branch, as merging it now would give,
                  or koi's own merge when GitHub's stays out of date
  --head          with --pr: build the pull request's head as pushed instead
  --comment       with --pr: post or update the preview comment on the pull request
  --build         with logs: show the build log
  --tail N        with logs: how many lines, at most ${LOG_TAIL_MAX_LINES} (default 200)
  --target NAME   the target in the config file to use (then KOI_TARGET, the
                  checkout's .koi/target.yaml, the file's defaultTarget)
  --config PATH   the config file (then KOI_CONFIG, then
                  $XDG_CONFIG_HOME/koi/config.yaml or ~/.config/koi/config.yaml)
  --domain D      the domain the host must serve previews under, instead of the
                  target's; never changes which host is used
  --local         use koid on this machine: its control socket (KOID_CONTROL_SOCKET,
                  else /run/koi/control.sock) and previews under koi.test, with no
                  config file
  --fingerprint F with target trust: the host key's SHA256 fingerprint, as the
                  host's operator read it with ssh-keygen -l
  --minutes N     with lease: how long to hold the preview, at most ${LEASE_MAX_MINUTES}
  --holder TEXT   with lease: who holds it (default: your user and host)
  --force         with down: remove the preview even while a lease holds it
  --profile NAME  with verify plan and run: the profile in .koi/verify.yaml (default pr)
  --out DIR       with verify evidence: an empty or new directory to write into
  --json          machine-readable output on stdout; progress stays on stderr

environment:
  KOI_TARGET and KOI_CONFIG, as --target and --config. KOI_DOMAIN as --domain.
  KOID_CONTROL_SOCKET: with --local, where koid's control socket is.
  On an AWS target, or without a config file: KOI_AWS_PROFILE (default koi-cli),
  KOI_AWS_REGION (default us-east-1), KOI_INSTANCE_ID and KOI_BUCKET. Without a
  config file the rest is discovered: the box by its tags, the domain from the
  box's Domain tag, the bucket from the account. See docs/configuration.md.
`;
