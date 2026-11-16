import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { Env } from './config.ts';

// Whether koi may run in the directory it was started in.
//
// Bun loads the dotenv files of the current directory into process.env, and
// runs the preload scripts of its bunfig.toml, before any of this code runs.
// A checkout with `KOI_CONFIG=./injected.yaml` in its .env would choose koi's
// config file, and with it the host, bucket and credential profile, which is
// what the alias-only rule forbids; a preload script could do anything. koi
// cannot undo either once it is running, and filtering process.env after the
// fact misses Bun's other dotenv syntaxes, drops `bun --env-file` values and
// does nothing about a preload. So koi does not try.
//
// The compiled koi binary is built with --no-compile-autoload-dotenv and
// --no-compile-autoload-bunfig and loads neither file; it is the supported
// way to run koi in any checkout. Run from source, koi refuses to go on when
// the directory has a file Bun would have loaded. Existence is enough: the
// file has already run, and reading it would prove nothing.

export const PROC_ENVIRON = '/proc/self/environ';

// Set to 1 in the shell to run koi from source in a checkout anyway.
export const TRUST_CHECKOUT = 'KOI_TRUST_CHECKOUT';

// Every file Bun autoloads from the current directory, whatever NODE_ENV
// says: the dotenv files for each mode and their .local variants, and the
// bunfig. The list does not depend on NODE_ENV because a .env.local can set
// NODE_ENV itself, and a check that read it would skip the file that set it.
export const AUTOLOAD_FILES = [
	'.env',
	'.env.local',
	'.env.development',
	'.env.development.local',
	'.env.production',
	'.env.production.local',
	'.env.test',
	'.env.test.local',
	'bunfig.toml',
] as const;

// Whether this koi is a Bun compiled executable. A compiled binary's modules
// live under a virtual root, /$bunfs/ on Unix and B:\~BUN\ on Windows, and
// Bun.main is the entry module's path there. Run from source, Bun.main is a
// real path.
export function isCompiledBinary(main: string = Bun.main): boolean {
	return main.startsWith('/$bunfs/') || /^[A-Za-z]:\\~BUN\\/.test(main);
}

// The autoload files that exist in `dir`, in AUTOLOAD_FILES order. A file
// that cannot be seen could not have been loaded either.
export async function autoloadFilesIn(dir: string): Promise<string[]> {
	const found = await Promise.all(
		AUTOLOAD_FILES.map(async (name) => {
			try {
				await stat(join(dir, name));
				return name;
			} catch {
				return undefined;
			}
		}),
	);
	return found.filter((name): name is (typeof AUTOLOAD_FILES)[number] => name !== undefined);
}

// The variables in a NUL-separated environment block, as /proc/self/environ
// holds them. The first of a repeated name wins, as getenv has it.
export function parseEnviron(text: string): Env {
	const env: Env = {};
	for (const entry of text.split('\0')) {
		const eq = entry.indexOf('=');
		if (eq <= 0) continue;
		const name = entry.slice(0, eq);
		if (!Object.hasOwn(env, name)) env[name] = entry.slice(eq + 1);
	}
	return env;
}

export interface CheckoutInput {
	// The directory Bun autoloaded from: the current directory at start.
	cwd: string;
	// Whether koi is the compiled binary; isCompiledBinary() unless a test
	// says otherwise.
	compiled?: boolean | undefined;
	// process.env as the runtime filled it.
	loaded?: Env | undefined;
	// process.platform unless a test says otherwise.
	platform?: string | undefined;
	// The file with the environment the parent passed; tests point elsewhere.
	environ?: string | undefined;
}

// Whether the shell that started koi set KOI_TRUST_CHECKOUT=1. On Linux the
// kernel keeps the environment the parent passed in /proc/self/environ, where
// a dotenv file's additions never appear, so only that file counts: a .env
// cannot grant the override to itself. Elsewhere there is no such record and
// process.env is all there is; docs/configuration.md says so.
export async function trustsCheckout(i: CheckoutInput): Promise<boolean> {
	const platform = i.platform ?? process.platform;
	if (platform !== 'linux') return (i.loaded ?? process.env)[TRUST_CHECKOUT] === '1';
	let text: string;
	try {
		text = await readFile(i.environ ?? PROC_ENVIRON, 'utf8');
	} catch {
		return false;
	}
	return parseEnviron(text)[TRUST_CHECKOUT] === '1';
}

// Throws when koi runs from source in a directory with a file Bun autoloads,
// unless the shell set KOI_TRUST_CHECKOUT=1. Does nothing in the compiled
// binary, which loads no such file.
export async function refuseAutoloadedCheckout(i: CheckoutInput): Promise<void> {
	if (i.compiled ?? isCompiledBinary()) return;
	const files = await autoloadFilesIn(i.cwd);
	if (files.length === 0) return;
	if (await trustsCheckout(i)) return;
	throw new Error(refusalMessage(i.cwd, files));
}

export function refusalMessage(cwd: string, files: readonly string[]): string {
	return [
		`koi was started from source in a checkout that has dotenv or bunfig files: ${files.join(', ')} in ${cwd}.`,
		'Bun loads these files before koi runs, so they already took effect before koi could check them, and koi cannot tell what they changed.',
		'Run the compiled koi binary instead (bun run --filter @koi/cli build writes packages/cli/dist/koi), which loads neither, or run koi from a directory without such files.',
		`To run from source in a checkout you trust, export ${TRUST_CHECKOUT}=1 in the shell before starting koi.`,
	].join(' ');
}
