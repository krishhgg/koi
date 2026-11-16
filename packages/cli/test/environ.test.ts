import { describe, expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	AUTOLOAD_FILES,
	autoloadFilesIn,
	isCompiledBinary,
	parseEnviron,
	refuseAutoloadedCheckout,
	TRUST_CHECKOUT,
	trustsCheckout,
} from '../src/environ.ts';

describe('isCompiledBinary', () => {
	test("tells a compiled executable's virtual root from a real path", () => {
		expect(isCompiledBinary('/$bunfs/root/koi')).toBe(true);
		expect(isCompiledBinary('B:\\~BUN\\root\\koi.exe')).toBe(true);
		expect(isCompiledBinary('/home/u/koi/packages/cli/src/main.ts')).toBe(false);
		expect(isCompiledBinary('C:\\Users\\u\\koi\\packages\\cli\\src\\main.ts')).toBe(false);
		expect(isCompiledBinary('/home/u/$bunfs/main.ts')).toBe(false);
		// This test runs from source.
		expect(isCompiledBinary()).toBe(false);
	});

	// The flags koi is built with, read from the CLI's build script so the
	// probe is built as koi is. If the script loses a flag, the probe loses
	// it too and the test below fails. The script is "bun build <flags>
	// --outfile <path> <entry>"; the output and the entry are the probe's own.
	async function buildFlags(): Promise<string[]> {
		const manifest = (await Bun.file(join(import.meta.dir, '../package.json')).json()) as {
			scripts: { build: string };
		};
		const words = manifest.scripts.build.trim().split(/\s+/);
		expect(words.slice(0, 2)).toEqual(['bun', 'build']);
		expect(words.at(-1)).toBe('./src/main.ts');
		const flags = words
			.slice(2, -1)
			.filter((word, i, all) => word !== '--outfile' && all[i - 1] !== '--outfile');
		expect(flags.every((flag) => flag.startsWith('--'))).toBe(true);
		return flags;
	}

	// The virtual root is how Bun lays out a compiled executable, not a
	// documented promise, so a real compiled probe checks it for the Bun in
	// use. The probe imports this module and reports what it sees from a
	// directory with a .env and a bunfig preload that both set the probe
	// variable. The binary (built like koi) loads neither, so a build script
	// that lost either flag fails here.
	test('holds for a binary compiled by the Bun in use, which loads no dotenv file and no bunfig', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-compiled-'));
		try {
			const probe = join(dir, 'probe.ts');
			await writeFile(
				probe,
				[
					`import { isCompiledBinary, refuseAutoloadedCheckout } from ${JSON.stringify(join(import.meta.dir, '../src/environ.ts'))};`,
					'await refuseAutoloadedCheckout({ cwd: process.cwd() });',
					'console.log(JSON.stringify({ compiled: isCompiledBinary(), main: Bun.main, probe: process.env.KOI_PROBE ?? null }));',
				].join('\n'),
			);
			const built = Bun.spawnSync(
				[
					process.execPath,
					'build',
					...(await buildFlags()),
					'--outfile',
					join(dir, 'probe'),
					probe,
				],
				{ cwd: dir },
			);
			expect(built.exitCode).toBe(0);
			const checkout = join(dir, 'checkout');
			await Bun.write(join(checkout, '.env'), 'KOI_PROBE=from-dotenv\n');
			await Bun.write(join(checkout, 'bunfig.toml'), 'preload = ["./preload.ts"]\n');
			await Bun.write(join(checkout, 'preload.ts'), 'process.env.KOI_PROBE = "from-bunfig";\n');
			const ran = Bun.spawnSync([join(dir, 'probe')], {
				cwd: checkout,
				env: { PATH: process.env.PATH ?? '' },
			});
			expect(ran.stderr.toString()).toBe('');
			expect(ran.exitCode).toBe(0);
			const seen = JSON.parse(ran.stdout.toString());
			expect(seen).toEqual({
				compiled: true,
				main: expect.stringMatching(/^\/\$bunfs\//),
				probe: null,
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	}, 30_000);
});

describe('autoloadFilesIn', () => {
	test('lists every file Bun would load, for any NODE_ENV, and nothing else', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
		expect(await autoloadFilesIn(dir)).toEqual([]);
		await writeFile(join(dir, '.env.example'), 'KOI_CONFIG=~/koi.yaml\n');
		await writeFile(join(dir, '.envrc'), 'export KOI_TARGET=x\n');
		await writeFile(join(dir, 'package.json'), '{}\n');
		expect(await autoloadFilesIn(dir)).toEqual([]);
		for (const name of AUTOLOAD_FILES) await writeFile(join(dir, name), '');
		expect(await autoloadFilesIn(dir)).toEqual([...AUTOLOAD_FILES]);
		expect(AUTOLOAD_FILES).toContain('.env.test.local');
		expect(AUTOLOAD_FILES).toContain('bunfig.toml');
	});
});

describe('parseEnviron', () => {
	test('reads NUL-separated KEY=VALUE entries, the first of a name winning', () => {
		expect(
			parseEnviron('HOME=/home/u\0KOI_TARGET=a=b\0EMPTY=\0junk\0=nokey\0KOI_TARGET=c\0'),
		).toEqual({
			HOME: '/home/u',
			KOI_TARGET: 'a=b',
			EMPTY: '',
		});
		expect(parseEnviron('')).toEqual({});
	});
});

describe('trustsCheckout', () => {
	test("on Linux, counts the override only in the parent's environment", async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-environ-'));
		const environ = join(dir, 'environ');
		await writeFile(environ, `HOME=/home/u\0${TRUST_CHECKOUT}=1\0`);
		const loaded = { HOME: '/home/u', [TRUST_CHECKOUT]: '1' };
		expect(await trustsCheckout({ cwd: dir, platform: 'linux', environ, loaded })).toBe(true);
		// A .env that sets it reaches process.env, never /proc/self/environ.
		await writeFile(environ, 'HOME=/home/u\0');
		expect(await trustsCheckout({ cwd: dir, platform: 'linux', environ, loaded })).toBe(false);
		// No record of the parent's environment: no override.
		const missing = join(dir, 'no-such-environ');
		expect(await trustsCheckout({ cwd: dir, platform: 'linux', environ: missing, loaded })).toBe(
			false,
		);
		// Only the value 1 counts.
		await writeFile(environ, `${TRUST_CHECKOUT}=yes\0`);
		expect(await trustsCheckout({ cwd: dir, platform: 'linux', environ, loaded })).toBe(false);
	});

	test('elsewhere, takes the override from the loaded environment', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-environ-'));
		const missing = join(dir, 'no-such-environ');
		for (const platform of ['darwin', 'win32', 'freebsd']) {
			expect(
				await trustsCheckout({
					cwd: dir,
					platform,
					environ: missing,
					loaded: { [TRUST_CHECKOUT]: '1' },
				}),
			).toBe(true);
			expect(await trustsCheckout({ cwd: dir, platform, environ: missing, loaded: {} })).toBe(
				false,
			);
			expect(
				await trustsCheckout({
					cwd: dir,
					platform,
					environ: missing,
					loaded: { [TRUST_CHECKOUT]: '' },
				}),
			).toBe(false);
		}
	});
});

describe('refuseAutoloadedCheckout', () => {
	const fromSource = (cwd: string, overrides: Partial<Parameters<typeof trustsCheckout>[0]> = {}) =>
		refuseAutoloadedCheckout({
			cwd,
			compiled: false,
			platform: 'linux',
			environ: join(cwd, 'no-such-environ'),
			loaded: {},
			...overrides,
		});

	test('from source, refuses a directory with any file Bun autoloads', async () => {
		for (const name of AUTOLOAD_FILES) {
			const dir = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
			await writeFile(join(dir, name), name === 'bunfig.toml' ? '' : 'KOI_TARGET=evil\n');
			const err = await fromSource(dir).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(Error);
			const message = (err as Error).message;
			expect(message).toBe(
				`koi was started from source in a checkout that has dotenv or bunfig files: ${name} in ${dir}. Bun loads these files before koi runs, so they already took effect before koi could check them, and koi cannot tell what they changed. Run the compiled koi binary instead (bun run --filter @koi/cli build writes packages/cli/dist/koi), which loads neither, or run koi from a directory without such files. To run from source in a checkout you trust, export KOI_TRUST_CHECKOUT=1 in the shell before starting koi.`,
			);
		}
	});

	test('names every such file, and does not read them', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
		// Not a dotenv file at all; existence is what counts.
		await writeFile(join(dir, '.env'), Buffer.from([0xff, 0xfe, 0x00]));
		await writeFile(join(dir, '.env.test.local'), 'NODE_ENV: test\r');
		await writeFile(join(dir, 'bunfig.toml'), 'preload = ["./x.ts"]\n');
		await expect(fromSource(dir)).rejects.toThrow(
			`dotenv or bunfig files: .env, .env.test.local, bunfig.toml in ${dir}.`,
		);
	});

	test('with the override, goes on; from a dotenv file alone, on Linux, it does not', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
		const environ = join(dir, 'environ');
		for (const name of AUTOLOAD_FILES) {
			await writeFile(join(dir, name), `${TRUST_CHECKOUT}=1\n`);
			await writeFile(environ, `${TRUST_CHECKOUT}=1\0`);
			await fromSource(dir, { environ, loaded: { [TRUST_CHECKOUT]: '1' } });
			// The same value, loaded from the file: process.env has it and the
			// parent's environment does not.
			await writeFile(environ, 'HOME=/home/u\0');
			await expect(fromSource(dir, { environ, loaded: { [TRUST_CHECKOUT]: '1' } })).rejects.toThrow(
				'koi was started from source',
			);
			// Off Linux, process.env is all there is.
			await fromSource(dir, { environ, platform: 'darwin', loaded: { [TRUST_CHECKOUT]: '1' } });
			await expect(fromSource(dir, { environ, platform: 'darwin', loaded: {} })).rejects.toThrow(
				'koi was started from source',
			);
			await rm(join(dir, name));
		}
	});

	test('a directory with only .env.example, or nothing, is fine', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
		await fromSource(dir);
		await writeFile(join(dir, '.env.example'), 'KOI_CONFIG=./injected.yaml\n');
		await writeFile(join(dir, '.koi'), '');
		await fromSource(dir);
		// A directory that is not there has nothing to load.
		await fromSource(join(dir, 'missing'));
	});

	test('the compiled binary does nothing: it loaded no such file', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-checkout-'));
		await writeFile(join(dir, '.env'), 'KOI_TARGET=evil\n');
		await writeFile(join(dir, 'bunfig.toml'), 'preload = ["./x.ts"]\n');
		await fromSource(dir, { compiled: true });
	});
});
