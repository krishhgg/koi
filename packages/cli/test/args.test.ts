import { describe, expect, test } from 'bun:test';
import { parseCli } from '../src/args.ts';

describe('parseCli', () => {
	test('defaults to help with no arguments', () => {
		expect(parseCli([]).command).toBe('help');
	});

	test('parses a command with flags', () => {
		const cli = parseCli(['up', '--pr', '2518', '--comment', '--json']);
		expect(cli.command).toBe('up');
		expect(cli.pr).toBe(2518);
		expect(cli.comment).toBe(true);
		expect(cli.json).toBe(true);
	});

	test('takes a preview name for logs and down, and validates it', () => {
		expect(parseCli(['logs', 'storefront-pr-2518']).label).toBe('storefront-pr-2518');
		expect(parseCli(['down', 'hello']).label).toBe('hello');
		expect(() => parseCli(['logs'])).toThrow(/needs a preview name/);
		expect(() => parseCli(['down', 'Bad_Name'])).toThrow(/not a preview name/);
		expect(() => parseCli(['list', 'extra'])).toThrow(/takes no arguments/);
		expect(() => parseCli(['logs', 'a', 'b'])).toThrow(/unexpected arguments/);
	});

	test('--comment needs --pr', () => {
		expect(() => parseCli(['up', '--comment'])).toThrow(/needs --pr/);
	});

	test('--head asks for the pull request head as pushed, and needs --pr', () => {
		expect(parseCli(['up', '--pr', '7', '--head']).head).toBe(true);
		expect(parseCli(['up', '--pr', '7']).head).toBe(false);
		expect(() => parseCli(['up', '--head'])).toThrow(/--head needs --pr/);
	});

	test('--tail takes 1 to 5000 lines, the most koid gives', () => {
		expect(parseCli(['logs', 'a', '--tail', '50']).tail).toBe(50);
		expect(parseCli(['logs', 'a']).tail).toBe(200);
		expect(parseCli(['logs', 'a', '--tail', '1']).tail).toBe(1);
		expect(parseCli(['logs', 'a', '--tail', '5000']).tail).toBe(5000);
		for (const bad of ['0', '-5', '5001', '9999', '10000', '05', 'x'])
			expect(() => parseCli(['logs', 'a', `--tail=${bad}`])).toThrow('--tail expects 1 to 5000');
	});

	test('lease takes a preview name, --minutes 1 to 120 and a holder', () => {
		const cli = parseCli([
			'lease',
			'hello-pr-7',
			'--minutes',
			'30',
			'--holder',
			'ci run 42',
			'--json',
		]);
		expect(cli.command).toBe('lease');
		expect(cli.label).toBe('hello-pr-7');
		expect(cli.minutes).toBe(30);
		expect(cli.holder).toBe('ci run 42');
		expect(cli.json).toBe(true);
		expect(parseCli(['lease', 'hello-pr-7', '--minutes', '120']).holder).toBeUndefined();
		expect(() => parseCli(['lease'])).toThrow(/needs a preview name/);
		expect(() => parseCli(['lease', 'hello-pr-7'])).toThrow(/lease needs --minutes/);
		for (const bad of ['0', '121', '-5', '05', '1.5', 'x']) {
			expect(() => parseCli(['lease', 'hello-pr-7', `--minutes=${bad}`])).toThrow(
				'--minutes expects 1 to 120',
			);
		}
		expect(() => parseCli(['lease', 'hello-pr-7', '--minutes', '5', '--holder', ''])).toThrow(
			/--holder/,
		);
		expect(() =>
			parseCli(['lease', 'hello-pr-7', '--minutes', '5', '--holder', 'a\u0001b']),
		).toThrow(/--holder/);
	});

	test('release takes a preview name and a lease id', () => {
		const cli = parseCli(['release', 'hello-pr-7', 'l'.repeat(20)]);
		expect(cli.command).toBe('release');
		expect(cli.label).toBe('hello-pr-7');
		expect(cli.leaseId).toBe('l'.repeat(20));
		expect(() => parseCli(['release', 'hello-pr-7'])).toThrow(
			/needs a preview name and a lease id/,
		);
		expect(() => parseCli(['release', 'hello-pr-7', '../x'])).toThrow(/not a lease id/);
		expect(() => parseCli(['release', 'hello-pr-7', 'l'.repeat(20), 'x'])).toThrow(/unexpected/);
		expect(() => parseCli(['down', 'hello-pr-7', 'l'.repeat(20)])).toThrow(/unexpected/);
	});

	test('--force is read for down', () => {
		expect(parseCli(['down', 'hello-pr-7', '--force']).force).toBe(true);
		expect(parseCli(['down', 'hello-pr-7']).force).toBe(false);
	});

	test('rejects an unknown command', () => {
		expect(() => parseCli(['deploy'])).toThrow(/unknown command/);
	});

	test('rejects a non-numeric pull request number', () => {
		expect(() => parseCli(['up', '--pr', 'abc'])).toThrow(/--pr/);
		expect(() => parseCli(['up', '--pr', '12x'])).toThrow(/--pr/);
	});

	test('rejects pull request numbers that are not plain digits', () => {
		for (const pr of ['0', '-1', '0123', '1e21', '1.5', '0x10', ' 12', '']) {
			expect(() => parseCli(['up', '--pr', pr])).toThrow(/--pr/);
		}
	});

	test('takes --target, --config and --domain on any command', () => {
		const cli = parseCli([
			'up',
			'--target',
			'team',
			'--config',
			'/tmp/k.yaml',
			'--domain',
			'previews.example.com',
		]);
		expect([cli.target, cli.config, cli.domain]).toEqual([
			'team',
			'/tmp/k.yaml',
			'previews.example.com',
		]);
		const plain = parseCli(['list']);
		expect([plain.target, plain.config, plain.domain]).toEqual([undefined, undefined, undefined]);
		expect(parseCli(['logs', 'a', '--target', 't']).target).toBe('t');
	});

	test('an empty selector is an error', () => {
		for (const flag of ['--target', '--config', '--domain']) {
			expect(() => parseCli(['up', `${flag}=`])).toThrow(`${flag} needs a value`);
		}
		expect(() => parseCli(['config', 'import-aws', '--name='])).toThrow('--name needs a value');
	});

	test('config takes a subcommand, and import-aws a target name', () => {
		expect(parseCli(['config', 'show']).sub).toBe('show');
		const imported = parseCli(['config', 'import-aws', '--name', 'owner-aws', '--replace']);
		expect([imported.command, imported.sub, imported.name, imported.replace]).toEqual([
			'config',
			'import-aws',
			'owner-aws',
			true,
		]);
		expect(parseCli(['config', 'import-aws', '--name', 'x']).replace).toBe(false);
		expect(() => parseCli(['config'])).toThrow('config needs a subcommand: show or import-aws');
		expect(() => parseCli(['config', 'bogus'])).toThrow(/config needs a subcommand/);
		expect(() => parseCli(['config', 'import-aws'])).toThrow('config import-aws needs --name NAME');
		expect(() => parseCli(['config', 'import-aws', '--name', 'Bad_Name'])).toThrow(
			/--name expects a target name/,
		);
		expect(() => parseCli(['config', 'show', '--name', 'x'])).toThrow(
			'--name goes with config import-aws',
		);
		expect(() => parseCli(['config', 'show', '--replace'])).toThrow(
			'--replace goes with config import-aws',
		);
		expect(() => parseCli(['up', '--replace'])).toThrow('--replace goes with config import-aws');
		expect(() => parseCli(['config', 'show', 'extra'])).toThrow(/unexpected arguments/);
	});

	test('target takes a subcommand and a target name, and trust a fingerprint', () => {
		const fp = 'SHA256:yafprXjNqGAiu4TRle+qC+BurNOzHuZM6xevfySqbqk';
		const shown = parseCli(['target', 'show', 'team']);
		expect([shown.command, shown.sub, shown.name, shown.fingerprint]).toEqual([
			'target',
			'show',
			'team',
			undefined,
		]);
		const trusted = parseCli(['target', 'trust', 'team', '--fingerprint', fp, '--json']);
		expect([trusted.sub, trusted.name, trusted.fingerprint, trusted.json]).toEqual([
			'trust',
			'team',
			fp,
			true,
		]);
		expect(() => parseCli(['target'])).toThrow('target needs a subcommand: show or trust');
		expect(() => parseCli(['target', 'bogus', 'x'])).toThrow(/target needs a subcommand/);
		expect(() => parseCli(['target', 'show'])).toThrow('target show needs a target name');
		expect(() => parseCli(['target', 'show', 'Bad_Name'])).toThrow(/is not a target name/);
		expect(() => parseCli(['target', 'show', 'team', 'extra'])).toThrow(
			/unexpected arguments: extra/,
		);
		expect(() => parseCli(['target', 'trust', 'team'])).toThrow(
			'target trust needs --fingerprint SHA256:..., the host key fingerprint',
		);
		for (const bad of [
			'MD5:ab:cd',
			'SHA256:short',
			`${fp}=`,
			fp.toLowerCase().slice(0, 7) + fp.slice(7),
		]) {
			expect(() => parseCli(['target', 'trust', 'team', '--fingerprint', bad])).toThrow(
				/--fingerprint expects SHA256: followed by 43 base64 characters/,
			);
		}
		expect(() => parseCli(['target', 'trust', 'team', '--fingerprint='])).toThrow(
			'--fingerprint needs a value',
		);
		expect(() => parseCli(['target', 'show', 'team', '--fingerprint', fp])).toThrow(
			'--fingerprint goes with target trust',
		);
		expect(() => parseCli(['up', '--fingerprint', fp])).toThrow(
			'--fingerprint goes with target trust',
		);
	});

	test('rejects pull request numbers longer than nine digits', () => {
		expect(parseCli(['up', '--pr', '999999999']).pr).toBe(999999999);
		expect(() => parseCli(['up', '--pr', '1000000000'])).toThrow(/--pr/);
		// Number('9007199254740993') rounds to 9007199254740992.
		expect(() => parseCli(['up', '--pr', '9007199254740993'])).toThrow(/--pr/);
	});
});
