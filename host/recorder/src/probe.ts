// Starts Chromium as the recorder does, with its own sandbox on, opens a page
// and runs a line of script in it, closes it, and exits 0. koid runs this in
// the recorder image under the recorder's confinement before it calls
// verification available (packages/daemon/src/host.ts, docker.ts
// sandboxProbeArgs), so a seccomp profile or an AppArmor policy that refuses
// what the sandbox needs shows up there and not in a run. On failure it
// prints one line, the one in Chromium's output that says why when there is
// one, and exits 1.
import { mkdir } from 'node:fs/promises';
import { chromium } from 'playwright-core';
import { SANDBOXED } from './broker.ts';

// Lines in a failed launch that name the cause, where Playwright's first line
// only says the browser did not start.
const CAUSE = /Check failed|FATAL|No usable sandbox|Operation not permitted|Permission denied/;

async function probe(): Promise<void> {
	const home = '/tmp/koi-probe';
	await mkdir(home, { recursive: true, mode: 0o700 });
	const browser = await chromium.launch({
		...SANDBOXED,
		timeout: 60_000,
		env: {
			PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
			HOME: home,
			TMPDIR: '/tmp',
			LANG: 'C.UTF-8',
			LC_ALL: 'C.UTF-8',
		},
	});
	try {
		const page = await browser.newPage();
		await page.goto('about:blank');
		if ((await page.evaluate(() => 1 + 1)) !== 2) throw new Error('the page did not run script');
	} finally {
		await browser.close();
	}
}

probe().then(
	() => process.exit(0),
	(err: unknown) => {
		const lines = (err instanceof Error ? err.message : String(err))
			.split('\n')
			.map((line) => line.trim())
			.filter((line) => line !== '');
		const line = lines.find((l) => CAUSE.test(l)) ?? lines[0] ?? 'the browser did not start';
		process.stderr.write(`${line.slice(0, 400)}\n`);
		process.exit(1);
	},
);
