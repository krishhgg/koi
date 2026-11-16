#!/usr/bin/env bun
import { hostname, userInfo } from 'node:os';
import {
	escapeControls,
	LeaseReplySchema,
	LOG_TEXT_MAX,
	logCutNote,
	PreviewListPageSchema,
	type PreviewSummary,
	randomId,
} from '@koi/shared';
import { parseCli, USAGE } from './args.ts';
import { type Box, ctlErrorText } from './box.ts';
import { BUILTIN_RECIPES } from './builtins.ts';
import type { Env, TargetFlags } from './config.ts';
import { configCommand } from './config-command.ts';
import { refuseAutoloadedCheckout } from './environ.ts';
import { cliGit, type Git } from './git.ts';
import { type GitHub, ghCli, ownerRepoFor } from './github.ts';
import { openHost } from './host.ts';
import { targetCommand } from './target-command.ts';
import { abandonedCalls } from './transport.ts';
import { builtFrom, type HealthAnswer, keysPageUrl, up, wakePreview } from './up.ts';
import {
	cancelVerification,
	exportEvidence,
	formatExport,
	formatPlan,
	formatStatus,
	planVerification,
	readRunStatus,
	runVerification,
	type VerifyDeps,
} from './verify.ts';

export const VERSION = '0.1.0';

export interface Io {
	stdout: (s: string) => void;
	stderr: (s: string) => void;
}

const processIo: Io = {
	stdout: (s) => {
		process.stdout.write(s);
	},
	stderr: (s) => {
		process.stderr.write(s);
	},
};

// What a command needs to reach its host: the selectors from the command
// line, the environment, the checkout (for .koi/target.yaml) and where to
// print notices.
export interface HostContext {
	flags: TargetFlags;
	env: Env;
	checkoutDir: string;
	notice: (message: string) => void;
}

export interface Runtime {
	box: (ctx: HostContext) => Promise<{ box: Box; domain: string }>;
	cwd: string;
	// Told of the host a command opened, so that a signal can close it
	// (main). Nothing, unless main or a test passes its own.
	opened?: (box: Box) => void;
	// The environment; process.env unless a test passes its own. Before koi
	// reads it from source, environ.ts refuses a checkout whose dotenv or
	// bunfig files Bun has already loaded.
	env?: Record<string, string | undefined>;
	// How koi up and koi lease wait between polls; Bun.sleep unless a test
	// passes its own.
	sleep?: (ms: number) => Promise<void>;
	// The clock those waits measure by; Date unless a test passes its own.
	now?: () => Date;
	// One request to a preview's health URL, for koi lease; fetch unless a
	// test passes its own.
	probe?: (url: string) => Promise<HealthAnswer>;
	// The git and gh clients koi up uses; cliGit(cwd) and ghCli unless a test
	// passes its own.
	git?: Git;
	github?: (ownerRepo: string) => GitHub;
}

const realRuntime: Runtime = {
	cwd: process.cwd(),
	async box(ctx) {
		const { box, domain } = await openHost(ctx);
		return { box, domain };
	},
};

// The top of the checkout koi runs in, or the directory itself outside one.
async function checkoutDir(runtime: Runtime): Promise<string> {
	return (runtime.git ?? cliGit(runtime.cwd)).root().catch(() => runtime.cwd);
}

export async function run(
	argv: string[],
	io: Io = processIo,
	runtime: Runtime = realRuntime,
): Promise<number> {
	let cli: ReturnType<typeof parseCli>;
	try {
		cli = parseCli(argv);
	} catch (err) {
		io.stderr(`koi: ${message(err)}\n\n${USAGE}`);
		return 2;
	}
	const progress = (m: string) => io.stderr(`koi  ${m}\n`);
	const environment = async () => {
		if (runtime.env !== undefined) return runtime.env;
		await refuseAutoloadedCheckout({ cwd: runtime.cwd });
		return process.env;
	};
	// The host a command opened; closed once the command is done, however
	// it ended, so that no master connection or temporary directory of the
	// transport outlives the command.
	let host: Box | undefined;
	const connect = async () => {
		const opened = await runtime.box({
			flags: { target: cli.target, config: cli.config, domain: cli.domain },
			env: await environment(),
			checkoutDir: await checkoutDir(runtime),
			notice: progress,
		});
		host = opened.box;
		runtime.opened?.(opened.box);
		return opened;
	};
	const command = async (): Promise<number> => {
		switch (cli.command) {
			case 'help':
				io.stdout(USAGE);
				return 0;
			case 'version':
				io.stdout(cli.json ? `${JSON.stringify({ version: VERSION })}\n` : `koi ${VERSION}\n`);
				return 0;
			case 'up': {
				const { box, domain } = await connect();
				const result = await up(
					{ pr: cli.pr, comment: cli.comment, head: cli.head },
					{
						git: runtime.git ?? cliGit(runtime.cwd),
						box,
						domain,
						builtins: BUILTIN_RECIPES,
						github: runtime.github ?? ((ownerRepo) => ghCli(ownerRepo)),
						ownerRepo: ownerRepoFor,
						progress,
						buildLine: (line) => io.stderr(`  | ${line}\n`),
						randomId,
						now: runtime.now ?? (() => new Date()),
						sleep: runtime.sleep ?? ((ms) => Bun.sleep(ms)),
					},
				);
				if (cli.json) {
					io.stdout(`${JSON.stringify(result)}\n`);
				} else if (result.status === 'running') {
					io.stdout(`\n  preview   ${result.url}\n`);
					if (result.loginKey) io.stdout(`  login     ${result.loginKey}\n`);
					// For a pull request, what koi built and what it holds; the merge
					// commit alone would not say which push of the pull request.
					if (result.pr !== undefined) io.stdout(`  built     ${builtFrom(result)}\n`);
					else io.stdout(`  commit    ${result.commit.slice(0, 12)}\n`);
					io.stdout(`  keys      ${keysPageUrl(domain, result.label)}\n`);
					if (result.comment) io.stdout(`  comment   ${result.comment}\n`);
				} else {
					io.stdout(`\n  build failed for ${result.label}\n\n${result.error ?? ''}\n`);
				}
				return result.status === 'running' ? 0 : 1;
			}
			case 'list': {
				const { box, domain } = await connect();
				await box.ensureAwake(progress);
				const records = await listPreviews(box);
				io.stdout(
					cli.json
						? `${JSON.stringify(records.map((r) => ({ ...r, keysUrl: keysPageUrl(domain, r.label) })))}\n`
						: table(records, domain),
				);
				return 0;
			}
			case 'logs': {
				const { box } = await connect();
				await box.ensureAwake(progress);
				// koid ctl returns the last lines asked for, cut to fit through SSM
				// with a line saying so when they are too long. koi prints that as
				// it is, so the line stays. With --json the line becomes `truncated`.
				const label = cli.label as string;
				const command = cli.build ? 'buildlog' : 'logs';
				const text = await ctlOk(box, [command, label, String(cli.tail)]);
				if (cli.json) {
					const note = logCutNote(LOG_TEXT_MAX);
					const truncated = text.startsWith(note);
					const reply = {
						label,
						build: cli.build,
						text: truncated ? text.slice(note.length) : text,
						truncated,
					};
					io.stdout(`${JSON.stringify(reply)}\n`);
				} else {
					io.stdout(ensureNewline(text));
				}
				return 0;
			}
			case 'lease': {
				const { box, domain } = await connect();
				await box.ensureAwake(progress);
				const label = cli.label as string;
				// koid leases only a preview that runs and is routed, and after
				// the box wakes none is until someone visits. So visit first.
				await wakePreview(label, domain, {
					probe: runtime.probe ?? probeHealth,
					sleep: runtime.sleep ?? ((ms) => Bun.sleep(ms)),
					now: runtime.now ?? (() => new Date()),
					progress,
				});
				const holder = cli.holder ?? defaultHolder();
				const ttl = String((cli.minutes as number) * 60);
				const reply = LeaseReplySchema.parse(
					JSON.parse(await ctlOk(box, ['lease', label, '--holder', holder, '--ttl-seconds', ttl])),
				);
				if (cli.json) {
					io.stdout(`${JSON.stringify(reply)}\n`);
				} else {
					const { lease, deployment } = reply;
					io.stdout(
						`leased ${label} until ${lease.expiresAt}\n` +
							`  lease       ${lease.leaseId}\n` +
							`  holder      ${lease.holder}\n` +
							`  deployment  ${deployment.deploymentId}\n` +
							`  image       ${deployment.imageDigest}\n` +
							`  commit      ${deployment.commit}\n`,
					);
				}
				return 0;
			}
			case 'release': {
				const { box } = await connect();
				await box.ensureAwake(progress);
				const label = cli.label as string;
				const leaseId = cli.leaseId as string;
				await ctlOk(box, ['release', label, leaseId]);
				io.stdout(
					cli.json
						? `${JSON.stringify({ label, leaseId, released: true })}\n`
						: `released ${leaseId} on ${label}\n`,
				);
				return 0;
			}
			case 'down': {
				const { box } = await connect();
				await box.ensureAwake(progress);
				const label = cli.label as string;
				await ctlOk(box, cli.force ? ['down', label, '--force'] : ['down', label]);
				io.stdout(cli.json ? `${JSON.stringify({ removed: label })}\n` : `removed ${label}\n`);
				return 0;
			}
			case 'config':
				return await configCommand(cli, io, {
					env: await environment(),
					checkoutDir: await checkoutDir(runtime),
					notice: progress,
				});
			case 'target':
				return await targetCommand(cli, io, { env: await environment(), notice: progress });
			case 'verify': {
				const args = cli.verify;
				if (args === undefined) throw new Error('verify needs a subcommand');
				const { box, domain } = await connect();
				// Progress can quote what a pull request named, as the formatters' text can.
				const say = (m: string) => progress(escapeControls(m));
				await box.ensureAwake(say);
				const deps: VerifyDeps = {
					box,
					domain,
					progress: say,
					probe: runtime.probe ?? probeHealth,
					sleep: runtime.sleep ?? ((ms) => Bun.sleep(ms)),
					now: runtime.now ?? (() => new Date()),
				};
				const print = (value: unknown, text: string) =>
					io.stdout(cli.json ? `${JSON.stringify(value)}\n` : text);
				switch (args.command) {
					case 'plan': {
						const plan = await planVerification(args.target, args.profile, deps);
						print(plan, formatPlan(plan));
						return 0;
					}
					case 'run': {
						const report = await runVerification(args.target, args.profile, deps);
						print(report, formatStatus(report.run));
						// Only an evaluated run that passed and has its manifest exits
						// 0. Failed and incomplete, interrupted and cancelled included,
						// exit 1, as does a judged run whose bundle was not finalized:
						// without a manifest nothing of it counts.
						const { run } = report;
						return run.completion === 'evaluated' && run.outcome === 'passed' && run.finalized
							? 0
							: 1;
					}
					case 'status': {
						const status = await readRunStatus(args.target, deps);
						print(status, formatStatus(status));
						return 0;
					}
					case 'evidence': {
						const report = await exportEvidence(args.target, args.out as string, deps);
						print(report, formatExport(report));
						return 0;
					}
					case 'cancel': {
						const status = await cancelVerification(args.target, deps);
						print(status, formatStatus(status));
						return 0;
					}
				}
			}
		}
	};
	try {
		return await command();
	} catch (err) {
		// A verify error can quote koid, and through it what a pull request named. Other
		// commands' errors can be several lines on purpose, a build's for one.
		io.stderr(`koi: ${cli.command === 'verify' ? escapeControls(message(err)) : message(err)}\n`);
		return 1;
	} finally {
		if (host !== undefined) {
			await closeHost(host).catch((err: unknown) =>
				io.stderr(`koi: closing the connection to the host failed: ${message(err)}\n`),
			);
		}
	}
}

// Closes the host once, however many ask: the end of run and a signal may
// both, and the second must wait for the first rather than find it half done.
const closing = new WeakMap<Box, Promise<void>>();
function closeHost(box: Box): Promise<void> {
	let done = closing.get(box);
	if (done === undefined) {
		done = box.close?.() ?? Promise.resolve();
		closing.set(box, done);
	}
	return done;
}

// Who holds a lease when --holder is not given: the local user and host, so
// a refused build names someone to ask.
function defaultHolder(): string {
	let user: string;
	try {
		user = userInfo().username;
	} catch {
		// No passwd entry for this uid, as in some containers.
		user = process.env.USER ?? process.env.USERNAME ?? `uid${process.getuid?.() ?? ''}`;
	}
	return `${user}@${hostname()}`;
}

// One request to a preview's health URL, which reaches koid through Caddy
// as a visit does. Redirects are not followed: a 200 must be koid's own.
async function probeHealth(url: string): Promise<HealthAnswer> {
	try {
		const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(10_000) });
		// Only the status is read; cancelling the body frees the connection.
		await res.body?.cancel().catch(() => {});
		return { status: res.status };
	} catch (err) {
		return { error: message(err) };
	}
}

async function ctlOk(box: Box, args: string[]): Promise<string> {
	const r = await box.ctl(args);
	if (r.code !== 0) throw new Error(ctlErrorText(r) || `koid ctl ${args[0]} failed`);
	return r.stdout;
}

// Every preview. koid ctl list prints a page at a time, small enough for SSM
// to return whole, and the label to ask for the previews after.
async function listPreviews(box: Box): Promise<PreviewSummary[]> {
	const all: PreviewSummary[] = [];
	let after: string | undefined;
	for (;;) {
		const page = PreviewListPageSchema.parse(
			JSON.parse(await ctlOk(box, after === undefined ? ['list'] : ['list', after])),
		);
		all.push(...page.previews);
		if (page.next === undefined) return all;
		// Pages come in label order. A next that does not move on would ask
		// for the same page forever.
		if (after !== undefined && page.next <= after) {
			throw new Error(`koid ctl list did not move past ${after}`);
		}
		after = page.next;
	}
}

export function table(records: PreviewSummary[], domain: string): string {
	if (records.length === 0) return 'no previews\n';
	const rows = records.map((r) => [
		r.label,
		r.status,
		r.commit.slice(0, 7),
		r.lastVisitAt?.slice(0, 16).replace('T', ' ') ?? '-',
		`https://${r.label}.${domain}`,
	]);
	const head = ['NAME', 'STATUS', 'COMMIT', 'LAST VISIT', 'URL'];
	const widths = head.map((h, i) => Math.max(h.length, ...rows.map((row) => row[i]?.length ?? 0)));
	const line = (cells: string[]) =>
		cells
			.map((c, i) => c.padEnd(widths[i] ?? 0))
			.join('  ')
			.trimEnd();
	return `${[line(head), ...rows.map(line)].join('\n')}\n`;
}

function ensureNewline(text: string): string {
	return text === '' || text.endsWith('\n') ? text : `${text}\n`;
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

// Runs the command and ends the process. Usually the runtime exits on its
// own once nothing is left to do. A call the transport stopped waiting for
// is still running inside the SDK, though. What the SDK started for it, a
// credential_process or a retry's timer, keeps the runtime alive until it
// ends, and a stuck helper never ends. Then koi exits itself, once its
// output is written. Tests pass their own runtime.
//
// SIGINT and SIGTERM end the command at once, as they did when nothing
// handled them, but the host the command opened is closed first: an SSH
// master connection would otherwise stay up for ten minutes with its
// temporary directory. The exit status is the shell's for a signal.
export async function main(argv: string[], runtime: Runtime = realRuntime): Promise<void> {
	let open: Box | undefined;
	const onSignal = (signal: NodeJS.Signals) => {
		const code = 128 + (signal === 'SIGINT' ? 2 : 15);
		const closed = open === undefined ? Promise.resolve() : closeHost(open).catch(() => {});
		void closed.then(() => process.exit(code));
	};
	process.on('SIGINT', onSignal);
	process.on('SIGTERM', onSignal);
	try {
		process.exitCode = await run(argv, processIo, {
			...runtime,
			opened: (box) => {
				open = box;
				runtime.opened?.(box);
			},
		});
	} finally {
		process.off('SIGINT', onSignal);
		process.off('SIGTERM', onSignal);
	}
	if (abandonedCalls() === 0) return;
	await Promise.all([flushed(process.stdout), flushed(process.stderr)]);
	process.exit(process.exitCode);
}

// Settles once everything written to the stream has left the process. On a
// pipe, Bun drops what is still queued when the process exits, and a write
// callback does not wait for the queue. Ending the stream does.
function flushed(stream: NodeJS.WriteStream): Promise<void> {
	return new Promise((resolve) => {
		stream.once('error', () => resolve());
		stream.end(() => resolve());
	});
}

if (import.meta.main) await main(process.argv.slice(2));
