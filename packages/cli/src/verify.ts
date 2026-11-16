import { createHash } from 'node:crypto';
import { mkdir, open, readdir, rename, rm, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import {
	ARTIFACT_CHUNK_BYTES,
	ArtifactChunkSchema,
	artifactFileName,
	CTL_EXIT,
	EVENTS_PAGE_MAX,
	type EvidenceExport,
	EvidenceExportSchema,
	type EvidenceReply,
	EvidenceReplySchema,
	escapeControls,
	type PlanReply,
	PlanReplySchema,
	type RunAccepted,
	RunAcceptedSchema,
	type RunEventsPage,
	RunEventsPageSchema,
	type RunStatusReply,
	RunStatusReplySchema,
	SSM_ARTIFACT_MAX_BYTES,
	SSM_EXPORT_MAX_BYTES,
	TEARDOWN_ALLOWANCE_SECONDS,
} from '@koi/shared';
import { type Box, BoxUnavailableError, ctlErrorText } from './box.ts';
import { type HealthAnswer, STATUS_RETRY_MS, wakePreview } from './up.ts';

// The koi verify commands (docs/verify.md, "Running a verification"), over
// koid ctl verify through SSM. Every reply is a page; these read every page
// and give the whole, with what any page said it cut. koid judges; the CLI
// shows and waits.

export interface VerifyDeps {
	box: Box;
	domain: string;
	progress: (message: string) => void;
	probe: (url: string) => Promise<HealthAnswer>;
	sleep: (ms: number) => Promise<void>;
	now: () => Date;
	// What one export over SSM may fetch: in all, and per artifact. The
	// shared ceilings unless a test lowers them.
	limits?: ExportLimits | undefined;
	// Opens a file the export writes; node's unless a test passes one that
	// writes less than it is asked to.
	openFile?: OpenExportFile | undefined;
}

// What an export needs of a file it writes.
export interface ExportFile {
	write(bytes: Uint8Array, offset: number, length: number): Promise<{ bytesWritten: number }>;
	close(): Promise<void>;
}

export type OpenExportFile = (path: string, flags: string, mode: number) => Promise<ExportFile>;

export interface ExportLimits {
	exportBytes: number;
	artifactBytes: number;
}

export const EXPORT_LIMITS: ExportLimits = {
	exportBytes: SSM_EXPORT_MAX_BYTES,
	artifactBytes: SSM_ARTIFACT_MAX_BYTES,
};

// How often koi verify run asks for the run's status.
export const VERIFY_POLL_MS = 5_000;
// What koi waits past the run's own limit before it stops following: the
// teardown allowance koid gives itself, and time for the box.
export const FOLLOW_MARGIN_MS = (TEARDOWN_ALLOWANCE_SECONDS + 180) * 1000;

type Schema<T> = { parse(data: unknown): T };

// One koid ctl verify call, parsed. Throws with koid's own message when it
// refused, and BoxUnavailableError when SSM could not run it this time.
async function call<T>(box: Box, args: string[], schema: Schema<T>): Promise<T> {
	const r = await box.ctl(['verify', ...args]);
	if (r.code === CTL_EXIT.unavailable) throw new BoxUnavailableError(ctlErrorText(r));
	if (r.code !== CTL_EXIT.ok) {
		throw new Error(ctlErrorText(r) || `koid ctl verify ${args[0] ?? ''} failed`);
	}
	return schema.parse(JSON.parse(r.stdout));
}

// What a later page said it cut, added to the whole: a cut named on any
// page is as true of the combined reply as one named on the first, and
// an entry cut to size on page three is still cut once the pages are one.
function mergeTruncated(
	whole: { truncated?: string[] | undefined },
	page: { truncated?: string[] | undefined },
): void {
	if (page.truncated === undefined) return;
	whole.truncated = [...new Set([...(whole.truncated ?? []), ...page.truncated])];
}

// The plan, whole: the first page and every page after it.
export async function planVerification(
	label: string,
	profile: string,
	deps: VerifyDeps,
): Promise<PlanReply> {
	const first = await call(deps.box, ['plan', label, '--profile', profile], PlanReplySchema);
	const plan: PlanReply = { ...first };
	let next = first.next;
	let pages = 1;
	while (next !== undefined) {
		if (pages > 10_000) throw new Error('the plan has more pages than koi reads');
		const page = await call(deps.box, ['plan-page', plan.planId, next], PlanReplySchema);
		plan.points = [...plan.points, ...page.points];
		plan.blocked = [...plan.blocked, ...page.blocked];
		plan.uncovered = [...plan.uncovered, ...page.uncovered];
		mergeTruncated(plan, page);
		if (page.next !== undefined && page.next === next) {
			throw new Error(`koid ctl verify plan-page did not move past ${next}`);
		}
		next = page.next;
		pages += 1;
	}
	delete plan.next;
	return plan;
}

export async function startVerification(
	plan: Pick<PlanReply, 'planId' | 'planDigest'>,
	deps: VerifyDeps,
): Promise<RunAccepted> {
	return call(deps.box, ['run', plan.planId, plan.planDigest], RunAcceptedSchema);
}

// The run's status, with every page of its points.
export async function readRunStatus(runId: string, deps: VerifyDeps): Promise<RunStatusReply> {
	const first = await call(deps.box, ['status', runId], RunStatusReplySchema);
	const status: RunStatusReply = { ...first };
	let next = first.next;
	while (next !== undefined) {
		const page = await call(deps.box, ['status', runId, String(next)], RunStatusReplySchema);
		status.points = [...status.points, ...page.points];
		mergeTruncated(status, page);
		if (page.next !== undefined && page.next <= next) {
			throw new Error(`koid ctl verify status did not move past ${next}`);
		}
		next = page.next;
	}
	delete status.next;
	return status;
}

export async function cancelVerification(runId: string, deps: VerifyDeps): Promise<RunStatusReply> {
	await call(deps.box, ['cancel', runId], RunStatusReplySchema);
	return readRunStatus(runId, deps);
}

// Polls the run until it is no longer running, saying on stderr what each
// poll learned. A read that fails in a way that can pass is tried again for
// STATUS_RETRY_MS. Gives up past the run's limit and the follow margin.
export async function followRun(
	accepted: Pick<RunAccepted, 'runId' | 'limits'>,
	deps: VerifyDeps,
): Promise<RunStatusReply> {
	const { runId } = accepted;
	const since = deps.now().getTime();
	const deadline = since + accepted.limits.runSeconds * 1000 + FOLLOW_MARGIN_MS;
	let failing: { since: number; why: string } | undefined;
	let seen = new Map<string, string>();
	for (;;) {
		await deps.sleep(VERIFY_POLL_MS);
		let status: RunStatusReply;
		try {
			status = await readRunStatus(runId, deps);
		} catch (err) {
			if (!(err instanceof BoxUnavailableError)) throw err;
			failing = { since: failing?.since ?? deps.now().getTime(), why: err.message };
			if (deps.now().getTime() - failing.since > STATUS_RETRY_MS) {
				throw new Error(
					`could not read the status of run ${runId} for ${Math.round(STATUS_RETRY_MS / 60_000)} minutes: ${failing.why}`,
				);
			}
			continue;
		}
		failing = undefined;
		const now = new Map<string, string>();
		for (const p of status.points) {
			if (p.state !== 'done' || p.outcome === undefined) continue;
			now.set(p.id, p.outcome);
			if (!seen.has(p.id)) deps.progress(`${p.id}: ${p.outcome}`);
		}
		seen = now;
		if (status.state !== 'running') return status;
		if (deps.now().getTime() >= deadline) {
			throw new Error(
				`run ${runId} is still running after its limit of ${accepted.limits.runSeconds} seconds and the follow margin; see koi verify status ${runId}, or koi verify cancel ${runId}`,
			);
		}
	}
}

export interface RunReport {
	version: 1;
	plan: PlanReply;
	accepted: RunAccepted;
	run: RunStatusReply;
}

// koi verify run: wake the preview, plan, start, follow to the end.
export async function runVerification(
	label: string,
	profile: string,
	deps: VerifyDeps,
): Promise<RunReport> {
	// koid leases only a preview that runs and is routed, and after the box
	// wakes none is until someone visits. So visit first, as koi lease does.
	await wakePreview(label, deps.domain, {
		probe: deps.probe,
		sleep: deps.sleep,
		now: deps.now,
		progress: deps.progress,
	});
	const plan = await planVerification(label, profile, deps);
	deps.progress(
		`plan ${plan.planId}: ${plan.counts.selected} point(s) selected, ${plan.counts.blocked} blocked, ${plan.counts.uncovered} uncovered change(s)`,
	);
	for (const note of plan.notes) deps.progress(`note: ${note}`);
	const accepted = await startVerification(plan, deps);
	deps.progress(`run ${accepted.runId} started; lease until ${accepted.leaseExpiresAt}`);
	const run = await followRun(accepted, deps);
	return { version: 1, plan, accepted, run };
}

// -- Evidence export -----------------------------------------------------------

// What an event line is taken to weigh before any has been read, for the
// first page's size. Lines are at most MAX_EVENT_BYTES (12 KiB) and most
// are well under this; the average of what was read replaces it.
const EVENT_LINE_ESTIMATE_BYTES = 256;

// koi verify evidence RUN --out DIR: the manifest, the status, the events
// and every artifact the SSM path can carry, each written to a temporary
// file, checked against the manifest's hash and renamed into place. Expired
// evidence has no events or artifacts left, so koid answers 410 for them: the
// export skips them, saves what is retained, and says what is missing. `out`
// must not exist, or must be empty: nothing here overwrites. The ceilings
// bound what is asked for, not only what is kept: every request is for at
// most what the allowance has left, and nothing is written past it, so an
// artifact a byte over its ceiling is partial, and says so. Events are
// asked for by count, as many as the allowance holds at the average line
// so far, so a page can carry the fetch past the ceiling by the lines in
// it that were bigger than average; every byte received crossed SSM, so
// every one counts against the allowance, written or not.
export async function exportEvidence(
	runId: string,
	out: string,
	deps: VerifyDeps,
): Promise<EvidenceExport> {
	const limits = deps.limits ?? EXPORT_LIMITS;
	const dir = resolve(out);
	const existing = await stat(dir).catch(() => undefined);
	if (existing !== undefined) {
		if (!existing.isDirectory()) throw new Error(`${dir} exists and is not a directory`);
		if ((await readdir(dir)).length > 0) {
			throw new Error(
				`${dir} is not empty; koi verify evidence writes only into an empty directory`,
			);
		}
	}
	await mkdir(join(dir, 'artifacts'), { recursive: true });
	const notes: string[] = [];
	const missing: string[] = [];
	let total = 0;
	const evidence = await readEvidence(runId, deps);
	if (!evidence.finalized) {
		notes.push(
			'the run is not finalized: its artifacts are not readable yet, and the manifest is not written',
		);
		missing.push('the manifest: the run is not finalized');
	}
	if (evidence.expired) {
		notes.push('the evidence has expired; only the manifest and the status remain');
		notes.push('events are unavailable: koid no longer keeps them for this run');
		missing.push(
			`events: the ${evidence.events?.count ?? 'recorded'} events of this run have expired`,
		);
	}
	const unlisted = evidence.artifactCount - evidence.artifacts.length;
	if (unlisted > 0) {
		const why = evidence.expired
			? 'they have expired'
			: evidence.finalized
				? 'koid did not list them'
				: 'the run is not finalized';
		missing.push(`${unlisted} of ${evidence.artifactCount} artifacts: ${why}`);
	}
	const status = await readRunStatus(runId, deps);
	await writeJson(join(dir, 'status.json'), status, deps);
	await writeJson(join(dir, 'evidence.json'), evidence, deps);

	const eventsFile = 'events.ndjson';
	let events = 0;
	if (!evidence.expired) {
		const exported = await exportEvents(runId, join(dir, eventsFile), limits, deps);
		events = exported.count;
		total += exported.received;
		const recorded = evidence.events;
		if (exported.outOfOrder !== undefined) missing.push(`events: ${exported.outOfOrder}`);
		if (exported.stopped !== undefined) {
			const stoppedAt = `events stop after sequence ${exported.stopped}: the export reached its ceiling of ${limits.exportBytes} bytes`;
			notes.push(stoppedAt);
			missing.push(stoppedAt);
		} else if (recorded !== undefined && events < recorded.count) {
			missing.push(`events: koid gave ${events} of the ${recorded.count} recorded`);
		} else if (
			recorded !== undefined &&
			exported.outOfOrder === undefined &&
			exported.sha256 !== recorded.sha256
		) {
			missing.push(
				`events: the ${events} lines koid gave hash to ${exported.sha256}, and the manifest says ${recorded.sha256}`,
			);
		}
	}

	const artifacts: EvidenceExport['artifacts'] = [];
	for (const entry of evidence.artifacts) {
		const base = {
			id: entry.id,
			kind: entry.kind,
			availability: entry.availability,
			bytes: 0,
			sha256: entry.sha256,
			verified: false,
			truncated: false,
		};
		if (entry.availability !== 'available') {
			artifacts.push({
				...base,
				note: `${entry.availability}: ${entry.redaction.limitations[0] ?? 'no bytes were kept'}`.slice(
					0,
					500,
				),
			});
			continue;
		}
		if (total >= limits.exportBytes) {
			artifacts.push({
				...base,
				truncated: true,
				note: `not exported: the export reached its ceiling of ${limits.exportBytes} bytes; the rest needs the channel (C2)`,
			});
			continue;
		}
		const file = join('artifacts', artifactFileName(entry.id, entry.mediaType));
		const path = join(dir, file);
		const part = `${path}.part`;
		const hash = createHash('sha256');
		const { written, truncated, note } = await fillPart(part, deps, async (file) => {
			let written = 0;
			let offset = 0;
			for (;;) {
				// What may still be asked for: the artifact's own ceiling and
				// the export's, less what is written. Settled before the
				// request, so no byte past either is fetched or written.
				const allowance = Math.min(
					limits.artifactBytes - written,
					limits.exportBytes - total,
					ARTIFACT_CHUNK_BYTES,
				);
				if (allowance <= 0) {
					return {
						written,
						truncated: true,
						note: `partial: ${written} of ${entry.size} bytes; the rest needs the channel (C2)`,
					};
				}
				const chunk = await readChunk(runId, entry.id, offset, allowance, deps);
				const bytes = Buffer.from(chunk.dataBase64, 'base64');
				if (bytes.length !== chunk.length || chunk.offset !== offset || bytes.length > allowance) {
					throw new Error(
						`${entry.id}: koid sent ${bytes.length} bytes at ${chunk.offset}, not up to ${allowance} at ${offset}`,
					);
				}
				// Hashed and counted once it is all in the file, so the hash and
				// the count describe the file and not only what was received.
				await writeAll(file, bytes, part);
				hash.update(bytes);
				written += bytes.length;
				total += bytes.length;
				if (chunk.next === undefined) return { written, truncated: false, note: undefined };
				offset = chunk.next;
			}
		});
		const digest = `sha256:${hash.digest('hex')}`;
		const verified = !truncated && written === entry.size && digest === entry.sha256;
		if (!truncated && !verified) {
			await rm(part, { force: true });
			artifacts.push({
				...base,
				bytes: written,
				note: `discarded: the bytes read hash to ${digest}, and the manifest says ${entry.sha256}`,
			});
			continue;
		}
		await movePart(part, truncated ? `${path}.partial` : path);
		artifacts.push({
			...base,
			file: truncated ? `${file}.partial` : file,
			bytes: written,
			verified,
			truncated,
			...(note !== undefined ? { note } : {}),
		});
	}
	for (const a of artifacts) {
		if (!a.verified) missing.push(`${a.id}: ${a.note ?? a.availability}`.slice(0, 500));
	}
	const report = EvidenceExportSchema.parse({
		version: 1,
		runId,
		out: dir,
		finalized: evidence.finalized,
		expired: evidence.expired,
		complete: missing.length === 0,
		missing,
		artifacts,
		events: { count: events, ...(evidence.expired ? {} : { file: eventsFile }) },
		bytes: total,
		notes,
	});
	// Last, and whole or not at all: its presence is what says the export finished.
	await writeJson(join(dir, 'export.json'), report, deps);
	return report;
}

// Events, page by page, within the export ceiling: each page is asked for with
// the count the remaining allowance holds at the average line so far, a whole
// page is counted as soon as it arrives, a line is written only when the
// allowance has room for it, and no page is asked for once the allowance is used
// up. Says how many were written, what crossed SSM (the lines written and the
// ones that did not fit), the sequence the events stop after if they do, the first
// place the sequence numbers do not count up by one, and the digest of the bytes
// written. A count alone says nothing of which events these are: a line replaced by
// a copy of another keeps it. koid writes each line so that writing it again here
// gives the same bytes, so the digest can be held to the manifest's.
async function exportEvents(
	runId: string,
	path: string,
	limits: ExportLimits,
	deps: VerifyDeps,
): Promise<{
	count: number;
	received: number;
	stopped: number | undefined;
	outOfOrder: string | undefined;
	sha256: string;
}> {
	const part = `${path}.part`;
	const done = await fillPart(part, deps, async (file) => {
		const hash = createHash('sha256');
		let count = 0;
		let written = 0;
		let received = 0;
		let receivedLines = 0;
		let after = 0;
		let last = 0;
		let outOfOrder: string | undefined;
		const end = (stopped: number | undefined) => ({
			count,
			received,
			stopped,
			outOfOrder,
			sha256: `sha256:${hash.digest('hex')}`,
		});
		for (;;) {
			const remaining = limits.exportBytes - received;
			if (remaining <= 0) return end(after);
			const average =
				receivedLines === 0 ? EVENT_LINE_ESTIMATE_BYTES : Math.ceil(received / receivedLines);
			const limit = Math.max(1, Math.min(EVENTS_PAGE_MAX, Math.floor(remaining / average)));
			const page = await readEventsPage(runId, after, limit, deps);
			const lines = page.events.map((event) => ({
				seq: event.seq,
				bytes: Buffer.from(`${JSON.stringify(event)}\n`),
			}));
			// Counted before any is written: the lines after one that does not
			// fit crossed SSM as well.
			received += lines.reduce((sum, { bytes }) => sum + bytes.length, 0);
			receivedLines += lines.length;
			for (const { seq, bytes } of lines) {
				if (written + bytes.length > limits.exportBytes) return end(after);
				await writeAll(file, bytes, part);
				hash.update(bytes);
				written += bytes.length;
				count += 1;
				after = seq;
				if (seq !== last + 1) outOfOrder ??= `sequence ${seq} comes after ${last}`;
				last = seq;
			}
			if (!page.more) return end(undefined);
			if (page.next <= after && page.events.length === 0) {
				throw new Error(`koid ctl verify events did not move past ${after}`);
			}
			after = Math.max(after, page.next);
		}
	});
	await movePart(part, path);
	return done;
}

// Fills a new file and closes it. On any failure the file goes too, so a failed
// export leaves no .part behind, whatever stopped it.
async function fillPart<T>(
	part: string,
	deps: VerifyDeps,
	fill: (file: ExportFile) => Promise<T>,
): Promise<T> {
	const file = await (deps.openFile ?? open)(part, 'wx', 0o600);
	try {
		const result = await fill(file);
		await file.close();
		return result;
	} catch (err) {
		await file.close().catch(() => {});
		await rm(part, { force: true }).catch(() => {});
		throw err;
	}
}

async function movePart(part: string, final: string): Promise<void> {
	try {
		await rename(part, final);
	} catch (err) {
		await rm(part, { force: true }).catch(() => {});
		throw err;
	}
}

// A write can take less than it is given, and a short write taken for a whole one
// would be a truncated file with the hash of the whole. A write that takes
// nothing would never finish, so it is an error.
async function writeAll(file: ExportFile, bytes: Uint8Array, path: string): Promise<void> {
	let at = 0;
	while (at < bytes.length) {
		const { bytesWritten } = await file.write(bytes, at, bytes.length - at);
		if (bytesWritten <= 0) {
			throw new Error(`writing ${path}: a write of ${bytes.length - at} bytes made no progress`);
		}
		at += bytesWritten;
	}
}

async function readEvidence(runId: string, deps: VerifyDeps): Promise<EvidenceReply> {
	const first = await call(deps.box, ['evidence', runId], EvidenceReplySchema);
	const evidence: EvidenceReply = { ...first };
	let next = first.next;
	while (next !== undefined) {
		const page = await call(deps.box, ['evidence', runId, String(next)], EvidenceReplySchema);
		evidence.artifacts = [...evidence.artifacts, ...page.artifacts];
		mergeTruncated(evidence, page);
		if (page.next !== undefined && page.next <= next) {
			throw new Error(`koid ctl verify evidence did not move past ${next}`);
		}
		next = page.next;
	}
	delete evidence.next;
	return evidence;
}

function readEventsPage(
	runId: string,
	after: number,
	limit: number,
	deps: VerifyDeps,
): Promise<RunEventsPage> {
	return call(deps.box, ['events', runId, String(after), String(limit)], RunEventsPageSchema);
}

function readChunk(
	runId: string,
	artifact: string,
	offset: number,
	length: number,
	deps: VerifyDeps,
) {
	return call(
		deps.box,
		['artifact', runId, artifact, String(offset), String(length)],
		ArtifactChunkSchema,
	);
}

// A JSON file goes through a .part file like any other, so a write that fails
// part way leaves nothing under the file's name.
async function writeJson(path: string, value: unknown, deps: VerifyDeps): Promise<void> {
	const part = `${path}.part`;
	const bytes = Buffer.from(`${JSON.stringify(value, null, '\t')}\n`);
	await fillPart(part, deps, (file) => writeAll(file, bytes, part));
	await movePart(part, path);
}

// -- Text output -----------------------------------------------------------------

// What a person reads, from one string per line. Every line passes through here, so no
// field can reach the terminal with a control character in it, a newline included: the
// join below is the only thing that may end a line. --json does not come here: a program
// reads that, and expects each value as it is.
function textOutput(lines: string[]): string {
	return lines.map(escapeControls).join('\n');
}

export function formatPlan(plan: PlanReply): string {
	const lines = [
		`plan ${plan.planId} for ${plan.label} (profile ${plan.profile}${plan.advisory ? ', advisory' : ''})`,
		`  deployment  ${plan.deployment.deploymentId}`,
		`  image       ${plan.deployment.imageDigest}`,
		`  commit      ${plan.deployment.commit}`,
		`  digest      ${plan.planDigest}`,
		`  policy      ${plan.policy.source}${plan.policy.advisory === undefined ? '' : ` (advisory ${plan.policy.advisory.path}: ${plan.policy.advisory.required.length} required${plan.policy.advisory.error === undefined ? '' : `, ${plan.policy.advisory.error}`})`}`,
		`  limits      ${plan.limits.runSeconds}s per run, ${plan.limits.pointSeconds}s per point`,
		'',
		`points (${plan.counts.selected}):`,
		...(plan.points.length === 0 ? ['  none'] : []),
		...plan.points.map(
			(p) =>
				`  ${p.id}  r${p.revision}  ${p.why}${p.required ? '  [required]' : ''}${p.proof === 'none' ? '  (no proof)' : '  (proof unverified)'}`,
		),
		'',
		`blocked (${plan.counts.blocked}):`,
		...(plan.blocked.length === 0 ? ['  none'] : []),
		...plan.blocked.map((p) => `  ${p.id}  ${p.reason}`),
		'',
		`uncovered changes (${plan.counts.uncovered}):`,
		...(plan.uncovered.length === 0 ? ['  none'] : []),
		...plan.uncovered.map((u) => `  ${u}`),
		'',
		'notes:',
		...plan.notes.map((n) => `  ${n}`),
		'',
	];
	return textOutput(lines);
}

export function formatStatus(s: RunStatusReply): string {
	const ended = s.completion === undefined ? '' : `, ${s.completion}`;
	const outcome = s.outcome === undefined ? '' : `: ${s.outcome}`;
	const lines = [
		`run ${s.runId} of ${s.label}: ${s.state}${ended}${outcome}`,
		`  plan        ${s.planId}`,
		`  deployment  ${s.deployment.deploymentId}`,
		`  progress    ${s.progress.done} of ${s.progress.total} points`,
		`  evidence    ${s.evidence}${s.finalized ? ', finalized' : ''}`,
		`  freshness   ${s.freshness}`,
		`  readiness   ${s.readiness.eligibleForMergeGate ? 'eligible for a merge gate' : `not eligible: ${s.readiness.reasons.join('; ')}`}`,
		...(s.interruption === undefined ? [] : [`  interrupted ${s.interruption}`]),
		...(s.cancelRequested ? ['  cancel      requested'] : []),
		'',
		'points:',
		...(s.points.length === 0 ? ['  none'] : []),
		...s.points.map(
			(p) =>
				`  ${p.id}  ${p.outcome ?? p.state}${p.reason === undefined ? '' : `  ${p.reason}`}${p.evidence.length === 0 ? '' : `  [${p.evidence.join(', ')}]`}`,
		),
		'',
		`problems (${s.problemCount}):`,
		...(s.problems.length === 0 ? ['  none'] : []),
		...s.problems.map((p) => `  ${p.code}: ${p.detail}`),
		'',
	];
	return textOutput(lines);
}

export function formatExport(e: EvidenceExport): string {
	const lines = [
		`exported run ${e.runId} to ${e.out}${e.finalized ? '' : ' (not finalized)'}${e.expired ? ' (expired)' : ''}`,
		`  complete    ${e.complete ? 'yes' : 'no'}`,
		`  events      ${e.events.file === undefined ? 'unavailable' : `${e.events.count} in ${e.events.file}`}`,
		`  bytes       ${e.bytes}`,
		'',
		`artifacts (${e.artifacts.length}):`,
		...(e.artifacts.length === 0 ? ['  none'] : []),
		...e.artifacts.map(
			(a) =>
				`  ${a.id}  ${a.file ?? a.availability}${a.verified ? '  verified' : ''}${a.note === undefined ? '' : `  ${a.note}`}`,
		),
		...(e.missing.length === 0 ? [] : ['', 'missing:', ...e.missing.map((m) => `  ${m}`)]),
		...(e.notes.length === 0 ? [] : ['', 'notes:', ...e.notes.map((n) => `  ${n}`)]),
		'',
	];
	return textOutput(lines);
}
