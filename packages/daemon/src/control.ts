import { chmod, chown, readFile } from 'node:fs/promises';
import {
	ArtifactIdSchema,
	AttemptSchema,
	ByteCountSchema,
	deploymentIdentity,
	type HostInfo,
	IN_FLIGHT_STATUSES,
	IndexCursorSchema,
	LEASE_MAX_SECONDS,
	LeaseHolderSchema,
	LeaseIdSchema,
	type LeaseReply,
	LOG_TAIL_MAX_LINES,
	LOG_TEXT_MAX,
	LogOffsetSchema,
	NO_SUCH_PREVIEW,
	type PingReply,
	PlanCursorSchema,
	PlanRequestSchema,
	PreviewLabelSchema,
	type PreviewListPage,
	type PreviewRecord,
	type PreviewSummary,
	type ReleaseReply,
	RequestIdSchema,
	RunRequestSchema,
	type StatusReply,
	type UpAccepted,
	VERIFICATION_BODY_MAX_BYTES,
	VERIFICATION_ERROR_ISSUES_MAX,
	VERIFICATION_ERROR_MESSAGE_MAX,
	type VerificationErrorReply,
	VerifyIdSchema,
} from '@koi/shared';
import { ZodError, z } from 'zod';
import { BodyTimeoutError, BodyTooLargeError, readJson } from './body.ts';
import { type BuildLogs, fitJson } from './buildlog.ts';
import {
	CapacityError,
	type Deployer,
	LeaseError,
	NoSuchLeaseError,
	NoSuchPreviewError,
	OwnershipError,
	UnsupportedRequestError,
} from './deployer.ts';
import type { Docker } from './docker.ts';
import type { PreviewStore } from './store.ts';
import { UPLOAD_SERVER_BODY_LIMIT, type UploadApi } from './upload-api.ts';
import { type Verification, VerificationError } from './verification.ts';

export interface ControlDeps {
	deployer: Pick<Deployer, 'up' | 'down' | 'acquireLease' | 'releaseLease'>;
	store: Pick<PreviewStore, 'get' | 'list'>;
	docker: Pick<Docker, 'logs'>;
	buildLogs: Pick<BuildLogs, 'read' | 'tail'>;
	// Refreshes the activity stamp the idle timer reads (Activity.touch).
	keepAwake: () => Promise<void>;
	// This host's descriptor, for `koid ctl describe` (host-info.ts).
	describe: () => Promise<HostInfo>;
	// Serves /v1/uploads when uploads come through this socket (KOI_UPLOADS=
	// spool). Absent on AWS, where the CLI puts them in S3; the route then
	// answers 404.
	uploadApi?: Pick<UploadApi, 'handle'> | undefined;
	// Serves the verification routes (verification.ts). Absent in a koid
	// without the controller; the routes then answer 404.
	verification?: VerificationApi | undefined;
	limits?: Partial<ControlLimits> | undefined;
}

export type VerificationApi = Pick<
	Verification,
	'plan' | 'planPage' | 'start' | 'status' | 'events' | 'evidence' | 'artifact' | 'cancel'
>;

export interface ControlLimits {
	// The most a POST /up body may be. It carries a request id in JSON, but
	// the bound stays at what Bun refused with 413 before the upload API
	// raised the server's limit (Bun's default maxRequestBodySize), so the
	// route answers as it did.
	upBodyBytes: number;
	// A JSON body must arrive whole within this.
	bodyTimeoutMs: number;
}

export const CONTROL_LIMITS: ControlLimits = {
	upBodyBytes: 128 * 1024 ** 2,
	bodyTimeoutMs: 30_000,
};

const UpBodySchema = z.object({ requestId: RequestIdSchema });

const LeaseBodySchema = z.object({
	holder: LeaseHolderSchema,
	ttlSeconds: z.number().int().min(1).max(LEASE_MAX_SECONDS),
});

// The CLI reads replies through SSM, which keeps only the first 24,000
// characters of a command's output. A status reply carries at most
// STATUS_LOG_CHARS of build log and STATUS_ERROR_CHARS of error, so with the
// rest of the record it stays well under that. One with no log lines may
// carry the deployment's slice instead, at most MAX_DEPLOYMENT_SLICE_BYTES
// (16 KiB), which with the record and its error stays under it too. A list
// reply is at most LIST_PAGE_CHARS, and the CLI asks for the next page until
// it has them all.
const STATUS_MAX_LINES = 200;
const STATUS_LOG_CHARS = 12_000;
const STATUS_ERROR_CHARS = 2_000;
const LIST_PAGE_CHARS = 16_000;
// A branch name in a list reply is cut to this, so that any one preview fits
// in a page with room to spare. koi sends at most 255 characters.
const LIST_BRANCH_CHARS = 2_000;

export interface ControlOptions {
	// The group the socket is given once it exists, so that an account in
	// it can connect: the SSH gateway's koi-connect (host/ssh), which is in
	// koi-control. Without one the socket keeps koid's own group, and only
	// root and koi can open it, as before the gateway.
	gid?: number | undefined;
	// Where a group koid could not give the socket is reported.
	log?: ((message: string) => void) | undefined;
}

// The control API, on a unix socket only root, koi and the socket's group
// can open. `koid ctl` is its client; the CLI reaches it through an SSM
// command that runs `koid ctl ...` as root on the box, or over SSH through
// the gateway, which connects as koi-connect.
export async function startControlServer(
	socket: string,
	deps: ControlDeps,
	options: ControlOptions = {},
) {
	// With uploads: a body may be a 2 GiB archive, and it may take ten
	// minutes. Bun's idleTimeout cannot bound that and leave it room. On Bun
	// 1.4.0 over a unix socket, measured: it takes at most 255 seconds; it
	// runs from the request's start to its response, and body bytes arriving
	// do not reset it, so a slow upload dies at the limit however steadily
	// it sends; server.timeout(request, 0) does not lift it for a streaming
	// body; and it never closes a connection that has sent no headers, or
	// only part of them. So with uploads it is off, and every handler bounds
	// its own body read instead (body.ts): the control routes within
	// CONTROL_LIMITS, the upload API within UploadLimits. Bun's types say
	// idleTimeout does not apply to a Unix socket server, but the runtime
	// applies it there, default included, which is why the options are cast.
	// Without uploads the server runs as it always has.
	const serveOptions = {
		unix: socket,
		fetch: (request: Request) => control(request, deps),
		...(deps.uploadApi === undefined
			? {}
			: { maxRequestBodySize: UPLOAD_SERVER_BODY_LIMIT, idleTimeout: 0 }),
	};
	const server = Bun.serve(serveOptions as unknown as Parameters<typeof Bun.serve>[0]);
	// The group is set every time the socket is made, never assumed from
	// the directory, and before the mode opens the socket to that group. A
	// group koid may not give (it is not a member, as on a box provisioned
	// before the group) leaves the socket as it was, and koid running: the
	// SSH path then fails at the socket, and the log says why.
	if (options.gid !== undefined) {
		try {
			await chown(socket, -1, options.gid);
		} catch (err) {
			options.log?.(
				`control socket: could not give ${socket} the group ${options.gid}: ${err instanceof Error ? err.message : String(err)}; the SSH gateway's account cannot open it. Run scripts/provision-host.sh, which puts koi in the group`,
			);
		}
	}
	await chmod(socket, 0o660);
	return server;
}

// The id of the group `name` in the system's group file, or undefined when
// there is no such group (a workstation, or a box provisioned before the
// group existed).
export async function groupId(name: string, file = '/etc/group'): Promise<number | undefined> {
	let text: string;
	try {
		text = await readFile(file, 'utf8');
	} catch (err) {
		if (err instanceof Error && 'code' in err && err.code === 'ENOENT') return undefined;
		throw err;
	}
	for (const line of text.split('\n')) {
		const [group, , gid] = line.split(':');
		if (group === name && gid !== undefined && /^\d{1,10}$/.test(gid)) return Number(gid);
	}
	return undefined;
}

export async function control(request: Request, deps: ControlDeps): Promise<Response> {
	const url = new URL(request.url);
	const parts = url.pathname.split('/').filter((p) => p !== '');
	const limits = { ...CONTROL_LIMITS, ...deps.limits };
	// Every command is someone using the box: koi up following a build,
	// koi logs, a person on the box. A stamp that cannot be written does not
	// stop the command.
	await deps.keepAwake().catch(() => {});
	try {
		// The control socket listens only once startup is done (see main.ts), so
		// an answer here means koid takes commands.
		if (request.method === 'GET' && url.pathname === '/health') {
			return Response.json({ ok: true } satisfies PingReply);
		}
		if (request.method === 'GET' && url.pathname === '/host') {
			return Response.json(await deps.describe());
		}
		if (request.method === 'POST' && url.pathname === '/up') {
			const body = await readJson(request, UpBodySchema, limits.upBodyBytes, limits.bodyTimeoutMs);
			const accepted: UpAccepted = await deps.deployer.up(body.requestId);
			return Response.json(accepted, { status: 202 });
		}
		if (request.method === 'GET' && url.pathname === '/previews') {
			const raw = url.searchParams.get('after');
			const after = raw === null ? undefined : PreviewLabelSchema.parse(raw);
			return Response.json(listPage((await deps.store.list()).map(summary), after));
		}
		if (parts[0] === 'previews' && parts[1] !== undefined) {
			const label = PreviewLabelSchema.parse(parts[1]);
			if (request.method === 'GET' && parts.length === 2) {
				const rawAttempt = url.searchParams.get('attempt');
				const attempt = rawAttempt === null ? undefined : AttemptSchema.parse(rawAttempt);
				const raw = url.searchParams.get('since');
				const since = raw === null ? 0 : LogOffsetSchema.parse(raw);
				const record = await deps.store.get(label);
				if (record === undefined) return Response.json({ error: NO_SUCH_PREVIEW }, { status: 404 });
				// The lines come from the asked attempt's log alone, and none
				// without one. The record may be on a newer attempt; the caller
				// sees that from its attempt and requestId.
				const deployment = deploymentIdentity(record);
				const log =
					attempt === undefined
						? { next: 0, lines: [] }
						: await deps.buildLogs.read(label, attempt, since, STATUS_MAX_LINES, STATUS_LOG_CHARS);
				// The deployment's slice, at most MAX_DEPLOYMENT_SLICE_BYTES,
				// only in a reply with no log lines, which has room for it, and
				// not while a build is under way, when polls would carry the
				// previous deployment's on every read.
				const slice =
					deployment !== undefined &&
					log.lines.length === 0 &&
					!IN_FLIGHT_STATUSES.has(record.status)
						? record.deployment?.slice
						: undefined;
				const reply: StatusReply = {
					record: statusRecord(record),
					log,
					...(deployment !== undefined ? { deployment } : {}),
					...(slice !== undefined ? { slice } : {}),
				};
				return Response.json(reply);
			}
			if (request.method === 'POST' && parts[2] === 'lease' && parts.length === 3) {
				const body = await readJson(
					request,
					LeaseBodySchema,
					limits.upBodyBytes,
					limits.bodyTimeoutMs,
				);
				const reply: LeaseReply = await deps.deployer.acquireLease(
					label,
					body.holder,
					body.ttlSeconds,
				);
				return Response.json(reply);
			}
			if (request.method === 'DELETE' && parts[2] === 'lease' && parts.length === 4) {
				await deps.deployer.releaseLease(label, LeaseIdSchema.parse(parts[3]));
				return Response.json({ released: true } satisfies ReleaseReply);
			}
			if (request.method === 'GET' && parts[2] === 'logs' && parts.length === 3) {
				const record = await deps.store.get(label);
				const container = record?.deployment?.container;
				if (container === undefined)
					return Response.json({ error: 'nothing running' }, { status: 404 });
				return new Response(await deps.docker.logs(container, tailParam(url, 200)));
			}
			if (request.method === 'GET' && parts[2] === 'buildlog' && parts.length === 3) {
				const record = await deps.store.get(label);
				if (record === undefined) return Response.json({ error: NO_SUCH_PREVIEW }, { status: 404 });
				// The latest attempt's log: the build under way, or the last one.
				return new Response(
					await deps.buildLogs.tail(label, record.attempt, tailParam(url, 200), LOG_TEXT_MAX),
				);
			}
			if (request.method === 'DELETE' && parts.length === 2) {
				// ?force=1 removes the preview under a lease.
				const force = url.searchParams.get('force') === '1';
				const removed = await deps.deployer.down(label, { force });
				return Response.json({ removed }, { status: removed ? 200 : 404 });
			}
		}
		if (
			parts[0] === 'v1' &&
			(parts[1] === 'verification-plans' || parts[1] === 'verification-runs')
		) {
			return await verification(request, url, parts, deps, limits);
		}
		if (parts[0] === 'v1' && parts[1] === 'uploads') {
			if (deps.uploadApi === undefined) {
				return Response.json(
					{ error: 'uploads do not come through this socket; koid reads them from S3' },
					{ status: 404 },
				);
			}
			return await deps.uploadApi.handle(request, parts.slice(2));
		}
		return Response.json({ error: 'not found' }, { status: 404 });
	} catch (err) {
		if (err instanceof ZodError || err instanceof SyntaxError) {
			return Response.json({ error: 'bad request', detail: err.message }, { status: 400 });
		}
		if (err instanceof BodyTooLargeError) {
			return Response.json(
				{ error: `the request is over ${limits.upBodyBytes} bytes` },
				{ status: 413 },
			);
		}
		if (err instanceof BodyTimeoutError) {
			return Response.json(
				{ error: `the request did not arrive within ${limits.bodyTimeoutMs / 1000} seconds` },
				{ status: 408 },
			);
		}
		if (err instanceof OwnershipError || err instanceof LeaseError) {
			return Response.json({ error: err.message }, { status: 409 });
		}
		if (err instanceof NoSuchPreviewError || err instanceof NoSuchLeaseError) {
			return Response.json({ error: err.message }, { status: 404 });
		}
		if (err instanceof UnsupportedRequestError) {
			return Response.json({ error: err.message }, { status: 400 });
		}
		if (err instanceof CapacityError) return Response.json({ error: err.message }, { status: 507 });
		return Response.json(
			{ error: err instanceof Error ? err.message : String(err) },
			{ status: 500 },
		);
	}
}

// The verification routes (docs/verify.md, "Running a verification"), with
// the versioned error shape of their own: {version, error: {code, message,
// retryable}}. The controller does the work; this maps paths and errors.
// An error reply is bounded like every other reply the CLI reads through
// SSM: its message is cut to VERIFICATION_ERROR_MESSAGE_MAX, and a
// validation error names its first VERIFICATION_ERROR_ISSUES_MAX issues,
// since zod's own message for a body of 64 KiB can run to hundreds of
// kilobytes.
async function verification(
	request: Request,
	url: URL,
	parts: string[],
	deps: ControlDeps,
	limits: ControlLimits,
): Promise<Response> {
	const api = deps.verification;
	const error = (status: number, code: string, message: string, retryable = false) =>
		Response.json(
			{
				version: 1,
				error: { code, message: fitJson(message, VERIFICATION_ERROR_MESSAGE_MAX), retryable },
			} satisfies VerificationErrorReply,
			{ status },
		);
	if (api === undefined) {
		return error(404, 'verification_unavailable', 'this koid has no verification controller');
	}
	const { method } = request;
	try {
		if (parts[1] === 'verification-plans') {
			if (method === 'POST' && parts.length === 2) {
				const body = await readJson(
					request,
					PlanRequestSchema,
					VERIFICATION_BODY_MAX_BYTES,
					limits.bodyTimeoutMs,
				);
				return Response.json(await api.plan(body), { status: 201 });
			}
			if (method === 'GET' && parts.length === 3) {
				const planId = VerifyIdSchema.parse(parts[2]);
				const raw = url.searchParams.get('after');
				const after = raw === null ? undefined : PlanCursorSchema.parse(raw);
				return Response.json(await api.planPage(planId, after));
			}
			return error(404, 'not_found', 'no such route');
		}
		if (method === 'POST' && parts.length === 2) {
			const body = await readJson(
				request,
				RunRequestSchema,
				VERIFICATION_BODY_MAX_BYTES,
				limits.bodyTimeoutMs,
			);
			return Response.json(await api.start(body), { status: 202 });
		}
		const runId = VerifyIdSchema.parse(parts[2]);
		const index = (name: string, fallback: number) => {
			const raw = url.searchParams.get(name);
			return raw === null ? fallback : IndexCursorSchema.parse(raw);
		};
		if (method === 'GET' && parts[3] === 'status' && parts.length === 4) {
			return Response.json(await api.status(runId, index('after', 0)));
		}
		if (method === 'GET' && parts[3] === 'events' && parts.length === 4) {
			const raw = url.searchParams.get('limit');
			const limit = raw === null ? undefined : IndexCursorSchema.parse(raw);
			return Response.json(await api.events(runId, index('after', 0), limit));
		}
		if (method === 'GET' && parts[3] === 'evidence' && parts.length === 4) {
			return Response.json(await api.evidence(runId, index('after', 0)));
		}
		if (method === 'GET' && parts[3] === 'artifacts' && parts.length === 5) {
			const artifact = ArtifactIdSchema.parse(decodeURIComponent(parts[4] ?? ''));
			const rawOffset = url.searchParams.get('offset');
			const rawLength = url.searchParams.get('length');
			return Response.json(
				await api.artifact(
					runId,
					artifact,
					rawOffset === null ? 0 : ByteCountSchema.parse(rawOffset),
					rawLength === null ? undefined : ByteCountSchema.parse(rawLength),
				),
			);
		}
		if (method === 'POST' && parts[3] === 'cancel' && parts.length === 4) {
			return Response.json(await api.cancel(runId), { status: 202 });
		}
		return error(404, 'not_found', 'no such route');
	} catch (err) {
		if (err instanceof VerificationError) {
			return error(err.status, err.code, err.message, err.retryable);
		}
		if (err instanceof ZodError) return error(400, 'invalid_request', issuesText(err));
		if (err instanceof SyntaxError) return error(400, 'invalid_request', err.message);
		if (err instanceof BodyTooLargeError) {
			return error(
				413,
				'body_too_large',
				`the request is over ${VERIFICATION_BODY_MAX_BYTES} bytes`,
			);
		}
		if (err instanceof BodyTimeoutError) {
			return error(
				408,
				'body_timeout',
				`the request did not arrive within ${limits.bodyTimeoutMs / 1000} seconds`,
				true,
			);
		}
		if (err instanceof LeaseError) return error(409, 'lease_refused', err.message);
		if (err instanceof NoSuchPreviewError) return error(404, 'no_such_preview', err.message);
		if (err instanceof NoSuchLeaseError) return error(404, 'no_such_lease', err.message);
		return error(500, 'internal', err instanceof Error ? err.message : String(err));
	}
}

// A validation error as one line per issue, the first
// VERIFICATION_ERROR_ISSUES_MAX of them, and the count of the rest.
function issuesText(err: ZodError): string {
	const issues = err.issues.slice(0, VERIFICATION_ERROR_ISSUES_MAX);
	const lines = issues.map((i) => `${i.path.join('.') || 'the request'}: ${i.message}`);
	const rest = err.issues.length - issues.length;
	if (rest > 0) lines.push(`and ${rest} more issue${rest === 1 ? '' : 's'}`);
	return lines.join('; ');
}

function summary(r: PreviewRecord): PreviewSummary {
	const deployment = deploymentIdentity(r);
	return {
		label: r.label,
		status: r.status,
		commit: r.commit,
		branch: fitJson(r.branch, LIST_BRANCH_CHARS),
		...(r.pr !== undefined ? { pr: r.pr } : {}),
		...(r.lastVisitAt !== undefined ? { lastVisitAt: r.lastVisitAt } : {}),
		updatedAt: r.updatedAt,
		...(deployment !== undefined ? { deployment } : {}),
	};
}

// The previews after `after` in label order, as many as fit in
// LIST_PAGE_CHARS with the reply around them, and always at least one.
// Counted in UTF-8 bytes, like jsonSize.
function listPage(all: PreviewSummary[], after: string | undefined): PreviewListPage {
	const rest = all
		.filter((s) => after === undefined || s.label > after)
		.sort((a, b) => (a.label < b.label ? -1 : 1));
	// The reply with no previews and the longest `next` a label can be.
	let used = jsonBytes({ previews: [], next: 'x'.repeat(63) });
	const previews: PreviewSummary[] = [];
	for (const s of rest) {
		// A preview costs its JSON and a comma.
		const size = jsonBytes(s) + 1;
		if (previews.length > 0 && used + size > LIST_PAGE_CHARS) break;
		previews.push(s);
		used += size;
	}
	const last = previews.at(-1);
	return last !== undefined && previews.length < rest.length
		? { previews, next: last.label }
		: { previews };
}

function jsonBytes(value: unknown): number {
	return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function statusRecord(record: PreviewRecord): StatusReply['record'] {
	const { deployment: _deployment, ...rest } = record;
	return rest.error === undefined
		? rest
		: { ...rest, error: fitJson(rest.error, STATUS_ERROR_CHARS) };
}

function tailParam(url: URL, fallback: number): number {
	const raw = url.searchParams.get('tail');
	const n = raw === null ? fallback : Number.parseInt(raw, 10);
	return Number.isInteger(n) && n > 0 ? Math.min(n, LOG_TAIL_MAX_LINES) : fallback;
}
