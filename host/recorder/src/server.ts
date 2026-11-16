import { createHash, timingSafeEqual } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { Broker, BrokerError, healthReply } from './broker.ts';
import { CaptureError, CaptureStore } from './captures.ts';
import { EventLog } from './events.ts';
import { parseOrigin } from './origin.ts';
import { startProxy } from './proxy.ts';

// The recorder of one verification run (docs/verify.md, "Recorder and
// evidence"). koid starts it inside the run's private network with the run
// id, the app's private URL and two tokens in its environment, and talks to
// it on TCP 4318; the verifier connects to the browser on TCP 4317 with the
// other token. Nothing is written to stdout or stderr: the container has no
// log driver, and capture data must never go through one anyway. What the
// recorder has to say goes into its event feed, which koid reads.
//
// Control API, every request with `Authorization: Bearer <control token>`:
//   GET    /health                          what runs, or 503 with the reason while
//                                           starting and once the browser or the
//                                           guard's connection is lost
//   POST   /contexts                        {pointId, attempt, open?} -> {contextId, pageId, url}
//   DELETE /contexts/:id                    closes the point's context
//   POST   /contexts/:id/captures           {kind, label, pageId?} -> a capture record
//   POST   /contexts/:id/reads              {method, path, maxBodyBytes} -> a capture record
//   GET    /captures/:id                    the raw bytes, from memory
//   DELETE /captures/:id                    koid's acknowledgment; the bytes go
//   GET    /events?after=N&limit=M          {events, next, dropped}
// Errors are {error, code} with the status that fits.

const CONTROL_PORT = 4318;
const BROWSER_PORT = 4317;
const STATE_DIR = '/tmp/koi-recorder';
const MAX_BODY_BYTES = 64 * 1024;
const EVENT_CAPACITY = 20_000;
// Raw captures live in this process's memory until koid acknowledges them
// (captures.ts), never under /tmp, which the browser shares.
const CAPTURE_LIMITS = { perCapture: 32 * 1024 ** 2, total: 256 * 1024 ** 2 };

class ApiError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string,
	) {
		super(message);
	}
}

interface Settings {
	runId: string;
	previewUrl: string;
	controlToken: string;
	browserToken: string;
}

// The settings koid passes in the environment. The tokens are read once and
// removed, so no child process inherits them.
function settings(env: NodeJS.ProcessEnv): Settings {
	const take = (name: string): string => {
		const value = env[name];
		if (value === undefined || value === '') throw new Error(`${name} is not set`);
		return value;
	};
	const result = {
		runId: take('KOI_RUN_ID'),
		previewUrl: take('KOI_PREVIEW_URL'),
		controlToken: take('KOI_RECORDER_CONTROL_TOKEN'),
		browserToken: take('KOI_RECORDER_BROWSER_TOKEN'),
	};
	for (const name of ['KOI_RECORDER_CONTROL_TOKEN', 'KOI_RECORDER_BROWSER_TOKEN']) delete env[name];
	if (!/^[0-9a-f]{32,128}$/.test(result.controlToken)) {
		throw new Error('KOI_RECORDER_CONTROL_TOKEN is not a hex token');
	}
	if (!/^[0-9a-f]{32,128}$/.test(result.browserToken)) {
		throw new Error('KOI_RECORDER_BROWSER_TOKEN is not a hex token');
	}
	return result;
}

function bearerMatches(header: string | undefined, token: string): boolean {
	if (header === undefined || !header.startsWith('Bearer ')) return false;
	const a = createHash('sha256').update(header.slice('Bearer '.length)).digest();
	const b = createHash('sha256').update(token).digest();
	return timingSafeEqual(a, b);
}

function json(res: ServerResponse, status: number, body: unknown): void {
	const text = JSON.stringify(body);
	res.writeHead(status, {
		'content-type': 'application/json',
		'content-length': Buffer.byteLength(text),
		'cache-control': 'no-store',
	});
	res.end(text);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
	const chunks: Buffer[] = [];
	let size = 0;
	for await (const chunk of req) {
		size += (chunk as Buffer).length;
		if (size > MAX_BODY_BYTES) throw new ApiError(413, 'body_too_large', 'the body is too large');
		chunks.push(chunk as Buffer);
	}
	if (size === 0) return {};
	let parsed: unknown;
	try {
		parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
	} catch {
		throw new ApiError(400, 'bad_json', 'the body is not JSON');
	}
	if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
		throw new ApiError(400, 'bad_json', 'the body is not an object');
	}
	return parsed as Record<string, unknown>;
}

function expectString(body: Record<string, unknown>, field: string, pattern: RegExp): string {
	const value = body[field];
	if (typeof value !== 'string' || !pattern.test(value)) {
		throw new ApiError(400, 'bad_request', `${field} is missing or malformed`);
	}
	return value;
}

function expectInt(body: Record<string, unknown>, field: string, min: number, max: number): number {
	const value = body[field];
	if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
		throw new ApiError(400, 'bad_request', `${field} is missing or out of range`);
	}
	return value;
}

const POINT_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)*$/;
const LABEL = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const OBJECT_ID = /^[a-z][0-9]+$/;
const CAPTURE_ID = /^c[1-9][0-9]*$/;
const PATH = /^\/[^\s]{0,2047}$/;

async function main(): Promise<void> {
	const config = settings(process.env);
	const origin = parseOrigin(config.previewUrl);
	const events = new EventLog(EVENT_CAPACITY);
	const captures = new CaptureStore(CAPTURE_LIMITS);
	const home = join(STATE_DIR, 'home');
	await mkdir(join(home, 'downloads'), { recursive: true, mode: 0o700 });
	let broker: Broker | undefined;
	let startupError: string | undefined;

	const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
		if (!bearerMatches(req.headers.authorization, config.controlToken)) {
			events.push('control-rejected', { reason: 'wrong token' });
			throw new ApiError(401, 'unauthorized', 'unauthorized');
		}
		const url = new URL(req.url ?? '/', 'http://recorder');
		const path = url.pathname;
		const method = req.method ?? 'GET';

		if (method === 'GET' && path === '/health') {
			const { status, body } = healthReply(broker, startupError, {
				runId: config.runId,
				origin,
				captures,
				events,
				playwright: playwrightVersion(),
			});
			json(res, status, body);
			return;
		}
		if (method === 'GET' && path === '/events') {
			const after = Number(url.searchParams.get('after') ?? '0');
			const limit = Number(url.searchParams.get('limit') ?? '500');
			if (!Number.isInteger(after) || after < 0 || !Number.isInteger(limit) || limit < 1) {
				throw new ApiError(400, 'bad_request', 'after and limit must be whole numbers');
			}
			json(res, 200, events.page(after, Math.min(limit, 1000)));
			return;
		}
		const captureMatch = /^\/captures\/([^/]+)$/.exec(path);
		if (captureMatch !== null) {
			const id = captureMatch[1] ?? '';
			if (!CAPTURE_ID.test(id)) throw new ApiError(404, 'no_capture', 'no such capture');
			if (method === 'GET') {
				const stored = captures.get(id);
				if (stored === undefined) throw new ApiError(404, 'no_capture', 'no such capture');
				res.writeHead(200, {
					'content-type': 'application/octet-stream',
					'content-length': stored.size,
					'cache-control': 'no-store',
				});
				res.end(Buffer.from(stored.bytes));
				return;
			}
			if (method === 'DELETE') {
				const deleted = captures.delete(id);
				if (!deleted) throw new ApiError(404, 'no_capture', 'no such capture');
				events.push('capture-acknowledged', { captureId: id });
				json(res, 200, { deleted: true });
				return;
			}
		}
		if (broker === undefined) {
			throw new ApiError(503, 'not_ready', startupError ?? 'the browser is starting');
		}
		if (method === 'POST' && path === '/contexts') {
			const body = await readJson(req);
			const pointId = expectString(body, 'pointId', POINT_ID);
			const attempt = expectInt(body, 'attempt', 1, 1_000_000);
			const open = body.open === undefined ? undefined : expectString(body, 'open', PATH);
			const made = await broker.openContext({
				pointId,
				attempt,
				...(open !== undefined ? { open } : {}),
			});
			json(res, 201, made);
			return;
		}
		const contextMatch = /^\/contexts\/([^/]+)(?:\/(captures|reads))?$/.exec(path);
		if (contextMatch !== null) {
			const contextId = contextMatch[1] ?? '';
			if (!OBJECT_ID.test(contextId)) throw new ApiError(404, 'no_context', 'no such context');
			const sub = contextMatch[2];
			if (method === 'DELETE' && sub === undefined) {
				await broker.closeContext(contextId);
				json(res, 200, { closed: true });
				return;
			}
			if (method === 'POST' && sub === 'captures') {
				const body = await readJson(req);
				const kind = expectString(body, 'kind', /^(screenshot|aria|console|network)$/);
				const label = expectString(body, 'label', LABEL);
				const pageId =
					body.pageId === undefined ? undefined : expectString(body, 'pageId', OBJECT_ID);
				json(
					res,
					201,
					await broker.capture(contextId, {
						kind,
						label,
						...(pageId !== undefined ? { pageId } : {}),
					}),
				);
				return;
			}
			if (method === 'POST' && sub === 'reads') {
				const body = await readJson(req);
				const readMethod = expectString(body, 'method', /^(GET|HEAD)$/) as 'GET' | 'HEAD';
				const readPath = expectString(body, 'path', PATH);
				const maxBodyBytes = expectInt(body, 'maxBodyBytes', 0, 4 * 1024 ** 2);
				json(
					res,
					201,
					await broker.read(contextId, { method: readMethod, path: readPath, maxBodyBytes }),
				);
				return;
			}
		}
		throw new ApiError(404, 'not_found', 'not found');
	};

	const control = createServer((req, res) => {
		handle(req, res).catch((err: unknown) => {
			if (res.headersSent) {
				res.destroy();
				return;
			}
			if (err instanceof ApiError) {
				json(res, err.status, { error: err.message, code: err.code });
			} else if (err instanceof BrokerError) {
				json(res, err.status, { error: err.message, code: err.code });
			} else if (err instanceof CaptureError) {
				json(res, err.code === 'capture_space' ? 507 : 413, { error: err.message, code: err.code });
			} else {
				// The message may carry page content; the feed gets the fact.
				events.push('recorder-error', { route: req.url ?? '' });
				json(res, 500, { error: 'the recorder failed', code: 'internal' });
			}
		});
	});
	control.requestTimeout = 120_000;
	await new Promise<void>((resolve, reject) => {
		control.once('error', reject);
		control.listen(CONTROL_PORT, '0.0.0.0', () => resolve());
	});

	const browserEnv = {
		PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
		HOME: home,
		TMPDIR: '/tmp',
		LANG: 'C.UTF-8',
		LC_ALL: 'C.UTF-8',
		XDG_CONFIG_HOME: join(home, '.config'),
		XDG_CACHE_HOME: join(home, '.cache'),
	};
	let proxy: Awaited<ReturnType<typeof startProxy>> | undefined;
	try {
		const launched = await Broker.launch({
			runId: config.runId,
			origin,
			captures,
			events,
			home,
			browserEnv,
		});
		proxy = await startProxy({
			port: BROWSER_PORT,
			token: config.browserToken,
			upstream: () => launched.cdp,
			ownsContext: (id) => launched.ownsContext(id),
			origin,
			events,
		});
		broker = launched;
		events.push('recorder-ready', { browser: launched.version });
	} catch (err) {
		startupError = `the browser did not start: ${err instanceof Error ? err.message : String(err)}`;
		events.push('recorder-failed', { reason: startupError });
	}

	const shutdown = () => {
		const done = () => process.exit(0);
		setTimeout(done, 10_000).unref();
		control.close();
		proxy?.close();
		(broker?.close() ?? Promise.resolve()).then(done, done);
	};
	process.once('SIGTERM', shutdown);
	process.once('SIGINT', shutdown);
}

// The package's version is the browser contract koid records.
function playwrightVersion(): string {
	try {
		const load = createRequire(import.meta.url);
		return (load('playwright-core/package.json') as { version: string }).version;
	} catch {
		return 'unknown';
	}
}

main().catch(() => {
	process.exit(1);
});
