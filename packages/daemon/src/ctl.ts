import {
	ARTIFACT_CHUNK_BYTES,
	ArtifactIdSchema,
	AttemptSchema,
	ByteCountSchema,
	CTL_EXIT,
	DigestSchema,
	decodeCtlArgs,
	EVENTS_PAGE_MAX,
	IndexCursorSchema,
	LEASE_MAX_SECONDS,
	LeaseHolderSchema,
	LeaseIdSchema,
	LOG_TAIL_MAX_LINES,
	LOG_TEXT_MAX,
	LogOffsetSchema,
	PlanCursorSchema,
	PlanRequestSchema,
	PreviewLabelSchema,
	RequestIdSchema,
	RunRequestSchema,
	SlugSchema,
	VerifyIdSchema,
} from '@koi/shared';
import { keepEnd } from './buildlog.ts';

// `koid ctl <command>`: the client for the control socket. The CLI runs it on
// the box through SSM as `koid ctl-b64 <blob>`, with the arguments encoded
// (see ctlEncoded). Arguments are validated before anything is sent, and
// output is the server's JSON (or log text) on stdout.
//
// It exits with CTL_EXIT: refused when koid answered with an error,
// unavailable when koid did not answer.
//
// SSM returns only the first 24,000 characters of a command's output. The
// JSON replies are bounded by the server; log text is cut here to its last
// LOG_TEXT_MAX characters.
export const CTL_USAGE = `usage: koid ctl <command>
  ping                     prints {"ok":true} once koid takes commands
  describe                 the host descriptor: protocol, host id, domain, address
                           and capabilities, for the CLI to check its target
  up <request-id>          build and run the request uploaded under that id
  list [after]             list previews in label order: label, status, commit,
                           branch, pr and times. A page of at most 16000
                           characters, with "next" when more follow; pass
                           it as <after> for the next page
  status <label> [attempt [offset]]
                           a preview's record and, with an attempt, that
                           attempt's build log: whole lines from byte
                           <offset> (default 0), with "next", the offset to
                           ask for next
  logs <label> [lines]     the tail of a preview's container log: at most
                           ${LOG_TAIL_MAX_LINES} lines and 16000 characters
  buildlog <label> [lines] the tail of the build log of a preview's latest
                           attempt: at most ${LOG_TAIL_MAX_LINES} lines and 16000 characters
  lease <label> --holder <text> --ttl-seconds <n>
                           hold a preview so no build replaces what serves
                           and down needs --force, for at most ${LEASE_MAX_SECONDS}
                           seconds; prints the lease and the deployment it
                           holds. Refused while another lease holds, while
                           the label builds, or when nothing serves
  release <label> <lease-id>
                           end a lease
  down <label> [--force]   remove a preview; --force removes a leased one
  verify plan <label> --profile <name>
                           plan a verification of what serves under the label:
                           the points taken and why, the ones blocked and why,
                           and the changed files no point covers. A page; pass
                           "next" to verify plan-page for the rest
  verify plan-page <plan-id> [cursor]
                           the rest of a plan, from the cursor
  verify run <plan-id> <plan-digest>
                           start a run of the plan: takes the lease, starts the
                           recorder, and answers at once with the run id
  verify status <run-id> [after]
                           the run's state, outcome and points, a page at a time
  verify events <run-id> [after [limit]]
                           the run's events after a sequence number, at most
                           ${EVENTS_PAGE_MAX} and 16 KiB a page
  verify evidence <run-id> [after]
                           the run's manifest and a page of its artifacts
  verify artifact <run-id> <artifact-id> [offset [length]]
                           at most ${ARTIFACT_CHUNK_BYTES} sanitized bytes of a finalized
                           artifact, as base64, with the offset of the rest
  verify cancel <run-id>   stop a run; its status says when it has stopped
`;

export interface CtlIo {
	stdout: (text: string) => void;
	stderr: (text: string) => void;
	fetch: (path: string, init?: RequestInit) => Promise<Response>;
}

export function socketFetch(socket: string): CtlIo['fetch'] {
	return (path, init) => fetch(`http://koid${path}`, { ...init, unix: socket } as RequestInit);
}

export async function ctl(args: string[], io: CtlIo): Promise<number> {
	const [command, arg, extra] = args;
	let path: string;
	let init: RequestInit = {};
	let logText = false;
	try {
		switch (command) {
			case 'ping':
				// koid answers at once when it is up; a hung one counts as not ready.
				path = '/health';
				init = { signal: AbortSignal.timeout(10_000) };
				break;
			case 'describe':
				path = '/host';
				break;
			case 'up':
				path = '/up';
				init = {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ requestId: RequestIdSchema.parse(arg) }),
				};
				break;
			case 'list':
				path = arg === undefined ? '/previews' : `/previews?after=${PreviewLabelSchema.parse(arg)}`;
				break;
			case 'status': {
				const label = PreviewLabelSchema.parse(arg);
				const offset = args[3];
				path =
					extra === undefined
						? `/previews/${label}`
						: offset === undefined
							? `/previews/${label}?attempt=${AttemptSchema.parse(extra)}`
							: `/previews/${label}?attempt=${AttemptSchema.parse(extra)}&since=${LogOffsetSchema.parse(offset)}`;
				break;
			}
			case 'logs':
			case 'buildlog': {
				const lines = extra === undefined ? 200 : Number.parseInt(extra, 10);
				if (!Number.isInteger(lines) || lines <= 0 || lines > LOG_TAIL_MAX_LINES)
					throw new Error(`lines must be 1 to ${LOG_TAIL_MAX_LINES}`);
				path = `/previews/${PreviewLabelSchema.parse(arg)}/${command}?tail=${lines}`;
				logText = true;
				break;
			}
			case 'lease': {
				const label = PreviewLabelSchema.parse(arg);
				const flags = parseFlags(args.slice(2), ['--holder', '--ttl-seconds']);
				const holder = LeaseHolderSchema.parse(flags['--holder']);
				const ttl = flags['--ttl-seconds'] ?? '';
				if (!/^[1-9][0-9]{0,8}$/.test(ttl) || Number(ttl) > LEASE_MAX_SECONDS) {
					throw new Error(`--ttl-seconds expects 1 to ${LEASE_MAX_SECONDS}`);
				}
				path = `/previews/${label}/lease`;
				init = {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ holder, ttlSeconds: Number(ttl) }),
				};
				break;
			}
			case 'release':
				path = `/previews/${PreviewLabelSchema.parse(arg)}/lease/${LeaseIdSchema.parse(extra)}`;
				init = { method: 'DELETE' };
				break;
			case 'down': {
				const label = PreviewLabelSchema.parse(arg);
				if (args.length > 3 || (extra !== undefined && extra !== '--force')) {
					throw new Error('down takes a label and, at most, --force');
				}
				path = extra === '--force' ? `/previews/${label}?force=1` : `/previews/${label}`;
				init = { method: 'DELETE' };
				break;
			}
			case 'verify': {
				const mapped = verifyCommand(args.slice(1));
				path = mapped.path;
				init = mapped.init;
				break;
			}
			default:
				io.stderr(CTL_USAGE);
				return 2;
		}
	} catch (err) {
		io.stderr(`koid ctl: ${err instanceof Error ? err.message : String(err)}\n${CTL_USAGE}`);
		return 2;
	}
	let res: Response;
	try {
		res = await io.fetch(path, init);
	} catch (err) {
		io.stderr(`koid ctl: cannot reach koid: ${err instanceof Error ? err.message : String(err)}\n`);
		return CTL_EXIT.unavailable;
	}
	const body = await res.text();
	const text = body.endsWith('\n') ? body : `${body}\n`;
	(res.ok ? io.stdout : io.stderr)(res.ok && logText ? keepEnd(text, LOG_TEXT_MAX) : text);
	return res.ok ? CTL_EXIT.ok : CTL_EXIT.refused;
}

// The verify subcommands as control routes. Every argument is checked here
// against the shared schema the route reads, so a wrong one fails before
// anything is sent.
function verifyCommand(args: string[]): { path: string; init: RequestInit } {
	const [sub, first, second, third, fourth] = args;
	const post = (body: unknown): RequestInit => ({
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(body),
	});
	const count = (most: number) => {
		if (args.length > most) throw new Error(`verify ${sub} takes at most ${most - 1} arguments`);
	};
	switch (sub) {
		case 'plan': {
			const label = PreviewLabelSchema.parse(first);
			const flags = parseFlags(args.slice(2), ['--profile']);
			const body = PlanRequestSchema.parse({
				version: 1,
				label,
				profile: SlugSchema.parse(flags['--profile']),
			});
			return { path: '/v1/verification-plans', init: post(body) };
		}
		case 'plan-page': {
			count(3);
			const planId = VerifyIdSchema.parse(first);
			return {
				path:
					second === undefined
						? `/v1/verification-plans/${planId}`
						: `/v1/verification-plans/${planId}?after=${PlanCursorSchema.parse(second)}`,
				init: {},
			};
		}
		case 'run': {
			count(3);
			const body = RunRequestSchema.parse({
				version: 1,
				planId: VerifyIdSchema.parse(first),
				planDigest: DigestSchema.parse(second),
				mode: 'runner',
			});
			return { path: '/v1/verification-runs', init: post(body) };
		}
		case 'status':
		case 'evidence': {
			count(3);
			const runId = VerifyIdSchema.parse(first);
			const after = second === undefined ? '' : `?after=${IndexCursorSchema.parse(second)}`;
			return { path: `/v1/verification-runs/${runId}/${sub}${after}`, init: {} };
		}
		case 'events': {
			count(4);
			const runId = VerifyIdSchema.parse(first);
			const after = second === undefined ? 0 : IndexCursorSchema.parse(second);
			const limit = third === undefined ? EVENTS_PAGE_MAX : IndexCursorSchema.parse(third);
			if (limit < 1 || limit > EVENTS_PAGE_MAX) {
				throw new Error(`limit must be 1 to ${EVENTS_PAGE_MAX}`);
			}
			return {
				path: `/v1/verification-runs/${runId}/events?after=${after}&limit=${limit}`,
				init: {},
			};
		}
		case 'artifact': {
			count(5);
			const runId = VerifyIdSchema.parse(first);
			const artifact = ArtifactIdSchema.parse(second);
			const offset = third === undefined ? 0 : ByteCountSchema.parse(third);
			const length = fourth === undefined ? ARTIFACT_CHUNK_BYTES : ByteCountSchema.parse(fourth);
			if (length < 1 || length > ARTIFACT_CHUNK_BYTES) {
				throw new Error(`length must be 1 to ${ARTIFACT_CHUNK_BYTES}`);
			}
			return {
				path: `/v1/verification-runs/${runId}/artifacts/${encodeURIComponent(artifact)}?offset=${offset}&length=${length}`,
				init: {},
			};
		}
		case 'cancel': {
			count(2);
			const runId = VerifyIdSchema.parse(first);
			return { path: `/v1/verification-runs/${runId}/cancel`, init: { method: 'POST' } };
		}
		default:
			throw new Error(
				'verify takes plan, plan-page, run, status, events, evidence, artifact or cancel',
			);
	}
}

// `--flag value` pairs from `args`, each flag from `known` at most once, with
// every known flag present. Anything else is an error.
function parseFlags(args: string[], known: string[]): Record<string, string> {
	const flags: Record<string, string> = {};
	for (let i = 0; i < args.length; i += 2) {
		const flag = args[i] ?? '';
		const value = args[i + 1];
		if (!known.includes(flag)) throw new Error(`unexpected argument ${JSON.stringify(flag)}`);
		if (value === undefined) throw new Error(`${flag} needs a value`);
		if (flag in flags) throw new Error(`${flag} given twice`);
		flags[flag] = value;
	}
	for (const flag of known) {
		if (!(flag in flags)) throw new Error(`${flag} is required`);
	}
	return flags;
}

// `koid ctl-b64 <blob>`: koid ctl with the arguments encoded by the CLI's
// encodeCtlArgs, so that the shell running the SSM command sees only base64.
// A blob that does not decode to a list of arguments is refused like a bad
// argument.
export async function ctlEncoded(args: string[], io: CtlIo): Promise<number> {
	let decoded: string[];
	try {
		const [blob, ...rest] = args;
		if (blob === undefined || rest.length > 0) throw new Error('expected one argument');
		decoded = decodeCtlArgs(blob);
	} catch (err) {
		io.stderr(`koid ctl-b64: ${err instanceof Error ? err.message : String(err)}\n`);
		return CTL_EXIT.usage;
	}
	return ctl(decoded, io);
}
