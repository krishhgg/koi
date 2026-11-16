import {
	type ArtifactKind,
	canonicalDigest,
	RecorderDroppedLineSchema,
	RecorderNetworkRecordSchema,
	RecorderStateReadSchema,
} from '@koi/shared';
import {
	LineScrubber,
	PngError,
	REDACTION_POLICY_VERSION,
	type SecretRegistry,
	stripPngMetadata,
	TEXT_LIMITATIONS,
} from './redact.ts';

// What koid does to each kind of capture between reading it from the
// recorder and keeping it (docs/verify.md, "Recorder and evidence"). The
// policy for a kind is fixed here and hashed into every artifact's
// policyDigest, so a reader can tell which policy ran. A capture the
// sanitizer cannot account for (a PNG that is not well formed, a record it
// does not recognise) throws SanitizeError, and the caller withholds the
// artifact: no payload, and no usable evidence reference.

export class SanitizeError extends Error {}

// Kinds the API accepts and this version always withholds, with the reason
// the manifest gives.
export const WITHHELD_KINDS: Readonly<Record<'trace' | 'har' | 'file', string>> = {
	trace:
		'Playwright traces are not sanitized in this version: the archive holds actions, snapshots, resources and sources that are not yet accounted for entry by entry',
	har: 'HAR files are not sanitized in this version: they hold every header and body of the session',
	file: 'files are not accepted in this version: only captures the recorder makes have a sanitizer',
};

export function isWithheldKind(kind: ArtifactKind): kind is keyof typeof WITHHELD_KINDS {
	return kind in WITHHELD_KINDS;
}

// The response headers a network record or a state read keeps. Everything
// else goes: Set-Cookie, Authorization echoes, provider headers and
// whatever the app invents.
export const RESPONSE_HEADER_ALLOWLIST: readonly string[] = [
	'content-type',
	'content-length',
	'content-encoding',
	'cache-control',
	'location',
	'date',
	'x-request-id',
];

// What each kind's sanitizer cannot promise. Copied into the artifact's
// manifest entry.
export const LIMITATIONS: Readonly<Record<ArtifactKind, readonly string[]>> = {
	screenshot: [
		'pixels may contain unknown application data; only password fields were masked before capture',
		'PNG metadata chunks were removed; the image data itself was not inspected',
	],
	aria: [
		...TEXT_LIMITATIONS,
		'accessibility names and values are application text; an unknown secret shown on the page stays',
	],
	console: TEXT_LIMITATIONS,
	network: [
		...TEXT_LIMITATIONS,
		'request headers and every body are omitted; response headers are reduced to an allowlist; URLs are scrubbed by pattern',
	],
	'http-response': [
		...TEXT_LIMITATIONS,
		'response headers are reduced to an allowlist; the body is kept only when the point policy asks for it, within its bound, and only as scrubbed text',
	],
	trace: [WITHHELD_KINDS.trace],
	har: [WITHHELD_KINDS.har],
	file: [WITHHELD_KINDS.file],
};

// The policy of each kind in words, for the digest.
const POLICIES: Readonly<Record<ArtifactKind, readonly string[]>> = {
	screenshot: [
		'refuse a PNG without one 13-byte IHDR first, an IDAT and an empty IEND last, or with a bad CRC',
		'strip every PNG chunk but IHDR, PLTE, tRNS, IDAT and IEND',
	],
	aria: ['scrub each line: known values in their forms, then credential patterns'],
	console: ['scrub each line: known values in their forms, then credential patterns'],
	network: [
		'keep id, page, method, url, resourceType, navigation, redirectedFrom, times, status, failure',
		'drop request headers and bodies; keep allowlisted response headers',
		'scrub and bound every string, the names of dropped headers included',
	],
	'http-response': [
		'keep method, url, status, allowlisted response headers, body size and truncation',
		'keep the body only when policy asks, within its bound, as scrubbed text',
		'scrub and bound every string, the names of dropped headers included',
	],
	trace: ['withhold'],
	har: ['withhold'],
	file: ['withhold'],
};

export function policyDigest(kind: ArtifactKind): string {
	return canonicalDigest({
		version: REDACTION_POLICY_VERSION,
		kind,
		rules: POLICIES[kind],
		headers: kind === 'network' || kind === 'http-response' ? RESPONSE_HEADER_ALLOWLIST : [],
	});
}

export interface Sanitized {
	bytes: Uint8Array;
	removedFields: string[];
	limitations: string[];
}

// The most one kept string value may be. The app controls method names,
// header names and values, failure texts; each is scrubbed and cut.
const MAX_VALUE_CHARS = 4096;
// Bounds the manifest schema puts on an entry's redaction record
// (RedactionSchema). A name past the first is dropped, not truncated into
// another name.
const MAX_REMOVED_FIELD_CHARS = 200;
const MAX_REMOVED_FIELDS = 1000;
export const MAX_LIMITATIONS = 50;

// A string the application chose, scrubbed of known values and patterns
// and cut to size. Nothing from a capture is kept as it came. The whole
// value is scrubbed before the cut: a cut first would leave a secret that
// starts inside the kept part and ends past it with most of its characters.
function scrubValue(value: unknown, secrets: SecretRegistry): string {
	return secrets.redact(String(value)).slice(0, MAX_VALUE_CHARS);
}

// The removed-field names of an entry: each scrubbed, cut to the schema's
// length, sorted, and the list cut to the schema's count. A list that was
// cut says so in its last entry.
function removedFields(names: Iterable<string>, secrets: SecretRegistry): string[] {
	const scrubbed = new Set<string>();
	for (const name of names)
		scrubbed.add(scrubValue(name, secrets).slice(0, MAX_REMOVED_FIELD_CHARS));
	const sorted = [...scrubbed].sort();
	if (sorted.length <= MAX_REMOVED_FIELDS) return sorted;
	return [...sorted.slice(0, MAX_REMOVED_FIELDS - 1), 'more:names past the manifest limit'];
}

// A screenshot: the PNG with its metadata chunks removed.
export function sanitizeScreenshot(bytes: Uint8Array): Sanitized {
	try {
		const stripped = stripPngMetadata(bytes);
		return {
			bytes: stripped.bytes,
			removedFields: stripped.removed.map((type) => `png:${type}`),
			limitations: [...LIMITATIONS.screenshot],
		};
	} catch (err) {
		if (err instanceof PngError)
			throw new SanitizeError(`not a PNG the sanitizer accepts: ${err.message}`);
		throw err;
	}
}

// Text in chunks, line by line (aria snapshots, console lines).
export class TextSanitizer {
	private readonly scrubber: LineScrubber;
	private readonly encoder = new TextEncoder();

	constructor(secrets: SecretRegistry) {
		this.scrubber = new LineScrubber((text) => secrets.redact(text));
	}

	push(chunk: Uint8Array): Uint8Array {
		return this.encoder.encode(this.scrubber.push(chunk));
	}

	end(): Uint8Array {
		return this.encoder.encode(this.scrubber.end());
	}
}

export function sanitizeText(
	bytes: Uint8Array,
	secrets: SecretRegistry,
	kind: 'aria' | 'console',
): Sanitized {
	const sanitizer = new TextSanitizer(secrets);
	const head = sanitizer.push(bytes);
	const tail = sanitizer.end();
	const out = new Uint8Array(head.length + tail.length);
	out.set(head, 0);
	out.set(tail, head.length);
	return { bytes: out, removedFields: [], limitations: [...LIMITATIONS[kind]] };
}

// A URL without its credentials, scrubbed.
export function scrubUrl(url: string, secrets: SecretRegistry): string {
	let text = url;
	try {
		const parsed = new URL(url);
		if (parsed.username !== '' || parsed.password !== '') {
			parsed.username = '';
			parsed.password = '';
			text = parsed.toString();
		}
	} catch {
		// Not a URL the parser takes; scrubbed as text.
	}
	return secrets.redact(text);
}

// Response headers reduced to the allowlist, values scrubbed, and the names
// of the ones dropped.
function projectHeaders(
	headers: unknown,
	secrets: SecretRegistry,
): { kept: Record<string, string>; dropped: string[] } {
	const kept: Record<string, string> = {};
	const dropped: string[] = [];
	if (headers === undefined || headers === null) return { kept, dropped };
	if (typeof headers !== 'object' || Array.isArray(headers)) {
		throw new SanitizeError('headers are not an object');
	}
	for (const [name, value] of Object.entries(headers as Record<string, unknown>)) {
		const lower = name.toLowerCase();
		if (RESPONSE_HEADER_ALLOWLIST.includes(lower)) {
			kept[lower] = scrubValue(value, secrets);
		} else {
			// The name is the app's too: a header named after a secret would
			// otherwise carry it into removedFields.
			dropped.push(scrubValue(lower, secrets));
		}
	}
	return { kept, dropped };
}

const NETWORK_FIELDS = new Set([
	'id',
	'pageId',
	'method',
	'url',
	'resourceType',
	'navigation',
	'redirectedFrom',
	'startedAt',
	'endedAt',
	'status',
	'headers',
	'failed',
]);

// The recorder's network observations, one JSON object per line, each read
// with the shared schema (RecorderNetworkRecordSchema), projected to the
// fields koi keeps and scrubbed. A line the schema refuses fails the whole
// capture: a record koid cannot read is not evidence.
export function sanitizeNetwork(bytes: Uint8Array, secrets: SecretRegistry): Sanitized {
	const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
	const removed = new Set<string>(['request-headers', 'bodies']);
	const limitations = [...LIMITATIONS.network];
	const lines: string[] = [];
	for (const line of text.split('\n')) {
		if (line === '') continue;
		let data: unknown;
		try {
			data = JSON.parse(line);
		} catch {
			throw new SanitizeError('a network line is not JSON');
		}
		const dropped = RecorderDroppedLineSchema.safeParse(data);
		if (dropped.success) {
			limitations.push(
				`${dropped.data.dropped} observations past the recorder's limit were not recorded`,
			);
			lines.push(JSON.stringify({ dropped: dropped.data.dropped }));
			continue;
		}
		const parsed = RecorderNetworkRecordSchema.safeParse(data);
		if (!parsed.success) {
			throw new SanitizeError(
				`a network line is not a record the recorder writes: ${issue(parsed.error)}`,
			);
		}
		const fields: Record<string, unknown> = parsed.data;
		const out: Record<string, unknown> = {};
		for (const [key, value] of Object.entries(fields)) {
			if (!NETWORK_FIELDS.has(key)) {
				removed.add(`network:${key}`);
				continue;
			}
			switch (key) {
				case 'url':
					out.url = scrubUrl(String(value), secrets);
					break;
				case 'headers': {
					const projected = projectHeaders(value, secrets);
					out.headers = projected.kept;
					for (const name of projected.dropped) removed.add(`header:${name}`);
					break;
				}
				default:
					// Method, resource type, failure text: strings the page or
					// the app chose are scrubbed like any other; numbers and
					// booleans pass.
					out[key] = typeof value === 'string' ? scrubValue(value, secrets) : value;
			}
		}
		lines.push(JSON.stringify(out));
	}
	const joined = lines.length === 0 ? '' : `${lines.join('\n')}\n`;
	return {
		bytes: new TextEncoder().encode(joined),
		removedFields: removedFields(removed, secrets),
		limitations: limitations.slice(0, MAX_LIMITATIONS),
	};
}

export interface BodyPolicy {
	// Whether the point's policy asked for the body at all.
	body: boolean;
	maxBodyBytes: number;
}

// A state read the recorder made, read with the shared schema
// (RecorderStateReadSchema): status, allowlisted headers, and the body only
// under the point's policy, as scrubbed text.
export function sanitizeHttpResponse(
	bytes: Uint8Array,
	secrets: SecretRegistry,
	policy: BodyPolicy,
): Sanitized {
	let data: unknown;
	try {
		data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
	} catch {
		throw new SanitizeError('the state read is not JSON');
	}
	const parsed = RecorderStateReadSchema.safeParse(data);
	if (!parsed.success) {
		throw new SanitizeError(
			`the state read is not what the recorder writes: ${issue(parsed.error)}`,
		);
	}
	const r = parsed.data;
	const removed = new Set<string>();
	const limitations = [...LIMITATIONS['http-response']];
	const headers = projectHeaders(r.response.headers, secrets);
	for (const name of headers.dropped) removed.add(`header:${name}`);
	const bodyBytes = r.response.bodyBytes;
	const out: Record<string, unknown> = {
		request: {
			method: scrubValue(r.request.method, secrets),
			url: scrubUrl(r.request.url, secrets),
		},
		response: {
			status: r.response.status,
			headers: headers.kept,
			bodyBytes,
			truncated: r.response.truncated,
		},
		startedAt: r.startedAt,
		endedAt: r.endedAt,
	};
	const response = out.response as Record<string, unknown>;
	if (!policy.body) {
		removed.add('body');
		response.bodyOmitted = 'the point policy did not ask for the body';
	} else if (bodyBytes > policy.maxBodyBytes) {
		removed.add('body');
		response.bodyOmitted = `the body is over the policy's bound of ${policy.maxBodyBytes} bytes`;
	} else {
		const raw = Buffer.from(r.response.bodyBase64, 'base64');
		let text: string | undefined;
		try {
			text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
		} catch {
			text = undefined;
		}
		if (text === undefined || text.includes('\u0000')) {
			removed.add('body');
			response.bodyOmitted = 'the body is not text';
		} else {
			// The recorder cut the body at the bound before koid saw it, so a
			// value split at the cut reaches the scrubber as a fragment the
			// registry does not know.
			if (r.response.truncated) {
				limitations.push(
					'the recorder cut the body at the bound before it was scrubbed; a value split at the cut is not found',
				);
			}
			const scrubber = new LineScrubber((line) => secrets.redact(line));
			response.body = (scrubber.push(new TextEncoder().encode(text)) + scrubber.end()).replace(
				/\n$/,
				'',
			);
		}
	}
	return {
		bytes: new TextEncoder().encode(`${JSON.stringify(out)}\n`),
		removedFields: removedFields(removed, secrets),
		limitations,
	};
}

// The first problem a schema found, as a path and a message. It names a
// field, never quotes a value, so it may go into a reason the manifest keeps.
function issue(error: { issues: Array<{ path: PropertyKey[]; message: string }> }): string {
	const first = error.issues[0];
	if (first === undefined) return 'invalid';
	const path = first.path.map(String).join('.');
	return path === '' ? first.message : `${path}: ${first.message}`;
}
