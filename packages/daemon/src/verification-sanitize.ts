import { KOI_DIR, type ProofRecord, TEXT_MAX, type VerifyConfig } from '@koi/shared';
import { holdsCredential, holdsCredentialShape, scrubWithin } from './redact.ts';

// What a run's data may say once it leaves koid (docs/verify.md, "Running a
// verification"). There are two kinds of text. Project text and koid's own values are
// written once, as they are, so their digests hold; an execution descriptor holds nothing
// else and never comes here. A plan is written the same way, and the little runtime text
// it holds comes here once as it enters, before the digest. Runtime text is what a page, a
// recorder, a runner, Docker or an error says. Every write of a run's other records and
// every reply about a run or a plan passes through sanitizeRunData, with the secrets known
// at that moment. RunWriter and EvidenceStore.writeRecord take no such record any other
// way, and Verification.readRun is how every reply reads a run.

export interface SanitizeRules {
	// Takes known secrets and credential patterns out of text.
	redact: (text: string) => string;
}

export type Sanitize = <T>(record: T) => T;

// The fields a record names that hold project text or koid's own values. A mask in one
// would change what it says or break its form, so a value someone registered as a key
// (the keys page takes any) could make a run's own records unreadable. Any field not
// named here is scrubbed, because a leak is worse than an ugly mask. No page or runner
// can put text of its own in any of these: an event's fields and a runner's words as they
// came never reach this list (walk, sanitizeEvent), and of what a runner reports, only a
// declared name and one of the protocol's outcomes do. A name here means this in every
// record, so a field that holds what a runner chose goes by another name: `evidence` is
// koid's artifact ids, and what a runner cited is `cited`.
const FIXED_FIELDS: ReadonlySet<string> = new Set([
	// Project text: what .koi/ declares, or what the pull request's git tree holds. A
	// report's `assertion` is a declared name: the verifier takes no report for another.
	'assertion',
	'assertions',
	'baseBranch',
	'id',
	'path',
	'pointId',
	'profile',
	'uncovered',
	// Ids and digests koid makes or computes. An id above can be koid's too: an artifact's.
	'artifact',
	'commit',
	'base',
	'deploymentId',
	'executionDigest',
	'head',
	'idempotencyKey',
	'imageDigest',
	'label',
	'leaseId',
	'planDigest',
	'planId',
	'policyDigest',
	'runId',
	'sha256',
	// Times from koid's clock.
	'at',
	'capturedAt',
	'checkedAt',
	'expiresAt',
	'finalizedAt',
	'finishedAt',
	'retainedUntil',
	'startedAt',
	'tombstoneUntil',
	'updatedAt',
	// Enums and fixed words. A media type is one of the recorder's literals for a kind,
	// and an origin is the literal `recorder` or the address koid gave the recorder.
	'availability',
	'cleanup',
	'code',
	'completion',
	'evidence',
	'freshness',
	'kind',
	'mediaType',
	'origin',
	'outcome',
	'source',
	'state',
	'status',
	// How koid saw a verifier end, one of PointRun's fixed words.
	'stopped',
]);

// What the schemas let each runtime text field hold. Applied here, after the scrub,
// because a cut made before it can leave half of a secret, and because the mask can be
// longer than what it replaces. Callers leave these fields uncut.
const TEXT_BOUNDS: ReadonlyMap<string, number> = new Map([
	['cited', 255],
	['detail', 2000],
	['error', 2000],
	['interruption', 2000],
	['limitations', 500],
	['reason', TEXT_MAX],
	['removedFields', 200],
]);

// `record` as it may leave koid now, with its runtime text scrubbed. It takes a record of
// any kind (a controller state, a result, a report's text, an event, a reply) and never
// changes what it is given. Scrubbing what this returned changes nothing, so a record
// read back and sent on says what the file says, unless koid has learned a secret since.
export function sanitizeRunData<T>(record: T, rules: SanitizeRules): T {
	if (typeof record === 'string') return rules.redact(record) as T;
	return (isEvent(record) ? sanitizeEvent(record, rules) : walk(record, undefined, rules)) as T;
}

function walk(value: unknown, key: string | undefined, rules: SanitizeRules): unknown {
	if (typeof value === 'string') return sanitizeField(value, key, rules);
	if (Array.isArray(value)) return value.map((item) => walk(item, key, rules));
	if (typeof value !== 'object' || value === null) return value;
	const out: Record<string, unknown> = {};
	for (const [name, field] of Object.entries(value)) {
		// A field called `reports` holds a runner's words as they came, whatever it calls a
		// field, so nothing under it is fixed. A point's observations say what koid checked
		// of a report in fields of their own (ObservedPoint).
		if (field !== undefined) out[name] = walk(field, key === 'reports' ? key : name, rules);
	}
	return out;
}

function sanitizeField(value: string, key: string | undefined, rules: SanitizeRules): string {
	if (key === undefined) return rules.redact(value);
	if (FIXED_FIELDS.has(key)) return value;
	return scrubWithin((text) => rules.redact(text), value, TEXT_BOUNDS.get(key));
}

type EventLike = Record<string, unknown> & { seq: number; source: unknown };

// An event's fields are the recorder's or the page's to name, so unlike a record's
// only its envelope is fixed, and the names of the rest are scrubbed too.
function isEvent(record: unknown): record is EventLike {
	return (
		typeof record === 'object' &&
		record !== null &&
		typeof (record as { seq?: unknown }).seq === 'number' &&
		'source' in record
	);
}

// The envelope goes first and in the order EvidenceEventSchema gives it. A
// reader's copy of the line, parsed and written again, is then these same bytes,
// so an export can hold the bytes it was given to the manifest's digest.
function sanitizeEvent(event: EventLike, rules: SanitizeRules): EventLike {
	const { seq, at, source, type, pointId, attempt, ...fields } = event;
	return {
		seq,
		at,
		source,
		type,
		...(pointId !== undefined ? { pointId } : {}),
		...(attempt !== undefined ? { attempt } : {}),
		...scrubFields(rules, fields),
	};
}

// Every string in an event's fields, however nested, scrubbed of known values and
// patterns, and cut to `max` when there is one; numbers, booleans and null pass,
// and undefined is left out. Keys are strings too: a recorder event's field names,
// and the keys of an object a page reported, are the app's words, and a key that
// scrubs to another name is replaced by it. Two keys that scrub to one name keep
// the first.
export function scrubFields(
	secrets: SanitizeRules,
	fields: Record<string, unknown>,
	max?: number,
): Record<string, unknown> {
	const scrub = (text: string) => scrubWithin((t) => secrets.redact(t), text, max);
	const value = (field: unknown): unknown => {
		if (typeof field === 'string') return scrub(field);
		if (Array.isArray(field)) return field.map(value);
		if (typeof field === 'object' && field !== null) {
			return scrubFields(secrets, field as Record<string, unknown>, max);
		}
		return field;
	};
	const out: Record<string, unknown> = {};
	for (const [key, field] of Object.entries(fields)) {
		if (field === undefined) continue;
		const name = scrub(key);
		if (!Object.hasOwn(out, name)) out[name] = value(field);
	}
	return out;
}

// -- The plan-time check -------------------------------------------------------

// What a project's files declare, as a plan reads them. Changed file names are not here:
// they are the pull request's own, and a false match on one would stop planning.
export interface DeclaredText {
	config: VerifyConfig;
	policy: { path: string; required: Array<{ id: string }>; error?: string | undefined } | undefined;
	proofs: { records: Iterable<ProofRecord>; errors: string[] };
}

// Where a project's declared text holds what looks like a real credential, or undefined.
// It names a file, a point's position and a field, and quotes no project text at all. A
// value can stand in a file's name with a prefix that keeps a pattern from seeing it, so
// asking the patterns whether a name is safe to show is no answer. Keys that a project
// chooses, a profile's name and a file's path, are checked as fields and never named, so
// the answer cannot carry a value by way of a field's own name. Every declared field is
// looked at, whether or not this plan would write it: the file is in the project either way.
// A project can declare 64 MiB here, so the rest of koid gets a turn between points.
export async function declaredCredential({
	config,
	policy,
	proofs,
}: DeclaredText): Promise<string | undefined> {
	const manifest = {
		...config.manifest,
		profiles: Object.entries(config.manifest.profiles).map(([name, profile]) => ({
			name,
			...profile,
		})),
	};
	const manifestField = credentialField(manifest, '');
	if (manifestField !== undefined) return `${KOI_DIR}/verify.yaml, field ${manifestField}`;
	for (const [i, { path, point, runners }] of config.points.entries()) {
		await new Promise((resolve) => setImmediate(resolve));
		const field = credentialField({ path, ...point, runners }, '');
		if (field === undefined) continue;
		// The loader sorts the files, so the position is enough to find this one.
		return `point ${i + 1} of ${config.points.length}, counting the point files in the sorted order of their paths, field ${field}`;
	}
	const policyField = credentialField(policy, '');
	if (policyField !== undefined) return `the required policy, field ${policyField}`;
	const proofField = credentialField({ records: [...proofs.records], errors: proofs.errors }, '');
	return proofField === undefined ? undefined : `the proof records, field ${proofField}`;
}

// The fields that hold an image reference.
const IMAGE_FIELDS: ReadonlySet<string> = new Set(['runner.image']);

function credentialField(value: unknown, at: string): string | undefined {
	if (typeof value === 'string') {
		const holds = IMAGE_FIELDS.has(at) ? holdsCredentialShape : holdsCredential;
		return holds(value) ? at : undefined;
	}
	if (typeof value !== 'object' || value === null) return undefined;
	for (const [key, field] of Object.entries(value)) {
		const name = Array.isArray(value) ? `${at}[${key}]` : at === '' ? key : `${at}.${key}`;
		const found = credentialField(field, name);
		if (found !== undefined) return found;
	}
	return undefined;
}
