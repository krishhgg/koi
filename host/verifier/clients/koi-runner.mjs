// The runner protocol for a JavaScript runner (docs/verify.md, "Writing a
// runner"). The default verifier image has no Node; a project whose own
// allowed image does copies this file from host/verifier/clients/ and
// imports it by path.
//
//   import * as koi from '/opt/koi/clients/koi-runner.mjs';
//   const shot = await koi.capture('screenshot', 'after-save');
//   const state = await koi.read('/api/pipelines/7', 'saved-row');
//   koi.assertion('name-persists', 'pass', [shot, state], 'the row holds the name');
//
// Events go to stdout as JSON lines; koid's acknowledgments come on stdin.
// A capture or a read resolves with its artifact id, or rejects with
// CaptureFailed carrying koid's error code. Lines on stdin that are not the
// acknowledgment awaited are ignored.
//
// koid discards a line over 8 KiB, so an assertion's detail and a note's text
// are cut until the whole line fits. An event that cannot fit without its free
// text throws: printing it would lose it without a word.

import { createInterface } from 'node:readline';

export const PROTOCOL_VERSION = 1;
const OUTCOMES = ['pass', 'fail', 'blocked', 'not-run', 'needs-review', 'pass-with-recovery'];
const CAPTURE_KINDS = ['screenshot', 'trace', 'har', 'aria', 'file'];
const PHASES = ['setup', 'journey', 'recovery', 'cleanup'];
// The longest line koid reads, without its newline (PROTOCOL_LIMITS.lineBytes
// in packages/daemon/src/verifier.ts). It discards a longer one whole, so an
// event past this would look as if the runner never sent it.
const MAX_LINE_BYTES = 8 * 1024;
// The longest free text koid's schema takes (RunnerEventSchema).
const MAX_TEXT_UNITS = 4000;

export class CaptureFailed extends Error {
	constructor(label, code) {
		super(`${label}: ${code}`);
		this.label = label;
		this.code = code;
	}
}

// What koid put in the environment.
export function env(environ = process.env) {
	let fixtures = {};
	try {
		const parsed = JSON.parse(environ.KOI_FIXTURES || '{}');
		if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) fixtures = parsed;
	} catch {
		fixtures = {};
	}
	return {
		runId: environ.KOI_RUN_ID || '',
		pointId: environ.KOI_POINT_ID || '',
		attempt: Number(environ.KOI_ATTEMPT || 1),
		previewUrl: environ.KOI_PREVIEW_URL || '',
		recorderWs: environ.KOI_RECORDER_WS || '',
		timeoutSeconds: Number(environ.KOI_TIMEOUT_SECONDS || 0),
		maxRequests: Number(environ.KOI_MAX_REQUESTS || 0),
		loginKey: environ.KOI_LOGIN_KEY,
		fixtures,
	};
}

let lines;
const waiting = new Map();

// One reader of stdin for the process: each acknowledgment goes to the
// caller waiting on its label.
function listen() {
	if (lines !== undefined) return;
	lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
	lines.on('line', (line) => {
		let ack;
		try {
			ack = JSON.parse(line);
		} catch {
			return;
		}
		if (ack?.type !== 'capture-result' || typeof ack.label !== 'string') return;
		const pending = waiting.get(ack.label);
		if (pending === undefined) return;
		waiting.delete(ack.label);
		if (ack.status === 'ready' && typeof ack.artifact === 'string') pending.resolve(ack.artifact);
		else pending.reject(new CaptureFailed(ack.label, String(ack.error ?? 'failed')));
	});
	lines.on('close', () => {
		for (const [label, pending] of waiting)
			pending.reject(new CaptureFailed(label, 'stdin_closed'));
		waiting.clear();
	});
}

const lineBytes = (record) => Buffer.byteLength(JSON.stringify(record));

// The event as koid reads it, or an error when koid would discard it.
function encode(record) {
	const bytes = lineBytes(record);
	if (bytes > MAX_LINE_BYTES) {
		throw new Error(
			`a ${record.type} event is ${bytes} bytes, and koid discards a line over ${MAX_LINE_BYTES}`,
		);
	}
	return `${JSON.stringify(record)}\n`;
}

function emit(record) {
	process.stdout.write(encode(record));
}

// The first `count` units of `text`, one fewer when the cut would split a
// surrogate pair: half of one is not text.
function cut(text, count) {
	const last = count > 0 && count < text.length ? text.charCodeAt(count - 1) : 0;
	return text.slice(0, last >= 0xd800 && last <= 0xdbff ? count - 1 : count);
}

// Sets record[field] to as much of `value` as koid's schema takes and the line
// bound leaves room for. The encoded size depends on what the text holds: 3
// bytes for a Chinese character, 4 for an emoji, 2 for a quote. So the cut is
// tried against the whole encoded line, not worked out from the text's length.
function fit(record, field, value) {
	const text = String(value).slice(0, MAX_TEXT_UNITS + 1);
	const fits = (count) => {
		record[field] = cut(text, count);
		return lineBytes(record) <= MAX_LINE_BYTES;
	};
	let high = Math.min(text.length, MAX_TEXT_UNITS);
	if (fits(high)) return;
	let low = 0;
	high -= 1;
	while (low < high) {
		const middle = Math.ceil((low + high) / 2);
		if (fits(middle)) low = middle;
		else high = middle - 1;
	}
	record[field] = cut(text, low);
}

// Called before the request goes out. One waiter per label, as an answer names only its
// label: a second request under a label still in flight would take the first's answer,
// and leave the first waiting forever. koid answers a used label with this same code.
function awaitResult(label) {
	listen();
	if (waiting.has(label)) return Promise.reject(new CaptureFailed(label, 'duplicate_label'));
	return new Promise((resolve, reject) => {
		waiting.set(label, { resolve, reject });
	});
}

function ask(line, label) {
	const inFlight = waiting.has(label);
	const result = awaitResult(label);
	if (!inFlight) process.stdout.write(line);
	return result;
}

// Reports one of the point's declared assertions. `point` defaults to
// KOI_POINT_ID.
export function assertion(name, outcome, evidence = [], detail, point) {
	if (!OUTCOMES.includes(outcome))
		throw new Error(`outcome ${outcome} is not one of ${OUTCOMES.join(', ')}`);
	const record = {
		type: 'assertion',
		point: point ?? process.env.KOI_POINT_ID ?? '',
		name,
		outcome,
		evidence: [...evidence],
	};
	if (detail !== undefined) fit(record, 'detail', detail);
	emit(record);
}

// Asks the recorder for a capture of the point's page; resolves with its
// artifact id.
export function capture(kind, label) {
	if (!CAPTURE_KINDS.includes(kind))
		throw new Error(`kind ${kind} is not one of ${CAPTURE_KINDS.join(', ')}`);
	// Encoded first: an event that cannot go must leave nobody waiting for its answer.
	return ask(encode({ type: 'capture', kind, label }), label);
}

// Asks the recorder to request `path` from the app; resolves with the
// http-response artifact id.
export function read(path, label, method = 'GET') {
	if (!path.startsWith('/')) throw new Error("path must start with /: a path on the app's origin");
	const record = { type: 'read', label, path };
	if (method !== 'GET') record.method = method;
	return ask(encode(record), label);
}

export function note(text) {
	const record = { type: 'note' };
	fit(record, 'text', text);
	emit(record);
}

export function phase(name, state) {
	if (!PHASES.includes(name) || !['start', 'end'].includes(state)) {
		throw new Error('phase is one of setup, journey, recovery, cleanup, with state start or end');
	}
	emit({ type: 'phase', name, state });
}

// Done with stdin: lets the process exit once the runner's own work ends.
export function close() {
	lines?.close();
	lines = undefined;
}
