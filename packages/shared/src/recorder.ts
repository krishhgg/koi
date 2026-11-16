import { z } from 'zod';
import { ArtifactKindSchema } from './evidence.ts';
import { DigestSchema, PointIdSchema } from './verify.ts';

// The recorder's control API, as koid reads its replies (docs/verify.md,
// "Recorder and evidence"). The recorder (host/recorder) serves it on TCP
// 4318 inside the run network; every request carries the host-only run
// capability as a bearer token. The server is written against these shapes
// by hand, since the image does not carry this package; a reply that does
// not fit is an error, never evidence.

// The recorder's ports on the run network.
export const RECORDER_BROWSER_PORT = 4317;
export const RECORDER_CONTROL_PORT = 4318;

// What the recorder keeps a capture under until koid acknowledges it.
export const RecorderCaptureIdSchema = z.string().regex(/^c[1-9][0-9]*$/);

// An opaque id the recorder gives a context or a page.
const RecorderObjectIdSchema = z.string().regex(/^[a-z][0-9]+$/);

export const RecorderHealthSchema = z.discriminatedUnion('ok', [
	z.strictObject({
		ok: z.literal(true),
		runId: z.string().min(1),
		origin: z.url(),
		browser: z.strictObject({ name: z.literal('chromium'), version: z.string().min(1) }),
		playwright: z.string().min(1),
		contexts: z.number().int().nonnegative(),
		captures: z.strictObject({
			count: z.number().int().nonnegative(),
			bytes: z.number().int().nonnegative(),
		}),
		events: z.strictObject({
			next: z.number().int().positive(),
			dropped: z.number().int().nonnegative(),
		}),
	}),
	z.strictObject({ ok: z.literal(false), reason: z.string() }),
]);

export type RecorderHealth = z.infer<typeof RecorderHealthSchema>;

export const RecorderContextSchema = z.strictObject({
	contextId: RecorderObjectIdSchema,
	pageId: RecorderObjectIdSchema,
	url: z.string(),
});

export type RecorderContext = z.infer<typeof RecorderContextSchema>;

// A capture the recorder holds in its tmpfs: raw bytes, which koid reads,
// sanitizes and only then keeps. Size and hash are of the raw bytes, for
// the transfer check; the artifact's own are computed again after
// sanitization.
export const RecorderCaptureSchema = z.strictObject({
	captureId: RecorderCaptureIdSchema,
	kind: ArtifactKindSchema,
	mediaType: z.string().min(1),
	size: z.number().int().nonnegative(),
	sha256: DigestSchema,
	pageId: RecorderObjectIdSchema.optional(),
	url: z.string().optional(),
	eventRange: z.strictObject({
		first: z.number().int().nonnegative(),
		last: z.number().int().nonnegative(),
	}),
	capturedAt: z.iso.datetime(),
	// What the recorder itself could not promise about the capture, in its
	// own words. koid scrubs and bounds each before it joins the artifact's
	// limitations.
	limitations: z.array(z.string()).max(50).optional(),
});

export type RecorderCapture = z.infer<typeof RecorderCaptureSchema>;

// What the recorder puts in place of an event field over its length limit
// (host/recorder/src/events.ts, OVERLONG_FIELD): the field is discarded
// whole, since the recorder cannot redact and a cut could keep most of a
// secret. The event's `truncatedFields` names the fields. koid records a
// limitation when it reads one.
export const RECORDER_OVERLONG_FIELD = '[koi: a field over 4096 characters was discarded]';

// One entry of the recorder's event feed. The envelope is fixed; what each
// type carries is the recorder's own, and koid bounds and scrubs it before
// it is written.
export const RecorderEventSchema = z.looseObject({
	seq: z.number().int().positive(),
	at: z.iso.datetime(),
	type: z
		.string()
		.min(1)
		.max(64)
		.regex(/^[a-z][a-z0-9-]*$/),
	contextId: RecorderObjectIdSchema.optional(),
	pageId: RecorderObjectIdSchema.optional(),
});

export type RecorderEvent = z.infer<typeof RecorderEventSchema>;

export const RecorderEventsPageSchema = z.strictObject({
	events: z.array(RecorderEventSchema),
	// The sequence number the next read starts after.
	next: z.number().int().nonnegative(),
	// Events after the read's `after` that the recorder's buffer lost before
	// this read: ones koid never got and now cannot. Not zero: a gap in
	// observation, which the run records. An eviction of an event koid had
	// read is not counted.
	dropped: z.number().int().nonnegative(),
});

export type RecorderEventsPage = z.infer<typeof RecorderEventsPageSchema>;

// -- Capture contents ---------------------------------------------------------

// What a network capture and a state read hold, as the recorder writes them
// (host/recorder/src/broker.ts). koid parses every line with these before
// its sanitizer projects it, so a record it cannot read is refused, never
// cast and kept.

// One network observation, one JSON object per line of a network capture.
// Loose: a field the recorder adds is dropped by the sanitizer and named in
// the entry's removedFields, never kept.
export const RecorderNetworkRecordSchema = z.looseObject({
	id: z.number().int().positive(),
	pageId: z.string().optional(),
	method: z.string(),
	url: z.string(),
	resourceType: z.string(),
	navigation: z.boolean(),
	redirectedFrom: z.number().int().positive().optional(),
	startedAt: z.string(),
	status: z.number().int().optional(),
	headers: z.record(z.string(), z.string()).optional(),
	endedAt: z.string().optional(),
	failed: z.string().optional(),
});

export type RecorderNetworkRecord = z.infer<typeof RecorderNetworkRecordSchema>;

// The last line of a capture whose observations passed the recorder's
// per-context limit: how many were not recorded.
export const RecorderDroppedLineSchema = z.strictObject({
	dropped: z.number().int().positive(),
});

// A state read: what the recorder asked the app for from inside the point's
// context, and what came back, the body as base64 up to the bound koid gave.
export const RecorderStateReadSchema = z.strictObject({
	request: z.strictObject({ method: z.enum(['GET', 'HEAD']), url: z.string() }),
	response: z.strictObject({
		status: z.number().int(),
		headers: z.record(z.string(), z.string()),
		bodyBase64: z.string(),
		bodyBytes: z.number().int().nonnegative(),
		truncated: z.boolean(),
	}),
	startedAt: z.iso.datetime(),
	endedAt: z.iso.datetime(),
});

export type RecorderStateRead = z.infer<typeof RecorderStateReadSchema>;

export const RecorderErrorSchema = z.object({
	error: z.string(),
	code: z
		.string()
		.regex(/^[a-z][a-z0-9_]*$/)
		.optional(),
});

// What koid sends to open a point's context.
export const RecorderOpenContextSchema = z.strictObject({
	pointId: PointIdSchema,
	attempt: z.number().int().positive(),
	// A same-origin path the first page opens at; about:blank without one.
	open: z.string().startsWith('/').max(2048).optional(),
});

// What koid sends to capture.
export const RecorderCaptureRequestSchema = z.strictObject({
	kind: z.enum(['screenshot', 'aria', 'console', 'network']),
	label: z.string().min(1).max(64),
	pageId: RecorderObjectIdSchema.optional(),
});

// What koid sends for a state read: the recorder requests the path from the
// app itself, from inside the point's context, and keeps what came back.
export const RecorderReadRequestSchema = z.strictObject({
	method: z.enum(['GET', 'HEAD']),
	path: z.string().startsWith('/').max(2048),
	maxBodyBytes: z
		.number()
		.int()
		.nonnegative()
		.max(4 * 1024 ** 2),
});
