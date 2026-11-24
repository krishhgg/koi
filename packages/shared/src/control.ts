import { z } from 'zod';
import { LeaseSchema, PreviewLabelSchema, PreviewRecordSchema } from './preview.ts';
import { DeploymentSliceSchema } from './recipe.ts';
import { DeploymentIdentitySchema } from './verify.ts';

// What `koid ctl` prints on stdout as JSON, for the CLI to parse. The CLI
// runs koid ctl through SSM, which returns only the first 24,000 characters
// of a command's output, so every reply here has a size limit far below that.

// koid ctl's arguments as the CLI sends them through SSM (`koid ctl-b64
// <blob>`): the base64 of a JSON array of strings. The SSM command is a shell
// string, and base64 holds no character a shell treats specially, so the
// arguments reach koid as data whatever they contain. koid ctl then checks
// each one as it would on its own command line.
const CtlArgsSchema = z.array(z.string().max(1024)).min(1).max(8);
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const CTL_BLOB_MAX_CHARS = 16_384;

export function encodeCtlArgs(args: string[]): string {
	return Buffer.from(JSON.stringify(CtlArgsSchema.parse(args)), 'utf8').toString('base64');
}

// The arguments in a blob from encodeCtlArgs. Throws on anything else.
export function decodeCtlArgs(blob: string): string[] {
	if (blob.length > CTL_BLOB_MAX_CHARS || !BASE64.test(blob)) {
		throw new Error('the arguments are not base64');
	}
	const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(blob, 'base64'));
	return CtlArgsSchema.parse(JSON.parse(text));
}

// `koid ctl ping` once koid takes commands.
export const PingReplySchema = z.object({ ok: z.literal(true) });

export type PingReply = z.infer<typeof PingReplySchema>;

// `koid ctl up <request-id>`: koid accepted the request for `label`, and
// `queued` says whether it waits for another build first.
export const UpAcceptedSchema = z.object({ label: PreviewLabelSchema, queued: z.boolean() });

export type UpAccepted = z.infer<typeof UpAcceptedSchema>;

// What koid ctl prints on stderr when koid refused a command.
export const ErrorReplySchema = z.object({ error: z.string(), detail: z.string().optional() });

export type ErrorReply = z.infer<typeof ErrorReplySchema>;

// The most lines `koid ctl logs` and `koid ctl buildlog` give, and so the
// most `koi logs --tail` takes.
export const LOG_TAIL_MAX_LINES = 5000;

// The most log text those commands print, in UTF-8 bytes: never fewer than
// the characters SSM counts.
export const LOG_TEXT_MAX = 16_000;

// The line koid puts first when it cut log text to at most `max` bytes,
// keeping the end.
export function logCutNote(max: number): string {
	return `[koid: earlier output cut; this is the last of it, at most ${max} characters]\n`;
}

// The error koid gives for a label it has no record of.
export const NO_SUCH_PREVIEW = 'no such preview';

// The error koid gives for a release of a lease the preview does not hold.
export const NO_SUCH_LEASE = 'no such lease';

// koid ctl's exit status. Only `unavailable` can pass by itself: koid is
// starting or restarting and did not answer.
export const CTL_EXIT = {
	ok: 0,
	// koid answered with an error, such as NO_SUCH_PREVIEW.
	refused: 1,
	// The arguments are not valid; nothing was sent to koid.
	usage: 2,
	unavailable: 3,
} as const;

// A byte offset in a build log as koid ctl and the control socket take it:
// plain digits, at most 15, so it converts to a Number exactly.
export const LogOffsetSchema = z
	.string()
	.regex(/^(?:0|[1-9][0-9]{0,14})$/, 'a log offset')
	.transform(Number);

// Whole lines of a build log: `lines` are the lines from the byte offset the
// caller asked for, and `next` is the offset just past the last of them, to
// ask for next. koi passes `next` back as it is.
export const BuildLogPageSchema = z.object({
	next: z.number().int().nonnegative(),
	lines: z.array(z.string()),
});

export type BuildLogPage = z.infer<typeof BuildLogPageSchema>;

// `koid ctl status <label> [attempt [offset]]`: the label's record and, with
// an attempt, lines of that attempt's build log. The record leaves out the deployment,
// whose environment can be large; `deployment` is the identity of the one
// serving (deploymentIdentity), absent while nothing serves. `slice` is what
// that deployment's build kept (DeploymentSliceSchema), when its recipe
// reports one. It comes only in a reply with no log lines for a record no
// longer queued or building, where it has room under SSM's limit: koi up's
// last read, once the log has been read to its end, is one.
export const StatusReplySchema = z.object({
	record: PreviewRecordSchema.omit({ deployment: true }),
	log: BuildLogPageSchema,
	deployment: DeploymentIdentitySchema.optional(),
	slice: DeploymentSliceSchema.optional(),
});

export type StatusReply = z.infer<typeof StatusReplySchema>;

// One preview in `koid ctl list`: the fields `koi list` shows, so the list
// stays short however much each record holds, and the identity of the
// deployment serving it, absent while nothing serves.
export const PreviewSummarySchema = PreviewRecordSchema.pick({
	label: true,
	status: true,
	commit: true,
	branch: true,
	pr: true,
	lastVisitAt: true,
	updatedAt: true,
}).extend({ deployment: DeploymentIdentitySchema.optional() });

export type PreviewSummary = z.infer<typeof PreviewSummarySchema>;

// `koid ctl list [after]`: previews in label order, starting after the label
// `after`, as many as fit in a reply far below SSM's limit. `next` is there
// when more follow; ask again with it as `after`.
export const PreviewListPageSchema = z.object({
	previews: z.array(PreviewSummarySchema),
	next: PreviewLabelSchema.optional(),
});

export type PreviewListPage = z.infer<typeof PreviewListPageSchema>;

// `koid ctl lease <label> --holder <text> --ttl-seconds <n>`: the lease koid
// took, and the deployment it holds, so the caller can stop when that is not
// the one it expects.
export const LeaseReplySchema = z.object({
	lease: LeaseSchema,
	deployment: DeploymentIdentitySchema,
});

export type LeaseReply = z.infer<typeof LeaseReplySchema>;

// `koid ctl release <label> <lease-id>` once the lease is gone.
export const ReleaseReplySchema = z.object({ released: z.literal(true) });

export type ReleaseReply = z.infer<typeof ReleaseReplySchema>;
