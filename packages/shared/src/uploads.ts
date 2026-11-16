import { z } from 'zod';
import { PreviewLabelSchema } from './preview.ts';
import { RequestIdSchema, UpRequestSchema } from './request.ts';

// The upload API on koid's control socket, for a CLI that reaches the box
// over SSH and has no bucket to put a request in. Three calls, in order:
// POST /v1/uploads for a ticket, PUT /v1/uploads/<upload-id>/source with
// the archive, POST /v1/uploads/<upload-id>/commit with the request. The
// daemon serves it (packages/daemon/src/upload-api.ts); both sides parse
// what crosses the socket with the schemas here.

export const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

// The body of POST /v1/uploads: which request the archive is for, and its
// exact size and digest, which the daemon holds the PUT to.
export const CreateUploadSchema = z.object({
	requestId: RequestIdSchema,
	sizeBytes: z.number().int().positive(),
	sha256: Sha256Schema,
});

export type CreateUpload = z.infer<typeof CreateUploadSchema>;

// The daemon's random name for an upload under way. It names nothing a
// caller chose.
export const UploadIdSchema = z.string().regex(/^[0-9a-f]{32}$/);

// 201 from POST /v1/uploads: a ticket, good until expiresAt.
export const UploadTicketSchema = z.object({
	uploadId: UploadIdSchema,
	expiresAt: z.iso.datetime(),
});

export type UploadTicket = z.infer<typeof UploadTicketSchema>;

// 200 from POST /v1/uploads: this content is already committed under the
// request id, so there is nothing to send.
export const UploadCommittedSchema = z.object({
	committed: z.literal(true),
	requestId: RequestIdSchema,
});

export type UploadCommitted = z.infer<typeof UploadCommittedSchema>;

// 200 from PUT /v1/uploads/<upload-id>/source: what arrived, whole and
// matching the ticket.
export const SourceReceivedSchema = z.object({
	sizeBytes: z.number().int().positive(),
	sha256: Sha256Schema,
});

export type SourceReceived = z.infer<typeof SourceReceivedSchema>;

// The body of POST /v1/uploads/<upload-id>/commit is the request itself, as
// the CLI would have put in the bucket.
export const CommitUploadSchema = UpRequestSchema;

export type CommitUpload = z.infer<typeof CommitUploadSchema>;

// 200 from the commit: the request is published under its id, for `koid ctl
// up <request-id>`.
export const CommitReplySchema = z.object({
	requestId: RequestIdSchema,
	label: PreviewLabelSchema,
});

export type CommitReply = z.infer<typeof CommitReplySchema>;
