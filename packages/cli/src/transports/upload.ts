import { createHash } from 'node:crypto';
import {
	CommitReplySchema,
	ErrorReplySchema,
	SourceReceivedSchema,
	UploadCommittedSchema,
	UploadTicketSchema,
	type UpRequest,
} from '@koi/shared';
import { type ByteRelay, HttpRelayClient, type RelayReply } from '../http1.ts';

// The source upload as koid's upload API takes it (packages/daemon/src/
// upload-api.ts), over any byte relay to koid's control socket: the SSH
// transport's tunnel through the gateway (ssh.ts), or the local transport's
// own connection to the socket (local.ts). Both send the same three
// requests and read the replies with the same schemas, so what an upload is
// does not depend on how koi reaches the host.

export interface Source {
	tarball: string;
	size: number;
	sha256: string;
}

// How many times a commit koid could not make durable is sent again.
const COMMIT_RETRIES = 2;

// The upload sequence: a ticket for the request id, size and digest; the
// archive streamed from disk; the request committed. Each reply is parsed
// with the shared schemas; a reply that does not fit stops the upload.
// `where` names the host in messages. A relay that breaks throws
// RelayBrokenError, and one that carried nothing for `idleMs`
// RelayIdleError; the caller decides what each means for its transport.
export async function uploadSequence(
	where: string,
	relay: ByteRelay,
	request: UpRequest,
	source: Source,
	sleep: (ms: number) => Promise<void>,
	idleMs: number,
): Promise<void> {
	const http = new HttpRelayClient(relay, undefined, idleMs);
	const json = (body: unknown) => ({
		headers: { 'content-type': 'application/json' },
		body: new TextEncoder().encode(JSON.stringify(body)),
	});
	const { label } = request;
	const ticket = await http.request({
		method: 'POST',
		path: '/v1/uploads',
		...json({ requestId: request.id, sizeBytes: source.size, sha256: source.sha256 }),
	});
	switch (ticket.status) {
		case 200: {
			// This content is on the host already, committed and durable.
			const committed = UploadCommittedSchema.safeParse(parseJson(ticket.body));
			if (!committed.success || committed.data.requestId !== request.id) {
				throw badReply(where, 'POST /v1/uploads', ticket);
			}
			return;
		}
		case 201:
			break;
		case 409:
			throw new Error(
				`koid on ${where} already holds request ${request.id} with other content: ${errorText(ticket)}`,
			);
		case 413:
			throw new Error(`koid on ${where} refuses the source of ${label}: ${errorText(ticket)}`);
		case 507:
			throw new Error(
				`koid on ${where} has no room for the source of ${label}: ${errorText(ticket)}. Try again once uploads have expired or previews were removed`,
			);
		default:
			throw unexpected(where, 'POST /v1/uploads', ticket);
	}
	const parsedTicket = UploadTicketSchema.safeParse(parseJson(ticket.body));
	if (!parsedTicket.success) throw badReply(where, 'POST /v1/uploads', ticket);
	const { uploadId } = parsedTicket.data;

	const put = await http.request({
		method: 'PUT',
		path: `/v1/uploads/${uploadId}/source`,
		headers: { 'content-type': 'application/gzip' },
		body: { chunks: Bun.file(source.tarball).stream(), length: source.size },
	});
	if (put.status !== 200) {
		throw new Error(
			`koid on ${where} did not take the source of ${label} (${put.status}): ${errorText(put)}`,
		);
	}
	const received = SourceReceivedSchema.safeParse(parseJson(put.body));
	if (!received.success) throw badReply(where, 'PUT source', put);
	if (received.data.sizeBytes !== source.size || received.data.sha256 !== source.sha256) {
		throw new Error(
			`koid on ${where} received ${received.data.sizeBytes} bytes with digest ${received.data.sha256}, not the ${source.size} bytes with digest ${source.sha256} koi sent`,
		);
	}

	for (let tries = 0; ; tries++) {
		const commit = await http.request({
			method: 'POST',
			path: `/v1/uploads/${uploadId}/commit`,
			...json(request),
		});
		if (commit.status === 200) {
			const reply = CommitReplySchema.safeParse(parseJson(commit.body));
			if (!reply.success) throw badReply(where, 'POST commit', commit);
			if (reply.data.requestId !== request.id || reply.data.label !== label) {
				throw new Error(
					`koid on ${where} committed the upload as ${reply.data.label} (request ${reply.data.requestId}), not ${label} (request ${request.id})`,
				);
			}
			return;
		}
		// The entry is on the disk but not durable yet, or the disk filled
		// up at the last step: koid says to commit again.
		if ((commit.status === 500 || commit.status === 507) && tries < COMMIT_RETRIES) {
			await sleep(1000);
			continue;
		}
		throw new Error(
			`koid on ${where} did not commit the upload of ${label} (${commit.status}): ${errorText(commit)}`,
		);
	}
}

function parseJson(body: Uint8Array): unknown {
	try {
		return JSON.parse(new TextDecoder().decode(body));
	} catch {
		return undefined;
	}
}

// koid's error for a refusal, or else the body as text.
function errorText(reply: RelayReply): string {
	const text = new TextDecoder().decode(reply.body).trim();
	const parsed = ErrorReplySchema.safeParse(parseJson(reply.body));
	return parsed.success ? parsed.data.error : text || `(empty reply with status ${reply.status})`;
}

function badReply(where: string, what: string, reply: RelayReply): Error {
	return new Error(
		`koid on ${where} answered ${what} with ${reply.status} and a body koi cannot read: ${new TextDecoder().decode(reply.body).slice(0, 200)}`,
	);
}

function unexpected(where: string, what: string, reply: RelayReply): Error {
	return new Error(`koid on ${where} answered ${what} with ${reply.status}: ${errorText(reply)}`);
}

// The SHA-256 of the file in hex, read a chunk at a time. The read stops at
// the first chunk after `signal` fires: an archive of up to 2 GiB would
// otherwise be hashed to the end after the caller stopped waiting.
export async function digestFile(path: string, signal?: AbortSignal): Promise<string> {
	signal?.throwIfAborted();
	const hash = createHash('sha256');
	for await (const chunk of Bun.file(path).stream()) {
		// Leaving the loop cancels the stream, so the file is closed.
		signal?.throwIfAborted();
		hash.update(chunk);
	}
	return hash.digest('hex');
}
