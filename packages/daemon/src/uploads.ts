import { createWriteStream } from 'node:fs';
import type { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { requestKey, sourceKey, type UpRequest, UpRequestSchema } from '@koi/shared';

// An upload store, from the daemon's side: read a request, fetch its source.
// On AWS the store is the uploads bucket; on a plain host it is the spool
// (spool-uploads.ts).
export interface Uploads {
	request(id: string): Promise<UpRequest>;
	// Holds the upload of `id` in the store until release(id). The deployer
	// claims a request as it accepts it and releases it once its build has
	// copied the source, so the store cannot drop the source in between.
	// Throws when there is no upload of that id to hold.
	claim(id: string): Promise<void>;
	release(id: string): Promise<void>;
	downloadSource(id: string, file: string): Promise<void>;
}

const MAX_SOURCE_BYTES = 2 * 1024 ** 3;
const MAX_REQUEST_BYTES = 256 * 1024;
const DOWNLOAD_TIMEOUT_MS = 10 * 60_000;

export function s3Uploads(bucket: string, client: S3Client): Uploads {
	return {
		async request(id) {
			const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: requestKey(id) }));
			if ((out.ContentLength ?? 0) > MAX_REQUEST_BYTES)
				throw new Error('request object is too large');
			const text = await out.Body?.transformToString();
			if (text === undefined) throw new Error(`request ${id} is empty`);
			const request = UpRequestSchema.parse(JSON.parse(text));
			if (request.id !== id) throw new Error(`request ${id} names itself ${request.id}`);
			return request;
		},
		// The bucket's own rule expires objects (infra/uploads.tf) and nothing
		// in koid deletes them, so there is nothing to hold or let go.
		async claim() {},
		async release() {},
		async downloadSource(id, file) {
			const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: sourceKey(id) }));
			if ((out.ContentLength ?? 0) > MAX_SOURCE_BYTES)
				throw new Error('source tarball is over 2 GB');
			if (out.Body === undefined) throw new Error(`source for ${id} is empty`);
			// Stream the SDK's Node body straight to the file. Converting it with
			// transformToWebStream() and handing that to Bun.write hangs for ever
			// in a compiled Bun binary (reproduced with a 497-byte object), so
			// the download is also bounded in time.
			await pipeline(out.Body as Readable, createWriteStream(file), {
				signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
			});
		},
	};
}
