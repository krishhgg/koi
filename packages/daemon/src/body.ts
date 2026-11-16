import type { z } from 'zod';

// Bounded reads of request bodies. Bun's idle timeout does not bound a body
// (see startControlServer in control.ts), so every handler that reads one
// reads it through here, within a size and a time of its own.

export class BodyTooLargeError extends Error {}

export class BodyTimeoutError extends Error {}

// The whole body, or BodyTooLargeError as soon as it passes `maxBytes`, or
// BodyTimeoutError when it has not ended within `timeoutMs`. The stream is
// cancelled either way, so the rest is never read.
export async function readBody(
	request: Request,
	maxBytes: number,
	timeoutMs: number,
): Promise<Buffer> {
	const body = request.body;
	if (body === null) return Buffer.alloc(0);
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	let timedOut = false;
	// Cancelling the reader resolves the pending read as done, so the loop
	// ends however slowly the client sends.
	const timer = setTimeout(() => {
		timedOut = true;
		void reader.cancel().catch(() => {});
	}, timeoutMs);
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maxBytes) {
				await reader.cancel().catch(() => {});
				throw new BodyTooLargeError(`the body is over ${maxBytes} bytes`);
			}
			chunks.push(value);
		}
	} finally {
		clearTimeout(timer);
	}
	// A read that ended because the timer cancelled it looks like the end of
	// the body; the flag tells them apart.
	if (timedOut) {
		throw new BodyTimeoutError(`the body did not arrive within ${timeoutMs / 1000} seconds`);
	}
	return Buffer.concat(chunks);
}

// The body as JSON that `schema` accepts. Throws what readBody throws,
// SyntaxError for text that is not JSON, and ZodError for JSON the schema
// refuses.
export async function readJson<T>(
	request: Request,
	schema: z.ZodType<T>,
	maxBytes: number,
	timeoutMs: number,
): Promise<T> {
	const bytes = await readBody(request, maxBytes, timeoutMs);
	return schema.parse(JSON.parse(bytes.toString('utf8')));
}
