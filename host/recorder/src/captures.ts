import { createHash } from 'node:crypto';

// Raw captures, held in this process's memory from the moment they are
// taken until koid has read, sanitized and acknowledged them. Never on the
// filesystem: Chromium and this server share uid 10001, so a file under
// /tmp is readable through the browser, and a page could read a capture of
// another page back. Memory is not. Nothing here is evidence: koid hashes
// and keeps the sanitized result, and frees the raw bytes by acknowledging.
// The space is bounded; a run that captures faster than koid acknowledges
// fails its captures rather than grow without limit.

export interface StoredCapture {
	captureId: string;
	kind: string;
	mediaType: string;
	size: number;
	sha256: string;
	bytes: Uint8Array;
}

export class CaptureError extends Error {
	constructor(
		readonly code: 'capture_too_large' | 'capture_space',
		message: string,
	) {
		super(message);
	}
}

export class CaptureStore {
	private next = 1;
	private readonly held = new Map<string, StoredCapture>();
	private bytes = 0;

	constructor(private readonly limits: { perCapture: number; total: number }) {}

	put(kind: string, mediaType: string, bytes: Uint8Array): StoredCapture {
		if (bytes.length > this.limits.perCapture) {
			throw new CaptureError(
				'capture_too_large',
				`the capture is ${bytes.length} bytes; the most the recorder holds is ${this.limits.perCapture}`,
			);
		}
		if (this.bytes + bytes.length > this.limits.total) {
			throw new CaptureError(
				'capture_space',
				'the recorder holds too many unacknowledged captures already',
			);
		}
		const captureId = `c${this.next++}`;
		const stored: StoredCapture = {
			captureId,
			kind,
			mediaType,
			size: bytes.length,
			sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
			// A copy: the caller's buffer may be a view of something reused.
			bytes: new Uint8Array(bytes),
		};
		this.held.set(captureId, stored);
		this.bytes += bytes.length;
		return stored;
	}

	get(captureId: string): StoredCapture | undefined {
		return this.held.get(captureId);
	}

	// koid's acknowledgment: the raw bytes go.
	delete(captureId: string): boolean {
		const stored = this.held.get(captureId);
		if (stored === undefined) return false;
		this.held.delete(captureId);
		this.bytes -= stored.size;
		return true;
	}

	stats(): { count: number; bytes: number } {
		return { count: this.held.size, bytes: this.bytes };
	}
}
