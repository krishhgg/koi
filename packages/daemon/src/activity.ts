import { utimes, writeFile } from 'node:fs/promises';
import { labelFromHost, RESERVED_LABELS } from '@koi/shared';
import { exec } from './exec.ts';

// Keeps the box awake while someone is using it. The idle timer on the box
// (host/cloud-init.sh) stops the instance when the stamp file is older than the
// idle limit; everything here exists to refresh that stamp at the right times
// and to remember when each preview was last visited, for expiry.
export class Activity {
	// The first and the latest visit to each label since the last drain.
	private readonly visits = new Map<string, { first: number; last: number }>();
	private lastTouch = 0;

	constructor(
		private readonly stamp: string,
		private readonly now: () => number = Date.now,
		private readonly minTouchIntervalMs = 30_000,
		// Which labels count as visits; the deployer's live previews.
		private readonly isLive: (label: string) => boolean = () => true,
	) {}

	// Refreshes the stamp, at most once per interval unless forced.
	async touch(force = false): Promise<void> {
		const at = this.now();
		if (!force && at - this.lastTouch < this.minTouchIntervalMs) return;
		this.lastTouch = at;
		const when = new Date(at);
		try {
			await utimes(this.stamp, when, when);
		} catch {
			await writeFile(this.stamp, '');
		}
	}

	// Counts a request for a live preview. A request for one of koi's own
	// pages (RESERVED_LABELS: the keys page and its API) keeps the box awake
	// too, though it has no record to renew. Anything else is ignored.
	visit(label: string): void {
		if ((RESERVED_LABELS as readonly string[]).includes(label)) {
			void this.touch();
			return;
		}
		if (!this.isLive(label)) return;
		const at = this.now();
		const seen = this.visits.get(label);
		this.visits.set(
			label,
			seen === undefined
				? { first: at, last: at }
				: { first: Math.min(seen.first, at), last: Math.max(seen.last, at) },
		);
		void this.touch();
	}

	// Visits since the last call, for writing to preview records: the first
	// and the latest to each label, or one if they are the same. The latest
	// alone is not enough. When a preview's deadline falls between the two,
	// the first visit renews it, and only then does the latest count.
	drainVisits(): Array<[string, number]> {
		const out: Array<[string, number]> = [];
		for (const [label, { first, last }] of this.visits) {
			out.push([label, first]);
			if (last !== first) out.push([label, last]);
		}
		this.visits.clear();
		return out;
	}
}

// The preview label a Caddy access log line was for, if any.
export function labelFromLogLine(line: string, domain: string): string | null {
	let entry: unknown;
	try {
		entry = JSON.parse(line);
	} catch {
		return null;
	}
	if (typeof entry !== 'object' || entry === null || !('request' in entry)) return null;
	const request = entry.request;
	if (typeof request !== 'object' || request === null || !('host' in request)) return null;
	return typeof request.host === 'string' ? labelFromHost(request.host, domain) : null;
}

// Receives Caddy's access log (one JSON object per line) on a localhost TCP
// port and reports which preview each request was for. A request is logged
// when it finishes, so this misses a WebSocket while it is open; see
// hasEstablishedConnections for that.
export function startLogSink(port: number, domain: string, onVisit: (label: string) => void) {
	const decoder = new TextDecoder();
	return Bun.listen<{ buffer: string }>({
		hostname: '127.0.0.1',
		port,
		socket: {
			open(socket) {
				socket.data = { buffer: '' };
			},
			data(socket, chunk) {
				const lines = (socket.data.buffer + decoder.decode(chunk, { stream: true })).split('\n');
				socket.data.buffer = (lines.pop() ?? '').slice(-64 * 1024);
				for (const line of lines) {
					const label = labelFromLogLine(line, domain);
					if (label !== null) onVisit(label);
				}
			},
		},
	});
}

// Whether anything (Caddy, in practice) holds an open TCP connection to this
// container address: a reviewer with an app page open over a WebSocket.
export async function hasEstablishedConnections(ip: string): Promise<boolean> {
	const r = await exec(['ss', '-Htn', 'state', 'established', 'dst', ip], { timeoutMs: 5_000 });
	return r.code === 0 && r.stdout.trim() !== '';
}
