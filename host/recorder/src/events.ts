// The recorder's event feed: everything it saw, numbered in order, held in
// a bounded ring until koid reads it over the control API. koid gives each
// event its host sequence number and writes it to the run's events file;
// what this ring loses before koid reads it is reported as `dropped` on the
// page that would have held it, which the run records as a gap in
// observation.

export interface RecorderEvent {
	seq: number;
	at: string;
	type: string;
	contextId?: string;
	pageId?: string;
	[field: string]: unknown;
}

// The most text one field may carry. A longer field is discarded whole,
// never cut: the recorder knows no secret values and cannot redact, and a
// field cut after a long prefix would keep most of a secret that sits past
// the cut. koid scrubs what it reads, but only a whole value matches.
export const MAX_FIELD_CHARS = 4096;

// What stands in for a discarded field. koid knows this text
// (RECORDER_OVERLONG_FIELD in packages/shared) and records a limitation when
// it reads an event that carries it; the event's `truncatedFields` names the
// fields.
export const OVERLONG_FIELD = `[koi: a field over ${MAX_FIELD_CHARS} characters was discarded]`;

export class EventLog {
	private readonly ring: RecorderEvent[] = [];
	private nextSeq = 1;
	private droppedCount = 0;

	constructor(
		private readonly capacity: number,
		private readonly now: () => Date = () => new Date(),
	) {}

	// Records an event and returns its sequence number. A string field over
	// MAX_FIELD_CHARS is replaced by OVERLONG_FIELD and named in
	// `truncatedFields`; nothing here decides what is sensitive, koid's
	// sanitizer does.
	push(type: string, fields: Record<string, unknown> = {}): number {
		const seq = this.nextSeq++;
		const event: RecorderEvent = { seq, at: this.now().toISOString(), type };
		const truncated: string[] = [];
		for (const [key, value] of Object.entries(fields)) {
			if (value === undefined) continue;
			if (typeof value === 'string' && value.length > MAX_FIELD_CHARS) {
				event[key] = OVERLONG_FIELD;
				truncated.push(key);
			} else {
				event[key] = value;
			}
		}
		if (truncated.length > 0) event.truncatedFields = truncated;
		this.ring.push(event);
		if (this.ring.length > this.capacity) {
			this.ring.shift();
			this.droppedCount += 1;
		}
		return seq;
	}

	// The sequence number the next event will get.
	get next(): number {
		return this.nextSeq;
	}

	// The last sequence number given out, 0 before any.
	get last(): number {
		return this.nextSeq - 1;
	}

	// Every event the ring has lost since the start, read or not. For the
	// health report; a reader's gap is what page() reports.
	get dropped(): number {
		return this.droppedCount;
	}

	// The sequence number of the oldest event still in the ring, or the next
	// one when the ring is empty.
	get oldest(): number {
		return this.ring[0]?.seq ?? this.nextSeq;
	}

	// Up to `limit` events after `after`, in order, and the number the next
	// read continues after. `dropped` counts the events after `after` the
	// ring lost before this read: the ones the reader never got and now
	// cannot. An eviction of an event the reader had read is not a gap, so
	// a long run past the ring's capacity reports nothing as long as koid
	// keeps up.
	page(after: number, limit: number): { events: RecorderEvent[]; next: number; dropped: number } {
		const events: RecorderEvent[] = [];
		for (const event of this.ring) {
			if (event.seq <= after) continue;
			events.push(event);
			if (events.length >= limit) break;
		}
		const next = events.length > 0 ? (events[events.length - 1]?.seq ?? after) : after;
		return { events, next, dropped: Math.max(0, this.oldest - after - 1) };
	}
}
