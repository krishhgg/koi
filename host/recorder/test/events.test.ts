import { describe, expect, test } from 'bun:test';
import { EventLog, MAX_FIELD_CHARS, OVERLONG_FIELD } from '../src/events.ts';

describe('EventLog', () => {
	test('numbers events in order and pages them after a sequence number', () => {
		const log = new EventLog(100, () => new Date('2026-10-06T12:00:00.000Z'));
		expect(log.last).toBe(0);
		expect(log.push('a', { x: 1 })).toBe(1);
		expect(log.push('b', { contextId: 'x1', skipped: undefined })).toBe(2);
		expect(log.push('c')).toBe(3);
		expect(log.last).toBe(3);
		expect(log.next).toBe(4);
		expect(log.page(0, 2)).toEqual({
			events: [
				{ seq: 1, at: '2026-10-06T12:00:00.000Z', type: 'a', x: 1 },
				{ seq: 2, at: '2026-10-06T12:00:00.000Z', type: 'b', contextId: 'x1' },
			],
			next: 2,
			dropped: 0,
		});
		expect(log.page(2, 10).events.map((e) => e.seq)).toEqual([3]);
		expect(log.page(3, 10)).toEqual({ events: [], next: 3, dropped: 0 });
	});

	test('drops the oldest past its capacity and tells a reader what it never got', () => {
		const log = new EventLog(3);
		for (let i = 0; i < 5; i++) log.push('e', { i });
		const page = log.page(0, 10);
		expect(page.events.map((e) => e.seq)).toEqual([3, 4, 5]);
		expect(page.dropped).toBe(2);
		expect(log.dropped).toBe(2);
		expect(log.oldest).toBe(3);
		// A reader that had read up to 2 lost nothing it had not read.
		expect(log.page(2, 10)).toMatchObject({ dropped: 0 });
		// One that had read up to 1 lost only event 2.
		expect(log.page(1, 10)).toMatchObject({ dropped: 1 });
	});

	test('an eviction of an event the reader had read is not a gap', () => {
		const log = new EventLog(3);
		for (let i = 0; i < 3; i++) log.push('e', { i });
		// Read everything, then push past the capacity by less than a ring.
		expect(log.page(0, 10)).toMatchObject({ next: 3, dropped: 0 });
		log.push('e');
		log.push('e');
		expect(log.dropped).toBe(2);
		expect(log.page(3, 10)).toMatchObject({ next: 5, dropped: 0 });
		// Push a whole ring and more without reading: the gap is what the
		// reader missed, not every eviction since the start.
		for (let i = 0; i < 5; i++) log.push('e');
		expect(log.dropped).toBe(7);
		expect(log.oldest).toBe(8);
		expect(log.page(5, 10)).toMatchObject({ next: 10, dropped: 2 });
		expect(log.page(10, 10)).toEqual({ events: [], next: 10, dropped: 0 });
	});

	test('discards an overlong string field whole and names it', () => {
		const log = new EventLog(10);
		const secret = 'the-login-value-12345';
		log.push('page-error', {
			text: `${'x'.repeat(MAX_FIELD_CHARS - 5)}${secret}`,
			n: 5000,
			url: 'http://app.x.invalid/',
		});
		const event = log.page(0, 1).events[0];
		if (event === undefined) throw new Error('no event');
		expect(event.text).toBe(OVERLONG_FIELD);
		expect(event.truncatedFields).toEqual(['text']);
		expect(event.n).toBe(5000);
		expect(event.url).toBe('http://app.x.invalid/');
		expect(JSON.stringify(event)).not.toContain(secret.slice(0, 8));
		// A field of exactly the limit is kept.
		log.push('e', { text: 'y'.repeat(MAX_FIELD_CHARS) });
		const kept = log.page(1, 1).events[0];
		if (kept === undefined) throw new Error('no event');
		expect((kept.text as string).length).toBe(MAX_FIELD_CHARS);
		expect(kept.truncatedFields).toBeUndefined();
	});
});
