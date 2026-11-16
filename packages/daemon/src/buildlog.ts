import { type FileHandle, mkdir, open, readdir, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import {
	AttemptSchema,
	type BuildLogPage,
	logCutNote,
	PreviewLabelSchema,
	type PreviewRecord,
} from '@koi/shared';
import { redact } from './redact.ts';

// The log of each attempt at a build, one file per attempt (see
// AttemptSchema) in a directory per label. `koi up` follows the log of its
// request's latest attempt by byte offset and `koi logs` reads the end of the
// label's latest attempt's log, both through koid ctl. A label keeps only the
// log of its latest build: opening a log removes the label's others.
export class BuildLogs {
	private readonly dir: string;

	constructor(
		stateDir: string,
		private readonly files: LogFiles = diskFiles,
	) {
		this.dir = join(stateDir, 'logs');
	}

	private labelDir(label: string): string {
		return join(this.dir, PreviewLabelSchema.parse(label));
	}

	private path(label: string, attempt: string): string {
		return join(this.labelDir(label), `${AttemptSchema.parse(attempt)}.build.log`);
	}

	// An attempt's log, or undefined if it has none. A record koid could not
	// give an attempt when it started (see PreviewStore.init) has attempt '',
	// and no log.
	private async file(label: string, attempt: string): Promise<LogFile | undefined> {
		return attempt === '' ? undefined : this.files(this.path(label, attempt));
	}

	// Opens an attempt's log and removes the label's other logs. Builds of a
	// label run one at a time, so none of those is being written; a reader of
	// one reads no lines from then on, and the record tells it a newer attempt
	// replaced the one it follows.
	async open(label: string, attempt: string): Promise<BuildLog> {
		const path = this.path(label, attempt);
		await rm(this.labelDir(label), { recursive: true, force: true });
		await mkdir(this.labelDir(label), { recursive: true });
		const sink = Bun.file(path).writer();
		return {
			line(text) {
				// Masked before it is cut, so a cut never leaves part of a key
				// unmasked.
				sink.write(`${capLine(`${new Date().toISOString()} ${redact(text)}`)}\n`);
			},
			async flush() {
				await sink.flush();
			},
			async close() {
				await sink.end();
			},
		};
	}

	// Logs koid kept before logs were per attempt, logs/<label>.build.log, were
	// each the log of their label's latest build. Each moves to its label's
	// latest attempt when the label has a record and no log of the new kind
	// yet; the rest are removed. koid runs this when it starts, before any
	// build.
	async upgrade(records: PreviewRecord[]): Promise<void> {
		const attempts = new Map(records.map((r) => [r.label, r.attempt]));
		const names = await readdir(this.dir).catch(() => [] as string[]);
		for (const name of names) {
			if (!name.endsWith(LEGACY_SUFFIX)) continue;
			const legacy = join(this.dir, name);
			const label = name.slice(0, -LEGACY_SUFFIX.length);
			const attempt = attempts.get(label);
			// Left for the next start, which may give the record an attempt.
			if (attempt === '') continue;
			if (attempt !== undefined && !(await hasEntries(this.labelDir(label)))) {
				await mkdir(this.labelDir(label), { recursive: true });
				await rename(legacy, this.path(label, attempt));
			} else {
				await rm(legacy, { force: true });
			}
		}
	}

	// The whole lines of an attempt's log after byte offset `since` (see
	// BuildLogPage), or none if the attempt has no log. At most maxLines
	// lines, whose size together (see jsonSize) is at most maxChars. Only
	// lines that end in a newline count, so a line still being written is
	// read whole next time.
	async read(
		label: string,
		attempt: string,
		since: number,
		maxLines: number,
		maxChars: number,
	): Promise<BuildLogPage> {
		const file = await this.file(label, attempt);
		if (file === undefined) return { next: since, lines: [] };
		try {
			return await pageAt(file, since, maxLines, maxChars);
		} finally {
			await file.close();
		}
	}

	// The last `lines` whole lines of an attempt's log as text, cut like
	// keepEnd to at most maxBytes, or nothing if the attempt has no log.
	async tail(label: string, attempt: string, lines: number, maxBytes: number): Promise<string> {
		const file = await this.file(label, attempt);
		if (file === undefined) return '';
		try {
			return await tailAt(file, lines, maxBytes);
		} finally {
			await file.close();
		}
	}
}

const LEGACY_SUFFIX = '.build.log';

async function hasEntries(dir: string): Promise<boolean> {
	return (await readdir(dir).catch(() => [] as string[])).length > 0;
}

// A file open for reading at byte offsets. Build logs are read through
// these and never whole, so a reply reads little more of a log than it
// returns, however long the build ran.
export interface LogFile {
	// The size when opened. Bytes written later are read next time.
	readonly size: number;
	// Up to `length` bytes from `position`; fewer at the end of the file.
	read(position: number, length: number): Promise<Buffer>;
	close(): Promise<void>;
}

// Opens a file for reading, or returns undefined if it cannot.
export type LogFiles = (path: string) => Promise<LogFile | undefined>;

export const diskFiles: LogFiles = async (path) => {
	let handle: FileHandle;
	try {
		handle = await open(path, 'r');
	} catch {
		return undefined;
	}
	try {
		const { size } = await handle.stat();
		return {
			size,
			async read(position, length) {
				const buffer = Buffer.alloc(length);
				const { bytesRead } = await handle.read(buffer, 0, length, position);
				return buffer.subarray(0, bytesRead);
			},
			close: () => handle.close(),
		};
	} catch (err) {
		await handle.close();
		throw err;
	}
};

// The most a stored line takes, its newline included. line() cuts longer
// lines, so a line's end is never further than this from its start.
export const LINE_MAX_BYTES = 4096;

// How far a read looks for a newline: far more than a line takes, for logs
// written before line() cut lines.
const SCAN_LIMIT = 64 * 1024;

// How much a search for a newline reads at a time.
const SCAN_BYTES = 16 * 1024;

// line, or as much of its start as fits in LINE_MAX_BYTES with CUT and a
// newline after it, ending on a whole character.
export function capLine(line: string): string {
	const max = LINE_MAX_BYTES - 1;
	if (Buffer.byteLength(line, 'utf8') <= max) return line;
	const bytes = Buffer.from(line, 'utf8');
	let end = max - Buffer.byteLength(CUT);
	while (end > 0 && ((bytes[end] as number) & 0xc0) === 0x80) end -= 1;
	return bytes.toString('utf8', 0, end) + CUT;
}

// The page after byte offset `since` (see BuildLogs.read). A line costs a
// page more than its bytes and newline (its quotes and a comma), so every
// line a page can hold whole is in the maxChars bytes after `since`, and
// only those are read. A line too long for a page is cut, and the page
// moves past it. Its end is looked for at most SCAN_LIMIT bytes on; a line
// longer than that, from before line() cut lines, is passed in pieces.
export async function pageAt(
	file: LogFile,
	since: number,
	maxLines: number,
	maxChars: number,
): Promise<BuildLogPage> {
	const chunk = await file.read(since, Math.max(0, Math.min(maxChars, file.size - since)));
	const lines: string[] = [];
	let used = 0;
	let at = 0;
	while (lines.length < maxLines) {
		const end = chunk.indexOf(0x0a, at);
		if (end === -1) break;
		const line = chunk.toString('utf8', at, end);
		const size = jsonSize(line) + 1;
		if (used + size > maxChars) break;
		lines.push(line);
		used += size;
		at = end + 1;
	}
	if (lines.length > 0) return { next: since + at, lines };
	// The first line does not fit whole, or has not ended yet.
	const inChunk = chunk.indexOf(0x0a);
	if (inChunk !== -1) {
		const line = chunk.toString('utf8', 0, inChunk);
		return { next: since + inChunk + 1, lines: [fitJson(line, maxChars - 1)] };
	}
	const limit = Math.min(file.size, since + SCAN_LIMIT);
	const end = await firstNewline(file, since + chunk.length, limit);
	// Still being written.
	if (end === -1 && limit === file.size) return { next: since, lines: [] };
	const next = end !== -1 ? end + 1 : await charStart(file, limit);
	return { next, lines: [fitJson(chunk.toString('utf8'), maxChars - 1)] };
}

// The last `n` whole lines as text, cut like keepEnd to at most maxBytes.
// Reads back from the end to the last newline, then at most maxBytes + 1
// bytes before it: if the lines start further back, they are longer than
// maxBytes, and keepEnd keeps no more of them than that. With no newline in
// the last SCAN_LIMIT bytes, which only a log from before line() cut lines
// can have, it is the end of that unfinished line, cut.
export async function tailAt(file: LogFile, n: number, maxBytes: number): Promise<string> {
	const floor = Math.max(0, file.size - SCAN_LIMIT);
	const last = await lastNewline(file, floor, file.size);
	if (last === -1) {
		if (floor === 0) return '';
		const start = file.size - (maxBytes + 1);
		return keepEnd((await file.read(start, maxBytes + 1)).toString('utf8'), maxBytes);
	}
	const start = Math.max(0, last + 1 - (maxBytes + 1));
	const window = await file.read(start, last + 1 - start);
	// Back over n newlines before the last; -1 when the window runs out first.
	let from = window.length - 1;
	for (let i = 0; i < n && from !== -1; i++) {
		from = from === 0 ? -1 : window.lastIndexOf(0x0a, from - 1);
	}
	return keepEnd(window.toString('utf8', from + 1), maxBytes);
}

// The offset of the first newline in [from, to), or -1.
async function firstNewline(file: LogFile, from: number, to: number): Promise<number> {
	for (let at = from; at < to; at += SCAN_BYTES) {
		const i = (await file.read(at, Math.min(SCAN_BYTES, to - at))).indexOf(0x0a);
		if (i !== -1) return at + i;
	}
	return -1;
}

// The offset of the last newline in [from, to), or -1.
async function lastNewline(file: LogFile, from: number, to: number): Promise<number> {
	for (let end = to; end > from; ) {
		const at = Math.max(from, end - SCAN_BYTES);
		const i = (await file.read(at, end - at)).lastIndexOf(0x0a);
		if (i !== -1) return at + i;
		end = at;
	}
	return -1;
}

// The offset of the first character that starts at or after `at`.
async function charStart(file: LogFile, at: number): Promise<number> {
	const bytes = await file.read(at, 3);
	let i = 0;
	while (i < bytes.length && ((bytes[i] as number) & 0xc0) === 0x80) i += 1;
	return at + i;
}

// text, if it is at most max characters; otherwise a line saying it was cut,
// then the whole lines from its end that fit in max with that line. Counted
// in UTF-8 bytes, never fewer than the characters SSM counts.
export function keepEnd(text: string, max: number): string {
	const bytes = Buffer.from(text, 'utf8');
	if (bytes.length <= max) return text;
	const note = logCutNote(max);
	let start = bytes.length - (max - Buffer.byteLength(note));
	// Start on a character, not inside one.
	while (start < bytes.length && ((bytes[start] as number) & 0xc0) === 0x80) start += 1;
	let kept = bytes.subarray(start).toString('utf8');
	// And on a line, unless the end is one long line.
	const cutInLine = bytes[start - 1] !== 0x0a;
	const newline = kept.indexOf('\n');
	if (cutInLine && newline !== -1 && newline < kept.length - 1) kept = kept.slice(newline + 1);
	return note + kept;
}

// The size of text as a JSON string, in UTF-8 bytes. Never less than the
// characters SSM counts, whether it counts characters or bytes.
export function jsonSize(text: string): number {
	return Buffer.byteLength(JSON.stringify(text), 'utf8');
}

const CUT = ' [cut by koid]';

// text, or as much of its start as fits in maxSize (see jsonSize) with CUT
// after it.
export function fitJson(text: string, maxSize: number): string {
	if (jsonSize(text) <= maxSize) return text;
	if (jsonSize(CUT) > maxSize) return '';
	// Every character takes at least one byte, so no longer prefix fits.
	let low = 0;
	let high = Math.min(text.length, maxSize);
	while (low < high) {
		const mid = Math.ceil((low + high) / 2);
		if (jsonSize(text.slice(0, mid) + CUT) <= maxSize) low = mid;
		else high = mid - 1;
	}
	// Do not end on half of a surrogate pair.
	const code = text.charCodeAt(low - 1);
	if (code >= 0xd800 && code <= 0xdbff) low -= 1;
	return text.slice(0, low) + CUT;
}

export interface BuildLog {
	// Lines reach the file soon after, not at once; flush waits for them.
	line(text: string): void;
	flush(): Promise<void>;
	close(): Promise<void>;
}
