import { createHash, randomBytes } from 'node:crypto';
import { constants, type Stats } from 'node:fs';
import {
	type FileHandle,
	lstat,
	mkdir,
	open,
	readdir,
	realpath,
	rename,
	rm,
} from 'node:fs/promises';
import { dirname, join, sep } from 'node:path';
import {
	type CommitReply,
	CommitUploadSchema,
	CreateUploadSchema,
	RequestIdSchema,
	type SourceReceived,
	type UploadCommitted,
	UploadIdSchema,
	type UploadTicket,
	type UpRequest,
} from '@koi/shared';
import { ZodError, type z } from 'zod';
import { BodyTimeoutError, BodyTooLargeError, readJson } from './body.ts';
import { minFreeBytes, diskSpace as statDiskSpace } from './fsutil.ts';
import { Mutex } from './lock.ts';
import {
	BrokenUploadError,
	isCode,
	MAX_REQUEST_BYTES,
	MAX_SOURCE_BYTES,
	NoSuchUploadError,
	openReadyFile,
	REQUEST_FILE,
	readReadyRequest,
	readWhole,
	SOURCE_FILE,
	type SpoolLayout,
	spoolLayout,
} from './spool-uploads.ts';

// The upload API on the control socket, for a CLI that reaches the box over
// SSH and has no S3 bucket to put a request in. The schemas of what crosses
// the socket are in packages/shared (uploads.ts). Three calls, in order:
//
//   POST /v1/uploads                      {requestId, sizeBytes, sha256}
//     201 {uploadId, expiresAt}           a ticket; disk space is reserved
//     200 {committed: true, requestId}    this content is already committed
//                                         and durable
//     408                                 the JSON took over thirty seconds
//     409                                 the id is committed with other content
//     413                                 sizeBytes is over 2 GiB, or the
//                                         JSON is over 256 KiB
//     500                                 this content is committed, but the
//                                         sync that makes it durable failed;
//                                         try again
//     507                                 the spool budget or the disk is full
//   PUT  /v1/uploads/<upload-id>/source   the archive, streamed
//     200 {sizeBytes, sha256}             received whole, matching, on disk
//     400                                 the body ended before sizeBytes
//     404                                 no such ticket, or it expired
//     408                                 the body took over ten minutes
//     409                                 the ticket already has its source
//     413                                 the body passed sizeBytes
//     422                                 the body's digest is not sha256
//     507                                 the disk filled up
//   POST /v1/uploads/<upload-id>/commit   the request JSON
//     200 {requestId, label}              published under ready/<request-id>
//                                         and durable
//     400                                 malformed, another id, or created
//                                         outside the time window
//     404                                 no such ticket, or it expired
//     408                                 the JSON took over thirty seconds
//     409                                 no source yet, or the id was
//                                         committed with other content
//     413                                 the JSON is over 256 KiB, as sent
//                                         or once its defaults are filled in
//     500                                 published, but the sync that makes
//                                         it durable failed; commit again
//     507                                 the disk filled up
//
// A retry of any step with the same content gets the same answer. `ctl up
// <request-id>` then reads the committed entry (spool-uploads.ts). The
// upload id is random and names nothing on disk that a caller could choose.
// A commit answers 200 only once the ready directory is synced, so an
// upload the CLI saw acknowledged survives a crash of the box. The same
// holds for a POST /v1/uploads that finds its content committed: the ledger
// says whether each entry is known durable, an entry read from the disk at
// startup is not until this koid has synced the directory, and the call
// syncs before it answers 200. An entry whose request file is missing or
// does not parse, or whose source is missing, is broken: a removal failed
// part way through it. The reader would refuse it, so it is never
// acknowledged, and cleanup removes it whatever its age, as does a POST
// /v1/uploads for its id, which then issues a ticket in its place.
//
// Bytes are counted as they arrive, never trusted from Content-Length, and
// the archive goes straight to a file: the daemon never holds it in memory.
// Every body is read within a bound of bytes and time, because Bun's idle
// timeout covers none of it (control.ts).
//
// What the spool holds and has promised is kept in a ledger in memory: the
// bytes of each committed entry, and for each ticket a reservation of its
// declared source plus the most a request file can be. Admission, commit,
// expiry, claims and cleanup change the ledger under one mutex, so an
// admission never counts while a commit moves an entry or an expiry removes
// one; the disk is read for it only at startup. A ticket with a PUT or a
// commit under way is held: expiry leaves it alone until the request has
// answered, so a commit still reading its JSON when the hour runs out keeps
// the reservation it is about to turn into an entry. An expired ticket
// whose directory could not be removed keeps its reservation until a later
// round removes it, so its bytes are never given to another upload while
// they are on the disk. The deployer claims an entry as it accepts the
// request and releases it once its build has copied the source; cleanup
// leaves a claimed entry whatever its age.

export interface UploadLimits {
	maxSourceBytes: number;
	maxRequestBytes: number;
	// A PUT must deliver the whole archive within this.
	sourceTimeoutMs: number;
	// A ticket or a commit must deliver its JSON within this.
	requestTimeoutMs: number;
	// A ticket not committed by then is dropped with what it received.
	ticketTtlMs: number;
	// A committed entry nobody claims lives this long.
	readyTtlMs: number;
	// How old, and how far in the future, a request's createdAt may be.
	createdAtMaxAgeMs: number;
	createdAtMaxAheadMs: number;
}

export const UPLOAD_LIMITS: UploadLimits = {
	maxSourceBytes: MAX_SOURCE_BYTES,
	maxRequestBytes: MAX_REQUEST_BYTES,
	sourceTimeoutMs: 10 * 60_000,
	requestTimeoutMs: 30_000,
	ticketTtlMs: 60 * 60_000,
	readyTtlMs: 24 * 60 * 60_000,
	createdAtMaxAgeMs: 60 * 60_000,
	createdAtMaxAheadMs: 5 * 60_000,
};

// Bun.serve refuses a body over this before the handler sees it. A little
// over the source limit, so the handler's own 413, which says why, comes
// first for anything a client could reasonably send.
export const UPLOAD_SERVER_BODY_LIMIT = MAX_SOURCE_BYTES + 1024 ** 2;

export interface UploadApiOptions {
	spoolDir: string;
	// The most the spool may hold: committed entries and reservations together.
	budgetBytes: number;
	log: (message: string) => void;
	now?: () => number;
	diskSpace?: (path: string) => Promise<{ free: number; size: number }>;
	limits?: Partial<UploadLimits>;
}

// `published` is from the rename into ready, when the ledger counts the
// entry, to the sync of the ready directory that makes the rename durable;
// `committed` is from that sync on.
type TicketState = 'open' | 'receiving' | 'received' | 'committing' | 'published' | 'committed';

interface Ticket {
	uploadId: string;
	requestId: string;
	sizeBytes: number;
	sha256: string;
	createdAt: number;
	state: TicketState;
	// Set once the ticket is past its hour and expiry has begun. A ticket
	// whose directory could not be removed stays on the map with this set,
	// so it keeps its reservation and serves no request, whatever the clock
	// says, until a later round removes the directory.
	expired: boolean;
	// Requests under way on this ticket, a PUT or a commit, from taking the
	// ticket (holdTicket) to answering. Expiry leaves a ticket with any: the
	// request has checked the ticket and acts on what it saw.
	busy: number;
	// Bytes of the source on disk so far. The disk's free space shows them;
	// the rest of the reservation it does not. Grows outside `spool` as the
	// source arrives; goes back to zero only under it (receive's discard).
	received: number;
	// The request the commit published under ready, from the rename on. A
	// retry of the commit is compared against it.
	published?: UpRequest;
	// What the commit answered, for a retry of it. Set only once the ready
	// directory is synced: a retry before that waits for the sync under
	// way, or runs it again if it failed, before it gets this reply.
	committed?: CommitReply;
}

type BodyOutcome =
	| { kind: 'done'; sha256: string }
	| { kind: 'oversize' }
	| { kind: 'short'; received: number }
	| { kind: 'timeout' }
	| { kind: 'disconnected'; received: number };

// An entry under ready as the ledger knows it. `durable` is set once the
// ready directory has been synced with the entry in it. An entry read from
// the disk at startup starts without it: nothing on the disk says whether
// the koid that wrote it got as far as that sync, so the first call that
// would acknowledge it syncs first.
interface Entry {
	bytes: number;
	durable: boolean;
}

// What ready/<id> holds, as the reader will see it (openEntry).
type ReadyEntry =
	| { kind: 'none' }
	| { kind: 'whole'; request: UpRequest; source: { handle: FileHandle; size: number } }
	| { kind: 'broken'; why: string }
	| { kind: 'unreadable'; why: string };

// How ready/<id> compares with a source a caller declares (compareReady).
type ReadyMatch =
	| { kind: 'none' }
	| { kind: 'same'; request: UpRequest }
	| { kind: 'different' }
	| { kind: 'broken'; why: string };

export class UploadApi {
	private readonly layout: SpoolLayout;
	private readonly tickets = new Map<string, Ticket>();
	// The ledger's committed side: each entry under ready, by name, with its
	// bytes and whether it is known durable. With the tickets' reservations
	// it is what the spool holds and has promised (usedBytes). Filled from
	// the disk at startup, when there are no tickets, and changed only under
	// `spool` after that.
	private readonly committed = new Map<string, Entry>();
	// Request ids the deployer holds, and how many times over. Cleanup
	// leaves their entries whatever their age.
	private readonly claims = new Map<string, number>();
	// Held for every change to what the spool holds or has promised:
	// admission, commit, expiry, claims and cleanup. Two of them never
	// interleave, so a commit cannot move an entry while an admission
	// counts, an expiry cannot give a reservation back while its bytes are
	// still on the disk, two uploads cannot both take the last room, and a
	// claim cannot land on an entry cleanup is removing.
	private readonly spool = new Mutex();
	private readonly limits: UploadLimits;
	private readonly now: () => number;
	private readonly diskSpace: (path: string) => Promise<{ free: number; size: number }>;

	constructor(private readonly options: UploadApiOptions) {
		this.layout = spoolLayout(options.spoolDir);
		this.limits = { ...UPLOAD_LIMITS, ...options.limits };
		this.now = options.now ?? Date.now;
		this.diskSpace = options.diskSpace ?? statDiskSpace;
	}

	// Makes the spool directories, reads what an earlier koid committed into
	// the ledger, and clears what it left half done. Fails, and with it the
	// start of koid, when an entry cannot be read: a ledger short of an
	// entry's bytes would admit uploads the spool has no room for, and a
	// disk that cannot be read is not one to take uploads on.
	async init(): Promise<void> {
		await this.makeDirectories();
		await this.spool.run(async () => {
			this.committed.clear();
			for (const name of await readdirOrEmpty(this.layout.ready)) {
				const dir = join(this.layout.ready, name);
				let bytes: number;
				try {
					bytes = await entryBytes(dir);
				} catch (err) {
					throw new Error(`upload spool: reading ${dir} into the ledger: ${message(err)}`, {
						cause: err,
					});
				}
				this.committed.set(name, { bytes, durable: false });
			}
		});
		await this.cleanup();
	}

	// Makes incoming and ready, with any parent they lack, and syncs every
	// directory made here along with its parent. mkdir by itself leaves the
	// new name in the cache, and a directory is not durably named until its
	// parent is synced. A commit syncs ready so its entry is durable, which
	// does nothing for the name of ready itself: on a fresh box a crash
	// soon after the first commit could lose ready and the entry with it,
	// an upload the CLI saw acknowledged. The spool root, the directory
	// that names it, incoming and ready are synced at every start whether
	// or not this one made them: the koid that made them may have exited
	// before it synced them, and this one finds them present and makes
	// nothing. Four syncs, cheap. Each directory before its parent, as a
	// file before its directory.
	private async makeDirectories(): Promise<void> {
		const made = [
			...(await mkdirAll(this.layout.incoming)),
			...(await mkdirAll(this.layout.ready)),
		];
		const always = [
			this.options.spoolDir,
			dirname(this.options.spoolDir),
			this.layout.incoming,
			this.layout.ready,
		];
		const dirs = new Set<string>();
		for (const dir of [...made, ...made.map((dir) => dirname(dir)), ...always]) {
			// Whatever was there before this start, the operator may have
			// put a symlink in its path; fsyncDir follows none, so each is
			// resolved first, and a directory reached two ways is synced
			// once.
			dirs.add(await realpath(dir));
		}
		const depth = (dir: string) => dir.split(sep).length;
		for (const dir of [...dirs].sort((a, b) => depth(b) - depth(a))) await fsyncDir(dir);
	}

	// `parts` is the path after /v1/uploads.
	async handle(request: Request, parts: string[]): Promise<Response> {
		if (parts.length === 0) {
			return request.method === 'POST' ? this.create(request) : notFound();
		}
		const uploadId = parts[0];
		if (
			parts.length !== 2 ||
			uploadId === undefined ||
			!UploadIdSchema.safeParse(uploadId).success
		) {
			return notFound();
		}
		if (parts[1] === 'source' && request.method === 'PUT') {
			return this.withTicket(uploadId, (ticket) => this.receive(ticket, request));
		}
		if (parts[1] === 'commit' && request.method === 'POST') {
			return this.withTicket(uploadId, (ticket) => this.commit(ticket, request));
		}
		return notFound();
	}

	// Runs `handler` with the ticket held, so expiry leaves it alone until
	// the handler has answered. 404 when there is no such ticket or it has
	// expired.
	private async withTicket(
		uploadId: string,
		handler: (ticket: Ticket) => Promise<Response>,
	): Promise<Response> {
		const ticket = await this.holdTicket(uploadId);
		if (ticket === undefined) return noSuchUpload();
		try {
			return await handler(ticket);
		} finally {
			ticket.busy -= 1;
		}
	}

	// Keeps ready/<id> from cleanup until release(id), for a request the
	// deployer has accepted and whose source its build has not copied yet.
	// Throws NoSuchUploadError when there is no such entry: it expired
	// between the deployer reading the request and accepting it, and the
	// request is refused rather than queued for a build that cannot start.
	async claim(id: string): Promise<void> {
		const dir = join(this.layout.ready, RequestIdSchema.parse(id));
		await this.spool.run(async () => {
			let entry: Awaited<ReturnType<typeof lstat>>;
			try {
				entry = await lstat(dir);
			} catch (err) {
				if (isCode(err, 'ENOENT')) throw new NoSuchUploadError(`no upload for request ${id}`);
				throw err;
			}
			if (!entry.isDirectory()) throw new Error(`upload ${id} is not a directory`);
			this.claims.set(id, (this.claims.get(id) ?? 0) + 1);
		});
	}

	// Lets cleanup take ready/<id> again once no claim is left on it.
	async release(id: string): Promise<void> {
		await this.spool.run(async () => {
			const held = this.claims.get(id);
			if (held === undefined) return;
			if (held > 1) this.claims.set(id, held - 1);
			else this.claims.delete(id);
		});
	}

	private async create(request: Request): Promise<Response> {
		const body = await this.jsonBody(request, CreateUploadSchema);
		if (!body.ok) return body.response;
		const { requestId, sizeBytes, sha256 } = body.value;
		if (sizeBytes > this.limits.maxSourceBytes) {
			return json(413, {
				error: `the source is ${sizeBytes} bytes; koid takes at most ${this.limits.maxSourceBytes}`,
			});
		}
		return this.spool.run(async () => {
			const existing = await this.compareReady(requestId, sizeBytes, sha256);
			if (existing.kind === 'same') {
				// Committed, but perhaps not durable: the sync after its commit
				// failed and no retry came, or a previous koid wrote it. The
				// caller is told it is committed only once it is durable, as a
				// commit is answered.
				const failed = await this.syncEntry(requestId);
				if (failed !== undefined) return failed;
				return json(200, { committed: true, requestId } satisfies UploadCommitted);
			}
			if (existing.kind === 'different') {
				return json(409, {
					error: `request ${requestId} was already uploaded with different content`,
				});
			}
			if (existing.kind === 'broken') {
				// Nothing can be built from it, and a commit of this id could not
				// take its place while it is there, so it goes now rather than
				// at the next round of cleanup, and the upload gets a ticket.
				// Unless a build still holds it: that build read the request
				// before the entry broke and is copying the source.
				if (!(await this.dropBroken(requestId, existing.why))) {
					return json(409, {
						error: `request ${requestId} has a broken upload that a build still holds; try again later`,
					});
				}
			}
			// What other tickets have yet to receive is not on the disk, so the
			// measurement does not show it; it is taken off the free space
			// below. Counted before the disk is measured, not after: a source
			// arriving meanwhile lands after this count, so the measurement
			// shows those bytes and this count still promises them, which
			// errs toward refusing. Counted after, bytes that landed in between
			// would show in neither figure. A discarded attempt gives its bytes
			// back under this mutex (receive), so the two figures cannot
			// straddle that either. The rest of the ledger changes only under
			// this mutex, and is read below with no await before it.
			const promised = this.unreceivedBytes();
			const disk = await this.diskSpace(this.options.spoolDir);
			const reserve = this.reservation(sizeBytes);
			const used = this.usedBytes();
			const { budgetBytes } = this.options;
			if (used + reserve > budgetBytes) {
				return json(507, {
					error: `the upload spool has ${used} of its ${budgetBytes} bytes in use or reserved; ${reserve} more do not fit until entries expire`,
				});
			}
			// What the deployer needs to build: an upload that took the disk below that
			// would only be refused later.
			const keep = Math.floor(minFreeBytes(disk.size));
			if (disk.free - promised - reserve < keep) {
				return json(507, {
					error: `the disk has ${disk.free} bytes free, ${promised} of them promised to uploads under way; ${reserve} more would leave less than the ${keep} bytes koid keeps free`,
				});
			}
			const now = this.now();
			const uploadId = randomBytes(16).toString('hex');
			const ticket: Ticket = {
				uploadId,
				requestId,
				sizeBytes,
				sha256,
				createdAt: now,
				state: 'open',
				expired: false,
				busy: 0,
				received: 0,
			};
			// On the map before the directory exists, so cleanup never takes
			// the directory for an orphan; and reserved from here.
			this.tickets.set(uploadId, ticket);
			try {
				await mkdir(join(this.layout.incoming, uploadId), { mode: 0o700 });
			} catch (err) {
				this.tickets.delete(uploadId);
				if (isCode(err, 'ENOSPC')) return json(507, { error: 'the disk is full' });
				throw err;
			}
			return json(201, {
				uploadId,
				expiresAt: new Date(now + this.limits.ticketTtlMs).toISOString(),
			} satisfies UploadTicket);
		});
	}

	// The caller holds the ticket (withTicket).
	private async receive(ticket: Ticket, request: Request): Promise<Response> {
		if (ticket.state !== 'open') return json(409, { error: stateMessage(ticket) });
		if (request.body === null) return json(400, { error: 'the body is empty' });
		ticket.state = 'receiving';
		const path = join(this.layout.incoming, ticket.uploadId, SOURCE_FILE);
		let handle: FileHandle | undefined;
		const discard = async () => {
			await handle?.close().catch(() => {});
			handle = undefined;
			// Under `spool`: the file goes and the ledger forgets its bytes in
			// one step, so an admission cannot measure a disk without the file
			// against a count that still credits them (create).
			await this.spool.run(async () => {
				await rm(path, { force: true });
				ticket.received = 0;
				ticket.state = 'open';
			});
		};
		try {
			// A file left by an attempt that failed gives way; the create itself
			// is exclusive, so nothing that appeared in between is written to.
			await rm(path, { force: true });
			handle = await open(path, CREATE_FLAGS, 0o600);
			const outcome = await this.receiveBody(request.body, ticket, handle);
			switch (outcome.kind) {
				case 'oversize':
					await discard();
					return json(413, {
						error: `the source is over its declared ${ticket.sizeBytes} bytes`,
					});
				case 'short':
				case 'disconnected':
					await discard();
					return json(400, {
						error: `the body ended after ${outcome.received} of ${ticket.sizeBytes} bytes`,
					});
				case 'timeout':
					await discard();
					return json(408, {
						error: `the source did not arrive within ${this.limits.sourceTimeoutMs / 1000} seconds`,
					});
				case 'done':
					if (outcome.sha256 !== ticket.sha256) {
						await discard();
						return json(422, {
							error: `the source's digest is ${outcome.sha256}, not the ${ticket.sha256} declared`,
						});
					}
					await handle.sync();
					await handle.close();
					handle = undefined;
					ticket.state = 'received';
					return json(200, {
						sizeBytes: ticket.sizeBytes,
						sha256: outcome.sha256,
					} satisfies SourceReceived);
			}
		} catch (err) {
			await discard();
			if (isCode(err, 'ENOSPC')) {
				return json(507, { error: 'the disk filled up while the source was arriving' });
			}
			throw err;
		}
	}

	// Streams the body to the file, counting bytes and hashing as it goes.
	// Stops reading the moment the count passes what the ticket declared or
	// the time bound passes.
	private async receiveBody(
		body: ReadableStream<Uint8Array>,
		ticket: Ticket,
		handle: FileHandle,
	): Promise<BodyOutcome> {
		const reader = body.getReader();
		const hash = createHash('sha256');
		let received = 0;
		let timedOut = false;
		// Cancelling the reader resolves the pending read as done, so the
		// loop ends however slowly the client sends.
		const timer = setTimeout(() => {
			timedOut = true;
			void reader.cancel().catch(() => {});
		}, this.limits.sourceTimeoutMs);
		try {
			for (;;) {
				const chunk = await reader.read().catch(() => undefined);
				if (chunk === undefined) return { kind: 'disconnected', received };
				if (chunk.done) break;
				received += chunk.value.byteLength;
				if (received > ticket.sizeBytes) {
					await reader.cancel().catch(() => {});
					return { kind: 'oversize' };
				}
				hash.update(chunk.value);
				await writeAll(handle, chunk.value);
				ticket.received = received;
			}
			// The timeout first: a body that delivered every declared byte and
			// then never ended was cut off by the timer, not finished, and the
			// client may still have had more to send.
			if (timedOut) return { kind: 'timeout' };
			if (received >= ticket.sizeBytes) return { kind: 'done', sha256: hash.digest('hex') };
			return { kind: 'short', received };
		} finally {
			clearTimeout(timer);
		}
	}

	// The caller holds the ticket (withTicket), so while the JSON arrives the
	// ticket cannot expire under it.
	private async commit(ticket: Ticket, request: Request): Promise<Response> {
		const body = await this.jsonBody(request, CommitUploadSchema);
		if (!body.ok) return body.response;
		const parsed = body.value;
		if (ticket.published !== undefined) {
			if (!Bun.deepEquals(ticket.published, parsed, true)) {
				return json(409, {
					error: `request ${ticket.requestId} was already committed with different content`,
				});
			}
			if (ticket.committed !== undefined) return json(200, ticket.committed);
			// Published, not durable yet. The sync may be under way, under
			// `spool`: this waits for it, and if it failed runs it again, so
			// no retry is answered before the entry is durable.
			return this.spool.run(() => this.syncReady(ticket, parsed));
		}
		if (ticket.state !== 'received') return json(409, { error: stateMessage(ticket) });
		if (parsed.id !== ticket.requestId) {
			return json(400, {
				error: `the request names itself ${parsed.id}; this upload is for ${ticket.requestId}`,
			});
		}
		const created = Date.parse(parsed.createdAt);
		const now = this.now();
		if (now - created > this.limits.createdAtMaxAgeMs) {
			return json(400, {
				error: `the request was created at ${parsed.createdAt}, more than ${this.limits.createdAtMaxAgeMs / 1000} seconds ago`,
			});
		}
		if (created - now > this.limits.createdAtMaxAheadMs) {
			return json(400, {
				error: `the request was created at ${parsed.createdAt}, more than ${this.limits.createdAtMaxAheadMs / 1000} seconds from now`,
			});
		}
		// The PUT enforced both; a ticket in `received` cannot say otherwise.
		if (ticket.received !== ticket.sizeBytes) {
			return json(422, {
				error: `the source on disk is ${ticket.received} bytes, not the ${ticket.sizeBytes} declared`,
			});
		}
		// Parsing filled in the recipe's defaults, so the file can be larger
		// than what arrived, and the reader refuses a file over the bound.
		const bytes = Buffer.from(JSON.stringify(parsed), 'utf8');
		if (bytes.byteLength > this.limits.maxRequestBytes) {
			return json(413, {
				error: `the request is ${bytes.byteLength} bytes once its defaults are filled in; koid keeps at most ${this.limits.maxRequestBytes}`,
			});
		}
		ticket.state = 'committing';
		try {
			return await this.spool.run(() => this.publish(ticket, parsed, bytes));
		} catch (err) {
			// A failure before the rename leaves the ticket for a retry. From
			// the rename on the ticket is published, and stays so: the entry
			// is under ready and the ledger counts it.
			if (ticket.state === 'committing') ticket.state = 'received';
			throw err;
		}
	}

	// Under `spool`. The source is already on disk and synced. The request
	// goes beside it, both are synced, then the directory moves into ready in
	// one rename: nothing under ready is visible before that, and the request
	// file is never there without its source. The ledger changes in the same
	// step, so no admission sees the entry in neither place. A failure before
	// the rename leaves the ticket as it was, for a retry; from the rename on
	// the entry is published, whatever fails after it, and only the sync
	// that makes it durable is left to do.
	private async publish(ticket: Ticket, parsed: UpRequest, bytes: Buffer): Promise<Response> {
		// The ticket was checked before the mutex was taken; checked again
		// under it, so what the ledger is told below is about a ticket it
		// still counts. A ticket a conflict dropped meanwhile is not.
		if (this.tickets.get(ticket.uploadId) !== ticket || ticket.state !== 'committing') {
			return noSuchUpload();
		}
		const dir = join(this.layout.incoming, ticket.uploadId);
		const target = join(this.layout.ready, ticket.requestId);
		// The entry's bytes take the place of the ticket's reservation. They
		// never exceed it, so this fails only if the ledger has gone wrong;
		// the spool then refuses rather than pass its budget.
		const entry = ticket.received + bytes.byteLength;
		const after = this.usedBytes() - this.reservation(ticket.sizeBytes) + entry;
		if (after > this.options.budgetBytes) {
			ticket.state = 'received';
			return json(507, {
				error: `the upload spool would hold ${after} of its ${this.options.budgetBytes} bytes`,
			});
		}
		try {
			await writeRequestFile(join(dir, REQUEST_FILE), bytes);
			await fsyncDir(dir);
		} catch (err) {
			if (!isCode(err, 'ENOSPC')) throw err;
			ticket.state = 'received';
			return json(507, { error: 'the disk filled up while the request was being written' });
		}
		let renamed = false;
		try {
			await rename(dir, target);
			renamed = true;
		} catch (err) {
			if (!isCode(err, 'ENOTEMPTY') && !isCode(err, 'EEXIST') && !isCode(err, 'ENOTDIR')) {
				throw err;
			}
			// Another commit of this request id got there first.
			const same = await this.sameAsReady(ticket, parsed);
			await rm(dir, { recursive: true, force: true });
			if (!same) {
				// With the ticket goes its reservation.
				this.tickets.delete(ticket.uploadId);
				return json(409, {
					error: `request ${ticket.requestId} was already uploaded with different content`,
				});
			}
		}
		// The entry is under ready, moved by this commit or by the one that
		// won, and the ticket is published: its entry's bytes take the place
		// of its reservation, and a retry of the commit is compared against
		// this request. Nothing from here can be undone, so nothing from here
		// unpublishes: the ledger keeps the entry whatever the sync below
		// answers, and a retry never writes into a directory that has moved.
		if (renamed) this.committed.set(ticket.requestId, { bytes: entry, durable: false });
		ticket.state = 'published';
		ticket.published = parsed;
		this.options.log(`upload ${ticket.requestId} committed for ${parsed.label}`);
		return this.syncReady(ticket, parsed);
	}

	// Under `spool`. The entry is under ready and the ledger counts it; this
	// makes it durable and answers the commit. The reply is cached, and 200
	// answered, only once the sync has succeeded. If it fails the entry
	// stays published and counted, the commit answers an error, and a retry
	// runs the sync again. The sync runs whether this commit moved the entry
	// or found it moved by another, unless the ledger knows the entry
	// durable: the commit that moved it may have failed here.
	private async syncReady(ticket: Ticket, parsed: UpRequest): Promise<Response> {
		// Another call on the ticket may have got here first while this one
		// waited for the mutex.
		if (ticket.committed !== undefined) return json(200, ticket.committed);
		const failed = await this.syncEntry(ticket.requestId);
		if (failed !== undefined) return failed;
		const reply: CommitReply = { requestId: ticket.requestId, label: parsed.label };
		ticket.state = 'committed';
		ticket.committed = reply;
		return json(200, reply);
	}

	// Under `spool`. Makes ready/<id> durable, unless the ledger knows it
	// is, and answers undefined once it is, or the error reply when the sync
	// fails. The rename into ready lives in the ready directory, and a crash
	// before that is synced can lose it, with the files' own syncs no help:
	// a file is not durably named until its directory is. One sync of the
	// directory makes every rename into it so far durable, and every rename
	// ran under this mutex, before this sync, so a sync that holds marks
	// every entry the ledger counts, the ones read at startup too.
	private async syncEntry(requestId: string): Promise<Response | undefined> {
		if (this.committed.get(requestId)?.durable === true) return undefined;
		try {
			await fsyncDir(this.layout.ready);
		} catch (err) {
			this.options.log(
				`upload spool: syncing ready after ${requestId} was published: ${message(err)}`,
			);
			if (isCode(err, 'ENOSPC')) {
				return json(507, {
					error: 'the disk filled up before the commit was durable; try again',
				});
			}
			return json(500, {
				error: `the commit is on the disk but not durable yet: ${message(err)}; try again`,
			});
		}
		for (const entry of this.committed.values()) entry.durable = true;
		return undefined;
	}

	// Under `spool`: drops tickets past their hour, with what they received,
	// and whatever is under incoming with no ticket (an upload a previous
	// koid was taking); then entries past their day that nobody claims, and
	// broken entries whatever their age. A held ticket waits for the next
	// round (expire). A claimed entry stays whatever its age or state: the
	// deployer accepted its request and has not copied its source yet.
	async cleanup(): Promise<void> {
		await this.spool.run(async () => {
			const now = this.now();
			for (const ticket of [...this.tickets.values()]) {
				if (!ticket.expired && now - ticket.createdAt < this.limits.ticketTtlMs) continue;
				await this.expire(ticket);
			}
			for (const name of await readdirOrEmpty(this.layout.incoming)) {
				if (this.tickets.has(name)) continue;
				await rm(join(this.layout.incoming, name), { recursive: true, force: true });
			}
			for (const name of await readdirOrEmpty(this.layout.ready)) {
				if (!RequestIdSchema.safeParse(name).success) {
					this.options.log(`upload spool: ${name} under ready is not a request id; leaving it`);
					continue;
				}
				if (this.claims.has(name)) continue;
				const dir = join(this.layout.ready, name);
				const entry = await this.openEntry(name);
				if (entry.kind === 'whole') await entry.source.handle.close().catch(() => {});
				if (entry.kind === 'broken') {
					await this.dropBroken(name, entry.why);
					continue;
				}
				if (now - (await entryTime(dir)) <= this.limits.readyTtlMs) continue;
				await rm(dir, { recursive: true, force: true });
				this.committed.delete(name);
				this.options.log(`upload ${name} expired`);
			}
		});
	}

	// Under `spool`. Removes a broken entry and forgets its bytes, unless the
	// deployer holds a claim on it: its build read the request before the
	// entry broke and is copying the source, and what is left goes at the
	// first round of cleanup after the claim is released. Says whether the
	// entry went.
	private async dropBroken(requestId: string, why: string): Promise<boolean> {
		if (this.claims.has(requestId)) return false;
		await rm(join(this.layout.ready, requestId), { recursive: true, force: true });
		this.committed.delete(requestId);
		this.options.log(`upload ${requestId} is broken: ${why}; removed`);
		return true;
	}

	// The ticket, held, or undefined once it has expired. The check against
	// the clock and the hold are one synchronous step, so no expiry falls
	// between them. An expired ticket is dropped here rather than waiting
	// for cleanup. A ticket marked expired is refused whatever the clock
	// says: its directory is being removed, or a removal failed and left it
	// in an unknown state.
	private async holdTicket(uploadId: string): Promise<Ticket | undefined> {
		const ticket = this.tickets.get(uploadId);
		if (ticket === undefined) return undefined;
		if (!ticket.expired && this.now() - ticket.createdAt < this.limits.ticketTtlMs) {
			ticket.busy += 1;
			return ticket;
		}
		await this.spool.run(() => this.expire(ticket));
		return undefined;
	}

	// Under `spool`. Drops a ticket past its hour with what it received, and
	// its reservation with it, unless a request holds it: that PUT or commit
	// checked the ticket and acts on what it saw, and would otherwise write
	// into a directory being removed or publish an entry whose reservation
	// an admission has already handed on. A held ticket waits for the next
	// round. The directory goes under the mutex as well, and before the
	// ticket leaves the map, so the budget the reservation stood for is not
	// given to another upload while these bytes are still on the disk. A
	// removal that fails leaves the ticket on the map, marked expired, with
	// its reservation: the next round, or the next request on the ticket,
	// tries again. The failure is logged and does not fail the caller, which
	// has other tickets to expire or a 404 to answer either way.
	private async expire(ticket: Ticket): Promise<void> {
		if (ticket.busy > 0) return;
		if (this.tickets.get(ticket.uploadId) !== ticket) return;
		ticket.expired = true;
		try {
			await rm(join(this.layout.incoming, ticket.uploadId), { recursive: true, force: true });
		} catch (err) {
			this.options.log(
				`upload spool: removing expired upload ${ticket.uploadId} for ${ticket.requestId}: ${message(err)}`,
			);
			return;
		}
		this.tickets.delete(ticket.uploadId);
	}

	// What a ticket for a source of `sizeBytes` reserves: the source and the
	// most a request file can be, so the commit's write is paid for at
	// admission.
	private reservation(sizeBytes: number): number {
		return sizeBytes + this.limits.maxRequestBytes;
	}

	// What the spool holds and has promised: the committed entries and the
	// reservation of every ticket whose entry is not published yet. An
	// expired ticket still on the map keeps its reservation: its bytes are
	// still on the disk.
	private usedBytes(): number {
		let total = 0;
		for (const entry of this.committed.values()) total += entry.bytes;
		for (const ticket of this.tickets.values()) {
			if (ticket.published === undefined) total += this.reservation(ticket.sizeBytes);
		}
		return total;
	}

	// Reserved bytes not on the disk yet: the rest of each source under way
	// and every request file not written. The disk's free space still
	// counts them as free.
	private unreceivedBytes(): number {
		let total = 0;
		for (const ticket of this.tickets.values()) {
			if (ticket.published !== undefined) continue;
			total += Math.max(0, ticket.sizeBytes - ticket.received) + this.limits.maxRequestBytes;
		}
		return total;
	}

	// Under `spool`. Opens ready/<id> as the reader will: its request, read
	// and checked, and its source, open for the caller to read and close.
	// 'none' when there is no entry. 'broken' when a file is missing or the
	// request is not one for this id (BrokenUploadError): the reader would
	// refuse it the same way, so no build can use it. 'unreadable' for any
	// other failure, a planted file, a disk error or a file that ends short
	// of the size fstat gave: refused, but left where it is. Both are
	// logged.
	private async openEntry(requestId: string): Promise<ReadyEntry> {
		try {
			const request = await readReadyRequest(this.layout.ready, requestId);
			const source = await openReadyFile(
				this.layout.ready,
				requestId,
				SOURCE_FILE,
				this.limits.maxSourceBytes,
			);
			return { kind: 'whole', request, source };
		} catch (err) {
			if (err instanceof NoSuchUploadError) return { kind: 'none' };
			const why = message(err);
			this.options.log(`upload spool: ready/${requestId}: ${why}`);
			return { kind: err instanceof BrokenUploadError ? 'broken' : 'unreadable', why };
		}
	}

	// Under `spool`. Whether ready/<id> is a whole entry with a source of
	// this size and digest, and its request if so: 'none' when there is no
	// entry, 'different' when there is one that does not match or cannot be
	// read, 'broken' when a file of it is missing or its request is not one
	// for this id. The request is checked along with the source: an entry
	// whose source matches but whose request the reader would refuse is no
	// use to anyone, and must not be acknowledged as committed. A source
	// that fails to read, or ends short of its size, throws: the caller
	// answers an error and the entry stays.
	private async compareReady(
		requestId: string,
		sizeBytes: number,
		sha256: string,
	): Promise<ReadyMatch> {
		const entry = await this.openEntry(requestId);
		if (entry.kind !== 'whole') return entry.kind === 'unreadable' ? { kind: 'different' } : entry;
		try {
			if (entry.source.size !== sizeBytes) return { kind: 'different' };
			const digest = await digestOf(
				entry.source.handle,
				entry.source.size,
				`${SOURCE_FILE} of upload ${requestId}`,
			);
			if (digest !== sha256) return { kind: 'different' };
			return { kind: 'same', request: entry.request };
		} finally {
			await entry.source.handle.close().catch(() => {});
		}
	}

	// Under `spool`. Whether ready/<id> holds this ticket's source and this
	// request, so a commit that found the entry already there can take it
	// as its own.
	private async sameAsReady(ticket: Ticket, request: UpRequest): Promise<boolean> {
		const match = await this.compareReady(ticket.requestId, ticket.sizeBytes, ticket.sha256);
		return match.kind === 'same' && Bun.deepEquals(match.request, request, true);
	}

	private async jsonBody<T>(
		request: Request,
		schema: z.ZodType<T>,
	): Promise<{ ok: true; value: T } | { ok: false; response: Response }> {
		try {
			const value = await readJson(
				request,
				schema,
				this.limits.maxRequestBytes,
				this.limits.requestTimeoutMs,
			);
			return { ok: true, value };
		} catch (err) {
			if (err instanceof BodyTooLargeError) {
				return {
					ok: false,
					response: json(413, {
						error: `the request is over ${this.limits.maxRequestBytes} bytes`,
					}),
				};
			}
			if (err instanceof BodyTimeoutError) {
				return {
					ok: false,
					response: json(408, {
						error: `the request did not arrive within ${this.limits.requestTimeoutMs / 1000} seconds`,
					}),
				};
			}
			if (err instanceof ZodError || err instanceof SyntaxError) {
				return { ok: false, response: json(400, { error: 'bad request', detail: err.message }) };
			}
			throw err;
		}
	}
}

const CREATE_FLAGS =
	constants.O_WRONLY |
	constants.O_CREAT |
	constants.O_EXCL |
	constants.O_NOFOLLOW |
	constants.O_NOCTTY;

function json(status: number, body: unknown): Response {
	return Response.json(body, { status });
}

function notFound(): Response {
	return json(404, { error: 'not found' });
}

function noSuchUpload(): Response {
	return json(404, { error: 'no such upload; it may have expired' });
}

function stateMessage(ticket: Ticket): string {
	switch (ticket.state) {
		case 'open':
			return 'upload the source before committing';
		case 'receiving':
			return 'the source is still being uploaded';
		case 'received':
			return 'the source was already uploaded; commit it';
		case 'committing':
			return 'a commit is under way';
		case 'published':
			return 'the upload was already committed but is not durable yet; commit it again';
		case 'committed':
			return 'the upload was already committed';
	}
}

function message(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

async function writeAll(handle: FileHandle, chunk: Uint8Array): Promise<void> {
	let offset = 0;
	while (offset < chunk.byteLength) {
		const { bytesWritten } = await handle.write(chunk, offset, chunk.byteLength - offset);
		if (bytesWritten <= 0) throw new Error('the write made no progress');
		offset += bytesWritten;
	}
}

// Creates the request file exclusively, writes it and syncs it.
async function writeRequestFile(path: string, bytes: Buffer): Promise<void> {
	await rm(path, { force: true });
	const handle = await open(path, CREATE_FLAGS, 0o600);
	try {
		await writeAll(handle, bytes);
		await handle.sync();
	} finally {
		await handle.close();
	}
}

// mkdir -p: makes `dir` and any parent it lacks, mode 0700, and names the
// directories it made, top down, so the caller can sync them.
async function mkdirAll(dir: string): Promise<string[]> {
	const missing: string[] = [];
	for (let path = dir; (await lstatOrAbsent(path)) === undefined; path = dirname(path)) {
		missing.unshift(path);
	}
	await mkdir(dir, { recursive: true, mode: 0o700 });
	return missing;
}

// Makes a directory's entries durable: a file synced inside it is not
// durably named until its directory is.
async function fsyncDir(dir: string): Promise<void> {
	const handle = await open(
		dir,
		constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NOCTTY,
	);
	try {
		await handle.sync();
	} finally {
		await handle.close();
	}
}

// The digest of an open source: the `size` bytes fstat gave for it, read
// whole (readWhole), and an error short of them.
async function digestOf(handle: FileHandle, size: number, what: string): Promise<string> {
	const hash = createHash('sha256');
	await readWhole(handle, size, what, (piece) => hash.update(piece));
	return hash.digest('hex');
}

async function readdirOrEmpty(dir: string): Promise<string[]> {
	try {
		return await readdir(dir);
	} catch (err) {
		if (isCode(err, 'ENOENT')) return [];
		throw err;
	}
}

// When an entry was committed: its request file's time, or the directory's
// for an entry with none.
async function entryTime(dir: string): Promise<number> {
	try {
		return (await lstat(join(dir, REQUEST_FILE))).mtimeMs;
	} catch {
		return (await lstat(dir)).mtimeMs;
	}
}

// The regular files directly under an entry, in bytes, following no symlink.
// A name under ready that is a file counts as itself. A path that is not
// there counts as nothing; any other failure to read one is thrown, since
// bytes left out of the ledger would be given to another upload while they
// are on the disk.
async function entryBytes(dir: string): Promise<number> {
	const stat = await lstatOrAbsent(dir);
	if (stat === undefined) return 0;
	if (stat.isFile()) return stat.size;
	if (!stat.isDirectory()) return 0;
	let total = 0;
	for (const name of await readdirOrEmpty(dir)) {
		const file = await lstatOrAbsent(join(dir, name));
		if (file?.isFile()) total += file.size;
	}
	return total;
}

// lstat, or undefined for a path that is not there. Any other failure is
// thrown, with the path in it.
async function lstatOrAbsent(path: string): Promise<Stats | undefined> {
	try {
		return await lstat(path);
	} catch (err) {
		if (isCode(err, 'ENOENT')) return undefined;
		throw new Error(`${path}: ${message(err)}`, { cause: err });
	}
}
