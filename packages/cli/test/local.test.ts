import { afterEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { chmod, link, mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CTL_EXIT, type UpRequest } from '@koi/shared';
import { type ControlDeps, startControlServer } from '../../daemon/src/control.ts';
import { CTL_USAGE } from '../../daemon/src/ctl.ts';
import { UploadApi } from '../../daemon/src/upload-api.ts';
import {
	HostMismatchError,
	UnknownOutcomeError,
	UnsupportedCapabilityError,
} from '../src/transport.ts';
import {
	type LocalTransportOptions,
	localTransport,
	socketPathProblem,
	socketProblem,
} from '../src/transports/local.ts';
import { hostInfoFor, koidDeps, previewRecord } from './koid.ts';

const DOMAIN = 'koi.test';
const uid = process.getuid?.() ?? 0;

// What each test leaves running or on disk, undone after it.
const cleanups: Array<() => Promise<unknown> | unknown> = [];
afterEach(async () => {
	for (const undo of cleanups.splice(0).reverse()) await undo();
});

async function scratch(): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), 'koi-local-'));
	cleanups.push(() => rm(dir, { recursive: true, force: true }));
	return dir;
}

// koid's control server on a socket of this test's, with the real upload
// API behind it and `over` for the rest (koidDeps fails what a test does not
// set). `ups` lists the request ids koid ctl up handed the deployer.
async function koid(over: Partial<ControlDeps> = {}, dir?: string) {
	const home = dir ?? (await scratch());
	const socket = join(home, 'control.sock');
	const uploadApi = new UploadApi({
		spoolDir: join(home, 'spool'),
		budgetBytes: 1e9,
		log: () => {},
	});
	await uploadApi.init();
	const ups: string[] = [];
	const server = await startControlServer(
		socket,
		koidDeps({
			describe: async () => hostInfoFor(DOMAIN),
			uploadApi,
			deployer: {
				up: async (requestId: string) => {
					ups.push(requestId);
					return { label: 'hello', requestId, attempt: 'a'.repeat(20) };
				},
				down: async () => {},
				acquireLease: async () => {
					throw new Error('not used');
				},
				releaseLease: async () => {
					throw new Error('not used');
				},
			} as unknown as ControlDeps['deployer'],
			...over,
		}),
	);
	cleanups.push(() => server.stop(true));
	return { socket, home, ups, spool: join(home, 'spool'), stop: () => server.stop(true) };
}

function transport(socket: string, o: LocalTransportOptions = {}, domain = DOMAIN) {
	return localTransport({ name: 'dev', socket, domain }, { sleep: async () => {}, ...o });
}

function request(): UpRequest {
	return {
		version: 1,
		id: 'abcdefghij0123456789',
		label: 'hello',
		project: 'hello',
		repo: 'github.com/acme/hello',
		commit: 'a'.repeat(40),
		branch: 'main',
		dirty: false,
		recipe: { kind: 'builtin', name: 'hello' },
		createdAt: new Date().toISOString(),
	} as UpRequest;
}

async function tarball(dir: string, size = 3 * 1024 ** 2 + 123) {
	const bytes = Buffer.alloc(size);
	for (let i = 0; i < size; i++) bytes[i] = (i * 7) & 0xff;
	const path = join(dir, 'source.tar.gz');
	await writeFile(path, bytes);
	return { path, sha256: createHash('sha256').update(bytes).digest('hex') };
}

describe('localTransport ctl', () => {
	test("runs koid ctl's own client against the socket, with its exit status and output", async () => {
		const k = await koid({ store: { get: async () => previewRecord(), list: async () => [] } });
		const t = transport(k.socket);
		const described = await t.ctl(['describe']);
		expect(described.code).toBe(CTL_EXIT.ok);
		expect(JSON.parse(described.stdout)).toEqual(hostInfoFor(DOMAIN));
		const listed = await t.ctl(['list']);
		expect(JSON.parse(listed.stdout)).toEqual({ previews: [] });
		// Arguments koid ctl refuses never reach the socket.
		const bad = await t.ctl(['frobnicate']);
		expect(bad).toEqual({ code: CTL_EXIT.usage, stdout: '', stderr: CTL_USAGE });
		const refused = await t.ctl(['status', 'Not A Label']);
		expect(refused.code).toBe(CTL_EXIT.usage);
	});

	test('a koid that does not answer is unavailable, and one that hangs ends at the limit', async () => {
		const dir = await scratch();
		const gone = await transport(join(dir, 'nothing.sock')).ctl(['describe']);
		expect(gone.code).toBe(CTL_EXIT.unavailable);
		expect(gone.stderr).toContain('koid ctl: cannot reach koid');
		const socket = join(dir, 'hung.sock');
		const server = Bun.serve({ unix: socket, fetch: () => new Promise<Response>(() => {}) });
		// Not waited for: the request it holds never ends.
		cleanups.push(() => void server.stop(true));
		const err = await transport(socket)
			.ctl(['up', 'abcdefghij0123456789'], { timeoutMs: 200 })
			.catch((e: unknown) => e);
		expect(err).toBeInstanceOf(UnknownOutcomeError);
		expect((err as Error).message).toBe(
			`koid ctl up may have run on koid at ${socket} (target dev): koi stopped waiting for its result after 200 ms, so its outcome is unknown`,
		);
	});
});

describe('localTransport ensureAwake', () => {
	test('checks the descriptor once, and stops on another domain before anything is sent', async () => {
		const k = await koid();
		await transport(k.socket).ensureAwake(() => {});
		const other = transport(k.socket, {}, 'previews.example.com');
		const err = await other.ensureAwake(() => {}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(HostMismatchError);
		expect((err as Error).message).toContain(
			'the host behind target "dev" serves previews under koi.test, not previews.example.com as configured',
		);
	});

	test('a socket that is not there is koid not running, reported at once for its operator', async () => {
		const dir = await scratch();
		let slept = 0;
		const t = transport(join(dir, 'control.sock'), {
			sleep: async () => {
				slept++;
			},
		});
		const err = await t.ensureAwake(() => {}).catch((e: unknown) => e);
		expect((err as Error).message).toStartWith(
			`there is no control socket at ${join(dir, 'control.sock')}, so koid is not running on this machine. koi cannot start it`,
		);
		expect(slept).toBe(0);
	});

	test('a socket nothing listens on is a koid that is starting, waited for and reported once', async () => {
		const dir = await scratch();
		const socket = join(dir, 'control.sock');
		// A second name for a socket whose server then goes: the file stays
		// and refuses connections, as a koid that is restarting leaves it.
		const first = Bun.serve({ unix: join(dir, 'gone.sock'), fetch: () => new Response() });
		await link(join(dir, 'gone.sock'), socket);
		first.stop(true);
		const progress: string[] = [];
		let k: Awaited<ReturnType<typeof koid>> | undefined;
		const t = transport(socket, {
			progress: () => {},
			sleep: async () => {
				if (k === undefined) {
					await rm(socket);
					k = await koid({}, dir);
				}
			},
		});
		await t.ensureAwake((m) => progress.push(m));
		expect(progress).toEqual([`waiting for koid at ${socket} to start`]);
	});

	test('a socket this account may not open is reported at once, with the group that lets it in', async () => {
		const k = await koid();
		await chmod(k.socket, 0o000);
		const err = await transport(k.socket)
			.ensureAwake(() => {})
			.catch((e: unknown) => e);
		expect((err as Error).message).toStartWith(`this account may not open ${k.socket}.`);
		expect((err as Error).message).toContain('koi-control');
	});

	test('a socket in a directory others may write to is refused before koid is asked anything', async () => {
		const dir = await scratch();
		const open = join(dir, 'open');
		await mkdir(open);
		await chmod(open, 0o777);
		let asked = 0;
		const k = await koid(
			{
				describe: async () => {
					asked++;
					return hostInfoFor(DOMAIN);
				},
			},
			open,
		);
		const err = await transport(k.socket)
			.ensureAwake(() => {})
			.catch((e: unknown) => e);
		expect((err as Error).message).toStartWith(
			`koi does not trust the control socket of target dev: ${open} is writable by any account (mode 0777)`,
		);
		expect(asked).toBe(0);
	});
});

describe('socketPathProblem', () => {
	test('takes a path whose directories only root, this account or their owners may write to', async () => {
		const k = await koid();
		expect(await socketPathProblem(k.socket, uid)).toBeUndefined();
	});

	test('refuses a directory its group may write to, as StrictModes does', async () => {
		const dir = await scratch();
		const shared = join(dir, 'shared');
		await mkdir(join(shared, 'inner'), { recursive: true });
		await chmod(shared, 0o775);
		const k = await koid({}, join(shared, 'inner'));
		expect(await socketPathProblem(k.socket, uid)).toBe(
			`${shared} is writable by its group (mode 0775)`,
		);
	});

	test("takes a sticky directory anyone may write to when the entry in it is this account's", async () => {
		const dir = await scratch();
		const sticky = join(dir, 'sticky');
		await mkdir(sticky);
		await chmod(sticky, 0o1777);
		const k = await koid({}, sticky);
		expect(await socketPathProblem(k.socket, uid)).toBeUndefined();
		// Seen from another account, an entry of this one's in a sticky
		// directory is a stranger's: /tmp's or this one.
		expect(await socketPathProblem(k.socket, uid + 4242)).toEndWith(
			'where any account may add an entry',
		);
	});

	test('walks a symbolic link and what it points to, and refuses an open directory on either', async () => {
		const k = await koid();
		const dir = await scratch();
		const via = join(dir, 'via.sock');
		await symlink(k.socket, via);
		expect(await socketPathProblem(via, uid)).toBeUndefined();
		const open = join(dir, 'open');
		await mkdir(open);
		await chmod(open, 0o777);
		await symlink(k.socket, join(open, 'link.sock'));
		expect(await socketPathProblem(join(open, 'link.sock'), uid)).toBe(
			`${open} is writable by any account (mode 0777)`,
		);
	});

	test('a file that is not a socket is not one', async () => {
		const dir = await scratch();
		await writeFile(join(dir, 'control.sock'), '');
		expect(await socketProblem(join(dir, 'control.sock'))).toBe(
			`${join(dir, 'control.sock')} is not a socket`,
		);
	});
});

describe('localTransport upload', () => {
	test('a ticket, the archive and the commit, over the socket, after the descriptor is checked', async () => {
		const k = await koid();
		const src = await tarball(await scratch());
		const progress: string[] = [];
		const t = transport(k.socket, { progress: (m) => progress.push(m) });
		await t.upload(request(), src.path);
		// The spool holds the request, committed, with the archive whole.
		expect(await readdir(join(k.spool, 'ready'))).toEqual([request().id]);
		const accepted = await t.ctl(['up', request().id]);
		expect(accepted.code).toBe(CTL_EXIT.ok);
		expect(k.ups).toEqual([request().id]);
		expect(progress).toEqual([]);
		// The same content again is already there and is not sent twice.
		await t.upload(request(), src.path);
	});

	test('a host that serves another domain gets none of the source', async () => {
		const k = await koid();
		const src = await tarball(await scratch(), 1000);
		const err = await transport(k.socket, {}, 'previews.example.com')
			.upload(request(), src.path)
			.catch((e: unknown) => e);
		expect(err).toBeInstanceOf(HostMismatchError);
		expect(await readdir(join(k.spool, 'ready'))).toEqual([]);
	});

	test('a koid that takes nothing for the idle limit is reported as not answering', async () => {
		const dir = await scratch();
		const k = await koid();
		// A second socket that answers describe through the real one and
		// never answers the upload.
		const socket = join(dir, 'slow.sock');
		const server = Bun.serve({
			unix: socket,
			fetch: (req: Request) =>
				new URL(req.url).pathname === '/host'
					? fetch(`http://koid/host`, { unix: k.socket } as RequestInit)
					: new Promise<Response>(() => {}),
		});
		cleanups.push(() => void server.stop(true));
		const src = await tarball(dir, 1000);
		const err = await transport(socket, { limits: { idleMs: 200 } })
			.upload(request(), src.path)
			.catch((e: unknown) => e);
		expect((err as Error).message).toBe(
			`koid at ${socket} (target dev) stopped answering during the upload of hello: nothing crossed the socket for 200 ms`,
		);
	});
});

describe('localTransport logs and channel', () => {
	test('cannot follow a container log, and has no channel', async () => {
		const t = transport('/run/koi/control.sock');
		expect(() => t.streamLogs({ label: 'hello', kind: 'runtime' })).toThrow(
			UnsupportedCapabilityError,
		);
		const err = await t.openChannel().catch((e: unknown) => e);
		expect((err as UnsupportedCapabilityError).capability).toBe('duplex');
	});
});
