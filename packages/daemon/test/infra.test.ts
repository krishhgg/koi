import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readdir, stat, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Activity, labelFromLogLine, startLogSink } from '../src/activity.ts';
import { ExecError, exec } from '../src/exec.ts';
import { extractTarball, resolveInside, tarMemberSize } from '../src/fsutil.ts';
import { KeyedLock, Semaphore } from '../src/lock.ts';
import { PreviewStore } from '../src/store.ts';

const temp = () => mkdtemp(join(tmpdir(), 'koid-'));

describe('resolveInside', () => {
	test('resolves paths inside the root and refuses symlinks that leave it', async () => {
		const root = await temp();
		await mkdir(join(root, 'docker'));
		await writeFile(join(root, 'docker', 'Dockerfile'), '');
		await symlink('/etc', join(root, 'escape'));
		await symlink('docker', join(root, 'inside'));
		expect(await resolveInside(root, 'docker/Dockerfile')).toEndWith('/docker/Dockerfile');
		expect(await resolveInside(root, 'inside')).toEndWith('/docker');
		expect(await resolveInside(root, '.')).not.toContain('..');
		await expect(resolveInside(root, 'escape')).rejects.toThrow(/outside/);
		await expect(resolveInside(root, 'escape/passwd')).rejects.toThrow(/outside/);
		await expect(resolveInside(root, 'missing')).rejects.toThrow(/does not exist/);
	});
});

describe('exec', () => {
	// `seq 1 100000` prints 588,895 bytes.
	const numbers = `${Array.from({ length: 100_000 }, (_, i) => i + 1).join('\n')}\n`;

	test('keeps the last 256 KiB of a long output by default', async () => {
		const r = await exec(['seq', '1', '100000']);
		expect(r.code).toBe(0);
		expect(r.stdout).toBe(numbers.slice(-256 * 1024));
	});

	test('keeps all of an output up to maxBytes', async () => {
		const r = await exec(['seq', '1', '100000'], { maxBytes: 1024 ** 2 });
		expect(r.stdout).toBe(numbers);
	});

	test('fails rather than return part of an output longer than maxBytes', async () => {
		const run = exec(['seq', '1', '100000'], { maxBytes: 300_000 });
		await expect(run).rejects.toBeInstanceOf(ExecError);
		await expect(run).rejects.toThrow('seq 1 printed more than 300000 bytes');
	});

	// The docker CLI ends buildx only when it gets to handle the signal, so
	// an abort asks first. These shells stand in for it: one ends its child
	// on SIGTERM, the other ignores SIGTERM.
	test('ends an aborted process with SIGTERM, so it can end its children', async () => {
		const stop = new AbortController();
		const started = Date.now();
		const run = exec(
			['bash', '-c', "trap 'echo stopping; kill $!; exit 3' TERM; sleep 30 & echo up; wait"],
			{ signal: stop.signal, onLine: (line) => line === 'up' && stop.abort() },
		);
		const result = await run;
		expect(result.code).toBe(3);
		expect(result.stdout).toBe('up\nstopping\n');
		expect(Date.now() - started).toBeLessThan(5_000);
	});

	test('kills an aborted process that ignores SIGTERM once the grace ends', async () => {
		const stop = new AbortController();
		const started = Date.now();
		const run = exec(['bash', '-c', 'trap "" TERM; echo up; while :; do sleep 0.1; done'], {
			signal: stop.signal,
			abortGraceMs: 300,
			onLine: (line) => line === 'up' && stop.abort(),
		});
		const result = await run;
		expect(result.code).not.toBe(0);
		expect(Date.now() - started).toBeLessThan(5_000);
	});
});

describe('extractTarball', () => {
	test('unpacks a source tree', async () => {
		const from = await temp();
		await writeFile(join(from, 'Dockerfile'), 'FROM scratch\n');
		const tarball = join(await temp(), 'src.tar.gz');
		expect((await exec(['tar', '-czf', tarball, '-C', from, '.'])).code).toBe(0);
		const to = join(await temp(), 'src');
		await extractTarball(tarball, to);
		expect(await Bun.file(join(to, 'Dockerfile')).text()).toBe('FROM scratch\n');
	});

	const pack = async (files: Record<string, string>) => {
		const from = await temp();
		for (const [name, text] of Object.entries(files)) await writeFile(join(from, name), text);
		const tarball = join(await temp(), 'src.tar.gz');
		expect((await exec(['tar', '-czf', tarball, '-C', from, '.'])).code).toBe(0);
		return tarball;
	};

	test('refuses an archive that unpacks to more than the byte limit, writing nothing', async () => {
		// 3 MiB of zeros compresses to a few kilobytes.
		const tarball = await pack({ a: '\0'.repeat(3 * 1024 ** 2) });
		const to = join(await temp(), 'src');
		await expect(
			extractTarball(tarball, to, { bytes: 2 * 1024 ** 2, entries: 100 }),
		).rejects.toThrow('the source unpacks to more than 2 MiB');
		await expect(readdir(to)).rejects.toMatchObject({ code: 'ENOENT' });
		await extractTarball(tarball, to, { bytes: 4 * 1024 ** 2, entries: 100 });
	});

	test('refuses an archive with more entries than the limit, writing nothing', async () => {
		// Ten files and the "./" directory.
		const files = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`f${i}`, 'x']));
		const tarball = await pack(files);
		const to = join(await temp(), 'src');
		await expect(extractTarball(tarball, to, { bytes: 1024 ** 2, entries: 10 })).rejects.toThrow(
			'more than 10 files',
		);
		await expect(readdir(to)).rejects.toMatchObject({ code: 'ENOENT' });
		await extractTarball(tarball, to, { bytes: 1024 ** 2, entries: 11 });
		expect(await readdir(to)).toHaveLength(10);
	});

	test('reads member sizes from the verbose listing', () => {
		expect(tarMemberSize('-rw-r--r-- 1000/1000      1234 2026-10-06 12:00 ./a b/c.md')).toBe(1234);
		expect(tarMemberSize('drwxr-xr-x 0/0 0 2026-10-06 12:00 ./')).toBe(0);
		expect(tarMemberSize('lrwxrwxrwx 0/0 0 2026-10-06 12:00 ./l -> /etc')).toBe(0);
		expect(tarMemberSize('crw-r--r-- 0/0 1,3 2026-10-06 12:00 ./null')).toBe(0);
		expect(tarMemberSize('-rw-r--r-- root/root 1234 2026-10-06 12:00 ./a')).toBeUndefined();
		expect(tarMemberSize('tar: something odd')).toBeUndefined();
	});
});

describe('PreviewStore', () => {
	const record = {
		label: 'hello',
		project: 'hello',
		repo: 'github.com/acme/hello',
		status: 'running' as const,
		commit: 'a'.repeat(40),
		branch: 'main',
		dirty: false,
		requestId: 'a'.repeat(16),
		attempt: 'b'.repeat(20),
		ttlDays: 7,
		createdAt: '2026-10-06T00:00:00.000Z',
		updatedAt: '2026-10-06T00:00:00.000Z',
	};
	const deployment = {
		requestId: 'a'.repeat(16),
		commit: 'a'.repeat(40),
		image: 'koi-preview/hello:x',
		container: 'koi-hello-x',
		port: 8080,
		healthPath: '/',
		healthTimeoutSeconds: 5,
		user: '65534:65534',
		env: {},
		deployedAt: '2026-10-06T00:00:00.000Z',
	};

	test('gives a record from before attempts one when it starts', async () => {
		const state = await temp();
		const store = new PreviewStore(state);
		await store.init();
		const { attempt: _none, ...old } = record;
		await writeFile(join(state, 'previews', 'hello.json'), JSON.stringify(old));
		await store.put({ ...record, label: 'other' });
		await new PreviewStore(state).init();
		const upgraded = await store.get('hello');
		expect(upgraded).toEqual({ ...record, attempt: expect.stringMatching(/^[a-z0-9]{20}$/) });
		expect(await store.get('other')).toEqual({ ...record, label: 'other' });
	});

	test('round-trips, updates and removes records', async () => {
		const store = new PreviewStore(await temp());
		await store.init();
		await store.put(record);
		expect(await store.get('hello')).toEqual(record);
		await store.update('hello', (r) => ({ ...r, status: 'stopped' }));
		expect((await store.get('hello'))?.status).toBe('stopped');
		await store.remove('hello');
		expect(await store.get('hello')).toBeUndefined();
		expect(await store.update('hello', (r) => r)).toBeUndefined();
	});

	test('skips a corrupt file in a listing instead of failing', async () => {
		const dir = await temp();
		const store = new PreviewStore(dir);
		await store.init();
		await store.put(record);
		await writeFile(join(dir, 'previews', 'broken.json'), '{not json');
		const bad: string[] = [];
		expect((await store.list((file) => bad.push(file))).map((r) => r.label)).toEqual(['hello']);
		expect(bad).toEqual(['broken.json']);
	});

	test('a visit and a deployment replacement that overlap both survive', async () => {
		// The next get() reads the record and then waits, so the visit below has
		// read the old record when the replacement starts.
		class PausingStore extends PreviewStore {
			pause: { read: () => void; resume: Promise<void> } | undefined;
			override async get(label: string) {
				const record = await super.get(label);
				const pause = this.pause;
				this.pause = undefined;
				if (pause !== undefined) {
					pause.read();
					await pause.resume;
				}
				return record;
			}
		}
		const store = new PausingStore(await temp());
		await store.init();
		const old = { ...deployment, requestId: 'a'.repeat(16), container: 'koi-hello-old' };
		const newer = { ...deployment, requestId: 'b'.repeat(16), container: 'koi-hello-new' };
		await store.put({ ...record, deployment: old });
		let resume = () => {};
		const read = new Promise<void>((read) => {
			store.pause = { read, resume: new Promise<void>((r) => (resume = r)) };
		});
		const visit = store.update('hello', (r) => ({ ...r, lastVisitAt: '2026-10-07T00:00:00.000Z' }));
		await read;
		const replace = store.update('hello', (r) => ({ ...r, deployment: newer }));
		// Unsynchronised, the replacement finishes here and the visit then writes
		// the old deployment back.
		await Promise.race([replace, Bun.sleep(100)]);
		resume();
		await Promise.all([visit, replace]);
		const after = await store.get('hello');
		expect(after?.deployment).toEqual(newer);
		expect(after?.lastVisitAt).toBe('2026-10-07T00:00:00.000Z');
	});

	test('upsert creates a record or changes the existing one', async () => {
		const store = new PreviewStore(await temp());
		await store.init();
		await store.upsert('hello', (current) => current ?? record);
		expect(await store.get('hello')).toEqual(record);
		await store.upsert('hello', (current) => ({ ...(current ?? record), status: 'failed' }));
		expect((await store.get('hello'))?.status).toBe('failed');
	});

	test('refuses labels that would escape its directory', async () => {
		const store = new PreviewStore(await temp());
		await expect(store.get('../../etc/passwd')).rejects.toThrow();
		await expect(store.put({ ...record, label: '../x' })).rejects.toThrow();
	});
});

describe('Activity', () => {
	test('touches the stamp at most once per interval unless forced', async () => {
		const dir = await temp();
		const stamp = join(dir, 'last-activity');
		await writeFile(stamp, '');
		await utimes(stamp, new Date(0), new Date(0));
		let now = 1_000_000;
		const activity = new Activity(stamp, () => now, 30_000);
		await activity.touch();
		expect((await stat(stamp)).mtimeMs).toBe(1_000_000);
		now += 10_000;
		await activity.touch();
		expect((await stat(stamp)).mtimeMs).toBe(1_000_000);
		await activity.touch(true);
		expect((await stat(stamp)).mtimeMs).toBe(1_010_000);
	});

	test('collects the first and the latest visit to each label until drained', () => {
		let now = 5;
		const activity = new Activity('/nonexistent/stamp', () => now);
		activity.visit('a');
		now = 7;
		activity.visit('a');
		now = 9;
		activity.visit('a');
		activity.visit('b');
		expect(activity.drainVisits()).toEqual([
			['a', 5],
			['a', 9],
			['b', 9],
		]);
		expect(activity.drainVisits()).toEqual([]);
	});

	test('ignores requests for labels that are not live previews', async () => {
		const dir = await temp();
		const stamp = join(dir, 'last-activity');
		await writeFile(stamp, '');
		await utimes(stamp, new Date(0), new Date(0));
		const activity = new Activity(
			stamp,
			() => 1_000_000,
			30_000,
			(label) => label === 'live',
		);
		activity.visit('unknown');
		await Bun.sleep(10);
		expect((await stat(stamp)).mtimeMs).toBe(0);
		activity.visit('live');
		await Bun.sleep(10);
		expect((await stat(stamp)).mtimeMs).toBe(1_000_000);
		expect(activity.drainVisits()).toEqual([['live', 1_000_000]]);
	});

	test('keeps the box awake for requests to the keys page, which renew no preview', async () => {
		const dir = await temp();
		const stamp = join(dir, 'last-activity');
		await writeFile(stamp, '');
		await utimes(stamp, new Date(0), new Date(0));
		let now = 1_000_000;
		// No live previews at all, as while a reviewer registers keys.
		const activity = new Activity(
			stamp,
			() => now,
			30_000,
			() => false,
		);
		// As Caddy logs each request to keys.<domain>, its page and its API.
		const sink = startLogSink(0, 'example.dev', (label) => activity.visit(label));
		const socket = await Bun.connect({
			hostname: '127.0.0.1',
			port: sink.port,
			socket: { data() {} },
		});
		const logged = (uri: string) =>
			`${JSON.stringify({ request: { host: 'keys.example.dev', uri } })}\n`;
		socket.write(logged('/'));
		await Bun.sleep(50);
		expect((await stat(stamp)).mtimeMs).toBe(1_000_000);
		now += 60_000;
		socket.write(logged('/api/register'));
		await Bun.sleep(50);
		expect((await stat(stamp)).mtimeMs).toBe(1_060_000);
		socket.end();
		sink.stop(true);
		expect(activity.drainVisits()).toEqual([]);
	});

	test('reads the preview from a Caddy access log line', () => {
		const line = JSON.stringify({
			level: 'info',
			request: { host: 'hello-pr-7.previews.example.net', uri: '/' },
		});
		expect(labelFromLogLine(line, 'previews.example.net')).toBe('hello-pr-7');
		expect(
			labelFromLogLine(
				JSON.stringify({ request: { host: 'x.evil.example' } }),
				'previews.example.net',
			),
		).toBeNull();
		expect(labelFromLogLine('not json', 'previews.example.net')).toBeNull();
		expect(labelFromLogLine('{"msg":"no request"}', 'previews.example.net')).toBeNull();
	});

	test('the log sink handles lines split across packets', async () => {
		const seen: string[] = [];
		const sink = startLogSink(0, 'previews.example.net', (label) => seen.push(label));
		const socket = await Bun.connect({
			hostname: '127.0.0.1',
			port: sink.port,
			socket: { data() {} },
		});
		const a = JSON.stringify({ request: { host: 'alpha.previews.example.net' } });
		const b = JSON.stringify({ request: { host: 'beta.previews.example.net' } });
		socket.write(`${a}\n${b.slice(0, 10)}`);
		await Bun.sleep(20);
		socket.write(`${b.slice(10)}\n`);
		await Bun.sleep(50);
		socket.end();
		sink.stop(true);
		expect(seen).toEqual(['alpha', 'beta']);
	});
});

describe('locks', () => {
	test('KeyedLock runs one task per key at a time and keeps going after a failure', async () => {
		const lock = new KeyedLock();
		const order: string[] = [];
		const slow = lock.run('a', async () => {
			await Bun.sleep(20);
			order.push('a1');
			throw new Error('a1 failed');
		});
		const next = lock.run('a', async () => {
			order.push('a2');
		});
		const other = lock.run('b', async () => {
			order.push('b1');
		});
		await expect(slow).rejects.toThrow('a1 failed');
		await next;
		await other;
		expect(order).toEqual(['b1', 'a1', 'a2']);
		expect(lock.busy('a')).toBe(false);
	});

	test('Semaphore never runs more than its limit', async () => {
		const sem = new Semaphore(1);
		let active = 0;
		let peak = 0;
		await Promise.all(
			[1, 2, 3].map(() =>
				sem.run(async () => {
					active += 1;
					peak = Math.max(peak, active);
					await Bun.sleep(5);
					active -= 1;
				}),
			),
		);
		expect(peak).toBe(1);
	});

	test('Semaphore hands a freed permit to the waiter, not to a newcomer', async () => {
		const sem = new Semaphore(1);
		let active = 0;
		let peak = 0;
		const task = (wait: Promise<void>) => async () => {
			active += 1;
			peak = Math.max(peak, active);
			await wait;
			active -= 1;
		};
		let finish = () => {};
		const first = new Promise<void>((resolve) => {
			finish = resolve;
		});
		const running = sem.run(() => first);
		const waiter = sem.run(task(Bun.sleep(5)));
		// Runs in the same microtask turn as the first task's release, before
		// the waiter resumes, so it sees whatever vacancy the release left.
		const newcomer = first.then(() => sem.run(task(Bun.sleep(5))));
		finish();
		await Promise.all([running, waiter, newcomer]);
		expect(peak).toBe(1);
	});
});
