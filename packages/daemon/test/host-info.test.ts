import { describe, expect, test } from 'bun:test';
import { mkdtemp, readdir, readFile, stat, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HostInfoSchema } from '@koi/shared';
import { createFileExclusive, removeIfEmpty } from '../src/fsutil.ts';
import { HOST_ID_FILE, hostDescriber, loadHostId, SSM_CAPABILITIES } from '../src/host-info.ts';

describe('hostDescriber', () => {
	test('describes the host with an id it makes once and keeps', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koid-state-'));
		const describe = hostDescriber(state, 'previews.example.com');
		const [first, second] = await Promise.all([describe(), describe()]);
		expect(HostInfoSchema.parse(first)).toEqual(first);
		expect(first).toEqual({
			protocol: 1,
			hostId: first.hostId,
			domain: 'previews.example.com',
			address: { scheme: 'https', port: 443 },
			capabilities: SSM_CAPABILITIES,
		});
		expect(second.hostId).toBe(first.hostId);
		expect(await readFile(join(state, HOST_ID_FILE), 'utf8')).toBe(`${first.hostId}\n`);
		expect((await stat(join(state, HOST_ID_FILE))).mode & 0o777).toBe(0o640);
		// A new koid on the same state directory is the same host.
		expect((await hostDescriber(state, 'previews.example.com')()).hostId).toBe(first.hostId);
		// Another state directory is another host.
		const other = await mkdtemp(join(tmpdir(), 'koid-state-'));
		expect((await hostDescriber(other, 'previews.example.com')()).hostId).not.toBe(first.hostId);
	});

	test('two koids that start together agree on one id', async () => {
		// Each describer has its own cache and finds no file; the id file is
		// created exclusively, so the loser reads the winner's id. Several
		// rounds, since the race is decided by timing.
		for (let round = 0; round < 10; round++) {
			const state = await mkdtemp(join(tmpdir(), 'koid-state-'));
			const [first, second] = await Promise.all([
				hostDescriber(state, 'previews.example.com')(),
				hostDescriber(state, 'previews.example.com')(),
			]);
			expect(second.hostId).toBe(first.hostId);
			expect(await readFile(join(state, HOST_ID_FILE), 'utf8')).toBe(`${first.hostId}\n`);
			// No temporary file is left behind by the loser.
			expect(await readdir(state)).toEqual([HOST_ID_FILE]);
		}
	});

	test('says what SSM can do: cursors over build logs, nothing live', () => {
		expect(SSM_CAPABILITIES).toEqual({
			duplex: false,
			buildLogCursor: true,
			runtimeLogStream: false,
			artifactTransfer: false,
		});
	});

	test('refuses a domain that is not a bare domain rather than describe a wrong one', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koid-state-'));
		await expect(hostDescriber(state, 'Example.com')()).rejects.toThrow();
		await expect(hostDescriber(state, 'example')()).rejects.toThrow();
	});
});

describe('loadHostId', () => {
	test('reads an id back, and refuses a file that is not one', async () => {
		const state = await mkdtemp(join(tmpdir(), 'koid-state-'));
		const path = join(state, HOST_ID_FILE);
		const id = await loadHostId(path);
		expect(await loadHostId(path)).toBe(id);
		await writeFile(path, 'not an id\n');
		await expect(loadHostId(path)).rejects.toThrow(`${path} does not hold a host id`);
		// The bad file is left as it is, for a person to look at.
		expect(await readFile(path, 'utf8')).toBe('not an id\n');
		// The directory is made when it is not there yet.
		expect(await loadHostId(join(state, 'deeper', 'host-id'))).toMatch(/^[a-z0-9]{20}$/);
	});

	test('many loaders racing for a missing file all get the id that was written', async () => {
		const path = join(await mkdtemp(join(tmpdir(), 'koid-state-')), HOST_ID_FILE);
		const ids = await Promise.all(Array.from({ length: 8 }, () => loadHostId(path)));
		expect(new Set(ids).size).toBe(1);
		expect(await readFile(path, 'utf8')).toBe(`${ids[0]}\n`);
		expect((await stat(path)).mode & 0o777).toBe(0o640);
	});

	test('a reader that finds the file empty waits for the winner to write it', async () => {
		// The file as the winner's exclusive open leaves it until its write,
		// on a filesystem without hard links. A reader that arrives then must
		// not call it bad.
		const path = join(await mkdtemp(join(tmpdir(), 'koid-state-')), HOST_ID_FILE);
		await writeFile(path, '');
		const began = Date.now();
		const reading = loadHostId(path);
		await Bun.sleep(120);
		await writeFile(path, `${'w'.repeat(20)}\n`);
		expect(await reading).toBe('w'.repeat(20));
		expect(Date.now() - began).toBeGreaterThanOrEqual(100);
	});

	test('replaces a file that stays empty, since no id can have come from it', async () => {
		// The file a koid leaves when it dies, or its write fails, between
		// its exclusive open and its write on a filesystem without hard
		// links. A later koid must not stop on it for good.
		const path = join(await mkdtemp(join(tmpdir(), 'koid-state-')), HOST_ID_FILE);
		await writeFile(path, '');
		const began = Date.now();
		const id = await loadHostId(path);
		expect(id).toMatch(/^[a-z0-9]{20}$/);
		// Only once a writer that might still come has had its second.
		expect(Date.now() - began).toBeGreaterThanOrEqual(900);
		expect(await readFile(path, 'utf8')).toBe(`${id}\n`);
		expect((await stat(path)).mode & 0o777).toBe(0o640);
		expect(await loadHostId(path)).toBe(id);
	});

	test('a writer that fills the empty file as it is about to be removed wins', async () => {
		const path = join(await mkdtemp(join(tmpdir(), 'koid-state-')), HOST_ID_FILE);
		await writeFile(path, '');
		const winner = `${'w'.repeat(20)}\n`;
		let unlinks = 0;
		const id = await loadHostId(path, {
			// The writer lands between the size check and the unlink, the one
			// moment the check cannot cover.
			unlink: async (p) => {
				await writeFile(p, winner);
				unlinks += 1;
				await unlink(p);
			},
		});
		expect(unlinks).toBe(1);
		expect(id).toBe('w'.repeat(20));
		expect(await readFile(path, 'utf8')).toBe(winner);
	});

	test('two readers that both give up on an empty file agree on one id', async () => {
		const path = join(await mkdtemp(join(tmpdir(), 'koid-state-')), HOST_ID_FILE);
		await writeFile(path, '');
		const [first, second] = await Promise.all([loadHostId(path), loadHostId(path)]);
		expect(second).toBe(first);
		expect(await readFile(path, 'utf8')).toBe(`${first}\n`);
	});

	test('refuses a file with part of an id, and asks for it to be removed by hand', async () => {
		// A write that stopped short. koid cannot know whether what is there
		// was ever handed out, so it does not decide; the operator does.
		const path = join(await mkdtemp(join(tmpdir(), 'koid-state-')), HOST_ID_FILE);
		await writeFile(path, 'abc123');
		const failing = loadHostId(path);
		await expect(failing).rejects.toThrow(`${path} does not hold a host id`);
		await expect(failing).rejects.toThrow('remove the file by hand');
		expect(await readFile(path, 'utf8')).toBe('abc123');
		// Still refused on the next call; nothing is retried behind the operator's back.
		await expect(loadHostId(path)).rejects.toThrow('remove the file by hand');
	});
});

describe('removeIfEmpty', () => {
	test('removes an empty file, keeps one with content, and is fine without one', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-state-'));
		const path = join(dir, 'host-id');
		expect(await removeIfEmpty(path)).toBe(true);
		await writeFile(path, '');
		expect(await removeIfEmpty(path)).toBe(true);
		expect(await readdir(dir)).toEqual([]);
		await writeFile(path, 'x\n');
		expect(await removeIfEmpty(path)).toBe(false);
		expect(await readFile(path, 'utf8')).toBe('x\n');
	});

	test('puts back the text of a writer that lands between the check and the unlink', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-state-'));
		const path = join(dir, 'host-id');
		await writeFile(path, '', { mode: 0o600 });
		const removed = await removeIfEmpty(path, {
			unlink: async (p) => {
				await writeFile(p, 'late\n');
				await unlink(p);
			},
		});
		expect(removed).toBe(false);
		expect(await readFile(path, 'utf8')).toBe('late\n');
		// With the mode the writer gave it, and no temporary file beside it.
		expect((await stat(path)).mode & 0o777).toBe(0o600);
		expect(await readdir(dir)).toEqual(['host-id']);
	});

	test('tolerates another reader removing the file first', async () => {
		const path = join(await mkdtemp(join(tmpdir(), 'koid-state-')), 'host-id');
		await writeFile(path, '');
		expect(
			await removeIfEmpty(path, {
				unlink: async (p) => {
					await unlink(p);
					await unlink(p);
				},
			}),
		).toBe(true);
	});
});

describe('createFileExclusive', () => {
	// link() as a filesystem without hard links answers it.
	const noLinks = (code: string) => ({
		link: async () => {
			throw Object.assign(new Error(`link: ${code}`), { code });
		},
	});

	test('falls back to an exclusive open where the filesystem has no hard links', async () => {
		for (const code of ['EOPNOTSUPP', 'ENOTSUP', 'EPERM']) {
			const dir = await mkdtemp(join(tmpdir(), 'koid-state-'));
			const path = join(dir, 'host-id');
			expect(await createFileExclusive(path, 'first\n', 0o640, noLinks(code))).toBe(true);
			expect(await readFile(path, 'utf8')).toBe('first\n');
			expect((await stat(path)).mode & 0o777).toBe(0o640);
			expect(await createFileExclusive(path, 'second\n', 0o640, noLinks(code))).toBe(false);
			expect(await readFile(path, 'utf8')).toBe('first\n');
			// No temporary file is left behind either way.
			expect(await readdir(dir)).toEqual(['host-id']);
		}
	});

	test('any other failure to link is an error, and leaves nothing behind', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-state-'));
		await expect(
			createFileExclusive(join(dir, 'host-id'), 'x\n', 0o640, noLinks('EIO')),
		).rejects.toThrow('link: EIO');
		expect(await readdir(dir)).toEqual([]);
	});

	test('without hard links, the loser waits for the winner to write the file', async () => {
		// The file as the winner's exclusive open leaves it until its write.
		const path = join(await mkdtemp(join(tmpdir(), 'koid-state-')), 'host-id');
		await writeFile(path, '');
		const began = Date.now();
		const losing = createFileExclusive(path, 'mine\n', 0o640, noLinks('EOPNOTSUPP'));
		await Bun.sleep(120);
		await writeFile(path, 'the winner\n');
		expect(await losing).toBe(false);
		expect(Date.now() - began).toBeGreaterThanOrEqual(100);
		expect(await readFile(path, 'utf8')).toBe('the winner\n');
		// A file that stays empty is given up on, for the caller to judge.
		await writeFile(path, '');
		const gaveUp = Date.now();
		expect(await createFileExclusive(path, 'mine\n', 0o640, noLinks('EOPNOTSUPP'))).toBe(false);
		expect(Date.now() - gaveUp).toBeGreaterThanOrEqual(900);
		expect(await readFile(path, 'utf8')).toBe('');
	});

	test('without hard links, racing writers still agree on one file', async () => {
		for (let round = 0; round < 5; round++) {
			const dir = await mkdtemp(join(tmpdir(), 'koid-state-'));
			const path = join(dir, 'host-id');
			const texts = Array.from({ length: 8 }, (_, i) => `id-${i}\n`);
			const created = await Promise.all(
				texts.map((text) => createFileExclusive(path, text, 0o640, noLinks('EPERM'))),
			);
			expect(created.filter(Boolean)).toHaveLength(1);
			const winner = texts[created.indexOf(true)];
			expect(await readFile(path, 'utf8')).toBe(winner as string);
			expect(await readdir(dir)).toEqual(['host-id']);
		}
	});
});
