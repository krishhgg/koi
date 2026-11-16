import { describe, expect, spyOn, test } from 'bun:test';
import { createHash } from 'node:crypto';
import {
	chmod,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	stat,
	symlink,
	writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
	canonicalDigest,
	InputSnapshotSchema,
	loadVerifyConfig,
	MAX_VERIFY_FILE_BYTES,
} from '@koi/shared';
import {
	hashRecipeDir,
	MAX_PROOF_FILES,
	proofFiles,
	SNAPSHOT_LIMITS,
	SnapshotError,
	snapshotInputs,
} from '../src/verification-snapshot.ts';
import { EvidenceStore } from '../src/verification-store.ts';
import { openingWith, refusingRemoval, refusingRename, request } from './fakes.ts';

const DEPLOYMENT = 'd'.repeat(20);
const sha = (bytes: Uint8Array | string) =>
	`sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const MANIFEST = `version: 1
skills:
  - id: hello
    path: skills/hello/SKILL.md
points:
  - points/*.yaml
profiles:
  pr:
    always: [hello.home]
runner:
  image: curlimages/curl:8.11.1
`;

const POINT = `id: hello.home
revision: 2
claim: The home page says hello.
select:
  always: true
  paths: [Dockerfile]
requires:
  fixtures: [fixtures/probe.txt]
run:
  command: [sh, .koi/runners/home.sh]
  files: [runners/lib.sh]
assertions:
  - name: home-says-hello
    description: GET / answers 200.
    evidence: [http-response]
`;

// A source tree as a build extracts it, with or without verification files.
async function source(options: { koi?: boolean; broken?: boolean; changed?: boolean } = {}) {
	const root = await mkdtemp(join(tmpdir(), 'koid-snapshot-'));
	const src = join(root, 'src');
	await mkdir(src, { recursive: true });
	await writeFile(join(src, 'Dockerfile'), 'FROM scratch\n');
	await writeFile(join(src, 'README.md'), 'not copied\n');
	const tarball = join(root, 'source.tar.gz');
	await writeFile(tarball, 'tarball bytes');
	if (options.koi !== false) {
		for (const dir of ['points', 'runners', 'fixtures', 'skills/hello']) {
			await mkdir(join(src, '.koi', dir), { recursive: true });
		}
		await writeFile(join(src, '.koi/verify.yaml'), options.broken ? 'version: 2\n' : MANIFEST);
		await writeFile(join(src, '.koi/points/home.yaml'), POINT);
		await writeFile(join(src, '.koi/runners/home.sh'), 'curl "$KOI_PREVIEW_URL"\n');
		await writeFile(join(src, '.koi/runners/lib.sh'), 'true\n');
		await writeFile(join(src, '.koi/runners/unused.sh'), 'not declared, not copied\n');
		await writeFile(join(src, '.koi/fixtures/probe.txt'), 'probe bytes');
		await writeFile(join(src, '.koi/skills/hello/SKILL.md'), '# hello\n');
		await writeFile(join(src, '.koi/koi.yaml'), 'port: 8080\n');
	}
	if (options.changed !== false) {
		await mkdir(join(src, '.koi-runtime'), { recursive: true });
		await writeFile(join(src, '.koi-runtime/changed-files.txt'), 'Dockerfile\nsrc/app.ts\n\n');
	}
	const inputs = join(root, 'state', 'verification', 'inputs', DEPLOYMENT);
	return { root, src, tarball, inputs };
}

const now = () => new Date('2026-10-06T12:00:00.000Z');

describe('snapshotInputs', () => {
	test('keeps a file executable that was executable, and writable by koid alone', async () => {
		const t = await source();
		await chmod(join(t.src, '.koi/runners/home.sh'), 0o755);
		await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		const mode = async (path: string) => (await stat(join(t.inputs, 'source', path))).mode & 0o777;
		expect(await mode('.koi/runners/home.sh')).toBe(0o700);
		expect(await mode('.koi/runners/lib.sh')).toBe(0o600);
		expect(await mode('.koi/verify.yaml')).toBe(0o600);
	});

	test('copies the loader files, declared fixtures, skills and the changed-file list, with digests', async () => {
		const t = await source();
		const req = request();
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: req, source: t.src, tarball: t.tarball },
			now,
		);
		expect(InputSnapshotSchema.parse(snapshot)).toEqual(snapshot);
		expect(snapshot.deploymentId).toBe(DEPLOYMENT);
		expect(snapshot.label).toBe('hello-pr-7');
		expect(snapshot.request.commit).toBe(req.commit);
		expect(snapshot.recipe).toEqual({ kind: 'repo', digest: canonicalDigest(req.recipe) });
		expect(snapshot.source).toEqual({ archiveDigest: sha('tarball bytes'), archiveBytes: 13 });
		expect(snapshot.changedFiles).toEqual({
			file: {
				path: '.koi-runtime/changed-files.txt',
				digest: sha('Dockerfile\nsrc/app.ts\n\n'),
				size: 23,
			},
			count: 2,
		});
		if (snapshot.verify.status !== 'present') throw new Error(snapshot.verify.status);
		expect(Object.keys(snapshot.verify.digests)).toEqual([
			'.koi/points/home.yaml',
			'.koi/runners/home.sh',
			'.koi/runners/lib.sh',
			'.koi/verify.yaml',
		]);
		expect(snapshot.verify.digests['.koi/runners/lib.sh']).toBe(sha('true\n'));
		expect(snapshot.verify.points).toEqual([
			{ id: 'hello.home', revision: 2, path: '.koi/points/home.yaml' },
		]);
		expect(snapshot.verify.fixtures).toEqual([
			{ path: '.koi/fixtures/probe.txt', digest: sha('probe bytes'), size: 11 },
		]);
		expect(snapshot.verify.other).toEqual([
			{ path: '.koi/koi.yaml', digest: sha('port: 8080\n'), size: 11 },
			{ path: '.koi/skills/hello/SKILL.md', digest: sha('# hello\n'), size: 8 },
		]);
		expect(snapshot.takenAt).toBe('2026-10-06T12:00:00.000Z');
		// On disk: snapshot.json beside source/, only what was declared, and
		// the copy loads as the original did.
		expect((await readdir(t.inputs)).sort()).toEqual(['snapshot.json', 'source']);
		expect(JSON.parse(await readFile(join(t.inputs, 'snapshot.json'), 'utf8'))).toEqual(snapshot);
		const copied = join(t.inputs, 'source');
		expect(
			await stat(join(copied, '.koi/runners/unused.sh')).catch(() => undefined),
		).toBeUndefined();
		expect(await stat(join(copied, 'README.md')).catch(() => undefined)).toBeUndefined();
		expect(await stat(join(copied, 'Dockerfile')).catch(() => undefined)).toBeUndefined();
		const loaded = await loadVerifyConfig(copied);
		expect(loaded.digests).toEqual(snapshot.verify.digests);
		expect((await stat(join(copied, '.koi/fixtures/probe.txt'))).mode & 0o777).toBe(0o600);
		expect((await stat(join(copied, '.koi'))).mode & 0o777).toBe(0o700);
		expect((await stat(t.inputs)).mode & 0o777).toBe(0o700);
		expect(await readdir(join(t.root, 'state', 'verification', 'inputs'))).toEqual([DEPLOYMENT]);
	});

	test('copies a script the manifest names in runner.command, for every point', async () => {
		const t = await source();
		await writeFile(join(t.src, '.koi/runners/wrapper.py'), 'print("wrapped")\n');
		await writeFile(
			join(t.src, '.koi/verify.yaml'),
			MANIFEST.replace(
				'image: curlimages/curl:8.11.1',
				'image: curlimages/curl:8.11.1\n  command: [python3, .koi/runners/wrapper.py]',
			),
		);
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		if (snapshot.verify.status !== 'present') throw new Error(snapshot.verify.status);
		expect(snapshot.verify.digests['.koi/runners/wrapper.py']).toBe(sha('print("wrapped")\n'));
		expect(await readFile(join(t.inputs, 'source/.koi/runners/wrapper.py'), 'utf8')).toBe(
			'print("wrapped")\n',
		);
	});

	test("a runner.command path that names no file makes the files invalid, with the loader's words", async () => {
		const t = await source();
		await writeFile(
			join(t.src, '.koi/verify.yaml'),
			MANIFEST.replace(
				'image: curlimages/curl:8.11.1',
				'image: curlimages/curl:8.11.1\n  command: [python3, .koi/runners/wrapper.py]',
			),
		);
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		expect(snapshot.verify).toEqual({
			status: 'invalid',
			error: '.koi/verify.yaml: runner.command[1]: no file runners/wrapper.py under .koi/',
		});
	});

	test('a file that is both a runner file and a fixture counts once toward the total', async () => {
		const t = await source();
		// 130 files at the loader's limit are about 33 MiB. Counted twice they
		// would pass the 64 MiB total, and the deployment would lose its snapshot.
		const body = 'x'.repeat(256 * 1024);
		const names = Array.from({ length: 130 }, (_, i) => `fixtures/shared-${i}.bin`);
		await Promise.all(names.map((name) => writeFile(join(t.src, '.koi', name), body)));
		await writeFile(
			join(t.src, '.koi/points/home.yaml'),
			POINT.replace('[fixtures/probe.txt]', `[${names.join(', ')}]`).replace(
				'[runners/lib.sh]',
				`[${names.join(', ')}]`,
			),
		);
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		if (snapshot.verify.status !== 'present') throw new Error(snapshot.verify.status);
		expect(snapshot.verify.fixtures.length).toBeGreaterThanOrEqual(names.length);
		const shared = snapshot.verify.fixtures.find((f) => f.path.endsWith('shared-0.bin'));
		expect(shared?.size).toBe(body.length);
	}, 60_000);

	test('a project without verification files gets a snapshot that says so', async () => {
		const t = await source({ koi: false, changed: false });
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		expect(snapshot.verify).toEqual({ status: 'absent' });
		expect(snapshot.changedFiles).toBeUndefined();
		expect(await readdir(join(t.inputs, 'source'))).toEqual([]);
	});

	test('a project whose files do not load gets the loader error, and nothing copied', async () => {
		const t = await source({ broken: true });
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		expect(snapshot.verify.status).toBe('invalid');
		if (snapshot.verify.status === 'invalid')
			expect(snapshot.verify.error).toMatch(/^\.koi\/verify\.yaml: version/);
		expect(await readdir(join(t.inputs, 'source'))).toEqual(['.koi-runtime']);
	});

	test('a .koi/ past the file count or byte bound is refused before anything in it is read', async () => {
		const t = await source();
		// One file past the count, each tiny, under a directory of their own.
		await mkdir(join(t.src, '.koi', 'many'), { recursive: true });
		const already = 8;
		for (let i = 0; i < SNAPSHOT_LIMITS.koiFiles - already + 1; i++) {
			await writeFile(join(t.src, '.koi', 'many', `${i}.txt`), 'x');
		}
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		expect(snapshot.verify).toEqual({
			status: 'invalid',
			error: `.koi/ holds more than ${SNAPSHOT_LIMITS.koiFiles} files; koi reads no more than that`,
		});
		expect(await readdir(join(t.inputs, 'source'))).toEqual(['.koi-runtime']);
		// Bytes: a few files whose sizes pass the bound together, each one
		// within the loader's own limit or not; neither is opened.
		const u = await source();
		await mkdir(join(u.src, '.koi', 'big'), { recursive: true });
		const chunk = Buffer.alloc(16 * 1024 ** 2, 1);
		for (let i = 0; i < 5; i++) await writeFile(join(u.src, '.koi', 'big', `${i}.bin`), chunk);
		const over = await snapshotInputs(
			u.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: u.src, tarball: u.tarball },
			now,
		);
		expect(over.verify).toEqual({
			status: 'invalid',
			error: `.koi/ holds more than ${SNAPSHOT_LIMITS.koiBytes} bytes; koi reads no more than that`,
		});
	});

	test('a runner file over the loader bound makes the files invalid, as the loader says', async () => {
		// The loader's per-file bound covers every file it opens, a runner
		// file a point names included; nothing of the tree is copied.
		const t = await source();
		await writeFile(join(t.src, '.koi/runners/lib.sh'), `#${'x'.repeat(MAX_VERIFY_FILE_BYTES)}\n`);
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		expect(snapshot.verify).toEqual({
			status: 'invalid',
			error: `.koi/runners/lib.sh: is ${MAX_VERIFY_FILE_BYTES + 2} bytes; the most koi reads is ${MAX_VERIFY_FILE_BYTES}`,
		});
		expect(await readdir(join(t.inputs, 'source'))).toEqual(['.koi-runtime']);
	});

	test('a symlink under .koi makes the files invalid, as the loader says', async () => {
		const t = await source();
		await symlink('../runners/home.sh', join(t.src, '.koi/fixtures/link.sh'));
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		expect(snapshot.verify.status).toBe('invalid');
		if (snapshot.verify.status === 'invalid') expect(snapshot.verify.error).toContain('symlink');
	});

	test('never overwrites a snapshot, and leaves no pending directory behind', async () => {
		const t = await source();
		const input = {
			deploymentId: DEPLOYMENT,
			request: request(),
			source: t.src,
			tarball: t.tarball,
		};
		await snapshotInputs(t.inputs, input, now);
		await expect(snapshotInputs(t.inputs, input, now)).rejects.toThrow(SnapshotError);
		const u = await source();
		await expect(
			snapshotInputs(
				u.inputs,
				{ ...input, source: u.src, tarball: join(u.root, 'missing.tar.gz') },
				now,
			),
		).rejects.toThrow();
		expect(await readdir(join(u.root, 'state', 'verification', 'inputs'))).toEqual([]);
	});

	// A file's own sync covers the directory right above it and nothing higher.
	// source/ and source/.koi/skills/ hold no file directly, so only the walk
	// syncs them. Lost to a power cut, they take copied files with them while
	// snapshot.json stays.
	test('syncs every directory it made, deepest first, before the rename that publishes it, and the parent after', async () => {
		const t = await source();
		const parent = dirname(t.inputs);
		const pending = join(parent, `.pending-${DEPLOYMENT}`);
		const steps: string[] = [];
		const opens = openingWith((path, handle) => {
			// Temporary files are written and synced in the pending directory
			// too; the steps here are the directories.
			if (path.endsWith('.tmp')) return;
			const sync = handle.sync.bind(handle);
			spyOn(handle, 'sync').mockImplementation(async () => {
				steps.push(path);
				return sync();
			});
		});
		const renames = refusingRename((to) => {
			if (to === t.inputs) steps.push('publish');
			return false;
		}, 'not refused');
		try {
			await snapshotInputs(
				t.inputs,
				{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
				now,
			);
		} finally {
			renames.mockRestore();
			opens.mockRestore();
		}
		const dirs = [
			'source/.koi/fixtures',
			'source/.koi/points',
			'source/.koi/runners',
			'source/.koi/skills/hello',
			'source/.koi/skills',
			'source/.koi',
			'source/.koi-runtime',
			'source',
		].map((dir) => join(pending, dir));
		const published = steps.indexOf('publish');
		const before = steps.slice(0, published);
		expect(published).toBeGreaterThan(0);
		for (const dir of dirs) {
			expect(before).toContain(dir);
			// The last sync of a directory comes after the last of any under it.
			expect(before.lastIndexOf(dir)).toBeLessThan(before.lastIndexOf(dirname(dir)));
		}
		expect(before.at(-1)).toBe(pending);
		expect(steps.slice(published + 1)).toEqual([parent]);
	});

	test('a directory that cannot be synced publishes nothing', async () => {
		const t = await source();
		const parent = dirname(t.inputs);
		const opens = openingWith((path, handle) => {
			if (path !== join(parent, `.pending-${DEPLOYMENT}`, 'source')) return;
			spyOn(handle, 'sync').mockImplementation(async () => {
				throw new Error('EIO: i/o error');
			});
		});
		try {
			await expect(
				snapshotInputs(
					t.inputs,
					{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
					now,
				),
			).rejects.toThrow('EIO');
		} finally {
			opens.mockRestore();
		}
		expect(await readdir(parent)).toEqual([]);
	});

	// A kill stops the copy where it is. A rename that fails, and a removal
	// after it that fails too, leave the same directory, under the name
	// snapshotInputs really gives it.
	test('a directory left by a copy that never finished is one the evidence sweep removes', async () => {
		const t = await source();
		const pending = join(dirname(t.inputs), `.pending-${DEPLOYMENT}`);
		let copied = false;
		const renames = refusingRename((to) => {
			copied = to === t.inputs;
			return copied;
		}, 'EIO: i/o error');
		// Not the removal before the copy, which clears an earlier attempt.
		const removals = refusingRemoval(
			(target) => copied && target === pending,
			'EBUSY: resource busy',
		);
		try {
			await expect(
				snapshotInputs(
					t.inputs,
					{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
					now,
				),
			).rejects.toThrow('EBUSY');
		} finally {
			removals.mockRestore();
			renames.mockRestore();
		}
		expect(await readdir(dirname(t.inputs))).toEqual([`.pending-${DEPLOYMENT}`]);
		const later = (ms: number) =>
			new EvidenceStore({
				stateDir: join(t.root, 'state'),
				now: () => new Date(Date.now() + ms),
			});
		expect((await later(0).sweep()).pendingInputs).toEqual([]);
		expect((await later(61 * 60_000).sweep()).pendingInputs).toEqual([DEPLOYMENT]);
		expect(await readdir(dirname(t.inputs))).toEqual([]);
	});

	test('records a built-in recipe by the digests the build took of its files', async () => {
		const t = await source({ koi: false });
		const dir = join(t.root, 'recipes', 'storefront');
		await mkdir(join(dir, 'scripts'), { recursive: true });
		await writeFile(join(dir, 'recipe.json'), '{"name":"storefront"}\n');
		await writeFile(join(dir, 'Dockerfile'), 'FROM scratch\n');
		await writeFile(join(dir, 'scripts', 'seed.py'), 'print(1)\n');
		const req = request({ recipe: { kind: 'builtin', name: 'storefront' } });
		// What the deployer takes as the build starts.
		const recipe = { dir, files: await hashRecipeDir(dir) };
		const files = {
			Dockerfile: sha('FROM scratch\n'),
			'recipe.json': sha('{"name":"storefront"}\n'),
			'scripts/seed.py': sha('print(1)\n'),
		};
		expect(recipe.files).toEqual(files);
		// The installed recipe is replaced before the snapshot is taken, as
		// a deploy of a newer koid does: the snapshot records what was built.
		await writeFile(join(dir, 'scripts', 'seed.py'), 'print(2)\n');
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: req, source: t.src, tarball: t.tarball, recipe },
			now,
		);
		expect(snapshot.recipe).toEqual({
			kind: 'builtin',
			name: 'storefront',
			digest: canonicalDigest({ name: 'storefront', files }),
			files,
		});
		expect(snapshot.recipe.digest).not.toBe(canonicalDigest(req.recipe));
		// A build of the changed script gets another digest; the request did
		// not change.
		const u = await source({ koi: false });
		const changed = await snapshotInputs(
			u.inputs,
			{
				deploymentId: DEPLOYMENT,
				request: req,
				source: u.src,
				tarball: u.tarball,
				recipe: { dir, files: await hashRecipeDir(dir) },
			},
			now,
		);
		expect(changed.recipe.digest).not.toBe(snapshot.recipe.digest);
		expect(changed.recipe.files?.['scripts/seed.py']).toBe(sha('print(2)\n'));
	});

	test('a built-in recipe without its digests, or without recipe.json, is refused', async () => {
		const t = await source({ koi: false });
		const req = request({ recipe: { kind: 'builtin', name: 'storefront' } });
		await expect(
			snapshotInputs(
				t.inputs,
				{ deploymentId: DEPLOYMENT, request: req, source: t.src, tarball: t.tarball },
				now,
			),
		).rejects.toThrow('has no file digests');
		const dir = join(t.root, 'recipes', 'storefront');
		await expect(
			snapshotInputs(
				t.inputs,
				{
					deploymentId: DEPLOYMENT,
					request: req,
					source: t.src,
					tarball: t.tarball,
					recipe: { dir, files: { Dockerfile: sha('FROM scratch\n') } },
				},
				now,
			),
		).rejects.toThrow('has no recipe.json');
		expect(await readdir(join(t.root, 'state', 'verification', 'inputs'))).toEqual([]);
	});
});

describe('hashRecipeDir', () => {
	test('hashes every regular file by path and refuses a symlink', async () => {
		const root = await mkdtemp(join(tmpdir(), 'koid-recipe-'));
		const dir = join(root, 'storefront');
		await mkdir(join(dir, 'scripts'), { recursive: true });
		await writeFile(join(dir, 'recipe.json'), '{}\n');
		await writeFile(join(dir, 'scripts', 'seed.py'), 'print(1)\n');
		expect(await hashRecipeDir(dir)).toEqual({
			'recipe.json': sha('{}\n'),
			'scripts/seed.py': sha('print(1)\n'),
		});
		await symlink('/etc/hostname', join(dir, 'link'));
		await expect(hashRecipeDir(dir)).rejects.toThrow('not a regular file');
		await expect(hashRecipeDir(join(root, 'missing'))).rejects.toThrow();
	});
});

describe('snapshotInputs and the advisory policy', () => {
	const PROOF = `pointId: hello.home
revision: 2
mutation:
  kind: ref
  digest: sha256:${'a'.repeat(64)}
failingRunId: ${'f'.repeat(20)}
passingRunId: ${'p'.repeat(20)}
provenAt: 2026-10-06T12:00:00.000Z
`;

	test('copies .koi/required.yaml and .koi/proofs/*.yaml|json among the other files', async () => {
		const t = await source();
		await writeFile(join(t.src, '.koi/required.yaml'), 'version: 1\nrequired: []\n');
		await mkdir(join(t.src, '.koi/proofs/notes'), { recursive: true });
		await writeFile(join(t.src, '.koi/proofs/hello.home.yaml'), PROOF);
		await writeFile(join(t.src, '.koi/proofs/other.json'), '{}\n');
		// Not a proof record by name: left where it is.
		await writeFile(join(t.src, '.koi/proofs/README.md'), 'notes\n');
		const snapshot = await snapshotInputs(
			t.inputs,
			{ deploymentId: DEPLOYMENT, request: request(), source: t.src, tarball: t.tarball },
			now,
		);
		if (snapshot.verify.status !== 'present') throw new Error(snapshot.verify.status);
		expect(snapshot.verify.other.map((f) => f.path)).toEqual([
			'.koi/koi.yaml',
			'.koi/proofs/hello.home.yaml',
			'.koi/proofs/other.json',
			'.koi/required.yaml',
			'.koi/skills/hello/SKILL.md',
		]);
		expect(
			snapshot.verify.other.find((f) => f.path === '.koi/proofs/hello.home.yaml')?.digest,
		).toBe(sha(PROOF));
		const copied = join(t.inputs, 'source');
		expect(await readFile(join(copied, '.koi/required.yaml'), 'utf8')).toBe(
			'version: 1\nrequired: []\n',
		);
		expect(
			await stat(join(copied, '.koi/proofs/README.md')).catch(() => undefined),
		).toBeUndefined();
		// The loader's digests are as they were: these files are not its.
		expect(Object.keys(snapshot.verify.digests)).toEqual([
			'.koi/points/home.yaml',
			'.koi/runners/home.sh',
			'.koi/runners/lib.sh',
			'.koi/verify.yaml',
		]);
	});

	test('lists proof files by name within the bound, and refuses more', async () => {
		const dir = await mkdtemp(join(tmpdir(), 'koid-proofs-'));
		expect(await proofFiles(join(dir, 'missing'))).toEqual([]);
		await writeFile(join(dir, 'b.yaml'), '');
		await writeFile(join(dir, 'a.json'), '');
		await writeFile(join(dir, 'c.yml'), '');
		await writeFile(join(dir, '.hidden.yaml'), '');
		await writeFile(join(dir, 'notes.txt'), '');
		await mkdir(join(dir, 'd.yaml'));
		expect(await proofFiles(dir)).toEqual(['a.json', 'b.yaml', 'c.yml']);
		for (let i = 0; i < MAX_PROOF_FILES; i++) await writeFile(join(dir, `p${i}.yaml`), '');
		expect(proofFiles(dir)).rejects.toThrow(`koi reads at most ${MAX_PROOF_FILES}`);
	});
});
