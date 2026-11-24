import { describe, expect, test } from 'bun:test';
import {
	DeploymentSchema,
	encodeLivePreviews,
	LeaseSchema,
	LIVE_PREVIEWS_MAX_BYTES,
	livePreviewsFit,
	PreviewRecordSchema,
} from '../src/preview.ts';
import {
	DeploymentSliceSchema,
	ImagePathSchema,
	MAX_DEPLOYMENT_SLICE_BYTES,
	MAX_DEPLOYMENT_SLICE_DEPTH,
	MAX_PROJECT_NAME,
	MAX_RECIPE_SLICE_BYTES,
	parsedJsonBytes,
	RecipeSchema,
	RepoRecipeSchema,
	repoMatches,
} from '../src/recipe.ts';

describe('RecipeSchema', () => {
	test('fills defaults for a minimal dockerfile recipe', () => {
		const recipe = RecipeSchema.parse({ name: 'hello', build: { kind: 'dockerfile' }, port: 8080 });
		expect(recipe.build).toEqual({
			kind: 'dockerfile',
			from: 'source',
			path: 'Dockerfile',
			context: '.',
		});
		expect(recipe.healthPath).toBe('/');
		expect(recipe.ttlDays).toBe(7);
		expect(recipe.buildTimeoutMinutes).toBe(45);
		expect(recipe.healthTimeoutSeconds).toBe(180);
		expect(recipe.env).toEqual({});
		expect(recipe.user).toBeUndefined();
	});

	test('a built-in recipe may bring its own Dockerfile', () => {
		const recipe = RecipeSchema.parse({
			name: 'storefront',
			build: { kind: 'dockerfile', from: 'recipe' },
			port: 8080,
		});
		expect(recipe.build.from).toBe('recipe');
	});

	test('rejects env names that are reserved or not shell-style', () => {
		const withEnv = (env: Record<string, string>) =>
			RecipeSchema.safeParse({ name: 'a', build: { kind: 'dockerfile' }, port: 80, env }).success;
		expect(withEnv({ APP_MODE: 'preview' })).toBe(true);
		expect(withEnv({ KOI_SECRET: 'x' })).toBe(false);
		expect(withEnv({ 'lower-case': 'x' })).toBe(false);
		expect(withEnv({ 'A=B': 'x' })).toBe(false);
	});

	test('accepts a numeric non-root user as uid:gid and rejects root in any spelling or names', () => {
		const asUser = (user: string) => {
			const r = RecipeSchema.safeParse({
				name: 'a',
				build: { kind: 'dockerfile' },
				port: 80,
				user,
			});
			return r.success ? r.data.user : 'rejected';
		};
		expect(asUser('1000')).toBe('1000:1000');
		expect(asUser('1000:1000')).toBe('1000:1000');
		expect(asUser('1000:5')).toBe('1000:5');
		// Only the uid makes root; gid 0 is an ordinary group.
		expect(asUser('1000:0')).toBe('1000:0');
		expect(asUser('01000')).toBe('1000:1000');
		expect(asUser('4294967294')).toBe('4294967294:4294967294');
		for (const bad of [
			'0',
			'00',
			'000:5',
			'0:1000',
			'0000000000',
			'root',
			'app',
			'1000:',
			':1000',
			' 1000',
			'1000:app',
			'-1',
			'4294967295',
			'',
		]) {
			expect(asUser(bad)).toBe('rejected');
		}
	});

	test('rejects names that cannot be hostname labels', () => {
		const result = RecipeSchema.safeParse({
			name: 'Hello World',
			build: { kind: 'dockerfile' },
			port: 80,
		});
		expect(result.success).toBe(false);
	});

	test('keeps a slice as the recipe wrote it, and refuses one that is not a JSON object or is too large', () => {
		const withSlice = (slice: unknown) =>
			RecipeSchema.safeParse({ name: 'a', build: { kind: 'dockerfile' }, port: 80, slice });
		const slice = { keep: ['web'], seed: { users: 2 }, note: null, tags: [1, 'x', false] };
		expect(withSlice(slice).data?.slice).toEqual(slice);
		expect(withSlice({}).success).toBe(true);
		for (const bad of ['all', ['web'], 3, null]) expect(withSlice(bad).success).toBe(false);
		// The bound is on the JSON in UTF-8: {"k":"..."} is 8 bytes around the
		// string, and an e with an accent is two bytes.
		const room = MAX_RECIPE_SLICE_BYTES - '{"k":""}'.length;
		expect(withSlice({ k: 'x'.repeat(room) }).success).toBe(true);
		expect(withSlice({ k: 'x'.repeat(room + 1) }).success).toBe(false);
		expect(withSlice({ k: `${'x'.repeat(room - 2)}\u00e9` }).success).toBe(true);
		expect(withSlice({ k: `${'x'.repeat(room - 1)}\u00e9` }).success).toBe(false);
		// JSON.parse makes an own __proto__ key. It is kept, and it counts.
		const own = JSON.parse(`{"__proto__":{"a":1},"k":"x"}`);
		const kept = withSlice(own).data?.slice;
		expect(Object.keys(kept ?? {})).toEqual(['__proto__', 'k']);
		expect(JSON.stringify(kept)).toBe(`{"__proto__":{"a":1},"k":"x"}`);
		const padded = JSON.parse(`{"__proto__":"${'x'.repeat(room)}","k":""}`);
		expect(withSlice(padded).success).toBe(false);
		// Only what JSON.parse could have made, at any depth.
		const cycle: Record<string, unknown> = {};
		cycle.self = cycle;
		const hidden: Record<string, unknown> = {};
		Object.defineProperty(hidden, 'self', { value: hidden, enumerable: false });
		const quiet: Record<string, unknown> = { k: 1 };
		quiet.self = quiet;
		Object.defineProperty(quiet, 'toJSON', { value: () => ({}), enumerable: false });
		const iterated = [undefined];
		Object.defineProperty(iterated, Symbol.iterator, { value: function* () {} });
		const getter = {};
		Object.defineProperty(getter, 'k', { get: () => 1, enumerable: true });
		const shared = { a: 1 };
		const sparse: unknown[] = [];
		sparse[2] = 1;
		const extra = Object.assign([1], { note: 'x' });
		const beyond: unknown[] = Array(1);
		(beyond as unknown as Record<string, unknown>)['4294967295'] = 1;
		const boxed = Object.setPrototypeOf(new Boolean(false), Object.prototype);
		const boxedSymbol = Object.setPrototypeOf(Object(Symbol('s')), Object.prototype);
		const bad: unknown[] = [
			{ k: Number.NaN },
			{ k: [Number.POSITIVE_INFINITY] },
			{ k: { d: new Date(0) } },
			{ k: () => 1 },
			{ k: undefined },
			{ k: 1n },
			{ [Symbol('s')]: 1 },
			cycle,
			hidden,
			quiet,
			{ k: iterated },
			getter,
			{ a: shared, b: shared },
			{ k: sparse },
			{ k: extra },
			{ k: beyond },
			{ k: boxed },
			{ k: boxedSymbol },
			JSON.parse('{"n":1e400}'),
			{ k: Object.create({ inherited: 1 }) },
		];
		for (const value of bad) expect(withSlice(value).success).toBe(false);
		// A deep nest is walked without recursion: 10,000 levels fit in the
		// bound and pass, 100,000 do not. A wide one stops at the budget.
		let fits: Record<string, unknown> = {};
		for (let i = 0; i < 10_000; i++) fits = { d: fits };
		expect(withSlice(fits).success).toBe(true);
		let deep: Record<string, unknown> = {};
		for (let i = 0; i < 100_000; i++) deep = { d: deep };
		expect(withSlice(deep).success).toBe(false);
		const wide = Object.fromEntries(
			Array.from({ length: MAX_RECIPE_SLICE_BYTES + 1 }, (_, i) => [`k${i}`, 0]),
		);
		expect(withSlice(wide).success).toBe(false);
		expect(withSlice(Object.assign(Object.create(null), { k: 'x' })).success).toBe(true);
		// Nested 10,000 deep as JSON text, which JSON.parse accepts and Node's
		// JSON.stringify cannot write back.
		const text = `${'{"k":'.repeat(10_000)}0${'}'.repeat(10_000)}`;
		expect(text.length).toBeLessThan(MAX_RECIPE_SLICE_BYTES);
		expect(withSlice(JSON.parse(text)).success).toBe(true);
	});

	test("a slice's size is counted exactly as JSON.stringify writes it, in UTF-8", () => {
		const samples = [
			'{}',
			'{"a":[]}',
			'{"a":[1,-0,0.1,1e21,-5e-7,true,false,null,"x\\n\\u0001\\"\u00e9\ud83d\ude00"]}',
			'{"__proto__":{"k":[[],{},[[{}]]]},"\u00e9":"\\ud800","":""}',
			'{"a":{"b":{"c":[1,2,{"d":"e"}]}},"f":[null,[true,[false]]]}',
		];
		for (const text of samples) {
			const value: unknown = JSON.parse(text);
			expect(parsedJsonBytes(value)).toBe(new TextEncoder().encode(JSON.stringify(value)).length);
		}
		expect(parsedJsonBytes({ k: () => 1 })).toBeUndefined();
	});

	test('accepts names of 1 to 31 characters with no leading or trailing dash', () => {
		const named = (name: string) =>
			RecipeSchema.safeParse({ name, build: { kind: 'dockerfile' }, port: 80 }).success;
		expect(named('a')).toBe(true);
		expect(named('hello-world')).toBe(true);
		expect(named('a'.repeat(31))).toBe(true);
		expect(named('a'.repeat(32))).toBe(false);
		// The constant the CLI cuts project names to is the pattern's limit.
		expect(MAX_PROJECT_NAME).toBe(31);
		expect(named('hello-')).toBe(false);
		// Would share labels with hello-world.
		expect(named('hello--world')).toBe(false);
		expect(named('-hello')).toBe(false);
		expect(named('')).toBe(false);
	});

	test('matches repos as host/owner/name, with * for a whole segment', () => {
		const withRepos = (repos: string[]) =>
			RecipeSchema.safeParse({
				name: 'a',
				build: { kind: 'dockerfile' },
				port: 80,
				match: { repos },
			}).success;
		expect(withRepos([])).toBe(true);
		expect(withRepos(['github.com/storefront-org/storefront-server'])).toBe(true);
		expect(withRepos(['github.com/*/storefront-server'])).toBe(true);
		// Two or four segments, a * inside a name, upper case, or nothing.
		expect(withRepos(['github.com/storefront-server'])).toBe(false);
		expect(withRepos(['github.com/*/*/storefront-server'])).toBe(false);
		expect(withRepos(['github.com/storefront-*/storefront-server'])).toBe(false);
		expect(withRepos(['github.com/*/storefront-*'])).toBe(false);
		expect(withRepos(['github.com/Acme/App'])).toBe(false);
		expect(withRepos([''])).toBe(false);
	});
});

describe('sliceFile and the slice it reports', () => {
	test('a built-in recipe may name an absolute path in its image; a koi.yaml may not', () => {
		const recipe = RecipeSchema.parse({
			name: 'storefront',
			build: { kind: 'dockerfile', from: 'recipe' },
			port: 8080,
			sliceFile: '/opt/rocketride/koi-slice.json',
		});
		expect(recipe.sliceFile).toBe('/opt/rocketride/koi-slice.json');
		const repo = RepoRecipeSchema.parse({
			build: { kind: 'dockerfile' },
			port: 8080,
			sliceFile: '/opt/app/koi-slice.json',
		});
		expect('sliceFile' in repo).toBe(false);
	});

	test('the path is absolute, plain and has no . or .. segment', () => {
		for (const good of ['/koi-slice.json', '/opt/app_1/koi-slice.v1.json']) {
			expect(ImagePathSchema.safeParse(good).success).toBe(true);
		}
		for (const bad of [
			'koi-slice.json',
			'/opt/../etc/passwd',
			'/opt/./x',
			'/opt//x',
			'/opt/x/',
			'/opt/a b',
			'/opt/x;rm',
			'/opt/$(x)',
			'/opt/x:y',
			`/${'x'.repeat(255)}`,
		]) {
			expect(ImagePathSchema.safeParse(bad).success).toBe(false);
		}
	});

	test('the slice is a JSON object of at most 16 KiB, kept as given', () => {
		const slice = JSON.parse('{"nodes":{"core":["core"]},"__proto__":{"x":1}}');
		const parsed = DeploymentSliceSchema.parse(slice);
		expect(parsed).toBe(slice);
		expect(Object.hasOwn(parsed, '__proto__')).toBe(true);
		const room = MAX_DEPLOYMENT_SLICE_BYTES - '{"k":""}'.length;
		expect(DeploymentSliceSchema.safeParse({ k: 'x'.repeat(room) }).success).toBe(true);
		expect(DeploymentSliceSchema.safeParse({ k: 'x'.repeat(room + 1) }).success).toBe(false);
		for (const bad of [[], 'core', 1, null, { n: Number.NaN }, { f: () => 1 }]) {
			expect(DeploymentSliceSchema.safeParse(bad).success).toBe(false);
		}
		// Nested at most 16 deep: the store indents each level, so 8,000
		// nested arrays in 16 KiB would take about 64 MB there.
		const nested = (levels: number) =>
			JSON.parse(`{"k":${'['.repeat(levels - 1)}${']'.repeat(levels - 1)}}`);
		expect(DeploymentSliceSchema.safeParse(nested(MAX_DEPLOYMENT_SLICE_DEPTH)).success).toBe(true);
		const deep = DeploymentSliceSchema.safeParse(nested(MAX_DEPLOYMENT_SLICE_DEPTH + 1));
		expect(deep.error?.issues[0]?.message).toBe('at most 16 levels of objects and arrays');
		expect(DeploymentSliceSchema.safeParse(nested(8000)).success).toBe(false);
		// A deployment keeps it; one without it still parses.
		const deployment = {
			requestId: 'a'.repeat(16),
			commit: 'c'.repeat(40),
			image: 'koi-preview/hello:a',
			container: 'koi-hello-a',
			port: 8080,
			healthPath: '/',
			healthTimeoutSeconds: 60,
			user: '65534:65534',
			env: {},
			deployedAt: '2026-10-06T00:00:00.000Z',
		};
		expect(DeploymentSchema.parse({ ...deployment, slice: { a: 1 } }).slice).toEqual({ a: 1 });
		expect(DeploymentSchema.parse(deployment).slice).toBeUndefined();
		expect(DeploymentSchema.safeParse({ ...deployment, slice: ['a'] }).success).toBe(false);
	});
});

describe('repoMatches', () => {
	const org = 'github.com/storefront-org/storefront-server';
	const forks = 'github.com/*/storefront-server';

	test('an exact entry matches that repo and no other', () => {
		expect(repoMatches(org, 'github.com/storefront-org/storefront-server')).toBe(true);
		expect(repoMatches(org, 'github.com/someone/storefront-server')).toBe(false);
		expect(repoMatches(org, 'github.com/storefront-org/storefront-client')).toBe(false);
	});

	test('a * owner matches every fork of the name on that host', () => {
		expect(repoMatches(forks, 'github.com/someone/storefront-server')).toBe(true);
		expect(repoMatches(forks, 'github.com/storefront-org/storefront-server')).toBe(true);
		// The same name on another host is not a fork.
		expect(repoMatches(forks, 'gitlab.com/someone/storefront-server')).toBe(false);
		// Another name under the same owner.
		expect(repoMatches(forks, 'github.com/someone/storefront-client')).toBe(false);
	});

	test('a * is one whole segment and never reaches across a slash', () => {
		expect(repoMatches(forks, 'github.com/a/b/storefront-server')).toBe(false);
		expect(repoMatches(forks, 'github.com/storefront-server')).toBe(false);
		expect(repoMatches(forks, 'github.com//storefront-server')).toBe(false);
		// A literal segment is compared whole: no prefix or suffix match.
		expect(repoMatches(forks, 'github.com/someone/storefront-server-2')).toBe(false);
		expect(repoMatches(forks, 'github.com/someone/my-storefront-server')).toBe(false);
	});
});

describe('RepoRecipeSchema', () => {
	test('rejects any build kind but a dockerfile', () => {
		const script = { build: { kind: 'script', path: './evil.sh' }, port: 8080 };
		expect(RepoRecipeSchema.safeParse(script).success).toBe(false);
		expect(RecipeSchema.safeParse({ name: 'a', ...script }).success).toBe(false);
	});

	test('rejects a Dockerfile taken from a built-in recipe directory', () => {
		const result = RepoRecipeSchema.safeParse({
			build: { kind: 'dockerfile', from: 'recipe', path: 'Dockerfile' },
			port: 8080,
		});
		expect(result.success).toBe(false);
	});

	test('drops a name, so a pull request cannot choose the project prefix', () => {
		const recipe = RepoRecipeSchema.parse({
			name: 'storefront',
			build: { kind: 'dockerfile' },
			port: 8080,
		});
		expect('name' in recipe).toBe(false);
		expect(recipe.build).toEqual({
			kind: 'dockerfile',
			from: 'source',
			path: 'Dockerfile',
			context: '.',
		});
	});
});

describe('PreviewRecordSchema', () => {
	test('accepts a well-formed record', () => {
		const now = new Date().toISOString();
		const result = PreviewRecordSchema.safeParse({
			label: 'storefront-pr-2518',
			project: 'storefront',
			status: 'running',
			commit: 'a'.repeat(40),
			branch: 'fix/agent-timeout',
			pr: 2518,
			dirty: false,
			repo: 'github.com/storefront-org/storefront-server',
			requestId: 'a'.repeat(16),
			attempt: 'b'.repeat(20),
			ttlDays: 7,
			createdAt: now,
			updatedAt: now,
		});
		expect(result.success).toBe(true);
	});

	test('rejects a label with uppercase or a trailing dash', () => {
		const now = new Date().toISOString();
		const base = {
			project: 'p',
			status: 'running',
			commit: 'a'.repeat(40),
			branch: 'b',
			dirty: false,
			repo: 'github.com/acme/app',
			requestId: 'a'.repeat(16),
			attempt: 'b'.repeat(20),
			ttlDays: 7,
			createdAt: now,
			updatedAt: now,
		};
		// Control: the same record with a good label parses, so the failures
		// below are about the label and nothing else.
		expect(PreviewRecordSchema.safeParse({ ...base, label: 'good' }).success).toBe(true);
		expect(PreviewRecordSchema.safeParse({ ...base, label: 'Bad' }).success).toBe(false);
		expect(PreviewRecordSchema.safeParse({ ...base, label: 'bad-' }).success).toBe(false);
	});

	test('reads a record written before attempts with an empty one, and refuses a malformed one', () => {
		const now = new Date().toISOString();
		const base = {
			label: 'hello',
			project: 'hello',
			status: 'running',
			commit: 'a'.repeat(40),
			branch: 'main',
			dirty: false,
			repo: 'github.com/acme/hello',
			requestId: 'a'.repeat(16),
			ttlDays: 7,
			createdAt: now,
			updatedAt: now,
		};
		expect(PreviewRecordSchema.parse(base).attempt).toBe('');
		expect(PreviewRecordSchema.parse({ ...base, attempt: 'b'.repeat(32) }).attempt).toBe(
			'b'.repeat(32),
		);
		expect(PreviewRecordSchema.safeParse({ ...base, attempt: '../x' }).success).toBe(false);
	});

	test('keeps the head and base a merge commit was built from, and reads a record without them', () => {
		const now = new Date().toISOString();
		const base = {
			label: 'hello-pr-7',
			project: 'hello',
			status: 'running',
			commit: 'a'.repeat(40),
			branch: 'feature',
			pr: 7,
			dirty: false,
			repo: 'github.com/acme/hello',
			requestId: 'a'.repeat(16),
			attempt: 'b'.repeat(20),
			ttlDays: 7,
			createdAt: now,
			updatedAt: now,
		};
		const merge = { head: 'b'.repeat(40), base: 'c'.repeat(40), baseBranch: 'main' };
		expect(PreviewRecordSchema.parse({ ...base, merge }).merge).toEqual(merge);
		// Records written before koid kept it, and builds of a working tree.
		expect(PreviewRecordSchema.parse(base).merge).toBeUndefined();
		expect(PreviewRecordSchema.safeParse({ ...base, merge: { head: merge.head } }).success).toBe(
			false,
		);
	});

	test('a deployment keeps its id, image digest and merge, and one written without them parses', () => {
		const old = {
			requestId: 'a'.repeat(16),
			commit: 'a'.repeat(40),
			image: 'koi-preview/hello:a',
			container: 'koi-hello-a',
			port: 8080,
			healthPath: '/',
			healthTimeoutSeconds: 60,
			user: '65534:65534',
			env: {},
			deployedAt: '2026-10-06T00:00:00.000Z',
		};
		const parsed = DeploymentSchema.parse(old);
		expect(parsed.deploymentId).toBeUndefined();
		expect(parsed.imageDigest).toBeUndefined();
		expect(parsed.merge).toBeUndefined();
		const identified = {
			...old,
			deploymentId: 'b'.repeat(20),
			imageDigest: `sha256:${'0'.repeat(64)}`,
			merge: { head: 'b'.repeat(40), base: 'c'.repeat(40), baseBranch: 'main' },
		};
		expect(DeploymentSchema.parse(identified)).toEqual(identified);
		expect(DeploymentSchema.safeParse({ ...identified, imageDigest: 'latest' }).success).toBe(
			false,
		);
		expect(DeploymentSchema.safeParse({ ...identified, deploymentId: '../x' }).success).toBe(false);
	});

	test('a lease has an id, the deployment it holds, a holder and its times, and a record may carry one', () => {
		const now = new Date().toISOString();
		const lease = {
			leaseId: 'l'.repeat(20),
			deploymentId: 'b'.repeat(20),
			holder: 'dev@laptop',
			acquiredAt: now,
			expiresAt: now,
		};
		expect(LeaseSchema.parse(lease)).toEqual(lease);
		for (const bad of [
			{ ...lease, leaseId: 'L'.repeat(20) },
			{ ...lease, holder: '' },
			{ ...lease, holder: 'a\u0001b' },
			{ ...lease, holder: 'h'.repeat(201) },
			{ ...lease, expiresAt: 'tomorrow' },
		]) {
			expect(LeaseSchema.safeParse(bad).success).toBe(false);
		}
		const record = {
			label: 'hello',
			project: 'hello',
			status: 'running',
			commit: 'a'.repeat(40),
			branch: 'main',
			dirty: false,
			repo: 'github.com/acme/hello',
			requestId: 'a'.repeat(16),
			attempt: 'b'.repeat(20),
			ttlDays: 7,
			createdAt: now,
			updatedAt: now,
		};
		// Records written before koid kept leases have none.
		expect(PreviewRecordSchema.parse(record).lease).toBeUndefined();
		expect(PreviewRecordSchema.parse({ ...record, lease }).lease).toEqual(lease);
	});
});

describe('the live preview list', () => {
	// 62 characters each: with quotes and commas, 63 of them take exactly
	// 1 + 63 * 65 = 4096 bytes.
	const labels = (n: number) =>
		Array.from({ length: n }, (_, i) => `x${String(i).padStart(3, '0')}${'a'.repeat(58)}`);

	test('is each label once, sorted, as JSON', () => {
		expect(encodeLivePreviews(['b', 'a', 'b'])).toBe('["a","b"]');
	});

	test('fits up to the parameter limit and not a byte past it', () => {
		expect(new TextEncoder().encode(encodeLivePreviews(labels(63))).length).toBe(
			LIVE_PREVIEWS_MAX_BYTES,
		);
		expect(livePreviewsFit(labels(63))).toBe(true);
		expect(livePreviewsFit([...labels(63), 'a'])).toBe(false);
		// A label already listed adds nothing.
		expect(livePreviewsFit([...labels(63), labels(1)[0] ?? ''])).toBe(true);
	});
});
