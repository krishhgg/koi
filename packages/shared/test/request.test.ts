import { describe, expect, test } from 'bun:test';
import {
	KeepSchema,
	MAX_KEEP,
	repoIdFromRemote,
	requestKey,
	sourceKey,
	type UpRequest,
	UpRequestSchema,
} from '../src/request.ts';

const ID = 'k3j9x0a1b2c3d4e5';

const valid: UpRequest = {
	version: 1,
	id: ID,
	label: 'storefront-pr-2518',
	project: 'storefront',
	repo: 'github.com/storefront-org/storefront-server',
	commit: 'a'.repeat(40),
	branch: 'fix/agent-timeout',
	pr: 2518,
	dirty: false,
	recipe: { kind: 'builtin', name: 'storefront' },
	createdAt: new Date().toISOString(),
};

describe('UpRequestSchema', () => {
	test('accepts a built-in recipe request', () => {
		expect(UpRequestSchema.safeParse(valid).success).toBe(true);
	});

	test('accepts a repo recipe and strips a smuggled name', () => {
		const parsed = UpRequestSchema.parse({
			...valid,
			recipe: { kind: 'repo', recipe: { name: 'evil', build: { kind: 'dockerfile' }, port: 8080 } },
		});
		expect(parsed.recipe.kind === 'repo' && 'name' in parsed.recipe.recipe).toBe(false);
	});

	test('takes the head and base a merge commit was built from, whole or not at all', () => {
		const merge = { head: 'b'.repeat(40), base: 'c'.repeat(40), baseBranch: 'develop' };
		expect(UpRequestSchema.parse({ ...valid, merge }).merge).toEqual(merge);
		// The base branch's name is known only when gh is there to ask.
		const { baseBranch: _, ...unnamed } = merge;
		expect(UpRequestSchema.parse({ ...valid, merge: unnamed }).merge).toEqual(unnamed);
		expect(UpRequestSchema.parse(valid).merge).toBeUndefined();
		for (const bad of [
			{ head: merge.head },
			{ base: merge.base },
			{ ...merge, head: 'abc' },
			{ ...merge, baseBranch: '' },
		]) {
			expect(UpRequestSchema.safeParse({ ...valid, merge: bad }).success).toBe(false);
		}
	});

	test('rejects ids that could break out of a key or command line', () => {
		for (const id of ['short', 'UPPERCASE0123456', 'abc/def/ghi/jkl0', 'abcdefghijklmnop;rm', '']) {
			expect(UpRequestSchema.safeParse({ ...valid, id }).success).toBe(false);
		}
	});

	test('rejects unknown versions and malformed repos', () => {
		expect(UpRequestSchema.safeParse({ ...valid, version: 2 }).success).toBe(false);
		expect(UpRequestSchema.safeParse({ ...valid, repo: 'acme/app' }).success).toBe(false);
		expect(UpRequestSchema.safeParse({ ...valid, repo: 'GitHub.com/Acme/App' }).success).toBe(
			false,
		);
	});
});

describe('object keys', () => {
	test('place the request and the source under fixed prefixes', () => {
		expect(requestKey(ID)).toBe(`requests/${ID}.json`);
		expect(sourceKey(ID)).toBe(`sources/${ID}.tar.gz`);
	});

	test('refuse an id that is not a request id', () => {
		expect(() => requestKey('../../etc/passwd')).toThrow();
		expect(() => sourceKey('x')).toThrow();
	});
});

describe('repoIdFromRemote', () => {
	test.each([
		[
			'https://github.com/storefront-org/storefront-server.git',
			'github.com/storefront-org/storefront-server',
		],
		['https://github.com/Acme/App', 'github.com/acme/app'],
		['git@github.com:acme/app.git', 'github.com/acme/app'],
		['ssh://git@github.com/acme/app.git', 'github.com/acme/app'],
		['https://user:token@github.com/acme/app.git', 'github.com/acme/app'],
	])('%p -> %p', (remote, id) => {
		expect(repoIdFromRemote(remote)).toBe(id);
	});

	test.each([
		'not a remote',
		'https://github.com/acme',
		'https://github.com/acme/app/extra',
		'/local/path/repo',
	])('rejects %p', (remote) => {
		expect(() => repoIdFromRemote(remote)).toThrow();
	});
});

describe('koi up --keep', () => {
	const request = {
		version: 1,
		id: 'a'.repeat(16),
		label: 'hello-pr-7',
		project: 'hello',
		repo: 'github.com/acme/hello',
		commit: 'c'.repeat(40),
		branch: 'feature/x',
		dirty: false,
		recipe: { kind: 'builtin', name: 'hello' },
		createdAt: '2026-10-06T00:00:00.000Z',
	};

	test('a request carries the names, each once, at most 32, safe on a command line', () => {
		expect(UpRequestSchema.parse({ ...request, keep: ['llm_openai', 'a.b-c'] }).keep).toEqual([
			'llm_openai',
			'a.b-c',
		]);
		expect(UpRequestSchema.parse(request).keep).toBeUndefined();
		for (const keep of [
			[],
			['a', 'a'],
			['-rf'],
			['.hidden'],
			['a b'],
			['a;b'],
			['$(id)'],
			['a\nb'],
			['x'.repeat(65)],
			Array.from({ length: MAX_KEEP + 1 }, (_, i) => `n${i}`),
		]) {
			expect(KeepSchema.safeParse(keep).success).toBe(false);
			expect(UpRequestSchema.safeParse({ ...request, keep }).success).toBe(false);
		}
		expect(KeepSchema.safeParse(Array.from({ length: MAX_KEEP }, (_, i) => `n${i}`)).success).toBe(
			true,
		);
	});
});
