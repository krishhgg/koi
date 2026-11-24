import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { MAX_PROJECT_NAME, previewHostLabel, RecipeSchema, repoIdFromRemote } from '@koi/shared';
import { BUILTIN_RECIPES } from '../src/builtins.ts';
import { projectForBuiltin, projectFromRepo, resolveRecipe } from '../src/recipe.ts';
import { RECIPES_DIR, readRecipeFiles } from '../src/recipe-files.ts';

const files = (map: Record<string, string>) => async (path: string) => map[path];

describe('resolveRecipe', () => {
	const builtin = RecipeSchema.parse({
		name: 'storefront',
		match: { repos: ['github.com/storefront-org/storefront-server'] },
		port: 8080,
		build: { kind: 'dockerfile', from: 'recipe' },
	});

	test('a built-in recipe wins, by repo', async () => {
		const r = await resolveRecipe(
			'github.com/storefront-org/storefront-server',
			[builtin],
			files({ 'koi.yaml': 'port: 1' }),
		);
		expect(r).toEqual({
			project: 'storefront',
			recipe: { kind: 'builtin', name: 'storefront' },
			limits: { buildTimeoutMinutes: 45, healthTimeoutSeconds: 180 },
			reportsSlice: false,
		});
		// One with a sliceFile reports its slice, and so takes --keep.
		const reporting = RecipeSchema.parse({ ...builtin, sliceFile: '/app/koi-slice.json' });
		const withSlice = await resolveRecipe(
			'github.com/storefront-org/storefront-server',
			[reporting],
			files({}),
		);
		expect(withSlice.reportsSlice).toBe(true);
	});

	test('a built-in recipe also wins for a fork, by a * owner in its match list', async () => {
		const withForks = RecipeSchema.parse({
			name: 'storefront',
			match: {
				repos: ['github.com/storefront-org/storefront-server', 'github.com/*/storefront-server'],
			},
			port: 8080,
			build: { kind: 'dockerfile', from: 'recipe' },
		});
		const fork = await resolveRecipe(
			'github.com/someone/storefront-server',
			[withForks],
			files({ 'koi.yaml': 'port: 1' }),
		);
		// The shared recipe, under the fork's own project name.
		expect(fork.project).toBe('storefront-someone');
		expect(fork.recipe).toEqual({ kind: 'builtin', name: 'storefront' });
		// The same name on another host is not a fork, so koi.yaml decides.
		const elsewhere = await resolveRecipe(
			'gitlab.com/someone/storefront-server',
			[withForks],
			files({ 'koi.yaml': 'port: 1\nbuild:\n  kind: dockerfile\n' }),
		);
		expect(elsewhere.project).toBe('storefront-server');
		expect(elsewhere.recipe.kind).toBe('repo');
	});

	test('falls back to koi.yaml, naming the project after the repo', async () => {
		const r = await resolveRecipe(
			'github.com/acme/My_App',
			[builtin],
			files({ 'koi.yaml': 'name: storefront\nport: 8080\nbuild:\n  kind: dockerfile\n' }),
		);
		expect(r.project).toBe('my-app');
		expect(r.recipe.kind).toBe('repo');
		expect(r.recipe.kind === 'repo' && 'name' in r.recipe.recipe).toBe(false);
	});

	test('reads .koi/koi.yaml when the root has none, and the root wins when both exist', async () => {
		const under = await resolveRecipe(
			'github.com/acme/app',
			[],
			files({ '.koi/koi.yaml': 'port: 7000\nbuild:\n  kind: dockerfile\n' }),
		);
		expect(under.recipe.kind === 'repo' && under.recipe.recipe.port).toBe(7000);
		const both = await resolveRecipe(
			'github.com/acme/app',
			[],
			files({
				'koi.yaml': 'port: 8080\nbuild:\n  kind: dockerfile\n',
				'.koi/koi.yaml': 'port: 7000\nbuild:\n  kind: dockerfile\n',
			}),
		);
		expect(both.recipe.kind === 'repo' && both.recipe.recipe.port).toBe(8080);
	});

	test('reads koi.json too', async () => {
		const r = await resolveRecipe(
			'github.com/acme/app',
			[],
			files({ 'koi.json': '{"port":3000,"build":{"kind":"dockerfile"}}' }),
		);
		expect(r.recipe.kind === 'repo' && r.recipe.recipe.port).toBe(3000);
	});

	test("gives the recipe's build and health time limits", async () => {
		const r = await resolveRecipe(
			'github.com/acme/app',
			[],
			files({
				'koi.yaml':
					'port: 8080\nbuildTimeoutMinutes: 180\nhealthTimeoutSeconds: 600\nbuild:\n  kind: dockerfile\n',
			}),
		);
		expect(r.limits).toEqual({ buildTimeoutMinutes: 180, healthTimeoutSeconds: 600 });
	});

	test('explains an invalid koi.yaml', async () => {
		await expect(
			resolveRecipe(
				'github.com/acme/app',
				[],
				files({ 'koi.yaml': 'port: 8080\nbuild:\n  kind: script\n' }),
			),
		).rejects.toThrow(/koi.yaml is not a valid koi recipe: build/);
	});

	test('says how to add a recipe when there is none', async () => {
		await expect(resolveRecipe('github.com/acme/app', [], files({}))).rejects.toThrow(
			/Add a koi.yaml/,
		);
	});
});

describe('projectForBuiltin', () => {
	const recipe = (name: string, repos: string[]) =>
		RecipeSchema.parse({ name, match: { repos }, port: 80, build: { kind: 'dockerfile' } });
	const upstream = 'github.com/storefront-org/storefront-server';
	const forks = 'github.com/*/storefront-server';

	test('keeps the plain recipe name for a repo the match list names exactly', () => {
		expect(projectForBuiltin(recipe('storefront', [upstream, forks]), upstream)).toBe('storefront');
		// Whatever the order of the entries.
		expect(projectForBuiltin(recipe('storefront', [forks, upstream]), upstream)).toBe('storefront');
	});

	test('names a fork matched through a * entry after the recipe and its owner', () => {
		const r = recipe('storefront', [upstream, forks]);
		expect(projectForBuiltin(r, 'github.com/someone/storefront-server')).toBe('storefront-someone');
		expect(projectForBuiltin(r, 'github.com/some.one/storefront-server')).toBe(
			'storefront-some-one',
		);
	});

	test('cuts a long owner so the name fits and a long branch still gets a label', () => {
		const r = recipe('storefront', [forks]);
		// GitHub allows 39 characters in a user or organisation name.
		const project = projectForBuiltin(r, `github.com/${'o'.repeat(39)}/storefront-server`);
		expect(project).toBe(`storefront-${'o'.repeat(MAX_PROJECT_NAME - 'storefront-'.length)}`);
		expect(project).toHaveLength(MAX_PROJECT_NAME);
		expect(previewHostLabel(project, { branch: 'b'.repeat(100) })).toHaveLength(63);
		// A cut never leaves a trailing dash.
		expect(
			projectForBuiltin(r, `github.com/${'o'.repeat(19)}-${'p'.repeat(19)}/storefront-server`),
		).toBe(`storefront-${'o'.repeat(19)}`);
	});

	test('gives a fork different labels from the main repository', () => {
		const r = recipe('storefront', [upstream, forks]);
		const main = projectForBuiltin(r, upstream);
		const fork = projectForBuiltin(r, 'github.com/someone/storefront-server');
		expect(previewHostLabel(main, { branch: 'develop' })).not.toBe(
			previewHostLabel(fork, { branch: 'develop' }),
		);
		expect(previewHostLabel(main, { pr: 12 })).toBe('storefront-pr-12');
		expect(previewHostLabel(fork, { pr: 12 })).toBe('storefront-someone-pr-12');
	});

	test('refuses a recipe whose name leaves no room for an owner', () => {
		const r = recipe('r'.repeat(MAX_PROJECT_NAME - 1), ['github.com/*/app']);
		expect(() => projectForBuiltin(r, 'github.com/someone/app')).toThrow(/project name/);
	});
});

describe('projectFromRepo', () => {
	test('slugs the repo name and fits it into 31 characters', () => {
		expect(projectFromRepo('github.com/acme/storefront-server')).toBe('storefront-server');
		expect(projectFromRepo('github.com/acme/My__App.v2')).toBe('my-app-v2');
		expect(projectFromRepo(`github.com/acme/${'a'.repeat(30)}-bbbb`)).toBe('a'.repeat(30));
	});
});

describe('BUILTIN_RECIPES', () => {
	test('lists exactly the recipes in recipes/', async () => {
		const entries = await readdir(RECIPES_DIR, { withFileTypes: true });
		const onDisk = entries
			.filter((e) => e.isDirectory())
			.map((e) => e.name)
			.sort();
		expect(BUILTIN_RECIPES.map((r) => r.name).sort()).toEqual(onDisk);
		for (const name of onDisk) {
			const file = RecipeSchema.parse(
				await Bun.file(join(RECIPES_DIR, name, 'recipe.json')).json(),
			);
			expect(BUILTIN_RECIPES.find((r) => r.name === name)).toEqual(file);
		}
	});

	test('every recipe that matches forks leaves room for the longest GitHub owner', () => {
		for (const r of BUILTIN_RECIPES) {
			for (const pattern of r.match.repos.filter((p) => p.includes('*'))) {
				const repo = pattern.replace('*', 'o'.repeat(39));
				const project = projectForBuiltin(r, repo);
				expect(project).toMatch(new RegExp(`^${r.name}-o+$`));
				expect(previewHostLabel(project, { branch: 'b'.repeat(100) })).toHaveLength(63);
			}
		}
	});

	test('a fork is matched from every common remote form', async () => {
		const withForks = RecipeSchema.parse({
			name: 'storefront',
			match: {
				repos: ['github.com/storefront-org/storefront-server', 'github.com/*/storefront-server'],
			},
			port: 8080,
			build: { kind: 'dockerfile', from: 'recipe' },
		});
		for (const remote of [
			'https://github.com/Someone/Storefront-Server.git',
			'https://github.com/someone/storefront-server',
			'git@github.com:someone/storefront-server.git',
			'git@github.com:Someone/storefront-server',
			'ssh://git@github.com/someone/storefront-server.git',
			'ssh://git@github.com/someone/storefront-server',
		]) {
			const r = await resolveRecipe(repoIdFromRemote(remote), [withForks], files({}));
			expect(r.recipe).toEqual({ kind: 'builtin', name: 'storefront' });
			expect(r.project).toBe('storefront-someone');
		}
	});
});

describe('readRecipeFiles', () => {
	const recipesDir = async (layout: Record<string, string>) => {
		const dir = await mkdtemp(join(tmpdir(), 'koi-recipes-'));
		for (const [path, text] of Object.entries(layout)) {
			await mkdir(join(dir, dirname(path)), { recursive: true });
			await writeFile(join(dir, path), text);
		}
		return dir;
	};

	test('reads the recipe.json of every directory, in name order, and skips other files', async () => {
		const dir = await recipesDir({
			'web/recipe.json': '{"name":"web","port":8080,"build":{"kind":"dockerfile"}}',
			'api/recipe.json': '{"name":"api","port":3000,"data":{"keep":["a"]}}',
			'api/Dockerfile': 'FROM scratch\n',
			'README.md': '# recipes\n',
		});
		expect(readRecipeFiles(dir)).toEqual([
			{ name: 'api', port: 3000, data: { keep: ['a'] } },
			{ name: 'web', port: 8080, build: { kind: 'dockerfile' } },
		]);
	});

	test('gives nothing for a directory with no recipes', async () => {
		expect(readRecipeFiles(await recipesDir({ 'README.md': '# recipes\n' }))).toEqual([]);
	});

	test('names a directory that has no recipe.json', async () => {
		const dir = await recipesDir({ 'web/Dockerfile': 'FROM scratch\n' });
		expect(() => readRecipeFiles(dir)).toThrow(/recipes\/web has no readable recipe\.json/);
	});

	test('refuses a recipe.json that is not JSON', async () => {
		const dir = await recipesDir({ 'web/recipe.json': '{"name":' });
		expect(() => readRecipeFiles(dir)).toThrow(SyntaxError);
	});
});
