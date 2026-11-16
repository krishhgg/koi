import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_RECIPE_SLICE_BYTES } from '@koi/shared';
import { ZodError } from 'zod';
import { loadBuiltinRecipe } from '../src/recipes.ts';
import { recipeDockerfiles, sourceStages, stages, writableMounts } from './dockerfiles.ts';

// A recipes directory with one recipe directory, `name`, holding `text` as
// its recipe.json (or no recipe.json when text is undefined).
async function recipes(name: string, text?: string): Promise<string> {
	const root = await mkdtemp(join(tmpdir(), 'koid-recipes-'));
	await mkdir(join(root, name));
	if (text !== undefined) await writeFile(join(root, name, 'recipe.json'), text);
	return root;
}

const hello = {
	name: 'hello',
	port: 8080,
	build: { kind: 'dockerfile', from: 'recipe', path: 'Dockerfile' },
};

describe('loadBuiltinRecipe', () => {
	test('reads <recipesDir>/<name>/recipe.json, filling defaults, with its directory', async () => {
		const root = await recipes('hello', JSON.stringify(hello));
		const { recipe, dir } = await loadBuiltinRecipe(root, 'hello');
		expect(dir).toBe(join(root, 'hello'));
		expect(recipe.name).toBe('hello');
		expect(recipe.port).toBe(8080);
		expect(recipe.build).toEqual({
			kind: 'dockerfile',
			from: 'recipe',
			path: 'Dockerfile',
			context: '.',
		});
		expect(recipe.buildTimeoutMinutes).toBe(45);
	});

	test('says there is no such recipe when its file is missing', async () => {
		const root = await recipes('hello');
		await expect(loadBuiltinRecipe(root, 'hello')).rejects.toThrow(
			'no built-in recipe named hello',
		);
		await expect(loadBuiltinRecipe(root, 'other')).rejects.toThrow(
			'no built-in recipe named other',
		);
	});

	test('refuses a recipe file that is not JSON', async () => {
		const root = await recipes('hello', '{"name": "hello",');
		await expect(loadBuiltinRecipe(root, 'hello')).rejects.toBeInstanceOf(SyntaxError);
	});

	test('refuses a recipe the schema does not accept', async () => {
		const root = await recipes('hello', JSON.stringify({ ...hello, port: 0 }));
		const loading = loadBuiltinRecipe(root, 'hello');
		await expect(loading).rejects.toBeInstanceOf(ZodError);
		await expect(loading).rejects.toThrow('port');
	});

	test('refuses a recipe whose name is not its directory', async () => {
		const root = await recipes('hello', JSON.stringify({ ...hello, name: 'other' }));
		await expect(loadBuiltinRecipe(root, 'hello')).rejects.toThrow(
			`recipe in ${join(root, 'hello')} is named other, not hello`,
		);
	});

	test('refuses a name that is not a project name before reading anything', async () => {
		const root = await recipes('hello', JSON.stringify(hello));
		await expect(loadBuiltinRecipe(root, '../hello')).rejects.toBeInstanceOf(ZodError);
		await expect(loadBuiltinRecipe(join(root, 'x'), '..')).rejects.toBeInstanceOf(ZodError);
	});

	test("keeps a slice section as written, the recipe's own data", async () => {
		const slice = {
			keep: ['web', 'api'],
			seed: { users: 2, admin: true },
			note: null,
		};
		const root = await recipes('hello', JSON.stringify({ ...hello, slice }));
		// No defaults are filled in: koi does not know the shape.
		expect((await loadBuiltinRecipe(root, 'hello')).recipe.slice).toEqual(slice);
	});

	test('refuses a slice that is not a JSON object, or that is too large', async () => {
		for (const slice of ['all', ['web'], 3]) {
			const root = await recipes('hello', JSON.stringify({ ...hello, slice }));
			await expect(loadBuiltinRecipe(root, 'hello')).rejects.toBeInstanceOf(ZodError);
		}
		const big = { keep: 'x'.repeat(MAX_RECIPE_SLICE_BYTES) };
		const root = await recipes('hello', JSON.stringify({ ...hello, slice: big }));
		await expect(loadBuiltinRecipe(root, 'hello')).rejects.toThrow('bytes as JSON');
	});
});

describe('built-in recipe Dockerfiles', () => {
	test('mount no cache a pull request can write, and bind nothing writable', async () => {
		for (const [name, all] of await recipeDockerfiles()) {
			expect(writableMounts(all), name).toEqual([]);
		}
	});

	test('the check finds every recipe Dockerfile and flags a writable cache', async () => {
		const root = await recipes('safe', JSON.stringify(hello));
		await writeFile(
			join(root, 'safe', 'Dockerfile'),
			'FROM node:24\nRUN --mount=type=cache,target=/c,ro true\nCOPY . .\n',
		);
		await mkdir(join(root, 'shared-cache'));
		await writeFile(
			join(root, 'shared-cache', 'Dockerfile'),
			'FROM node:24\nCOPY . .\nRUN --mount=type=cache,target=/root/.npm npm ci\n',
		);
		// A recipe without its own Dockerfile, and a file beside the recipes.
		await mkdir(join(root, 'from-source'));
		await writeFile(join(root, 'README.md'), '# recipes\n');
		const found = await recipeDockerfiles(root);
		expect(found.map(([name]) => name)).toEqual(['safe', 'shared-cache']);
		const flagged = Object.fromEntries(found.map(([name, all]) => [name, writableMounts(all)]));
		expect(flagged).toEqual({ safe: [], 'shared-cache': ['type=cache,target=/root/.npm'] });
	});
});

describe('the Dockerfile checks', () => {
	const dockerfile = (mounts: string) =>
		stages(
			[
				'# syntax=docker/dockerfile:1.7',
				'FROM node:24 AS deps',
				'ADD https://example.com/releases.atom /x/releases.atom',
				'RUN --mount=type=cache,target=/x,ro\\',
				'\ttrue',
				'FROM node:24 AS build',
				'COPY . .',
				`RUN ${mounts} npm ci`,
				'FROM build AS test',
				'RUN npm test',
				'FROM node:24-slim AS runtime',
				'COPY --from=build /src/dist /app',
			].join('\n'),
		);

	test('split a Dockerfile into stages, joining continued lines and dropping comments', () => {
		const all = dockerfile('--mount=type=bind,source=a,target=/a');
		expect(all.map((s) => [s.name, s.from])).toEqual([
			['deps', 'node:24'],
			['build', 'node:24'],
			['test', 'build'],
			['runtime', 'node:24-slim'],
		]);
		expect(all[0]?.lines).toEqual([
			'ADD https://example.com/releases.atom /x/releases.atom',
			'RUN --mount=type=cache,target=/x,ro true',
		]);
	});

	test('find the stages that hold the source: those that copy it and those built on them', () => {
		const held = sourceStages(dockerfile(''));
		expect([...held].sort()).toEqual(['build', 'test']);
	});

	test('pass read-only caches and plain binds, and flag a writable cache or a rw mount', () => {
		expect(writableMounts(dockerfile('--mount=type=bind,source=a,target=/a'))).toEqual([]);
		expect(writableMounts(dockerfile('--mount=type=cache,target=/c,readonly'))).toEqual([]);
		expect(writableMounts(dockerfile('--mount=type=cache,target=/root/.npm'))).toEqual([
			'type=cache,target=/root/.npm',
		]);
		expect(writableMounts(dockerfile('--mount=type=bind,source=a,target=/a,rw'))).toEqual([
			'type=bind,source=a,target=/a,rw',
		]);
		expect(writableMounts(dockerfile('--mount=type=bind,target=/a,readwrite'))).toEqual([
			'type=bind,target=/a,readwrite',
		]);
	});
});
