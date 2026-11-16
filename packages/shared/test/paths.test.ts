import { describe, expect, test } from 'bun:test';
import { RelativePathSchema } from '../src/paths.ts';
import { RecipeSchema } from '../src/recipe.ts';

const BAD_PATHS = [
	'',
	'/',
	'/etc/passwd',
	'..',
	'../..',
	'docker/../../etc',
	'./..',
	'..\\..',
	'docker\\Dockerfile',
	'Docker\u0000file',
	'Dockerfile\n',
	'a\u007fb',
	'http://example.com/context.tar.gz',
	'https://github.com/x/y.git',
	'file:///etc',
	'git://github.com/x/y',
	'git@github.com:x/y.git',
	'git@github.com/x/y',
	'github.com/x/y',
	'C:/Windows',
	'-',
	'--file=/etc/passwd',
	// Prefixes hidden behind "./" or "." segments until normalisation.
	'./-',
	'././--file=x',
	'./github.com/x/y',
	'.//git@github.com/x/y',
];

describe('RelativePathSchema', () => {
	test.each(BAD_PATHS)('rejects %p', (path) => {
		expect(RelativePathSchema.safeParse(path).success).toBe(false);
	});

	test('accepts paths inside the tree and drops "." segments', () => {
		expect(RelativePathSchema.parse('.')).toBe('.');
		expect(RelativePathSchema.parse('./')).toBe('.');
		expect(RelativePathSchema.parse('Dockerfile')).toBe('Dockerfile');
		expect(RelativePathSchema.parse('./Dockerfile')).toBe('Dockerfile');
		expect(RelativePathSchema.parse('./docker//app.Dockerfile')).toBe('docker/app.Dockerfile');
		expect(RelativePathSchema.parse('services/web/')).toBe('services/web');
		expect(RelativePathSchema.parse('...')).toBe('...');
		expect(RelativePathSchema.parse('packages/@koi/app')).toBe('packages/@koi/app');
	});
});

describe('recipe build paths', () => {
	const recipe = (build: object) => RecipeSchema.safeParse({ name: 'hello', build, port: 8080 });

	test.each(BAD_PATHS)('rejects %p as a Dockerfile path or context', (path) => {
		expect(recipe({ kind: 'dockerfile', path }).success).toBe(false);
		expect(recipe({ kind: 'dockerfile', context: path }).success).toBe(false);
	});

	test('normalises a ./ prefix', () => {
		const result = recipe({ kind: 'dockerfile', path: './docker/Dockerfile', context: './' });
		expect(result.success && result.data.build).toEqual({
			kind: 'dockerfile',
			from: 'source',
			path: 'docker/Dockerfile',
			context: '.',
		});
	});
});
