import { describe, expect, test } from 'bun:test';
import {
	compileGlob,
	GLOB_MAX_CHARS,
	GLOB_MAX_EXPANDED_CHARS,
	GLOB_MAX_EXPANSIONS,
	GLOB_STEP_BUDGET,
	GLOB_TURN_STEPS,
	GlobWork,
	globProblem,
} from '../src/glob.ts';

// Work that never runs out, for tests about what matches and not about what it costs.
const free = () =>
	new GlobWork({ over: () => new Error('over budget'), budget: Number.MAX_SAFE_INTEGER });

async function matches(glob: string, path: string): Promise<boolean> {
	return free().match(compileGlob(glob), path);
}

const WORKSPACE =
	'{apps,packages}/{web,api,cli,shared}/**/*.{ts,tsx,js,jsx,mjs,cjs,json,yaml,yml,css,scss,html,md,mdx,toml}';

describe('what a glob may hold', () => {
	test.each([
		'src/**',
		'**/CartPanel.tsx',
		'a/?/*.ts',
		'a,b',
		'a!b',
		'{!a,b}',
		'{}',
		'a{,b}',
		'name with spaces/*',
		WORKSPACE,
	])('%s is a glob', (glob) => {
		expect(globProblem(glob)).toBeUndefined();
	});

	test.each([
		['[a-z].ts', '[ is not supported'],
		['a].ts', '] is not supported'],
		['{[a},b}', '[ is not supported'],
		['!src/**', 'a leading ! is not supported'],
		['a\\*b', '\\ is not supported'],
		['{a,{b,c}}', 'a group inside a group is not supported'],
		['{a', 'has a { with no } after it'],
		['a}', 'has a } with no { before it'],
		['a}b{c', 'has a } with no { before it'],
	])('%s is refused, and the message says what a glob holds', (glob, says) => {
		const problem = globProblem(glob);
		expect(problem).toContain(says);
		expect(problem).toContain('a glob holds literal characters, *, ** as a whole path segment');
	});

	test('a glob is held to its length', () => {
		expect(globProblem('a'.repeat(GLOB_MAX_CHARS))).toBeUndefined();
		expect(globProblem('a'.repeat(GLOB_MAX_CHARS + 1))).toContain('at most 4096 characters');
	});

	test('a glob is held to its count of expansions, counted without writing them out', () => {
		expect(GLOB_MAX_EXPANSIONS).toBe(2 ** 10);
		expect(globProblem('{a,b}'.repeat(10))).toBeUndefined();
		expect(globProblem('{a,b}'.repeat(11))).toContain('expand more than 1024 ways');
		// A count of 2 ** 800 would take far longer than this test to write out.
		expect(globProblem('{a,b}'.repeat(800))).toContain('expand more than 1024 ways');
	});

	test('a glob is held to the characters it expands to', () => {
		const choices = '{a,b}{c,d}{e,f}{g,h}{i,j}';
		const room = GLOB_MAX_EXPANDED_CHARS / 32 - 5;
		expect(globProblem(`${choices}${'x'.repeat(room)}`)).toBeUndefined();
		expect(globProblem(`${choices}${'x'.repeat(room + 1)}`)).toContain(
			`more than ${GLOB_MAX_EXPANDED_CHARS} characters`,
		);
	});

	test('compiling refuses what the schemas refuse', () => {
		expect(() => compileGlob('[a]')).toThrow('[ is not supported');
	});
});

describe('what a glob matches', () => {
	test.each<[string, string[], string[]]>([
		// `*` stops at a slash, and takes dots and spaces and nothing at all.
		['*', ['a', '.a', 'a b'], ['a/b']],
		['*.ts', ['a.ts', '.ts', '.a.ts'], ['a/b.ts', 'a.tsx']],
		['a*b', ['ab', 'axb', 'a b'], ['a/b']],
		// `?` takes one character, whatever its size, and never a slash.
		['a?c', ['abc', 'aéc', 'a日c', 'a😀c'], ['ac', 'a/c', 'abbc']],
		['*??', ['ab', '😀😀'], ['a', 'é', '😀']],
		// `**` as a whole segment is zero or more segments, dot directories too.
		['**', ['a', 'a/b', '.a/.b'], []],
		['**/a', ['a', 'b/a', 'b/c/a', '.b/a'], ['ba', 'b/ba']],
		['a/**', ['a/b', 'a/b/c', 'a/.b'], ['a', 'ab']],
		['a/**/b', ['a/b', 'a/x/b', 'a/x/y/b', 'a/.x/b'], ['ab', 'a/xb']],
		['**/*', ['a', 'a/b', '.a/.b'], []],
		['**/**', ['a', 'a/b'], []],
		['a/**/**/b', ['a/b', 'a/x/y/b'], ['ab']],
		['**/a/**', ['a/b', 'x/a/b'], ['a', 'x/a']],
		// A `**` that is not a whole segment is a `*`, as in Bun.Glob, and so is a longer run.
		['a**', ['a', 'ab'], ['a/b']],
		['**a', ['a', 'ba'], ['b/a']],
		['a**b', ['ab', 'axb'], ['a/b', 'a/x/b']],
		['a/**b', ['a/b', 'a/xb'], ['a/x/b']],
		['a**/b', ['a/b', 'ax/b'], ['a/x/b']],
		['***', ['a'], ['a/b']],
		['***/a', ['b/a'], ['a', 'c/b/a']],
		['a/***/b', ['a/x/b'], ['a/b', 'a/x/y/b']],
		// Groups, an empty choice, a group of one, and a comma outside a group.
		['{a,b}', ['a', 'b'], ['ab', '{a,b}']],
		['a{,b}', ['a', 'ab'], ['b', 'a{,b}']],
		['{a}', ['a'], ['{a}']],
		['a{}', ['a'], ['a{}']],
		['a,b', ['a,b'], ['a', 'b']],
		['{a,b}/{c,d}', ['a/c', 'b/d'], ['ac']],
		['**/{a,b}', ['a', 'x/b', 'x/y/a'], ['xa']],
		// `!` is only special where the schema refuses it, and a `.` segment stays literal.
		['{!a,b}', ['!a', 'b'], ['a']],
		['a!b', ['a!b'], ['ab']],
		['{./a,b}', ['./a', 'b'], ['a']],
		// What docs/verify.md tells a project to write.
		['{a,a/**}', ['a', 'a/b', 'a/b/c'], ['b']],
		['v{1,2,3}/**', ['v1/a', 'v3/a/b'], ['v4/a']],
		['app/?id?/page.tsx', ['app/[id]/page.tsx'], ['app/id/page.tsx']],
		[
			WORKSPACE,
			['apps/web/a.ts', 'packages/cli/src/deep/er/x.toml'],
			['README.md', 'libs/web/a.ts', 'apps/web/a.py'],
		],
	])('%s', async (glob, yes, no) => {
		for (const path of yes) expect(await matches(glob, path)).toBe(true);
		for (const path of no) expect(await matches(glob, path)).toBe(false);
	});

	// Braces expand first and each expansion is read alone. Bun.Glob 1.4.0 reads a `**` by
	// the text around it, so it disagrees on each line here. koi answers what the expansion
	// written out would answer.
	test.each<[string, string, boolean]>([
		['{src/**,test/**}', 'src/a/b', true],
		['{src/**,test/**}', 'test/a/b', true],
		['{a/**,b}', 'a/b/c', true],
		['{**}', 'a/b', true],
		['{a/,b/}**/c', 'a/x/y/c', true],
		['x/**{,/a}', 'x/a/b', true],
		['**{/a,/b}', 'x/y/b', true],
		['a{**/,b}c', 'ax/y/c', false],
		['a{**/,b}c', 'a/x/c', false],
	])('%s on %s reads by the expansion', async (glob, path, expected) => {
		expect(await matches(glob, path)).toBe(expected);
	});

	// Two more where Bun.Glob 1.4.0 answers what no reading of the glob gives, so koi does not.
	test.each<[string, string, boolean]>([
		// The `/` in the glob has nothing to match in the path.
		['x**/**', 'x', false],
		['x**/**/y', 'xy', false],
		// No expansion holds a `}`.
		['**/?**/{é,~,}', 'ab/}', false],
	])('%s on %s reads by what the glob says', async (glob, path, expected) => {
		expect(await matches(glob, path)).toBe(expected);
	});
});

// A small generator with a seed, so a failure names a glob that comes back on the next run.
function randomizer(seed: number) {
	let state = seed;
	const below = (n: number) => {
		state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
		return Math.floor((state / 4294967296) * n);
	};
	const pick = <T>(items: readonly T[]) => items[below(items.length)] as T;
	return { below, pick };
}

const LITERALS = ['a', 'b', 'c', '.', '.a', 'a.b', ' ', 'x y', 'é', '日', '😀', '-', '_', '!', '+'];
const NAMES = [
	'a',
	'b',
	'ab',
	'ba',
	'aa',
	'.a',
	'.b',
	'..a',
	'a.',
	'a b',
	' a',
	'é',
	'日',
	'😀',
	'a😀',
	'😀b',
	'src',
	'x.ts',
	'.ts',
	'!a',
	'a,b',
	'}',
	'{',
	'[a]',
	'a\\b',
	'(x)',
];

function generator(seed: number) {
	const { below, pick } = randomizer(seed);
	const segment = () => {
		let out = '';
		for (let i = 0, n = 1 + below(4); i < n; i++) {
			const roll = below(10);
			if (roll < 4) out += pick(LITERALS);
			else if (roll < 6) out += '*';
			else if (roll < 8) out += '?';
			else if (roll < 9) out += '**';
			else out += '***';
		}
		return out;
	};
	const group = () => {
		const choices: string[] = [];
		for (let i = 0, n = 1 + below(3); i < n; i++) {
			const roll = below(10);
			if (roll === 0) choices.push('');
			else if (roll < 7) choices.push(segment());
			else choices.push(`${segment()}/${segment()}`);
		}
		return `{${choices.join(',')}}`;
	};
	const glob = (braces: boolean) => {
		const parts: string[] = [];
		for (let i = 0, n = 1 + below(4); i < n; i++) {
			const roll = below(10);
			if (roll < 3) parts.push('**');
			else if (braces && roll < 6) parts.push(`${below(2) ? pick(LITERALS) : ''}${group()}`);
			else parts.push(segment());
		}
		const text = parts.join('/').replace(/^!+/, '');
		return text === '' ? 'a' : text;
	};
	const path = () => {
		const parts: string[] = [];
		for (let i = 0, n = 1 + below(5); i < n; i++) parts.push(pick(NAMES));
		return parts.join('/');
	};
	// A path made from the glob, so that many of them match.
	const pathFrom = (text: string) =>
		text
			.replace(/\{([^}]*)\}/g, (_, body: string) => pick(body.split(',')))
			.replace(/\*\*\//g, () => (below(2) ? '' : `${pick(NAMES)}/`))
			.replace(/\*+/g, () => (below(2) ? '' : pick(['a', 'ab', 'é', '😀'])))
			.replace(/\?/g, () => pick(['a', 'é', '😀', '.']));
	return { glob, path, pathFrom };
}

// A changed file's name is never empty, and has no empty segment.
const isName = (path: string) =>
	path !== '' && !path.startsWith('/') && !path.endsWith('/') && !path.includes('//');

function starRuns(glob: string) {
	return [...glob.matchAll(/\*{2,}/g)].map((run) => {
		const start = run.index;
		const end = start + run[0].length;
		const whole =
			run[0].length === 2 &&
			(start === 0 || glob[start - 1] === '/') &&
			(end === glob.length || glob[end] === '/');
		return { length: run[0].length, end, whole };
	});
}

// `x**/**`: Bun.Glob loses the `/`.
const bunLosesASlash = (glob: string) =>
	starRuns(glob).some(
		(run) => !run.whole && run.length % 2 === 0 && glob.startsWith('/**', run.end),
	);

function expansions(glob: string): string[] {
	let out = [''];
	for (const part of glob.matchAll(/\{([^}]*)\}|[^{]+/g)) {
		const choices = part[1] !== undefined ? part[1].split(',') : [part[0]];
		out = out.flatMap((before) => choices.map((choice) => before + choice));
	}
	return out;
}

describe('the same results as Bun.Glob on the supported grammar', () => {
	const GLOBS = 30_000;

	const compare = async (
		seed: number,
		braces: boolean,
		compared: (glob: string) => ((path: string) => boolean) | undefined,
	) => {
		const { glob: makeGlob, path, pathFrom } = generator(seed);
		const work = free();
		const differences: string[] = [];
		let checked = 0;
		let matched = 0;
		for (let i = 0; i < GLOBS; i++) {
			const glob = makeGlob(braces);
			if (globProblem(glob) !== undefined) continue;
			const expected = compared(glob);
			if (expected === undefined) continue;
			const compiled = compileGlob(glob);
			for (const name of [path(), path(), pathFrom(glob), pathFrom(glob), pathFrom(glob)]) {
				if (!isName(name)) continue;
				const ours = await work.match(compiled, name);
				const theirs = expected(name);
				checked += 1;
				if (theirs) matched += 1;
				if (ours !== theirs) differences.push(`${glob} on ${name}: koi ${ours}, Bun ${theirs}`);
			}
		}
		expect(differences.slice(0, 20)).toEqual([]);
		// So the test cannot pass by comparing nothing, or only misses.
		expect(checked).toBeGreaterThan(GLOBS);
		expect(matched).toBeGreaterThan(checked / 10);
	};

	test('globs with no braces', async () => {
		await compare(1, false, (glob) => {
			if (bunLosesASlash(glob)) return undefined;
			const bun = new Bun.Glob(glob);
			return (path) => bun.match(path);
		});
	});

	test('globs with braces, where each `**` is a whole segment of the text', async () => {
		await compare(2, true, (glob) => {
			if (starRuns(glob).some((run) => !run.whole)) return undefined;
			const bun = new Bun.Glob(glob);
			return (path) => bun.match(path);
		});
	});

	// Any `**` here, touching a brace or not. Bun.Glob reads each expansion by itself, so
	// this says koi's braces are what they should be, even where Bun's text reading differs.
	test('globs with braces, against each expansion alone', async () => {
		await compare(3, true, (glob) => {
			const each = expansions(glob);
			// A `!` starting a choice is literal, and starting an expansion alone it negates.
			if (each.some((one) => bunLosesASlash(one) || one.startsWith('!'))) return undefined;
			const buns = each.map((one) => new Bun.Glob(one));
			return (path) => buns.some((bun) => bun.match(path));
		});
	});
});

describe('what a match costs', () => {
	const stepsOf = async (glob: string, path: string) => {
		const work = free();
		const compiled = compileGlob(glob);
		const answer = await work.match(compiled, path);
		return { answer, steps: work.steps, tokens: compiled.tokens.length, starts: compiled.starts };
	};

	// A step for each token at each path position, and one scan of the path per expansion.
	const bound = (tokens: number, expansions: number, name: string) =>
		tokens * (name.length + 1) + expansions * name.length + 4;

	const NAME = 'a'.repeat(GLOB_MAX_CHARS);
	const DEEP_NAME = Array.from({ length: GLOB_MAX_CHARS / 2 }, () => 'a').join('/');
	const GROUP = `{${Array.from({ length: 10 }, (_, i) => `${'a'.repeat(19)}${i}`).join(',')}}`;

	test.each<[string, string, string]>([
		['a star before a long literal', `*${'a'.repeat(GLOB_MAX_CHARS - 2)}b`, NAME],
		['a star before half a name of literal', `*${'a'.repeat(GLOB_MAX_CHARS / 2)}b`, NAME],
		['a star before each of many characters', `${'*a'.repeat(GLOB_MAX_CHARS / 2 - 1)}b`, NAME],
		['many stars, with one literal that fails', `${'*'.repeat(100)}b`, NAME],
		['a ** before many segments', `**/${'a/'.repeat(1000)}b`, DEEP_NAME],
		['a ** before segments with stars', `**/${'*a/'.repeat(500)}b`, DEEP_NAME],
		['many ** segments', `${'**/a/'.repeat(500)}b`, DEEP_NAME],
		['a ** and a star at the end', `**/*${'a'.repeat(1000)}b`, DEEP_NAME],
		['the expansions of three groups', `*${GROUP.repeat(3)}b`, NAME],
		['the same on segments', `**/*${GROUP.repeat(3)}b`, DEEP_NAME],
	])('%s stays within tokens times name length', async (_what, glob, name) => {
		const { answer, steps, tokens, starts } = await stepsOf(glob, name);
		expect(answer).toBe(false);
		expect(steps).toBeLessThanOrEqual(bound(tokens, starts.length, name));
	});

	test('any glob on any name stays within tokens times name length', async () => {
		const { glob: makeGlob, path } = generator(4);
		for (let i = 0; i < 3000; i++) {
			const glob = makeGlob(i % 2 === 0);
			if (globProblem(glob) !== undefined) continue;
			// Long names with short segments, so stars and `**` have much to retry.
			const name = Array.from({ length: 20 }, path).join('/');
			const { steps, tokens, starts } = await stepsOf(glob, name);
			expect(steps).toBeLessThanOrEqual(bound(tokens, starts.length, name));
		}
	});

	test('a run of the matcher between turns stays within its bound, however long the match', async () => {
		for (const [glob, name] of [
			[`*${'a'.repeat(GLOB_MAX_CHARS - 2)}b`, NAME],
			[`**/*${GROUP.repeat(3)}b`, DEEP_NAME],
		] as const) {
			const at: number[] = [];
			const work = new GlobWork({
				over: () => new Error('over budget'),
				budget: Number.MAX_SAFE_INTEGER,
				onTurn: () => at.push(work.steps),
			});
			const compiled = work.compile(glob);
			expect(await work.match(compiled, name)).toBe(false);
			expect(at.length).toBeGreaterThan(10);
			at.forEach((steps, i) => {
				// A scan for a `/` can pass the end of a turn, by at most one name.
				expect(steps - (at[i - 1] ?? 0)).toBeLessThanOrEqual(GLOB_TURN_STEPS + name.length);
			});
		}
	}, 30_000);

	test('the second input a reviewer built is refused, and what fits the limits is counted', async () => {
		// With a bracket, as it was built, the grammar refuses it.
		const bracketed = `{[a},${Array(9).fill('a'.repeat(20)).join(',')}}`;
		expect(globProblem(`**/*${bracketed.repeat(8)}b`)).toContain('[ is not supported');
		// Without one, it expands 100 million ways.
		const plain = `{${Array(10).fill('a'.repeat(20)).join(',')}}`;
		expect(globProblem(`**/*${plain.repeat(8)}b`)).toContain('expand more than 1024 ways');
		// As much of it as the limits allow took 8.66 seconds in one call of Bun's matcher.
		// Here its steps are counted, and each stretch between turns is short.
		const glob = `**/*${plain.repeat(3)}b`;
		expect(globProblem(glob)).toBeUndefined();
		const { answer, steps, tokens, starts } = await stepsOf(glob, NAME);
		expect(answer).toBe(false);
		expect(steps).toBeLessThanOrEqual(bound(tokens, starts.length, NAME));
		// One such match is a small part of what a plan may spend.
		expect(steps).toBeLessThan(GLOB_STEP_BUDGET / 10);
	}, 30_000);

	test('steps are the same on every run, so a budget refuses the same plan on every box', async () => {
		const once = async () => {
			const work = free();
			const compiled = work.compile(WORKSPACE);
			for (let i = 0; i < 2000; i++) {
				await work.match(compiled, `packages/web/src/feature-${i}/a.tsx`);
				await work.match(compiled, `other/place-${i}/a.py`);
			}
			return work.steps;
		};
		expect(await once()).toBe(await once());
	});

	test('over its budget, work stops with the error it was given', async () => {
		const compiled = compileGlob(`*${'a'.repeat(100)}b`);
		const over = new Error('over budget');
		const work = new GlobWork({ over: () => over, budget: 500 });
		// A short match finishes in the budget, and the long one does not, wherever it stops.
		expect(await work.match(compileGlob('a'), 'a')).toBe(true);
		let thrown: unknown;
		try {
			await work.match(compiled, 'a'.repeat(GLOB_MAX_CHARS));
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBe(over);
		expect(work.steps).toBeGreaterThan(500);
	});

	test('compiling counts too, so a project of globs that match nothing is not free', () => {
		const work = free();
		work.compile(WORKSPACE);
		expect(work.steps).toBeGreaterThan(compileGlob(WORKSPACE).starts.length);
		expect(work.steps).toBe(compileGlob(WORKSPACE).cost);
	});

	test('a group of one adds nothing to expand, however many there are', async () => {
		const glob = `${'{,}'.repeat(10)}${'{}'.repeat(2032)}x`;
		expect(globProblem(glob)).toBeUndefined();
		const compiled = compileGlob(glob);
		expect(compiled.starts.length).toBe(1024);
		expect(compiled.cost).toBeLessThan(glob.length + 30 * 1024);
		expect(await free().match(compiled, 'x')).toBe(true);
		expect(await free().match(compileGlob('a{}b{c}d{}'), 'abcd')).toBe(true);
	});

	test.each<[string, string]>([
		['a run of empty groups', `${'{,}'.repeat(10)}${'{}'.repeat(2032)}x`],
		['text between the groups', `${`${'a'.repeat(6)}{,}`.repeat(10)}`],
		['a single large group', `{${Array.from({ length: 1024 }, () => '').join(',')}}`],
		['a long name with no group', 'a'.repeat(GLOB_MAX_CHARS)],
	])('one compile stays within a turn: %s', (_name, glob) => {
		expect(globProblem(glob)).toBeUndefined();
		expect(compileGlob(glob).cost).toBeLessThan(GLOB_TURN_STEPS);
	});

	test('a search for a slash that finds none is counted', async () => {
		const name = 'a'.repeat(250);
		const { answer, steps } = await stepsOf('**/b', name);
		expect(answer).toBe(false);
		expect(steps).toBeGreaterThanOrEqual(name.length);
	});

	test('the event loop runs at each turn, and a match that falls due goes on where it was', async () => {
		let others = 0;
		const work = new GlobWork({
			over: () => new Error('over budget'),
			budget: Number.MAX_SAFE_INTEGER,
			onTurn: () => {
				setImmediate(() => {
					others += 1;
				});
			},
		});
		// The star has to reach nearly the end of the name, many times over a turn's steps.
		const glob = `*${'a'.repeat(2000)}b`;
		const answer = work.match(work.compile(glob), `${'a'.repeat(GLOB_MAX_CHARS - 1)}b`);
		expect(answer).toBeInstanceOf(Promise);
		expect(others).toBe(0);
		// The same answer as a match that nothing paused.
		expect(await answer).toBe(true);
		expect(others).toBeGreaterThan(0);
	});

	test('a match that nothing paused answers with no promise', () => {
		const work = free();
		expect(work.match(compileGlob('**/*.ts'), 'a/b.ts')).toBe(true);
		expect(work.match(compileGlob('**/*.ts'), 'a/b.py')).toBe(false);
	});
});
