// koi's own matcher for `select.paths` and the manifest's point globs. A pull request
// chooses the globs and the file names, and koid matches them on its one event loop. koid
// cannot see the cost of a third-party matcher or stop one partway, so this one counts its
// steps and can pause at any step. docs/verify.md has the grammar ("Globs") and the numbers
// ("Planning limits").

// A real glob is under 200 characters. An exact path is a glob too, so as long as a
// changed file's name may be.
export const GLOB_MAX_CHARS = 4096;
// The workspace selector in docs/verify.md, a large real one, has 120 expansions.
export const GLOB_MAX_EXPANSIONS = 1024;
// The same selector comes to 2,386 characters. This also bounds what one compiled glob
// holds in memory and what compiling it takes, about 0.5 milliseconds at the limit.
export const GLOB_MAX_EXPANDED_CHARS = 65_536;
// What one plan may spend. "Planning limits" has the measurements behind it.
export const GLOB_STEP_BUDGET = 4_000_000_000;
// How many steps run before the rest of koid gets a turn: under 2 milliseconds.
export const GLOB_TURN_STEPS = 256 * 1024;
// What starting a match costs next to one trip round the loop. A plan is mostly matches
// that end on their first character, and this is most of their time.
const MATCH_STEPS = 4;
// What compiling costs next to one trip round the loop, for each token it writes.
const COMPILE_STEPS = 2;

const GRAMMAR =
	'a glob holds literal characters, *, ** as a whole path segment, ? and {a,b} groups';

// The text between groups, and each group's choices, in order. Text outside a group is
// a list of one. Or what is wrong with the glob.
function parse(glob: string): string[][] | string {
	if (glob.length > GLOB_MAX_CHARS) return `must be at most ${GLOB_MAX_CHARS} characters`;
	if (glob.startsWith('!'))
		return `a leading ! is not supported, as a glob cannot negate; ${GRAMMAR}`;
	const pieces: string[][] = [];
	// Text and a group of one add no way to expand, so each joins the text before it.
	// Otherwise thousands of `{}` would each make compiling walk every expansion so far.
	const add = (choices: string[]): void => {
		const last = pieces.at(-1);
		if (choices.length === 1 && last?.length === 1) last[0] = `${last[0]}${choices[0]}`;
		else pieces.push(choices);
	};
	let group: string[] | undefined;
	let start = 0;
	for (let i = 0; i < glob.length; i++) {
		const char = glob[i];
		if (char === '\\') return `\\ is not supported, as a glob has no escape; ${GRAMMAR}`;
		if (char === '[' || char === ']') {
			return `${char} is not supported; list the choices as {a,b,c} instead; ${GRAMMAR}`;
		}
		if (char === '{') {
			if (group !== undefined) {
				return `a group inside a group is not supported; write {a{b,c},d} as {ab,ac,d}; ${GRAMMAR}`;
			}
			add([glob.slice(start, i)]);
			group = [];
			start = i + 1;
		} else if (char === ',' && group !== undefined) {
			group.push(glob.slice(start, i));
			start = i + 1;
		} else if (char === '}') {
			if (group === undefined) return `has a } with no { before it; ${GRAMMAR}`;
			group.push(glob.slice(start, i));
			add(group);
			group = undefined;
			start = i + 1;
		}
	}
	if (group !== undefined) return `has a { with no } after it; ${GRAMMAR}`;
	add([glob.slice(start)]);

	// Counted without writing them out, so a glob over a limit costs only this walk.
	let expansions = 1;
	let chars = 0;
	for (const piece of pieces) {
		const pieceChars = piece.reduce((sum, choice) => sum + choice.length, 0);
		chars = chars * piece.length + pieceChars * expansions;
		expansions *= piece.length;
		if (expansions > GLOB_MAX_EXPANSIONS) {
			return `its braces expand more than ${GLOB_MAX_EXPANSIONS} ways`;
		}
		if (chars > GLOB_MAX_EXPANDED_CHARS) {
			return `its braces expand to more than ${GLOB_MAX_EXPANDED_CHARS} characters`;
		}
	}
	return pieces;
}

// What is wrong with a glob, or undefined. The schemas call this, so a glob koi cannot
// match never loads.
export function globProblem(glob: string): string | undefined {
	const parsed = parse(glob);
	return typeof parsed === 'string' ? parsed : undefined;
}

const SLASH = 47;
const STAR_UNIT = 42;
const QUESTION_UNIT = 63;

// A token is a literal's UTF-16 unit, so zero or more, or one of these.
const ANY = -1; // ?
const STAR = -2; // *
const DEEP = -3; // **/, zero or more whole segments
const REST = -4; // a ** that ends the glob, all that is left, slashes too
const END = -5;

// Every expansion's tokens in one array, each closed by END, and where each starts.
export interface CompiledGlob {
	readonly tokens: Int32Array;
	readonly starts: Int32Array;
	// The steps compiling it took, so a plan of globs that match nothing is not free.
	readonly cost: number;
}

// Braces expand first, and each expansion then reads as a glob of its own. So whether a
// `**` is a whole segment depends on the expansion, wherever the braces were. Stars that
// do not make a whole segment read as one star, as they do in Bun.Glob.
function tokenize(expansion: string, tokens: number[]): void {
	let i = 0;
	while (i < expansion.length) {
		const unit = expansion.charCodeAt(i);
		if (unit !== STAR_UNIT) {
			tokens.push(unit === QUESTION_UNIT ? ANY : unit);
			i += 1;
			continue;
		}
		let end = i + 1;
		while (expansion.charCodeAt(end) === STAR_UNIT) end += 1;
		const whole = end - i === 2 && (i === 0 || expansion.charCodeAt(i - 1) === SLASH);
		if (whole && end === expansion.length) {
			tokens.push(REST);
			i = end;
		} else if (whole && expansion.charCodeAt(end) === SLASH) {
			tokens.push(DEEP);
			i = end + 1;
		} else {
			tokens.push(STAR);
			i = end;
		}
	}
	tokens.push(END);
}

// Throws on a glob the schemas would refuse, which loaded files cannot hold.
export function compileGlob(glob: string): CompiledGlob {
	const pieces = parse(glob);
	if (typeof pieces === 'string') throw new Error(`glob ${glob}: ${pieces}`);
	// Each character read, each string built, and each character of each expansion. The
	// limits in parse keep the total under one turn.
	let cost = glob.length;
	let expansions = [''];
	for (const piece of pieces) {
		expansions = expansions.flatMap((before) => piece.map((choice) => before + choice));
		cost += expansions.length;
	}
	const tokens: number[] = [];
	const starts = new Int32Array(expansions.length);
	for (const [i, expansion] of expansions.entries()) {
		starts[i] = tokens.length;
		tokenize(expansion, tokens);
		cost += expansion.length;
	}
	cost += tokens.length * COMPILE_STEPS;
	return { tokens: Int32Array.from(tokens), starts, cost };
}

// Where one match has got to. It lives outside the loop so the loop can stop at any step
// and go on after koid's other work has had a turn.
interface Cursor {
	expansion: number;
	glob: number;
	path: number;
	// The token after the last `*` in this segment, and how far along the path it has
	// tried to end. -1 when there is none.
	starGlob: number;
	starPath: number;
	// The same for the last `**/`, which retries from each later segment.
	deepGlob: number;
	deepPath: number;
	answer: boolean | undefined;
}

// How many UTF-16 units the character at `at` takes, as `?` and `*` count characters.
function unitsAt(path: string, at: number): number {
	const unit = path.charCodeAt(at);
	if (unit < 0xd800 || unit > 0xdbff) return 1;
	const next = path.charCodeAt(at + 1);
	return next >= 0xdc00 && next <= 0xdfff ? 2 : 1;
}

// Runs a match for at most about `quota` steps and returns how many it took, setting
// `answer` if it finished. A step is one trip round the loop, and a scan for a `/` counts
// each character it passes, which can run past `quota` by at most one name's length.
//
// Within one expansion this never visits a pair of token and path position twice, so it
// takes at most tokens times path length steps, plus one scan of the path:
// - A `*` only ever retries from further along, and a later `*` replaces it. The earlier
//   one cannot do better, since what lies between them has already matched.
// - A `/` that matches forgets the `*`. A `*` cannot cross a `/`, so every way of matching
//   the segment reaches this same pair.
// - A `**/` only ever retries from a later segment, and a later `**/` replaces it. The
//   earlier one cannot do better, since the later one can skip anything it could.
function advance(glob: CompiledGlob, path: string, at: Cursor, quota: number): number {
	const { tokens, starts } = glob;
	const length = path.length;
	let { expansion, glob: g, path: p, starGlob, starPath, deepGlob, deepPath } = at;
	let steps = 0;
	while (steps < quota) {
		steps += 1;
		const token = tokens[g] as number;
		if (token >= 0) {
			if (path.charCodeAt(p) === token) {
				g += 1;
				p += 1;
				if (token === SLASH) starGlob = -1;
				continue;
			}
		} else if (token === STAR) {
			g += 1;
			starGlob = g;
			starPath = p;
			continue;
		} else if (token === ANY) {
			if (p < length && path.charCodeAt(p) !== SLASH) {
				g += 1;
				p += unitsAt(path, p);
				continue;
			}
		} else if (token === DEEP) {
			g += 1;
			deepGlob = g;
			deepPath = p;
			continue;
		} else if (token === REST || p === length) {
			at.answer = true;
			return steps;
		}

		// No match here. Let the `*` take one more character, or the `**/` skip one more
		// segment, or go to the next expansion.
		if (starGlob >= 0 && starPath < length && path.charCodeAt(starPath) !== SLASH) {
			starPath += unitsAt(path, starPath);
			g = starGlob;
			p = starPath;
			continue;
		}
		starGlob = -1;
		if (deepGlob >= 0) {
			const slash = path.indexOf('/', deepPath);
			if (slash >= 0) {
				steps += slash - deepPath;
				deepPath = slash + 1;
				g = deepGlob;
				p = deepPath;
				continue;
			}
			// A search that finds no `/` read the rest of the name too.
			steps += length - deepPath;
		}
		expansion += 1;
		if (expansion === starts.length) {
			at.answer = false;
			return steps;
		}
		g = starts[expansion] as number;
		p = 0;
		deepGlob = -1;
	}
	at.expansion = expansion;
	at.glob = g;
	at.path = p;
	at.starGlob = starGlob;
	at.starPath = starPath;
	at.deepGlob = deepGlob;
	at.deepPath = deepPath;
	at.answer = undefined;
	return steps;
}

export interface GlobWorkOptions {
	// The error to stop with once the work has spent more than its budget.
	over: (budget: number) => Error;
	// A test sets these. The budget is otherwise GLOB_STEP_BUDGET, the same on every box.
	budget?: number | undefined;
	// Runs each time matching gives the rest of koid a turn.
	onTurn?: (() => void) | undefined;
}

// All the matching one plan does, or one load of a project's files. It counts steps and
// never looks at a clock, so what it allows does not depend on how fast the box is.
export class GlobWork {
	steps = 0;
	private turnLeft = GLOB_TURN_STEPS;
	private readonly budget: number;
	private readonly at: Cursor = {
		expansion: 0,
		glob: 0,
		path: 0,
		starGlob: -1,
		starPath: 0,
		deepGlob: -1,
		deepPath: 0,
		answer: undefined,
	};

	constructor(private readonly options: GlobWorkOptions) {
		this.budget = options.budget ?? GLOB_STEP_BUDGET;
	}

	compile(glob: string): CompiledGlob {
		const compiled = compileGlob(glob);
		this.spend(compiled.cost);
		return compiled;
	}

	// Whether the glob matches the path. A promise only when a turn fell due, so a loop
	// awaits only then: an await on every match would cost more than the match.
	match(glob: CompiledGlob, path: string): boolean | Promise<boolean> {
		const at = this.at;
		at.expansion = 0;
		at.glob = 0;
		at.path = 0;
		at.starGlob = -1;
		at.deepGlob = -1;
		this.spend(MATCH_STEPS);
		const used = advance(glob, path, at, this.turnLeft);
		this.spend(used);
		return at.answer ?? this.finish(glob, path);
	}

	private async finish(glob: CompiledGlob, path: string): Promise<boolean> {
		for (;;) {
			this.options.onTurn?.();
			await new Promise((resolve) => setImmediate(resolve));
			this.turnLeft = GLOB_TURN_STEPS;
			const used = advance(glob, path, this.at, this.turnLeft);
			this.spend(used);
			if (this.at.answer !== undefined) return this.at.answer;
		}
	}

	private spend(steps: number): void {
		this.steps += steps;
		this.turnLeft -= steps;
		if (this.steps > this.budget) throw this.options.over(this.budget);
	}
}
