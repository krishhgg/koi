import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// The repository's recipes/ directory, which scripts/deploy-host.sh installs
// on the box for the daemon.
export const RECIPES_DIR = join(import.meta.dir, '../../../recipes');

// The recipe.json of every directory in `dir`, parsed but not validated, in
// the order of the directory names. Files beside the directories, such as a
// README, are skipped. A directory without a recipe.json is an error: the
// daemon would refuse a request that named it.
export function readRecipeFiles(dir: string): unknown[] {
	const names = readdirSync(dir, { withFileTypes: true })
		.filter((entry) => entry.isDirectory())
		.map((entry) => entry.name)
		.sort();
	return names.map((name) => {
		const file = join(dir, name, 'recipe.json');
		let text: string;
		try {
			text = readFileSync(file, 'utf8');
		} catch (err) {
			throw new Error(`recipes/${name} has no readable recipe.json: ${String(err)}`);
		}
		return JSON.parse(text) as unknown;
	});
}

// builtins.ts imports this as a Bun macro, so it runs when Bun transpiles
// builtins.ts: at bundle time for `bun build --compile`, and at load time for
// `bun run` and `bun test`. Bun writes the returned list into the code in
// place of the call, so the compiled koi binary carries every recipe and
// reads no recipes/ directory at run time.
export function builtinRecipeFiles(): unknown[] {
	return readRecipeFiles(RECIPES_DIR);
}
