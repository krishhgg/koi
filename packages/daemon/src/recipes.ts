import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ProjectNameSchema, type Recipe, RecipeSchema } from '@koi/shared';

export interface LoadedRecipe {
	recipe: Recipe;
	// The recipe's directory on the box; a Dockerfile with from: "recipe" is
	// resolved inside it.
	dir: string;
}

// Built-in recipes are installed on the box with the daemon, in
// <recipesDir>/<name>/recipe.json. The request names one; the daemon reads its
// own copy, so a request cannot supply a trusted recipe's contents.
export async function loadBuiltinRecipe(recipesDir: string, name: string): Promise<LoadedRecipe> {
	const dir = join(recipesDir, ProjectNameSchema.parse(name));
	try {
		return { recipe: await readRecipe(dir, name), dir };
	} catch (err) {
		if (isNotFound(err)) throw new Error(`no built-in recipe named ${name}`);
		throw err;
	}
}

// Reads the recipe.json in `dir`, which must name the recipe `name`: the
// installed directory of a built-in recipe, or the copy of it a build makes
// (deployer.ts), whose settings the build follows.
export async function readRecipe(dir: string, name: string): Promise<Recipe> {
	const recipe = RecipeSchema.parse(JSON.parse(await readFile(join(dir, 'recipe.json'), 'utf8')));
	if (recipe.name !== name) {
		throw new Error(`recipe in ${dir} is named ${recipe.name}, not ${name}`);
	}
	return recipe;
}

// No directory or no file: no such recipe. Any other failure to read it says
// what went wrong.
function isNotFound(err: unknown): boolean {
	return (
		typeof err === 'object' &&
		err !== null &&
		'code' in err &&
		(err.code === 'ENOENT' || err.code === 'ENOTDIR')
	);
}
