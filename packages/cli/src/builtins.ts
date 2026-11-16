import { type Recipe, RecipeSchema } from '@koi/shared';
import { builtinRecipeFiles } from './recipe-files.ts' with { type: 'macro' };

// The built-in recipes the CLI can match by repo: the recipe.json of every
// directory in recipes/, the same files the daemon reads on the box. The
// macro reads them when the CLI is built (see recipe-files.ts), so a new
// recipe needs only its directory. A test checks the two lists agree.
const RAW: unknown[] = builtinRecipeFiles();

export const BUILTIN_RECIPES: Recipe[] = RAW.map((r) => RecipeSchema.parse(r));
