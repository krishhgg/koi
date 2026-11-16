import {
	MAX_PROJECT_NAME,
	PROJECT_NAME,
	type Recipe,
	type RepoRecipe,
	RepoRecipeSchema,
	repoMatches,
	slugify,
	type UpRequest,
} from '@koi/shared';

export interface ResolvedRecipe {
	project: string;
	recipe: UpRequest['recipe'];
	// How long koid lets the build, and then the health check, take.
	limits: Pick<Recipe, 'buildTimeoutMinutes' | 'healthTimeoutSeconds'>;
}

// In the order tried: a file at the root wins over one under .koi/.
const REPO_RECIPE_FILES = [
	'koi.yaml',
	'koi.yml',
	'koi.json',
	'.koi/koi.yaml',
	'.koi/koi.yml',
	'.koi/koi.json',
];

// Picks the recipe for a repo: a built-in one whose match list names the repo
// (or its forks, with a `*` owner), otherwise a koi.yaml (or .yml/.json) at the
// root of the source being built, or under its .koi/ directory. The project
// prefix comes from the built-in recipe's name (projectForBuiltin) or from the
// repo's own name, never from the file, which the pull request controls.
export async function resolveRecipe(
	repoId: string,
	builtins: Recipe[],
	read: (path: string) => Promise<string | undefined>,
): Promise<ResolvedRecipe> {
	const builtin = builtins.find((r) => r.match.repos.some((p) => repoMatches(p, repoId)));
	if (builtin !== undefined) {
		return {
			project: projectForBuiltin(builtin, repoId),
			recipe: { kind: 'builtin', name: builtin.name },
			limits: limitsOf(builtin),
		};
	}
	for (const file of REPO_RECIPE_FILES) {
		const text = await read(file);
		if (text === undefined) continue;
		const data: unknown = file.endsWith('.json') ? JSON.parse(text) : Bun.YAML.parse(text);
		const parsed = RepoRecipeSchema.safeParse(data);
		if (!parsed.success) {
			throw new Error(
				`${file} is not a valid koi recipe: ${parsed.error.issues.map(describe).join('; ')}`,
			);
		}
		const recipe: RepoRecipe = parsed.data;
		return {
			project: projectFromRepo(repoId),
			recipe: { kind: 'repo', recipe },
			limits: limitsOf(recipe),
		};
	}
	throw new Error(
		`koi has no recipe for ${repoId}. Add a koi.yaml at the repo root, for example:\n\n  port: 8080\n  build:\n    kind: dockerfile\n    path: Dockerfile\n`,
	);
}

// The project name for a repo a built-in recipe matched. A repo the match list
// names exactly gets the recipe's name, so every label the main repository
// has today stays the same. A repo matched only through a `*` entry, a fork,
// gets "<name>-<owner>". A fork's branches and pull request numbers are its
// own, its develop is not upstream's develop and its PR 12 is not upstream's
// PR 12, yet under the plain name both would get the same label, and the
// daemon would refuse the second preview as belonging to another repo. The
// owner is the second segment of the repo id (github.com/<owner>/<name>),
// slugified and cut so the whole name is still a PROJECT_NAME, which
// previewHostLabel fits with any branch. Two forks whose owners differ only
// past the cut, or only in dots and underscores, get the same name; the
// daemon's ownership check keeps their previews apart, as it does today for
// two koi.yaml repos with the same name.
export function projectForBuiltin(recipe: Recipe, repoId: string): string {
	if (recipe.match.repos.includes(repoId)) return recipe.name;
	const owner = repoId.split('/')[1] ?? '';
	const room = MAX_PROJECT_NAME - recipe.name.length - 1;
	const slug = room > 0 ? slugify(owner).slice(0, room).replace(/-+$/g, '') : '';
	const project = `${recipe.name}-${slug}`;
	if (!PROJECT_NAME.test(project)) {
		throw new Error(`cannot make a project name for ${repoId} from recipe ${recipe.name}`);
	}
	return project;
}

function limitsOf(recipe: Recipe | RepoRecipe): ResolvedRecipe['limits'] {
	return {
		buildTimeoutMinutes: recipe.buildTimeoutMinutes,
		healthTimeoutSeconds: recipe.healthTimeoutSeconds,
	};
}

function describe(issue: { path: PropertyKey[]; message: string }): string {
	return issue.path.length > 0 ? `${issue.path.join('.')}: ${issue.message}` : issue.message;
}

// github.com/acme/My_App -> my-app, cut to a project name's 31 characters.
export function projectFromRepo(repoId: string): string {
	const name = repoId.split('/').at(-1) ?? '';
	const project = name
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '')
		.slice(0, MAX_PROJECT_NAME)
		.replace(/-+$/g, '');
	if (!PROJECT_NAME.test(project)) {
		throw new Error(`cannot make a project name from ${repoId}`);
	}
	return project;
}
