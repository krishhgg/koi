import { types } from 'node:util';
import { z } from 'zod';
import { RelativePathSchema } from './paths.ts';

// A recipe tells koi how to turn a source tree into a running preview. Built-in
// recipes live in recipes/<name>/ in this repo, are installed on the box with
// the daemon, and are matched by the source repo's git remote. A koi.yaml at a
// repo root can describe a project koi has no recipe for. The two are parsed
// with different schemas because only the first is trusted.
//
// Every build is a Dockerfile build. Nothing from the source tree ever runs on
// the host: RUN steps execute inside BuildKit, and the result runs as a
// confined container.

// A project name: lowercase letters and digits in words joined by single
// dashes, at most MAX_PROJECT_NAME characters. Canonical, so it is its own
// slug and two names never share labels (hello-world and hello--world would).
// The limit is written into the pattern too, since a regex literal cannot
// read a constant; a test checks the two agree.
export const MAX_PROJECT_NAME = 31;
export const PROJECT_NAME = /^(?=.{1,31}$)[a-z0-9]+(?:-[a-z0-9]+)*$/;

export const ProjectNameSchema = z
	.string()
	.max(MAX_PROJECT_NAME)
	.regex(PROJECT_NAME, '1 to 31 lowercase letters and digits in dash-separated words');

export const DockerfileBuildSchema = z.object({
	kind: z.literal('dockerfile'),
	// Where the Dockerfile lives. "source": in the source tree, at `path`
	// relative to its root. "recipe": shipped with a built-in recipe, at `path`
	// relative to the recipe's directory on the box. The build context is
	// always inside the source tree.
	from: z.enum(['source', 'recipe']).default('source'),
	path: RelativePathSchema.default('Dockerfile'),
	context: RelativePathSchema.default('.'),
});

export type DockerfileBuild = z.infer<typeof DockerfileBuildSchema>;

// Environment variable names a recipe may set on the preview container. KOI_
// is reserved for values the daemon sets itself.
export const EnvNameSchema = z
	.string()
	.regex(/^[A-Z_][A-Z0-9_]{0,63}$/, 'uppercase letters, digits and underscores')
	.refine((name) => !name.startsWith('KOI_'), 'KOI_ is reserved');

// Linux ids are 32 bits wide and 4294967295 means "no id".
const MAX_ID = 4_294_967_294;

// "<uid>" or "<uid>:<gid>" in digits, as "<uid>:<gid>" with the gid defaulting
// to the uid; undefined for names, root in any spelling ("0", "00", "000:5"),
// or anything else. The ids are compared as numbers, never as text. Numeric so
// that the result means the same thing whatever /etc/passwd an image ships: an
// image can define a user called "app" with uid 0.
export function numericUser(user: string): string | undefined {
	const match = /^([0-9]{1,10})(?::([0-9]{1,10}))?$/.exec(user);
	if (match?.[1] === undefined) return undefined;
	const uid = Number(match[1]);
	const gid = match[2] === undefined ? uid : Number(match[2]);
	if (uid === 0 || uid > MAX_ID || gid > MAX_ID) return undefined;
	return `${uid}:${gid}`;
}

// A numeric uid, optionally with a gid, never root, normalised to "<uid>:<gid>".
// Only the uid decides root: gid 0 is allowed.
export const ContainerUserSchema = z.string().transform((user, ctx) => {
	const normal = numericUser(user);
	if (normal === undefined) {
		ctx.addIssue({
			code: 'custom',
			message: 'a numeric uid or uid:gid, with a uid other than 0',
		});
		return z.NEVER;
	}
	return normal;
});

// The longest a recipe may let a build, and then a health check, take.
export const MAX_BUILD_TIMEOUT_MINUTES = 180;
export const MAX_HEALTH_TIMEOUT_SECONDS = 1800;

const runtimeFields = {
	// Port the preview container listens on.
	port: z.number().int().min(1).max(65535),
	healthPath: z.string().startsWith('/').default('/'),
	env: z.record(EnvNameSchema, z.string().max(4096)).default({}),
	// Run as this user instead of the image's. When neither names a non-root
	// user the daemon runs the container as nobody (65534).
	user: ContainerUserSchema.optional(),
	ttlDays: z.number().int().positive().max(90).default(7),
	// The environment variable that carries the preview's login key, for an
	// app with a sign-in that reads the key it accepts from its environment.
	// The daemon generates one random key per preview, keeps it across
	// redeploys, and koi up prints it.
	loginKeyEnv: EnvNameSchema.optional(),
	buildTimeoutMinutes: z.number().int().positive().max(MAX_BUILD_TIMEOUT_MINUTES).default(45),
	healthTimeoutSeconds: z.number().int().positive().max(MAX_HEALTH_TIMEOUT_SECONDS).default(180),
};

// The most a recipe's `slice` may take, as JSON in UTF-8.
export const MAX_RECIPE_SLICE_BYTES = 64 * 1024;

// The most a deployment's slice may take, as JSON in UTF-8: what a recipe's
// sliceFile says the build kept. koi up reads it back through koid ctl
// status, whose reply has to stay under SSM's 24,000 characters with the
// record beside it (packages/daemon/src/control.ts).
export const MAX_DEPLOYMENT_SLICE_BYTES = 16 * 1024;

// The most of a sliceFile koid reads from the image before it parses it.
// Above MAX_DEPLOYMENT_SLICE_BYTES so that the file may be indented.
export const MAX_SLICE_FILE_BYTES = 64 * 1024;

// What a preview keeps of the project, for a recipe whose Dockerfile cuts the
// build down to the pull request's change. The recipe owns the shape. Its own
// build scripts read the field from the recipe.json in the "recipe" build
// context, and koi never reads it. koi checks only that it is a JSON object of
// at most MAX_RECIPE_SLICE_BYTES, and keeps the object it was given, every key
// included. A record schema would drop an own `__proto__` key, which
// JSON.parse makes, before the size check saw it.
export const RecipeSliceSchema = jsonObjectSchema(MAX_RECIPE_SLICE_BYTES);

// What a deployment's build kept of the project, as the recipe's build wrote
// it to its sliceFile: the recipe owns the shape, as it owns `slice`. koid
// reads it from the image once the build is done, keeps it on the
// deployment, and koi up --json returns it as `slice`. koi checks only that
// it is a JSON object of at most MAX_DEPLOYMENT_SLICE_BYTES. The build that
// wrote it ran the pull request's code, so it says what the recipe's scripts
// reported, not what koi saw.
export const DeploymentSliceSchema = jsonObjectSchema(MAX_DEPLOYMENT_SLICE_BYTES);

// A JSON object of at most `max` bytes as JSON, kept as given.
function jsonObjectSchema(max: number) {
	return z
		.custom<Record<string, unknown>>(isPlainObject, 'a JSON object')
		.superRefine((value, ctx) => {
			const bytes = parsedJsonBytes(value, max);
			if (bytes === undefined) {
				ctx.addIssue({
					code: 'custom',
					message: 'only strings, finite numbers, booleans, null, arrays and objects',
				});
			} else if (bytes > max) {
				ctx.addIssue({ code: 'custom', message: `at most ${max} bytes as JSON` });
			}
		});
}

// An absolute path in a built image, such as /opt/app/koi-slice.json: letters,
// digits, dots, dashes and underscores in segments joined by single slashes,
// with no . or .. segment. koid passes it to docker cp as one argument.
export const ImagePathSchema = z
	.string()
	.max(255)
	.regex(
		/^(?:\/[A-Za-z0-9._-]+)+$/,
		'an absolute path of letters, digits, dots, dashes and underscores',
	)
	.refine((p) => !p.split('/').some((s) => s === '.' || s === '..'), 'no . or .. segments');

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
}

const ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/;
const utf8 = new TextEncoder();

// The size in UTF-8 of a string or number as JSON. JSON.stringify of a
// primitive reads no property of it, so nothing on the input runs.
function primitiveBytes(value: string | number): number {
	return utf8.encode(JSON.stringify(value)).length;
}

// The size in UTF-8 of `value` as JSON.stringify writes it, when `value` is
// something JSON.parse could have made, and undefined when it is not. That
// means plain objects and arrays, without holes, of strings, finite numbers,
// booleans and null, each object reached once, with only enumerable data
// properties under string keys. It stops counting once the size passes
// `max` (MAX_RECIPE_SLICE_BYTES unless given) and returns the count so far.
//
// It counts while it walks, with a stack rather than recursion, and never
// passes an object to JSON.stringify. So no toJSON, getter or iterator on the
// input runs, no input can hang it or overflow the call stack, and a deep
// nest that JSON.parse accepts is measured even where JSON.stringify would
// overflow.
//
// It does not try to cover a Proxy, built-in prototypes changed by other
// code, or exotic objects built in memory (a Map given Object.prototype).
// Slices come from JSON.parse of a recipe.json or a sliceFile. A number too large for a
// double, which JSON.parse reads as Infinity, is refused, since JSON.stringify
// would write it back as null.
export function parsedJsonBytes(
	value: unknown,
	max: number = MAX_RECIPE_SLICE_BYTES,
): number | undefined {
	const seen = new Set<object>();
	const stack: unknown[] = [value];
	let bytes = 0;
	while (stack.length > 0) {
		if (bytes > max) return bytes;
		const v = stack.pop();
		if (v === null || v === true) {
			bytes += 4;
			continue;
		}
		if (v === false) {
			bytes += 5;
			continue;
		}
		if (typeof v === 'string') {
			bytes += primitiveBytes(v);
			continue;
		}
		if (typeof v === 'number') {
			if (!Number.isFinite(v)) return undefined;
			bytes += primitiveBytes(v);
			continue;
		}
		if (typeof v !== 'object' || seen.has(v)) return undefined;
		seen.add(v);
		const array = Array.isArray(v);
		const proto = Object.getPrototypeOf(v);
		if (array ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) {
			return undefined;
		}
		// A boxed primitive (new Boolean(false), Object(Symbol())) given
		// Object.prototype has no own keys, yet it is not a plain object.
		// isBoxedPrimitive reads the internal slot, so nothing on it runs.
		if (types.isBoxedPrimitive(v)) return undefined;
		const keys = Reflect.ownKeys(v);
		// Each key takes at least a byte, so this many could never fit.
		if (keys.length > max) return max + 1;
		const length = array ? (v as unknown[]).length : 0;
		let items = 0;
		for (const key of keys) {
			if (typeof key === 'symbol') return undefined;
			if (array && key === 'length') continue;
			if (array && !(ARRAY_INDEX.test(key) && Number(key) < length)) return undefined;
			const d = Object.getOwnPropertyDescriptor(v, key);
			if (d === undefined || !('value' in d) || !d.enumerable) return undefined;
			// An object writes "key": before each value.
			if (!array) bytes += primitiveBytes(key) + 1;
			stack.push(d.value);
			items += 1;
		}
		if (array && items !== length) return undefined;
		// The brackets, and a comma between items.
		bytes += 2 + Math.max(items - 1, 0);
	}
	return bytes;
}

// A repo a built-in recipe matches, in the host/owner/name form that
// repoIdFromRemote gives a git remote (lowercase, see RepoIdSchema). A segment
// may be `*`, which stands for any one segment: github.com/*/storefront is
// every fork of storefront on GitHub. Forks are matched because
// contributors push from forks, and their pull requests should get the same
// recipe as a branch of the main repository. A `*` is a whole segment, so it
// never reaches across a slash and never matches part of a name.
export const REPO_PATTERN = /^(?:\*|[a-z0-9.-]+)\/(?:\*|[a-z0-9._-]+)\/(?:\*|[a-z0-9._-]+)$/;

export const RepoPatternSchema = z
	.string()
	.regex(REPO_PATTERN, 'host/owner/name in lowercase, with * for a whole segment');

// Whether a repo id (host/owner/name, lowercase) is one the pattern names.
export function repoMatches(pattern: string, repoId: string): boolean {
	const want = pattern.split('/');
	const have = repoId.split('/');
	if (want.length !== have.length) return false;
	return want.every((segment, i) => {
		const actual = have[i] ?? '';
		return segment === '*' ? actual !== '' : segment === actual;
	});
}

// Built-in recipes in recipes/<name>/recipe.json. Reviewed and shipped with
// koi, so they may bring their own Dockerfile.
export const RecipeSchema = z.object({
	name: ProjectNameSchema,
	match: z
		.object({
			// Repos that select this recipe, each a RepoPatternSchema: the
			// repo itself, and github.com/*/<name> for its forks.
			repos: z.array(RepoPatternSchema).default([]),
		})
		.default({ repos: [] }),
	...runtimeFields,
	slice: RecipeSliceSchema.optional(),
	// Where the recipe's build writes what it kept of the project, in the
	// image: a JSON object of the recipe's own shape (DeploymentSliceSchema).
	// koid reads it after the build, before the container starts, and fails
	// the build when it is missing or not such an object. A recipe with one
	// takes koi up --keep (UpRequestSchema).
	sliceFile: ImagePathSchema.optional(),
	build: DockerfileBuildSchema,
});

export type Recipe = z.infer<typeof RecipeSchema>;

// A koi.yaml found in the source tree. It comes from the pull request, so it
// may only point at a Dockerfile inside that tree, and it has no name: the
// project prefix of a preview's label comes from the repo itself, never from a
// file the pull request controls.
export const RepoRecipeSchema = z.object({
	...runtimeFields,
	build: DockerfileBuildSchema.extend({
		from: z.literal('source').default('source'),
	}),
});

export type RepoRecipe = z.infer<typeof RepoRecipeSchema>;
