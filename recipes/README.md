# Built-in recipes

One directory per recipe: `recipes/<name>/recipe.json`, plus a `Dockerfile`
when the recipe brings its own (`"build": {"kind": "dockerfile", "from": "recipe"}`).
`scripts/deploy-host.sh` installs this directory on the box at
`/usr/local/share/koi/recipes`, where the daemon reads it. Requests only name a
recipe; its contents always come from here. `match.repos` lists the repositories a
recipe applies to as `host/owner/name`, with `*` for a whole segment; a repository
matched only through a `*` entry, a fork, gets the project name `<name>-<owner>` so
its previews never share a label with the main repository's.

A recipe's Dockerfile runs pull request code, so it must not give that code a cache
another pull request's build also sees: no writable `--mount=type=cache` and no writable
bind mounts (a test in `packages/daemon/test/recipes.test.ts` checks). Fetch anything
worth caching in a stage that copies nothing from the pull request, check it against a
published digest, and mount it read-only in the stage that builds the pull request.

Adding a recipe takes only its directory. The CLI reads every `recipes/*/recipe.json`
when it is built (`packages/cli/src/recipe-files.ts`, run as a Bun macro), so the
compiled `koi` binary carries them all, and a test checks that its list matches this
directory.

A recipe may keep data of its own for its build scripts under `slice` in `recipe.json`,
such as what a preview keeps of the project. koi never reads it and checks only that it
is a JSON object of at most 64 KiB. The Dockerfile gets the file with
`COPY --from=recipe recipe.json`.

A recipe that cuts the build down can report what it kept: `sliceFile` in `recipe.json`
names an absolute path in the image, such as `/opt/app/koi-slice.json`, where the build
writes a JSON object of at most 16 KiB, in a shape the recipe defines. koid reads it
from the built image before the container starts, fails the build when it is missing
or not such an object, and `koi up --json` returns it as `slice`. Such a recipe also
takes `koi up --keep NAME`: the build gets the names as the build argument `KOI_KEEP`,
joined by single spaces. Declare it with `ARG KOI_KEEP` in the stage that reads it, and
read it from the environment (a RUN step sees it as `$KOI_KEEP`); the names hold only
letters, digits, dots, dashes and underscores. The recipe decides what a name means,
and should fail the build on one it does not know. See Recipes in
[docs/design.md](../docs/design.md).

Everything in a recipe's directory goes to the box and into the `recipe` build context,
so keep its tests and fixtures out of it, under `packages/<package>/test/<name>/`.
