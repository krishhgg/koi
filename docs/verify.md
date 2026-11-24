# Verification files

A project tells koi what to check on a preview with files under `.koi/`. This
page describes those files, the shapes koi reads them into, and the protocol a
runner speaks. The schemas are in `packages/shared/src/verify.ts`, and
`loadVerifyConfig` there reads a tree's files. `examples/hello/.koi/` is a
complete small example.

A build carries these files in the source tarball and, once the preview is
healthy, copies the ones a run reads into koid's evidence store (Input
snapshot, below). `koi verify plan` and `koi verify run` read that copy. A
run takes the preview's lease, starts the recorder, and runs each point's
commands in a verifier container against the recorder's browser; it judges
the point from what the runner reported and what the recorder kept. Running
a verification, below, says exactly what runs and what does not.

## Layout

```text
.koi/
  koi.yaml            how to build and run the app; a root koi.yaml wins over this one
  verify.yaml         the manifest: where the points are, which run when, the runner image
  points/*.yaml       one verification point per file
  runners/            the programs the points run; any language
  skills/<id>/SKILL.md  how an agent drives this app on a preview (later)
  fixtures/           files a point can ask for
.koi-runtime/         reserved for koi; the CLI writes changed-files.txt here on every build
```

`.koi/` belongs to the project and travels in the tarball as it is. koi never
writes there. `.koi-runtime/` belongs to koi: `koi up` refuses a tree that has
one. A recipe's Dockerfile may read `.koi-runtime/changed-files.txt` to decide
what the preview keeps.

The fields that hold paths are relative to `.koi/`, never absolute and never
with a `..` segment: `skills[].path` and the `points` globs in `verify.yaml`,
and `requires.fixtures` and the `files` of `setup`, `run` and `cleanup` in a
point. Two fields are about the source tree instead, so they are relative to
the source root: `select.paths`, and the `command` of each step, which runs in
the source root. `feature` is free text, not a path.

## verify.yaml

The manifest. `examples/hello/.koi/verify.yaml` is the smallest one:

```yaml
version: 1
points:
  - points/*.yaml
profiles:
  pr:
    always: [hello.home]
    select: changed
runner:
  image: koi-verifier
```

Fields:

- `version`: always `1`.
- `skills`: a list of `{id, path}`, where `path` is a `SKILL.md` inside `.koi/`.
  Optional.
- `points`: globs, relative to `.koi/`, for the point files. Every glob must
  match at least one file. See Globs for what a glob may hold.
- `profiles`: a map of profile name to `{always, select, include}`. `always`
  lists points every run of the profile takes. `select: changed` adds the
  points whose `select.paths` match a file the pull request changed;
  `select: none`, the default, adds none. `include` adds points by id, for a
  profile that is about them, such as a provider matrix.
- `runner`: `{image, command?}`. The container image the points' commands run
  in, and an argv prefix put before each step's command. A file under `.koi/`
  the prefix names is a runner file of every point (Runner files, below).
  `koi-verifier` names the box's default image (`host/verifier`): Python 3 with
  the Playwright client, no browser. Any other image must be on the box and on
  the operator's allowlist, and must have `python3` with `ctypes` on its PATH
  for koi's supervisor (Writing a runner, below); koid never pulls an image a
  pull request names.
- `budgets`: `{timeoutSeconds?, maxRequests?}`. Limits for a whole run.
  Optional.
- `fallback`: `{mode, onUnmapped}`. What koi does with changed files no point
  selects: `suggest` drafts a point from the diff, `off` does nothing. The gap
  counts as `needs-review` or `blocked`. Optional.

A point listed under `always` is selected for every run of that profile. That
does not make it required. Which points a pull request must pass is policy on
the base branch, below.

## Points

One file per point under `.koi/points/`. A point is a user outcome, with what
would show it false. `examples/hello/.koi/points/home.yaml`:

```yaml
id: hello.home
revision: 2
claim: The home page says hello from koi.
select:
  always: true
  paths: [Dockerfile]
run:
  command: [python3, .koi/runners/home.py]
assertions:
  - name: home-says-hello
    description: The home page's heading reads "hello from koi" in koi's browser, shown by a screenshot and by the recorder's own read of GET /.
    evidence: [screenshot, http-response]
```

Fields:

- `id`: permanent. Lowercase words in segments joined by dots, like
  `app.canvas.save`. A file can be renamed; the id keeps its history.
- `revision`: a positive integer, raised when the claim or the assertions
  change. koi also hashes the file, so a forgotten bump still shows as a change.
- `claim`: the outcome in one sentence a reviewer can disagree with.
- `feature`: the feature this point belongs to, usually a feature file of the
  project's skill. Optional.
- `select`: `{paths, always?}`. `paths` are globs relative to the source root; see
  Globs for what one may hold.
  List the callers and consumers of the feature, not only its directory. With
  `always: true` the point is taken by every run of a profile that selects by
  change. A point needs at least one path or `always: true`.
- `requires`: `{services?, fixtures?, browser?, provider?, network?}`. What the
  point needs from the preview and the host. These are requests the host checks
  against its policy, not grants. A point that asks for what the host does not
  give is `blocked`, with the reason. `fixtures` are paths inside `.koi/`;
  `provider` is one of koi's LLM providers. Optional.
- `setup`, `run`, `cleanup`: each `{command, files?}`. `command` is an
  argument array, never a shell string. `files` lists files inside `.koi/` the
  command depends on but does not name, such as a module it imports; see
  Runner files. `run` is required.
- `assertions`: at least one `{name, description, evidence}`. Each names one
  thing the runner must show, in words, and the kinds of evidence it must show
  it with. Names are unique within the point.
- `budgets`: `{timeoutSeconds?, maxRequests?}` for this point, over the
  manifest's. Optional.

Every object is strict. A key the schema does not know is an error, so a typo
cannot silently turn a check off.

## Globs

`select.paths` and the `points` of `verify.yaml` use koi's own matcher. A glob holds:

| Written | Matches |
|---|---|
| Any other character | That character. |
| `*` | Any characters, or none, except `/`. A leading dot is a character like any other, so `*` matches `.env`. |
| `?` | One character, except `/`. A character of any size counts as one, so `?` matches `日` and `😀`. |
| `**` as a whole path segment | Zero or more whole segments, dot directories too. `**/a` matches `a` and `x/y/a`. `a/**/b` matches `a/b`. |
| `{a,b,c}` | Any one of the choices. A choice may be empty, so `a{,b}` matches `a` and `ab`. |

A few things this means:

- `a/**` needs something after `a/`, so it does not match the file `a`. Write `{a,a/**}`
  for both.
- A `**` that is not a whole segment reads as a `*`, so `a**` and `a**/b` cross no `/`. A
  run of three or more stars also reads as a `*`.
- Braces expand first, and each expansion then reads as a glob of its own.
  `{src/**,test/**}` means the same as listing `src/**` and `test/**`.
- A `,` outside a group, a `!` anywhere but the start, and a space are plain characters.
- Matching is case-sensitive, so `A` does not match `a`.

koi refuses these when it loads the file, and the message says what a glob may hold:

- `[` and `]`. Write the choices out: `{a,b,c}` for `[abc]`, and `v{1,2,3}/**` for
  `v[1-3]/**`. For a long range such as `[a-z]`, a `?` or a `*` is usually what the point
  means: `src/[a-z]*.ts` becomes `src/*.ts`. There is no way to say "not these", so list
  what the point is about. To match a name that holds a bracket, such as the route
  `app/[id]/page.tsx`, use `?` for each bracket: `app/?id?/page.tsx`.
- A group inside a group. Write `{a{b,c},d}` as `{ab,ac,d}`.
- A `!` at the start. A glob cannot negate, so list what the point selects.
- `\`. A glob has no escape.
- Braces that do not pair up.

## Runner files

A point's checks live in its runners, and a pull request can change a runner
without touching the point file, whose digest then stays the same. So the
loader also finds each point's runner files: every entry of `files` in
`setup`, `run` and `cleanup`, and every argument of those commands that names
a file under `.koi/` when read as a path from the source root, where the
commands run (`.koi/runners/home.py` in the example). It returns them per
point with their digests, and the plan records them next to the point's own
digest. That is how a change to a required point's runner is seen, which the
core contract says puts the point into `needs-review`. The loader cannot see
what a program opens, so a runner that reads other files under `.koi/`, a
shared module or a fixture, must list them in `files`. An argument that names
no file is not an error; a `files` entry that names no file is. The plan
records each runner file as `.koi/` and its path under it, under the same
rule as a `files` entry, so every runner file the loader returns is one a plan
can hold.

The manifest's `runner.command` goes before every step of every point, so a file
under `.koi/` it names is a runner file of every point: it is in the input
snapshot, in `/workspace`, and in each point's digests, so a change to a shared
wrapper shows on all of them. The manifest has no `files` list to catch a typo, so
an argument here answers for itself. One under `.koi/` that names no file is an
error, and so is one with a `..` segment, in the words a `files` entry gets:
`.koi/verify.yaml: runner.command[1]: no file runners/wrapper.py under .koi/`. Other
arguments stay as they are: a program on the image's PATH, a flag, an absolute path
in the image. The loader cannot tell a relative path outside `.koi/` from any other
word, so it does not check one, and a file there is not in the snapshot. A module a
wrapper imports goes in the `files` of each point that needs it.

Nothing under `.koi/` may be a symlink, to a file or to a directory, wherever
it points. The loader records each file at the path it lists it at and
matches a command's arguments against those paths. With `alias -> runners`, a
command could name `runners/check.sh` as `.koi/alias/check.sh`; the script
would run, but the loader would record nothing for it, and a change to the
script would change no digest. Use the real path.

## Outcomes

A point ends in one of six outcomes: `pass`, `fail`, `blocked`, `not-run`,
`needs-review`, `pass-with-recovery`.

koi, not the runner, decides a point's outcome. It computes it from the
assertion events the runner reported, matched against the point's declared
assertions. An assertion that never reported makes the point `not-run`, and
`not-run` fails the point. A runner cannot report a point verdict, only
assertions with evidence.

## The runner event protocol

A runner is any program. koi starts it with the point's `run.command` in the
manifest's runner image, in the frozen source tree, and tells it where the
preview and the recorder's browser are (Writing a runner, below, has the
environment). The runner prints one JSON object per line on stdout:

```json
{"type":"assertion","point":"hello.home","name":"home-says-hello","outcome":"pass","evidence":["recorder:screenshot:1","recorder:http-response:2"],"detail":"the heading reads \"hello from koi\""}
```

Five kinds of event:

- `assertion`: `{point, name, outcome, evidence, detail?}`. One of the point's
  declared assertions, what the runner saw, and references to the evidence
  koi holds for it. `point` must be the running point and `name` one of its
  declared assertions; anything else is a protocol diagnostic, not a report.
- `capture`: `{kind, label}`, where `kind` is `screenshot`, `trace`, `har`,
  `aria` or `file`. Asks koi's recorder to keep a capture of the point's page
  under that label. koi answers on stdin.
- `read`: `{label, path, method?}`. Asks the recorder to request `path` from
  the app, from inside the point's browser context, and keep what came back
  as an `http-response` artifact: the recorder's own record of what the app
  served, which no script in the page can touch. koi answers on stdin.
- `note`: `{text}`. A remark for the report.
- `phase`: `{name, state}`, where `name` is `setup`, `journey`, `recovery` or
  `cleanup`, and `state` is `start` or `end`. Marks where the runner is. A
  `recovery` start makes a passing point `pass-with-recovery`.

A line that is not one of these is kept as the runner's log and means nothing
to koi. A line that starts with a brace and is not one of these (unknown
type, unknown field, wrong shape) is counted as malformed and recorded as a
fixed diagnostic; nothing is repaired or inferred from it.

koi answers a capture or a read with one JSON line on the runner's stdin:

```json
{"version":1,"type":"capture-result","label":"home","status":"ready","artifact":"recorder:screenshot:1"}
{"version":1,"type":"capture-result","label":"trace","status":"failed","error":"withheld"}
```

Only `ready` carries an artifact reference, which the runner cites in an
assertion's `evidence`. An assertion may cite at most 100 references. A report that cites
more counts as a failure of its assertion, whatever outcome it gave. A runner that cannot read stdin may cite
`capture:<label>` instead; koi resolves that alias to the artifact the
capture gave, within the point. Labels are unique within a point: a repeated
one fails with `duplicate_label`, and the JavaScript client fails a second call under a
label still in flight without sending it. A label that holds a known secret or
credential still makes its capture, since the keys page takes any word and that
word must not cost a point its evidence. koi's events and records say the label
with the value masked. Errors are stable codes: `withheld` and `failed` are the
artifact's availability, `duplicate_label`, `capture_limit` (200 captures and
reads per point), `cap_exceeded` (the run can keep no more evidence),
`capture_failed`.

`examples/hello/.koi/runners/home.py` is a complete runner: it drives the
page koi opened, asks for a screenshot and a read of `/`, and reports one
assertion citing both.

## Writing a runner

What koi does with a point, in order. It opens a browser context in the
recorder with its first page at the app's `/`. It fills the point's input
volumes with the frozen inputs, creates a fresh verifier container from the
manifest's runner image, resolved to a digest, with those volumes mounted
read-only, starts it with koi's supervisor as the entrypoint, waits until it
is running and the firewall has bound the run's permits to its bridge port,
and tells the supervisor to begin. The supervisor runs the point's `setup`, `run` and
`cleanup` commands one after another, each as the manifest's
`runner.command` prefix plus the step's argv, never through a shell, with
`/workspace` as the working directory. When the last step ends, or the
point's budget runs out, koi stops and removes the container, closes the
context, and judges the point.

The container. `/workspace` holds the input snapshot: `.koi/` as the build
had it, `koi.yaml`, and the changed-file list. `/fixtures/<path>` holds each
fixture the point's `requires.fixtures` names, checked against the digest the
snapshot recorded. `/koi` holds the supervisor and the point's file. All three
are root-owned and read-only. A file executable in the tree stays executable, so
`command: [.koi/runners/check.sh]` runs a script with a shebang: it is mode 0555
in the verifier, and every other file is 0444. `/tmp` (256 MiB) and `/work`
(128 MiB) are the only writable places, and `HOME` is `/tmp/home`.
The root is read-only, every capability is dropped, there is no network but
the run's, and the image's own `ENTRYPOINT`, `CMD`, `USER` and `WORKDIR` do
not apply: the supervisor is `/koi/supervisor.py`, run with `python3 -I`, as
uid 10002. A custom image must have `python3` with `ctypes` on
`/usr/local/bin:/usr/bin:/bin` and may declare only runtime constants in its environment (`PATH`, `LANG`,
`PYTHON_VERSION` and the like); an image that declares a proxy or a token is
refused with `image_env_not_allowed`.

The environment. Each step gets exactly these variables, from the
supervisor, and nothing the image or the daemon set:

| Variable | Value |
|---|---|
| `PATH`, `HOME`, `TMPDIR`, `LANG`, `TZ` | `/usr/local/bin:/usr/bin:/bin`, `/tmp/home`, `/tmp`, `C.UTF-8`, `UTC`. |
| `KOI_PROTOCOL_VERSION` | `1`. |
| `KOI_RUN_ID`, `KOI_POINT_ID`, `KOI_ATTEMPT` | The run, the point, and the attempt number (always `1` today). |
| `KOI_PREVIEW_URL` | `http://app.<runId>.invalid:<appPort>`, the app's private origin on the run network. |
| `KOI_RECORDER_WS` | `ws://<recorder>:4317/<token>`: the recorder's browser, for a Playwright client's `connect_over_cdp`. The token is the run's; never print it. |
| `KOI_FIXTURES` | A JSON object from each fixture's path under `.koi/` to its read-only path under `/fixtures`. |
| `KOI_TIMEOUT_SECONDS`, `KOI_MAX_REQUESTS` | What the point has left of its time budget when the steps start, in whole seconds rounded up, and its request budget. The request budget is recorded and passed on; the egress proxy does not count against it yet, and a point that requires a provider is blocked at plan time. |
| `KOI_LOGIN_KEY` | Absent. No policy grants a runner the preview's login key yet. |

The browser. Connect a Playwright client to `KOI_RECORDER_WS` with
`connect_over_cdp` (Python) or `connectOverCDP` (JavaScript), find the page
whose URL starts with `KOI_PREVIEW_URL` among `browser.contexts()`, and
drive it. The recorder owns the browser and its contexts; a runner leaves
pages open, since closing them is refused, and never starts a browser of its
own: koi accepts no evidence from one. What the proxy on 4317 allows and
refuses is under The recorder, below.

The clients. `koi_runner` (Python, on the default image's path) and
`koi-runner.mjs` (JavaScript, at `/opt/koi/clients/koi-runner.mjs` in the
default image, for a custom image with Node; copy either from
`host/verifier/clients/`) print the events and wait for the
acknowledgments: `capture(kind, label)` and `read(path, label)` return the
artifact id or raise `CaptureFailed` with the error code; `assertion(name,
outcome, evidence, detail)`, `note(text)` and `phase(name, state)` print
their event; `env()` reads the variables above. koi discards a line over 8 KiB,
and a discarded assertion reads as one never reported, so both clients cut an
assertion's detail and a note's text until the whole encoded line fits. That
size is in bytes, after escapes: 2,000 Chinese characters are 12 KiB in the
Python client's JSON. An event too large without its free text, such as an
assertion citing a thousand artifacts, raises an error rather than go missing.
A runner that prints events itself has to keep to the same bound.

Budgets and bounds. The point's time budget is its own `budgets.timeoutSeconds`,
or the manifest's when it names none, under the host's point ceiling (900
seconds) and the time the run has left. A point may ask for more than the
manifest's value. The point has one deadline, set before koi opens its context
in the recorder, and the recorder's calls, the supervisor and koi's own stop all
work to it. What opening the context, staging the inputs, starting the container
and binding the firewall take comes off the budget: koi's start line tells the
supervisor what is left at that moment, and that is the budget the steps get. With
nothing left, the point is `blocked` with `point_timeout` and no verifier starts.
The three steps share what is left; the supervisor holds the last 30
seconds (or a quarter of a small budget) back when the point has a cleanup, stops a step past
its share by signalling its whole process group (SIGTERM, then SIGKILL after 5
seconds), and still runs cleanup after a failed setup or run when time is
left. The supervisor reports a step only once all the step wrote has gone on,
however slowly koi reads it, with no limit but the point's budget. A process
that leaves the step's group and keeps its stdout open cannot hold the
supervisor: once that pipe has given nothing for 5 seconds after the step ended,
the supervisor stops reading it. Whenever the supervisor stops before the pipe's
end, for that reason, for the budget or for a failed write, the step's signed
line says `output_incomplete: true`, and the point fails. koi stops the container
itself 15 seconds past the deadline, on a timer of its own, whatever it is reading
at the time. That stop ends any capture, read or acknowledgment still in flight.
The same timer runs from the moment the point starts, so a cancel or the deadline
also ends what koi is preparing: the Docker command in progress, such as a
`docker cp` of the inputs that could otherwise run for 120 seconds, is killed, and
koi looks once more before it starts the container. No grace applies before the
container starts. The wait for the firewall ends with that timer too, since
another run can hold the network's lock and the helper can be slow. A reapply
still waiting for the lock when the point stops is dropped and asks the helper for
nothing. One already at the helper finishes on its own and keeps the lock until it
does, because killing `sudo` does not stop the root helper: the run's revoke then
comes after that apply, and a reapply that gets the lock after the teardown finds
no record and changes nothing. The point's teardown then removes the staging
container and the input volumes, as it does after any end.
On the output: a line is at
most 8 KiB (a longer one is discarded whole and recorded as a diagnostic),
a point's stdout and stderr together at most 8 MiB, events at most 50 per
second with a burst of 100, and captures and reads at most 200 per point. Past
100 malformed lines, the event rate or the total, koi stops the verifier with
`runner_protocol_limit`. Runner log lines are kept as events up to 2,000 per
point and counted after that.

koi reads a verifier's output the moment it starts and never stops reading it,
whatever it is doing with what it read, so a slow capture does not delay the
bounds. A reading loop puts complete lines on a queue, and a separate handler
takes them from there in order.

One rule covers the bounds: koi counts each of them as the output arrives, and
never waits while it handles a line. So a burst is either over a bound and stops
the point, or is handled at full speed. There is no rate on bytes, because koi
cannot slow a process it is reading as fast as it can, and a wait would slow only
koi. The event rate and the malformed lines are counted on the reading loop too:
events queued behind a long capture are not a burst the runner made, and a flood
behind one stops the point at once. The queue holds at most 8 MiB, counting each
line at its UTF-8 length plus 128 bytes for the object that holds it, so 8 MiB of
empty lines cannot become half a gigabyte of objects. Past any bound, the reading
loop has the watchdog stop the container at once, the capture in flight ends with
it, and the point fails with `runner_protocol_limit`. A runner under the total
reaches the queue's bound only with lines so short that their cost fills it. koid
holds a verifier's output in three places only: the queue, one unfinished line per
stream (at most 8 KiB), and the chunk in hand, which Bun sizes at under 1 MiB.
During the `docker stop` that follows, a process that ignores SIGTERM can go on
writing for 10 seconds. koi goes on reading through that and keeps none of it. A
line the handler has taken off the queue always counts. What is still queued when
the point stops is dropped, except a line the supervisor signed, which still
counts. A point's observations record the most the queue held
(`counts.queuedBytes`).

The runner's time ends when its container exits, and the time koi then takes over
the queue is koi's. koi goes on handling what is queued until the later of the time
the point had anyway and 60 seconds after the exit, past the point's budget if it
has to, and never past the run's deadline. A stuck capture cannot hold the point
open longer than that. At that end, or when the recorder refuses a capture still
queued because the point's budget has ended, the point is `blocked` with
`handling_timeout`, which says the runner finished in time and koi did not.

What fails a point. The verdict rules under Running a verification apply to
what the runner reported; on top of them, a point fails when its `run` step
exits with an error, is killed, is skipped, or cannot start (`runner_failed`,
`setup_failed`, and this holds however the later steps end: a run that already
reported its failure stays a `fail` if its cleanup then runs out of time, and
the point's reasons name both), when its cleanup fails, when the verifier is killed for its
memory, when a protocol bound stops it, when the steps the supervisor reports
are not the ones the point declares, in order, each once
(`supervisor_sequence`), when the exit code its exit line implies and the
container's disagree (`supervisor_mismatch`), when the verifier exits 0 with no
such line (`supervisor_missing`), or when not all of its output was read
(`runner_output_incomplete`: the streams stayed silent for 5 seconds after the
exit without ending, one broke, or a step's line says `output_incomplete`). A
point is `not-run` when a declared assertion never reported. It is `blocked`,
never passed, when the verifier
could not be created or started, when its image is not allowed or not on the
box, when the point reached its budget (`point_timeout`, whether koi or the
supervisor stopped it, or a step had no time left), when koi could not finish
with the output of a verifier that exited in time (`handling_timeout`), when koid
stopped waiting for a verifier that did not come back (`verifier_stuck`, under
Running a verification), or when the run was cancelled under it. An assertion
citing a capture that was withheld, failed, or never made lacks its evidence and
fails.

The supervisor's own lines on stdout (`{"type":"supervisor",...}`) report
each step as it ends and, last, which step the sequence ended on and how.
Those lines decide the steps' part of a point's verdict, so koi must know they
are real, and a runner shares that stdout. koi puts a random key in the start
line on the supervisor's stdin, and the supervisor signs each of its lines with
it: a number that goes up by one and an HMAC-SHA256 of the line's text. koi
believes only a line that checks and has the next number. A line that merely
looks like the supervisor's is a malformed line, a diagnostic and no more.

The key is not in the supervisor's argv, environment or files, and no step
exists yet when it arrives. The start line stops at the supervisor. The
supervisor also makes itself undumpable before it reads stdin, which closes its
`/proc/<pid>/mem` and `/proc/<pid>/fd`, and `ptrace`, to the steps, whose uid
is the same; one that cannot do so runs nothing. Each line carries a MAC and
not the key because a step can read this stdout through `/proc/1/fd/1` of the
init process, whose descriptors are not closed to it. Stealing a line that way
gives it nothing to forge with, printing it again shows in the number, and
keeping it leaves a gap that fails the point. What this does not cover is the
image itself: a custom image's `python3` runs the supervisor, and is as trusted
as the operator's allowlist makes it.

## The records koi writes

`koi up --json`, `koi list --json` and `koi lease` carry `DeploymentIdentity`
(see Identity and leases below). `koi verify plan` writes a `Plan`, and
`koi verify run` writes a `Run` and, when it ends normally, a `Result`
(Running a verification, below). Nothing reads a `ProofRecord` or a
`RequiredPolicy` as trusted yet: the plan shows the tree's own as advisory.

- `DeploymentIdentity`: `{label, deploymentId, imageDigest, commit, merge?}`.
  The build a run is bound to: the preview, the deployment serving it, the
  image by content, the commit built, and for a pull request the merge's head,
  base and base branch.
- `Plan`: `{version, planId, deployment, profile, points, blocked, uncovered,
  planDigest}`. What a run will do, frozen before it starts: each point taken
  with its revision, file digest, runner files with their digests, and why it
  was selected; each point blocked with its reason; what the change touches
  that no point covers.
- `Run`: `{version, runId, planId, deployment, planDigest, state, startedAt,
  finishedAt?}`. `state` is `running`, `completed` or `cancelled`; `finishedAt`
  is set exactly when the run is no longer running.
- `Result`: `{version, runId, outcome, points, uncovered}`. Each point has its
  outcome, a reason when it did not pass, and its evidence references. The
  run's `outcome` follows from the points': `passed` when every point passed,
  `failed` when one failed, and `incomplete` otherwise, when no point failed
  and one did not pass. The schema refuses a result that says otherwise, and
  a point that did not pass without a reason.
- `ProofRecord`: `{pointId, revision, mutation, failingRunId, passingRunId,
  provenAt}`. Proof that a point can fail: a run against a deliberately broken
  build (`mutation`, a commit or a patch by digest) failed it, and a run against
  the fixed build passed it. A point without a proof record cannot be required.
- `RequiredPolicy`: `{version, required: [{id, revision}]}`. Which points a
  pull request must pass, at which revision. koi reads it from the protected
  base branch, never from the pull request's tree, so a pull request cannot
  make its own checks optional. A required point must have a proof record at
  that revision; the policy has no field to waive it.

## Identity and leases

A run is bound to one build, so koi must say which build serves a preview and
keep it there while the run goes. Two pieces of the CLI do that today.

`koi up --json` and each entry of `koi list --json` carry `deployment`, the
`DeploymentIdentity` of the preview's saved deployment, and `keysUrl`, the
preview's keys page. The saved deployment is the build that serves whenever the
preview is running. `deployment` says which build is saved, not whether the
container is up right now: after the box wakes, `koi list --json` reads saved
records without starting anything, so a stopped preview still has an identity.
`status` says how the latest build attempt ended, and not whether the container
is up either: after the box wakes it says `running` for a stopped container, and
after a failed rebuild it says `failed` while the previous deployment serves. For
a live check, request `https://NAME.<domain>/__koi/health`, which answers 200
only while the container runs and Caddy routes to it, or run `koi lease`, which
refuses a preview that is not running.
`deployment` is absent only when no build has succeeded or koid retired the
deployment, for example after stopping the container for disk use. After a
failed rebuild the previous deployment stays saved, and `deployment` names it,
so a caller compares `deployment.commit` with the commit it asked for before it
starts a run. `deploymentId` is the id of the build attempt that made the deployment,
which is also the name of its build log, and is new for every deployment.
`imageDigest` is the id Docker gave the image. It is a content identity, a
hash of the image's configuration, so a cached rebuild of the same input
keeps it and two deployments may share one. To tell deployments apart,
compare `deploymentId`; `imageDigest` says whether two deployments run the
same image. Previews deployed before koid kept these fields have no
`deployment` until `koi up` replaces them.

```json
{"schemaVersion":1,"label":"hello-pr-7","url":"https://hello-pr-7.previews.example.com",
 "status":"running","commit":"<40 hex>","pr":7,
 "merge":{"head":"<40 hex>","base":"<40 hex>","baseBranch":"main"},
 "deployment":{"label":"hello-pr-7","deploymentId":"<20 chars>","imageDigest":"sha256:<64 hex>",
  "commit":"<40 hex>","merge":{"head":"<40 hex>","base":"<40 hex>","baseBranch":"main"}},
 "keysUrl":"https://keys.previews.example.com/?for=hello-pr-7"}
```

`koi lease NAME --minutes N [--holder TEXT]` holds the preview for up to 120
minutes; the holder defaults to the local user and host. While the lease lasts,
`koi up` for that name is refused before anything is built, with a message
that names the holder and the expiry, and `koi down NAME` refuses unless given
`--force`. A preview holds at most one lease: a second `koi lease` is refused
until the first expires or `koi release NAME LEASE` ends it. koid also refuses
a lease while a build of the name is in progress, since it would replace what
serves as soon as it is healthy, and when nothing serves. Nothing serves
unless the preview's container runs and Caddy routes to it, which is what its
health check at `https://NAME.<domain>/__koi/health` answers 200 for; a record
can say `running` while the container is stopped, after the box wakes or a
start fails. So `koi lease` requests that URL first, as a visit would, which
starts a stopped preview, and asks koid for the lease once it answers 200. It
gives up after 90 seconds and reports the last answer. Before it grants the
lease, koid applies the routes its records call for and waits for Caddy to take
them, so that what Caddy serves, what koid routes and what the record names are
the same build. A cutover that Caddy took before reporting a failure can leave
them apart. If Caddy does not take the routes, koid refuses the lease and says
the preview's routes are not settled; `koi lease` can be run again. The reply,
as JSON with `--json`, is the lease and the `DeploymentIdentity` it is bound to:

```json
{"schemaVersion":1,
 "lease":{"leaseId":"<20 chars>","deploymentId":"<20 chars>","holder":"dev@laptop",
  "acquiredAt":"2026-10-06T10:00:00.000Z","expiresAt":"2026-10-06T10:30:00.000Z"},
 "deployment":{"label":"hello-pr-7","deploymentId":"<20 chars>","imageDigest":"sha256:<64 hex>",
  "commit":"<40 hex>"}}
```

A caller checks `deployment` against the one it expects and stops when they
differ. Expiry is wall clock: koid keeps the lease in the preview's record, so
it survives a koid restart and the box sleeping, and ends on time either way.
koid drops an expired lease on its next expiry sweep; until then it is ignored.
`koi release --json` prints
`{"schemaVersion":1,"label":"hello-pr-7","leaseId":"<20 chars>","released":true}`.

The JSON Schemas of these three outputs are `schemas/koi-up.schema.json`,
`schemas/koi-lease.schema.json` and `schemas/koi-release.schema.json`, generated
from the zod schemas in `packages/shared/src/cli-output.ts`. Each output's
`schemaVersion` is its own, and changes only when koi removes a field or changes
what one means. Adding an optional field keeps the version. The schemas refuse
fields they do not name, so a caller that validates with them copies them from
the koi commit it runs. `loginKey` in `koi up`'s output is a secret, and must
never go into evidence or logs.

Leases coordinate callers that trust each other and carry no per-holder
authorization. `holder` is whatever the caller says it is; koid does not check
it. Anyone who can reach koid's control socket, which is anyone who can run
`koi` against the box, can lease any preview, release another holder's lease
with the `leaseId` that koid's status reply shows, and remove any preview with
`koi down NAME --force`. A lease makes `koi up` wait and `koi down` ask for
`--force`. It keeps nobody out.

## Running a verification

`koi verify` plans a verification of a preview, runs it, follows it to the
end and exports what it recorded. koid does the work and judges; the CLI
asks, waits and shows. This section says what a run does today, what it
does not, and what each outcome and exit code means.

### What runs today, and what does not

A run does this, in order: freezes a plan, takes the preview's lease, makes
the run network and starts the recorder, resolves the manifest's runner
image under the operator's policy, and for each planned point opens its
browser context in the recorder at `/`, creates a verifier from that image
with the frozen inputs, runs the point's `setup`, `run` and `cleanup`
commands in it under the runner protocol (Writing a runner, above), stops
and removes the verifier, and judges the point from the assertion events
the runner reported against the artifacts the recorder kept. Then it judges
the run, writes the evidence bundle, stops the recorder, removes the
network, and releases the lease. A point can pass now, and a run can be
`passed`.

What a run does not do. It does not take agent actions: `verify act` and the
restricted action API are later work, and nothing starts an exploratory
session on its own. It does not count provider requests: a point that
requires a provider is blocked at plan time until the egress proxy keeps a
per-run budget. It does not give a runner the preview's login key: no policy
grants it yet.

Two more things are not here. The required policy has no trusted source: a
`.koi/required.yaml` in the tree is shown in the plan as advisory, since a
pull request cannot make its own checks required, and the protected base
branch is later work. So readiness (`eligibleForMergeGate`) is false for
every run, with the reasons listed. And nothing is posted to GitHub: the
report is written into the bundle as `report.md`, in the comment's exact
form, and a publisher is later work.

### Commands

```text
koi verify plan NAME [--profile pr] [--json]
koi verify run NAME [--profile pr] [--json]
koi verify status RUN [--json]
koi verify evidence RUN --out DIR [--json]
koi verify cancel RUN [--json]
```

`koi verify plan` reads the deployment's input snapshot and says what a run
would do: the points the profile takes and why each one (`always`, a changed
file matching `select.paths`, `select.always`, or `include`), the points it
cannot take and why (a requirement this host does not give), the changed
files no point's `select.paths` covers, the advisory policy, whether each
point has a proof record in `.koi/proofs/` (shown as `unverified`, since
koid does not resolve the runs it names), and the limits a run gets. A plan
of a dirty tree, a build without a pull request context, or an explicit
subset is advisory. Planning does not touch the preview and does not take a
lease; a stopped preview can be planned.

A note on why a point was selected holds at most 2,000 characters. When a long
changed file and a long `select.paths` entry do not fit, each is cut in the
middle and marked `[cut by koid]`, so the note still names both, and the plan
still loads. An uncovered file's name over that length is cut the same way.

`koi verify plan` refuses a project that declares what looks like a real credential,
with `declared_credential`, and writes nothing (see "Project text and runtime text").
It also refuses a plan too large to match, with `plan_too_large`, and writes nothing
(see "Planning limits").

Requirements and what blocks them today: `provider` (no request budgets until
the egress proxy counts them), `network` (no named network policies),
`services` (no service policy to check against), a fixture missing from the
snapshot, a runner image that cannot run here, which blocks every point with why, and
verification unavailable on the box, which blocks every point with the reason the
startup check gave.

`koi verify run` visits the preview first, as `koi lease` does, so it is
running; plans; asks koid to start a run of that plan; then asks for the
run's status every five seconds until it is no longer running, saying each
point's outcome on stderr as it arrives. It gives up after the run's time
limit plus five minutes. The JSON result is one object: `{version, plan,
accepted, run}`, where `run` is the final status.

`koi verify status` reads a run's status, with every page of its points.
It exits 0 when the read succeeds, whatever the run's outcome; automation
reads `state`, `completion` and `outcome`.

`koi verify evidence` writes into an empty or new directory: `status.json`,
`evidence.json` (the manifest's fields and every artifact entry),
`events.ndjson`, `artifacts/<kind>-<n>.<ext>` for each available artifact,
and `export.json` saying what was written. `export.json` says `complete: true`
only when every event and every artifact the manifest records is in the
directory and each artifact hashes to the manifest; otherwise `missing` lists
what is not there and why. A withheld artifact counts as missing, since the
export does not hold it.

A count says nothing of which events these are: a line replaced by a copy of
another keeps it. So the exporter checks that the sequence numbers count up by one
from 1, with no gap or repeat, and that the bytes it wrote hash to the digest of
`events.ndjson` that the manifest records. koid writes each line with its fixed
fields first, in the order the schema gives them, so a line parsed and written
again is the same bytes. An event line that fails either check is still saved, and
`missing` says what is wrong. A line that holds a secret koid learned after writing it
also fails the digest check, since the reply masks it and no longer says what the
manifest hashed (see "Project text and runtime text").

Each artifact is fetched in 6 KiB
chunks, hashed as it arrives, and kept only when the bytes hash to what the
manifest records; otherwise it is discarded and the export says so. An
export over SSM reads at most 1 MiB of each artifact and 8 MiB in all. The
ceilings bound what is asked for: every request is for at most what the
allowance has left, and nothing is written past it, so an artifact a byte
over its ceiling is kept as `.partial`, marked `truncated`, with a note that
the rest needs the channel (C2). Events are asked for by count: as many as
the allowance holds at the average line so far, and at least one. Every
line received counts against the allowance, written or not, since it
crossed SSM either way. Events stop at the last line that fits, and the
export says at which sequence. Withheld and failed artifacts have no bytes
and are listed with their reason.

Each file, the JSON ones included, is written to a `.part` file, every byte of it,
and renamed into place. A write that takes only part of its bytes is carried on
from there, and a write that takes none fails the export. A file counts as verified
only once all its bytes are in it. `export.json` is written last. When an export
fails part way, its `.part` file is removed and no `export.json` is written, so the
directory cannot read as a finished export.

Once a run's evidence has expired, koid keeps only the manifest, the status and
the controller's record. `koi verify evidence` still finishes and exits 0, without
asking for events or artifacts: it writes `status.json`, `evidence.json` and
`export.json`, and no `events.ndjson`. `export.json` then has `expired: true`,
`complete: false`, no `events.file`, and `missing` names the events and the
artifacts that are gone.

`koi verify cancel` asks koid to stop a run. The run ends after the point in
progress; its status says when.

A file name comes from the pull request and can hold any byte but a NUL, and a runner's
detail can hold any character. So in text mode, every line `koi verify` prints, its progress
messages and its errors show each control character as an escape: ESC as `\x1b`, a newline
as `\x0a`. That covers C0, DEL and C1, the line separators U+2028 and U+2029, and the
explicit bidi controls, which show as `\u202e` and so on. A name or a detail cannot erase or
forge what `koi verify` shows, or reach the clipboard through OSC 52. A backslash stays as
it is, so a file literally named `a\x1bb` reads the same as one holding ESC. `report.md`
shows them the same way, so a newline or a backtick in a file name or a detail cannot break
its table or start a section.

`--json` prints the values as they are. JSON escapes C0 and newlines, and leaves DEL, C1
and the others, so read `--json` with a program and not on a terminal.

### Planning limits

A pull request chooses its changed files and its `select.paths`, and koid runs every
changed file against every glob on its one event loop. So what a plan may match is
bounded. These numbers are far past any real project, and each says why:

| Limit | Value | Why this number |
|---|---|---|
| Changed files | 20,000 | 1 MiB of names, the snapshot's bound, comes to about this many real ones. |
| Characters in a changed file's name | 4,096 | `PATH_MAX` on Linux. A longer path cannot be checked out. |
| `select.paths` globs across all points | 5,000 | 2,000 point files, the most `.koi/` may hold, at 2.5 each. |
| Steps of matching, per plan | 4,000,000,000 | 5 times a large real project, measured below. About 20 seconds at the worst. |
| Characters in a glob | 4,096 | An exact path is a glob, so as long as a changed file's name. |
| Ways a glob's braces can expand | 1,024 | The selector below has 120. |
| Characters those ways come to | 65,536 | The same selector comes to 2,386. |
| Point globs in `verify.yaml` | 200 | A project has a few. Each runs over every file under `.koi/`. |

koid checks the first three before any glob runs, so a plan over one ends at once. Over
any of the first four, koid refuses the plan with `plan_too_large`, and the message says
which limit. It writes nothing. The plan is refused and not cut short, since a point left
out without a word could make a run look more covered than it is. The last four are part
of the files' schemas, so a project over one does not load, and planning answers
`verify_invalid`, naming the file and the field.

A large selector that a real project writes, and the one the limits above are measured
against:

```
{apps,packages}/{web,api,cli,shared}/**/*.{ts,tsx,js,jsx,mjs,cjs,json,yaml,yml,css,scss,html,md,mdx,toml}
```

The matcher counts its steps. A step is one trip round its loop, which looks at one glob
token and one path position. A search for a `/` counts each character it reads, whether or
not it finds one. Starting a match counts as 4. Compiling counts each character it reads,
each string it builds and each character of each expansion, and 2 for each token, so one
compile stays under one turn. These are about what the work costs. One plan has one budget, and the point globs the loader
matches for that plan count toward it. Loaded alone, as `koi up` does, the point globs have
the same budget, and over it the project does not load. Nothing looks at a clock, so the
same project and the same change get the same answer on any box. A plan near the budget
takes longer on a slower box, and is not refused there.

The cost of one match has a known bound. koi expands a glob's braces when it compiles the
glob, and matches each expansion with a loop that never visits the same pair of glob token
and path position twice. So one expansion takes at most its length times the name's length.
No part of this is exponential, and the limits above bound the product.

Measured on a Ryzen 9 6900HS, where a step costs between 2 and 5 nanoseconds:

| Plan | Steps | Time |
|---|---|---|
| A large project: 5,000 changed files, 500 points, 950 globs, one point in ten with a selector like the one above | 791 million | 1.5 seconds |
| The same mix at 20,000 changed files and 1,000 globs | 3.35 billion | 6.2 seconds |
| The limit on counts: 20,000 files by 5,000 globs of the form `g1/**` | 1 billion | 3.7 seconds |
| The costliest match, repeated until the budget refuses: `*` and 4,094 `a` and `b`, on a name of 4,096 `a` | 4 billion | 20.4 seconds |

The rest of koid gets a turn every 262,144 steps, and a long match stops where it is and
goes on after the turn. So the costliest single match, 8.4 million steps, takes 33 turns,
and koid goes on answering during a large plan that is allowed. A turn takes under 2
milliseconds. The first turn in a new process takes up to 6 milliseconds, since the code
has not been compiled yet. Compiling a glob at the limits takes 0.5 milliseconds more. The
check for declared credentials also gives koid turns, between points, as `.koi/` may hold
64 MiB of text.

### Starting a run

`koid ctl verify run` takes the plan's id and digest. koid refuses a plan it
does not have, a plan whose digest is not the one it wrote (`plan_stale`), a
plan whose inputs changed since (`inputs_changed`), a plan that selects nothing
(`empty_plan`), and any run when verification is unavailable on the box. The
inputs include the runner image. A plan records the digest the manifest's image
resolved to, inside what `planDigest` covers, and koid resolves the image again
at the start of the run. An allowed tag that now names another image, or an image
no longer on the box or the allowlist, needs a new plan. Every verifier of the run
is made from the digest found at that start. koid then takes the preview's
lease as holder `verify:<runId>`, for the run's time limit plus
120 seconds of teardown allowance (never more than the two-hour lease cap),
and compares the deployment the lease holds with the plan's: a different
deployment id, image or commit releases the lease and refuses the run
(`deployment_mismatch`), so an older image left after a failed rebuild is
never verified under a plan made for another. The lease alone does not
prove the app is free: an earlier run's lease may have expired while its
teardown or its last capture was still pending. So koid also refuses the
run (`preview_busy`, retryable) while anything of an earlier run is still
on the preview: a run of the label still finishing, a run network record
naming the app's container, a run network the container is still attached
to, or a helper container of a run of the label. Only then does it open the
evidence run and answer, at once, with the run id; the run goes on in koid.

A request may carry an `idempotencyKey`. A retry with a key koid has seen
starts nothing and gets the first acceptance back, whether that run is still
going or has ended. koid keeps the key in the run's `controller.json` and loads
every key back at startup, so a retry after a restart finds the same run. Its
`leaseExpiresAt` is the latest the record holds, which a renewal may have moved.
A retry that arrives while the first request with its key is still being
admitted waits for that request and gets its answer, the acceptance or the
failure, and starts nothing. After a failure the key is free, so a later retry
starts again.

While a run goes, koid checks before each point that its lease still holds
and that the same deployment still serves. A lost lease interrupts the run.
The run's time limit bounds every operation, not only the gaps between
points. The setup is under it from the wait for the network lock to the
recorder's start, and a setup past the limit is rolled back. Each call to
the recorder and each Docker command gets what is left of the limit as its
timeout and an abort signal, so a call pending at the deadline is aborted
and one asked for past it is refused before it is made. A point whose
verifier had not started by the deadline ends `not-run` with reason
`run_deadline`, as do the points not reached. A point whose verifier was
running ends `blocked` with reason `point_timeout`, and what it reported by then
still counts. The run is still evaluated, since the limit is its own and no
capture error.

Stopping a verifier and removing it have to happen after the point has ended, so
no signal reaches those commands, and they get 60 seconds. Past that koi stops
waiting for them and judges the point on what it read, so a signed failure still
fails it. Beyond that, koid gives a verifier a limit from outside for anything else
that does not come back: 90
seconds past the latest it can be stopped, which is the point's budget, the 15
seconds of stop grace and the 60 seconds of handling, or the run's deadline when
that comes first. Past that the point ends `blocked`, since what it read is out of
koid's reach. Either way the reason is `verifier_stuck`, and the run does not go on
to the next point, since a run has one name for its verifier and the old one may
still be using it. With time left the run ends `interrupted`, and its teardown
removes what is left. What the old verifier tries to record once the run is
finalized is refused.

A point has a time limit of its own: its `budgets.timeoutSeconds`, or the
plan's `pointSeconds` when it names none, under the host's ceiling of 900
seconds and the time the run has left. A point may ask for more than the
manifest's value. The same number bounds the recorder calls, is the runner's
`KOI_TIMEOUT_SECONDS` and is what the supervisor keeps to. Each recorder call of
the point gets what is left of that limit as its timeout and an abort signal. A
capture or read refused at the limit stops the verifier then: koid's refusal says
nothing about the app, so nothing the runner reports after it counts. A point
that reaches its limit ends `blocked` with reason `point_timeout` and keeps what
it captured, and the run goes on to the next point; this is no capture error
either. koid closes the point's context under the run's limit. A navigation the limit cut short goes on
inside the recorder, so koid finds that context by the recorder's events and
closes it too. If the recorder still refuses the next point because a context
is open, the run ends `interrupted` with `recorder_unavailable`. When the point
has more time than the run has left, the end is the run's deadline, above.
The recorder may keep the raw bytes of a capture the limit cut short until the
recorder stops, within the recorder's own bound on what it holds.

The teardown then has its own allowance of 120
seconds, bounded the same way, and nothing in it waits longer. It looks for
what the run left, a network record in any state, a helper or a run network,
whether or not the setup succeeded, and the lease goes only once nothing is
left.

The teardown always starts, and no wait of a run on its disk has no end. koid gives
each thing a run has the disk do 60 seconds: a write and its sync, a read of one
artifact. A disk that takes longer has stopped answering, as far as the run can tell.
koid then stops waiting on that disk for the whole run: everything waiting ends at
once and nothing new starts, so what stops the run cannot queue behind the write that
did not come back. The point in progress ends `blocked`, unless the runner or the host
had reported a failure, which stands. A pass it reported does not count, since its
evidence cannot be checked. The run goes straight to its teardown, whether or not its
deadline has passed. The run ends `interrupted`, with outcome `incomplete` and an
`interruption` that starts with `evidence_unwritable:`, even when a cancel was asked
for. It writes no more records and has no manifest. koid keeps how it ended in memory
and answers from there until it restarts. Then the run reads as interrupted by the
restart, with the same outcome.

A write that comes back after that changes nothing. A record whose sync comes back is
not renamed into place, and a manifest that landed just as koid gave up is removed once
the disk answers. An event line already written stays in `events.ndjson`, where nothing
counts it without a manifest.

The rest of the state is on the same disk by default, so the teardown keeps away from
it where it can. The network's record is marked `destroying` beside the revoke and not
ahead of it, so the permits and the helpers go first. Each call to the preview store
gets 60 seconds too. A lease whose release the store does not take in that time stays
until it expires, since the store is the only place that holds it. If the record of the
run network cannot be removed, the teardown counts as failed, as any other failed step
does, and the next start cleans it up.

Every wait koid knows of ends by one of those limits. For one it does not know of, the
teardown starts anyway at 210 seconds past the run's deadline: the 90 a verifier may take
past it and two disk waits. The run ends `interrupted` with `run_stuck:`, the point in
progress ends `blocked`, and no later point starts. What those points do once they come
back changes no record.

A cancel that arrives during the teardown still counts: koid answered it
as `running` with `cancelRequested`, so the run ends `cancelled`, with no
`Result`, unless the teardown failed, which makes any cancelled run
`interrupted`. A cancel that arrives once the final records are being written
changes nothing and is answered with the state the run ended in. The lease is
taken for the limit and the allowance together, and is renewed before it
expires whenever the run's remaining budget outlives it, never past that
budget, so the lease and the run end together. koid touches the host
activity stamp every five seconds, so the box does not stop under a run.

### Project text and runtime text

The registry of secret values takes any value of 8 or more characters from
whoever can reach a preview's keys page. So what the registry holds never decides
what a project may say or how a run ends. koid treats text as one of two kinds.

Project text and koid's own values are not scrubbed against the registry, and are
never refused because of it. Project text is anything the project declares in
`.koi/`, or that comes from the git tree of the pull request: point ids, profile
names, file and runner paths, declared assertion names, notes, `why`, changed file
names, uncovered file names and image references. koid's own values are ids, digests,
times, enums and fixed words such as the browser name. These are written once, as they
are, so their digests hold. A declared point id or file name is in the project's repo and
in koid's input snapshot, so whoever wrote it already knew it. No hostile party can get a
secret into it through a run, because declared text is fixed before the run starts.

So a point whose id happens to match a registered value runs like any other: it is
opened, gets a verifier of its own, is judged, and its id stays in every record. The
same goes for a profile, a runner path, an assertion name or an image. `run.json` and
`execution.json` hold nothing else, so koid writes them without the sanitizer, and
registering `.koi/runners` or `chromium` changes none of them.

`execution.json` holds three things koid did not choose. The runner image's digest is
the id Docker gave it, which `DigestSchema` holds to a hash. The browser's version and
the Playwright version are what the recorder says of itself, once, before any page
opens, and the recorder is the operator's image and not the pull request's. The schema
holds each to a version's form, with no spaces and no separators, so neither can carry
a sentence, an error or `name=value`. A recorder that says anything else stops the run
before the file is written. The origin is the address koid gave the recorder, and a
recorder that answers for another is refused with `recorder_mismatch`.

`plan.json` and `planning.json` are written the same way, with one difference. A plan can
hold a little runtime text: in a blocked point's reason, why the box cannot verify, which is
what Docker or the helper said at startup, and why the runner image cannot run, which can
quote what Docker says of the image; and an error from reading the required policy or a
proof record, in `policy.advisory.error` and `notes`. koid scrubs these as the last step
before the digest, after all the glob matching and after Docker has answered, with nothing
to wait for between the scrub and the digest, so a secret koid learned during either does
not reach the plan. The digest then holds on every read. A secret koid learns after the
digest and before the two files are written stays in them, as with any record written before
koid learned a secret. That window is the time of two file writes. Each reply scrubs this
text again, as koid may have learned a secret since. The rest of the reply, and every other
reason, stays as the project declared it.

Runtime text is always scrubbed, with the registry and the credential patterns, when
it is written and when it is replied. Runtime text is what a page, a recorder, a
runner, Docker or an error says during a run: event fields, details, reasons, error
messages, interruption text, and all a runner says of its own: its log lines, notes,
assertion details, evidence references, capture labels, and any name it reports that
does not match a declared one. One function does this, `sanitizeRunData`
(`packages/daemon/src/verification-sanitize.ts`), with the secrets known at that
moment. The writer holds it and the store takes it as an argument, so nothing writes
such a record without it, and replies read a run only through `readRun`, which applies
it. It scrubs any field it has no name for, because a leak is worse than an ugly mask.
An event's fields are all scrubbed, their names too, and only its envelope stays: the
sequence number, time, source, type, point and attempt, which koid fills itself.
`report.md` holds both kinds, so koid renders it from one record that has been through
the function just before the file is written, and does not scrub the finished text. The
function cuts text to what its schema allows, and it cuts after the scrub, since a cut
made first can leave half of a secret. A refusal's message is an error's text, so it is
scrubbed too.

koid computes outcomes on what it received, before the scrub, so a registered word can
mask text but cannot change an outcome. koi reads a runner's line by the protocol's schema
before anything is scrubbed, and judges a point on what it read, so a reference still names
its artifact and a label still makes its capture, and a failing assertion still fails. A
required point that did not pass is still not passed. The readiness reasons are runtime
text, so one may read `required point [redacted] is blocked`, while the run's record still
names the point by its id.

A record's field names are koid's and never change. In a point's `observations.json`,
`assertions` is what the point declares and `asserted` is what the runner reported for each.
There `assertion` is a declared name and `outcome` one of the protocol's words, since the
verifier takes no other report, so both stay as they are. `cited` and `detail` are the
runner's, and are scrubbed. Its capture labels are a list of `{name, artifact}`: the name is
the runner's, and the artifact is koid's id.

The registry takes no value under 8 characters, so `pass`, `fail`, `steps`, `outcome`,
`blocked` and `pointId` cannot be registered at all. `evidence` and `assertion` can, and they
mask only text.

A scrub of a scrub changes nothing. The registry ignores a value when any of its forms
is part of the mask, such as `redacted` or `[redacted]`, so `docs/redacted.md` stays as
it is and that word is not masked anywhere. It also ignores a value that holds the whole
mask, such as `prefix-[redacted]-suffix`. No real credential holds that text, and masking
one would mean scrubbing a line again each time a mask completed it. It looks for other
values only between masks, the patterns run until nothing changes, and a cut never stops
inside a mask. An event read back and sent on is therefore the line on disk, unless koid
has learned a secret since.

A record is written once. koid does not rewrite a record because it learned a secret,
and a read writes nothing. `controller.json` and `status.json` are saved again as the
run goes and when recovery ends a run, and each such save passes through the function. A
point's `observations.json` is written again only when the last check of its evidence
changes its verdict. Runtime text written before koid learned a secret stays on disk until
retention ends, in koid's 0700 evidence folder. Replies mask it, with two results:

- A reply's event can differ from the line on disk. An export of that run then says
  `complete: false`, and `missing` names the events as differing from the manifest's
  digest. That is correct: the export holds what koid may say now, and the manifest
  hashed what was written.
- An artifact's bytes are returned as they are, even when they hold a secret koid
  learned after the capture, since they must hash to the manifest.

A plan-time check catches a real credential pasted into `.koi/`. Once, as it plans, koid
checks what the project declares against the credential patterns, never the registry:
every field of `verify.yaml`, every field and the file name of every point, the tree's
required policy and proof records, and any error from reading those two, since an error
can quote a file. A match refuses the plan with `declared_credential`, and nothing is
written. The message names where to look and quotes no project text, since a value can
stand in a file's name where no pattern sees it. For a point it says, for example, `point 3
of 12, counting the point files in the sorted order of their paths, field claim`. A point
that this plan would not select counts too, since the file is in the project either way.
koid does not check changed file names or the base branch, which are the pull request's
own, since a false match there would stop planning. It does not read runner files,
fixtures or `koi.yaml` for this: none of them reaches a plan.

A mask costs little and a refusal stops work, so the check is narrower than the scrub.
A fixed format always counts: a koi token, an AWS key id, a GitHub token, a Google key,
a JSON web token. A value that only starts like a provider's key must have a long run of
mixed characters, so `sk-learn-model-trains` and `xai-chat-completes` pass. A value after
a word such as `token` or a header such as `Authorization` must be at least 20 characters
of mixed case and digits, so `--token=$KOI_TOKEN`, `password=test` and a sentence such as
`password: must be long` pass. `sha256:` digests, commit ids and ordinary paths pass.

An image reference has a fixed grammar, so `runner.image` is held only to the rules that
know a key by its own shape. In `ghcr.io/acme/token:DevelopmentBuild20261103`, `token:` is
a repository and a tag, and it passes. An `AKIA` key id or an `sk-` key in the reference
is refused. `runner.command` is a command like a point's, so all the rules above apply to
each of its arguments. A runner file it names reaches a plan as a path in each point's
`runners`, and is checked there too.

### Outcomes

A run's status has three fields that say how it ended, and each means one
thing.

`state` is `running`, `completed` or `cancelled`.

`completion` says how the run reached its end:

- `evaluated`: the run ran to its end and was judged. Only this completion
  has a `Result` (`result.json`).
- `cancelled`: `koi verify cancel` stopped it.
- `interrupted`: the run could not go on. `interruption` says why: a lost
  lease, a recorder that did not start (`recorder_unavailable`) or stopped
  answering (`recorder_lost`, which includes a connection that drops while a
  reply is read), a teardown that failed, an identity that could not be
  confirmed at the end, a disk that stopped answering (`evidence_unwritable`),
  points still not done long past the deadline (`run_stuck`), or `koid_restarted`.
- `capture-error`: the run ran to its end, but its evidence is incomplete (a
  capture failed, a cap was reached, the recorder dropped events, a capture's
  file on disk is no longer the size and sha256 its entry records). No point
  can pass over missing evidence, so there is no `Result`.
- `empty-plan`: the plan selected no point. koid refuses to start such a
  run, so this completion is not seen today.
- `finalize-failed`: the run was judged, but its manifest could not be
  written. A bundle without a manifest counts for nothing, whatever was
  judged: the outcome is `incomplete`, the points keep what they had, and
  `finalized` is false. When the disk refuses this record too, koid keeps it
  in memory and answers from there until it restarts. `status` also reports
  any other terminal record without a manifest this way, whatever the record
  claims. A restart's `interrupted` record and an `evidence_unwritable` one are
  the exceptions, since neither ever has a manifest.

`outcome` is `passed`, `failed` or `incomplete`. It follows the `Result`
when there is one: `passed` when every point passed, `failed` when any
failed, `incomplete` otherwise. Every other completion is `incomplete`.

Each point ends in one of the six outcomes, decided by koid from what it
holds, in this order of precedence:

| Condition | Point outcome |
|---|---|
| An assertion reported `fail`; two terminal events for one assertion disagree; an assertion claimed a pass but its evidence is missing, withheld or failed, is not sanitized, does not hash to the manifest, or lacks a declared kind; evidence the point held no longer matches its entry on disk; the required cleanup failed or did not run | `fail` |
| koid itself could not run the point: a requirement the host does not give, no verifier, the point's time limit | `blocked` |
| A declared assertion has no terminal event (`not-run` reported counts as none) | `not-run` |
| The runner reported `blocked`, a claim koid could not confirm | `blocked` |
| The point's definition differs from the approved one, a required point has no proof, or an assertion asked for review | `needs-review` |
| Every assertion passed, but one passed after recovery or a retry | `pass-with-recovery` |
| Every assertion passed on its first path with available evidence of every declared kind | `pass` |

Every condition that applied is kept in the point's reason, in the table's
order, and the first row that applies decides the outcome; a failure is
never hidden by a later missing assertion. A point the host blocked never
started, so its cleanup not running is not held against it.

A point's evidence is every capture it made that koid kept, cited by a report or
not, whatever its outcome. A report's citation counts only for a capture of the
same point and attempt. koid checks each point's evidence on disk as the point
ends, and checks all of it again after the teardown, just before it judges the
run. A file that changed or went is a problem on the run (`artifact_corrupt`, `artifact_missing`), so the
run's evidence is incomplete and an otherwise finished run is `capture-error`.
The point no longer holds that file, and it ends `fail` with reason
`corrupt_evidence` or `missing_evidence`, whichever check found it and whatever
it had been. A file changed after that last check is not found by koid; the
manifest still records the size and sha256 it should have.

`readiness.eligibleForMergeGate` is true only when the run was evaluated and
passed, the plan was not advisory, the required policy came from the
protected base branch, every required point ran at its required revision
and passed with a verified proof, the run is current, the uncovered changes
have a maintainer disposition, and cleanup succeeded. `reasons` lists every
condition that failed. Today the policy source is always `none`, so it is
always false.

`freshness` is `current` while the deployment the run bound to still serves
the preview, `stale` once another does or the preview is gone, and
`unknown` when koid could not read the record. It is computed when status
is read; `controller.json` keeps the value at finalization.

### Exit codes

`koi verify run` exits 0 only for an evaluated run that passed and whose
bundle is finalized (`finalized` is true). It exits 1 for a run that failed
or is incomplete, which includes every cancelled, interrupted,
capture-error and finalize-failed run, and for a refusal from koid. `koi
verify plan`, `status`, `evidence` and `cancel` exit 0 when the operation
succeeded, 1 when koid refused it or the box could not be reached. Every
command exits 2 for invalid arguments, before touching the box.

### Routes and koid ctl

The CLI runs `koid ctl verify ...` through SSM, which returns the first
24,000 characters of a command's output, so every reply is at most 16 KiB
once serialized and a list that does not fit is paged with a cursor. koid
measures each reply once built. When the unpaged parts alone would leave
no room for a page, it cuts them (the problems, the readiness reasons, the
notes, the advisory policy, the manifest's limitations, free text) and
names what it cut in `truncated`; an entry of a page over 4 KiB is cut to
that (a long reason, an artifact's removed fields) and named too. The
records on disk are whole; only the reply is cut. A refusal is `{version,
error: {code, message, retryable}}`, with the message cut to 2 KiB and a
validation error naming at most 20 issues. The shapes are in
`packages/shared/src/verification.ts`; every reply has `version: 1`.

| Route | `koid ctl` | What it does |
|---|---|---|
| `POST /v1/verification-plans` | `verify plan <label> --profile <name>` | Plans; answers the first page, with `next` as `<list>:<index>` when more follows |
| `GET /v1/verification-plans/{plan}?after=` | `verify plan-page <plan> [cursor]` | The rest of a plan |
| `POST /v1/verification-runs` | `verify run <plan> <digest>` | Takes the lease, starts the run, answers 202 with the run id |
| `GET /v1/verification-runs/{run}/status?after=` | `verify status <run> [after]` | State, completion, outcome, readiness, freshness, a page of points, the first 20 problems |
| `GET /v1/verification-runs/{run}/events?after=&limit=` | `verify events <run> [after [limit]]` | Events after a sequence number, at most 200 a page |
| `GET /v1/verification-runs/{run}/evidence?after=` | `verify evidence <run> [after]` | The manifest's fields and a page of artifact entries; before finalization, the status and no entries |
| `GET /v1/verification-runs/{run}/artifacts/{id}?offset=&length=` | `verify artifact <run> <id> [offset [length]]` | At most 6 KiB of a finalized, available artifact as base64, with `next` and `truncated` |
| `POST /v1/verification-runs/{run}/cancel` | `verify cancel <run>` | Records the cancel; the run stops after the point in progress |

### Restart

At startup, before the control socket listens, koid marks every run the
last koid left `running` as `completed` with completion `interrupted`,
reason `koid_restarted`, and outcome `incomplete`. Its points keep the
outcomes they had; it never becomes passed, and it gets no manifest. A run
the last koid had judged but whose manifest it did not write is marked
`finalize-failed` and `incomplete` the same way, since a bundle without a
manifest counts for nothing. The run's network and helpers are removed by
the startup cleanup. Its lease is released only when that cleanup is known
to have run; otherwise it stays until it expires, and the log says so. koid
also loads back the idempotency key of every run on disk, finished ones
included (Starting a run).

## Recorder and evidence

A verification run gets a private network of its own on the box, a browser
koi owns inside it, a verifier container per point, and a directory of
evidence on the host that only koid writes. This section says what exists
for that today and what does not. The agent actions do not exist yet. What
exists is the network a run uses, the firewall around it, the recorder image
and the daemon's client for it, the verifier image and the runner protocol
(Writing a runner, above), the evidence store, the sanitizers, the input
snapshot every deploy keeps, and the controller that `koi verify run` drives
(Running a verification, above).

### Run network

- koid holds its lease on the preview (above) for the whole run, and the app
  keeps everything it has: its `koi-previews` address, its proxy settings and
  CA files, and Caddy's route. The run adds a second interface to the app's
  container and removes only that at the end. It never stops or recreates the
  app for the run network.
- The run network is a Docker bridge named `koi-v-<runId>`, internal, IPv4
  only, with inter-container traffic off and a bridge interface named `kv` and
  twelve hex digits. Its subnet is a /28 from the operator's reserved pool,
  `KOI_VERIFY_POOL`, allocated lowest first: the gateway is `.1`, the app `.2`,
  the recorder `.3` and the verifier `.4`. Each network has a record under
  `<stateDir>/verification/networks/<runId>.json` from before Docker is asked
  for anything until after the firewall has dropped the run's permits and
  connection state and the network is gone, so a subnet is never reused while
  anything of the old run could still match it, and koid finds at startup what
  a crash left. Startup removes every recorded network and every container,
  volume or network koid made for a run that has no record, going by name and
  label together.
- The recorder and the verifier are containers koi owns, created but not
  started, named `koi-verify-<runId>-recorder` and
  `koi-verify-<runId>-verifier` (the verifier is created again for each
  point, with that point's environment and inputs, at the same name and
  address), labelled `koi.role=recorder` or `koi.role=verifier` and
  `koi.run=<runId>`, with `koi.preview` set to
  nothing. Docker copies an image's labels onto its container and the
  verifier image is the project's, so the empty value is set on purpose: it
  overrides whatever the image carries (previews get `koi.role` set to
  nothing in the same way). What tells a helper from a preview is the name,
  which only koid assigns: a preview is `koi-<label>-<id>`, which never ends
  in a role, and carries a non-empty `koi.preview`. The preview reconciler,
  the disk watchdog and the death watch apply that rule (`isPreview` in
  `packages/daemon/src/docker.ts`), so none of them touches a helper, and a
  `koi.role` that a pull request's image put on a preview, which an older
  koid did not override, hides nothing from them. Startup cleanup asks more
  before it removes a helper: its labels must name the same run and role,
  and `koi.preview` must be empty (`helperOf`).
  Their flags are fixed in `packages/daemon/src/docker.ts` (`recorderArgs`,
  `verifierArgs`): a fixed address and MAC on the run network only, uid 10001
  or 10002, a read-only root, every capability dropped, no new privileges, a
  private IPC namespace, an init process, no restart, memory, CPU, process and
  file limits, no core dumps, a tmpfs for `/tmp` (and `/work` for the
  verifier), no Docker logs, and the shared slice. Both resolve
  `app.<runId>.invalid` to the app's private address through `/etc/hosts`, and
  their resolver forwards to the run's gateway, where nothing answers. Neither
  gets the daemon's or the app's environment, and a helper whose image
  declares a volume is refused. `KOI_PREVIEW_URL` for them is
  `http://app.<runId>.invalid:<appPort>`, the application path; public TLS,
  secure cookies and public-origin callbacks are not what a run tests.
- A verifier's inputs reach it through three Docker volumes, one each for
  `/koi`, `/workspace` and `/fixtures`, named `koi-verify-<runId>-inputs-<part>`
  and labelled `koi.role=inputs` and `koi.run=<runId>`. Docker refuses `docker
  cp` into a container with a read-only root (`container rootfs is marked
  read-only`), and the verifier's root stays read-only, so koid never copies
  into the verifier. It makes the volumes, creates a staging container
  (`koi-verify-<runId>-staging`, labelled `koi.role=staging`) from the same
  image with the volumes mounted writable, on no network, copies the inputs
  through it with `docker cp`, and removes it. The staging container is never
  started, so nothing in the image runs. The verifier then mounts the same
  volumes read-only, and koid checks after create that these are its only
  mounts. No host directory is mounted at any step. Three volumes rather than
  one with subpaths, since volume subpaths need Docker 26. The volumes and the
  staging container go when the point ends, and with the run's teardown or the
  next start if that fails. A point whose leftovers cannot be removed is
  blocked rather than run on them.
- The firewall permits exactly these connections, and their replies: recorder
  to the app's port, verifier to the app's port, verifier to the recorder on
  TCP 4317, and koid on the host (the `koi` user) to the recorder on TCP 4318.
  Everything else on a `kv+` bridge is dropped: new connections from the app,
  anything to the host, UDP, DNS, multicast, link-local, invalid packets, and
  all IPv6. Each permit names the run's bridge, the source address and the
  source MAC, and the source's bridge port once the container runs. A permit
  between two containers also names the port the packet must leave by
  (`--physdev-out`) once the receiving container runs. The rules
  live in three chains, `KOI-VERIFY` (from `DOCKER-USER`, so it sees bridged
  traffic before Docker's own rules), `KOI-VERIFY-IN` (from `INPUT`) and
  `KOI-VERIFY-OUT` (from `OUTPUT`), each ending in default denies. A run's
  permits go above the denies and carry a `koi-run=<runId>` comment.
- Below iptables, three things keep another container on the bridge from
  receiving what is meant for an endpoint. First, only plain IPv4 and ARP
  cross a `kv+` bridge. br_netfilter shows iptables a packet under one VLAN
  tag only with `net.bridge.bridge-nf-filter-vlan-tagged=1`, and a packet
  under two tags never, yet the receiving kernel strips tags with VLAN id 0
  and takes the packet. So ebtables' `FORWARD` jumps first to a chain,
  `KOI-VERIFY-L2`, that returns IPv4 and ARP and drops everything else:
  tagged frames, PPPoE and IPv6. The sysctl is on as well. Second, once an
  endpoint runs, its MAC is a static, sticky entry in the bridge's
  forwarding table on its own port (`bridge fdb replace <mac> dev <port>
  master static sticky`). The bridge learns where a MAC is from the source
  of every frame, ARP included, which iptables never sees, so without the
  pin a container that sent frames from the recorder's MAC would get the
  recorder's traffic. A sticky entry does not move. Third, the host keeps
  the recorder's address at the recorder's MAC as a permanent neighbour
  (`ip neigh replace ... nud permanent`). An ARP reply cannot change it, so
  koid's connection to the recorder on TCP 4318 always goes to the recorder's
  MAC, and from there only to its port. Between containers, an ARP reply can
  still make the verifier send the recorder's packets to another MAC; the
  bridge sends them to that container's port, and the permit's
  `--physdev-out` drops them there. The pins and the neighbour go with
  `revoke`, and a pin goes with its port when a container stops.
- koid cannot change iptables, so it asks a root-owned helper,
  `/usr/local/libexec/koi-verify-net` (`host/verify/koi_verify_net.py`,
  Python, standard library only), through `sudo -n`. A sudoers rule lets `koi`
  run exactly that path. The helper takes four commands. `provision`, run as
  root by `host/cloud-init.sh` and by the helper's installer, creates the
  three chains with their default denies and the jumps that reach them, or
  brings an older layout up to date: it builds a changed chain again beside
  the old one, moves the jump to it, and only then removes the old one, under
  the same lock as the other commands, so kv+ traffic is denied at every
  instant and a run's permits survive. It also puts `KOI-VERIFY-L2` and its
  jump first in ebtables' `FORWARD` (a changed chain gets the allowlist
  inserted above what it holds, the drop first), and sets
  `net.bridge.bridge-nf-filter-vlan-tagged` to 1. koi-firewall runs it at
  every boot, so both hold across reboots. `apply` takes one JSON descriptor on
  stdin (the run id, bridge, subnet, app port and three endpoints with role,
  container, address and MAC), checks every field against a fixed shape,
  refuses a subnet outside the pool or overlapping another run or a host
  route, checks the Docker network and each endpoint against Docker itself,
  removes the generation an earlier `apply` of the run installed, writes the
  run's state file, pins each running endpoint's MAC to its port and the
  recorder's address to its MAC on the host, and then installs the run's
  rules as one generation, so the installed rules are ones the state
  describes at every instant and a crash part way leaves nothing `attest`
  refuses. The helper binds a permit
  to a bridge port only once the container runs, so koid runs `apply` again
  after it starts the recorder, and after each verifier is seen running
  (`VerificationNetwork.reapply`). For a verifier, koid then requires the
  attestation to name its bridge port before it releases the runner. A helper
  older than koid prints no ports, so its points are blocked until the helper
  is installed again.
  `revoke <runId>` removes
  that generation and the pins on the run's bridge, and flushes the subnet's
  conntrack entries; the state file
  goes only once the flush has succeeded, and a revoke that finds rules
  without a state file records their subnet before it removes any of them.
  Both `apply` and `revoke` first finish or discard a chain swap an
  interrupted `provision` left, and `revoke` takes the run's permits from
  every `KOI-VERIFY` chain, a staged one included, so none survives for the
  next `provision` to rename back. `attest` prints the
  policy version, the pool, whether the chains end in their defaults and
  hold nothing above them but the permits of recorded runs, whether the
  jumps are reached before any rule that could accept kv+ traffic (`FORWARD`
  to `DOCKER-USER`, whose first rule must be the `KOI-VERIFY` jump; the
  `INPUT` and `OUTPUT` jumps; the IPv6 denies), whether `KOI-VERIFY-L2` is
  the allowlist and first in `FORWARD` (`bridge.guard`), whether every
  endpoint the state calls running has its MAC pinned to its port and the
  recorder its permanent neighbour, with no pin or permanent neighbour on a
  `kv+` bridge that no state describes (`bridge.pins`; a port that is gone
  is not looked for), the bridge filtering sysctls, the runs it holds and
  the bridge port each endpoint's permits are bound to. A missing chain is
  one the listing of the whole table does not name: iptables 1.8.10 on
  kernel 7.0 reports a chain that does not exist as "Incompatible with this
  kernel" once the filter table has an `OUTPUT` chain, a message it also
  gives for real errors. Listings are parsed into a canonical form,
  never compared as text:
  `iptables -S` prints a rule in its own order, with a `/32` on a bare
  address, upper case MACs and a quoted comment. Each option's values are
  read by count, so a comment of `!` or `-j` is a comment, and a rule with an
  option the helper does not know is reported, never passed as harmless.
- Verification is a capability of the box, not a requirement. At startup koid
  checks `KOI_VERIFY_POOL` (set, and a network address between a /16 and a
  /28; a wrong value is a reason, and koid still serves previews),
  the helper's owner and mode, and that `sudo -n` runs its
  `attest`. As soon as
  the helper answers, whatever it attests, koid removes what earlier runs
  left through it: the helper's `revoke` also finishes a chain swap an
  interrupted `provision` left, which `attest` reports as a problem until
  then. Only after that does koid judge the policy version, the pool the
  helper reads, the chains, the IPv6 denies, the layer 2 allowlist and the
  pins, `br_netfilter` and its sysctls (`bridge-nf-filter-vlan-tagged`
  among them),
  the slice, `KOI_RECORDER_IMAGE` and that the image is on the box, the
  recorder's seccomp profile, and that Chromium starts with its sandbox in the
  recorder image under the recorder's confinement (a `docker run` of the image
  with the recorder's user, read-only root, capabilities, limits, /tmp, shared
  memory and seccomp profile, on no network, running `dist/probe.js`, which
  launches Chromium as the recorder does, opens a page and closes it; this is
  what fails when the seccomp file is out of date or the host's AppArmor
  policy keeps containers from making a user namespace. The probe container
  is named `koi-sandbox-probe-<12 hex digits>` and labelled `koi.sandbox-probe`;
  koid removes it after, and removes any an earlier start left first of all,
  before the helper is checked, knowing one by the label and the name both,
  since a preview's image can carry any label),
  and log `verification: available` or
  `verification: unavailable (reason)`. A check that throws, such as a seccomp
  profile koid may not read, adds its reason to the others and the later
  checks still run. A leftover koid could not remove is one of the reasons,
  with the run and the step that failed; the rest of the cleanup still runs,
  and the next start tries the leftover again. A record
  koid cannot read or parse is a reason too, naming the file. What its run
  left in Docker and in the helper still goes, and the file stays until the
  operator has looked at it and removed it, since koid cannot tell which
  subnet it held. Last, the cleanup asks the helper which runs it holds and
  revokes any that koid has no record of; one it cannot revoke is a reason,
  naming the run. A box provisioned before this keeps serving previews and
  reports unavailable.
- The firewall unit koid requires, `koi-firewall.service`, does not depend on
  verification. It installs the preview rules first, and a failure there stops
  koid. It then loads `br_netfilter`, sets its three sysctls and runs the helper's
  `provision`, and a failure in any of those is logged in the unit's journal
  and does not fail the unit: koid starts, serves previews, and the check above
  reports what is missing. Nothing is left open by that. The denies match only
  `kv+` bridges, only a run network makes one, and nothing makes a run network
  on a box whose capability is unavailable.

### The recorder

The recorder is the browser a run is recorded with: one container per run
from the image in `host/recorder/`, built from Microsoft's Playwright image
pinned by digest, with Chromium and a small Node server, running as uid
10001 on a read-only root. koid starts it, waits for it on TCP 4318 through
the run network, has the firewall bind the run's permits to its bridge port,
and then drives it over that port with a bearer token made for the run. The
recorder never writes to Docker logs; what it has to say goes into an event
feed koid reads.

Two ports, two tokens:

- TCP 4318 is koid's control port. Every request carries the run's control
  token, which only koid holds. Routes: `GET /health`; `POST /contexts` opens
  a point's browser context, with its first page at a path on the app's
  origin when asked; `POST /contexts/:id/captures` takes a screenshot, an
  aria snapshot, or the context's console or network observations so far;
  `POST /contexts/:id/reads` requests a path from the app from inside the
  context and keeps the reply; `GET /captures/:id` returns a capture's raw
  bytes and `DELETE /captures/:id` acknowledges them, at which point the
  recorder frees them; `GET /events` pages the event feed;
  `DELETE /contexts/:id` closes the context. One context is open at a time.
  Raw captures are held in the recorder process's memory, never on its
  filesystem: Chromium and the server share uid 10001, so a file under
  `/tmp` would be readable through the browser. They are bounded, 32 MiB
  each and 256 MiB together; a run that captures faster than koid
  acknowledges fails its captures rather than grow.
- TCP 4317 is the browser port for the verifier. Chromium's DevTools endpoint
  listens on the container's loopback; a proxy in the recorder puts the run's
  browser token in its path and reads each message on the way in. A
  Playwright client connects with `connectOverCDP` and the ws URL koid gives
  the verifier, finds the context's pages in `browser.contexts()`, and drives
  them. The proxy forwards only the DevTools methods on the allowlist in
  `host/recorder/src/cdp-allowlist.ts`: what the pinned Playwright client
  sends to connect, to drive a page, and to open a raw session on one with
  `newCDPSession` (Target attach and detach, including a session on the
  browser target, Page, Runtime, Network observation, Emulation, Input, DOM
  queries, Log), and nothing else. The allowlist carries an audit table
  naming every method whose params can point at a file, a URL or a target
  off the page, what the proxy checks on each, and why it is safe.

  What is refused. Every method not on the list gets a DevTools error: among
  them tracing, creating or disposing browser contexts, exposing the protocol
  to page scripts, closing or crashing the browser, setting file inputs
  (`DOM.setFileInputFiles`), the Fetch domain (the recorder uses it itself,
  below), streams (`IO`), cookie storage, and loading a resource outside a
  page (`Network.loadNetworkResource`). Three more are refused though the
  pinned client can send them. `Input.dispatchDragEvent`, because its
  `data.files` hands host files to the page on drop and the runner does not
  drag-and-drop in version 1. `Target.closeTarget` and `Page.close`, which
  the client sends for `page.close()` and for
  `page.close({ runBeforeUnload: true })`, because every target the client
  can reach is in the recorder's own run context and the recorder owns page
  and context lifecycle in version 1. Setting a cookie for any origin but the
  app's is refused. `Target.sendMessageToTarget`, the wrapped form of a
  nested message, is refused. A refusal is answered on the session the
  request named, so the client's pending call rejects with the reason, and
  it is written only between the browser's messages, never inside a frame
  the proxy is still forwarding in chunks. One caution for verifiers: the
  pinned client swallows the error inside `page.close()`, so
  `page.close({ runBeforeUnload: true })` returns without closing and a
  plain `page.close()` waits for a close that never comes. A verifier
  leaves pages open; koid closes the context.

  What is checked. `Page.navigate` and `Target.createTarget` may name only an
  `http:` URL or `about:blank`; a `javascript:`, `data:`, `blob:`, `file:` or
  `chrome:` URL is refused with a protocol error and a `client-denied` event,
  so a navigation cannot run script or open a local file. The origin of an
  `http:` target is still the guard's call. `Target.createTarget` is allowed
  only with the run's own browser context id, and a target that appears in
  any other context is closed by the recorder at once and reported as
  `foreign-target`. Each session is bound to the connection: the proxy reads
  the `Target.attachedToTarget` events Chromium sends this client and records
  every session id it hands out, and a client message carrying a session id
  the proxy never handed out is refused before its method is read, so a
  forged or guessed handle reaches no target, screenshots and evaluation
  included. Only a top-level event counts, a message with no `id`; a result
  that returns such an event by value, as `Runtime.evaluate` can, is told
  apart by its `id` in the first bytes of the frame and hands out nothing,
  whatever its size, and nothing the browser sends switches the check off.

  What is rewritten. `Browser.setDownloadBehavior` and
  `Page.setDownloadBehavior` go through as `deny`, because the Playwright
  client sends one on connect, so no client gains download control.
  `Target.attachToTarget` and `Target.setAutoAttach` go through with
  `flatten: true`, so a message for an attached target is a top-level message
  with a session id and is checked by the same rule; only `flatten` is
  forced, because the guard auto-attaches on its own connection with
  `waitForDebuggerOnStart: true` and so, not the client's flag, decides when
  a new target may run.

  The design asked for a broker speaking Playwright's own protocol; version 1
  serves DevTools instead, because that is the one path on which both the
  client and the recorder's own Playwright see the same pages. One power is
  by design: through the allowed `Runtime` methods the verifier can run any
  script in the page, which is what a runner does. That leaves two claims,
  and they are not the same claim.

  The network boundary holds. No request leaves the app origin: the origin
  guard fails any request the page or its script makes off the origin, the
  dead proxy fails any the guard somehow missed, and the firewall keeps
  packets in the run network. With `Fetch` refused the client cannot route
  or fulfil requests, and with `Target.createBrowserContext` refused it
  cannot open a context the guard does not cover.

  Content provenance does not follow from that. The verifier's script can
  author what the page shows: it can replace the document, build `data:`
  and `blob:` subresources the guard never sees because they make no
  request, and start navigations within the origin without `Page.navigate`.
  So a screenshot or an aria snapshot proves what the browser rendered at
  that moment, not what the app served. The evidence of what the app served
  is a state read: `POST /contexts/:id/reads` fetches a path from the app
  from inside the context, with the context's cookies, and keeps the raw
  reply as an `http-response` capture that no client script touched.
  Verifiers that need provenance pair a capture with a read.

Two layers keep the browser on `http://app.<runId>.invalid:<appPort>`, and
both are inside the recorder; the OS firewall around the run network is what
keeps packets in.

- The origin guard (`host/recorder/src/guard.ts`) holds a DevTools
  connection of its own to Chromium's loopback endpoint, attaches to every
  target the browser makes (pages, frames, workers, in any context, each
  paused until the guard is on), and enables the `Fetch` domain at the
  request stage. Every request, redirects included, pauses there and is
  continued only when its URL is on the app origin: the same host and port
  over `http` or `ws`, compared as canonical origins, so port 80 matches
  whether or not it is written; blank pages and in-memory `data:` and
  `blob:` resources are allowed too. Anything else fails with
  `BlockedByClient` and is reported as `denied`, with `what: redirect` when
  the app redirected there. This is the layer that gives a readable
  denial. The recorder's own Playwright route is not used for this, since
  the pinned Playwright skips route handlers for redirected requests.
  WebSockets do not pass through `Fetch`; the context's WebSocket route
  checks them with the same rule. The guard sees requests, so a navigation
  that makes no request, a `javascript:` URL, is not its to catch; the proxy
  refuses those navigations above, so the two layers together keep the page
  on the app origin.
- Chromium's proxy setting (`proxyArgs` in `host/recorder/src/origin.ts`):
  `--proxy-server=127.0.0.1:1`, where nothing listens, with
  `--proxy-bypass-list` naming only the app's name and `<-loopback>`, which
  removes Chromium's implicit bypass of localhost. A navigation or fetch to
  an IP literal, to `127.0.0.1`, to the host's services or to any other name
  goes to the dead proxy and fails at the network layer, whatever the guard
  did. The host resolver rule fails every name but the app's as well.

Every context the recorder opens also blocks service workers, refuses
downloads, and records console messages, page errors, navigations, dialogs,
popups and crashes. A target Chromium opens outside the recorder's contexts
is closed and reported as `foreign-target`, and the run records it as a gap:
evidence from a page the recorder could not see does not exist. A target
the guard could not enable `Fetch` on is reported as `guard-unavailable` and
recorded as a problem; the proxy layer still holds it. The recorder also
watches the browser and the guard's DevTools connection. If either closes
without the recorder closing it, the recorder emits `recorder-failed` with the
reason, `GET /health` answers 503 with that reason, and a new context is
refused. koid reads the event on its next drain, the last of which comes when
it stops the recorder, so a browser that dies after the last capture still
leaves the run incomplete. The recorder keeps
at most 10,000 console and 10,000 network observations per context; the
first one dropped past that is a `dropped` event, which the run records as
a problem, so the evidence is incomplete rather than silently short. The
event feed itself is a ring of 20,000. A page koid reads reports how many
events after its cursor the ring lost, which the run records as an
`observation_gap`; an eviction of an event koid had read is not one. A
string field of an event over 4,096 characters is discarded whole and
replaced by a fixed marker, with the field named in the event's
`truncatedFields`. The recorder knows no secret values and cannot redact,
and a cut would keep most of a secret past it. koid records a limitation
on the run when it reads one.

### What is captured, and how it is sanitized

koid asks for captures; the recorder holds them in memory; koid reads the
raw bytes, runs the kind's sanitizer, hashes and writes the result, and only
then acknowledges, so the raw bytes go. Hash and size in the manifest are of
the sanitized bytes. The sanitizers (`packages/daemon/src/sanitize.ts`,
`redact.ts`) and what each cannot do:

- `screenshot`: a PNG of the viewport, with every password field masked
  before the pixels exist, in the main frame and in each child frame, since
  a mask on the main frame does not reach into an iframe. The frames are
  listed once, so a frame attached after the listing has no mask. The
  recorder watches frame attach and detach events from before the listing
  until the pixels are back, discards the screenshot if any fired and takes
  it once more. If the frames changed again it fails the capture
  (`frames_changed`), which koid records as a failed entry with a
  `capture_failed` problem. No screenshot with fewer masks than frames is
  ever kept. The file's structure is
  enforced: the signature, exactly one 13-byte `IHDR` first, at least one
  `IDAT`, an empty `IEND` last with nothing after it, every chunk length
  within the file, and a valid CRC on every kept chunk; anything else is
  withheld. Every chunk but
  `IHDR`, `PLTE`, `tRNS`, `IDAT` and `IEND` is removed and named in
  `removedFields`. Pixels are not decoded or inspected: they may show
  anything the page did.
- `aria`: the page's accessibility snapshot as text, scrubbed line by line.
- `console`: the context's console messages as JSON lines, scrubbed.
- `network`: one JSON line per request with method, scrubbed URL, resource
  type, whether it was a navigation, what it redirected from, times, status
  and failure. Request headers and every body are omitted. Response headers
  are reduced to `content-type`, `content-length`, `content-encoding`,
  `cache-control`, `location`, `date` and `x-request-id`. Every string the
  app or the page chose is scrubbed and cut to 4 KiB: the method, the
  resource type, the failure text, header values, and the names of the
  dropped headers that go into `removedFields`, since a header named after
  a secret would otherwise carry it into the manifest.
- `http-response`: a state read the recorder made from inside the context,
  with the context's cookies. Status and the same allowlisted headers are
  kept, the method and header names scrubbed as above; the body only when
  the point's policy asks for it, within the policy's bound, as text (never
  binary), scrubbed.

`removedFields` is bounded to what a manifest entry holds, 1,000 names of
200 characters; a longer list ends in a fixed entry that says names were
left out. An entry the manifest schema still refuses is never published:
the pending file is removed, the run gets an `artifact_invalid` problem,
and the entry is recorded as failed.

Scrubbing replaces the exact secret values koid knows while it runs, in
their plain, URL-encoded, JSON-escaped and base64 forms, and then the
credential patterns `redact.ts` has always masked, now with preview login
keys among them. The known values are the keys and koi tokens that pass
through the keys page and the previews' login keys, registered the moment
the deployer makes one, before any container sees it; they live in memory
and are never written. The registry holds 10,000 values. Past that the
oldest go, and koid's log says so, since a sanitizer may then miss one of
them; the bound is there because the keys page registers values for anyone
the egress proxy admits. Every event koid writes to a run goes through the
registry, its own events included, since a page's final URL after a
redirect can carry a login key. Every string in an event is scrubbed, at
any depth, the names of its fields included: a field whose name scrubs to
another name is written under that name, and two that scrub to one name
keep the first. Text goes through the scrubber one complete line at
a time, however it arrives, so a value split across two chunks is seen
whole; a line over 64 KiB is discarded and replaced by a fixed diagnostic
that carries nothing of it.

What the line scrubber does not catch:

- A secret split across two records. Each console message and each network
  event is its own line; a value whose first half ends one record and whose
  second half starts the next is not seen whole, and neither half matches a
  known value or a credential pattern on its own.
- A secret in an encoding other than the ones generated for it. Only the
  exact plain, URL-encoded, JSON-escaped and base64 (padded, unpadded and
  URL-safe) forms of a registered value are matched. A value the app
  hex-encoded, compressed, split with separators, reversed, or encoded twice
  passes, as does one inside a binary body or a pixel.
- A secret koid never learned. Only values that passed through the keys
  page or that the deployer made are registered; a credential the app
  holds on its own is found only if it matches a credential pattern.

"Sanitized" means the stated policy ran, not that the artifact holds no
sensitive data. Each artifact's manifest entry carries the digest of the
policy that ran, the fields it removed and the limitations of that policy,
and the run's manifest copies the limitations.

### What is withheld in version 1

`trace`, `har` and `file` captures are accepted by the API and always
recorded as `withheld`: an entry with the reason, no payload, and no usable
evidence reference. A Playwright trace is an archive of actions, snapshots,
resources and sources that no sanitizer here accounts for entry by entry; a
HAR carries every header and body of the session; and a file would be
whatever the runner chose, which only the runner could vouch for. There is
no video. A required assertion whose evidence is withheld cannot pass.

### Evidence layout

Under `<stateDir>/verification/`, directories 0700 and files 0600 (0700 for a
snapshot file executable in the tree, so a point can run it by path), written by
koid alone and seen by no container:

```text
inputs/<deploymentId>/snapshot.json     what the build had (below)
inputs/<deploymentId>/source/.koi/...   the copied verification files
inputs/.pending-<deploymentId>/         a snapshot being copied
plans/<planId>/plan.json                the strict Plan
plans/<planId>/planning.json            the plan reply: reasons, policy, limits
runs/<runId>/run.json, plan.json, execution.json
runs/<runId>/controller.json            how the run ended, points, the lease, the idempotency key
runs/<runId>/status.json                state, evidence completeness, problems
runs/<runId>/events.ndjson              host-sequenced, sanitized events
runs/<runId>/points/<pointId>/observations.json
runs/<runId>/artifacts/<artifactId>     sanitized bytes only
runs/<runId>/result.json, report.md
runs/<runId>/manifest.json              written last
runs/<runId>/.pending/                  atomic writes in progress
```

Every file is written whole into `.pending/`, fsynced and renamed into place,
so a reader sees the old file or the new, never half of one. `manifest.json`
goes last, once every artifact, the status and whatever result and report
exist are durable; a run directory without one is not a completed bundle.
Artifact ids are `recorder:<kind>:<n>`, counting up within the run and never
reused; the store derives the file from the id, and the id names no path.
Accepted bytes are never changed. The shapes are in
`packages/shared/src/evidence.ts`: the artifact entry (id, run, point,
attempt, kind, media type, size, sha256, origin, time, event range,
redaction with its status, policy digest, removed fields and limitations,
availability, retention), the run status, the execution descriptor (images
by digest, browser, policy source, proofs, origin mode, limits, the runner's
capabilities) and the manifest. The capabilities always include `raw-cdp`: the
browser port gives every run's verifier a DevTools connection, whether or not
it uses one, so koid sets it when the recorder session starts. There is no
capability for request interception, because the recorder refuses `Fetch`.

### Retention and caps

Run evidence stays 30 days after the manifest is written, or 90 when an
operator pins the run; then the artifacts, events and records go and a
tombstone stays with the manifest, the status and `controller.json` until
180 days, so a verdict stays explainable after its evidence is gone: the
run's status still answers, its artifacts answer 410. A run that never got
a manifest and an input snapshot go after 30 days; a plan after 180, with
the manifests that name it. A snapshot koid was killed while copying stays in
`inputs/.pending-<deploymentId>/` and goes once that directory has not changed
for an hour, which is longer than any snapshot takes. koid sweeps at startup
and every hour.

A run may keep 512 MiB of artifacts, 32 MiB per artifact, 10,000 artifacts
and 10,000 events, and a run is not started unless the evidence filesystem
keeps 5 GiB or 10 percent (at most 20 GiB) free, whichever is larger, over the run's
allowance and over the allowances of every run still open: each open run
holds a reservation of 512 MiB from admission until it finalizes or is
abandoned, so two runs admitted together are not promised the same bytes.
Reaching a cap stops capture: the entry is recorded as failed, the run gets
a `cap_exceeded` problem, its evidence is incomplete, and it cannot pass.
The artifact count counts every entry, withheld and failed ones included;
past it no entry of any kind is recorded, and the cap never exceeds what
the manifest schema holds. The byte cap counts the bytes of artifacts
still streaming in with the bytes kept: a write reserves its size before
a byte is written, a whole body at once and a stream chunk by chunk, so
two captures each under the cap cannot together pass it. Events are
appended one at a time, so the event cap holds however many are appended
at once. The status holds 1,000 problems. The last place
goes to a fixed `problems_capped` entry and later problems are not
recorded, so a run with any number of them still writes its status and
finalizes, as incomplete. Nothing is truncated to fit, and
every byte of an artifact or an event is written or the file is removed:
a short write is never accepted. An event whose write fails part way is
cut out of `events.ndjson`, back to the last whole line, and the run gets
an `event_write_failed` problem. An artifact whose file fails to close, or
whose rename into place fails, is removed from `.pending/`, and one whose
directory sync fails after the
rename is removed from `artifacts/`, so the disk never holds more artifact
bytes than the run counts; one that cannot be removed keeps its bytes
reserved under the run's cap and gets an `artifact_orphaned` problem. A
failed write gives its reservation back only once its file is gone, so an
overlapping write cannot take those bytes while they are still on disk. These
are application caps, not filesystem quotas.

Expiry is idempotent. A sweep interrupted after it wrote a run's tombstone
but before it removed the evidence is finished by the next sweep, which
finds the tombstone and the leftover files together and removes the files.

Besides caps, the run records as problems, and so as incomplete evidence:
a recorder that dropped events before koid read them, or whose last events
koid could not read when a point closed or the recorder stopped
(`observation_gap`); console or network observations the recorder dropped
past its per-context limit (`observations_dropped`); a target outside the
recorder's contexts (`unobserved_target`); a target the origin guard could
not cover (`origin_guard_unavailable`); a page crash; an artifact entry the
manifest refused (`artifact_invalid`); an artifact file on disk but not
counted, which the store could not remove (`artifact_orphaned`); an event
the store could not write (`event_write_failed`) or that was too large to keep
(`event_oversized`); a capture that failed;
a recorder that was healthy and then failed (`recorder_failed`) or
stopped answering (`recorder_unavailable`) before the session was up; and a
recorder that lost its browser or the origin guard's connection at any later
time (`recorder_failed`).

### Input snapshot

A build's directory goes when the build ends, so every deploy now copies
what a run of it will need into `inputs/<deploymentId>/` before the cutover:
the files `loadVerifyConfig` reads (`.koi/verify.yaml`, the point files, the
runner files), every fixture the points declare, the skills' files and
`.koi/koi.yaml`, the changed-file list the CLI wrote to
`.koi-runtime/changed-files.txt`, and in `snapshot.json` the request's
identity (id, repo, commit, branch, pull request, merge), the recipe, the
source archive's digest and size, the loader's digests over the copy, the
fixtures' digests and sizes, and when it was taken. A repo recipe is
recorded by the digest of the request's copy. A built-in recipe is recorded
by its name, the digest of every regular file in its directory on the box
(`recipe.json`, the Dockerfile, the scripts the build used), and a digest
over the two, so a change to the installed recipe changes the snapshot
although the request did not change. The deployer copies the installed
directory into the build's own directory before the build, hashes the copy,
and builds from it: the Dockerfile and the `recipe` build context are
resolved inside the copy, never the installed directory, and the settings
the build and the container take from `recipe.json` (the Dockerfile's path,
the context, the port, the env, the user, the timeouts, the login key's
variable) are read from the copy too, so the deployment and the snapshot
describe the same bytes. What koid read from the installed directory when
it accepted the request decides only the record's ttl and whether a login
key is made then; when the copy names a login key variable and the
installed recipe did not, the build makes the key before the container
starts. The digests go to the snapshot. `scripts/deploy-host.sh` replaces the installed recipes
before it restarts the old koid, so a build that read the installed
directory could mix two versions, and a hash of it could be of a version
the build did not read; the copy goes with the build directory. A symlink
in the recipe refuses the digests, and with them the snapshot. The copy
is loaded again after it is made and must give the digests the original did.
Nothing is ever taken from the running container. Before the loader opens
anything, `.koi/` is counted. More than 2,000 files or 64 MiB in it makes
the snapshot say `invalid` without a file read, since the loader holds
every file it reads. The loader's files are copied within its own 256 KiB
bound, fixtures at 16 MiB each and 64 MiB together, the changed-file list
at 1 MiB. A verifier's input volumes hold the snapshot under `/workspace` and a
copy of each fixture its point requires under `/fixtures`. A fixture counts once
against the 64 MiB, so a snapshot that was taken can run. What the volumes take on
disk is at most twice that, plus tar's headers and the two small files under
`/koi`, since `/fixtures` holds only files of the snapshot, each once however often
a point lists it. A run has one verifier at a time, and its volumes go before the
next is filled. A project
without `.koi/verify.yaml` gets a snapshot that says `absent`; one whose
files do not load gets `invalid` with the loader's message. Before the rename
that publishes a snapshot, koid fsyncs every directory in it, deepest first,
and it fsyncs `inputs/` after the rename, so a power cut cannot leave
`snapshot.json` without the directories it names. A snapshot that
cannot be taken is logged in the build log and does not fail the deploy; a
run of that deployment is then refused for want of inputs.

### Settings

`KOI_VERIFY_POOL` (no default; provisioning writes it to
`/etc/koi/verify/env`, which `koid.service` reads), `KOI_VERIFY_HELPER`
(default `/usr/local/libexec/koi-verify-net`), `KOI_RECORDER_IMAGE` (no
default; the id Docker gives the image built from `host/recorder`, or a
registry reference pinned with `@sha256:`; verification is unavailable
without it), `KOI_RECORDER_SECCOMP` (default
`/usr/local/share/koi/recorder-seccomp.json`, a copy of
`host/recorder/seccomp.json`, which lets Chromium's own sandbox make the
user namespace it needs; never `--no-sandbox`), `KOI_VERIFIER_IMAGE` (no
default; the image built from `host/verifier`, in the same forms as the
recorder's; verification is unavailable without it; a manifest names it as
`koi-verifier`) and `KOI_VERIFIER_IMAGES` (default empty; references or
digests of other runner images a manifest may name, separated by spaces or
commas; each must already be on the box, since koid never pulls one).

What the operator does on a box that exists: run `scripts/provision-host.sh`
(installs the sysctls, the sudoers rule, `conntrack`, and
`/etc/koi/verify/env` with the pool from `var.verify_pool`, default
`10.213.0.0/20`, and runs the helper's `provision` when the helper is
installed), then `scripts/deploy-host.sh` (installs the helper, runs its
`provision` and restarts koid). Set `verify_pool` in `infra/koi.auto.tfvars`
(or the module call of another root, and `KOI_VERIFY_POOL` for
`provision-host.sh`) first if the default overlaps a network the box can
reach. For the recorder:
build the image on the box (`docker build -t koi-recorder:1 host/recorder`),
copy `host/recorder/seccomp.json` to the seccomp path, add
`KOI_RECORDER_IMAGE=<the image id>` to `/etc/koi/verify/env`, and restart
koid. For the verifier: build the image on the box
(`docker build -t koi-verifier:1 host/verifier`), add
`KOI_VERIFIER_IMAGE=<the image id>` to `/etc/koi/verify/env`, and restart
koid. To let a project name another image, put it on the box yourself
(`docker pull` by digest, or a build) and list it in `KOI_VERIFIER_IMAGES`.

### Packet tests

`host/verify/packet-test/run.sh` sends real packets through two run networks
and checks each flow against the rules in "Run network". Run it as root on a
box set up like the real one, after `host/verify/install.sh`. Stop koid
first, since koid's startup removes run networks it did not make. On a
deployed box the files are under `/usr/local/share/koi/verify/packet-test/`.

```sh
sudo systemctl stop koid
sudo host/verify/packet-test/run.sh
sudo systemctl start koid
```

The test runs `provision` twice and checks that the ruleset, ebtables
included, does not change. It then builds two runs with the same `docker`
arguments as `packages/daemon/src/docker.ts`, the same addresses and MACs,
and the same `apply` calls through `sudo -n` as `koi`. The recorder and the
verifier are a small stand-in image, since the network is what is tested.
Probes run in each container's network namespace through nsenter. Once the
verifiers run, it checks that `KOI-VERIFY-L2` is first in ebtables' `FORWARD`,
that `bridge-nf-filter-vlan-tagged` is 1, and that each endpoint's MAC is
pinned to its port and the recorder is the host's permanent neighbour.

A privileged attacker container on the same bridge forges the other
endpoints' addresses and MACs. It sends packets under one VLAN tag, under two
(802.1Q twice, and 802.1ad outside 802.1Q) and inside PPPoE. And it tries to
read three permitted flows while they carry markers: the verifier to the
recorder on TCP 4317, the recorder's replies, and `koi` on the host to the
recorder on TCP 4318. It tries two ways: frames from the recorder's MAC, a
gratuitous ARP among them, so the bridge learns that MAC on its port; and
ARP that tells the verifier, the recorder or the host that an address is at
the attacker's MAC. At the end the test revokes one run as koid does, checks
that its pins and the neighbour are gone, and checks the helper's refusals.

Every target gets a listener first, so a drop is told apart from nothing
listening. A flow counts as dropped when the client got no answer, the
listener saw nothing, and a deny rule's packet counter went up: an iptables
deny, or the drop at the end of `KOI-VERIFY-L2`. A run network
has no route off its /28, so for targets off it the test adds a route through
the gateway in the probing namespace. The firewall is then what stops the
packet.

The test prints one line per flow: what it expected, what it saw, and how.
`GAP` marks a limit this page states, the time before a container's permits
bind to its bridge port and its MAC is pinned, and does not fail the run. The exit code is 1 when
any line fails. `--keep` leaves the networks for inspection, `--verbose`
prints the rules after `apply`, and `--cleanup` removes what a killed run
left.

### What is not here yet

The agent actions (`verify act`), the trusted required policy from the base
branch, proof verification, the pull request comment publisher, provider
request budgets in the egress proxy, a login key for runners, and fixtures
registered with the recorder.

The packet tests ran twice, on Ubuntu 24.04 with kernel 7.0.0-1014-aws,
Docker 29.10.0 and iptables 1.8.10 (nf_tables). The first run found three
problems. All three are fixed (see "Run network"):

- The helper could not run `provision` a second time, or `apply` or `revoke`
  at all. On that kernel, iptables reports a chain that does not exist as
  "Incompatible with this kernel" once the filter table has an `OUTPUT` chain.
  `attest` still worked, so koid reported verification available and every
  run failed at `apply`.
- A UDP datagram under an 802.1Q tag with VLAN id 0 reached the recorder,
  since provisioning left `bridge-nf-filter-vlan-tagged` at 0.
- A container that sent frames from the recorder's MAC read the verifier's
  data to TCP 4317, since a permit named the source's bridge port only.

The second run used the fixed helper, unpatched: 128 checks, none failed,
and the one `GAP` line. It also tried what the first run did not. A packet
under two VLAN tags reached the recorder's socket with the sysctl at 1, which
is why `KOI-VERIFY-L2` exists; it is now dropped. A PPPoE frame reached the
recorder's port but no socket, since the receiving kernel has no PPPoE
session, so `bridge-nf-filter-pppoe-tagged` stays 0 and the allowlist drops
those frames. Frames from the recorder's MAC no longer move it, so the
verifier's flow and koid's flow to the recorder both kept their data. ARP
that pointed the verifier, the recorder or the host at the attacker's MAC
got the attacker nothing. Between containers the misled flow stalls until
the sender's ARP entry is right again, since `--physdev-out` drops its
packets. koid's flow to the recorder carried on, since the host's neighbour
for the recorder is permanent. A `koi verify run` with koid on the same box
passed one point and failed the other, as the points say, and left no rule,
pin or neighbour behind.

Runs with one protection taken out of a copy of the helper showed what each
one is for. Without `--physdev-out`, ARP led the verifier's data and the
recorder's replies to the attacker. Without the permanent neighbour, ARP led
koid's data to it. Without the pins, frames from the recorder's MAC led
koid's data to it; the verifier's flow only stalled, since `--physdev-out`
held. Without `KOI-VERIFY-L2`, packets under two VLAN tags reached the
recorder's socket.

These attacks need a container that can send raw frames. The app, the
recorder and the verifier cannot: each has every capability dropped, and the
test checks that. One limit stays, the `GAP` line: before a container first
runs, its permits name no bridge port and its MAC has no pin. The same holds
after a container stops and before `apply` binds its next start, since a pin
goes with its port.

The recorder's Chromium sandbox needs the host to allow
unprivileged user namespaces inside the container; that is part of the host
configuration still to be pinned and tested, and the Docker-gated
integration tests (`packages/daemon/test/recorder.integration.test.ts`,
`packages/daemon/test/verifier.integration.test.ts`) are where it shows.
koid's sandbox probe passed on the host above.
The design's runner protocol had four events; this version adds `read`,
because a point whose assertion declares `http-response` evidence had no
way to ask for it.

## What the loader checks

`loadVerifyConfig(root)` reads `.koi/verify.yaml`, expands the point globs,
parses each point, finds each point's runner files, and returns the manifest,
the points by path with their runner files and digests, and the sha256 of
every file it read, keyed by path. It opens each file without following a
symlink in its last segment and takes the size from the open file, so a file
swapped for a symlink after it was listed is refused and a file that grows is
read to the limit and no further. It expects a static tree, which an
extracted tarball is. It refuses:

- a `.koi/` that is a symlink, or a symlink anywhere under it, to a file or to
  a directory, wherever it points (see Runner files);
- a file over 256 KiB, before reading it;
- two points with one id;
- a `skills[].path`, point glob, `requires.fixtures` or `files` entry that is
  absolute or has a `..` segment;
- a glob that matches no file, a skill, fixture or `files` entry that names no
  file, and a profile that names a point that does not exist;
- a `select.paths` or point glob that is not in the grammar under Globs: one with `[`, `]`,
  a leading `!`, `\`, a group inside a group, or braces that do not pair up;
- a `select.paths` or point glob over 4,096 characters, or whose braces expand more than
  1,024 ways or to more than 65,536 characters; more than 200 point globs; and point globs
  that take more than the budget of 4,000,000,000 steps to match (see "Planning limits");
- any key a schema does not know.

Every error names the file, and the field when there is one, as in
`.koi/points/save.yaml: run.command: Invalid input: expected array`.
