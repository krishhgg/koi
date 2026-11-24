# koi design

koi is a preview-environment tool for pull requests. It knows a project only
through the project's recipe (see Recipes).

## Why

A reviewer should be able to test the change in a PR without building the product
locally and without hunting for where the change lives. A shared staging environment
cannot serve this. It is slow, has one slot, and ships whole branches. koi gives each
PR one container, which is enough for an app that serves its own web UI and needs no
outside database.

The model is one deploy command an agent or a person can run that prints a URL. Not a
new cloud.

## How it works, by actor

### Author or agent

Previews live under the operator's own domain, set once as `domain` in
`infra/koi.auto.tfvars`; `previews.example.com` stands in for it below.

```
$ koi up
koi  project: storefront (recipe matched by git remote)
koi  packing working tree: fix/checkout-timeout, 3 uncommitted files
koi  waking the box... up in 48s
koi  building... 3m12s
koi  starting preview... healthy

  preview   https://storefront-fix-checkout-timeout-trnoodgx.previews.example.com
  login     koi-k9f3xxxxxxxxxxxxxxxxxxxx
  commit    3f1c2a9b7d4e
  keys      https://keys.previews.example.com/?for=storefront-fix-checkout-timeout-trnoodgx
```

`koi up` ships the working tree, uncommitted changes included, and names the preview
after the branch plus eight letters derived from the project and the exact branch name, so `feature/a`
and `feature-a` get different previews. A fork, matched through the recipe's
`github.com/*/storefront` entry, gets the project name `storefront-<owner>`. Its
branches and pull request numbers are its own, and under the plain name its `develop` or
its PR 12 would take the main repository's label. `koi up --pr 2518` builds GitHub's merge of
the PR into its base (`refs/pull/2518/merge`), the PR as merging it now would give, and
names the preview `storefront-pr-2518`. The output and the PR comment say what was
built, "Built from #2518 (abc1234) merged into develop (def5678)", and the preview
record keeps the merge commit and both its parents. koi checks that the merge is
current before uploading: its head must be the PR's head now, and its base the base
branch's tip now (asked of origin with `git ls-remote`). The base branch's name comes
from gh, so a merge build needs gh signed in and stops without it.

GitHub may keep an old merge after the base alone moves on, through any number of
fetches of the ref: only a request for the PR's mergeability (`GET
/repos/{owner}/{repo}/pulls/{n}`, whose `mergeable` is null while GitHub works it out)
makes it recompute the merge. So when the merge is out of date koi asks, fetches the
merge again every 15 seconds for up to 90, and checks it each time against the base
branch and head that GitHub's answer just named, so a PR retargeted or pushed during the
wait is checked against what it is now. The 90 seconds are a deadline on a clock that
only moves forward, and each gh call, fetch and sleep in the wait gets only the time
left; a program killed at the deadline gets up to 2 seconds more for its output to end
(`PIPE_GRACE_MS` in exec.ts). When the merge stays out of date (or GitHub says the PR cannot merge, or gh
cannot ask, or a fetch during the wait fails), koi reads the base branch and head from
GitHub once more, whatever happened during the wait. A read that fails is tried again,
three times in all, 5 seconds apart, each with gh's usual 2 minute limit. Without an
answer koi stops before uploading rather than merge a base branch or head that an
earlier answer named, since the PR may have been retargeted or pushed since. With one,
koi fetches the PR and checks that origin's head is the one GitHub named; when the
author pushed in between, it reads and fetches again, up to three times, then stops.
The API's `base.sha` is not used: GitHub leaves it at the base of the PR's last
push, even after it remakes the merge onto a later base, so koi takes the base's tip
from origin. If GitHub's merge has caught up by then koi builds it; otherwise koi
merges the PR's head into the base's tip itself, with `git merge-tree --write-tree`.
That needs git 2.43 or later: older releases lack `git --attr-source`, or abort when
`git merge-tree` reads attributes through it, and koi refuses to merge with them.

koi makes that merge in a temporary bare repository that shares only the checkout's
objects, with no system or global git config, no work tree, index or `info/attributes`,
and the merge settings pinned to git's defaults (no renormalizing, renames on, a rename
limit of 7,000). Attributes come from the `.gitattributes` files in the base's tree and
nowhere else (`git --attr-source=<base>`), as `git merge` reads them with the base
checked out in a fresh clone, and no merge driver runs. git merges from the newest
commits the two parents share, and in a shallow checkout a boundary can hide the newest
one while an older one stays in reach, which can turn a clean merge into a conflict. So
in a shallow checkout koi first walks both histories in the temporary repository, which
has no list of shallow commits and so fails on any parent the checkout lacks. When one
is missing, koi fetches both histories whole (`git fetch --unshallow origin <base>
<head>`) and walks them again, for up to 10 minutes in all, and refuses a history that
is still not whole.

koi's merge depends on these inputs and no others:

- the base commit, the tip on origin of the base branch GitHub's API named just before;
- the head commit, `refs/pull/N/head` on origin, which must be the head GitHub named;
- the whole history of both, back to their roots;
- the `.gitattributes` files in the base's tree;
- the git that runs it (2.43 or later), with git's default merge settings.

Nothing else in the checkout or on the machine counts: not the work tree, index, config,
`info/attributes` or hooks, not the user's global or system git config or attributes,
and no merge driver. The same parents give the same tree in any checkout with the same
git release.

koi does not promise that its tree matches GitHub's. GitHub merges with the same
algorithm (ort), but it may run another git release, read attributes from elsewhere, or
apply LFS or other settings of its own, any of which can give another tree. koi's
output and comment say koi made the merge, its commit names koi as author, and what the
commit-match rule checks is the commit and its parents, not that GitHub would have made
the same tree.

koi commits that merge with `git commit-tree`: parents the base then the head, message
`Merge <head> into <base>`, author and committer `koi <koi@koi.invalid>` at the later
parent's commit time in UTC, unsigned. So the commit follows from its two parents, and
anyone can make it again.
koi records it exactly as it records GitHub's merge (the commit, and `merge.head`,
`merge.base`, `merge.baseBranch`), so deployment and lease checks, which compare those
fields, hold as they would for GitHub's. The output and the comment add that koi made
the merge, since GitHub does not have its commit. A PR whose head conflicts with its
base's tip has no merge, from GitHub or koi, and koi stops before uploading, names the
conflicting files and says to rebase or merge the base. A PR with no merge ref at all
stops the same way, as one GitHub found to conflict or has not checked yet. `--head`
builds the head as pushed and needs no gh. Both work from a shallow checkout such as
actions/checkout makes. The list of changed files a recipe may read comes from the PR's
own changes either way, not from everything the merge holds. `--comment` posts or
updates one sticky comment on the PR. `--json` prints the same block as JSON, plus `keysUrl`, the keys page, and
`deployment`: the identity of the preview's saved deployment, the build that serves
whenever the preview is running, with its `deploymentId`, `imageDigest`, `commit` and,
for a pull request, `merge`. After a failed build that is still the previous deployment.
It is absent only when no build has ever succeeded or the deployment was retired.
`deployment` says which build is saved. `status` says how far the latest build attempt
has got and how it ended: `queued`, `building` or `starting` while it goes, `running`
once it deployed, `failed` when it did not, and `expired` once the preview is retired.
Neither says whether the container is up right now. After the box wakes, `status` says
`running` while the container starts, or if it did not; after a failed rebuild it says `failed`
while the previous deployment serves. For a live check, request `/__koi/health` on the
preview, which answers 200 only while the container runs and Caddy routes to it, or run
`koi lease`, which refuses a preview that is not running. A verification run binds to
`deployment` ([docs/verify.md](verify.md)). `koi list --json` carries the same two fields
for each preview. The JSON of `koi up`, `koi lease` and `koi release` also carries
`schemaVersion`, and has a JSON Schema in `schemas/` (see the README).
Running `up` again for the same name replaces the preview and keeps its URL.
`koi list`, `koi logs NAME` and `koi down NAME` complete the set. `koi lease NAME
--minutes N` holds a preview so no build replaces it: `koi up` for that name is refused
before anything is built until the lease expires or `koi release NAME LEASE` ends it,
and `koi down` refuses it unless given `--force`. `koi down` on a preview that is still
building stops the build and drops any request queued for it, and the `koi up` waiting
on it ends with `failed`.

The CLI uploads a tarball of the source to an S3 bucket and tells the daemon on the
box to build it, through SSM. Only people with AWS credentials for the account can
run `koi up`.

### Reviewer

The link always points at CloudFront, which holds the certificate for
`*.previews.example.com` and forwards to the box. When the box is stopped the origin fails
and CloudFront falls back to the wake Lambda, which starts the instance and returns a
plain "waking up" page that reloads until the preview answers. If only the preview's
container was stopped, the daemon shows the same page for a few seconds. One address
the whole time; DNS never changes.

When the app has a login, the reviewer signs in with the login key from the PR
comment. A recipe can seed the preview from the list of changed files, so the
reviewer starts at the change instead of hunting for it.

### Keys

An app that calls an LLM provider needs a key. The reviewer opens the preview's keys page,
`https://keys.previews.example.com/?for=<label>`, linked from the PR comment and printed by
`koi up`. It is served by koi on its own origin. They paste their provider keys, and for
each key the proxy gives a koi token such as `koi_7f3a...`, good for that provider and
that preview only. In the app they type the token as the API key.

The page shows some tokens after their provider's key prefix: `sk-koi_...` for OpenAI
and DeepSeek, `sk-ant-koi_...` for Anthropic, `xai-koi_...` for xAI. Some apps
refuse a key that does not begin that way before sending anything, so a bare `koi_`
token would never reach the provider. The proxy accepts a token with or without one
of these prefixes and still checks that the token is the provider's own.

A token is derived, not drawn at random: `koi_` and 160 bits of HMAC-SHA256 under a
secret on the box, in lowercase base32, of a fixed domain string and the provider, the
preview label and the key, each behind its length. So the same key registered again for
the same preview gets the same token, after a proxy restart or a sleep, while a change
in any of the three, or in the secret, gives an unrelated one, and a token tells nothing
about its key to anyone without the secret. Registering stays the only way to get a
token; the caller never names one, so knowing a token lets nobody rebind it. The secret
is 32 bytes from `/dev/urandom` that `install.sh` writes once to
`/etc/koi/egress/private/token-secret`: owned by the proxy's user with mode 0400, in a
directory only root can write (root, 0711), so not even the proxy's own user can replace
or change it, and `install.sh` refuses a symlink there rather than following one. It is
kept across reboots and deploys and never logged or sent anywhere. The proxy opens it
at load without following a symlink or waiting on a FIFO, and stays down, as with any
other load failure, if it is missing, not a regular file, owned by someone else, of any
mode but 0400, or not 32 bytes. Deleting the file invalidates every token: each key
gets a new one when its keys page registers it again, and the reviewer pastes the new
tokens into the preview.

The preview container has no route to the internet except through koi's proxy. The
proxy swaps a token for the real key only in that provider's own authentication field
(Authorization: Bearer, x-api-key, x-goog-api-key, or Gemini's `?key=` on its API
paths), only over HTTPS on port 443 where the CONNECT host, the TLS server name, the URL
and the Host header all name the provider, and only for requests from the container of
the preview the token was registered for: koid tells the proxy which container address
runs which preview whenever the routes change. Whatever the provider sends back reaches
the preview with the key replaced by the token. WebSocket APIs, such as the realtime
ones, take no koi token: the proxy relays an upgraded connection as raw bytes it cannot
scrub, so it refuses a token in the upgrade. The PR's code never sees the key,
cannot send it elsewhere because only provider and package hosts are reachable, and the
proxy caps requests per token. Keys live in the reviewer's browser storage and the
proxy's memory. The proxy forgets every registration when the box sleeps. The keys page
saves each preview's last registration, keys and tokens, and registers that preview's
keys again on its own, when it opens and when its tab becomes visible, at most once a
minute across its tabs; it gets the same tokens back and says so in a status line, and
if the box gave another token for some provider it names that provider and asks for
that token to be pasted. Every registration and Forget of one browser runs under one
Web Locks API lock, so its tabs never overlap (a tab without the API queues within
itself). A Forget revokes everything and wins any race: it records itself as pending
and bumps a count in storage at once, a registration that was asked for under an older
count sends nothing or revokes what it got and saves nothing, every tab sees the count
move and shows the keys are gone, and the next operation under the lock in any tab, or
the next page to open, finishes a Forget whose tab closed before its turn. Revocation
never touches a token in a preview's latest registration. A tab shows the tokens of the
registration another tab saved for its preview, never ones that registration revoked.
Secrets the proxy cannot cover, such as database passwords, get a visible warning that
the PR's code will see them.

### Sleep and expiry

After 10 minutes with no requests and no build running, the box stops itself. Preview
files stay on disk; keys do not, though their tokens come back unchanged when the keys
page registers them again (see Keys). The box stopping stops every preview container,
and Docker does not start them again. koid does, as soon as it starts: every preview
that has a deployment, at the same URL with the same deployment and login key,
one at a time, each routed once it answers its health check. It skips a preview stopped
for disk use, one whose container did not start or answer last time, and one past its
ttl, which expires instead. A visit to a preview still waiting its turn starts it at
once; a visit while its preview starts gets the waiting page until it answers. Seven
days after a preview's last visit its container and files are deleted and the link
reports that it expired. The wake Lambda checks a list of live previews before
starting the box, so scanners hitting random hostnames do not wake it.

## Parts

On AWS, all in us-east-1: one t3.xlarge with an 80 GB disk and a fixed IP, a security
group that admits only CloudFront's origin-facing addresses on 443, an instance role
limited to the SSM agent, the upload bucket, the preview list and the one ACME TXT
record, an S3 bucket for source uploads, CloudFront with an ACM certificate, Route 53
records under the domain, and the wake Lambda. Only CloudFront can reach the box, but
CloudFront forwards anyone's request for any `*.previews.example.com` name, so koid counts
only requests for live previews as activity; a scanner hitting random names neither
wakes the box (the wake function checks the live list) nor keeps it awake. Idle cost is
the disk and the fixed IP, under $10 a month. Nothing runs while the box sleeps except
CloudFront and the Lambda, which cost nothing idle.

On the box: Docker, Caddy on 80 and 443, `koid` on localhost, a dedicated BuildKit
builder, and the egress proxy.

- **Builds** run in the `koi-builder` BuildKit container (8 GB memory, three CPUs) on
  its own network. Builds need the internet for packages, but the firewall drops any
  new connection from that network to the host, and the metadata endpoint is blocked.
  Nothing from a pull request runs on the host itself.
- **Previews** run as a numeric non-root user with no capabilities, no host mounts,
  no published ports, and memory, CPU and process limits, on the internal network
  `koi-previews`. That network has no route out, previews cannot reach each other,
  and the firewall drops new connections from it to the host except to the egress
  proxy.
- **Memory**: the builder and every preview run in one systemd slice, `koi.slice`,
  capped at 82% of the box's memory, so together they cannot take the memory Docker,
  Caddy, koid and the egress proxy need. The egress proxy is a host service and runs
  outside the slice, with its own 1 GB ceiling.
- **The egress proxy** (mitmdump with koi's policy addon) is the previews' only way
  out. It allows an allowlist of hosts (package registries, model weights, LLM
  provider APIs) and refuses everything else, the metadata endpoint included. It
  intercepts TLS in every tunnel and refuses one whose TLS server name, or any
  request's Host, is not the host the tunnel was opened to, so a tunnel to an
  allowed host cannot reach another site on the same CDN. It streams bodies rather
  than holding them, and cuts off a refused request at its headers. On requests to
  LLM providers it swaps a koi token for the reviewer's key (see Keys). Previews
  trust its CA through a bundle koid copies into each container before it starts.
- **koid** owns the Caddyfile and regenerates it whenever a preview starts, stops or
  is replaced. Caddy proxies each running preview directly and sends everything else
  to koid, which shows a status page or starts a stopped preview.

What this does not cover is listed in the README under "Trust model and limits".

gVisor is a later hardening step.

### Uploads and the live list without AWS

On AWS the CLI puts each request and its source tarball in the S3 bucket, and koid
publishes the labels allowed to wake the box to an SSM parameter. A plain Linux host has
neither, so koid has a second implementation of each, chosen by its configuration
(`packages/daemon/src/adapters.ts`). The AWS box sets `KOI_UPLOADS_BUCKET` and
`KOI_PREVIEWS_PARAM` and nothing new, and gets S3 and SSM as before.

- **The spool** (`KOI_UPLOADS=spool`, under `KOI_SPOOL_DIR`, default
  `/var/lib/koi/uploads`) holds uploads on the host's own disk. A client delivers one
  through the control socket in three calls: `POST /v1/uploads` with the request id,
  the tarball's size and its SHA-256 gives a random upload id and reserves the space;
  `PUT /v1/uploads/<upload-id>/source` streams the tarball into an exclusively
  created file under `incoming/<upload-id>/`, counting bytes as they arrive, refusing
  at once a body over the declared size (413), one that ends short (400), one whose
  digest differs (422) or one that takes over ten minutes (408), and never holding
  the tarball in memory; `POST /v1/uploads/<upload-id>/commit` takes the request
  JSON, checks its schema, that it names the ticket's id and was created within the
  hour, syncs both files and renames the directory to `ready/<request-id>` in one
  step. Nothing under `ready` is visible before that rename, and the request file is
  never there without its source. koid reads only `ready`, with the S3 reader's
  limits (a request of at most 256 KiB, a source of at most 2 GiB), and refuses
  symlinks and anything that is not a plain file. One check is out of reach and not
  faked: Bun and Node have no `openat`, so the entry directory is not pinned between
  the check that it is a directory and the open of a file inside it. A process that
  swapped it in that moment would have to run as koid's user, since the spool is a
  0700 directory of that user, and such a process already controls koid; the checks
  stand against mistakes and planted files, not against that user. A retry with the
  same content gets the same answer; the same request id with other content is a
  conflict (409). A ticket lives an hour. An entry lives a day unless the deployer
  holds a claim on it: it claims the entry as it accepts the request and releases it
  once the build has copied the source, so cleanup never removes a source a build
  still needs. Cleanup runs at startup and every ten minutes. The spool keeps a
  ledger in memory of what it holds and has promised: each committed entry's bytes
  and, for each open ticket, the declared source size plus the 256 KiB a request
  file may be. Admission, commit, expiry, claims and cleanup change the ledger under
  one lock, a ticket with a PUT or a commit under way is left alone by expiry until
  that call has answered, and koid rebuilds the ledger from the disk at startup; if an
  entry cannot be read then, koid does not start, rather than run a ledger short of
  its bytes. A commit answers 200 only once the `ready` directory is synced, so an
  upload the CLI saw acknowledged survives a crash of the box; if the sync fails the
  commit fails, the entry stays counted, and a retry syncs again. A ticket request
  that finds its content committed syncs the same way before it says so, and every
  entry found at startup counts as not yet synced. An entry missing its request or
  source is broken: it is never acknowledged, and cleanup removes it whatever its
  age. An upload is refused
  (507) when it would pass the spool's budget (`KOI_SPOOL_BUDGET_BYTES`, default
  10 GiB) or leave the disk under 10% free, or under 20 GiB on a disk over 200 GiB, counting bytes promised to uploads under
  way, where builds are refused anyway. Every body on the control socket is read
  within a bound of bytes and time, the archive within ten minutes and JSON within
  thirty seconds, because Bun's idle timeout covers none of a streaming body. `koid
  ctl up <request-id>` means what it always did. The SSH transport fills the spool
  through this API; see Reaching the box over SSH.
- **The file live list** (`KOI_LIVE=file`, at `KOI_LIVE_FILE`, default
  `<state dir>/live-previews.json`) is the sorted list of live labels as one JSON line,
  written to a temporary file and renamed into place, so a reader sees a whole list
  or the previous one. It has no size cap. The SSM list keeps its 4 KB cap, and that
  cap is the SSM adapter's alone: the deployer asks the live list whether it has room
  for a new label before accepting it, and refuses the label with the list's reason.
  The file list is the default with the spool, SSM the default with S3; either pairs
  with either.

No preview has a hard disk quota. Docker's overlay2 storage on the box's ext4 root disk
cannot cap a container's writable layer or its volumes, and hard per-container quotas
are out of scope. koid checks instead: when it starts and every five minutes after, it
stops a preview whose writable layer and volumes together pass 10 GiB and keeps it
stopped, and before each build it trims the build cache to 20 GB when the disk is under
20% free, then refuses the build if it is still under 10%. On a disk over 200 GiB those
limits are 40 GiB and 20 GiB, as a build there needs no more than one anywhere else. A preview can fill the disk between two checks.

The CLI is one Bun binary. The code is TypeScript throughout: `shared` for schemas,
`cli`, `daemon`, `lambda`. Infrastructure is OpenTofu in `infra/`.

### Reaching the box over SSH

A plain Linux host has no SSM. The CLI reaches it through the system `ssh`
client, as the `koi-connect` account, with a key, and sshd runs one program for
that account whatever the client asked for: the gateway
(`host/ssh/koi-ssh-gateway.ts`, installed root-owned at
`/usr/local/libexec/koi-ssh-gateway` by `host/ssh/install.sh`). The gateway reads
the client's request from `SSH_ORIGINAL_COMMAND`, matches it against two forms and
runs nothing else: `ctl-b64 <blob>` runs `koid ctl` with the arguments the blob
encodes, through the same client koid's own `ctl-b64` uses, and relays its output
and exit status; `tunnel-v1` copies bytes between the session and koid's control
socket until either side ends, and the CLI speaks HTTP to the upload API over it. A
shell, scp, sftp, rsync, an environment assignment or any other word is refused
with exit 2. The gateway clears its environment first and uses a fixed socket
path, which only the sshd configuration can change. The sshd `Match User
koi-connect` block (`host/ssh/sshd.sh`) allows keys only, no PTY, no `~/.ssh/rc`
and no forwarding of any kind (`DisableForwarding`), reads the account's keys
from a root-owned file outside its home, and replaces `AcceptEnv` and `SetEnv`
for the account with placeholder names nothing reads, so that no variable the
client sends (`LD_PRELOAD`, which the loader would act on before the gateway
runs) reaches it. The installer writes the block as the first `Match` sshd
reads and refuses to reload sshd when the files, read in sshd's order and with
sshd's quoting, show another `Match` before it or another block that can apply
to the account (one without a `User` list that leaves `koi-connect` out) and
sets a keyword the block guards; `sshd -T` for one client then confirms the
block loaded as written. The account has no password and is in no
group but `koi-control`, which may open the control socket: koid gives the
socket that group when it makes it, and the socket's directory has it from
`koid.service`.

On the CLI side every option is on the command line and `-F none` keeps ssh's
own configuration files out: batch mode, one identity (a key file, or a key in
ssh-agent named by its public half), strict host key checking against a
known_hosts file of the target's own under the target's alias, no PTY, no
forwarding, no local command. The host key is enrolled one way only, by `koi
target trust NAME --fingerprint SHA256:...`, which writes the key `ssh-keyscan`
collects if its fingerprint is the one the operator gave; there is no trust on
first use. One master connection carries every session of a koi run and is ended
when the run ends. `koi up` sends a ticket request, streams the archive from disk
in pieces, then commits, all over one tunnel; a tunnel that breaks part way is
opened once more and the sequence starts again from the ticket, which says
whether the commit had already landed. koi cannot start an SSH host: a host that
refuses the connection is reported as one its operator must start. The AWS box
gets the gateway and the account too, from `scripts/deploy-host.sh`, but its
security group admits no SSH, so nothing is opened there.

### Reaching koid on the same machine

A local target reaches koid through its control socket with nothing in
between (`packages/cli/src/transports/local.ts`). The CLI runs koid ctl's own
client against the socket, as the gateway does, and sends the source to the
upload API over a connection to it, in the same requests the SSH tunnel
carries (`transports/upload.ts`, which both transports use). Access is decided
where it is for the gateway: the socket is mode 0660 in `koi-control`, and an
account in that group stands where a `koi-connect` key does. In place of a
pinned host key, the CLI refuses a socket on a path another account could have
written to, then checks koid's descriptor before any source goes out. The host
is set up by `host/install-vm.sh --local`, which runs `host/cloud-init.sh`
without its AWS parts: certificates from Caddy's own CA, no idle shutdown.

### Updating the box and the CLI

`scripts/deploy-host.sh` installs koid, the built-in recipes and the egress proxy on
the box together. Update the box first, then the CLI. The two exchange no version:
`koid ctl ping` answers `{"ok":true}`, the `version` in a request file is the version
of its schema, and the status reply is the preview's record, so a new CLI cannot tell
an old box from a new one. What has to match is the tarball's layout, which the
recipes on the box read. A recipe that reads the list of changed files can also look
for `.koi/changed-files.txt`, where a CLI from before `.koi-runtime/` wrote it, when
`.koi-runtime/changed-files.txt` is missing, so a box newer than the CLI still builds.
A CLI newer than the box may not: its tarball has no file where an old recipe looks.

## Recipes

A recipe says how to build and run a project's preview. A built-in recipe is
`recipes/<name>/recipe.json`, reviewed and shipped with koi. `scripts/deploy-host.sh`
installs the directory on the box, and a request only names the recipe. Any other
repository brings a `koi.yaml`, which may only point at a Dockerfile in its own tree.
[recipes/README.md](../recipes/README.md) says how a recipe matches a repository.

A built-in recipe may bring its own Dockerfile (`"build": {"kind": "dockerfile",
"from": "recipe"}`). The pull request's tree is then only the build context. For each
build koid copies the recipe's installed directory and hands the copy to BuildKit as
the named context `recipe`, so the Dockerfile takes its scripts and `recipe.json` with
`COPY --from=recipe`. The build follows the copy, so a deploy that replaces the
installed recipes during a build does not change that build.

Every source tarball carries `.koi-runtime/changed-files.txt`, the paths the change
touched, one per line. A recipe can use it to seed the preview at the change, or to
cut the build down to what the change needs. The list must describe the tree koi
builds, whole, so koi never guesses it. A merge build lists it from the merge commit
koi builds, against the base it was merged into (`git diff merge^1 merge`): the one
list tied to that tree, with no limit. A shallow checkout that lacks the parent is
deepened by one along the pull request's merge ref first. A head build (`--head`)
takes GitHub's list, but only when gh's `headRefOid` is the head koi fetched (a push
in between makes the list describe another tree) and the list is short of GitHub's
3,000-file limit (a list that long may be cut). When gh cannot list the files, git
can, as the head against the merge's base parent. When neither is there, koi stops
before uploading and says what to do: run again, build the merge, or install and sign
in to gh. A working tree is compared with origin's default branch, and koi stops when
the clone has none to compare with. The CLI never cuts the list, however long.

A recipe may keep data of its own for its build scripts under `slice` in
`recipe.json`, such as what a preview keeps of the project. koi never reads it. It
checks only that the field is a JSON object of at most 64 KiB (`RecipeSliceSchema` in
`packages/shared/src/recipe.ts`). The recipe's own tests check the shape.

A built-in recipe that cuts the build down can report what it kept. `sliceFile` in its
`recipe.json` names an absolute path in the image, where the build writes a JSON object
of the recipe's own shape. Once the image is built, and before the container starts,
koid creates a container from the image without starting it, reads the file through
`docker cp CONTAINER:PATH -`, and removes the container. That prints a tar archive,
which koid stops reading past 72 KiB and parses in memory; nothing from the image is
written to the box's disk. koid takes only an archive of one regular file, with valid
header checksums and octal sizes, and a PAX header before it only when no record sets
the size or makes the file sparse. It refuses a symlink, a directory or any other
entry, a file over 64 KiB, text that is not UTF-8, and anything but a JSON object of at
most 16 KiB and 16 levels of nesting (`DeploymentSliceSchema`; koid's store indents
each level, so 16 KiB of deeply nested arrays would take tens of megabytes). Each of
those fails the build, as a missing file does. If the container will not go, koid logs it and the build goes on; reconcile
removes it with the other leftovers when koid next starts. koid
keeps the object on the deployment, and `koi up --json` returns it as `slice`, beside
the `deployment` it describes. koi never reads inside it. The build that wrote it ran
the pull request's code, so it is what the recipe's scripts said, not something koi
checked.

The `slice` reaches the CLI in `koid ctl status`. It comes only in a reply with no log
lines, for a record no longer queued or building, so a reply never carries both a page
of log and a slice, and polls during a build carry neither the old nor the new one. The
largest such reply, with a 16 KiB slice, a 2,000-character error and the longest
branch, lease holder and base branch, is about 21,400 characters, under SSM's 24,000.

`koi up --keep NAME` (repeatable, at most 32) asks such a recipe to keep NAME whatever
the change touched. koi gives the name no meaning; the recipe decides what it names,
such as a node. Each name is 1 to 64 letters, digits, dots, dashes and underscores,
starting with a letter or digit (`KeepSchema` in `packages/shared/src/request.ts`).
The CLI checks them, and koid checks the request again. koid passes them to the build
as one build argument, `KOI_KEEP`, the names joined by single spaces, given to `docker
buildx` as an argument and never through a shell. A recipe without a `sliceFile` does
not take `--keep`: the CLI refuses it before uploading, and koid refuses the request,
because only a slice can show the caller what was kept. A koid older than the CLI drops
`keep` from the request and returns no `slice`. No reply of koid's gives its version
before the upload, so koi up finds out after the build: with `--keep` and no `slice`,
it reports `failed`, with an error saying koid did not apply `--keep`, and exits 1.
Without `--keep`, an older koid works as before.

A recipe's Dockerfile runs pull request code, so no cache is shared between pull
requests: one pull request's code could poison it for the next. A test checks every
built-in recipe's Dockerfile for a writable `--mount=type=cache` and for writable bind
mounts (`packages/daemon/test/recipes.test.ts`). Package managers download again in
every build. Anything worth caching is fetched in a stage that copies nothing from
the pull request, checked against a published digest, and mounted read-only.

When a recipe names `loginKeyEnv`, each preview gets its own random login key in that
variable. koid keeps the key across redeploys of the preview, and `koi up` and the
pull request comment show it.

The CLI reads the built-in recipes when it is built. `packages/cli/src/recipe-files.ts`
runs as a Bun macro and writes every `recipes/*/recipe.json` into the CLI's code, so
the compiled binary needs no `recipes/` directory at run time. Adding a recipe takes
only its directory. Its tests and fixtures stay out of that directory, since the
directory goes to the box and into the build context.

## Phases

1. Scaffold: workspace, schemas, CI, Greptile config, this document.
2. Infrastructure in OpenTofu, applied with the operator's admin session; the CLI
   gets a narrow `koi-cli` user.
3. Daemon, Caddy and a hello preview; first wake-on-click link.
4. CLI with a generic Dockerfile recipe, proven on a toy project.
5. A built-in recipe with its own Dockerfile: login key, seeded previews, `--pr`,
   `--comment`.
6. Keys page and injecting proxy.
7. VS Code in the browser beside a preview.
8. Sleep, expiry, hardening, Greptile config pass.

## Decisions

- TypeScript on Bun, OpenTofu for infrastructure.
- No deploy user. A policy broad enough to run `tofu apply` can grant itself
  administrator, so infrastructure is applied with the operator's short-lived
  `aws login` session. Day-to-day use goes through `koi-cli`, which can upload
  source, run commands on the box, start it, and read the preview list.
- CloudFront replaces origin responses with status 502 and 504 by the wake page,
  because a stopped or booting box surfaces as those. A preview's own 502 or 504
  is replaced too; 503 is left alone because real apps send it.
- No GitHub Actions for previews. The CLI is the only entry point; an Action can wrap
  it later.
- No funded provider keys. Reviewers bring their own through the key proxy.
- Fork PRs get previews only when a maintainer runs `koi up --pr`.
- Login key may appear in the PR comment: a preview holds no secrets of ours, so the
  worst case is someone using its compute until it expires.

## Open questions

- Whether every provider SDK an app uses accepts the proxy's certificate. The OpenAI
  and Anthropic Python SDKs do, given a CA bundle through `SSL_CERT_FILE` and
  `REQUESTS_CA_BUNDLE` (tested: the provider received the swapped key). Others are
  checked as previews exercise them.
