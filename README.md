# koi

One command turns a pull request, or your working tree, into a link a reviewer can
click: `https://storefront-pr-2518.previews.example.com`. The link opens the real product
built from that code, on a box that sleeps when nobody is using it and wakes when the
link is clicked. Previews live under a domain you own; `previews.example.com` stands in
for it throughout these docs.

The design, the threat model and the decisions behind them are in
[docs/design.md](docs/design.md).

## Using it

```
koi up                    # build this working tree (uncommitted changes included)
koi up --pr 2518          # build pull request 2518 merged into its base branch
koi up --pr 2518 --head   # ...the head as pushed instead, not merged
koi up --pr 2518 --comment   # ...and post or update the preview link on the PR
koi list                  # previews on the box
koi logs NAME [--build]   # container log, or the last build's log
koi lease NAME --minutes N   # hold a preview so no build replaces it, for N minutes
koi release NAME LEASE    # end a lease
koi down NAME [--force]   # remove a preview; --force removes a leased one
```

Add `--json` to any command for machine-readable output on stdout; progress goes to
stderr. Exit codes: 0 success, 1 failure, 2 bad usage.

`koi up --pr` builds GitHub's merge of the pull request into its base branch (the
repository's `refs/pull/N/merge`): the pull request as merging it now would give, with
the base branch's later changes. The output and the pull request comment say what was
built, as in "Built from #2518 (abc1234) merged into develop (def5678)". A pull request
that conflicts with its base has no such merge, and GitHub may keep an old merge after
the base alone moves on; in both cases koi stops before uploading and says to rebase or
merge the base, or to try again in a minute if GitHub has not computed the merge yet.
Checking the merge against the base needs the base branch's name, which koi asks gh
for, so a merge build needs gh installed and signed in. `--head` builds the head as
pushed instead, and needs no gh.

`koi up` prints the preview URL and, for projects with a login, the
preview's login key, and the preview's keys page, `https://keys.previews.example.com/?for=<label>`.
A reviewer who needs an LLM opens that page, pastes their provider keys there, and gets
one koi token per provider, which they use wherever the app asks for that provider's API
key. The tokens work only in that preview, which never sees the real keys. The box
forgets the keys when it sleeps; the keys page registers them again on its own when the
reviewer opens or returns to it, and the tokens stay the same.

### Which projects

A project needs a recipe. Built-in recipes live in `recipes/` and match by git remote. A
recipe that lists `github.com/acme/storefront` builds that repository's previews (see
[recipes/README.md](recipes/README.md)). Any other repo can add a `koi.yaml` at its root:

```yaml
port: 8080          # the port the container listens on
healthPath: /       # answers below 500 when the preview is ready
build:
  kind: dockerfile
  path: Dockerfile  # relative to the repo root
```

The file may also live at `.koi/koi.yaml`, next to the project's other koi files
(see [docs/verify.md](docs/verify.md)). When both exist, the one at the root wins. Paths in it are relative to the repo root
either way. koi adds its own files to every build under `.koi-runtime/`, so a repo
must not have a directory of that name.

### Credentials

The CLI uses the AWS profile `koi-cli` (override with `KOI_AWS_PROFILE`). It can
upload source, start the box, and run commands on it; nothing else. It finds the box
by its tags, the preview domain from the box's `Domain` tag, and the upload bucket from
the account id; `KOI_INSTANCE_ID`, `KOI_DOMAIN` and `KOI_BUCKET` override them. A
per-user config file can name the deployment instead, and other hosts later; see
[docs/configuration.md](docs/configuration.md).

## Operating it

Before the first `infra/bootstrap.sh`, copy `infra/koi.auto.tfvars.example` to
`infra/koi.auto.tfvars` and set `domain` to a domain whose Route 53 hosted zone is in
the account. The variable has no default. Everything else reads the domain from there:
the box's `Domain` tag (which the CLI reads), the wake function's environment,
`scripts/deploy-host.sh` (which writes `KOI_DOMAIN` to `/etc/koi/env` for koid) and
`scripts/provision-host.sh` (which hands it to `host/cloud-init.sh`).

| Task | Command |
|---|---|
| Create or change the AWS stack | `AWS_PROFILE=<admin> infra/bootstrap.sh` |
| Re-run host provisioning on the running box | `AWS_PROFILE=<admin> scripts/provision-host.sh` |
| Install a new koid, recipes, egress proxy and SSH gateway | `AWS_PROFILE=<admin> scripts/deploy-host.sh` |
| Let a CLI reach a host over SSH | On the host, after the deploy: append the CLI's public key to `/etc/ssh/koi-connect/authorized_keys` and read `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`; on the CLI, `koi target trust NAME --fingerprint SHA256:...` (see [docs/configuration.md](docs/configuration.md)) |

Update the box before the CLI; see Updating the box and the CLI in
[docs/design.md](docs/design.md).

## Trust model and limits

koi builds and runs code from pull requests that may be hostile and puts the result on
the public internet. [docs/design.md](docs/design.md) describes the isolation. These
are its limits, each with the file that decides it.

- Anyone with the CLI's AWS credentials can run any command on the box, as root. The
  `koi-cli` policy grants `ssm:SendCommand` for the `AWS-RunShellScript` document on
  the instance (`infra/users.tf`), and SSM runs such a script as root. The CLI itself
  only sends `koid ctl` commands (`packages/cli/src/box.ts`), but nothing holds the
  credentials to that.
- Previews have no hard disk quota. The box's root filesystem is ext4, where Docker's
  overlay2 storage cannot cap a container's writable layer (that needs XFS with project
  quotas), and nothing caps its volumes, so koid measures after the fact. When it
  starts and every five minutes after, it stops a preview whose writable layer and
  volumes together pass 10 GiB (`DISK_LIMIT_BYTES` in `packages/daemon/src/deployer.ts`,
  the timer in `packages/daemon/src/main.ts`). A preview can fill the disk between two
  checks.
- The host installer is for a dedicated machine, not a personal workstation.
  `host/cloud-init.sh` writes `cgroup-parent: koi.slice` into `/etc/docker/daemon.json`,
  so from then on every container on the machine that names no cgroup parent starts
  under koi's memory ceiling, and it restarts Docker when that setting changes. A
  container takes its cgroup parent when it starts, so one that keeps running through
  the restart (Docker's live-restore) stays where it was. The installer restarts the
  builder to move it into the slice (`move_builder_into_slice`), and koid stops a
  preview it finds outside the slice and starts it there on its next visit
  (`Deployer.reconcile` in `packages/daemon/src/deployer.ts`). Without live-restore,
  the restart stops every container. The installer adds iptables rules and installs
  Caddy, which serves `*.<domain>` on port 443 with a wildcard certificate from a
  DNS-01 challenge and does not redirect port 80 (`auto_https disable_redirects`); the
  security group opens only 443 (`infra/network.tf`). A timer checks every minute and
  powers the machine off (`systemctl poweroff`) once 10 minutes pass with no activity.
  A koi request, a build and an open connection to a preview all count as activity;
  koid looks for open connections every 30 seconds (`packages/daemon/src/main.ts`).
- A preview never holds a provider key that was registered on the keys page. That key
  stays in the reviewer's browser and in the egress proxy's memory. The preview gets a
  per-preview token, and the proxy swaps it for the key only in that provider's own
  authentication field, on that provider's host (`PROVIDERS` and `derive_token` in
  `host/egress/koi_egress.py`). Two limits apply. The substitution protects
  only keys registered through the keys page; a real key pasted straight into a preview
  goes to the pull request's code, as does any other secret typed there, such as a
  database password. The keys page says so (`packages/daemon/src/keys.ts`). And the
  proxy does not limit what the registered key may do at the provider or what it may
  spend. It swaps the token into any request to the provider's host, and the registry
  caps a token at 600 requests an hour (`REQUESTS_PER_HOUR` in `koi_egress.py`), which
  caps the request count, not the cost.
- A preview reaches the network only through the egress proxy's allowlist
  (`host/egress/allow.txt`, plus the provider hosts in `koi_egress.py`). Its Docker
  network is internal with inter-container traffic off, and the firewall drops new
  connections from it to the host except to the proxy (`ensure_network` and
  `koi-firewall` in `host/cloud-init.sh`), so a pull request's code cannot reach
  other hosts, other previews or the host. Builds are different. The BuildKit
  container sits on a network with internet access, and only the metadata endpoint
  and the host are blocked, so a Dockerfile step can reach any host.
- Fork code runs only when someone with koi's credentials builds it. Nothing builds on
  push. The only workflow in `.github/workflows/` is CI. A build starts when someone
  with the CLI's AWS credentials runs `koi up --pr`, or plain `koi up` in a checkout of
  the fork (`packages/cli/src/up.ts`), or when someone on the box runs `koid ctl up`
  (`packages/daemon/src/main.ts`, `packages/daemon/src/control.ts`).
- Built-in recipe Dockerfiles are checked for writable BuildKit cache mounts and
  writable bind mounts by a test (`packages/daemon/test/recipes.test.ts`), which reads
  only `recipes/*/Dockerfile`. A repo's own recipe, a `koi.yaml` with a Dockerfile in
  the pull request, is not checked anywhere. koid hands the Dockerfile to
  `docker buildx build` without reading it (`packages/daemon/src/deployer.ts`,
  `packages/daemon/src/docker.ts`). A project Dockerfile with `--mount=type=cache`
  shares that cache across pull requests, and one pull request's build can poison it
  for the next.
- Nothing koi reports is signed. The preview record, the build log, the pull request
  comment and `koi list` are trusted because the host and the person running the CLI
  are trusted. There is no evidence that can be checked outside the host.

## Layout

| Path | What it is |
|---|---|
| `packages/shared` | Schemas and pure functions everything else validates with: labels, recipes, requests, preview records, providers. |
| `packages/cli` | The `koi` command. Compiles to one binary with `bun build --compile`. |
| `packages/daemon` | `koid`, the service on the box: builds, runs and routes previews, tracks activity, serves the keys page. |
| `packages/lambda` | The wake function behind CloudFront: the "waking up" page and the API that starts the box. |
| `infra` | OpenTofu for the AWS pieces. |
| `host` | Box provisioning (`cloud-init.sh`), the egress proxy (`egress/`), the verification firewall helper (`verify/`), the SSH gateway for the CLI (`ssh/`), and the recorder (`recorder/`) and verifier (`verifier/`) images a verification run uses. |
| `recipes` | Built-in recipes, one directory each. |
| `examples/hello` | The smallest preview: a static page. |

## Developing

```
bun install
bun run typecheck && bun run lint && bun run test
KOI_DOCKER_TESTS=1 bun run test packages/daemon   # also build and run a real container
uv run --with mitmproxy==12.2.3 --with pytest pytest host/egress/test
uv run --with pytest pytest host/verify/test   # the verification firewall helper
uv run --with pytest pytest host/verifier      # the verifier's supervisor and runner clients
```

CI and a Greptile review run on every pull request. Greptile's configuration is in `.greptile/`.

## License

koi is MIT licensed. See [LICENSE](LICENSE).
