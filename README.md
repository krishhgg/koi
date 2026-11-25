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
koi up --pr 2518 --keep llm_openai   # ...and have the recipe's slice keep llm_openai too
koi list                  # previews on the box
koi logs NAME [--build]   # container log, or the last build's log
koi lease NAME --minutes N   # hold a preview so no build replaces it, for N minutes
koi release NAME LEASE    # end a lease
koi down NAME [--force]   # remove a preview; --force removes a leased one
```

Add `--json` to any command for machine-readable output on stdout; progress goes to
stderr. Exit codes: 0 success, 1 failure, 2 bad usage.

The JSON that `koi up`, `koi lease` and `koi release` print carries `schemaVersion`, now
1 for each command. For a recipe that reports what its slice kept, `koi up` also prints
`slice`: the JSON object the recipe's build wrote, whose shape the recipe defines. It
describes `deployment`, which after a failed rebuild is the previous build.
`deployment.source` says what that build read, as koid hashed it from the tarball it
unpacked: `tree`, the git tree id of the project's files, which is `git rev-parse
COMMIT^{tree}` for a build of exactly that commit, and `matchesCommit`, whether it is.
`dirty` is the CLI's own `git status` of the working tree it packed. A clean checkout
in which git converts files on checkout (line endings, LFS) gives another tree; see
[What a deployment was built from](docs/design.md#what-a-deployment-was-built-from). `--keep NAME`,
repeatable, asks such a recipe to keep NAME whatever the change touched; see Recipes in
[docs/design.md](docs/design.md). [schemas/](schemas/) holds a JSON Schema (draft 2020-12) of each,
generated from the zod schemas the CLI's types come from. A command's `schemaVersion`
changes only when koi removes a field or changes what one means. Adding an optional field
keeps the version, so a program that reads the fields it knows keeps working. The schemas
refuse fields they do not name, so a program that validates with them copies them from
the koi commit it runs. `loginKey` in `koi up`'s output is a secret, and must never go
into evidence or logs.

`koi up --pr` builds GitHub's merge of the pull request into its base branch (the
repository's `refs/pull/N/merge`): the pull request as merging it now would give, with
the base branch's later changes. The output and the pull request comment say what was
built, as in "Built from #2518 (abc1234) merged into develop (def5678)". GitHub may keep
an old merge after the base alone moves on. koi then asks GitHub's API whether the pull
request can merge, which makes GitHub recompute the merge, and fetches it again for up
to 90 seconds. If it is still out of date, koi merges the head into the base's tip
itself with `git merge-tree` (git 2.43 or later), and says so. That merge reads nothing
from your checkout or machine but the commits: no git config, no attributes or merge
drivers of yours, only the `.gitattributes` in the base's tree. A pull request that
conflicts with its base has no merge, and koi stops before uploading and says to rebase
or merge the base. Checking the merge against the base needs the base branch's name,
which koi asks gh for, so a merge build needs gh installed and signed in. `--head`
builds the head as pushed instead, and needs no gh. koi runs git and gh without a
terminal, so neither can ask you for a password or passphrase: fetching from origin
needs an SSH agent or a git credential helper that answers on its own.

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
upload source, start the box, and run commands on it; nothing else. The profile may
hold static keys or sign in through IAM Identity Center (`aws sso login`). It finds the
box by its `koi:role = box` tag, the preview domain from the box's `Domain` tag, and the
upload bucket from its `koi:bucket` tag (from the account id for a box applied before
that tag); `KOI_INSTANCE_ID`, `KOI_DOMAIN` and `KOI_BUCKET` override them. A per-user config file can name the deployment instead, including one
in another AWS account, and other hosts later; see
[docs/configuration.md](docs/configuration.md).

## Operating it

The AWS deployment is an OpenTofu module, `infra/modules/koi`: the box, its security
group and roles, the uploads bucket, the preview list parameter, the wake function,
CloudFront, its certificate and the DNS records. `infra/` is the root that uses it for
one personal account. It adds the backend, the providers with a `Project = koi` default
tag, and the `koi-cli` IAM user. A root in another account uses the module the same
way; see [From another root](#from-another-root).

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
| Remove the AWS stack | `tofu -chdir=infra destroy`. The uploads bucket goes with what is left in it (one-day uploads only). A state applied before the module set `force_destroy` on that bucket needs one `tofu apply` first, or the destroy stops on `BucketNotEmpty` |
| Install a new koid, recipes, egress proxy and SSH gateway | `AWS_PROFILE=<admin> scripts/deploy-host.sh` |
| Set up, or update, a plain Linux VM as a host | `scripts/host-bundle.sh DIR`, copy `DIR` to the VM, then `sudo DIR/install-vm.sh --domain D --tls MODE` there |
| Set up this machine as a host for `koi up --local` | `scripts/host-bundle.sh DIR`, then `sudo DIR/install-vm.sh --local --user "$USER"` |
| Let a CLI reach a host over SSH | On the host, after the deploy: append the CLI's public key to `/etc/ssh/koi-connect/authorized_keys` and read `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`; on the CLI, `koi target trust NAME --fingerprint SHA256:...` (see [docs/configuration.md](docs/configuration.md)) |

Update the box before the CLI; see Updating the box and the CLI in
[docs/design.md](docs/design.md).

koi also runs without AWS. `host/install-vm.sh` sets up an Ubuntu 24.04 VM
anywhere, which the CLI reaches over SSH, or the machine the CLI runs on, which
`koi up --local` reaches through koid's control socket. It runs the same
provisioning as the AWS box without the AWS parts: certificates come from
Caddy's own CA or from Let's Encrypt over HTTP-01 or a DNS provider of your
choice instead of Route 53, nothing stops the host when it is idle, and koid
takes uploads through its socket instead of S3. See Setting up a Linux host and
A local host in [docs/configuration.md](docs/configuration.md).

### From another root

The module has no provider or backend block and no OpenTofu-only syntax, so a root in
another account can call it with its own backend, providers and default tags, and no
IAM users. A root that assumes a role, sets `Project` to another name, has the module
create the zone and names a VPC and subnet validates with Terraform 1.9.0 and with
OpenTofu.

1. Copy the module with the files it links to. `files/cloud-init.sh` links to
   `host/cloud-init.sh`, and `files/handler.mjs` is the wake function that
   `scripts/build-lambda.sh` writes:

   ```sh
   scripts/build-lambda.sh
   cp -rL infra/modules/koi <root>/modules/koi
   ```

   The copy holds both as plain files, so the other repository needs no Bun. Copy it
   again when `host/cloud-init.sh` or `packages/lambda` changes. Planning writes
   `files/wake.zip` next to them; ignore it there as `.gitignore` does here.

2. Call it. The box goes in the region of the `aws` provider; the certificate goes in
   us-east-1 through `aws.us_east_1`, because CloudFront takes it from there only.

   ```hcl
   provider "aws" {
     alias  = "us_east_1"
     region = "us-east-1"
   }

   module "koi" {
     source    = "./modules/koi"
     providers = { aws = aws, aws.us_east_1 = aws.us_east_1 }

     domain      = "previews.example.com"
     create_zone = true
   }
   ```

   | Variable | Default | Meaning |
   |---|---|---|
   | `domain` | none | Previews live at `<label>.<domain>`. Use a registrable domain of its own: previews run pull-request code, and a subdomain of another site's domain is same-site with everything under it. |
   | `zone_id`, `create_zone` | `null`, `false` | Set exactly one. `zone_id` names an existing hosted zone in the account; `create_zone = true` makes one, and the registrar must then point at its `name_servers` output before the certificate validates. |
   | `name_prefix` | `koi` | Names `<prefix>-box`, `<prefix>-wake`, `<prefix>-uploads-<account>` and `/<prefix>/previews`. |
   | `instance_type`, `root_volume_gb` | `t3.xlarge`, `80` | The box. |
   | `vpc_id`, `subnet_id` | the default VPC | Set both or neither. The subnet needs a route to an internet gateway. |
   | `tags` | `{}` | Added to every resource that takes tags, on top of the provider's `default_tags`. |
   | `verify_pool` | `10.213.0.0/20` | See [docs/verify.md](docs/verify.md), "Run network". |
   | `wake_reserved_concurrency` | `null` | Reserves concurrency for the wake function, which also caps it. Lambda keeps 100 of a region's quota unreserved, so a reservation fails where other functions already hold all but 100 plus this many, and on the new-account quota of 10. The personal root reserves 10 unless its own `wake_reserved_concurrency` is set to `null`. |
   | `ubuntu_ami_name` | Ubuntu 24.04 | The AMI name pattern for a new box. |

   Outputs: `instance_id`, `uploads_bucket`, `previews_parameter`, `domain`,
   `verify_pool`, `region`, `zone_id`, `name_servers`, `cloudfront_domain`,
   `wake_function_url`, `box_public_ip` and `operator_policy_json`.

3. Give people `operator_policy_json`, for example as the inline policy of an
   Identity Center permission set. It allows what `koi up` needs and no more: start and
   describe the box, run `AWS-RunShellScript` on that one instance through SSM, upload to
   the bucket and read the preview list. It names the instance, so a rebuilt box needs
   the permission set updated. The two host scripts need more, such as reading back
   what they upload so the box can download it; run them with an admin session in
   that account.

4. Install koid. The scripts read the deployment from the environment instead of
   `tofu output` of `infra/`, so they never touch the other root's state. Set all
   four: with `KOI_INSTANCE_ID` set, a script stops when another is missing instead of
   reading it from `infra/`:

   ```sh
   export AWS_PROFILE=<admin profile in that account> AWS_REGION=us-east-1
   export KOI_INSTANCE_ID=<instance_id> KOI_BUCKET=<uploads_bucket>
   export KOI_PREVIEWS_PARAM=<previews_parameter> KOI_DOMAIN=<domain>
   scripts/deploy-host.sh
   ```

   The box provisions itself at first boot. To provision it again, set
   `KOI_VERIFY_POOL=<verify_pool>` as well and run `scripts/provision-host.sh`. Without
   `AWS_REGION`, both scripts use the profile's region, then us-east-1. (For the
   personal root, with no `KOI_*` set, they use the `region` output of `infra/`.)

5. Point the CLI at the box with a target that names the profile, the instance and the
   bucket ([docs/configuration.md](docs/configuration.md), "A box in another
   account").

The CLI finds a box without a config file by the `koi:role = box` tag the module sets,
so a root whose `default_tags` set `Project` to something else does not hide it, and
its bucket by the `koi:bucket` tag, which carries the name prefix.

## Trust model and limits

koi builds and runs code from pull requests that may be hostile and puts the result on
the public internet. [docs/design.md](docs/design.md) describes the isolation. These
are its limits, each with the file that decides it.

- Anyone with the CLI's AWS credentials can run any command on the box, as root. The
  operator policy, which `koi-cli` has, grants `ssm:SendCommand` for the
  `AWS-RunShellScript` document on the instance (`infra/modules/koi/operator.tf`), and
  SSM runs such a script as root. The CLI itself
  only sends `koid ctl` commands (`packages/cli/src/box.ts`), but nothing holds the
  credentials to that.
- Previews have no hard disk quota. The box's root filesystem is ext4, where Docker's
  overlay2 storage cannot cap a container's writable layer (that needs XFS with project
  quotas), and nothing caps its volumes, so koid measures after the fact. When it
  starts and every five minutes after, it stops a preview whose writable layer and
  volumes together pass 10 GiB (`DISK_LIMIT_BYTES` in `packages/daemon/src/deployer.ts`,
  the timer in `packages/daemon/src/main.ts`). A preview can fill the disk between two
  checks.
- The host installer is for a dedicated machine, not a personal workstation, and
  `host/install-vm.sh`, `--local` included, runs it too: for `koi up --local` on a
  workstation, a Linux VM there is the cleaner host.
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
  security group opens only 443 (`infra/modules/koi/network.tf`). Outside AWS the
  certificates come from the TLS mode `install-vm.sh` was given, and which ports are
  open is the operator's to decide. On the AWS box a timer checks every minute and
  powers the machine off (`systemctl poweroff`) once 10 minutes pass with no activity.
  A koi request, a build and an open connection to a preview all count as activity;
  koid looks for open connections every 30 seconds (`packages/daemon/src/main.ts`).
- On a local host, any member of the `koi-control` group can run any koid command
  and upload source, as a holder of a `koi-connect` key can over SSH: koid makes its
  control socket mode 0660 in that group (`packages/daemon/src/control.ts`), and
  `install-vm.sh --user` adds accounts to it. The CLI talks only to a socket on a path
  no other account could have written to (`socketPathProblem` in
  `packages/cli/src/transports/local.ts`), and checks koid's descriptor before it
  sends any source.
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
| `packages/shared` | Schemas and pure functions everything else validates with: labels, recipes, requests, preview records, providers, and the CLI's `--json` output. |
| `packages/cli` | The `koi` command. Compiles to one binary with `bun build --compile`. |
| `packages/daemon` | `koid`, the service on the box: builds, runs and routes previews, tracks activity, serves the keys page. |
| `packages/lambda` | The wake function behind CloudFront: the "waking up" page and the API that starts the box. |
| `schemas` | JSON Schemas of what `koi up`, `koi lease` and `koi release` print with `--json`, written by `bun scripts/json-schemas.ts`. |
| `infra` | OpenTofu for the AWS pieces: the koi module (`modules/koi`) and the personal deployment's root. |
| `host` | Box provisioning (`cloud-init.sh`), the installer for a host outside AWS (`install-vm.sh`), the egress proxy (`egress/`), the verification firewall helper (`verify/`), the SSH gateway for the CLI (`ssh/`), and the recorder (`recorder/`) and verifier (`verifier/`) images a verification run uses. |
| `recipes` | Built-in recipes, one directory each. |
| `examples/hello` | The smallest preview: a static page. |

## Developing

```
bun install
bun run typecheck && bun run lint && bun run test
KOI_DOCKER_TESTS=1 bun run test packages/daemon   # also build and run a real container
KOI_DOCKER_TESTS=1 bun run test packages/cli/test/local.integration.test.ts   # koi up --local, end to end
uv run --with mitmproxy==12.2.3 --with pytest pytest host/egress/test
uv run --with pytest pytest host/verify/test   # the verification firewall helper
uv run --with pytest pytest host/verifier      # the verifier's supervisor and runner clients
```

The local end-to-end test runs koid from source and Caddy in a container on the
host's network, so it needs port 443 free and no `koi-previews0` or
`koi-build0` bridge, as on a machine that is not itself a koi host.

After changing the `--json` output schemas in `packages/shared/src/cli-output.ts`, run
`bun scripts/json-schemas.ts` and commit what it writes to `schemas/`. A test fails while
the committed files differ from what the script writes.

CI and a Greptile review run on every pull request. Greptile's configuration is in `.greptile/`.

## License

koi is MIT licensed. See [LICENSE](LICENSE).
