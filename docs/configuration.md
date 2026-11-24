# Configuration

koi needs to know which host builds and serves previews, and under which
domain. This page covers the per-user config file, the repository alias, the
order in which koi picks a target, and how an existing AWS deployment moves to
the file. Until a file exists, koi works as it did before: it finds the AWS
box by its tags.

## The file

koi reads one file per user:

- `$XDG_CONFIG_HOME/koi/config.yaml` when `XDG_CONFIG_HOME` is set,
- `~/.config/koi/config.yaml` otherwise.

`--config PATH` or `KOI_CONFIG=PATH` names another file. A file named this way
must exist; the default file may be absent. A path may start with `~/`, which
koi expands to the home directory. A relative `XDG_CONFIG_HOME` is invalid by
the XDG specification; koi ignores it and uses `~/.config`.

The file holds references: an AWS profile name, an instance id, a bucket, a
path to an SSH key. It never holds a key, a token or a command. The host
keys koi trusts live in a separate known_hosts file the target names, which
`koi target trust` writes. `koi config
import-aws` writes it with mode 0600 in a directory with mode 0700. koi warns
when the file is readable by other users.

Unknown fields are errors, so a typo cannot pass as a setting. `version: 1` is
the only version this koi reads.

```yaml
version: 1
defaultTarget: owner-aws
targets:
  owner-aws:
    domain: previews.example.com
    transport:
      kind: aws-ssm
    aws:
      profile: koi-cli
      region: us-east-1
      instanceId: i-0123456789abcdef0
      uploadsBucket: koi-uploads-123456789012
    power:
      kind: ec2
```

Each target has these fields.

| Field | Meaning |
|---|---|
| `domain` | The domain previews live under, as `<label>.<domain>`. A bare domain: lowercase labels and dots, at least two labels, no scheme, port, path, wildcard or trailing dot. Required. |
| `address` | `scheme` and `port` of the preview URLs. Only `https` on `443` works in this version; the field is reserved. |
| `transport` | How koi reaches the host: `aws-ssm`, `ssh` or `local`. See the examples. |
| `aws` | `profile` (default `koi-cli`), `region` (default `us-east-1`), `instanceId` and `uploadsBucket`. Required with the `aws-ssm` transport or `ec2` power, and not allowed otherwise. Wake and commands use the same instance. |
| `power` | `ec2`: koi starts the instance before use, and it stops itself when idle. `always-on`: koi never stops the host and never starts it; when the host does not answer, koi stops with an error and the host's operator must start it. The `ssh` transport takes `always-on` only. |

## Repository alias

A repository may commit `.koi/target.yaml` with one target name:

```yaml
version: 1
target: team
```

The name resolves against the user's file. The alias file may not hold
anything else: no endpoint, domain, key path or command. koi reads it from the
checkout it runs in, never from a fetched pull request, and does not look in
parent directories. The file must be a regular file of at most 4 KiB; koi
ignores a symlink there with a warning and refuses a larger file. koi prints
the selected target before it uploads anything. CI should pass `--target`
rather than rely on the alias.

## Which target koi uses

In this order, the first that applies:

1. `--target NAME`
2. `KOI_TARGET`
3. The checkout's `.koi/target.yaml`
4. `defaultTarget` in the user's file
5. With no config file at all: the AWS deployment as the environment and
   discovery describe it (see Without a config file)

A config file that selects nothing is an error, not a fall back to discovery.
A name that the file does not have is an error, including one from
`.koi/target.yaml`.

Then koi applies overrides to the selected target, in this order: command line
flags, then environment variables, over the target as written, over the
defaults.

| Override | Applies to | Effect |
|---|---|---|
| `--domain D`, `KOI_DOMAIN` | any target | The domain the host must serve previews under. It changes what koi expects, never which host it talks to. |
| `KOI_AWS_PROFILE`, `KOI_AWS_REGION`, `KOI_INSTANCE_ID`, `KOI_BUCKET` | AWS targets | Replace the matching `aws` field. On an `ssh` or `local` target they are errors. |

An empty value (`--target ''`, `KOI_DOMAIN=`) is an error, not an absence.
The target with overrides applied is checked by the same rules as the file.

## Running koi from source in a checkout

Bun, which koi runs on, loads `.env`, `.env.local` and the `NODE_ENV`
variants from the current directory into the environment, and runs the
preload scripts a `bunfig.toml` there names, before koi starts. A repository
could put `KOI_CONFIG=./injected.yaml` in its `.env` and choose koi's config
file, with its host, bucket and credential profile, or point
`AWS_ENDPOINT_URL` at a server of its own. Once koi is running it cannot undo
either, and it does not try to.

The compiled `koi` binary is the supported way to run koi in any checkout. It
is built with `--no-compile-autoload-dotenv` and
`--no-compile-autoload-bunfig`, so it loads neither kind of file from the
directory it runs in. `bun run --filter @koi/cli build` writes it to
`packages/cli/dist/koi`.

Run from source (`bun packages/cli/src/main.ts`), koi refuses to go on when
the current directory has any file Bun would have loaded: `.env`,
`.env.local`, `.env.development`, `.env.production`, `.env.test`, their
`.local` variants, or `bunfig.toml`. The check asks only whether the file
exists. koi does not read it, and the list does not depend on `NODE_ENV`,
which such a file could have set. The error names the files and says to run
the compiled binary or to run from a directory without them. `.env.example`
is not loaded and does not count. `koi help` and `koi version` read nothing
and run anywhere.

A developer who trusts the checkout can set `KOI_TRUST_CHECKOUT=1` in the
shell. On Linux koi reads that variable from `/proc/self/environ`, the
environment the shell passed, so a `.env` that sets it does not grant itself
the override. Other platforms keep no such record, and koi takes the variable
from the environment as loaded, which a `.env` can set; there, use the binary
in a checkout you do not trust.

koi reads its settings from the environment as it stands. Variables passed
with `bun --env-file` and variables set at run time reach koi like any other;
koi no longer replaces its environment with the one its parent passed.
`bun --no-env-file` is not a substitute for the binary: it skips the dotenv
files, but a `bunfig.toml` preload still runs.

## The host check

Before koi hands a request to koid, it asks the host to describe itself
(`koid ctl describe`): protocol version, a host id koid keeps in its state
directory, the domain it serves, its address and what it can do. koi compares
the domain and address with the target. On a mismatch koi stops and says which
domain the host serves; nothing is sent to koid. On AWS this happens after the
source upload to S3 and after the box is awake, because SSM cannot reach a
sleeping box; the request itself goes to koid only after the check.

A koid from before this command exists cannot answer. On an AWS target koi
takes the configured domain, prints a warning and goes on, so that the CLI can
move to the config file before the host is redeployed. A descriptor koi cannot
read, or one that names another domain, is never excused.

## Examples

### The existing AWS deployment

The example at the top. S3 holds source uploads, SSM runs `koid ctl`, EC2 wake
and CloudFront ingress stay as they are, and the preview URLs do not change.
The instance id and bucket are placeholders; `koi config import-aws` fills in
the real ones.

### A Linux VM over SSH

```yaml
version: 1
defaultTarget: team
targets:
  team:
    domain: previews.example.com
    transport:
      kind: ssh
      endpoint:
        host: 203.0.113.10
        port: 22
        user: koi-connect
        identityFile: /home/operator/.ssh/koi_team_ed25519
        knownHostsFile: /home/operator/.config/koi/known_hosts
        hostKeyAlias: team
    power:
      kind: always-on
```

`identityFile` is a private key koi hands to ssh; `identityPublicKey` instead
names the public half of a key that ssh-agent holds. Exactly one of the two.
`user` is always `koi-connect`. `knownHostsFile` pins the host key under
`hostKeyAlias`. Paths are absolute or start with `~/`. `port` defaults to 22.
`power` must be `always-on`: koi cannot start a host over SSH. The walkthrough
below says how to set the host and the key up.

## Reaching a host over SSH

An SSH target is a Linux host that runs koid with its upload spool
(`KOI_UPLOADS=spool`) and the koi SSH gateway. The CLI logs in as the
`koi-connect` account with a key, and sshd runs the gateway for that account
whatever the client asked for. The gateway takes two commands and nothing
else: `ctl-b64 <blob>` runs `koid ctl` with the encoded arguments, and
`tunnel-v1` copies bytes between the session and koid's control socket,
over which `koi up` sends the source to the upload API. There is no shell,
no scp or sftp, no forwarding of ports, agents or X11, and no PTY. The
account has no password, is in no other group, and reads its authorized
keys from a root-owned file outside its home.

### On the host

1. Install the gateway. `scripts/deploy-host.sh` builds it and runs
   `host/ssh/install.sh`, which creates the `koi-connect` account and the
   `koi-control` group, installs the binary at
   `/usr/local/libexec/koi-ssh-gateway`, writes the sshd `Match User
   koi-connect` block to `/etc/ssh/sshd_config.d/00-koi-connect.conf`,
   checks it, and reloads sshd. A reload leaves open sessions alone. The
   standalone installer for a plain VM is a later change; until then run
   `host/ssh/install.sh` by hand as root with the gateway binary as its
   argument, after `host/cloud-init.sh`.

   The account's password field is `*`, which no password hashes to, so no
   password logs in. The account is not locked. A locked account has a field
   that starts with `!`, which `usermod -L` writes and `useradd` leaves. With
   `UsePAM no`, sshd refuses a locked account before it looks at any key, so
   the installer would succeed and every CLI login would fail. OpenSSH does
   not read `*` as locked. The installer sets `*` whenever the field is
   anything else, which also repairs an account an earlier installer locked.

   The block (`host/ssh/sshd.sh`) gives the account keys only, no PTY, no
   `~/.ssh/rc`, no chroot, no forwarding, the gateway as its one command,
   and no variable from the client or from the configuration's `AcceptEnv`
   and `SetEnv`. It depends on how sshd settles the keywords it sets: the
   global section is read first, then the `Match` blocks in order once the
   client is known, and for each of those keywords the first value
   obtained wins, a `Match` value over the global one, except `AcceptEnv`,
   to which every matching block's list is added. That is the rule for
   these keywords, each tried with `sshd -T`; other keywords have rules of
   their own. So the block is written to be the first `Match` sshd reads,
   and to set every keyword that decides who gets in, what runs, where and
   with what: `ForceCommand`, `ChrootDirectory none`, `TrustedUserCAKeys
   none`, `AuthorizedKeysFile`, `AuthorizedKeysCommand none`, the
   principals keywords, the authentication keywords, `PermitTTY`,
   `PermitUserRC`, every forwarding keyword, `PermitOpen none`,
   `PermitListen none`, `SetEnv` and `AcceptEnv`. A global
   `ChrootDirectory` or `TrustedUserCAKeys`, or a later block that sets
   one, changes nothing for the account. `none` is a switch for
   `ForceCommand` and `ChrootDirectory`, which sshd clears once the block
   applies. For `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`,
   `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` it is a
   literal name that sshd keeps as the value, a file it cannot open or a
   command it cannot run, which comes to the same. sshd cannot clear
   `AcceptEnv` or `SetEnv` inside a `Match` block, but a list given there
   replaces the global one for the account, so the block names one
   placeholder each (`KOI_NO_CLIENT_ENV`, `KOI_NO_SERVER_ENV=`) that
   nothing reads; the global `AcceptEnv LANG LC_*` of a stock Ubuntu does
   not reach the account. `PermitUserEnvironment` is the one keyword of
   the set that sshd does not take inside a `Match` block; the installer
   reads the global value with `sshd -T` and refuses anything but `no`.
   `ExposeAuthInfo` is not in the block: where the global section or a
   later block turns it on, sshd adds `SSH_USER_AUTH`, the path of a file
   listing how the client authenticated, to the gateway's environment.

   The installer refuses to reload sshd unless the files, read as sshd
   reads them (`/etc/ssh/sshd_config` and every `Include` in sshd's order,
   with sshd's quoting), show two things, and `sshd -t` passes after. The
   files are read first: sshd, with `-t` as with `-T`, opens whatever an
   `Include` names, and a named pipe with no writer would hold it for
   good, where the reader refuses the pipe without opening it. The
   block is the first `Match` sshd reads: a `Match` before the `Include`
   would set the account's keywords first, and would also swallow the
   `Include` into itself. And no other `Match` block, whoever it is for,
   sets `AcceptEnv`: sshd appends every matching block's `AcceptEnv` to
   the account's list, and the installer does not read whom a block is
   for. sshd reads `Match` criteria by rules of its own, under which `User
   *,!'koi-connect'` keeps its quotes and excludes nobody, and the
   installer does not try to follow them. On a host dedicated to koi no
   other account needs a variable from its client: set `AcceptEnv` in the
   global section, which the block replaces for the account, or drop it.
   What the installer cannot read as sshd would is refused with its file
   and line, never skipped: a NUL byte anywhere (sshd cuts the line there,
   newline included, where bash drops the byte and reads on), a quote
   never closed, an `Include` with `~`, `[` or `\`, and an `Include` of
   anything but a regular file (sshd opens a named pipe and reads what it
   is fed, a directory as nothing, and stops on a link to nothing).
   Last, `sshd -T -C user=koi-connect` for a few client addresses shows
   every keyword of the block with the block's value, `AcceptEnv` and
   `SetEnv` with the placeholders alone: that sshd loads the block as
   written. What the installer cannot see: a sshd started on another file
   (`-f`), and a `Match` block added after it ran. Run it again after any
   change to the sshd configuration.
2. Authorize the CLI's key: append its public key (the `.pub` file, one
   line) to `/etc/ssh/koi-connect/authorized_keys`.
3. Read the host key fingerprint, to hand to whoever runs the CLI:
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Send it over a
   channel you trust; it is what stops a host in the middle.

### On the machine running koi

1. Make a key for koi, with no passphrase or one that ssh-agent holds:
   `ssh-keygen -t ed25519 -f ~/.ssh/koi_team_ed25519 -C koi`. Name its
   private half as `identityFile`, or add it to ssh-agent and name the
   public half as `identityPublicKey`; then ssh asks the agent for that one
   key and no other.
2. Write the target as in the example, with the host's address, the key and
   a `knownHostsFile` of koi's own. The file need not exist yet.
3. Trust the host key: `koi target trust team --fingerprint SHA256:...`
   with the fingerprint from the host's operator. koi asks the host for its
   keys with `ssh-keyscan` and writes the one whose fingerprint matches to
   the known_hosts file under the alias, mode 0600. A fingerprint that
   matches none of the offered keys is refused and nothing is written. koi
   never trusts a key on first use, and a changed key stops every command
   until `koi target trust` is run again with the new fingerprint. While it
   reads and writes the file koi holds the directory `known_hosts.lock`
   beside it, as `koi config import-aws` holds `config.yaml.lock`, so two
   targets that share a file cannot lose each other's key. A lock a crash
   left behind is removed by hand, as with the config file's.

   The alias gets a line of its own, and no other line may apply the alias
   to another key, as OpenSSH reads the file:

   - An entry the alias shared with other names (`team,prod ssh-ed25519
     ...`) keeps those names and their key.
   - A wildcard that matches the alias stays for the names it still covers,
     with a negation added (`*,!team ssh-ed25519 ...`).
   - A hashed entry of the alias (`|1|salt|hash`) is removed.
   - A `@cert-authority` line follows the same rules.
   - A `@revoked` line stays as it is, since it only takes trust away. koi
     refuses a key the file revokes for the alias. A line with a certificate
     revokes the public key inside it, as OpenSSH reads it, so koi compares
     the fingerprints `ssh-keygen -l` prints.

   Before the new file replaces the old one, koi runs `ssh-keygen -F` for
   the alias on it, so `koi target trust` needs `ssh-keygen` on `PATH`. If
   that finds a key other than the new one, does not find the new one, or
   finds a revocation of the new one, koi fails and the old file stays as it
   was.
4. Check with `koi target show team`, which prints the endpoint and the
   fingerprints of the keys the file trusts for the alias. A wildcard or a
   hashed entry that matches the alias counts. A key the file revokes for the
   alias does not, and neither does a line OpenSSH cannot parse or a
   certificate on a line without a marker, since strict `ssh` takes none of
   them. If the file has a line for the alias, `koi target show` runs
   `ssh-keygen -l` on the keys, so it needs `ssh-keygen` on `PATH` too.

Then `koi up` works as on AWS, with these differences. The source goes to
the host through the tunnel and into the spool, not to a bucket, so the
upload needs the host up: the upload first connects, waits for koid and
checks the host's descriptor against the target, and only then opens the
tunnel. The host is never started or stopped: a host that refuses the
connection is reported as one its operator must start. The descriptor check
is the same as on AWS, before any source is handed to koid.

### What koi runs

koi runs the system `ssh` with an argument list, never a shell string, and
with `-F none`, so neither `~/.ssh/config` nor `/etc/ssh/ssh_config` adds
anything. Every option is on the command line: batch mode, `IdentitiesOnly`
with the target's one identity, public key authentication only, strict
host key checking against the target's known_hosts file and alias with the
system known_hosts files ignored, no PTY, no agent, X11 or port forwarding,
no local command, no proxy, a 30 second connect timeout and keepalives.
Each path is passed in double quotes, since ssh splits an unquoted option
value on whitespace and would read `/a b` as two files; a path with `%`
(an ssh token), a line break or a control character is refused when the
config file is read. Of koi's environment ssh gets `PATH`, and
`SSH_AUTH_SOCK` only when the identity is in the agent. One master
connection (`ControlMaster=auto`, its socket in a directory of koi's own
with mode 0700) carries every session of a koi run; koi ends it when the
command finishes, fails or is ended by SIGINT or SIGTERM, and a master left
behind by a crash ends itself after ten minutes idle.

Each operation has a time limit when the command sets none, since ssh keeps
a session up for as long as sshd does and a koid that stops answering
would otherwise hold koi for good: five minutes for a `koid ctl` command
(what the AWS transport gives SSM for one), one minute for the descriptor,
thirty minutes for an upload in all, and a tunnel that carries nothing in
either direction for two minutes is given up as koid not answering. koi
writes the source in pieces of at most 64 KiB and restarts that clock after
each one, so a slow transfer is not a stall. A link under about 550 bytes a
second counts as one. A limit the command sets stands instead.

### Errors

- `koi does not trust the host key of ...`: no key is enrolled under the
  alias, or the host's key changed. Get the fingerprint from the operator
  and run `koi target trust`.
- `... refused koi's key for koi-connect: Permission denied`: the key's
  public half is not in `/etc/ssh/koi-connect/authorized_keys` on the
  host, or the identity in the target is the wrong key. If sshd's log says
  `User koi-connect not allowed because account is locked`, run
  `host/ssh/install.sh` again, which sets the account's password field to
  `*`.
- `cannot connect to ...; target team does not manage the host's power`:
  sshd did not answer. The host is off, or sshd is down, and koi cannot
  start it.
- `koid on ... is not taking uploads` or `waiting for koid on ... to
  start`: sshd and the gateway answer but koid does not. koi waits up to
  five minutes for a koid that is starting.

### A local Docker host (reserved)

```yaml
version: 1
targets:
  local:
    domain: koi.test
    address:
      scheme: https
      port: 443
    transport:
      kind: local
      controlSocket: /run/koi-local/control.sock
    power:
      kind: always-on
```

## Moving the existing AWS deployment to the file

Nothing has to change for the deployment to keep working. When ready:

1. Make sure the current `infra/` is applied, which tags the box with its
   domain, or know the domain.
2. Run `koi config import-aws --name owner-aws`. It finds the deployment the
   way koi always has (the profile, the region, the one instance tagged
   `koi:role=box`, the bucket from the account id) and reads the domain from
   `--domain`, `KOI_DOMAIN` or the instance's `Domain` tag, in that order.
   Without any of the three it stops; it does not guess a domain. A box applied
   before the module set `koi:role` is found by `Project=koi` and
   `Name=koi-box` instead, when no instance has `koi:role`.
3. It writes the target to the user's file and prints what it wrote. The first
   target written becomes `defaultTarget`. An existing target of the same name
   is kept unless you pass `--replace`. While it reads and writes the file, it
   holds the directory `config.yaml.lock` next to it, so two imports cannot
   lose each other's target. An import that finds the lock held waits up to a
   minute for it to go away, then fails. koi never removes a lock it did not
   make. If a `koi config` run crashed and left one behind, check that no
   other `koi config` is running, then remove the directory by hand.
4. Check with `koi config show`, which prints the resolved target without
   calling AWS.

Or write the file by hand from the example, with your instance id, bucket and
domain.

The next `koi up` prints the target it uses, with the file it came from, its
transport and its domain, before it uploads anything. Deploy the current koid
(`scripts/deploy-host.sh`) when convenient; until then koi warns once per run
that it cannot check the host's domain.

`koi config import-aws` rewrites the whole file, so comments in it are lost.

## A box in another account

A deployment made by another root, in another AWS account, works the same way:
the target names that account's profile, the instance and the bucket, and koi
asks AWS nothing about tags. What the root's `default_tags` set, `Project`
included, does not matter to it.

1. Give the profile the module's `operator_policy_json` (README, "From another
   root"). In an account people sign in to through IAM Identity Center, that is
   a permission set, and the profile is an SSO profile in `~/.aws/config`:

   ```ini
   [profile koi-company]
   sso_session = company
   sso_account_id = 111122223333
   sso_role_name = KoiOperator
   region = us-east-1

   [sso-session company]
   sso_start_url = https://example.awsapps.com/start
   sso_region = us-east-1
   sso_registration_scopes = sso:account:access
   ```

   Run `aws sso login --profile koi-company` before koi. Identity Center
   decides how long a login lasts. Without a current one, koi stops with the
   SDK's error, which says to run `aws sso login`, so an agent that runs koi
   unattended needs someone to sign in again when the login ends. A profile with
   static keys, `credential_process` or an assumed role works too: koi takes
   whatever the AWS SDK's shared config files resolve for the profile.
   `packages/cli/test/aws-credentials.test.ts` resolves a static-key profile
   and an SSO profile through the CLI's own clients.

2. Write the target, with the `instance_id` and `uploads_bucket` outputs of the
   root:

   ```yaml
   version: 1
   defaultTarget: company
   targets:
     company:
       domain: previews.example.com
       transport:
         kind: aws-ssm
       aws:
         profile: koi-company
         region: us-east-1
         instanceId: i-0123456789abcdef0
         uploadsBucket: koi-uploads-111122223333
       power:
         kind: ec2
   ```

   Or let koi find them: `KOI_AWS_PROFILE=koi-company koi config import-aws
   --name company` finds the instance by its `koi:role=box` tag and the bucket
   as `koi-uploads-<account id>`. With a `name_prefix` other than `koi`, set
   `KOI_BUCKET` to the bucket for the import. Discovery needs
   `ec2:DescribeInstances`, which the operator policy has, and
   `sts:GetCallerIdentity`, which every principal has.

3. Check with `koi config show`, then `koi up` prints the target before it
   uploads anything.

Keep a target per account and pick one with `--target` or `KOI_TARGET`.

## Without a config file

With no config file and no `--target`, `KOI_TARGET` or alias, koi behaves as
before this file existed: `KOI_AWS_PROFILE` (default `koi-cli`),
`KOI_AWS_REGION` (default `us-east-1`), and `KOI_INSTANCE_ID`, `KOI_BUCKET`
and `KOI_DOMAIN` when set; what is not set is discovered from the box's tags
(`koi:role=box`, else `Project=koi` and `Name=koi-box`) and the account. koi prints one notice per run pointing at `koi config
import-aws`. This path is for compatibility; explicit targets never read the
`Domain` tag.

## Not supported yet

The schema accepts these so a file written for a later koi reads cleanly, but
this version stops with a plain error when a command selects them:

- the `ssh` transport with `ec2` power (an SSH host koi would also start),
- the `local` transport and `koi up --local`,
- an SSH `channel` on an `aws-ssm` target,
- an `address.port` other than 443,
- following a container log live (`koi logs` shows a bounded tail), and the
  control channel for interactive verification, on either transport.
