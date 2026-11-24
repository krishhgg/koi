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
| `power` | `ec2`: koi starts the instance before use, and it stops itself when idle. `always-on`: koi never stops the host and never starts it; when the host does not answer, koi stops with an error and the host's operator must start it. The `ssh` and `local` transports take `always-on` only. |

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

1. `--local`: koid on this machine, a target built into koi that needs no
   config file (see A local host). It cannot be combined with `--target`.
2. `--target NAME`
3. `KOI_TARGET`
4. The checkout's `.koi/target.yaml`
5. `defaultTarget` in the user's file
6. With no config file at all: the AWS deployment as the environment and
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

## Setting up a Linux host

`host/install-vm.sh` makes a plain Linux machine a koi host: an Ubuntu 24.04
VM at any provider, which the CLI reaches over SSH, or a machine the CLI runs
on, with `--local`. It runs `host/cloud-init.sh`, the AWS box's provisioning,
for Docker, the memory slice, the preview and build networks, the BuildKit
builder, the firewall and Caddy, with the AWS parts switched off. Then it
installs what `scripts/deploy-host.sh` installs on the AWS box: koid, the
recipes, the egress proxy, the verification helper and, unless `--local`, the
SSH gateway. What differs from the AWS box:

- Certificates come from the TLS mode given to the installer, not from Route 53.
- Nothing stops the host when it is idle, and there is no wake page: the host
  is always on.
- koid takes uploads through its control socket into a spool
  (`KOI_UPLOADS=spool`), and keeps the list of live previews in a file
  (`KOI_LIVE=file`), where the AWS box uses S3 and SSM.

The installer takes its files from the directory it is in. Build that
directory on a machine with this repository and Bun, copy it whole, and run
the installer there as root:

```sh
scripts/host-bundle.sh /tmp/koi-host
scp -r /tmp/koi-host vm:
ssh vm sudo koi-host/install-vm.sh --domain previews.example.com --tls acme-http
```

`scripts/host-bundle.sh` builds koid and the gateway the way
`scripts/deploy-host.sh` does, packs the recipes, the egress proxy, the SSH
installer and the verification helper, and writes the SHA-256 of every file to
`SHA256SUMS`. The installer refuses a directory whose files do not match it.
Every step can be repeated: run the installer again with a new bundle to
update the host.

| Option | Meaning |
|---|---|
| `--domain D` | Previews are served at `<label>.D`. Required, except with `--local`, where it defaults to `koi.test`. |
| `--tls MODE` | How Caddy gets certificates for `*.D`; see the table below. Required, except with `--local`, where it defaults to `internal`. |
| `--local` | This machine, for the local transport: no SSH gateway. |
| `--user NAME` | An account that may use koid through its control socket. Repeat it for more. |
| `--verify-pool CIDR` | The network verification runs are carved from, as `var.verify_pool` on AWS. Default `10.213.0.0/20`. |

| TLS mode | Certificates | What the host needs |
|---|---|---|
| `internal` | One wildcard certificate from Caddy's own CA. | Every machine that visits previews trusts the CA's root, `/var/lib/caddy/pki/authorities/local/root.crt`: on the host itself, `sudo caddy trust --address unix//run/caddy/admin.sock`. |
| `acme-http` | A certificate per preview name from Let's Encrypt, which cannot issue a wildcard over HTTP. Caddy gets one at the first visit of a name, once koid confirms the name is a preview's (`/__koi/tls-ask`), so a stranger cannot make the host order certificates for names of their choosing. | A DNS record `*.D` pointing at the host, and ports 80 and 443 open to the internet: Let's Encrypt checks each name over HTTP-01 on 80 or TLS-ALPN-01 on 443. Let's Encrypt allows 50 new certificates a week for a registered domain. |
| `acme-dns:PROVIDER` | One wildcard certificate from Let's Encrypt over DNS-01, through `github.com/caddy-dns/PROVIDER` (`cloudflare`, `digitalocean`, `hetzner` and so on), which the installer builds Caddy with. | A DNS record `*.D` pointing at the host, port 443 open to visitors, and the provider's API token. The installer writes `/etc/koi/caddy/dns.caddy` with `dns PROVIDER {env.KOI_DNS_API_TOKEN}`, and `/etc/koi/caddy/env` (mode 0600) with an empty `KOI_DNS_API_TOKEN=`. Caddy refuses the config without the token, so the first run stops before it starts koid: put the token in that file, edit the `dns` line for a provider that takes other arguments, and run the installer again. It keeps both files on a run again. To change the token later, edit the file and run `systemctl restart caddy`. |

koid reads the mode from `KOI_TLS` in `/etc/koi/env` and writes the matching
`tls` block into the Caddyfile it owns. With `acme-dns` the block imports
`/etc/koi/caddy/dns.caddy`, which root owns and Caddy reads, and the token is in
Caddy's environment alone, so koid never sees it. Both files are in
`/etc/koi/caddy`, a directory of root's that Caddy may read, so that no other
account can put a file or a link there. The AWS box sets no `KOI_TLS`
and keeps its Route 53 block.

Caddy's admin API, through which koid loads each new Caddyfile, is a unix
socket outside AWS: `/run/caddy/admin.sock`, mode 0660 in the `caddy` group,
in a directory only root and that group may enter. Provisioning puts koid's
account, `koi`, in the group, and the installer sets `KOI_CADDY_ADMIN` to the
socket. On `127.0.0.1:2019`, as on the AWS box, any account on the machine
could change what Caddy serves, or have it answer with its environment and so
the provider's token. Commands that talk to the admin API take the socket with
`--address unix//run/caddy/admin.sock`, as root or as a member of the group.

The installer changes the machine as `host/cloud-init.sh` changes the AWS box
(see Trust model and limits in the README): it sets Docker's default cgroup
parent to `koi.slice`, which puts every container on the machine under koi's
memory ceiling and restarts Docker once, adds iptables rules, and runs Caddy
on port 443. Give it a machine, or a VM, of its own. It stops before changing
anything on a machine that already has a Caddy it did not set up: an
`/etc/caddy/Caddyfile`, the `caddy` package, or a `caddy.service` that runs
another config. Its setup would replace that unit and remove that file.

When it finishes, the installer prints what is left to do once: the DNS record
or `/etc/hosts` lines, the CA, the ports, and for an SSH host the key to
authorize and the fingerprint to hand to the CLI's operator.

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

1. Install the gateway. On a plain VM `host/install-vm.sh` does it with
   the rest of koi (see Setting up a Linux host); on the AWS box
   `scripts/deploy-host.sh` does. Both run `host/ssh/install.sh`, which
   creates the `koi-connect` account and the `koi-control` group, installs
   the binary at `/usr/local/libexec/koi-ssh-gateway`, writes the sshd
   `Match User koi-connect` block to
   `/etc/ssh/sshd_config.d/00-koi-connect.conf`, checks it, and reloads
   sshd. A reload leaves open sessions alone.

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

### A local host

```yaml
version: 1
targets:
  dev:
    domain: koi.test
    transport:
      kind: local
      controlSocket: /run/koi/control.sock
    power:
      kind: always-on
```

`controlSocket` is koid's control socket: `/run/koi/control.sock` on a host
`host/install-vm.sh` set up, or wherever a VM tool forwards it. `power` must be
`always-on`: koi cannot start koid. `koi up --local` stands for this target with
no file at all, the socket taken from `KOID_CONTROL_SOCKET` when it is set. See
A local host below.

## A local host

A local target reaches koid on the machine koi runs on, through koid's control
socket: no SSH, SSM or bucket in between. koid's network rules use the Linux
firewall, so the host is Linux: this machine, or a Linux VM whose socket a
tool forwards to the machine koi runs on (a Mac, say).

The CLI speaks to the socket as the SSH gateway does on its host. A command
runs koid ctl's own client (`packages/daemon/src/ctl.ts`) in the CLI's
process, with the same arguments, replies and exit codes as `koid ctl` on the
host. `koi up` sends the source over a connection to the socket, in the same
three requests the SSH tunnel carries: a ticket for the request id, size and
digest, the archive, the commit. koid checks the digest as it does over SSH.

Who may do this is decided on the host, as for the SSH gateway. koid makes the
socket mode 0660 with the group `koi-control`, in a directory of mode 2750, so
root, koid's account and the members of `koi-control` can open it, and no one
else. `install-vm.sh --user NAME` puts an account in that group, as the SSH
installer puts `koi-connect` there, and a member may do what a holder of a
`koi-connect` key may: any koid command, and uploads.

What stands in for the SSH host key is the socket's path. Before it sends
anything, koi checks that no account but root, the one running koi and `koi`,
the account koid runs as, could have put the socket, or anything on the way to
it, there. koi resolves the path itself, one entry at a time from `/`, and
walks the target of every symbolic link it meets in its place. Each entry must
belong to one of those three accounts, in a directory writable by its owner
alone or sticky like `/tmp`. A directory its group or anyone may write to
without the sticky bit is refused, as OpenSSH's StrictModes refuses one on the
way to `authorized_keys`, since another user of the machine could put a socket
of their own there and receive the source. Then, as over SSH, koid's descriptor
must name the target's domain before any of the source goes out.

### Once, on the machine

1. Build the bundle and install koid for this machine, with your account in
   `koi-control`:

   ```sh
   scripts/host-bundle.sh /tmp/koi-host
   sudo /tmp/koi-host/install-vm.sh --local --user "$USER"
   ```

   That serves previews under `koi.test` with Caddy's own CA. Pass `--domain`
   for another domain; `koi up --local` then needs the same `--domain`, or
   `KOI_DOMAIN`.
2. Log out and in again, or start a shell with `newgrp koi-control`, so the
   new group applies.
3. Trust Caddy's CA: `sudo caddy trust --address unix//run/caddy/admin.sock`
   adds its root to the system's trust store, and to Firefox's and Chrome's
   when `certutil` (`libnss3-tools`) is installed. It asks Caddy's admin API
   for the root, which listens on that socket. For another machine, or a program with a store of its own, the
   root is `/var/lib/caddy/pki/authorities/local/root.crt`.
4. Names: `/etc/hosts` takes no wildcard, so add a line per preview,
   `127.0.0.1 hello.koi.test`, or let a local resolver answer for the whole
   domain, as dnsmasq does with `address=/koi.test/127.0.0.1`. Browsers, and
   systemd-resolved as Ubuntu runs it, already resolve every `*.localhost`
   name to the machine itself, so `--domain koi.localhost` needs neither
   there.

Then, in a checkout, `koi up --local`, and `koi list --local`, `koi down NAME
--local` and the rest. A target with `transport: local` in the config file
works the same way, with `--target`.

### A Linux VM on a Mac

Run the installer with `--local` inside the VM, and forward the VM's
`/run/koi/control.sock` to a socket on the Mac. With Lima, for example:

```yaml
portForwards:
  - guestSocket: /run/koi/control.sock
    hostSocket: "{{.Dir}}/sock/koi.sock"
```

Then name that socket on the Mac: a target with it as `controlSocket`, or
`KOID_CONTROL_SOCKET=~/.lima/koi/sock/koi.sock koi up --local`. The account in
the VM that the tool forwards as must be in `koi-control`. Forward the VM's
port 443 to the Mac as well, and point the names at the address that reaches
it.

### Errors

- `there is no control socket at ...`: koid is not running there. koi cannot
  start it: `sudo systemctl start koid`, or set the machine up as above.
- `this account may not open ...`: the account is not in `koi-control` in this
  session. Run the installer with `--user`, then log in again.
- `koi does not trust the control socket of target ...`: a directory on the
  way to the socket can be written by others, or an entry on the way belongs
  to another account. Use a socket in a directory only root, you or koid's
  account can write to.
- `waiting for koid at ... to start`: the socket is there and koid does not
  answer yet. koi waits up to five minutes, as over SSH.

## Moving the existing AWS deployment to the file

Nothing has to change for the deployment to keep working. When ready:

1. Make sure the current `infra/` is applied, which tags the box with its
   domain, or know the domain.
2. Run `koi config import-aws --name owner-aws`. It finds the deployment the
   way koi always has (the profile, the region, the one instance tagged
   `koi:role=box`, the bucket from its `koi:bucket` tag or else the account
   id) and reads the domain from
   `--domain`, `KOI_DOMAIN` or the instance's `Domain` tag, in that order.
   Without any of the three it stops; it does not guess a domain. A box applied
   before the module set `koi:role` is found by `Project=koi` and
   `Name=koi-box`. Both are asked for, and two different instances between
   them stop the import: set `KOI_INSTANCE_ID`.
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
   by its `koi:bucket` tag, whatever the `name_prefix`. Discovery needs
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
(`koi:role=box` or `Project=koi` and `Name=koi-box`, and `koi:bucket`) and the account. koi prints one notice per run pointing at `koi config
import-aws`. This path is for compatibility; explicit targets never read the
`Domain` tag.

## Not supported yet

The schema accepts these so a file written for a later koi reads cleanly, but
this version stops with a plain error when a command selects them:

- the `ssh` transport with `ec2` power (an SSH host koi would also start),
  and the `local` transport with `ec2` power,
- an SSH `channel` on an `aws-ssm` target,
- an `address.port` other than 443,
- following a container log live (`koi logs` shows a bounded tail), and the
  control channel for interactive verification, on any transport.
