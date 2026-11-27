#!/bin/bash
# Provisioning for the koi box (Ubuntu 24.04), as root. cloud-init runs it once
# at first boot; scripts/provision-host.sh runs the same file again over SSM to
# update a box that already exists, so every step must be safe to repeat.
# Installs Docker and Caddy, creates the koi user and directories, and arms an
# idle shutdown so a box nobody is using stops itself. The daemon binary is
# installed separately. host/install-vm.sh runs the same file on a host
# outside AWS, with KOI_TLS and KOI_POWER (below) set for it.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# The base domain previews live under: var.domain in infra, which has no
# default. infra/modules/koi/box.tf puts a KOI_DOMAIN= line in front of this
# script for first boot and scripts/provision-host.sh does the same for a
# re-run, both from the domain output or KOI_DOMAIN. To run the script by
# hand, set KOI_DOMAIN yourself.
if [ -z "${KOI_DOMAIN:-}" ]; then
	echo "koi: KOI_DOMAIN is not set. It must be the preview domain (var.domain of the koi module, in infra/koi.auto.tfvars for the personal root); run scripts/provision-host.sh, which sets it, or set it before running this script." >&2
	exit 1
fi
if ! [[ $KOI_DOMAIN =~ ^[a-z0-9.-]+$ ]]; then
	echo "koi: KOI_DOMAIN '$KOI_DOMAIN' is not a bare hostname" >&2
	exit 1
fi
DOMAIN=$KOI_DOMAIN
IDLE_MINUTES=10

# The AWS region the box runs in, which Caddy's Route 53 client is given.
# infra/modules/koi/box.tf and scripts/provision-host.sh pass it as KOI_REGION
# the way they pass the domain. It goes into a unit file, so it is checked.
KOI_REGION=${KOI_REGION:-us-east-1}
if ! [[ $KOI_REGION =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]]; then
	echo "koi: KOI_REGION '$KOI_REGION' is not an AWS region name" >&2
	exit 1
fi

# How Caddy gets certificates for *.$DOMAIN; koid writes the same choice
# into the Caddyfile it owns (KOI_TLS in /etc/koi/env, which koid reads, and
# packages/daemon/src/caddy.ts). route53, the AWS box's: one wildcard
# certificate over DNS-01 with the box's role. host/install-vm.sh passes
# another for a host outside AWS: internal (Caddy's own CA), acme-http (a
# certificate per preview name over HTTP-01 or TLS-ALPN-01) or
# acme-dns:<provider> (a wildcard over DNS-01 with that caddy-dns module).
KOI_TLS=${KOI_TLS:-route53}
if ! [[ $KOI_TLS =~ ^(route53|internal|acme-http|acme-dns:[a-z0-9]+)$ ]]; then
	echo "koi: KOI_TLS '$KOI_TLS' is not route53, internal, acme-http or acme-dns:<provider>" >&2
	exit 1
fi
# ec2, the AWS box's: it stops itself after IDLE_MINUTES without activity,
# and the wake function starts it. always-on: a host koi never stops
# (host/install-vm.sh); no idle shutdown.
KOI_POWER=${KOI_POWER:-ec2}
if ! [[ $KOI_POWER =~ ^(ec2|always-on)$ ]]; then
	echo "koi: KOI_POWER '$KOI_POWER' is not ec2 or always-on" >&2
	exit 1
fi

# The addresses verification run networks are carved from, a /28 each
# (docs/verify.md, "Run network"): var.verify_pool in infra, which
# infra/modules/koi/box.tf and scripts/provision-host.sh pass as
# KOI_VERIFY_POOL the way they pass the domain. The default sits outside
# Docker's own pools (172.17.0.0/12 and 192.168.0.0/16, where koi-previews and
# koi-build get their subnets) and the default VPC (172.31.0.0/16). koid reads it from /etc/koi/verify/env, and so
# does the helper that installs a run's firewall permits.
KOI_VERIFY_POOL=${KOI_VERIFY_POOL:-10.213.0.0/20}
if ! [[ $KOI_VERIFY_POOL =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/(1[6-9]|2[0-8])$ ]]; then
	echo "koi: KOI_VERIFY_POOL '$KOI_VERIFY_POOL' is not an IPv4 network between /16 and /28" >&2
	exit 1
fi

# Provisioning is activity: on a re-run the idle timer may be armed, and the
# last activity can be long ago, so refresh the stamp before anything else.
# (Its owner and mode are fixed below; touch keeps them.)
[ -f /var/lib/koi/last-activity ] && touch /var/lib/koi/last-activity

apt-get update
# conntrack: the verification helper drops a run's connection state on revoke.
apt-get install -y ca-certificates curl gnupg unzip jq git conntrack

# --- Memory budget ----------------------------------------------------------
# A preview may use 6 GB and the builder 8 GB, so two previews and a build can
# ask for more memory than the box has. All of them run in koi.slice, which
# caps them together at 82% of memory: 12.8 GiB of a t3.xlarge's 15.6, leaving
# about 2.8 GiB for Docker, Caddy, koid and the SSM agent. When the slice is
# full the kernel kills a process inside it (a build step or a preview), never
# one of those. koid.service requires the slice, and koid checks its ceiling.
cat > /etc/systemd/system/koi.slice <<'UNIT'
[Unit]
Description=koi: builds and previews, under one memory ceiling

[Slice]
MemoryMax=82%
UNIT
systemctl daemon-reload
systemctl start koi.slice

# Previews get the slice from koid (docker run --cgroup-parent). buildx makes
# the builder's container and passes its own cgroup-parent option only with
# Docker's cgroupfs driver, but Ubuntu 24.04 runs cgroup v2, where Docker uses
# the systemd driver. So Docker's default parent, for every container that
# names none, is the slice too. The systemd driver takes a slice name here,
# not a path. koid checks the driver, and that the builder runs in the slice.
DOCKER_ETC=/etc/docker
# Present from the moment daemon.json changes until Docker has restarted with
# it, so a run that fails in between (a download, say) restarts Docker on the
# next run, which finds daemon.json already as it wants it.
DOCKER_RESTART_PENDING=$DOCKER_ETC/koi-restart-pending

# Sets Docker's default cgroup parent in daemon.json, keeping the rest of the
# file, and marks a restart pending when the file changes. The marker goes
# first, so no run can see the new file without it.
configure_docker() {
	local file=$DOCKER_ETC/daemon.json wanted current=''
	install -m 0755 -d "$DOCKER_ETC"
	if [ -f "$file" ]; then
		wanted=$(jq --sort-keys '. + {"cgroup-parent": "koi.slice"}' "$file")
		current=$(jq --sort-keys . "$file")
	else
		wanted=$(jq --null-input --sort-keys '{"cgroup-parent": "koi.slice"}')
	fi
	[ "$wanted" = "$current" ] && return 0
	touch "$DOCKER_RESTART_PENDING"
	printf '%s\n' "$wanted" > "$file"
}

# A changed daemon.json takes effect when Docker restarts. On a box already
# running, that stops every container: the builder starts again at once,
# previews on their next visit, and a build in progress fails. koid restarts
# with Docker and marks that build failed. The marker goes only once the
# restart has worked.
restart_docker_if_pending() {
	[ -f "$DOCKER_RESTART_PENDING" ] || return 0
	systemctl restart docker.service
	rm -f "$DOCKER_RESTART_PENDING"
}

# The container buildx runs koi-builder in.
BUILDER_CONTAINER=buildx_buildkit_koi-builder0

# The slice the container named $1 runs in, or nothing.
container_slice() {
	local id
	id=$(docker container inspect --format '{{.Id}}' "$1" 2>/dev/null) || return 0
	systemctl show --property=Slice --value "docker-$id.scope"
}

# Moves the builder into koi.slice, then checks that it is there. A
# container takes its cgroup parent when it starts, so a builder that kept
# running while Docker restarted (live-restore keeps containers running)
# stays where it was, and restarting it moves it. Nothing routes to the
# builder, so this is safe while koid runs. Previews are koid's: when it
# starts, it takes one that runs outside the slice out of Caddy's routes and
# then stops it (Deployer.reconcile). Runs every time, so it also repairs
# what an earlier run left. Stops provisioning when the builder is still
# outside the slice.
move_builder_into_slice() {
	local slice
	[ "$(docker container inspect --format '{{.State.Running}}' "$BUILDER_CONTAINER" 2>/dev/null)" = true ] || return 0
	slice=$(container_slice "$BUILDER_CONTAINER")
	[ "$slice" = koi.slice ] && return 0
	echo "koi: restarting $BUILDER_CONTAINER, which runs in ${slice:-no slice}, to move it into koi.slice"
	docker restart "$BUILDER_CONTAINER" >/dev/null
	slice=$(container_slice "$BUILDER_CONTAINER")
	if [ "$slice" != koi.slice ]; then
		echo "koi: $BUILDER_CONTAINER runs in ${slice:-no slice}, not koi.slice; check cgroup-parent in $DOCKER_ETC/daemon.json and that Docker uses its systemd cgroup driver" >&2
		return 1
	fi
}

configure_docker

# --- Docker (official repository) -------------------------------------------
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
	> /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
restart_docker_if_pending

# --- Unattended upgrades ------------------------------------------------------
# Ubuntu's daily security upgrade stays on. The box is stopped most of the
# time, so the run its timer missed starts a few minutes after each start,
# often while a build runs, and needrestart then restarts every service that
# loaded an upgraded library: koid, Docker and containerd among them, which
# kills the build in flight ("the daemon restarted before this build
# finished"). needrestart now leaves these services running on the old
# libraries. The box stops when idle, and its next start loads the new ones;
# an always-on host (host/install-vm.sh) loads them at its next reboot.
install -d -m 0755 /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/50-koi.conf <<'CONF'
# Written by koi's host/cloud-init.sh: needrestart skips its automatic
# restart of the services builds and previews run on. The next start of the
# box loads the upgraded libraries.
$nrconf{override_rc}{qr(^(koid|koi-egress|koi-firewall|caddy|docker|containerd)\.service$)} = 0;
CONF

# --- koi user and state -----------------------------------------------------
id koi >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/koi --shell /usr/sbin/nologin koi
usermod -aG docker koi
install -d -o koi -g koi /var/lib/koi/previews /var/lib/koi/builds /var/lib/koi/logs /etc/koi
install -d -o root -g root -m 0755 /usr/local/share/koi/recipes
# koid touches this on every request and while a build runs. Owned by koi so
# it can; the idle check only reads it. chown on every run repairs a stamp an
# earlier version created as root, and leaves its modification time alone.
[ -f /var/lib/koi/last-activity ] || install -o koi -g koi -m 0644 /dev/null /var/lib/koi/last-activity
chown koi:koi /var/lib/koi/last-activity

# --- SSH access for the CLI (host/ssh) --------------------------------------
# koi-connect is the account the CLI logs in as; sshd runs the koi gateway
# for it and nothing else (host/ssh/install.sh, which scripts/deploy-host.sh
# runs, installs the gateway and that sshd configuration). koi-control may
# open koid's control socket: koid gives the socket that group, koid.service
# below gives it the socket's directory, koi-connect is in it, and koi is in
# it so that koid may chgrp the socket.
getent group koi-control > /dev/null || groupadd --system koi-control
id koi-connect > /dev/null 2>&1 || useradd --system --home-dir /var/lib/koi-connect --no-create-home --shell /bin/sh koi-connect
install -d -o root -g root -m 0755 /var/lib/koi-connect
usermod -aG koi-control koi-connect
usermod -aG koi-control koi

# --- Networks and the build sandbox -------------------------------------------
# Previews attach only to koi-previews. --internal: no route to the outside
# (the egress proxy, phase 6, will be the only way out). Builds run in a
# BuildKit container on koi-build, which is not internal because builds fetch
# packages. On both, enable_icc=false stops containers talking to each other,
# and a fixed bridge name lets the firewall below drop their connections to
# the host. koid checks all of this when it starts and refuses to run without
# it.

# The options that matter, as "<driver> <internal> <icc> <bridge>".
network_options() {
	docker network inspect "$1" \
		--format '{{.Driver}} {{.Internal}} {{index .Options "com.docker.network.bridge.enable_icc"}} {{index .Options "com.docker.network.bridge.name"}}'
}

# ensure_network NAME BRIDGE INTERNAL creates the network, or recreates one
# that exists with other options. It stops provisioning rather than
# disconnect containers from a network that is set up wrong.
ensure_network() {
	local name=$1 bridge=$2 internal=$3 want have
	want="bridge $internal false $bridge"
	if have=$(network_options "$name" 2>/dev/null); then
		[ "$have" = "$want" ] && return 0
		if [ -n "$(docker ps -aq --filter "network=$name")" ]; then
			echo "koi: network $name is set up as '$have', not '$want', and these containers use it:" >&2
			docker ps -a --filter "network=$name" --format '  {{.Names}}' >&2
			echo "koi: remove them (koi down NAME for a preview) and run provisioning again" >&2
			exit 1
		fi
		echo "koi: recreating network $name ('$have' -> '$want')"
		docker network rm "$name" >/dev/null
	fi
	local flags=(-o com.docker.network.bridge.enable_icc=false -o "com.docker.network.bridge.name=$bridge")
	if [ "$internal" = true ]; then flags+=(--internal); fi
	docker network create "${flags[@]}" "$name" >/dev/null
}

# buildx keeps builders per user, and koid runs as koi.
as_koi() { runuser -u koi -- env HOME=/var/lib/koi "$@"; }

# Whether koi-builder exists as created below.
builder_ok() {
	local out
	out=$(as_koi docker buildx inspect koi-builder 2>/dev/null) || return 1
	grep -Eq '^Driver:[[:space:]]+docker-container$' <<<"$out" &&
		grep -Eq '^Driver Options:.* network="koi-build"( |$)' <<<"$out" &&
		grep -Eq '^Driver Options:.* memory="8g"( |$)' <<<"$out" &&
		grep -Eq '^Driver Options:.* cpu-quota="300000"( |$)' <<<"$out"
}

ensure_network koi-previews koi-previews0 true
# The builder's own container sits on koi-build. If that network has to be
# recreated, the builder goes first; it is recreated below.
if [ "$(network_options koi-build 2>/dev/null || true)" != "bridge false false koi-build0" ] &&
	as_koi docker buildx inspect koi-builder >/dev/null 2>&1; then
	as_koi docker buildx rm --force koi-builder
fi
ensure_network koi-build koi-build0 false

# koid builds with `docker buildx build --builder koi-builder`. The
# docker-container driver runs BuildKit in its own container on koi-build,
# with at most 8 GB of memory and three CPUs; RUN steps share that container's
# network, so they reach the internet but, through the firewall below, not the
# host. A builder made with other options is replaced (only its cache is lost).
# Its container runs in koi.slice through Docker's default parent (above).
if ! builder_ok; then
	as_koi docker buildx rm --force koi-builder >/dev/null 2>&1 || true
	as_koi docker buildx create --name koi-builder --driver docker-container \
		--driver-opt network=koi-build --driver-opt memory=8g --driver-opt cpu-quota=300000 \
		--bootstrap
fi
# A builder that kept running through a Docker restart is still outside
# koi.slice; see move_builder_into_slice.
move_builder_into_slice

# Belt and braces with the IMDS hop limit: nothing in Docker reaches the
# metadata endpoint. DOCKER-USER is evaluated before Docker's own rules.
cat > /usr/local/sbin/koi-firewall <<'FW'
#!/bin/bash
set -e
iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
ip6tables -C DOCKER-USER -d fd00:ec2::254 -j DROP 2>/dev/null || ip6tables -I DOCKER-USER -d fd00:ec2::254 -j DROP
# A container can reach the host on its bridge's address, which would let a
# preview talk to Caddy (and through it to other previews) and a build talk to
# Caddy, koid or anything else listening on the host. Drop every new
# connection that arrives from either bridge; replies to connections the host
# opened (Caddy to a preview) are not new, so they still pass.
for bridge in koi-previews0 koi-build0; do
	rule=(INPUT -i "$bridge" -m conntrack --ctstate NEW -j DROP)
	iptables -C "${rule[@]}" 2>/dev/null || iptables -I "${rule[@]}"
done
# The one exception: previews may open connections to the egress proxy
# (host/egress), their only way out. It is removed and inserted again at the
# top on every run, so it always comes before the drop rules above.
accept=(INPUT -i koi-previews0 -p tcp --dport 3128 -m conntrack --ctstate NEW -j ACCEPT)
while iptables -D "${accept[@]}" 2>/dev/null; do :; done
iptables -I "${accept[@]}"
# The same proxy for code in a preview that ignores the proxy setting, such
# as code that resolves a host itself to refuse private addresses. koid gives
# each preview a default route to the bridge (host/egress/koi-preview-route)
# and the proxy's DNS listener as its DNS server. New connections to ports
# 443 and 80 anywhere off the bridge go to the proxy's transparent listener,
# which applies the same policy, by name, whatever address they were for.
# Only connections redirected there are accepted on its ports. Everything else
# that would leave the bridge is dropped: by Docker's rules for an internal
# network, and by the DOCKER-USER rule below in case those ever change.
subnet=$(docker network inspect koi-previews -f '{{(index .IPAM.Config 0).Subnet}}')
gateway=$(docker network inspect koi-previews -f '{{(index .IPAM.Config 0).Gateway}}')
# shellcheck disable=SC2054 # 443,80 is one multiport list
redirect=(PREROUTING -i koi-previews0 ! -d "$subnet" -p tcp -m multiport --dports 443,80 -j REDIRECT --to-ports 3129)
iptables -t nat -C "${redirect[@]}" 2>/dev/null || iptables -t nat -A "${redirect[@]}"
# Previews' lookups go to port 53 on the gateway, and from there only to the
# proxy's DNS listener: no other server on the host can answer them.
dns=(PREROUTING -i koi-previews0 -d "$gateway" -p udp --dport 53 -j REDIRECT --to-ports 3153)
iptables -t nat -C "${dns[@]}" 2>/dev/null || iptables -t nat -A "${dns[@]}"
# Each accept goes in again at the top, ahead of the drop rules, as above.
on_top() {
	while iptables -D "$@" 2>/dev/null; do :; done
	iptables -I "$@"
}
on_top INPUT -i koi-previews0 -p tcp --dport 3129 -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j ACCEPT
on_top INPUT -i koi-previews0 -p udp --dport 3153 -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j ACCEPT
leave=(DOCKER-USER -i koi-previews0 ! -o koi-previews0 -j DROP)
iptables -C "${leave[@]}" 2>/dev/null || iptables -I "${leave[@]}"

# --- Verification run networks (kv+) ------------------------------------------
# Verification is optional and the rules above are not. koid.service Requires=
# this unit, so a step below that ended this script with an error would stop
# koid and every preview before koid could report verification unavailable.
# So no step below can end the script. Each logs its failure to the unit's
# journal, and koid's check (verificationCapability in
# packages/daemon/src/host.ts) finds what is missing through the helper's
# attest and reports verification unavailable.
#
# Going on without the kv+ denies leaves nothing open. They match only a kv+
# bridge, a kv+ bridge exists only as a run network, and only
# VerificationNetwork.create makes one. Nothing calls that on a box whose
# capability is unavailable, and missing denies make it unavailable. The
# helper's apply also refuses a host without its chains.
verification_step_failed() {
	echo "koi: $1 failed. Previews are not affected; koid's verification check reports what this leaves missing." >&2
}

# A verification run gets a private bridge named kv<12 hex> (docs/verify.md,
# "Run network"). Traffic bridged between two containers passes through
# iptables only with br_netfilter loaded and these sysctls on. Docker turns
# the first two on for its own inter-container rules; the third hands
# iptables a packet under a VLAN tag, which the receiving kernel would
# otherwise take untagged and unfiltered. /etc/modules-load.d and
# /etc/sysctl.d (written below) keep them on across boots, this sets them
# again in case the firewall runs first, and the helper's provision sets
# the third once more.
modprobe br_netfilter || verification_step_failed 'modprobe br_netfilter'
sysctl -q -w net.bridge.bridge-nf-call-iptables=1 net.bridge.bridge-nf-call-ip6tables=1 net.bridge.bridge-nf-filter-vlan-tagged=1 ||
	verification_step_failed 'setting the bridge sysctls'

# The chains that confine kv+ bridges, their default denies and the jumps
# that reach them belong to the helper koid also uses for a run's permits,
# /usr/local/libexec/koi-verify-net (host/verify/koi_verify_net.py, installed
# by scripts/deploy-host.sh). Its `provision` command creates them or brings
# an older layout up to date under the same lock as a run's apply and revoke,
# keeps every run's permits, and reaches a rebuilt chain before the old one
# goes, so kv+ traffic is denied at every instant while koid keeps running.
# Nothing here writes a rule of those chains by hand. Before the first
# deploy the helper is not installed yet: koid then reports verification
# unavailable, and the helper's installer runs provision when it arrives.
KOI_VERIFY_NET=/usr/local/libexec/koi-verify-net
if [ -x "$KOI_VERIFY_NET" ]; then
	"$KOI_VERIFY_NET" provision || verification_step_failed "$KOI_VERIFY_NET provision (exit $?)"
else
	echo "koi: $KOI_VERIFY_NET is not installed yet; the verification chains come with the first deploy (scripts/deploy-host.sh)"
fi
FW
chmod 755 /usr/local/sbin/koi-firewall
cat > /etc/systemd/system/koi-firewall.service <<'UNIT'
[Unit]
Description=koi: block metadata and host access from containers
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/koi-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

# --- Verification run networks: sysctls, pool and helper access ---------------
# br_netfilter and its sysctls at boot, before the firewall unit sets them
# again (above): systemd loads the module, then applies sysctl.d.
printf 'br_netfilter\n' > /etc/modules-load.d/koi-verify.conf
cat > /etc/sysctl.d/90-koi-verify.conf <<'SYSCTL'
# koi: bridged traffic on verification run networks goes through iptables,
# VLAN-tagged frames included.
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-filter-vlan-tagged = 1
SYSCTL
modprobe br_netfilter
sysctl -q -p /etc/sysctl.d/90-koi-verify.conf

# The reserved pool, read by koid (koid.service lists this file) and by the
# helper, which refuses a run subnet outside it.
install -d -m 0755 /etc/koi/verify
printf 'KOI_VERIFY_POOL=%s\n' "$KOI_VERIFY_POOL" > /etc/koi/verify/env

# koid changes the firewall for a run only through the root-owned helper at
# this path (host/verify/koi_verify_net.py, which scripts/deploy-host.sh
# installs with koid), and sudo lets koi run exactly that path and nothing
# else. visudo checks the rule before it is installed: a broken file in
# sudoers.d locks sudo for everyone. sudo skips a file whose name has a dot
# in it, so the one being written is not read half way.
install -d -m 0755 /usr/local/libexec
cat > /etc/sudoers.d/.koi-verify-net.new <<'SUDO'
# koid applies and removes one verification run's firewall permits through
# this helper, and does nothing else as root. The helper checks its input.
koi ALL=(root:root) NOPASSWD: /usr/local/libexec/koi-verify-net
SUDO
chmod 0440 /etc/sudoers.d/.koi-verify-net.new
visudo -cf /etc/sudoers.d/.koi-verify-net.new >/dev/null
mv -f /etc/sudoers.d/.koi-verify-net.new /etc/sudoers.d/koi-verify-net

# The same for the helper that gives a preview its default route to the
# bridge (host/egress/koi-preview-route, which the egress installer puts in
# place). It checks its one argument and changes nothing but that route.
cat > /etc/sudoers.d/.koi-preview-route.new <<'SUDO'
# koid gives each preview it starts a default route to its bridge through
# this helper. The helper checks its input.
koi ALL=(root:root) NOPASSWD: /usr/local/libexec/koi-preview-route
SUDO
chmod 0440 /etc/sudoers.d/.koi-preview-route.new
visudo -cf /etc/sudoers.d/.koi-preview-route.new >/dev/null
mv -f /etc/sudoers.d/.koi-preview-route.new /etc/sudoers.d/koi-preview-route

# --- Caddy with the Route 53 DNS module (wildcard certificate via DNS-01) ----
# Download beside the binary and rename over it: overwriting a running
# executable in place fails (ETXTBSY), a rename does not. The restart at the
# end of this script picks up the new binary. Outside AWS the build has the
# chosen provider's DNS module, or none.
case $KOI_TLS in
route53) caddy_module='&p=github.com/caddy-dns/route53' ;;
acme-dns:*) caddy_module="&p=github.com/caddy-dns/${KOI_TLS#acme-dns:}" ;;
*) caddy_module='' ;;
esac
curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64$caddy_module" \
	-o /usr/local/bin/caddy.new
chmod 755 /usr/local/bin/caddy.new
mv -f /usr/local/bin/caddy.new /usr/local/bin/caddy
id caddy >/dev/null 2>&1 || useradd --system --home /var/lib/caddy --create-home --shell /usr/sbin/nologin caddy
install -d -o caddy -g caddy /etc/caddy /var/lib/caddy /var/log/caddy
# Outside AWS, Caddy's admin API is a unix socket only its group may open
# (below), and koid reaches it as a member.
[ "$KOI_TLS" = route53 ] || usermod -aG caddy koi

# koid owns the Caddyfile and rewrites it whenever previews change, then loads
# it through Caddy's admin API: on 127.0.0.1:2019 on the AWS box, which has no
# account but its own; elsewhere on /run/caddy/admin.sock, mode 0660 in the
# caddy group, since any account could use the port to change what Caddy
# serves or have it answer with its environment. It lives in its own
# directory: koi's home is 0750, which Caddy cannot enter. The directory is
# koi:caddy with the setgid bit, so files koid writes there are readable by
# Caddy and by nobody else. This first version, written only when there is
# none, sends everything to koid; koid replaces it on start. Outside AWS it
# serves nothing until then: a Route 53 block would not load without the
# module, and koid's file brings the chosen one.
install -d -o koi -g caddy -m 2750 /var/lib/koi-caddy
if [ ! -f /var/lib/koi-caddy/Caddyfile ] && [ "$KOI_TLS" != route53 ]; then
	cat > /var/lib/koi-caddy/Caddyfile <<'CADDY'
# Written by provisioning; koid replaces it on start.
{
	auto_https disable_redirects
	admin unix//run/caddy/admin.sock|0660
}
CADDY
fi
if [ ! -f /var/lib/koi-caddy/Caddyfile ]; then
	cat > /var/lib/koi-caddy/Caddyfile <<CADDY
# Written by provisioning; koid replaces it on start.
{
	auto_https disable_redirects
	admin 127.0.0.1:2019
}

*.${DOMAIN} {
	tls {
		# Route 53 takes a while to serve a new record; without waiting, the
		# ACME server looks before the TXT record exists and the order fails.
		dns route53 {
			wait_for_route53_sync true
			route53_max_wait 2m
		}
		propagation_delay 30s
	}
	reverse_proxy 127.0.0.1:7777
}
CADDY
fi
chown koi:caddy /var/lib/koi-caddy/Caddyfile
chmod 0640 /var/lib/koi-caddy/Caddyfile
# An earlier version kept it in koi's home, where Caddy could not read it.
rm -f /var/lib/koi/Caddyfile
rm -f /etc/caddy/Caddyfile

# What Caddy's DNS module reads from its environment: on AWS the region, with
# credentials from the box's role; elsewhere a provider's token, from a file
# of root's, in a directory of root's, that host/install-vm.sh makes for the
# operator to fill. Elsewhere also /run/caddy, for the admin socket, which
# only root and the caddy group may enter.
if [ "$KOI_TLS" = route53 ]; then
	caddy_unit="Environment=AWS_REGION=$KOI_REGION"
else
	caddy_unit='EnvironmentFile=-/etc/koi/caddy/env
RuntimeDirectory=caddy
RuntimeDirectoryMode=0750'
fi
# Unquoted, for those lines; nothing else in the unit expands.
cat > /etc/systemd/system/caddy.service <<UNIT
[Unit]
Description=Caddy
After=network-online.target
Wants=network-online.target

[Service]
User=caddy
Group=caddy
$caddy_unit
Environment=XDG_DATA_HOME=/var/lib
Environment=XDG_CONFIG_HOME=/var/lib
ExecStart=/usr/local/bin/caddy run --config /var/lib/koi-caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/local/bin/caddy reload --config /var/lib/koi-caddy/Caddyfile --adapter caddyfile --force
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# --- koid (binary arrives via scripts/deploy-host.sh) -----------------------
cat > /etc/systemd/system/koid.service <<'UNIT'
[Unit]
Description=koi daemon
After=docker.service koi-firewall.service koi.slice caddy.service network-online.target
Wants=network-online.target
# Never run previews or builds without the firewall rules or the memory
# ceiling. koid runs as koi and cannot read iptables itself; it does check the
# networks, the builder and the slice. koid itself runs outside the slice.
Requires=docker.service koi-firewall.service koi.slice
# Not installed until scripts/deploy-host.sh has run.
ConditionPathExists=/usr/local/bin/koid

[Service]
User=koi
Group=koi
# /run/koi holds the control socket. koi-connect (host/ssh) reaches it
# through the koi-control group: the directory takes that group here, with
# the setgid bit so the socket is made with it, and koid sets the socket's
# group again itself when it makes it.
RuntimeDirectory=koi
RuntimeDirectoryMode=0750
ExecStartPre=+/bin/sh -c 'chgrp koi-control /run/koi && chmod 2750 /run/koi'
Environment=KOID_PORT=7777
Environment=KOID_LOG_PORT=7778
# /etc/koi/env, which scripts/deploy-host.sh writes, sets the deployment's
# region over this.
Environment=AWS_REGION=us-east-1
EnvironmentFile=-/etc/koi/env
# KOI_VERIFY_POOL, written by provisioning (above).
EnvironmentFile=-/etc/koi/verify/env
ExecStart=/usr/local/bin/koid
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

# --- Idle shutdown ----------------------------------------------------------
# Idle time counts from the later of this boot and koid's last activity stamp.
# The stamp survives stop/start, so without the boot time a box woken after an
# idle stop would power off again at the first check. An always-on host gets
# none, and loses one an earlier run gave it.
if [ "$KOI_POWER" = always-on ]; then
	systemctl disable --now koi-idle.timer 2>/dev/null || true
	rm -f /etc/systemd/system/koi-idle.timer /etc/systemd/system/koi-idle.service /usr/local/sbin/koi-idle-check
else
cat > /usr/local/sbin/koi-idle-check <<IDLE
#!/bin/bash
set -eu
limit=$(( IDLE_MINUTES * 60 ))
boot=\$(awk '/^btime/ {print \$2}' /proc/stat)
last=\$boot
stamp=/var/lib/koi/last-activity
if [ -f "\$stamp" ]; then
	touched=\$(stat -c %Y "\$stamp")
	if [ "\$touched" -gt "\$last" ]; then last=\$touched; fi
fi
if [ "\$(( \$(date +%s) - last ))" -ge "\$limit" ]; then
	logger -t koi "idle for ${IDLE_MINUTES} minutes, stopping"
	systemctl poweroff
fi
IDLE
chmod 755 /usr/local/sbin/koi-idle-check
cat > /etc/systemd/system/koi-idle.service <<'UNIT'
[Unit]
Description=koi: stop the box when idle

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/koi-idle-check
UNIT
cat > /etc/systemd/system/koi-idle.timer <<'UNIT'
[Unit]
Description=koi: idle check every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
UNIT
fi

systemctl daemon-reload
# Count this run as activity again right before the idle timer comes back, so
# its first check does not power the box off on the strength of how long ago
# it booted.
touch /var/lib/koi/last-activity
# The idle timer is the AWS box's alone (above).
idle_timer=()
[ "$KOI_POWER" = always-on ] || idle_timer=(koi-idle.timer)
systemctl enable --now koi-firewall.service caddy.service "${idle_timer[@]}"
systemctl enable koid.service
# On a re-run, pick up changed scripts and configuration.
# Re-apply the firewall rules by running the script, not by restarting its
# unit: koid Requires= that unit, so a restart would restart koid and kill any
# build in progress. The script only adds rules that are missing.
/usr/local/sbin/koi-firewall
[ "$KOI_POWER" = always-on ] || systemctl restart koi-idle.timer
systemctl reload-or-restart caddy.service
logger -t koi "cloud-init provisioning complete"
