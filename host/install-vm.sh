#!/bin/bash
# Installs koi on a plain Linux host, as root: an Ubuntu 24.04 VM anywhere,
# which the CLI then reaches over SSH, or this machine itself, which the CLI
# reaches through koid's control socket (--local). It runs
# host/cloud-init.sh, the AWS box's provisioning, for Docker, the memory
# slice, the networks and builder, the firewall and Caddy, with the AWS parts
# switched off: certificates come from the TLS mode given here instead of
# Route 53, and nothing stops the host when it is idle. Then it installs what
# scripts/deploy-host.sh installs on the AWS box, from the directory this
# script is in rather than from S3 over SSM: koid, the recipes, the egress
# proxy, the verification helper and, unless --local, the SSH gateway. koid
# takes uploads through its control socket into a spool and keeps its live
# list in a file, where the AWS box uses S3 and SSM. scripts/host-bundle.sh
# fills the directory. Every step is safe to repeat; run it again to update.
#
#   sudo ./install-vm.sh --domain previews.example.com --tls acme-http
#   sudo ./install-vm.sh --domain previews.example.com --tls acme-dns:cloudflare
#   sudo ./install-vm.sh --local --user "$USER"
#
# See docs/configuration.md, "A Linux VM" and "A local host".
set -euo pipefail

BUNDLE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OS_RELEASE=/etc/os-release
BIN_DIR=/usr/local/bin
SHARE=/usr/local/share/koi
KOI_ENV=/etc/koi/env
EGRESS_ENV=/etc/koi/egress/env
# Read by Caddy alone (cloud-init.sh's caddy.service, and the import in the
# Caddyfile koid writes): a DNS provider's token never reaches koid. The
# directory is root's, so that only root makes entries in it; /etc/caddy is
# the caddy account's, which could plant a link where root then writes.
CADDY_DIR=/etc/koi/caddy
CADDY_ENV=$CADDY_DIR/env
DNS_FILE=$CADDY_DIR/dns.caddy
# The Caddyfile of a Caddy set up by something other than koi, which
# cloud-init.sh removes.
STOCK_CADDYFILE=/etc/caddy/Caddyfile
# How koi's caddy.service (cloud-init.sh) starts Caddy, as systemctl shows it.
KOI_CADDY_START='argv[]=/usr/local/bin/caddy run --config /var/lib/koi-caddy/Caddyfile --adapter caddyfile ;'
# Caddy's admin API, which cloud-init.sh puts on a socket koid opens as a
# member of the caddy group, in the form KOI_CADDY_ADMIN and caddy take.
CADDY_ADMIN=unix//run/caddy/admin.sock
# Where Caddy keeps its own CA's root (XDG_DATA_HOME=/var/lib in its unit).
CADDY_ROOT=/var/lib/caddy/pki/authorities/local/root.crt
KOID_HEALTH=http://127.0.0.1:7777/__koi/health

DOMAIN=''
TLS=''
LOCAL=false
POOL=''
USERS=()

usage() {
	cat <<'USAGE'
usage: install-vm.sh --domain DOMAIN --tls MODE [--user NAME]... [--verify-pool CIDR]
       install-vm.sh --local [--domain DOMAIN] [--tls MODE] [--user NAME]... [--verify-pool CIDR]

  --domain DOMAIN   previews are served at <label>.DOMAIN (with --local, default koi.test)
  --tls MODE        how Caddy gets certificates for *.DOMAIN:
                      internal             Caddy's own CA, which visitors' machines trust
                                           (the default with --local)
                      acme-http            Let's Encrypt, a certificate per preview over
                                           HTTP-01 or TLS-ALPN-01: ports 80 and 443 open
                      acme-dns:PROVIDER    Let's Encrypt, one wildcard over DNS-01 with
                                           github.com/caddy-dns/PROVIDER (cloudflare, ...)
  --local           this machine, for koi's local transport: no SSH gateway
  --user NAME       an account that may use koid through its control socket, as the SSH
                    gateway's account does; may be given more than once
  --verify-pool CIDR
                    the network verification runs are carved from (default 10.213.0.0/20)
USAGE
}

die() {
	echo "koi: $*" >&2
	exit 1
}

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
		--domain) DOMAIN=${2:?--domain needs a value}; shift 2 ;;
		--tls) TLS=${2:?--tls needs a value}; shift 2 ;;
		--local) LOCAL=true; shift ;;
		--user) USERS+=("${2:?--user needs a value}"); shift 2 ;;
		--verify-pool) POOL=${2:?--verify-pool needs a value}; shift 2 ;;
		-h | --help) usage; exit 0 ;;
		*) usage >&2; die "unknown argument '$1'" ;;
		esac
	done
	if [ "$LOCAL" = true ]; then
		DOMAIN=${DOMAIN:-koi.test}
		TLS=${TLS:-internal}
	fi
	[ -n "$DOMAIN" ] || die '--domain is required: previews are served at <label>.DOMAIN'
	[ -n "$TLS" ] || die '--tls is required: internal, acme-http or acme-dns:PROVIDER'
	# Each value goes into a unit, an environment file or a Caddyfile, so it
	# is held to a shape that cannot carry anything else.
	[[ $DOMAIN =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] ||
		die "--domain '$DOMAIN' is not a bare domain of two or more labels"
	[[ $TLS =~ ^(internal|acme-http|acme-dns:[a-z0-9]+)$ ]] ||
		die "--tls '$TLS' is not internal, acme-http or acme-dns:PROVIDER"
	if [ -n "$POOL" ] && ! [[ $POOL =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/(1[6-9]|2[0-8])$ ]]; then
		die "--verify-pool '$POOL' is not an IPv4 network between /16 and /28"
	fi
	local user
	for user in "${USERS[@]}"; do
		[[ $user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--user '$user' is not an account name"
	done
}

# Root, and the system host/cloud-init.sh and the bundle are made for.
check_platform() {
	[ "$(id -u)" = 0 ] || die 'run this as root (sudo)'
	local id version
	id=$(. "$OS_RELEASE" && printf '%s' "${ID:-}")
	version=$(. "$OS_RELEASE" && printf '%s' "${VERSION_ID:-}")
	[ "$id $version" = 'ubuntu 24.04' ] ||
		die "this host runs ${id:-an unknown system} ${version}; koi's host setup is for Ubuntu 24.04"
	[ "$(uname -m)" = x86_64 ] || die "this host is $(uname -m); koi's host binaries are built for x86_64"
}

# Every file is the one scripts/host-bundle.sh built, whole. sha256sum -c
# checks only the files SHA256SUMS lists, so each file this script reads must
# have its line there, and a line it cannot read fails the check.
check_bundle() {
	[ -f "$BUNDLE/SHA256SUMS" ] ||
		die "$BUNDLE has no SHA256SUMS; build the bundle with scripts/host-bundle.sh and copy the whole directory"
	local name listed
	local needed=(cloud-init.sh koid recipes.tar.gz egress.tar.gz verify.tar.gz)
	[ "$LOCAL" = true ] || needed+=(ssh.tar.gz koi-ssh-gateway)
	listed=$(cut -d ' ' -f 3- "$BUNDLE/SHA256SUMS")
	for name in "${needed[@]}"; do
		grep -qxF -- "$name" <<<"$listed" ||
			die "the SHA256SUMS in $BUNDLE has no line for $name; build the bundle again with scripts/host-bundle.sh"
	done
	(cd "$BUNDLE" && sha256sum --strict --quiet -c SHA256SUMS) ||
		die "the bundle in $BUNDLE does not match its SHA256SUMS; copy it again"
}

# cloud-init.sh replaces caddy.service and removes /etc/caddy/Caddyfile, so on
# a machine that runs a Caddy for something else it would take that Caddy
# over. A Caddy koi set up has neither that file nor the package, and its unit
# runs koid's Caddyfile, so a run again goes on.
check_caddy() {
	local found=''
	if [ -e "$STOCK_CADDYFILE" ]; then
		found="$STOCK_CADDYFILE is there"
	else
		case $(dpkg-query -W -f='${db:Status-Status}' caddy 2>/dev/null) in
		'' | not-installed | config-files) ;;
		*) found='the caddy package is installed' ;;
		esac
	fi
	# The unit systemd runs, wherever its file is and with any drop-in. Only
	# none at all, or koi's, goes on; a masked or broken unit, or no answer
	# from systemd, stops here.
	if [ -z "$found" ] && [ "$(systemctl show -P LoadState caddy.service 2>/dev/null)" != not-found ] &&
		[[ $(systemctl show -P ExecStart caddy.service 2>/dev/null) != *" $KOI_CADDY_START "* ]]; then
		found='caddy.service runs another Caddy or config'
	fi
	[ -z "$found" ] ||
		die "this machine has a Caddy that koi did not set up ($found). koi's setup replaces caddy.service and removes /etc/caddy/Caddyfile, which would take that Caddy down; install koi in a VM instead"
}

# host/cloud-init.sh as the AWS box gets it, with the host's own TLS mode
# and no idle shutdown.
provision() {
	local settings=(KOI_DOMAIN="$DOMAIN" KOI_TLS="$TLS" KOI_POWER=always-on)
	[ -z "$POOL" ] || settings+=(KOI_VERIFY_POOL="$POOL")
	env "${settings[@]}" bash "$BUNDLE/cloud-init.sh"
}

# Unpacks the bundle $1 into $2, replacing what was there.
unpack() {
	rm -rf "$2.new"
	mkdir -p "$2.new"
	tar -xzf "$BUNDLE/$1" -C "$2.new" --no-same-owner
	rm -rf "$2"
	mv "$2.new" "$2"
}

# What scripts/deploy-host.sh installs on the AWS box, in its order.
install_bundle() {
	install -m 0755 "$BUNDLE/koid" "$BIN_DIR/koid.new"
	mv -f "$BIN_DIR/koid.new" "$BIN_DIR/koid"
	unpack recipes.tar.gz "$SHARE/recipes"
	unpack egress.tar.gz "$SHARE/egress"
	bash "$SHARE/egress/install.sh"
	unpack verify.tar.gz "$SHARE/verify"
	bash "$SHARE/verify/install.sh"
	if [ "$LOCAL" = false ]; then
		unpack ssh.tar.gz "$SHARE/ssh"
		bash "$SHARE/ssh/install.sh" "$BUNDLE/koi-ssh-gateway"
	fi
}

# For acme-dns: the provider's line, which the Caddyfile imports, and the
# file its token goes in. Both are written only when missing, so the
# operator's edits stay; Caddy cannot get a certificate until the token is
# there.
write_dns_files() {
	case $TLS in acme-dns:*) ;; *) return 0 ;; esac
	local provider=${TLS#acme-dns:}
	install -d -o root -g caddy -m 0750 "$CADDY_DIR"
	if [ ! -e "$DNS_FILE" ]; then
		printf '%s\n' \
			"# The DNS provider Caddy proves control of *.$DOMAIN with (koid's Caddyfile" \
			'# imports this file into its tls block). Most caddy-dns providers take their' \
			'# token as the one argument; see github.com/caddy-dns/'"$provider"' for this one.' \
			"dns $provider {env.KOI_DNS_API_TOKEN}" >"$DNS_FILE.new"
		install -o root -g caddy -m 0640 "$DNS_FILE.new" "$DNS_FILE"
		rm -f "$DNS_FILE.new"
	fi
	if [ ! -e "$CADDY_ENV" ]; then
		printf '%s\n' \
			"# The token Caddy's DNS module reads for $provider (see $DNS_FILE)." \
			'# Set it and run install-vm.sh again. To change it later, set it here' \
			'# and run systemctl restart caddy.' \
			'KOI_DNS_API_TOKEN=' >"$CADDY_ENV.new"
		install -o root -g root -m 0600 "$CADDY_ENV.new" "$CADDY_ENV"
		rm -f "$CADDY_ENV.new"
	fi
}

# With acme-dns, Caddy refuses a config whose provider line names an empty
# token, so koid, which loads its config into Caddy as it starts, would fail
# to start. The installer stops here instead, for the operator to set the
# token and run it again, which then goes on. A provider line edited to take
# other arguments is the operator's to fill.
check_dns_env() {
	case $TLS in acme-dns:*) ;; *) return 0 ;; esac
	grep -qF '{env.KOI_DNS_API_TOKEN}' "$DNS_FILE" || return 0
	# systemd takes the last assignment, quoted or not.
	grep -E '^[[:space:]]*KOI_DNS_API_TOKEN[[:space:]]*=' "$CADDY_ENV" | tail -n 1 |
		grep -Eq "=[[:space:]]*[\"']?[^\"'[:space:]]" && return 0
	{
		echo "koi: the DNS provider's API token is not set. Caddy refuses koid's config without"
		echo '  it, so koid was not started. Put the token in'
		echo "  $CADDY_ENV (KOI_DNS_API_TOKEN=...), check the provider line"
		echo "  in $DNS_FILE, then run install-vm.sh again with the same arguments."
	} >&2
	exit 2
}

# koid's settings: the spool and a file where the AWS box has S3 and SSM,
# the TLS mode Caddy runs with, Caddy's admin socket, and the egress proxy
# its installer set up.
write_env() {
	local egress_host egress_port
	egress_host=$(. "$EGRESS_ENV" && printf '%s' "$KOI_EGRESS_HOST")
	egress_port=$(. "$EGRESS_ENV" && printf '%s' "$KOI_EGRESS_PORT")
	printf '%s\n' \
		"KOI_DOMAIN=$DOMAIN" \
		'KOI_UPLOADS=spool' \
		'KOI_LIVE=file' \
		"KOI_TLS=${TLS%%:*}" \
		"KOI_CADDY_ADMIN=$CADDY_ADMIN" \
		"KOI_EGRESS_PROXY=http://$egress_host:$egress_port" \
		'KOI_EGRESS_CA=/etc/koi/egress/ca.pem' >"$KOI_ENV.new"
	mv -f "$KOI_ENV.new" "$KOI_ENV"
}

# Every account --user names is there, before anything is changed.
check_users() {
	local user
	for user in "${USERS[@]}"; do
		id "$user" >/dev/null 2>&1 || die "there is no account '$user' on this host"
	done
}

# Each account may open koid's control socket from its next login on: the
# socket is mode 0660 in the group koi-control, as the SSH gateway's
# koi-connect reaches it.
add_users() {
	local user
	for user in "${USERS[@]}"; do
		usermod -aG koi-control "$user"
	done
}

# koid checks the host before it listens, which takes a minute or more with
# large images, as scripts/deploy-host.sh waits for it.
start_koid() {
	systemctl daemon-reload
	# Caddy starts again, with the environment file as it is now: a reload,
	# as cloud-init.sh does, keeps the environment Caddy started with, which
	# on a first install with a DNS provider had no token.
	systemctl restart caddy.service
	systemctl enable koid.service
	systemctl restart koid.service
	local _
	for _ in $(seq 1 300); do
		curl -fsS "$KOID_HEALTH" >/dev/null 2>&1 && return 0
		sleep 1
	done
	journalctl -u koid --no-pager -n 50 || true
	die 'koid did not answer; its log is above'
}

# What only the operator can do, once.
next_steps() {
	echo
	echo "koi is installed: previews will be served at https://<label>.$DOMAIN/"
	echo "Left to do once:"
	if [ "$LOCAL" = true ]; then
		echo "  - Names: point <label>.$DOMAIN at this machine, one line per preview in /etc/hosts"
		echo "    (127.0.0.1 hello.$DOMAIN), or every name at once with a local resolver"
		echo "    (dnsmasq: address=/$DOMAIN/127.0.0.1)."
	else
		echo "  - Names: a DNS record *.$DOMAIN pointing at this host's public address."
	fi
	case $TLS in
	internal)
		echo "  - Trust Caddy's CA on each machine that visits previews: here,"
		echo "    sudo caddy trust --address $CADDY_ADMIN;"
		echo "    elsewhere, add $CADDY_ROOT from this host to its trust store."
		;;
	acme-http)
		echo "  - Open ports 80 and 443 to the internet; Let's Encrypt checks each preview name there."
		;;
	acme-dns:*)
		echo "  - Open port 443 to whoever visits previews."
		;;
	esac
	if [ ${#USERS[@]} -gt 0 ]; then
		echo "  - ${USERS[*]}: log out and in again (or run newgrp koi-control) to reach koid's socket."
	fi
	if [ "$LOCAL" = true ]; then
		echo "  - Then, in a checkout: koi up --local"
	else
		echo "  - Authorize each CLI's public key in /etc/ssh/koi-connect/authorized_keys, and hand"
		echo "    its operator the host key fingerprint above for koi target trust."
	fi
}

main() {
	parse_args "$@"
	check_platform
	check_bundle
	check_users
	check_caddy
	provision
	install_bundle
	write_dns_files
	write_env
	add_users
	check_dns_env
	start_koid
	next_steps
}

# Sourced by the tests, which run the steps one at a time.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
