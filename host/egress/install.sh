#!/bin/bash
# Installs or updates the koi egress proxy on the box, as root. Run by
# scripts/deploy-host.sh from the unpacked host bundle, so it must be safe to
# repeat. The proxy is mitmdump with koi's policy addon, listening on the
# preview network's gateway address, the only address previews can reach. It
# intercepts TLS, so it also publishes its CA certificate for koid to copy
# into previews.
#
# It listens three ways, all under the one policy: as the proxy in previews'
# HTTP(S)_PROXY (PORT); transparently, for the connections to ports 443 and
# 80 the firewall (host/cloud-init.sh, koi-firewall) redirects from previews
# whose code ignores the proxy setting (TRANSPARENT_PORT); and as the DNS
# server koid gives previews (DNS_PORT, where the firewall redirects their
# lookups to port 53 on the gateway, so no other server on the host answers
# them). KOI_DOMAIN, from deploy-host.sh, names
# the fixtures host the policy answers itself: fixtures.koi.<domain>, which
# the box's wildcard record already resolves. Two labels deep, it can never
# be a preview's name.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

MITM_VERSION=12.2.3
MITM_SHA256=2e95286b618fa6fd33e5e62a78c2e5112571d85f42ec2bac29b97ee242bdb5c5
PORT=3128
TRANSPARENT_PORT=3129
DNS_PORT=3153
fixtures=""
if [[ ${KOI_DOMAIN:-} =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]; then
	fixtures=fixtures.koi.$KOI_DOMAIN
fi

if [ "$(/usr/local/bin/mitmdump --version 2>/dev/null | awk '/^Mitmproxy:/ {print $2}')" != "$MITM_VERSION" ]; then
	tmp=$(mktemp -d)
	curl -fsSL -o "$tmp/mitm.tar.gz" "https://downloads.mitmproxy.org/$MITM_VERSION/mitmproxy-$MITM_VERSION-linux-x86_64.tar.gz"
	echo "$MITM_SHA256  $tmp/mitm.tar.gz" | sha256sum -c -
	tar -xzf "$tmp/mitm.tar.gz" -C "$tmp" mitmdump
	install -m 0755 "$tmp/mitmdump" /usr/local/bin/mitmdump
	rm -rf "$tmp"
fi

id koi-egress > /dev/null 2>&1 || useradd --system --home /var/lib/koi-egress --create-home --shell /usr/sbin/nologin koi-egress
# koid registers reviewers' tokens over the proxy's control socket.
usermod -aG koi-egress koi
install -d -m 0755 /etc/koi/egress

# The secret every koi token is derived from (koi_egress.py, derive_token):
# 32 random bytes, made once and kept across reboots and deploys. It is a
# file only the proxy's user can read and nobody can write (mode 0400), in
# a directory only root can write: code running as that user, which a
# compromised proxy would be, can neither replace the file nor put a
# symlink in its place for root to follow here, and a symlink is refused
# rather than followed. Nothing prints or copies it. The proxy refuses to
# start without it, or with one of another size, owner or mode. Deleting it
# invalidates every token: each key gets a new one when its keys page
# registers it again, and the reviewer pastes the new tokens into the
# preview. It is made before the policy is written below, so a running
# mitmdump that loads the new policy finds it there.
secret_dir=/etc/koi/egress/private
secret=$secret_dir/token-secret
if [ -L "$secret_dir" ] || [ -L "$secret" ]; then
	echo "$secret_dir or $secret is a symlink; refusing to touch it" >&2
	exit 1
fi
install -d -m 0711 "$secret_dir"
if [ ! -e "$secret" ]; then
	new=$(mktemp "$secret_dir/.token-secret.XXXXXX")
	head -c 32 /dev/urandom > "$new"
	if [ "$(stat -c %s "$new")" != 32 ]; then
		rm -f "$new"
		echo "could not read 32 random bytes for $secret" >&2
		exit 1
	fi
	chown koi-egress:koi-egress "$new"
	chmod 0400 "$new"
	mv -f "$new" "$secret"
fi
if [ ! -f "$secret" ]; then
	echo "$secret is not a regular file, so the proxy will not start; delete it to make a new one (every koi token then changes)" >&2
	exit 1
fi
chown koi-egress:koi-egress "$secret"
chmod 0400 "$secret"
if [ "$(stat -c %s "$secret")" != 32 ]; then
	echo "$secret is not 32 bytes, so the proxy will not start; delete it to make a new one (every koi token then changes)" >&2
	exit 1
fi

# Boxes deployed from an earlier revision of this script kept the secret at
# /var/lib/koi-egress/private/token-secret, in a directory the proxy's user
# owns. Nothing reads it now, so it goes, and so does the directory once it
# is empty. Both go as that user: the proxy, which owns the directory above,
# could swap the path for a symlink between any check here and the removal,
# and root would then delete through it; the proxy's user can delete only
# what it could delete anyway, and nothing in the root-owned directory the
# live secret is in.
remove_old_secret() {
	local dir=/var/lib/koi-egress/private
	if [ ! -d "$dir" ] || [ -L "$dir" ]; then
		return 0
	fi
	runuser -u koi-egress -- rm -f "$dir/token-secret" || true
	runuser -u koi-egress -- rmdir "$dir" 2> /dev/null || true
}
remove_old_secret

# Each file is written next to its place and renamed over it, so a running
# mitmdump, which loads koi_egress.py again whenever it changes, never reads
# a half-written one. (One that fails to load leaves the proxy down; see
# koi_egress.py.)
put() {
	install -m "$1" "$here/$2" "/etc/koi/egress/.$2.new"
	mv -f "/etc/koi/egress/.$2.new" "/etc/koi/egress/$2"
}
put 0644 koi_egress.py
put 0644 allow.txt
put 0755 ready.sh
# The helper koid runs through sudo to give each preview a default route to
# the bridge (see the file). The sudoers rule comes from provisioning.
install -d -m 0755 /usr/local/libexec
install -m 0755 -o root -g root "$here/koi-preview-route" /usr/local/libexec/.koi-preview-route.new
mv -f /usr/local/libexec/.koi-preview-route.new /usr/local/libexec/koi-preview-route

gateway=$(docker network inspect koi-previews -f '{{(index .IPAM.Config 0).Gateway}}')
case "$gateway" in
	*.*.*.*) ;;
	*) echo "koi-previews has no IPv4 gateway (got '$gateway')" >&2; exit 1 ;;
esac
printf 'KOI_EGRESS_HOST=%s\nKOI_EGRESS_PORT=%s\nKOI_EGRESS_TRANSPARENT_PORT=%s\nKOI_EGRESS_DNS_PORT=%s\nKOI_EGRESS_FIXTURES=%s\n' \
	"$gateway" "$PORT" "$TRANSPARENT_PORT" "$DNS_PORT" "$fixtures" > /etc/koi/egress/env

cat > /etc/systemd/system/koi-egress.service <<'UNIT'
[Unit]
Description=koi egress proxy for previews
After=docker.service koi-firewall.service
Requires=docker.service koi-firewall.service

[Service]
User=koi-egress
Group=koi-egress
EnvironmentFile=/etc/koi/egress/env
# The control socket lives here; koid is in the koi-egress group.
RuntimeDirectory=koi-egress
RuntimeDirectoryMode=0750
# server=false: mitmdump listens only once koi_egress.py has loaded and turns
# its server on, and ready.sh holds the start until then. A policy file that
# fails to load, or finds no usable token secret, leaves the proxy down,
# never open.
ExecStart=/usr/local/bin/mitmdump --quiet --listen-host ${KOI_EGRESS_HOST} --mode regular@${KOI_EGRESS_PORT} --mode transparent@${KOI_EGRESS_TRANSPARENT_PORT} --mode dns@${KOI_EGRESS_DNS_PORT} --set server=false --set confdir=/var/lib/koi-egress --set koi_allow=/etc/koi/egress/allow.txt --set koi_control=/run/koi-egress/control.sock --set koi_secret=/etc/koi/egress/private/token-secret --set koi_fixtures=${KOI_EGRESS_FIXTURES} -s /etc/koi/egress/koi_egress.py
ExecStartPost=/etc/koi/egress/ready.sh
Restart=on-failure
RestartSec=3
# Outside koi.slice, so previews cannot starve it, but with a ceiling of its
# own: whatever a preview sends, the proxy cannot take the memory Docker,
# Caddy and koid need. Past MemoryHigh the kernel reclaims hard; at MemoryMax
# it kills mitmdump, and systemd starts it again.
MemoryHigh=768M
MemoryMax=1G
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/koi-egress
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable koi-egress.service
# Returns once ready.sh has seen the policy start the proxy, or fails.
systemctl restart koi-egress.service || {
	journalctl -u koi-egress --no-pager -n 30
	exit 1
}
# Puts the CA certificate (public half only) where koid can read it and
# copy it into preview containers, so they trust the proxy, which
# intercepts TLS to every host it allows. The private key stays in
# /var/lib/koi-egress. The proxy's user owns that directory, so root never
# opens a path in it, which a swap under its feet could point anywhere: the
# file is read as that user, which can reach nothing the proxy itself
# cannot, into a file of root's own, and that is installed once it holds a
# certificate and nothing else.
publish_ca() {
	local ca=/var/lib/koi-egress/mitmproxy-ca-cert.pem
	local copy
	copy=$(mktemp)
	if ! runuser -u koi-egress -- cat "$ca" > "$copy"; then
		rm -f "$copy"
		echo "could not read $ca as koi-egress" >&2
		return 1
	fi
	if [ "$(head -n 1 "$copy")" != "-----BEGIN CERTIFICATE-----" ] || grep -q PRIVATE "$copy"; then
		rm -f "$copy"
		echo "$ca does not hold a certificate alone; refusing to publish it" >&2
		return 1
	fi
	install -m 0644 "$copy" /etc/koi/egress/ca.pem
	rm -f "$copy"
}

for _ in $(seq 1 20); do
	# The policy opens the control socket before it starts listening.
	if [ -S /run/koi-egress/control.sock ] && [ -s /var/lib/koi-egress/mitmproxy-ca-cert.pem ]; then
		publish_ca
		echo "koi-egress listening on $gateway:$PORT, $gateway:$TRANSPARENT_PORT and $gateway:$DNS_PORT"
		exit 0
	fi
	sleep 1
done
journalctl -u koi-egress --no-pager -n 30
exit 1
