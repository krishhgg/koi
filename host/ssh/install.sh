#!/bin/bash
# Installs the SSH gateway for the CLI on the box, as root: the koi-connect
# account that sshd runs the gateway for, the koi-control group that may
# open koid's control socket, the authorized keys file, the gateway binary
# and the sshd configuration for the account. Run by scripts/deploy-host.sh
# from the unpacked host bundle with the freshly built gateway as its one
# argument, so every step must be safe to repeat; run without an argument it
# keeps the gateway already installed. The sshd configuration is checked
# by reading the files as sshd does: the block must be the first Match sshd
# meets, and no other Match block may set AcceptEnv; then with sshd -t;
# then sshd -T shows the global PermitUserEnvironment, and sshd -T -C for
# a few clients of the account shows every keyword of the block with the
# block's value. The files are read before sshd is run on them: sshd opens
# whatever an Include names, and a named pipe with no writer would hold
# sshd -t for good, where the walker refuses it without opening it. Only
# then is sshd asked to reload; a reload leaves every session that exists,
# the operator's among them, as it is. The block and the checks are in
# sshd.sh next to this file, which the CLI's integration test shares. See
# docs/configuration.md.
set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/sshd.sh"

SSHD=$(command -v sshd || echo /usr/sbin/sshd)
GATEWAY=/usr/local/libexec/koi-ssh-gateway
KEYS_DIR=/etc/ssh/koi-connect
KEYS=$KEYS_DIR/authorized_keys
SSHD_MAIN=/etc/ssh/sshd_config
# Named to sort first in the directory: sshd reads included files in
# lexical order, and the first Match block that matches a client wins.
SSHD_CONF=/etc/ssh/sshd_config.d/00-koi-connect.conf
# Where an earlier installer wrote the block; removed, so that sshd reads
# one block for the account and not two.
OLD_SSHD_CONF=/etc/ssh/sshd_config.d/60-koi-connect.conf
HOME_DIR=/var/lib/koi-connect

# --- Accounts ---------------------------------------------------------------
# koi-connect logs in; sshd runs the gateway for it and nothing else. It has
# no password, no startup files it can write (its home is root's and empty),
# and a real shell only because sshd runs the forced command through the
# account's shell. koi-control may open the control socket: koi-connect is
# in it, and so is koi, which gives the socket that group when it makes it
# (a member may chgrp to its own groups; nobody else may).
getent group koi-control > /dev/null || groupadd --system koi-control
id koi-connect > /dev/null 2>&1 || useradd --system --home-dir "$HOME_DIR" --no-create-home --shell /bin/sh koi-connect
install -d -o root -g root -m 0755 "$HOME_DIR"
usermod -aG koi-control koi-connect
# No password, and not locked. `*` is a field no password hashes to. A leading
# `!`, which usermod -L writes and useradd leaves, means a locked account to
# OpenSSH, and with UsePAM no sshd refuses a locked account before it looks at
# any key (auth.c, allowed_user; tried with sshd 9.6). This also repairs an
# account an earlier installer locked. A field that is `*` already is not
# written again.
password=$(getent shadow koi-connect | cut -d: -f2) || password=''
[ "$password" = '*' ] || usermod -p '*' koi-connect
id koi > /dev/null 2>&1 && usermod -aG koi-control koi
# Never in docker, sudo or koi's own group, whatever an earlier run or a
# person did.
for group in docker sudo koi; do
	if id -nG koi-connect | tr ' ' '\n' | grep -qx "$group"; then
		gpasswd -d koi-connect "$group" > /dev/null
	fi
done

# --- Gateway ----------------------------------------------------------------
install -d -o root -g root -m 0755 /usr/local/libexec
if [ $# -ge 1 ]; then
	install -o root -g root -m 0755 "$1" "$GATEWAY.new"
	mv -f "$GATEWAY.new" "$GATEWAY"
fi
if [ ! -x "$GATEWAY" ]; then
	echo "koi: no gateway at $GATEWAY; run scripts/deploy-host.sh, which builds and installs it" >&2
	exit 1
fi
# Nothing on the way to the gateway may be writable by anyone but root:
# sshd runs the path as koi-connect, and a writable link in it would be a
# way to run something else as that account.
for path in /usr /usr/local /usr/local/libexec "$GATEWAY"; do
	if [ -L "$path" ]; then
		echo "koi: $path is a symlink; the gateway's path must be plain directories" >&2
		exit 1
	fi
	read -r owner mode < <(stat -c '%u %a' "$path")
	if [ "$owner" != 0 ] || [ $((8#$mode & 8#022)) -ne 0 ]; then
		echo "koi: $path is owned by uid $owner with mode $mode; it must be root's and not group or world writable" >&2
		exit 1
	fi
done

# --- Authorized keys --------------------------------------------------------
# Root's file, outside the account's home, so the account cannot add a key
# of its own. The operator appends the CLI's public keys here, one a line.
if [ -L "$KEYS_DIR" ] || [ -L "$KEYS" ]; then
	echo "koi: $KEYS_DIR or $KEYS is a symlink; refusing to touch it" >&2
	exit 1
fi
install -d -o root -g root -m 0755 "$KEYS_DIR"
[ -e "$KEYS" ] || install -o root -g root -m 0644 /dev/null "$KEYS"
chown root:root "$KEYS"
chmod 0644 "$KEYS"

# --- sshd -------------------------------------------------------------------
# The Match block applies to koi-connect alone (sshd.sh, koi_match_block):
# keys from the one root-owned file and nothing else, no PTY, no ~/.ssh/rc,
# no chroot, no forwarding of any kind, the gateway as the one command
# whatever the client asked for, and no variable from the client or the
# configuration's AcceptEnv and SetEnv in its environment. Each of those
# is a keyword the block sets itself, since for the keywords it sets sshd
# keeps the first value it obtains, except AcceptEnv, to which every
# matching block adds. Ubuntu's sshd_config includes this directory first;
# a Match block in an included file ends with that file.
wanted=$(koi_match_block koi-connect "$GATEWAY" "$KEYS")
for path in "$SSHD_CONF" "$OLD_SSHD_CONF"; do
	if [ -L "$path" ]; then
		echo "koi: $path is a symlink; refusing to touch it" >&2
		exit 1
	fi
done
previous=''
[ -f "$SSHD_CONF" ] && previous=$(cat "$SSHD_CONF")
old_previous=''
[ -f "$OLD_SSHD_CONF" ] && old_previous=$(cat "$OLD_SSHD_CONF")
changed=0
if [ "$wanted" != "$previous" ]; then
	changed=1
	install -d -o root -g root -m 0755 "$(dirname "$SSHD_CONF")"
	printf '%s\n' "$wanted" > "$SSHD_CONF.new"
	chmod 0644 "$SSHD_CONF.new"
	mv -f "$SSHD_CONF.new" "$SSHD_CONF"
fi
if [ -n "$old_previous" ]; then
	changed=1
	rm -f "$OLD_SSHD_CONF"
fi

# Back out a configuration sshd would not load or that does not bind the
# account as intended: both files as they were. The running sshd is
# untouched until every check passes.
restore() {
	if [ -n "$previous" ]; then
		printf '%s\n' "$previous" > "$SSHD_CONF"
	else
		rm -f "$SSHD_CONF"
	fi
	if [ -n "$old_previous" ]; then
		printf '%s\n' "$old_previous" > "$OLD_SSHD_CONF"
	fi
}
# sshd -t refuses every configuration while its privilege separation
# directory is missing. With socket activation (ssh.socket on Ubuntu 24.04)
# sshd has not run since boot until someone connects, and the directory comes
# from the service's RuntimeDirectory, so on a box reached only through SSM it
# is gone after every start. Make it as the service would.
[ -d /run/sshd ] || install -d -o root -g root -m 0755 /run/sshd
# The checks, in sshd.sh's order (koi_check_sshd). The files are read as
# sshd reads them, every Include in sshd's order, before sshd is run on
# them: the block must be the first Match sshd reads, and no other Match
# block may set AcceptEnv, the one keyword sshd adds up across matching
# blocks; sshd -T answers for one client at a time, and a later block may
# match clients a probe does not stand for. Then sshd -t. The global
# section must set PermitUserEnvironment no, which a Match block cannot.
# Then sshd -T -C for a few clients of the account shows that sshd loads
# the block as written and that the block's value is the one in force for
# every keyword it sets. What the checks cannot see is a sshd started on
# another file (-f), or a Match block added after this run. See
# docs/configuration.md.
if ! koi_check_sshd "$SSHD" "$SSHD_MAIN" "$SSHD_CONF" /etc/ssh koi-connect "$GATEWAY" "$KEYS"; then
	echo "koi: $SSHD_CONF is removed again and sshd was not reloaded" >&2
	restore
	exit 1
fi

if [ "$changed" = 1 ]; then
	# A reload re-reads the configuration for new connections and leaves
	# the sessions that exist alone. With socket activation the service may
	# not be running; then the next connection reads the new file anyway.
	for unit in ssh.service sshd.service; do
		if systemctl is-active --quiet "$unit" 2> /dev/null; then
			systemctl reload "$unit"
			break
		fi
	done
	echo "koi: sshd configuration for koi-connect installed and reloaded"
fi

if [ ! -s "$KEYS" ]; then
	echo "koi: no key authorized yet; append each CLI's public key to $KEYS (one a line, as ssh-keygen wrote it)"
fi
echo "koi: SSH gateway ready at $GATEWAY for koi-connect; host key fingerprint for koi target trust:"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2> /dev/null || true
