#!/bin/bash
# Packet tests for the verification run network (docs/verify.md, "Packet
# tests"). Run as root on a box provisioned like the real one, after
# host/verify/install.sh, with koid stopped:
#
#   sudo systemctl stop koid
#   sudo host/verify/packet-test/run.sh [--verbose] [--keep]
#   sudo systemctl start koid
#
# It builds two run networks as koid does, sends real packets through them,
# prints one line per flow with what it expected and what it saw, and exits 1
# when any line does not match. It removes what it made when it ends; `--cleanup`
# removes what a run that was killed left behind.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
	echo "koi packet test: run as root" >&2
	exit 2
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    sys.exit("koi packet test: needs python3 3.10 or newer")
PY
for tool in docker nsenter tcpdump conntrack ip ss curl runuser sudo ping; do
	if ! command -v "$tool" >/dev/null; then
		echo "koi packet test: $tool is not installed" >&2
		exit 2
	fi
done
exec python3 -I "$here/packets.py" "$@"
