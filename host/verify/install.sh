#!/bin/bash
# Installs the verification network helper on the box, as root. Run by
# scripts/deploy-host.sh from the unpacked host bundle, so it must be safe to
# repeat. The helper (koi_verify_net.py) is the one program koid may run as
# root, through the sudoers rule host/cloud-init.sh installs for exactly this
# path. It is root-owned and not writable by anyone else: koid checks the
# owner and mode before it counts verification as available.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

TARGET=/usr/local/libexec/koi-verify-net

python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    sys.exit("koi: the verification helper needs python3 3.10 or newer")
PY
# A file that does not parse would be installed broken; compile it first,
# without leaving bytecode next to the source.
python3 -B -c "import ast, sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])" "$here/koi_verify_net.py"

install -d -m 0755 "$(dirname "$TARGET")"
# Written beside its place and renamed over it, so a koid that runs the
# helper at that moment gets the old file or the new one, never half of one.
install -o root -g root -m 0755 "$here/koi_verify_net.py" "$TARGET.new"
mv -f "$TARGET.new" "$TARGET"
# The chains, their default denies and the jumps that reach them are the
# helper's to install and repair (`provision`, also run by host/cloud-init.sh
# on every provisioning). Running it here puts them in place on a box that
# got the helper for the first time, and checks that the file runs at all
# before koid depends on it. It prints what it changed and how the host
# attests.
"$TARGET" provision
echo "koi: installed $TARGET"
