#!/usr/bin/env bash
# Builds what a koi host runs into DIR: koid, the SSH gateway, and the
# bundles of the recipes, the egress proxy, the SSH gateway's installer and
# the verification helper. scripts/deploy-host.sh builds them this way and
# uploads them to S3 for the AWS box. For a host outside AWS, DIR also gets
# host/cloud-init.sh and host/install-vm.sh, with the SHA-256 of every file
# in SHA256SUMS, which the installer checks: copy the whole directory to the
# host and run install-vm.sh there as root (docs/configuration.md).
#
#   scripts/host-bundle.sh DIR
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
[ $# -eq 1 ] || { echo "usage: scripts/host-bundle.sh DIR" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd)

(cd "$repo/packages/daemon" && bun build --compile --target=bun-linux-x64 --outfile "$out/koid" ./src/main.ts >/dev/null)
(cd "$repo" && bun build --compile --target=bun-linux-x64 --outfile "$out/koi-ssh-gateway" ./host/ssh/koi-ssh-gateway.ts >/dev/null)
tar -czf "$out/recipes.tar.gz" -C "$repo/recipes" .
tar -czf "$out/egress.tar.gz" -C "$repo/host/egress" --exclude=test --exclude=__pycache__ .
tar -czf "$out/ssh.tar.gz" -C "$repo/host/ssh" --exclude=test .
tar -czf "$out/verify.tar.gz" -C "$repo/host/verify" --exclude=test --exclude=__pycache__ .
install -m 0755 "$repo/host/cloud-init.sh" "$repo/host/install-vm.sh" "$out/"
(cd "$out" && sha256sum koid koi-ssh-gateway recipes.tar.gz egress.tar.gz ssh.tar.gz verify.tar.gz cloud-init.sh install-vm.sh > SHA256SUMS)
echo "koi host bundle in $out"
