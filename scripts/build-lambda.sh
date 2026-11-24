#!/usr/bin/env bash
# Bundles the wake function for the nodejs22.x runtime. Output is one ESM file,
# written into the koi module, whose wake.tf zips it.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
out=infra/modules/koi/files/handler.mjs
bun build --target=node --format=esm --minify --outfile "$out" packages/lambda/src/handler.ts
echo "built $out"
