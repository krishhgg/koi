#!/usr/bin/env bash
# Bundles the wake function for the nodejs22.x runtime. Output is one ESM file;
# infra/wake.tf zips it.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
bun build --target=node --format=esm --minify \
	--outfile packages/lambda/dist/handler.mjs packages/lambda/src/handler.ts
echo "built packages/lambda/dist/handler.mjs"
