#!/usr/bin/env bash
# Build the Svelte control plane and embed it into the Go server.
#
# Usage: ./scripts/build-web.sh
#
# Produces cmd/server/webdist/, which is embedded by cmd/server/webui.go via
# //go:embed. Run this before `go build ./...` whenever the web/ sources change.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo ">> Building Svelte SPA (web/)…"
npm --prefix web install --no-audit --no-fund
npm --prefix web run build

echo ">> Embedding build output into cmd/server/webdist/…"
rm -rf cmd/server/webdist
mkdir -p cmd/server/webdist
cp -R web/build/. cmd/server/webdist/

echo ">> Done. Now run: go build ./..."
