#!/usr/bin/env bash
# Build the Svelte control plane and embed it into the Go server.
#
# Usage: ./scripts/build-web.sh
#
# Produces cmd/server/webdist/ (not committed), which cmd/server/webui.go embeds
# via //go:embed. Run this before `go build ./...` for a binary with the console.
# Container images build the console themselves (see Dockerfile).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo ">> Building Svelte SPA (web/)…"
npm --prefix web ci --no-audit --no-fund
npm --prefix web run build

echo ">> Embedding build output into cmd/server/webdist/…"
find cmd/server/webdist -mindepth 1 ! -name .keep -exec rm -rf {} +
cp -R web/build/. cmd/server/webdist/

echo ">> Done. Now run: go build ./..."
