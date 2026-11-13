#!/usr/bin/env bash
# Fails unless the SDK versions match a release tag.
#
#   scripts/check-sdk-version.sh v2.6.0   # compare with this tag
#   scripts/check-sdk-version.sh          # use GITHUB_REF_NAME (tag builds)
#
# The SDKs carry the Citadel release they ship with (sent in User-Agent and
# published to npm). The release workflow runs this before building, so a
# release whose SDKs still name the previous version fails instead of
# shipping. Bump them in the release pull request:
#
#   sdk/citadel/client.go             const Version = "X.Y.Z"
#   sdk/typescript/src/version.ts     export const VERSION = 'X.Y.Z';
#   sdk/typescript/package.json       (npm version X.Y.Z --no-git-tag-version
#   sdk/typescript/package-lock.json   in sdk/typescript updates both)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tag="${1:-${GITHUB_REF_NAME:-}}"
if [ -z "$tag" ]; then
  echo "usage: $0 <tag>  (or set GITHUB_REF_NAME)" >&2
  exit 2
fi
want="${tag#v}"

go_version="$(sed -n 's/^const Version = "\([^"]*\)"$/\1/p' "$ROOT/sdk/citadel/client.go")"
ts_version="$(sed -n "s/^export const VERSION = '\([^']*\)';$/\1/p" "$ROOT/sdk/typescript/src/version.ts")"
# The first "version" in package.json and the first two in package-lock.json
# (the lockfile root and its "" package entry) are the package's own.
pkg_version="$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$ROOT/sdk/typescript/package.json" | head -n 1)"
lock_versions="$(grep -m 2 '"version":' "$ROOT/sdk/typescript/package-lock.json" | sed 's/.*"version": "\([^"]*\)".*/\1/')"
lock_root="$(printf '%s\n' "$lock_versions" | sed -n 1p)"
lock_pkg="$(printf '%s\n' "$lock_versions" | sed -n 2p)"

fail=0
check() {
  local what="$1" got="$2"
  if [ -z "$got" ]; then
    echo "no version found in $what" >&2
    fail=1
  elif [ "$got" != "$want" ]; then
    echo "$what is \"$got\" but the release tag is $tag (expected \"$want\")." >&2
    fail=1
  fi
}
check "sdk/citadel/client.go Version" "$go_version"
check "sdk/typescript/src/version.ts VERSION" "$ts_version"
check "sdk/typescript/package.json version" "$pkg_version"
check "sdk/typescript/package-lock.json version" "$lock_root"
check "sdk/typescript/package-lock.json packages[\"\"].version" "$lock_pkg"

if [ "$fail" -ne 0 ]; then
  echo "Bump the SDK versions to $want (see the header of $0) and tag again." >&2
  exit 1
fi
echo "SDK versions $want match $tag"
