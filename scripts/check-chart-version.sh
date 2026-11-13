#!/usr/bin/env bash
# Fails unless the Helm chart's appVersion matches a release tag.
#
#   scripts/check-chart-version.sh v2.0.3   # compare with this tag
#   scripts/check-chart-version.sh          # use GITHUB_REF_NAME (tag builds)
#
# The release workflow runs this before building the image, so a release
# whose chart still points at the previous image tag fails instead of
# shipping. Bump deploy/helm/citadel/Chart.yaml appVersion in the release
# pull request; nothing commits it for you.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="$ROOT/deploy/helm/citadel/Chart.yaml"

tag="${1:-${GITHUB_REF_NAME:-}}"
if [ -z "$tag" ]; then
  echo "usage: $0 <tag>  (or set GITHUB_REF_NAME)" >&2
  exit 2
fi
want="${tag#v}"

got="$(sed -n 's/^appVersion:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CHART")"
if [ -z "$got" ]; then
  echo "no appVersion in $CHART" >&2
  exit 1
fi
if [ "$got" != "$want" ]; then
  echo "Chart.yaml appVersion is \"$got\" but the release tag is $tag (expected \"$want\")." >&2
  echo "Set appVersion: \"$want\" in deploy/helm/citadel/Chart.yaml and tag again." >&2
  exit 1
fi
echo "Chart.yaml appVersion $got matches $tag"
