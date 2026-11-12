#!/usr/bin/env bash
# Lints and renders the Citadel chart with every values file in ci/, checks
# the rendered manifests with kubeconform, and checks that unsafe values are
# refused. Used by CI; runs locally with helm and kubeconform on PATH, or with
# HELM / KUBECONFORM set to other commands (e.g. docker run ...).
#
#   deploy/helm/validate.sh
#   HELM="docker run --rm -v $PWD:/w -w /w alpine/helm:3.16.4" \
#   KUBECONFORM="docker run --rm -i ghcr.io/yannh/kubeconform:latest-alpine" \
#     deploy/helm/validate.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
HELM=${HELM:-helm}
KUBECONFORM=${KUBECONFORM:-kubeconform}
KUBE_VERSION=${KUBE_VERSION:-1.31.0}
chart=deploy/helm/citadel
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

kubeconform() {
  # CRD schemas (HTTPRoute, ServiceMonitor) come from the datree catalog.
  $KUBECONFORM -strict -summary \
    -kubernetes-version "$KUBE_VERSION" \
    -schema-location default \
    -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
}

echo "==> helm lint"
for f in "$chart"/ci/*-values.yaml; do
  $HELM lint --strict "$chart" -f "$f"
done

echo "==> helm template + kubeconform"
for f in "$chart"/ci/*-values.yaml; do
  name=$(basename "$f" .yaml)
  for kv in 1.29.0 "$KUBE_VERSION"; do
    $HELM template citadel "$chart" -n citadel --kube-version "$kv" -f "$f" > "$out/$name-$kv.yaml"
    echo "--- $name (Kubernetes $kv)"
    kubeconform < "$out/$name-$kv.yaml"
  done
done

echo "==> refused configurations"
expect_fail() {
  local why=$1; shift
  if $HELM template citadel "$chart" "$@" > /dev/null 2>"$out/err"; then
    echo "FAIL: rendered although it should be refused: $why" >&2
    exit 1
  fi
  echo "ok: refused ($why): $(tr '\n' ' ' < "$out/err" | cut -c1-200)"
}
expect_fail "no database secret"
expect_fail "inline secret without secrets.create" \
  --set secrets.existingSecret=s --set secrets.wrappingKey.value=x
expect_fail "in-memory with two replicas" \
  --set devMode.inMemory=true --set secrets.existingSecret=s
expect_fail "grace period shorter than the drain" \
  --set secrets.existingSecret=s --set terminationGracePeriodSeconds=10
expect_fail "grace period shorter than preStop sleep + drain" \
  --set secrets.existingSecret=s --set terminationGracePeriodSeconds=20 --set preStopSleepSeconds=10
expect_fail "trusting every proxy" \
  --set secrets.existingSecret=s --set 'config.trustedProxies={0.0.0.0/0}'
expect_fail "network policy without a database egress rule" \
  --set secrets.existingSecret=s --set networkPolicy.enabled=true
expect_fail "tls without a certificate secret" \
  --set secrets.existingSecret=s --set tls.enabled=true
expect_fail "schema: invalid public URL" \
  --set secrets.existingSecret=s --set config.publicUrl=citadel.example.com
expect_fail "schema: unknown top-level key" \
  --set secrets.existingSecret=s --set replicas=3

echo "All chart checks passed."
