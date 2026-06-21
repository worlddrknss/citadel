# Citadel

Citadel is a lightweight AWS KMS + Secrets Manager JSON API-compatible service
intended for Vault auto-unseal and secret storage.

> Naming: the product is **Citadel**. The Go module path
> (`github.com/worlddrknss/go-kms`), container image, Kubernetes manifests, and
> `KMS_*` environment variables retain the historical `go-kms` / `KMS_`
> identifiers for backward compatibility with existing deployments.

## Supported AWS KMS actions

- `TrentService.Encrypt`
- `TrentService.Decrypt`
- `TrentService.DescribeKey`
- `TrentService.CreateKey` (DB mode)
- `TrentService.ListKeys`
- `TrentService.CreateAlias`
- `TrentService.UpdateAlias`
- `TrentService.ListAliases`
- `TrentService.EnableKey`
- `TrentService.DisableKey`
- `TrentService.ScheduleKeyDeletion`
- `TrentService.CancelKeyDeletion`

Additional endpoints:

- `GET /admin` for management overview of keys and aliases.

Current implementation status:

- Phase 1 foundation in progress: PostgreSQL-backed key metadata with env bootstrap fallback.
- Legacy ciphertexts are still decryptable after enabling DB mode.

## Run locally

```bash
export KMS_MASTER_KEY_B64="$(openssl rand -base64 32)"
export KMS_KEY_ID="go-kms-default-key"
# Optional: enforce access key ID presence in SigV4 Authorization header
# export KMS_ACCESS_KEY_ID="vault"

go run ./cmd/server
```

Run with PostgreSQL (recommended for migration and future phases):

```bash
export KMS_DB_URL="postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"

# Optional bootstrap/fallback values during migration from env-only mode.
export KMS_MASTER_KEY_B64="$(openssl rand -base64 32)"
export KMS_KEY_ID="go-kms-default-key"

go run ./cmd/server
```

Health check:

```bash
curl -s http://127.0.0.1:8080/healthz
```

## Vault seal example

```hcl
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "go-kms-default-key"
  endpoint   = "http://go-kms.infrastructure.svc.cluster.local:8080"
}
```

## Notes

- This service targets protocol compatibility for Vault unseal flows and is not a full AWS KMS implementation.
- Security model, trust boundaries, and a production hardening checklist are documented in `docs/SECURITY.md`.
- Production deployments should enable strict SigV4 verification (`KMS_SIGV4_STRICT=true` with `KMS_SECRET_ACCESS_KEY`), default-deny policies, HMAC audit chaining, TLS, and Argon2id-hashed admin users. See `docs/SECURITY.md`.
- Full phased implementation details are in `docs/PHASES.md`.
- Phase A compatibility status is tracked in `docs/COMPATIBILITY_MATRIX.md`.
- AWS Secrets Manager supplemental planning is tracked in `docs/SECRETS_MANAGER_PHASES.md`.
- The admin console now includes an audit explorer shared across KMS and Secrets Manager.

## Build Roadmap (5 phases)

1. Phase 1: PostgreSQL-backed key/config storage, default key resolution, migration-safe env fallback.
2. Phase 2: Lifecycle APIs (`CreateKey`, `ListKeys`, aliases, enable/disable, deletion windows).
3. Phase 3: AuthZ model (grants/policies), stronger SigV4 validation, tenant boundaries.
4. Phase 4: Management UI (key inventory, policy/grant management, audit explorer, operator workflows).
5. Phase 5: Hardening and operations (HA, backups, key wrapping root, SLOs, security tests).

## Release image on tag

GitHub Actions publishes a multi-arch image to GHCR when pushing a semver tag.

```bash
git tag v1.0.0
git push origin v1.0.0
```

Published tags include:

- `1.0.0`
- `1.0`
- `1`
- `sha-<commit>`
