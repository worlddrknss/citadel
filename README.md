# go-kms

Lightweight AWS KMS JSON API-compatible service intended for Vault auto-unseal lab environments.

## Supported AWS KMS actions

- `TrentService.Encrypt`
- `TrentService.Decrypt`
- `TrentService.DescribeKey`

## Run locally

```bash
export KMS_MASTER_KEY_B64="$(openssl rand -base64 32)"
export KMS_KEY_ID="go-kms-default-key"
# Optional: enforce access key ID presence in SigV4 Authorization header
# export KMS_ACCESS_KEY_ID="vault"

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
- For production, add strict SigV4 verification, mTLS, key persistence, and audit logging.

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
