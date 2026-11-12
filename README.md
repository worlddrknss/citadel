# Citadel

Citadel is an open-source control plane for cryptographic keys, secrets, certificates, and parameters.
It provides AWS-compatible APIs (KMS, Secrets Manager, ACM/ACM PCA, and SSM Parameter Store) and a modern web console for day-to-day operations.

![Citadel dashboard](assets/image.png)

## Why Citadel

- AWS API compatibility for existing clients and integrations
- Single service for keys, secrets, PKI, and parameters
- Account-aware isolation and RBAC for multi-tenant deployments
- Native operator UI built with Svelte
- PostgreSQL-backed persistence with in-memory mode for local/dev workflows

## Core capabilities

- KMS-compatible encryption, decryption, key lifecycle, aliases, and signing
- Secrets Manager-compatible secret/version workflows
- ACM/ACM PCA-compatible private CA and certificate issuance/revocation
- SSM-compatible Parameter Store with versions, labels, tags, and SecureString encryption
- Native control-plane endpoints under `/v1/*` used by the web UI
- Audit logging and account-scoped access control

## Compatibility scope

Citadel is designed for practical interoperability with AWS clients and tooling.
It is not a drop-in reimplementation of every AWS feature or edge behavior.

## Quick start

### Prerequisites

- Go 1.25+
- Optional: PostgreSQL (recommended for persistent environments)

### Local run (in-memory)

```bash
export KMS_MASTER_KEY_B64="$(openssl rand -base64 32)"
export KMS_KEY_ID="citadel-default-key"

go run ./cmd/server
```

### Local run (PostgreSQL)

```bash
export KMS_DB_URL="postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
export KMS_MASTER_KEY_B64="$(openssl rand -base64 32)"
export KMS_KEY_ID="citadel-default-key"

go run ./cmd/server
```

### Health check

```bash
curl -s http://127.0.0.1:8080/healthz
```

## Vault seal example

```hcl
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "citadel-default-key"
  endpoint   = "http://citadel.infrastructure.svc.cluster.local:8080"
}
```

## Project layout

- `cmd/server`: the Citadel binary (config, store and server wiring)
- `internal/server`: HTTP routing, middleware and handlers (AWS-compatible and native APIs)
- `internal/store`: domain records and storage interfaces, with `postgres` (versioned SQL migrations) and `memory` backends
- `internal/config`, `internal/sigv4`, `internal/cryptoutil`, `internal/arn`: configuration, SigV4 verification, crypto helpers and ARN helpers
- `web`: Svelte frontend for the operator console
- `sdk`: client libraries
- `docs`: architecture and implementation notes

## Security

Citadel handles sensitive workloads; run it with production controls enabled.

- Use TLS in all non-local environments
- Use strict SigV4 validation where applicable
- Keep bootstrap credentials out of source control
- Run with least-privilege database and network policies
- Rotate keys, access keys, and session credentials regularly

For coordinated vulnerability disclosure, follow the process in `SECURITY.md` before any public disclosure.

### Rotating KMS key material

Symmetric KMS keys can rotate their material automatically (`EnableKeyRotation`,
every 90-2560 days, default 365) or on demand (`RotateKeyOnDemand`, at most 10
times per key). New ciphertext is sealed under the current material version
and names that version in its header; every earlier version is kept, so
ciphertext produced before a rotation (including blobs written by Citadel
versions that predate rotation) keeps decrypting. A background job (every
`KMS_JOB_INTERVAL`, default `1h`) performs due rotations and destroys keys whose
scheduled deletion date has passed. As in AWS, deletion proceeds even if
secrets or parameters still use the key; the job audits how many did. The
per-account default key (`alias/default`) can never be deleted.

### Rotating the wrapping key

`KMS_WRAPPING_KEY_B64` encrypts everything Citadel stores at rest: KMS key
material, access-key secrets, STS session secrets and ACME private keys. To
rotate it without downtime:

1. Generate a new key: `openssl rand -base64 32`.
2. Restart every replica with `KMS_WRAPPING_KEY_B64=<new key>` and
   `KMS_PREVIOUS_WRAPPING_KEYS_B64=<old key>` (a comma-separated list if you
   rotate again before finishing). Everything stays readable; anything newly
   written is wrapped with the new key.
3. Re-wrap stored material onto the new key. Replicas started with previous
   keys do this once at startup and then daily; a platform admin can also run
   it on demand with `POST /v1/kms/admin/rewrap`, which returns how many key
   material versions, access-key secrets and STS session secrets it re-wrapped
   and is audited as `citadel.RewrapKeyMaterial`. The pass is idempotent and
   resumable: rows already on the new key are skipped, and each update only
   applies if the row is unchanged.
4. When a pass reports `"failed": 0` and `"rewrapped": 0`, remove
   `KMS_PREVIOUS_WRAPPING_KEYS_B64` and restart. Keep a backup of the old key
   until you have confirmed the deployment starts and serves without it.

A non-zero `failed` count means some rows could not be opened with any
configured key; they are left untouched and logged by table and row ID.

## Open source readiness note

This repository has been reviewed for obvious committed plaintext secrets and direct token/key literals in tracked source files.
As with any cryptographic or control-plane service, you should still run your own secret scanning and history checks in CI before broad publication.

## License

This project is licensed under the GNU Affero General Public License v3.0 (or later).
See the `LICENSE` file for details.

SPDX: `AGPL-3.0-or-later`

## Contributing

Contributions are welcome.

- Start with `CONTRIBUTING.md` for setup, validation, and pull request expectations.
- Follow `CODE_OF_CONDUCT.md` when participating in project spaces.

By contributing, you agree that your contributions are licensed under AGPL-3.0-or-later.
