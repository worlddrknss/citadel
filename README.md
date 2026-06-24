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
export KMS_KEY_ID="go-kms-default-key"

go run ./cmd/server
```

### Local run (PostgreSQL)

```bash
export KMS_DB_URL="postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
export KMS_MASTER_KEY_B64="$(openssl rand -base64 32)"
export KMS_KEY_ID="go-kms-default-key"

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
  kms_key_id = "go-kms-default-key"
  endpoint   = "http://go-kms.infrastructure.svc.cluster.local:8080"
}
```

## Project layout

- `cmd/server`: main Citadel service (AWS-compatible and native APIs)
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

For coordinated vulnerability disclosure, open a private security report in your forge of choice or contact maintainers directly before public disclosure.

## Open source readiness note

This repository has been reviewed for obvious committed plaintext secrets and direct token/key literals in tracked source files.
As with any cryptographic or control-plane service, you should still run your own secret scanning and history checks in CI before broad publication.

## License

This project is licensed under the GNU Affero General Public License v3.0 (or later).
See the `LICENSE` file for details.

SPDX: `AGPL-3.0-or-later`

## Contributing

Contributions are welcome.

- Open an issue for bugs and feature proposals
- Keep changes focused and well-tested
- Include tests for behavior changes where possible
- Follow existing coding and API conventions

By contributing, you agree that your contributions are licensed under AGPL-3.0-or-later.
