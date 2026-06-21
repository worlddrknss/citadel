# go-kms Full Suite Plan

This document tracks the implementation path to evolve go-kms toward an AWS KMS-like management suite while preserving Vault auto-unseal compatibility.

## Vault Continuity Principle

Migration order must preserve existing decryptability and startup behavior:

1. Keep legacy env vars (`KMS_MASTER_KEY_B64`, `KMS_KEY_ID`) during rollout.
2. Enable DB mode with `KMS_DB_URL`.
3. On startup, go-kms bootstraps the legacy key into `kms_keys` if missing.
4. New ciphertexts embed key ID metadata; old ciphertexts remain decryptable.
5. Remove legacy env key material only after validating DB state and unseal continuity.

## Phase 1 (Started)

Goal: persistent key/config foundation.

Implemented:

- PostgreSQL-backed key storage (`kms_keys`) and settings (`kms_settings`).
- Bootstrapping from legacy env key into DB.
- Default key selection via `kms_settings.default_key_id` with fallback behavior.
- Ciphertext format with key ID header and legacy compatibility.

Pending in phase:

- Move from plaintext `master_key_b64` to wrapped key material.
- Add startup health checks that assert key presence in DB.

## Phase 2 (Started)

Goal: key lifecycle API surface.

Implemented:

- `TrentService.CreateKey`
- `TrentService.ListKeys`

Pending in phase:

- `CreateAlias`, `ListAliases`, `UpdateAlias`.
- `EnableKey`, `DisableKey`, `ScheduleKeyDeletion`, `CancelKeyDeletion`.
- Rotation metadata and versioned key material.

## Phase 3 (Scaffolded)

Goal: authN/authZ parity direction.

Started:

- Access key gate is still available (`KMS_ACCESS_KEY_ID`).

Planned:

- Full SigV4 signature validation.
- Grants and key policies in DB.
- Tenant-aware authorization model.

## Phase 4 (Planned)

Goal: management UI.

Planned scope:

- Key inventory and detail pages.
- Alias and policy management.
- Key state transitions.
- Audit event explorer.

## Phase 5 (Started)

Goal: operational hardening and audit.

Implemented:

- Audit table scaffold (`kms_audit_events`).
- API action audit inserts for main operations.

Planned:

- Tamper-evident hash chaining on audit rows.
- Metrics, SLOs, and failure budget alerts.
- HA deployment profile and backup/restore runbooks.

## Production Migration Runbook (Initial)

1. Deploy go-kms with both `KMS_DB_URL` and legacy key env vars set.
2. Confirm go-kms startup and `DescribeKey` success for existing key ID.
3. Verify `ListKeys` includes legacy key.
4. Restart Vault pods one by one and verify auto-unseal behavior.
5. After stable period, remove legacy key env vars and keep DB as source of truth.
6. Rotate to wrapped key material implementation before broader adoption.
