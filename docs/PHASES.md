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

## Phase 2 (Completed for MVP)

Goal: key lifecycle API surface.

Implemented:

- `TrentService.CreateKey`
- `TrentService.ListKeys`
- `TrentService.CreateAlias`
- `TrentService.UpdateAlias`
- `TrentService.ListAliases`
- `TrentService.EnableKey`
- `TrentService.DisableKey`
- `TrentService.ScheduleKeyDeletion`
- `TrentService.CancelKeyDeletion`

Pending in phase:

- Rotation metadata and versioned key material.

## Phase 3 (Completed for MVP)

Goal: authN/authZ parity direction.

Implemented:

- Access key gate is still available (`KMS_ACCESS_KEY_ID`).
- Optional strict SigV4 header validation mode (`KMS_SIGV4_STRICT=true`).

Remaining hardening:

- Full cryptographic SigV4 signature verification.
- Grants and key policies in DB.
- Tenant-aware authorization model.

## Phase 4 (Completed for MVP)

Goal: management UI.

Implemented scope:

- Minimal management UI endpoint at `/admin` with key and alias inventory.

Remaining UI expansion:

- Authenticated UI with RBAC.
- Key workflows and policy editors.
- Audit explorer and tenant views.

## Phase 5 (Completed for MVP)

Goal: operational hardening and audit.

Implemented:

- Audit table scaffold (`kms_audit_events`).
- API action audit inserts for main operations.
- Tamper-evident chaining fields (`prev_hash`, `event_hash`) with chained writes.

Remaining hardening:

# go-kms Full Compatibility Plan

This is the execution plan to compete with AWS KMS and Fortanix while keeping the core open source.

## Goal

Deliver full AWS KMS compatibility with enterprise-grade security controls and operations, while keeping deployment self-hostable and FOSS.

## Fastest to Longest Phases

Order is based on implementation speed and dependency chain.

1. Phase A: Compatibility Core Hardening (fastest, 1-2 weeks)
2. Phase B: Policy and AuthZ Model (2-4 weeks)
3. Phase C: Key Material Security Model (3-5 weeks)
4. Phase D: Enterprise UI and Workflow UX (4-6 weeks)
5. Phase E: Production and Compliance Readiness (longest, 6-10+ weeks)

## Phase A: Compatibility Core Hardening (1-2 weeks)

Objective:

- Finish high-frequency AWS KMS API behavioral parity.

Deliverables:

- Lock down current APIs to AWS-like response semantics (status codes, error types, payload fields).
- Add operation conformance tests comparing go-kms responses to expected AWS behavior.
- Add stable paging and limits for list operations.
- Add compatibility matrix document with pass/fail tracking.

Acceptance criteria:

- >=95 percent pass rate on defined core KMS compatibility suite.
- No breaking diffs on existing Vault auto-unseal flows.

## Phase B: Policy and AuthZ Model (2-4 weeks)

Objective:

- Deliver real authorization behavior, not just endpoint checks.

Deliverables:

- Grants model (CreateGrant, RetireGrant, RevokeGrant, ListGrants).
- Resource policy storage and evaluation.
- Principal and tenant model for multi-tenant isolation.
- Full SigV4 verification (canonical request and signature validation).

Acceptance criteria:

- AuthZ integration tests prove deny-by-default behavior.
- Cross-tenant key access attempts are consistently rejected.

## Phase C: Key Material Security Model (3-5 weeks)

Objective:

- Remove plaintext key material persistence and align to enterprise crypto expectations.

Deliverables:

- Replace `master_key_b64` at rest with wrapped key material.
- Internal wrapping-key subsystem so go-kms remains fully standalone by default.
- Optional external root-of-trust integrations as an add-on, not a core dependency.
- Key versioning and rotation metadata for symmetric keys.
- Safe migration path from existing DB rows.

Acceptance criteria:

- No plaintext key material in DB after migration.
- Key unwrap path tested with backup and restore scenarios.

## Phase D: Enterprise UI and Workflow UX (4-6 weeks)

Objective:

- Move from admin utility page to enterprise control plane UX.

Deliverables:

- Authenticated UI with RBAC and tenant scoping.
- Key detail pages, aliases, lifecycle workflows, grants and policy editor.
- Audit explorer and request tracing.
- Bulk operations and safe confirmations for destructive actions.

Acceptance criteria:

- All lifecycle tasks can be completed from UI and API.
- No direct HTML string rendering in service entrypoint; templates/components are modular.

## Phase E: Production and Compliance Readiness (6-10+ weeks)

Objective:

- Prove reliability and auditability for enterprise adoption.

Deliverables:

- SLOs, metrics, and alerting (API latency, decrypt error rates, auth failures).
- HA deployment profile and disaster recovery runbook.
- Tamper-evident audit verification tooling and export pipeline.
- Security documentation: threat model, hardening guide, and incident response playbook.

Acceptance criteria:

- Runbook-tested backup and restore.
- Independent security review issues resolved to agreed baseline.

## Current Status Snapshot

Done:

- DB-backed key and settings model.
- Core lifecycle operations and alias operations.
- Strict SigV4 header mode and access key gate.
- Admin UI with interactive key actions.
- Audit chain fields and chained writes.

Not done yet (required for true full-compatibility positioning):

- Full cryptographic SigV4 verification.
- Complete grants and policy parity.
- Wrapped key material at rest.
- Enterprise-authenticated UI and full audit workflow UX.
- HA and compliance-grade operational guarantees.

## Migration Guardrails (must keep)

1. Keep legacy env vars (`KMS_MASTER_KEY_B64`, `KMS_KEY_ID`) until migration is verified.
2. Enable DB mode with `KMS_DB_URL` and verify bootstrap key row exists.
3. Confirm decrypt compatibility for old ciphertext blobs.
4. Roll Vault pods one-by-one and verify auto-unseal.
5. Remove legacy key env vars only after production soak period.
