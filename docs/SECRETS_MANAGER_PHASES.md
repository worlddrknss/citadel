# AWS Secrets Manager Compatibility Supplement

This document extends the go-kms roadmap with an AWS Secrets Manager-compatible service plan that can share identity, policy, audit, and operational building blocks with the KMS implementation.

## Goal

Deliver an AWS Secrets Manager-compatible API and control plane that stays self-hostable, reuses go-kms security primitives where practical, and supports predictable migration paths for applications that already speak the AWS JSON protocol.

## Design Principles

1. Reuse shared platform pieces where possible: SigV4 handling, tenant identity, audit chain, UI shell, and storage migrations.
2. Keep KMS and Secrets Manager protocol surfaces distinct even when they share internals.
3. Preserve AWS behavioral compatibility first for core secret CRUD, version labels, and retrieval semantics.
4. Encrypt secret values with managed keys instead of introducing a second independent cryptographic root unless there is a clear operational reason.
5. Treat version staging labels and idempotency tokens as first-class compatibility requirements, not optional extras.

## Recommended Execution Order

The supplement can start before the full KMS roadmap is finished, but the dependency chain should stay explicit:

1. Build Secrets Phase S1 in parallel with remaining KMS work.
2. Align Secrets Phase S2 with KMS Phase C so secret-at-rest protections do not outrun key-wrapping guarantees.
3. Align Secrets Phase S3 with KMS Phase B so policy evaluation and tenant isolation use one model.
4. Build Secrets Phase S4 and S5 after the shared authZ, audit, and UI foundations stabilize.

## Protocol Scope

Priority AWS-compatible operations for the first usable cut:

- `secretsmanager.CreateSecret`
- `secretsmanager.DescribeSecret`
- `secretsmanager.GetSecretValue`
- `secretsmanager.PutSecretValue`
- `secretsmanager.UpdateSecret`
- `secretsmanager.DeleteSecret`
- `secretsmanager.RestoreSecret`
- `secretsmanager.ListSecrets`
- `secretsmanager.ListSecretVersionIds`
- `secretsmanager.TagResource`
- `secretsmanager.UntagResource`

Follow-on compatibility surface:

- `secretsmanager.RotateSecret`
- `secretsmanager.CancelRotateSecret`
- `secretsmanager.UpdateSecretVersionStage`
- `secretsmanager.GetResourcePolicy`
- `secretsmanager.PutResourcePolicy`
- `secretsmanager.ValidateResourcePolicy`

## Proposed Storage Model

Core tables or equivalent storage entities:

- `sm_secrets`: secret metadata, ARN, name, description, deletion state, owning tenant.
- `sm_secret_versions`: encrypted secret payloads, checksum metadata, creation time, client request token.
- `sm_secret_version_labels`: staging labels such as `AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING`.
- `sm_secret_tags`: key/value tags for filtering and access decisions.
- `sm_secret_policies`: resource policies if policy parity is enabled.
- `sm_rotation_jobs`: rotation state, schedule metadata, executor hooks, and last outcome.

Recommended encryption model:

- Generate per-secret data keys or version keys.
- Encrypt secret payloads using KMS-managed master keys or a shared internal wrapping hierarchy.
- Keep binary and string secret forms compatible with AWS response fields.

## Compatibility Guardrails

1. Preserve AWS naming, ARN shape, field names, and version-stage behavior for the supported API set.
2. Honor idempotency behavior for `ClientRequestToken` on create and version writes.
3. Keep delete and restore behavior explicit, including recovery windows and pending deletion state.
4. Never allow version-stage corruption where multiple versions claim `AWSCURRENT` without an explicit stage move.
5. Make `GetSecretValue` and version-stage reads stable before adding rotation automation.

## Fastest to Longest Phases

1. Phase S1: Compatibility Core and Secret CRUD (fastest, 1-2 weeks)
2. Phase S2: Secret Versioning and Encryption Model (2-4 weeks)
3. Phase S3: Policy, Tenancy, and Access Control (3-5 weeks)
4. Phase S4: Rotation Workflows and Operational Automation (4-6 weeks)
5. Phase S5: UI, Audit, and Production Readiness (longest, 5-8+ weeks)

## Phase S1: Compatibility Core and Secret CRUD (Completed for MVP)

Objective:

- Establish the first AWS-compatible Secrets Manager surface with reliable secret creation, retrieval, listing, update, and deletion semantics.

Deliverables:

- Request router for Secrets Manager JSON protocol targets.
- Core operations: `CreateSecret`, `DescribeSecret`, `GetSecretValue`, `PutSecretValue`, `UpdateSecret`, `DeleteSecret`, `RestoreSecret`, `ListSecrets`.
- Stable pagination for `ListSecrets`.
- Compatibility tests for status codes, error types, payload fields, and secret lifecycle state changes.
- Compatibility matrix similar to the KMS Phase A matrix.

Acceptance criteria:

- >=95 percent pass rate on the defined Secrets core compatibility suite.
- Stable `AWSCURRENT` reads for new and updated secrets.
- Delete and restore flows behave predictably with recovery-window rules.

Implemented:

- Secrets Manager JSON target routing in the main server.
- Core operations: `CreateSecret`, `DescribeSecret`, `GetSecretValue`, `PutSecretValue`, `UpdateSecret`, `DeleteSecret`, `RestoreSecret`, `ListSecrets`.
- Stable pagination for `ListSecrets`.
- Compatibility tests for secret lifecycle state changes, stage behavior, and admin rendering.

Completion status:

- Core secret CRUD and list flows are implemented and validated in `cmd/server/main_test.go`.
- `AWSCURRENT` reads and delete/restore behavior are covered by tests.
- A dedicated Secrets compatibility matrix document is not created yet; coverage currently lives in Go tests.

## Phase S2: Secret Versioning and Encryption Model (Completed for MVP)

Objective:

- Make versioned secret storage safe and compatible without compromising the KMS migration path.

Deliverables:

- Version-aware secret persistence with `VersionId` and `VersionStages`.
- `ListSecretVersionIds` support.
- Idempotent `ClientRequestToken` handling for repeated writes.
- Secret value encryption using KMS-backed or shared wrapped-key infrastructure.
- Migration-safe handling for future schema changes and re-encryption.

Acceptance criteria:

- Each write produces a durable version record with deterministic label movement.
- No plaintext secret payloads remain in durable storage after the write path is finalized.
- Repeated `PutSecretValue` requests with the same token do not create duplicate versions.

Implemented:

- Version-aware secret persistence with `VersionId`, `AWSCURRENT`, `AWSPREVIOUS`, and `AWSPENDING` stage tracking.
- `ListSecretVersionIds` support.
- Idempotent `ClientRequestToken` handling for repeated version writes.
- Secret payload encryption using KMS-backed ciphertext blobs instead of plaintext secret storage.

Completion status:

- Version writes and stage transitions are implemented for both DB-backed and in-memory modes.
- Secret payloads are stored encrypted in the current durable model.
- No broader re-encryption tooling or schema-migration orchestration exists yet.

## Phase S3: Policy, Tenancy, and Access Control (3-5 weeks)

Objective:

- Apply real authorization and tenant boundaries to secrets instead of relying on perimeter checks.

Deliverables:

- Secret resource policies and evaluation.
- Tenant-aware ownership and visibility model.
- Shared principal model with the KMS authZ layer where possible.
- Tag-aware authorization hooks for future ABAC-style behavior.
- Compatibility coverage for denied reads, denied writes, and cross-tenant rejection.

Acceptance criteria:

- Deny-by-default behavior is enforced for protected secrets.
- Cross-tenant secret access attempts are consistently rejected.
- Resource policy behavior matches the supported AWS compatibility scope.

Implemented so far:

- Secret resource policy storage and retrieval.
- Policy JSON validation endpoint support.
- Secret tag storage suitable for future filtering and authorization hooks.
- Resource policy enforcement on core secret read/write and management operations.
- Shared audit coverage that will support future denied-access analysis.

Remaining in phase:

- Tenant-aware ownership and visibility enforcement.
- Deny-by-default authorization behavior and cross-tenant rejection tests.
- Reuse of the future KMS principal and grants model once it exists.
- Authenticated principal mapping from API/UI requests into policy decisions.

## Phase S4: Rotation Workflows and Operational Automation (Partially implemented for MVP)

Objective:

- Introduce AWS-like rotation semantics without binding the service to Lambda-specific infrastructure.

Deliverables:

- Rotation metadata and scheduling model.
- `RotateSecret`, `CancelRotateSecret`, and `UpdateSecretVersionStage` support.
- Pluggable rotation executors such as HTTP webhook, job runner, or controller integration.
- Guardrails around `AWSPENDING`, `AWSCURRENT`, and rollback behavior.
- Failure and retry semantics for partial rotation runs.

Acceptance criteria:

- Rotation can advance a secret from pending to current without stage corruption.
- Failed rotation runs leave the current version readable and auditable.
- Operators can inspect the latest rotation outcome through API or UI.

Implemented so far:

- Rotation metadata fields and scheduling state.
- `RotateSecret`, `CancelRotateSecret`, and `UpdateSecretVersionStage` support.
- Stage movement logic for `AWSPENDING`, `AWSCURRENT`, and `AWSPREVIOUS`.
- UI visibility into rotation configuration and next rotation date.

Remaining in phase:

- Real rotation executor integration such as webhook, job, or controller-backed execution.
- Failure, retry, rollback, and last-outcome tracking for rotation runs.
- Clear operational distinction between scheduled-only rotation metadata and completed credential rotation.

## Phase S5: UI, Audit, and Production Readiness (Partially implemented for MVP)

Objective:

- Make the Secrets Manager surface operationally credible for day-to-day use.

Deliverables:

- UI pages for secret inventory, version history, tags, policy, and rotation state.
- Audit events for reads, writes, stage moves, deletion, restore, and rotation outcomes.
- Metrics and alerts for secret retrieval latency, auth failures, and rotation failures.
- Backup and restore guidance for secret metadata and encrypted payloads.
- Operator documentation for recovery windows, rollback, and rotation incident handling.

Acceptance criteria:

- All supported secret lifecycle tasks can be completed from API and UI.
- Audit records are complete enough to reconstruct secret version and stage history.
- Operational runbooks exist for rotation failure recovery and data restore.

Implemented so far:

- UI pages for secret inventory, retrieval, version history, tags, resource policy, and rotation configuration.
- API-level audit recording through the shared request audit path.
- Shared audit explorer coverage across Secrets Manager and KMS control-plane events.

Remaining in phase:

- Authenticated UI with RBAC and tenant scoping.
- Richer secret-specific audit event analysis.
- Metrics, alerts, backup guidance, restore runbooks, and rotation incident docs.
- UI support for binary-secret workflows and more advanced operator controls.

## Initial Success Metrics

- Core Secrets compatibility suite stays above 95 percent pass rate.
- Secret reads and writes remain backward compatible across schema migrations.
- Secret retrieval latency stays within defined service objectives under normal load.
- No stage-label divergence is observed in compatibility or concurrency tests.

## Current Status Snapshot

Done:

- Core Secrets Manager CRUD and list APIs.
- Version listing, stage transitions, and client-request-token idempotency.
- Secret tag storage plus resource policy get/put/validate endpoints.
- Rotation metadata, pending-version creation, and manual promote/cancel flows.
- AWS-style admin UI pages for overview, retrieve, versions, tags, policy, and rotation.
- Shared audit explorer coverage across Secrets Manager and KMS control-plane events.

Not done yet:

- Resource policy enforcement on data-plane requests.
- Tenant-aware authorization and deny-by-default behavior.
- External rotation executors and retry/rollback orchestration.
- Dedicated Secrets compatibility matrix document.
- Metrics, operational runbooks, backup/restore guidance, and production UI hardening.
- Authenticated UI, tenant scoping, and richer audit workflow UX.

## Open Design Decisions

- Whether the Secrets Manager protocol should live in the same binary and port as KMS or behind a separate listener.
- Whether per-secret encryption should use envelope data keys or direct encryption under a shared master key.
- Whether rotation executors should be embedded, webhook-driven, or delegated to Kubernetes-native jobs/controllers.
- How far to go on AWS parity for policy validation and replication semantics in the open-source baseline.