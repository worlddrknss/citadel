# Design: AWS-faithful Accounts, IAM Access Keys, Per-Account Isolation & Real SigV4

Status: **Planned — not yet built.** Captured 2026-06-21 for implementation.

This document is the build plan for making Citadel behave like real AWS for
identity and request signing:

1. Accounts have a **system-generated, immutable, unique 12-digit Account ID** plus a name.
2. Each **user belongs to exactly one account** (AWS IAM model).
3. Users are issued **programmatic credentials** (AWS Access Key ID + Secret Access Key),
   **max two at a time**, **rotatable** from a user dashboard.
4. **Per-account isolation** of resources (keys, secrets, etc.), as AWS does.
5. **Genuine SigV4 verification**: the server looks up the secret **by Access Key ID**,
   derives the **account** from the key, and authorizes accordingly. Then enable
   `KMS_SIGV4_STRICT=true`.
6. Wire **External Secrets Operator (ESO)** to Citadel via `auth.secretRef`, while
   **keeping `93rdavenue` and `varaperformance` on Vault** (untouched).

---

## 1. Does this follow the full AWS standard?

Yes — the design is faithful to AWS. Mapping:

| Requirement | AWS reality | Verdict |
|---|---|---|
| 12-digit, non-editable, system-generated Account ID per account | AWS account IDs are 12-digit, immutable, system-assigned | Correct |
| Account Name alongside the ID | AWS = account alias (friendly) + account ID (canonical) | Correct |
| Account ID used in ARNs | `arn:aws:<svc>:<region>:<account-id>:<resource>` | Correct |
| Programmatic keys = Access Key ID + Secret Access Key | IAM access keys are exactly this | Correct |
| Max two keys at a time | AWS hard limit is **2 access keys per IAM user** | Correct |
| Rotate via dashboard | AWS rotation = create 2nd → migrate → delete old | Correct |
| `KMS_SIGV4_STRICT=true` + per-key secret | genuine SigV4 verification | Correct |

### Three truths that make it "full standard"

1. **The secret must be stored server-side and looked up by Access Key ID.** A single
   `KMS_SECRET_ACCESS_KEY` env does **not** follow AWS. For SigV4 to authenticate each
   principal, the server takes `Credential=AKIA…/date/region/service` from the request,
   finds *that key's* secret, derives the signing key, and compares. Each Access Key ID
   needs its own stored secret.

2. **The SigV4 secret cannot be hash-only — it must be recoverable.** HMAC verification
   needs the *actual* secret bytes to recompute the signature, so it can't be
   Argon2-hashed like a login password. Store it **wrapped with the master/wrapping key**
   (reuse `wrapKeyMaterial`/`unwrapKeyMaterial`) and show the plaintext to the user
   **once** at creation. To the user this matches AWS (shown once, never retrievable);
   internally it is recoverable for verification.

3. **AWS ties a principal to exactly one account.** Today `ui_users.accounts_json` lets a
   user have many. Decision: **one account per user** (replace the list with a single
   `account_id`). An access key inherits its owner's account; that account ID is what goes
   into ARNs and scopes visibility.

---

## 2. Decisions (locked)

1. **User ↔ account:** one account per user (AWS-faithful). Replace
   `ui_users.accounts_json` with a single `account_id`.
2. **Isolation:** **full per-account isolation now** — add `account_id` to resource tables
   and scope every read/write by the caller's account.
3. **Rollout:** implement + unit/e2e test locally, then **deploy once green**
   (tag `v1.13.0` → CI image → Flux). Update infrastructure repo if needed.
4. **ESO:** wire via `auth.secretRef`; **do not disturb** the Vault-backed stores for
   `93rdavenue` and `varaperformance`.

---

## 3. Current state (as-is, with code references)

All paths are under `cmd/server/` unless noted.

### Deployment identity / "AWS Settings"
- Stored in `kms_settings` (`setting_key`, `setting_value`): keys `aws_region`,
  `aws_account_id`, `arn_identity_applied`.
- Env bootstrap: `KMS_AWS_REGION` (default `us-west-2`), `KMS_AWS_ACCOUNT_ID` (random
  12-digit if absent).
- Account ID is **global** today (single value for the whole deployment).
- Handler `masterAdminUpdateAWSSettings()` in `admin_master_ui.go` (~L411); saves via
  `putSetting()` in `deployment_identity.go` (~L143); then `migrateResourceARNs()` rewrites
  existing ARNs.

### ARN construction
- `arnFor(service, region, accountID, resource string)` in `arn.go` (~L43):
  `arn:aws:<service>:<region>:<account_id>:<resource>`; empty account → `placeholderAccountID` `000000000000`.
- Helpers: `keyARN(id)` → `arn:aws:kms:<region>:<account>:key/<keyid>` (~L96);
  `secretARNFor(name)` → `arn:aws:secretsmanager:<region>:<account>:secret:<name>` (~L106).
- PCA: `pca_certificate_authorities.urn` →
  `arn:aws:acm-pca:<region>:<account>:certificate-authority/<caId>`.
- Migration `migrateResourceARNs()` in `deployment_identity.go` (~L52) SQL-REPLACEs ARNs in
  `kms_keys.arn`, `sm_secrets.arn`, `pca_certificate_authorities.urn`.

### Account Creation
- Route `/admin/accounts` → `handleMasterAdminAccounts()` (`admin_master_ui.go` ~L49).
- Table `ui_accounts` (`account TEXT PRIMARY KEY`, `created_at`, `updated_at`). The **name
  is the identifier**; no numeric ID. Normalized by `normalizeAccountName()` in
  `admin_accounts.go`.
- Actions: `create_account`, `delete_account`, `assign_account`, `remove_account`
  (`masterAdmin*Account()` in `admin_master_ui.go` ~L318–L383). DB methods
  `UpsertUIAccount`/`DeleteUIAccount`/`ListUIAccounts`.

### Users / auth
- Table `ui_users` (`username PK`, `password_hash`, `role` viewer|editor|admin,
  `display_name`, `accounts_json` JSON array, timestamps).
- Structs `uiUserConfig` (`admin_auth.go` ~L19), `uiSession` (~L56, has `Accounts []string`).
- Pages `/admin/users` with `create_user`/`update_user`/`delete_user`.
- Sessions in-memory; cookie `go_kms_admin_session`; TTLs via
  `KMS_UI_SESSION_IDLE_TTL`/`KMS_UI_SESSION_MAX_TTL`.
- **No per-user programmatic credentials today.** Only global env `KMS_ACCESS_KEY_ID` /
  `KMS_SECRET_ACCESS_KEY` (`config` fields `requireAccessKey`, `expectedAccessKey`,
  `secretAccessKey` in `main.go` ~L46–48).

### SigV4 gate (`handleKMS`, `main.go` ~L1150)
```
if strictSigV4:
    validateSigV4Request(r)               # header presence/shape only
    if secretAccessKey != "":
        bodyHash = drainAndHashBody(r, 1<<20)
        verifyAWSV4Signature(r, bodyHash, secretAccessKey)   # single global secret
if requireAccessKey:
    hasAccessKey(authHeader, expectedAccessKey)   # substring "Credential=<id>/"
```
- `validateSigV4Request` (`main.go` ~L1985), `verifyAWSV4Signature` (`security.go` ~L204),
  `drainAndHashBody` (`security.go` ~L262), `parseAuthorizationHeader` (`security.go` ~L173),
  `hasAccessKey` (`main.go` ~L2909).
- **Today strict SigV4 is OFF** (`KMS_SIGV4_STRICT` defaults false) and only
  `KMS_ACCESS_KEY_ID` is set → the only check is the `hasAccessKey` substring match; the
  signature is never cryptographically verified (a fake `Signature=00` passes). This is why
  the curl test worked.

### Schema / migrations
- `ensureSchema()` in `main.go` (~L854); idempotent `CREATE TABLE IF NOT EXISTS` /
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (DO blocks for renames).
- Resource tables: `kms_keys`, `kms_aliases`, `kms_key_policies`, `kms_grants`,
  `kms_audit_events`, `sm_secrets`, `sm_secret_versions`, `sm_secret_tags`,
  `sm_secret_policies`, `sm_secret_version_stages`, `pca_certificate_authorities`,
  `pca_certificates`, `pca_ca_policies`, `pca_crl_state`, `acme_le_accounts`,
  `acme_le_certificates`, plus `ui_users`, `ui_accounts`, `kms_settings`.

### Admin UI
- Dispatcher `handleMasterAdminAction()` (`admin_master_ui.go` ~L152) switches on
  `?action=`; `renderMasterAdminSection()` (~L62) gated by `requireUISession(w, r, "admin")`.
- Templates embedded; master page `templates/admin_master.html`.

---

## 4. Target design

### 4.1 Accounts get a real identity
- `ui_accounts`: add `account_id CHAR(12) UNIQUE NOT NULL` (system-generated, immutable);
  keep `account` as the display name. Add unique constraint; backfill existing rows with a
  generated ID.
- Account-ID generator: 12 numeric digits, first digit non-zero, uniqueness-checked against
  `ui_accounts` (mirror the existing global generator in `deployment_identity.go`).
- **Account Creation UI**: show **Account Name** (editable on create) + **Account ID**
  (read-only, system-generated). No manual ID entry.
- **AWS Settings UI**: **remove** the editable Account ID field (keep **Region** — region is
  per-resource/selectable in AWS, not an identity). The global `aws_account_id` setting is
  superseded by per-account IDs.

### 4.2 Users can belong to multiple accounts (SaaS model)
- **Junction table** `user_accounts`:
  - `username TEXT NOT NULL` (FK to `ui_users.username`)
  - `account_id CHAR(12) NOT NULL` (FK to `ui_accounts.account_id`)
  - `role TEXT DEFAULT 'Viewer'` (e.g. Owner, Admin, Editor, Viewer—for future RBAC per account)
  - `created_at TIMESTAMPTZ`, `updated_at TIMESTAMPTZ`
  - Primary key: `(username, account_id)`
- `ui_users`: keep unchanged (username, password_hash, display_name, etc.); remove
  `accounts_json`. Users are global; accounts are the tenants.
- Migration: for each existing user with `accounts_json`, insert rows into `user_accounts`
  (one per account in the list); if a user has no accounts, assign a default/"root" account
  (create one during migration if needed).
- `uiSession`: add `AccountID string` (the account the user is logged into this session);
  keep `Username string`. Session is scoped to one account per login.
- **Login flow**: form now requires `AccountID`, `Username`, `Password`. Server validates
  that the user belongs to that account (check `user_accounts`), then auth the password.
  Session is tied to that specific account.
- **Account switching**: optional—user can log out and log back in to a different account,
  or a UI page to pick another account and re-auth (brief re-entry of password for security).
- **User Management UI** (admin): "Assign/Remove Account to User" actions on `/admin/accounts`
  now add/remove rows in `user_accounts` (can grant same user multiple accounts).

### 4.3 Programmatic credentials (IAM access keys)
- New table `iam_access_keys`:
  - `access_key_id TEXT PRIMARY KEY` (e.g. `AKIA` + 16 base32 chars),
  - `username TEXT NOT NULL` (owner),
  - `account_id CHAR(12) NOT NULL` (the account this key belongs to),
  - `secret_wrapped_b64 TEXT NOT NULL`, `secret_nonce_b64 TEXT NOT NULL` (wrap via
    `wrapKeyMaterial`, AAD = access_key_id),
  - `status TEXT NOT NULL DEFAULT 'Active'` (`Active`|`Inactive`),
  - `created_at TIMESTAMPTZ`, `last_used_at TIMESTAMPTZ NULL`.
  - Foreign keys: `(username, account_id)` → `user_accounts` for validation.
- Generation: `AKIA…` ID + **40-char** secret (base64-ish, AWS-style entropy).
- **Max two per (user, account)** enforced at create time (AWS limit). Creation returns the
  secret **once** (display + copy; never retrievable again).
- Store methods: `CreateAccessKey(username, account_id)`, `ListAccessKeys(username, account_id)`,
  `GetAccessKeyByID(id)` (returns wrapped secret + account + status), `SetAccessKeyStatus`,
  `DeleteAccessKey`, `TouchAccessKeyLastUsed`. In-memory stubs return `errUnsupported`.
- **User dashboard** (`/account/*`, scoped to logged-in session account):
  - **Profile**: display username, display name, logout.
  - **Access Keys**: list keys for this (user, account) pair—show ID, status, created, last
    used. Actions: create (≤2), deactivate, delete, rotate (create new → save locally → delete
    old → confirm).
  - **Password**: change password (current password required).
  - All actions scoped to the user's current session account.

### 4.4 Real SigV4 in `handleKMS`
- New auth path (replaces the global-secret branch):
  1. `validateSigV4Request(r)` for shape.
  2. Parse `Credential=` → access key id, date, region, service, scope
     (`parseAuthorizationHeader`).
  3. `GetAccessKeyByID(id)`; reject if missing/`Inactive`
     (`UnrecognizedClientException` / `InvalidClientTokenId`).
  4. Unwrap secret; `bodyHash = drainAndHashBody`; `verifyAWSV4Signature(r, bodyHash, secret)`.
  5. On success, set the **caller account** = key's `account_id` in the request context;
     `TouchAccessKeyLastUsed`.
- Keep `KMS_ACCESS_KEY_ID`/`KMS_SECRET_ACCESS_KEY` env as an **optional bootstrap/root**
  credential (so the cluster can talk to a fresh DB before any user key exists) — but the
  primary path is DB-backed per-key lookup.
- Flip `KMS_SIGV4_STRICT=true` in the deployment once verification is DB-backed.

### 4.5 Per-account isolation
- Add `account_id CHAR(12)` to resource tables: `kms_keys`, `kms_aliases`,
  `sm_secrets` (+ versions/tags/policies/stages via their parent), `pca_certificate_authorities`
  (already has an `account` field — reconcile to `account_id`), `pca_certificates`,
  `acme_le_*` as appropriate.
- Stamp `account_id` from the **caller context** on every create.
- Scope every read/list/update/delete by the caller's `account_id` (WHERE clauses). Cross-
  account access returns NotFound/AccessDenied (AWS behavior).
- ARNs use the **caller's** account id (`arnFor(svc, region, callerAccountID, resource)`),
  not the global setting.
- Migration: backfill existing resources with a default/root account id; rewrite existing
  ARNs from the old global account to the per-resource account (extend
  `migrateResourceARNs` or add a one-off).

### 4.6 ESO integration (infrastructure repo)
- ESO **v0.20.4** AWS provider has **no per-SecretStore endpoint field** (confirmed: provider
  schema has only `additionalRoles, auth, externalID, prefix, region, role, secretsManager,
  service, sessionTags, transitiveTagKeys`). A custom endpoint is set via the **controller
  env** `AWS_SECRETSMANAGER_ENDPOINT` (affects all AWS stores on that controller).
- Options to avoid disturbing the Vault-backed apps:
  - **Preferred:** run a **separate ESO controller instance** (own Helm release /
    `controllerClass`) with `AWS_SECRETSMANAGER_ENDPOINT` pointing at
    `http://citadel.infrastructure.svc.cluster.local:8080`, used only by Citadel-backed stores.
    The existing controller keeps serving the Vault `SecretStore`s unchanged.
  - **Alternative:** set the endpoint on the existing controller (only safe if **no** AWS
    provider stores rely on real AWS — today only Vault stores exist, so technically safe,
    but it globally reroutes any future AWS store). Prefer the separate-instance approach for
    clarity and blast-radius.
- Create a test namespace + `SecretStore` (AWS provider, `service: SecretsManager`,
  `region: us-west-2`, `auth.secretRef` → a k8s secret holding the Citadel Access Key ID +
  Secret) + an `ExternalSecret` pulling `eso-kms-test/demo`. Verify the synced k8s secret
  matches what Citadel returned.
- **Leave** `93rdavenue` and `varaperformance` `SecretStore`/`ExternalSecret` (Vault)
  exactly as-is.

---

## 5. Build order (phased, each phase green before next)

1. **Account identity**: schema (`account_id` on `ui_accounts`, keep `account` as display
   name), generator, store methods for account CRUD. Unit tests.
2. **User ↔ account mapping**: add `user_accounts` junction table, store methods, migration
   (backfill existing users to accounts from `accounts_json`). Update in-memory store.
   Unit tests.
3. **Login flow**: update login form (AccountID, Username, Password) and auth logic to check
   `user_accounts`. Update session to include AccountID. Basic login test.
4. **User Management UI**: update `/admin/accounts` to show assign/remove account to user
   (managing `user_accounts` rows), `/admin/users` to show which accounts each user belongs to.
5. **IAM access keys**: `iam_access_keys` table + store methods (wrap/unwrap, max-2-per-account),
   FK validation. Unit tests.
6. **User dashboard** (`/account/*`): profile, access keys (list/create/rotate/delete),
   password change. All scoped to session account. Integration test.
7. **Real SigV4**: DB-backed verification in `handleKMS`, caller-account context, last-used
   touch, keep env bootstrap. Unit + integration tests.
8. **Per-account isolation**: `account_id` on resource tables, stamp-on-create, scope all
   queries, ARNs from caller account, migration/backfill. Tests for cross-account isolation.
9. **Verification gate**: `gofmt -l`, `go vet ./...`, `go vet -tags acme_integration ./cmd/server/`,
   `go build ./...`, `go test ./cmd/server/`, plus the Pebble/e2e tag if touched.
10. **Release**: tag `v1.13.0` → CI image → Flux bump → reconcile; set
    `KMS_SIGV4_STRICT=true` (+ optional bootstrap key) in `citadel/deployment.yaml`.
11. **ESO**: add the separate ESO controller (or endpoint) + test namespace store/ExternalSecret
    in the infrastructure repo; reconcile; verify sync. Keep Vault stores untouched.

---

## 6. Risks / notes

- **Migration safety**: all schema changes idempotent (`IF NOT EXISTS`, DO blocks). Backfill
  existing users/resources to a generated **default/root account** so nothing is orphaned.
  Test migration against a copy of prod data shape before deploy.
- **Secret recoverability**: access-key secrets are wrapped (recoverable), unlike login
  passwords (hashed). This is required for HMAC and matches AWS UX (shown once).
- **Bootstrap chicken-and-egg**: keep an env-based bootstrap/root credential so the platform
  can authenticate before any DB-stored user key exists (e.g. for the cluster's own calls).
- **ESO blast radius**: prefer a dedicated ESO controller for the Citadel endpoint so the
  shared Vault stores for `93rdavenue`/`varaperformance` are never rerouted.
- **Strict SigV4 flip is a hard cutover**: once `KMS_SIGV4_STRICT=true`, every caller must
  send a correctly-signed request with a known, Active key. Ensure the cluster's own
  bootstrap credential is in place first to avoid lockout.
- **`v1.13.0` tag triggers CI + Flux deploy to shared infra** — only tag once all phases are
  green and reviewed.

---

## 7. Quick reference — current verified facts

- Citadel SecretsManager API works (proven via `kubectl port-forward svc/citadel 18080:8080`
  then curl `secretsmanager.CreateSecret` / `secretsmanager.GetSecretValue`; seeded
  `eso-kms-test/demo`). Returns correct AWS-shaped JSON (ARN, VersionId, `AWSCURRENT`).
- Citadel `KMS_ACCESS_KEY_ID` is present (5 chars, likely `vault`); `KMS_SECRET_ACCESS_KEY`
  and `KMS_SIGV4_STRICT` are **not set** → SigV4 not verified today.
- Deployment: `ghcr.io/worlddrknss/citadel:1.12.0`, namespace `infrastructure`, Service
  `citadel:8080`, config secret `citadel-config`.
- ESO: Helm release `external-secrets` v0.20.4, `external-secrets.io/v1` API.
