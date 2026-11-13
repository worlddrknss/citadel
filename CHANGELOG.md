# Changelog

All notable changes to Citadel are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.1.0]

### Added

- **Built-in secret rotation.** Rotation schedules now rotate: Citadel runs
  AWS's four rotation steps (createSecret, setSecret, testSecret,
  finishSecret, with `AWSPENDING`/`AWSCURRENT`/`AWSPREVIOUS`) with built-in
  rotators: `random` (a new password, or one field of a JSON secret),
  `postgresql` (a database user's password, single-user or alternating-users
  as in AWS's templates, over TLS by default) and `webhook` (each step POSTed
  to an https endpoint, HMAC-SHA256 signed with a timestamp, with SSRF
  protections). `RotateSecret` selects one with
  `RotationLambdaARN = arn:citadel:rotator:<region>:<account>:<type>[/<config-id>]`
  and now accepts `ScheduleExpression` (`rate()`, `cron()`) and `Duration`.
  A job on every replica runs due rotations under a lease, retries failures
  with backoff while keeping `AWSPENDING`, records history and audits every
  step. New native routes: `GET /v1/secrets/rotation`,
  `POST /v1/secrets/rotation/rotate` and
  `POST /v1/secrets/rotation/signing-secret`; `POST /v1/secrets/rotation`
  configures rotators. The secret drawer has a **Rotation** tab, and the
  secrets table flags due and failed rotations. See
  [docs/rotation.md](docs/rotation.md). Migration 1200 adds two new tables.

- An OpenAPI 3.1 description of the native `/v1` API,
  [`docs/openapi.yaml`](docs/openapi.yaml), covering all 151 operations with
  their parameters, request and response schemas, the `{error, message}` error
  shape, authentication (session cookie with `X-Citadel-Request`, or a bearer
  access key), the role each operation needs (`x-citadel-role`) and the audit
  action it records (`x-citadel-audit`). It is served unauthenticated at
  `GET /v1/openapi.yaml`, also in bootstrap mode, since it holds no data. A
  test fails if the document and the registered routes drift apart, if a role
  or audit action disagrees with its handler, or if the TypeScript SDK's
  generated types are stale.
- An **API reference** page in the console (Help menu and command palette)
  that renders the spec: operations grouped by tag, with expandable schemas
  and a filter. It is built in, with no third-party bundle.
- The Go SDK (`sdk/citadel`), rebuilt against the spec: projects,
  environments, folders, secrets (with versions), parameters, KMS
  encrypt/decrypt and keys, certificates and workload identity tokens, with
  configuration from the environment, per-attempt timeouts, retries on 429
  and 5xx with jittered backoff honouring `Retry-After`, and typed errors that
  expose the API error code. Its tests run against the real server.
- A TypeScript SDK, `@worlddrknss/citadel` (`sdk/typescript`), for Node 18+
  and edge runtimes with no runtime dependencies: types generated from the
  spec, an ergonomic client, retries and timeouts, typed errors, a server-only
  guard, and `loadSecrets()` for Next.js (TTL cache with
  stale-while-revalidate, `revalidate`, optional `process.env` injection).
  CI builds and tests it in a new `sdk-ts` job.
- The in-memory store supports access keys, so bearer-token authentication
  works against it in local development and tests.
- Two-step verification (TOTP, RFC 6238) for console password sign-in.
  Users set it up under My account → Security: the browser draws the QR code
  locally, a code confirms it, and ten single-use recovery codes are shown
  once (copy or download). Sign-in then asks for a 6-digit code (or a
  recovery code) after the password: `POST /v1/login` returns
  `{mfaRequired, mfaToken}` and `POST /v1/login/mfa` creates the session.
  Codes are single-use per 30-second step, attempts are rate limited per
  user and per IP (deployment-wide with PostgreSQL) with lockout, and
  turning it off or creating new recovery codes needs the password and a
  code. Codes use HMAC-SHA-256 (`algorithm=SHA256`), because FIPS 140-only
  mode refuses SHA-1: the authenticator app must support SHA-256 (1Password,
  Authy and Microsoft Authenticator do).
- Organization setting **Require two-step verification** (`requireMFA` in
  `/v1/admin/settings`): password sign-ins without MFA get a session that can
  only enrol. Single sign-on and access keys are exempt.
- Admins can reset a user's two-step verification from Administration →
  People (type the username to confirm); the user is signed out everywhere.
  The users list shows who has it on (`mfaEnabled`).
- Audit events `citadel.MFAEnrollStart`, `citadel.MFAEnroll`,
  `citadel.MFADisable`, `citadel.MFAReset`, `citadel.MFARecoveryCodesRegenerate`,
  `citadel.LoginMFA` (success and failure) and `citadel.MFARecoveryCodeUsed`.
- Migration `1000_console_mfa` (new tables and one constant-default column;
  instant on large databases).
- Secrets Manager `DeleteResourcePolicy`, and `SortOrder` (`asc`/`desc`, by
  name) on `ListSecrets`. `SortBy` other than `name` is rejected.
- SSM `UnlabelParameterVersion` on the AWS API.
- ACM `RequestCertificate` honours `IdempotencyToken`: the same token and
  parameters within an hour return the same certificate ARN (stored per
  account, migration 1110). `ImportCertificate` accepts one as a Citadel
  extension.
- ACM PCA subordinate CAs over the AWS API, following AWS's flow:
  `CreateCertificateAuthority` with `SUBORDINATE` creates a CA in
  `PENDING_CERTIFICATE`, `GetCertificateAuthorityCsr` returns its CSR,
  `IssueCertificate` on the parent with a `SubordinateCACertificate_PathLenN/V1`
  template signs it, and `ImportCertificateAuthorityCertificate` activates it.
- Certificates imported through ACM `ImportCertificate` appear in the console
  certificates list and drawer (source `acm-imported`). They are read-only
  (no renew or revoke); admins can delete them, also through the new
  `DELETE /v1/certificates/acm?arn=...` (audited as
  `citadel.DeleteImportedCertificate`).
- `GET /v1/certificates/detail` returns `chain`: every certificate from this
  one to the root (leaf, intermediates, root), each with subject, issuer,
  serial, validity and PEM. The chain is built from the stored issuer chain
  and the account's CAs, and stops where Citadel doesn't hold the next
  issuer. The drawer's Chain tab lists each certificate with a PEM download.

### Changed

- Turning on two-step verification signs the user out of their other
  sessions.
- `RotateSecret` with a Lambda ARN (or none) and `RotateImmediately` no longer
  creates an `AWSPENDING` copy of the current value, and `CancelRotateSecret`
  no longer removes `AWSPENDING` (both now match AWS).

### Security

- `npm audit` in `web/` still reports four low-severity findings for
  GHSA-gcqx-w48m-w2h4 (deepmerge, via `@sveltejs/vite-plugin-svelte`). No
  patched deepmerge exists (4.3.1 is the latest and is affected), so no
  override is possible; the plugin uses it only to merge Svelte config at
  build time.
||||||| parent of 78292cb (docs: two-step verification (TOTP), requireMFA, MFA rate limits; changelog)

## [2.0.3]

### Added

- Images are published for `linux/arm64` as well as `linux/amd64`, built by
  cross-compiling (both are FIPS builds).
- Console dependencies on SvelteKit 3, Vite 8 and vitest 4 (TypeScript stays
  on 6 until SvelteKit supports 7).
- Certificate authorities in `GET /v1/certificates` and
  `GET /v1/certificates/detail` carry `isCA` and `pathLen` (the
  basic-constraints path length; absent when unlimited). The CA tree shows it
  for each CA and the CA drawer explains it.
- A **Full re-check** button on the audit log for platform admins, which
  re-walks the whole chain (`POST /v1/audit/verify?full=true`) and shows the
  result. Other users don't see it.

### Changed

- `POST /v1/audit/verify?full=true` needs a platform admin (it was any
  account admin): a full walk reads every event of the account.

### Fixed

- Let's Encrypt orders can take up to about 3 minutes, but the request (and
  the console) gave up after 30 seconds. Issuance is now asynchronous:
  `POST /v1/certificates/letsencrypt/request` and
  `POST /v1/certificates/letsencrypt/dns/complete` start the work and answer
  `202` with an `orderId`; a background task bounded by a 3-minute timeout
  (and cancelled on shutdown) completes it, and the new
  `GET /v1/certificates/letsencrypt/orders?id=` reports its status, current
  step, error and certificate. The console shows progress while it polls,
  shows failures, and keeps the DNS-01 records up for a retry. Starting a
  DNS-01 order is bounded at 20 seconds. Order rows gain progress columns
  (migration 0904); existing DNS-01 orders keep working.
- Rate limits on sign-in, first-run setup, SSO and the workload token
  endpoint were per replica, so each added replica multiplied them. With
  PostgreSQL they are now also enforced deployment-wide through shared
  fixed-window counters (one UPSERT per request, per-key rows, an `UNLOGGED`
  table purged by a job, failing open if the database is unavailable). The
  memory store keeps the in-memory limits. See "Rate limits" in
  docs/configuration.md.
- A generated bootstrap token (no `KMS_BOOTSTRAP_TOKEN`) worked only on the
  replica that printed it. The first replica to start now stores its SHA-256
  in the database and logs the token; the others log that one was already
  issued and where to find it. Any replica accepts it, the bootstrap
  transaction consumes it (once, atomically), and an unused token expires
  after 24 hours, after which the next replica to start issues a new one.
- Audit chains upgraded from 1.x showed as "broken" at the first pre-2.0
  event whose `prev_hash` didn't connect, which 1.x's unlocked appends
  produced under concurrent requests. Such links between pre-2.0 (hash
  version 1) events are now counted (`legacyLinkBreaks`,
  `firstLegacyBreakSeq`, `legacyEvents` in `GET`/`POST /v1/audit/verify`) and
  verification continues; the chain is "verified" when everything else
  holds, and the audit page and overview show an amber note with the count.
  2.0 events, the link from the last pre-2.0 event to the first 2.0 one, and
  sequence gaps stay strict. The next verification after upgrading walks the
  chain from the start (migration 0901).
- Parameter names follow AWS's rules when a parameter is created or
  overwritten (SSM `PutParameter` and `POST /v1/parameters`): names beginning
  with `aws` or `ssm` in any case (the first level of a hierarchy) are refused,
  a name's full ARN can be at most 1011 characters, and a hierarchy at most 15
  levels (SSM answers `HierarchyLevelLimitExceededException`). Names longer
  than 2048 characters are refused by every operation. The console checks the
  same rules with the same messages before submitting.
- Workload identity client names are unique per account, ignoring case
  (enforced by a database index). Creating or renaming a client onto a taken
  name answers 409 `name_taken`, and the console shows it on the name field.
  Upgrading renames existing duplicates other than the oldest by appending
  `-` and the end of their client ID; client IDs don't change.
- The Helm chart's `appVersion` (the default image tag) was still 2.0.0; it
  is now 2.0.2. The release workflow fails before building an image when
  `Chart.yaml` `appVersion` doesn't match the tag being released
  (`scripts/check-chart-version.sh`).

## [2.0.2]

### Changed

- Larger type throughout the console: body text is 14px (was 13px), and the
  rest of the scale moved up one step.
- Secret KMS pickers no longer list the account's managed default key next to
  "Account default (alias/default)"; they were the same key.

### Fixed

- Users upgraded from 1.x whose account list held account names instead of
  IDs saw a phantom account without an ID. Names now resolve to the account's
  ID and unknown entries are ignored.

## [2.0.1]

### Fixed

- Upgrading with a 1.x replica still serving (a rolling update) left audit
  events without an account or chain position, and the 2.0 server then failed
  to start ("null value in column chain_seq of relation audit_chain_heads")
  while holding a lock that stalled the old replica's audit writes. Startup
  now numbers and attributes such rows and advances the chain heads, so it
  succeeds and stays idempotent.

## [2.0.0]

### Breaking changes

- **Authentication is always on.** Every AWS-protocol request (KMS, Secrets
  Manager, SSM, ACM, ACM PCA, STS) must carry a valid SigV4 signature, on `/`
  and `/api` alike. `KMS_SIGV4_STRICT` is no longer read.
- **No implicit local admin.** The console API no longer hands every caller an
  admin session when no users are configured. The server refuses to start
  without console users (or, with PostgreSQL, offers a one-time bootstrap) and
  without a source of AWS credentials to verify signatures against.
- `KMS_INSECURE_DEV=true` is the single switch that turns authentication off,
  for local development only.
- `KMS_ACCESS_KEY_ID` and `KMS_SECRET_ACCESS_KEY` must be set together, and the
  secret must be at least 20 characters (FIPS 140-3 forbids shorter HMAC keys).
- Console session cookies are `Secure` by default. Set
  `KMS_UI_SECURE_COOKIES=false` only when serving the console over plain HTTP
  outside insecure dev mode.
- Console API bearer tokens act with their owner's role instead of admin, and
  STS temporary credentials are no longer accepted as console tokens.
- The built web console is no longer committed. Container images build it;
  for a local binary run `scripts/build-web.sh` before `go build`.

### Added

- Redesigned web console: light and dark themes, a responsive layout, a
  command palette, approvals inbox, workload identity, and audit verification
  and export.
- RFC 8555 ACME server with External Account Binding per account.
- Console sign-in through external OIDC providers.
- Workload identity: Citadel issues OIDC tokens to CI jobs, pods and services,
  signed by its KMS keys.
- Versioned database migrations with an advisory lock, safe for several
  replicas starting at once.
- CI on pull requests (tests in FIPS-only mode, race detector, govulncheck,
  type checks, image build), CodeQL, Dependabot, and signed release images with
  SBOM and provenance.

### Fixed

- Replayed requests: `X-Amz-Date` must be within 15 minutes of server time.
- STS temporary credentials now require their session token.
- Secret reads failed on fresh PostgreSQL databases because the
  `rotation_enabled` column was never created.
- The overview chart put audit events in the wrong day outside UTC.

### Security

- `AssumeRoleWithWebIdentity` fetched OIDC discovery for the issuer named in
  an unverified token before checking it against the role's provider, letting
  unauthenticated callers make Citadel send requests to arbitrary URLs. The
  provider is now checked first.
- Closed cross-tenant access: CAs and certificates, KMS aliases, grants and
  key policies, parameters, audit events, and secret names were not fully
  scoped to the caller's account.
- Approvals can't be self-approved, double-counted, or made with access keys.
- Release images are built with `GOFIPS140=certified`, as the Dockerfile
  already claimed but did not do.

### Upgrading from 1.x

- Take a database backup first. 1.x can read a 2.0 database but can't write
  secrets to it, so a full rollback means restoring the backup.
- Admins that exist at upgrade time become platform admins.
- Existing secrets keep their accounts; External Secrets Operator keeps
  working unchanged.
- If the console is served over plain HTTP, set `KMS_UI_SECURE_COOKIES=false`.
- Remove `KMS_SIGV4_STRICT`, and point readiness probes at `/readyz`.
