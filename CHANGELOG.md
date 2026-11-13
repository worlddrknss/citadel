# Changelog

All notable changes to Citadel are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Images are published for `linux/arm64` as well as `linux/amd64`, built by
  cross-compiling (both are FIPS builds).

### Fixed

- Parameter names follow AWS's rules when a parameter is created or
  overwritten (SSM `PutParameter` and `POST /v1/parameters`): names beginning
  with `aws` or `ssm` in any case (the first level of a hierarchy) are refused,
  a name's full ARN can be at most 1011 characters, and a hierarchy at most 15
  levels (SSM answers `HierarchyLevelLimitExceededException`). Names longer
  than 2048 characters are refused by every operation. The console checks the
  same rules with the same messages before submitting.
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
