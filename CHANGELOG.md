# Changelog

All notable changes to Citadel are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

- Release images are built with `GOFIPS140=certified`, as the Dockerfile
  already claimed but did not do.
