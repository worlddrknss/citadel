# Contributing to Citadel

Thanks for helping improve Citadel. This guide covers how to set up a
development environment, the checks a change has to pass, and what we look
for in a pull request.

## Before you start

- Open an issue before starting a large feature or a behaviour change, so we
  can agree on the approach first.
- Keep pull requests focused on one concern.
- Never include secrets, credentials, real hostnames or private
  infrastructure details in commits, tests, screenshots or issues.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Development setup

You need:

- Go 1.27 or later
- Node.js 22 or later (only for the web console)
- Docker (optional, for the PostgreSQL tests and image builds)

### Run the server

The quickest way is in-memory storage with authentication turned off. This is
for local development only:

```bash
export KMS_INSECURE_DEV=true
export KMS_MASTER_KEY_B64="$(openssl rand -base64 32)"
go run ./cmd/server
```

Open http://localhost:8080/app/.

To develop against PostgreSQL, start a database and point Citadel at it:

```bash
docker run -d --name citadel-pg -p 5432:5432 \
  -e POSTGRES_PASSWORD=citadel-dev-password postgres:17
export KMS_DB_URL="postgres://postgres:citadel-dev-password@127.0.0.1:5432/postgres?sslmode=disable"
export KMS_WRAPPING_KEY_B64="$(openssl rand -base64 32)"
go run ./cmd/server
```

See [docs/configuration.md](docs/configuration.md) for every setting.

### Work on the web console

The console is a SvelteKit app in `web/`. Run it with hot reload against a
local server (it proxies `/v1` to `:8080`):

```bash
npm --prefix web ci
npm --prefix web run dev
```

The Go binary embeds the built console from `cmd/server/webdist`, which is not
committed. To build a binary that includes it:

```bash
./scripts/build-web.sh
go build ./cmd/server
```

Container images build the console themselves (see the `Dockerfile`).

## Checks

CI runs all of these on every pull request; run the ones that cover your
change before pushing.

```bash
gofmt -l .                       # must print nothing
go vet ./...
go test -race ./...

# Citadel runs in FIPS 140-3 mode in production. Tests must also pass with
# only approved algorithms enabled:
GOFIPS140=latest GODEBUG=fips140=only go test ./...

npm --prefix web run check       # svelte-check: 0 errors, 0 warnings
npm --prefix web run build
```

### PostgreSQL tests

Store tests against PostgreSQL run when `CITADEL_TEST_DB_URL` is set (each test
uses its own schema):

```bash
docker run -d --rm --name citadel-test-pg -p 55432:5432 \
  -e POSTGRES_PASSWORD=citadel-test-password postgres:17
CITADEL_TEST_DB_URL="postgres://postgres:citadel-test-password@localhost:55432/postgres?sslmode=disable" \
  go test ./internal/store/postgres/...
```

Use a database password of at least 14 characters: under FIPS mode the
PostgreSQL driver uses it as an HMAC key, and shorter keys are rejected.

## Cryptography rules

Citadel must stay FIPS 140-3 compliant. In code you contribute:

- Use only the Go standard library's crypto packages for cryptographic
  operations. Don't add third-party crypto libraries. The one use of
  `golang.org/x/crypto` is `x/crypto/acme` as the Let's Encrypt protocol
  client; it performs no cryptography of its own (signing goes through the
  standard library). Don't add other `x/crypto` packages.
- Use approved algorithms only: AES-GCM, SHA-2, HMAC with keys of at least
  112 bits, HKDF, PBKDF2, RSA (2048 bits or more) and ECDSA (P-256, P-384).
- No MD5 or SHA-1 for anything security-related, no
  `InsecureSkipVerify`, and randomness only from `crypto/rand`.

## Database changes

Schema changes are versioned SQL files in
`internal/store/postgres/migrations/` named `NNNN_description.sql`. Never edit
a migration that has shipped; add a new one. Migrations must be safe to run on
existing databases.

## Change guidelines

- Keep AWS-compatible API behaviour unless the change documents an intentional
  difference in [docs/aws-compatibility.md](docs/aws-compatibility.md).
- Every handler authenticates, scopes data to the caller's account, and
  records an audit event with the authenticated identity.
- Add or update tests next to the behaviour you changed.
- When you add or change a `/v1` route, update
  [docs/openapi.yaml](docs/openapi.yaml) (its header comment lists the YAML
  subset it must stay in) and run `npm run generate` in `sdk/typescript`.
  `internal/server/openapi_test.go` fails on routes, roles or audit actions
  that drift from the document, and on stale generated TypeScript types.
- Update the README or `docs/` when setup, configuration, API behaviour or
  operator workflows change.

## Pull requests

Include:

- What problem the change solves and the approach you took.
- How you validated it.
- Screenshots for visible console changes, in light and dark themes.
- A line for [CHANGELOG.md](CHANGELOG.md) under "Unreleased" for user-facing
  changes.

## Releases

Releases follow semantic versioning: a minor release for new features
(including new SDK methods), a patch release for fixes only. The Go and
TypeScript SDKs carry the release version too.

1. Open a release pull request (`release/X.Y.Z`) that:
   - moves the "Unreleased" entries in [CHANGELOG.md](CHANGELOG.md) under
     `## [X.Y.Z] - YYYY-MM-DD`;
   - sets `appVersion: "X.Y.Z"` and bumps `version` in
     [deploy/helm/citadel/Chart.yaml](deploy/helm/citadel/Chart.yaml);
   - sets the SDK versions to `X.Y.Z`: `Version` in
     [sdk/citadel/client.go](sdk/citadel/client.go), `VERSION` in
     [sdk/typescript/src/version.ts](sdk/typescript/src/version.ts), and
     `npm version X.Y.Z --no-git-tag-version` in `sdk/typescript` (updates
     `package.json` and `package-lock.json`). Skip this when they already
     match, for example when a feature pull request bumped them ahead of the
     release.
2. Check locally: `scripts/check-chart-version.sh vX.Y.Z` and
   `scripts/check-sdk-version.sh vX.Y.Z`.
3. Merge once CI is green, then tag the merge commit `vX.Y.Z` and push the
   tag. The release workflow
   ([.github/workflows/release-image.yaml](.github/workflows/release-image.yaml))
   runs both checks first and fails without building or pushing anything if
   the chart or an SDK version doesn't match the tag.

By contributing, you agree that your contributions are licensed under the
GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
