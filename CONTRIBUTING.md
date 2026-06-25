# Contributing to Citadel

Thanks for contributing to Citadel.

## Before you start

- Open an issue before starting large features or behavior changes.
- Keep pull requests focused on one concern.
- Include tests and documentation updates when behavior changes.
- Do not include secrets, credentials, or private infrastructure details in commits.

## Development setup

### Backend

Requirements:

- Go 1.25+

Run the server locally:

```bash
export KMS_MASTER_KEY_B64="$(openssl rand -base64 32)"
export KMS_KEY_ID="citadel-default-key"

go run ./cmd/server
```

If you want persistent storage, also set `KMS_DB_URL` as described in the README.

### Web UI

Requirements:

- Node.js with npm

Install web dependencies and run checks:

```bash
npm --prefix web install
npm --prefix web run check
```

When changing files under `web/`, rebuild the embedded UI assets before shipping a change:

```bash
./scripts/build-web.sh
```

## Validation

Run the narrowest checks that cover your change. Common checks are:

```bash
go test ./...
npm --prefix web run check
```

If your change affects embedded web assets, run:

```bash
./scripts/build-web.sh
go build ./...
```

## Change guidelines

- Preserve existing AWS-compatible API behavior unless the change intentionally documents a difference.
- Prefer small, direct fixes over broad refactors.
- Add or update tests near the behavior you changed.
- Update the README or docs when setup, API behavior, or operator workflow changes.

## Pull requests

Pull requests should include:

- A clear description of the problem and the approach taken.
- Notes about validation performed.
- Screenshots for user-visible UI changes when useful.

By contributing to this repository, you agree that your contributions are licensed under AGPL-3.0-or-later.
