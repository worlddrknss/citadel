# Security Policy

Citadel stores and uses encryption keys, secrets and certificate authorities.
We treat every security report as sensitive.

## Reporting a vulnerability

Please do not open a public issue, discussion or pull request for a suspected
vulnerability.

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/worlddrknss/citadel/security/advisories/new)
for this repository.

Helpful details:

- The affected component and version or commit.
- Steps to reproduce, or a proof of concept.
- The impact you see: what an attacker could read, change or disrupt.
- Configuration that affects exploitability (for example, whether
  `KMS_INSECURE_DEV` or a reverse proxy is involved).

We aim to acknowledge reports within three business days and to agree on a
disclosure timeline with you once we understand the issue. We credit
reporters in the advisory unless you ask us not to.

## Supported versions

Security fixes land on `main` and in the next release. We support the latest
release; older releases receive fixes only when stated in the advisory.

## Scope

In scope: the Citadel server, its AWS-compatible and native APIs, the web
console, the container image built from this repository, and the Go SDK in
`sdk/`.

Out of scope:

- Deployments running with `KMS_INSECURE_DEV=true`, which disables
  authentication by design.
- Findings that require an already-compromised host, database or wrapping key.
- Missing hardening on infrastructure you operate (TLS termination, network
  policy, database access).

## How Citadel is built to be secure

- **FIPS 140-3.** Release images are built with the Go Cryptographic Module
  (`GOFIPS140=certified`) and run with `GODEBUG=fips140=only`, so non-approved
  algorithms fail at runtime. CI runs the test suite in the same mode.
- **Authentication by default.** Every AWS-protocol request must carry a valid
  SigV4 signature within a 15-minute clock window, and the console requires a
  signed-in user. The server refuses to start without credentials configured.
- **Envelope encryption.** Key material and secrets are encrypted with a
  wrapping key that never leaves the process and is never stored with the
  data.
- **Tenant isolation.** Data is scoped to the caller's account in every query.
- **Tamper-evident audit log.** Audit events form an HMAC chain that can be
  verified from the console or API.

See [docs/security-model.md](docs/security-model.md) for the full threat model
and operator guidance.
