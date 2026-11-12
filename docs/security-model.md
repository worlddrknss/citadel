# Security model

This document describes what Citadel protects, against whom, and what it
relies on you to provide. Report vulnerabilities as described in
[SECURITY.md](../SECURITY.md).

## What Citadel protects

- **KMS key material** (symmetric keys, asymmetric private keys, every rotated
  version).
- **Secret and SecureString values**, encrypted under KMS keys.
- **CA private keys**, held as asymmetric KMS keys.
- **Credentials Citadel issues or stores:** access-key secrets, STS session
  secrets, ACME account keys, EAB keys, SSO client secrets, the audit-stream
  token.
- **The integrity of the audit log.**

## Trust boundaries

| Component | Trusted for |
|---|---|
| The Citadel process | Everything. It holds the wrapping key in memory. |
| The wrapping key (`KMS_WRAPPING_KEY_B64`) | Confidentiality of everything at rest. Provide it from a secret store; never store it with database backups. |
| PostgreSQL | Availability and durability only. A database dump without the wrapping key reveals metadata (names, ARNs, tags, audit events) but no key material or secret values. |
| The network | Nothing. Use TLS (at Citadel or a trusted proxy) everywhere outside localhost. |
| Reverse proxies | Only those listed in `KMS_TRUSTED_PROXIES` are believed about client IPs. |
| Clients | Nothing until authenticated. |

## Cryptography

Citadel uses only the Go standard library's cryptography. Release builds use
the Go Cryptographic Module (CMVP certificate #5247, `GOFIPS140=certified`)
and run with `GODEBUG=fips140=only`, so a non-approved algorithm fails instead
of running. CI runs the full test suite in that mode.

| Use | Algorithm |
|---|---|
| Wrapping key material and sealed values | AES-256-GCM, with the row ID as additional authenticated data so a ciphertext can't be moved to another row |
| Symmetric KMS keys | AES-256-GCM |
| Asymmetric KMS keys | RSA 2048/3072/4096 (PSS, PKCS#1 v1.5, OAEP-SHA-256), ECDSA P-256/P-384 |
| Derived keys | HKDF-SHA-256 from a deployment root secret |
| Console passwords | PBKDF2-HMAC-SHA-256, 600,000 iterations |
| Session tokens | 256-bit random; only a SHA-256 hash is stored |
| Audit chain | HMAC-SHA-256 |
| Request signing | AWS SigV4 (HMAC-SHA-256) |

## Authentication

- **AWS APIs:** every request needs a SigV4 signature that verifies against
  a console-issued access key, STS temporary credentials (whose session token
  must also match), or the configured static key. `X-Amz-Date` must be within
  15 minutes of server time, which bounds replay.
  `AssumeRoleWithWebIdentity` is unsigned by design: the OIDC token is the
  credential, checked against the provider's keys, audience and the role's
  trust policy.
- **Console:** username and password (rate limited per IP and per username,
  with lockout and identical responses for every failure), or an external OIDC
  provider with PKCE, state and nonce. Sessions are server-side, expire after
  an idle and an absolute timeout, and can be revoked. The cookie is
  `HttpOnly`, `SameSite=Strict`, `Secure`, and `__Host-` prefixed.
- **Native API tokens:** console access keys sent as bearer tokens act with
  their owner's role in the key's account, never more, and never with
  platform-admin rights.
- **First run:** with no users, a PostgreSQL-backed instance only accepts the
  bootstrap call, which needs a one-time token printed in the server log (or
  set with `KMS_BOOTSTRAP_TOKEN`).

## Authorization and tenancy

- Every resource belongs to an account, and every query is scoped to the
  caller's account. Requests for another account's resources behave as if the
  resource doesn't exist.
- Console roles per account: **viewer** (read; revealing secret values is off
  unless an admin enables it), **editor** (write), **admin** (manage the
  account). **Platform admins** manage accounts and organization-wide
  settings.
- KMS key policies and grants are evaluated for AWS API calls; an explicit
  Deny always wins.
- **Approvals:** environments can require N approvals. The requester can never
  approve their own change, the same person can't count twice, and approvals
  can't be made with an access key.

## Web console protections

- State-changing requests made with a session cookie need the
  `X-Citadel-Request` header and a same-origin `Origin`/`Referer`.
- Every response sets `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  no-referrer`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy`, and a
  Content Security Policy. The console's CSP allows only hashed inline
  scripts. HSTS is sent when Citadel terminates TLS, and API responses are
  `Cache-Control: no-store`.
- Revealed secret values hide themselves after 30 seconds, and copied values
  are cleared from the clipboard after 30 seconds where the browser allows it.

## Audit

Every action records the authenticated actor, account, resource, source IP,
user agent and result. Events form one HMAC chain per account; appends lock
the chain head, so concurrent requests and replicas can't fork it. Editing or
deleting events is detected by verification. If an audit write fails, Citadel
refuses to return the result of a state-changing action or a secret reveal.

## Outbound requests

Citadel makes outbound requests for OIDC discovery and keys, ACME HTTP-01
validation, Let's Encrypt, SIEM streaming and Kubernetes TokenReview. ACME
HTTP-01 validation refuses loopback, link-local, multicast and cloud metadata
addresses, checked after DNS resolution and on redirects, unless an account
explicitly allows a range. SIEM delivery refuses loopback, link-local and
multicast addresses and doesn't follow redirects.

## What you are responsible for

- TLS in front of, or in, Citadel.
- Keeping the wrapping key, audit key and bootstrap token in a secret store,
  and backing up the wrapping key separately from the database.
- Network policy: only clients and your ingress should reach Citadel, and
  Citadel only needs PostgreSQL, DNS and the outbound services above.
- Restricting database access to Citadel.
- Never running `KMS_INSECURE_DEV=true` outside your own machine.

## Known limitations

- Rate limits are per replica, not shared across replicas.
- Rotation for Secrets Manager secrets records the schedule but runs no
  rotation function; Citadel shows when rotation is due.
- A generated bootstrap token is valid only on the replica that printed it.
