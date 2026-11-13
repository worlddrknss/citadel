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
| Console MFA (TOTP) | RFC 6238 with HMAC-SHA-256 (see below); 160-bit secrets sealed with AES-256-GCM under an HKDF-derived key, bound to the username |
| MFA recovery codes | 60 random bits each; stored as PBKDF2-HMAC-SHA-256 hashes (20,000 iterations) |
| MFA pending-login tokens | HMAC-SHA-256 signed, 5-minute, single-use |
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
- **Two-step verification (TOTP):** users can add an authenticator app (My
  account → Security). A correct password then returns only a pending-login
  token, with no session; `POST /v1/login/mfa` with the token and a 6-digit
  code (or a single-use recovery code) creates the session. Codes are
  accepted for the current 30-second step and one either side, and each step
  works once: the last accepted step is stored per user. Attempts are rate
  limited per user and per client address (shared across replicas with
  PostgreSQL) and repeated failures lock the user out with exponential
  backoff. Turning it off or creating new recovery codes needs the current
  password and a code. The organization setting **requireMFA** sends
  password sign-ins without MFA to a restricted session that can only enrol.
  Single sign-on is exempt (the identity provider handles MFA), and access
  keys are unaffected. An admin can reset a user's MFA (lost device), which
  signs the user out everywhere.

  The codes use HMAC-SHA-256, not the HMAC-SHA-1 most authenticator apps
  default to: Go's FIPS module refuses SHA-1 HMAC in `fips140=only` mode
  (Citadel tests this). The enrolment QR code carries `algorithm=SHA256`, so
  the app must support SHA-256; 1Password, Authy and Microsoft Authenticator
  do. The QR code is drawn in the browser; the secret never leaves the page
  or reaches a third party, and is never returned again after enrolment.
- **Native API tokens:** console access keys sent as bearer tokens act with
  their owner's role in the key's account, never more, and never with
  platform-admin rights.
- **AI agents:** agents authenticate only to the Agent API (`/v1/agent/...`),
  with an agent token (`cagt_...`, 256 random bits, stored as a PBKDF2 hash,
  optional expiry, revocable) or a workload identity token that exactly
  matches one of the agent's federation bindings (Citadel's own issuer, which
  must name the agent's account, or an IAM OIDC provider registered in that
  account). Agent tokens are not accepted anywhere else, and console sessions
  and access keys are not accepted by the Agent API. Every request re-reads
  the token and agent, so revocation, suspension and the account kill switch
  take effect immediately. Failed attempts are throttled per client address;
  requests per agent are limited locally and across replicas. Secret values
  are never returned by the endpoints in 2.2's first part, and tokens never
  appear in logs, audit events or errors. See [agents.md](agents.md).
- **First run:** with no users, a PostgreSQL-backed instance only accepts the
  bootstrap call, which needs a one-time token: `KMS_BOOTSTRAP_TOKEN`, or one
  the first replica generates and prints in its log. Only the generated
  token's SHA-256 is stored, it expires after 24 hours unused, and the
  bootstrap transaction consumes it, so it works once across all replicas.

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
deleting events is detected by verification.

### No unaudited changes (write-ahead audit)

No state change takes effect without an audit record. Before 2.1, the audit
event was written after the change: if that write failed the response became
a 500, but the change was already committed. Since 2.1:

1. **Attempt.** Before a state-changing operation runs, Citadel appends an
   *attempt* event: the action, actor, account, resource, source, result
   `pending` and a new `correlationId`. If that append fails, the request is
   refused (HTTP 500, `audit_unavailable` / `InternalFailure`, "nothing was
   changed") before anything is touched.
2. **Outcome.** The handler then records its outcome (`success`, `denied` or
   `error`) as before, stamped with the same `correlationId`. A request that
   records nothing of its own (a validation error, for example) gets an
   outcome derived from its HTTP status (`HTTP400`, `AccessDenied`...).
3. **Outcome retry.** If the outcome append fails, the change is already
   covered by its attempt, so the response stands. The outcome goes to an
   in-process retry queue (bounded at 50,000 events), flushed in order every
   10 seconds by the `audit-outcome-retry` job and once more at shutdown.
   Every failure is logged (`AUDIT WRITE FAILED ... outcome queued`), and
   `citadel_audit_outcome_queue_depth` exposes the backlog on the metrics
   listener; alert when it stays above zero.

An attempt with no outcome means the outcome is unknown: the process stopped
between the two appends, or a queued outcome was lost at shutdown. Treat such
an action as possibly performed. Filter for them with `result=pending` and
look up an attempt's outcome with `GET /v1/audit/events?correlation=<id>`.

Where the attempt is written, per path:

| Path | Attempt written | Action name on the attempt |
|---|---|---|
| AWS JSON APIs (KMS, Secrets Manager, SSM, ACM, ACM PCA) | after SigV4 verification, before dispatch | the `X-Amz-Target`, e.g. `TrentService.CreateKey` |
| Native `/v1` API (console, bearer tokens) | when the session is resolved, for POST/PUT/PATCH/DELETE | the route, e.g. `POST /v1/secrets`; the outcome carries the handler's action name |
| STS `AssumeRole`, `AssumeRoleWithWebIdentity` | after the trust check, before credentials are minted | `sts.AssumeRole...` |
| Console login (password and two-step verification), SSO login, bootstrap, logout | after credentials are verified, before the session or account is created (or deleted) | `citadel.Login`, ... |
| ACME server | before issuing, revoking, or binding an EAB key | `citadel.ACME...` |
| Background jobs | per key for KMS rotation and deletion, per secret for scheduled secret rotation (a rotation started by a request is covered by that request's attempt), per CA for the CA purge, per certificate for Let's Encrypt auto-renewal; before the workload signing-key rotation and the re-wrap; for the secrets purge (per account) and certificate expiry sweeps only when there is work, so idle runs write nothing | the job's action |

The resource on an attempt comes from the query string, else from the
identifying field of a JSON body (`SecretId`, `KeyId`, `name`, `arn`...).
Value fields are never used.

**What doesn't get an attempt.** Reads and operations that change nothing:
metadata reads (`List*`, `Describe*`, most `Get*`) fail open as before.
Cryptographic operations and secret disclosures (`Encrypt`, `Decrypt`,
`Sign`, `GenerateDataKey*`, `GetSecretValue`, `GetParameter*`,
`ExportCertificate`, the native encrypt/decrypt/sign/verify and reveal
routes) stay fail-closed after the fact: when their event can't be written,
the response, and so the result, is withheld. Nothing was changed, so no
attempt is needed. Audit verification and connection tests write no attempt
either.

**Why not the same transaction?** Writing the event inside each operation's
own database transaction was evaluated and not adopted. An audit append
locks the account's chain head, so folding it into domain transactions would
hold that lock for the whole operation, including key generation, and
serialize every write in the account. Many operations also span several
store calls, and the in-memory backend has no transactions at all. The
write-ahead pattern costs one extra append per state-changing request and
gives the same guarantee on every path.

**Upgrades.** The attempt link is a `correlation_id` column (migration 1100,
a catalog-only `ADD COLUMN` with a constant default, plus a small partial
index). The chain MAC covers it only when set, so every earlier event keeps
its MAC. During a rolling upgrade, a 2.0 replica that verifies the chain
reports events written by 2.1 replicas with a correlation ID as having a bad
MAC. Run verification only once all replicas run 2.1.

Verification (`POST /v1/audit/verify`) continues from the last verified
event; a platform admin can re-walk the whole chain with `?full=true` (the
console's **Full re-check**).

**Pre-2.0 history.** Citadel 1.x appended events by reading the last row and
then inserting, without a lock, so two concurrent requests could both link to
the same predecessor. Those events (hash version 1) carry no MAC, and a chain
upgraded from 1.x can contain `prev_hash` links that don't connect, typically
between events written within milliseconds of each other. Verification counts
these as `legacyLinkBreaks` (with `firstLegacyBreakSeq`/`firstLegacyBreakId`
and `legacyEvents`), continues from the event's own hash, and still reports the
chain as `verified`; the console shows an amber note with the count. Every
other check stays strict and makes the chain `broken`:

- any 2.0 event with a wrong MAC, a link that doesn't connect, or the wrong
  account;
- the first 2.0 event not linking to the last pre-2.0 event (the boundary);
- a gap in the sequence anywhere, legacy part included;
- a missing tail (the chain head pointing past the last stored event).

A legacy link break is therefore not proof of tampering, but it is not proof
of its absence either: pre-2.0 events were never keyed, so their integrity
rests on the 1.x deployment. Events from 2.0 on are fully verified.

## Outbound requests

Citadel makes outbound requests for OIDC discovery and keys, ACME HTTP-01
validation, Let's Encrypt, SIEM streaming, Kubernetes TokenReview and secret
rotation (PostgreSQL servers and rotation webhooks). ACME
HTTP-01 validation refuses loopback, link-local, multicast and cloud metadata
addresses, checked after DNS resolution and on redirects, unless an account
explicitly allows a range. SIEM delivery refuses loopback, link-local,
multicast and cloud metadata addresses and doesn't follow redirects. Rotation webhooks (https
only, HMAC-signed with a timestamp) and the PostgreSQL rotator refuse
loopback, link-local, multicast and cloud metadata addresses, checked on the
resolved address at dial time; webhooks don't follow redirects. Webhook
signing secrets are sealed at rest with a key derived from the deployment
root secret. See [rotation.md](rotation.md).

Notification webhooks and Slack messages (https only, no redirects) go
through the same dial-time check (shared as `newGuardedHTTPClient` in
`internal/server/outbound.go`); Slack messages go only to `hooks.slack.com`.
Webhooks are HMAC-SHA256 signed with a timestamp. Signing secrets and Slack
webhook URLs are sealed at rest (AES-256-GCM, a key derived from the
deployment root secret, bound to the account and channel). Email goes only to
the operator-configured SMTP server, always over TLS (STARTTLS that must be
offered, or implicit TLS) with a verified certificate. See
[notifications.md](notifications.md).

All of these share one dial-time check (`internal/server/outbound.go`), so
neither a DNS answer nor a redirect can steer a connection to the host
itself or a metadata service; the features differ only in which ranges they
let through. The agent HTTP broker (`POST /v1/agent/http`, the MCP
`http_request` tool) is stricter: it also refuses private ranges (RFC 1918,
unique local, CGNAT, and NAT64/6to4 addresses embedding them) unless the
credential lists them in `allowedCIDRs`, never uses an environment proxy,
sends a credential only to the hosts, ports, methods and paths its usage
profile allows, follows at most three same-host redirects (re-checking each),
and replaces the secret and its encoded forms in responses with
`[REDACTED]`. See [agents.md](agents.md).

## What you are responsible for

- TLS in front of, or in, Citadel.
- Keeping the wrapping key, audit key and bootstrap token in a secret store,
  and backing up the wrapping key separately from the database.
- Network policy: only clients and your ingress should reach Citadel, and
  Citadel only needs PostgreSQL, DNS and the outbound services above.
- Restricting database access to Citadel.
- Never running `KMS_INSECURE_DEV=true` outside your own machine.

## Known limitations

- With PostgreSQL, rate limits on sign-in, first-run setup, SSO and the
  workload token endpoint are shared across replicas (see "Rate limits" in
  [configuration.md](configuration.md)); the failed sign-in and MFA lockouts
  and other limits (ACME, audit export) remain per replica. Shared counters fail
  open if the database is unavailable.
- Deleting a private CA certificate that is still valid revokes it first
  (reason `CessationOfOperation`), and its row is kept, so a certificate can
  never leave the inventory while still trusted, and the CRL keeps listing
  revoked certificates until they expire. A CA can be deleted only when it is
  disabled and nothing it issued is still valid; until its restore window
  ends it can be restored.
- Let's Encrypt HTTP-01 challenge responses are held in memory by the
  replica running the order. Behind several replicas, the CA's validation
  request can reach a replica that doesn't have the response; use manual
  DNS-01, or route `/.well-known/acme-challenge/` to one replica while
  issuing.
- Secrets Manager rotation runs only Citadel's built-in rotators (random,
  PostgreSQL, webhook); a schedule naming a Lambda function is recorded but
  runs nothing, and Citadel shows when it is due.
