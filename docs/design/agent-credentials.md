# Design: credentials for AI agents (2.2–2.4)

Status: accepted. This is the shared design for the agent credential features
shipping in 2.2, 2.3 and 2.4. User-facing documentation lives in
`docs/agents.md` and is written as the features land.

## Goal

Let AI agents (coding agents, MCP clients, browser agents, LLM workflows) use
credentials **without holding them**. An agent that never sees a secret can't
leak it through prompt injection, logs, or its context window. Where an agent
must hold a credential, it gets a short-lived, narrowly scoped one, and a
human can approve, watch, and revoke it.

Non-goals: a consumer password manager; replacing the existing secrets,
workload identity or IAM features (agents build on them).

## Concepts

- **Agent:** a first-class principal in an account. Fields: `agentId`
  (`agt_` + 20 base32), `name` (unique per account), `description`,
  `owner` (a console username, accountable for it), `status`
  (`active` | `suspended` | `revoked`), `createdAt`, `lastUsedAt`, `labels`.
- **Agent credential (how an agent authenticates to Citadel):** one or more
  of:
  - an **agent token**: `cagt_<agentId>_<secret>`, shown once and stored as a
    PBKDF2 hash (like recovery codes, cheaper iterations because the secret is
    256-bit random), with an optional expiry;
  - **workload identity federation**: an existing workload identity token
    (issued by Citadel's `/oidc` issuer) or an external OIDC token (e.g. GitHub
    Actions, Kubernetes service accounts via existing IAM OIDC providers) whose
    issuer/subject/audience match a binding on the agent.
  Agent tokens are presented as `Authorization: Bearer cagt_...`. Agents
  never use console sessions or IAM access keys.
- **Credential:** a reference to a secret the agent may use, plus how to use
  it. A credential is a Citadel secret (native project/env/key or a Secrets
  Manager secret ARN) with a **usage profile**:
  - `kind`: `http_header` (inject `Header: <prefix><value>`), `http_basic`
    (JSON `{username,password}`), `http_query` (query parameter),
    `login` (JSON `{username,password,totpSeed?,url}` for browser agents, 2.4),
    `raw` (opaque value; only usable through reveal).
  - `allowedHosts`: exact hosts or `*.example.com` suffixes the credential may
    be sent to (required for http kinds; the broker refuses anything else).
  - `allowedMethods`, optional `allowedPathPrefixes`.
- **Grant (policy):** binds an agent to a credential with: `actions` ⊆
  {`use`, `reveal`, `totp`}, optional `notBefore`/`notAfter`, optional
  time-of-day window, `maxUsesPerHour`, `requiresApproval` (2.3), and
  `leaseTtl` (2.3). Default action is `use` only; `reveal` must be granted
  explicitly and is highlighted in the UI as risky.
- **Kill switch:** suspending an agent (or the account-wide "suspend all
  agents") immediately rejects all its requests, ends its leases, and revokes
  its tokens' sessions. Revoking is permanent.

## Brokered use (2.2)

`POST /v1/agent/http` — the agent asks Citadel to perform an HTTP request with
a credential injected. Body:

```json
{ "credential": "github-pat", "method": "GET",
  "url": "https://api.github.com/user/repos", "headers": {"Accept": "..."},
  "body": "<base64 or text>", "bodyEncoding": "text|base64",
  "taskId": "optional caller task/session id" }
```

Citadel checks: agent active; grant exists with `use`; time window; rate
limit; URL scheme https (http only with an explicit per-credential flag);
host matches `allowedHosts` (after IDNA normalisation, no userinfo, default
ports only unless listed); method/path allowed; SSRF protections (no loopback,
link-local, private or metadata addresses unless the credential allows a
CIDR); no redirects followed across hosts (same-host redirects up to 3).
Then it injects the credential, strips any agent-supplied header that would
collide with or override it (e.g. `Authorization`, `Cookie`, `Proxy-*`), sends
the request with timeouts (connect 5s, total 30s), size limits (request 1 MiB,
response 5 MiB, truncated with a flag), and returns:

```json
{ "status": 200, "headers": {...}, "body": "...", "bodyEncoding": "text|base64",
  "truncated": false, "redacted": false }
```

Response headers that can carry credentials (`Set-Cookie`, `Authorization`,
`WWW-Authenticate` challenge params are kept) are filtered, and any exact
occurrence of the secret value (and its base64/URL-encoded forms) in the
response is replaced with `[REDACTED]` (`redacted: true`).

Every call is audited (`citadel.AgentHTTP`): agent, owner, credential,
method, host, path (no query string), status, bytes, taskId, and denials
with the reason. Secret values are never logged.

## Reveal (2.2, opt-in)

`POST /v1/agent/credentials/reveal {credential}` returns the value only with an
explicit `reveal` grant; audited as `citadel.AgentReveal`. 2.3 adds leases so a
revealed value can be a short-lived derivative instead (see below).

## MCP server (2.2)

Citadel speaks the Model Context Protocol over Streamable HTTP at `/mcp`
(JSON-RPC 2.0, protocol version per the current MCP spec; support
`initialize`, `tools/list`, `tools/call`, `ping`), authenticated with the
agent token (Bearer). Tools:

- `list_credentials` → the credentials the agent can use: name, kind,
  description, allowedHosts, actions. Never values.
- `http_request` → brokered use (same as `/v1/agent/http`).
- `reveal_credential` → only listed when the agent has any `reveal` grant.
- 2.3: `request_access` (ask a human for a grant or approval), `get_lease`.
- 2.4: `get_totp_code`, `get_login` (for browser agents; see below).

The TypeScript SDK ships a stdio bridge (`npx @worlddrknss/citadel mcp`) for
MCP clients that only speak stdio; it forwards to `/mcp` with the token from
`CITADEL_AGENT_TOKEN`. Docs give copy-paste config for Claude Code, Claude
Desktop, Cursor and VS Code (`docs/agents-mcp.md`).

## Just-in-time access and approvals (2.3)

- A grant with `requiresApproval` makes `use`/`reveal` return
  `approval_required` with a `requestId`; the agent (or MCP tool
  `request_access`) can also ask for a grant it doesn't have, with a reason.
- Approvers (owner, account admins; never the agent's own token) see pending
  agent requests in the console Approvals inbox (reuse the change-request UI
  patterns, new type `agent_access`), approve for `once`, `duration` (e.g. 1h)
  or `task` (bound to taskId), or deny. Approval requires a console session
  (and MFA when the org requires it).
- **Notifications:** a notification channel framework (webhook, Slack
  incoming webhook, email via SMTP config) used for approval requests,
  kill-switch events and anomaly alerts. Signed webhooks (HMAC-SHA256 +
  timestamp), same SSRF rules as SIEM streaming.
- **Leases:** approvals and `leaseTtl` grants produce a lease (id, agent,
  credential, scope, expiresAt). Leases end at expiry, on suspend, or when
  revoked in the console. Brokered use under a lease is attributed to it.
- Agents' long-lived tokens can be optional: an agent may be configured to
  require federation (workload identity) only.

## Browser agents and provider-scoped tokens (2.4)

- **Logins:** `login` credentials hold username, password, URL patterns and an
  optional TOTP seed. `get_totp_code` returns the current 6–8 digit code (RFC
  6238, SHA1/SHA256/SHA512 per the site's seed — note SHA1 HMAC is unavailable
  under fips140=only, so SHA1 seeds are refused in FIPS mode with a clear
  error). `get_login` returns username + password only with `reveal`, scoped
  to a URL that matches the credential's patterns; a `fill` flow for agent
  browsers is out of scope for the server and documented as a client concern.
- **Provider-scoped credentials:** instead of a stored static secret, a
  credential can be **minted on use**:
  - `aws_sts`: AssumeRole into a configured role (Citadel's own STS for
    Citadel resources, or real AWS STS with stored source credentials) with a
    session policy; returns temporary credentials via reveal/lease, or signs
    brokered AWS requests (SigV4) server-side.
  - `github_app`: a GitHub App installation token with restricted
    repositories/permissions per grant (App private key stored as a secret;
    JWT RS256 signing).
  - `oauth2_client_credentials`: fetch and cache an access token from a token
    endpoint; inject it into brokered requests.
- **Minting library (`internal/providertoken`):** the minters above, plus
  TOTP and a `Static` wrapper, share one interface,
  `Mint(ctx, Params) (Token{Value, ExpiresAt, Kind, Metadata}, error)`, so the
  broker treats stored and minted credentials alike. `Metadata` is never
  secret (assumed role ARN, granted repositories and permissions, token
  type); `Token` redacts `Value` under `%v` and `slog`. Outbound HTTP uses the
  injected (SSRF-guarded) client, never follows redirects, requires https,
  and runs under a timeout; provider errors are reduced to the HTTP status
  and a validated error code. Notes and small deviations:
  - TOTP: SHA1 seeds are refused **always**, not only in FIPS mode
    (`ErrSHA1Unsupported`), because Citadel always runs with
    `fips140=only` and HMAC-SHA-1 panics there. A missing otpauth
    `algorithm` (the format's default) and a bare base32 seed without an
    explicit algorithm both mean SHA1. Seeds shorter than 112 bits are
    refused for the same reason (FIPS minimum HMAC key length), so some
    80-bit seeds cannot be used even with SHA-256.
  - `aws_sts`: the value handed out is the AWS CLI `credential_process` JSON
    document. A grant may set a session policy only when the credential has
    none configured (policies cannot be intersected client side). Citadel's
    own STS accepts AssumeRole from this client but ignores `Policy` and
    `ExternalId`. `SignAWSRequest` signs brokered calls server-side (SigV4
    signing lives in `internal/sigv4.SignRequest`).
  - `github_app`: with no repositories or permissions in the grant or the
    credential's defaults, GitHub issues an installation-wide token; the
    broker should require a restriction where policy demands one.
  - `oauth2_client_credentials`: tokens are cached per (scopes, audience,
    resource) until 60 s before `expires_in`, with concurrent requests
    sharing one fetch; a response without `expires_in` is not cached.
- **Anomaly alerts:** per-agent baselines (hosts, hours, rate); alert through
  the notification channels on new host, off-hours use, rate spikes, repeated
  denials; optional auto-suspend.

## Security requirements (all releases)

FIPS 140-3 (standard library crypto, `GODEBUG=fips140=only` in tests); every
handler authenticated and account-scoped; agent tokens and secrets never
logged (beware CodeQL clear-text logging rules: don't log request-context
values); audit-before-change (write-ahead audit) for all state changes;
fixed error messages to clients; SSRF protections reuse the existing
validated dialer used by ACME/SIEM/rotation; rate limits via
`internal/ratelimit` + the shared Postgres limiter.

## Console

A top-level **Agents** section (sidebar, under Identity): agents list (status,
owner, last used, grants count, suspend), agent detail (overview, tokens,
federation bindings, grants, activity — filtered audit — and in 2.3 leases and
requests), credential usage profiles on the secret drawer ("Agent access"
tab), the global kill switch in Administration, and a setup wizard that
generates MCP client configs. Follows the existing design system.
