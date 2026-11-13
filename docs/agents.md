# Credentials for AI agents

Citadel lets AI agents (coding agents, MCP clients, browser agents, LLM
workflows) use credentials **without holding them**. An agent asks Citadel
to act with a credential; Citadel checks what the agent was granted and
injects the secret itself. A secret that never enters the agent's context
can't leak through prompt injection, its logs or its output.

This page covers the concepts, setting an agent up, tokens and workload
identity, grants, and the kill switch. Connecting MCP clients is in
[agents-mcp.md](agents-mcp.md); the design is in
[design/agent-credentials.md](design/agent-credentials.md).

## Concepts

- **Agent.** A principal in an account, with a name, an owner (the console
  user accountable for it), a status (`active`, `suspended` or `revoked`) and
  labels. Agents never sign in to the console and never use IAM access keys;
  they authenticate every request with their own credentials.
- **Agent token.** `cagt_<agentId>_<secret>`, sent as
  `Authorization: Bearer cagt_...`. It is shown once; Citadel stores only a
  PBKDF2-SHA256 hash. Tokens can expire (1–365 days) and can be revoked at any
  time. An agent has at most 10 active tokens.
- **Federation binding.** Instead of a stored token, an agent can present a
  workload identity token (JWT) whose issuer, subject and audience exactly
  match one of its bindings: a token from Citadel's own workload identity
  issuer (`<KMS_PUBLIC_URL>/oidc`), or from an issuer registered as an OIDC
  provider under **IAM** in the same account (GitHub Actions, Kubernetes
  service accounts, ...).
- **Credential (usage profile).** A secret made usable by agents, under a name
  agents refer to (`github-pat`), saying how it is used and where it may go:

  | Kind | Use |
  |---|---|
  | `http_header` | Injected as `<headerName>: <headerPrefix><value>` (default `Authorization: Bearer ...`) |
  | `http_basic` | The secret is JSON `{"username","password"}`, sent as HTTP basic auth |
  | `http_query` | Injected as the query parameter `queryParam` |
  | `login` | JSON `{"username","password","totpSeed"?}` for browser agents, with the pages it may be used on (`login.urlPatterns`); see [Logins for browser agents](#logins-for-browser-agents) |
  | `raw` | An opaque value, only usable through reveal |
  | `aws_sts` | Temporary AWS credentials minted with AssumeRole; see [Minted credentials](#minted-credentials) |
  | `github_app` | A GitHub App installation token, minted on use |
  | `oauth2_client_credentials` | An OAuth 2.0 access token from a token endpoint, minted on use |

  HTTP kinds need `allowedHosts` (exact hosts or `*.example.com`, with an
  optional `:port`); `allowedMethods` default to `GET`; `allowedPathPrefixes`
  narrow paths further. Requests are https only unless `allowHttp` is set, and
  private, loopback, link-local and metadata addresses are refused unless an
  `allowedCidrs` entry covers them.
- **Grant.** Binds an agent to a credential with:
  - `actions`: `use` (Citadel injects the credential; the default), `reveal`
    (the agent receives the value; flagged as risky in the console and
    confirmed when granted) and `totp` (current one-time codes for a `login`).
  - `notBefore` / `notAfter`.
  - A time-of-day window, `HH:MM` to `HH:MM` in an IANA time zone (UTC when
    unset), optionally on some weekdays. An end before the start runs past
    midnight and counts as the day it started.
  - `maxUsesPerHour`, counted across all replicas (0 = unlimited).
  - `requiresApproval`: every use needs a person's approval (see
    [Approvals and leases](#approvals-and-leases)).
  - `leaseTtlSeconds` (60 to 86400): caps how long an approval may last;
    without `requiresApproval`, the first use opens a lease of that length
    and later uses within it are attributed to it.
- **Lease.** Time-boxed access to a credential for some actions, made by an
  approval or a grant's `leaseTtlSeconds`: single use (`once`), until it
  expires (`duration`), or for one task ID (`task`).
- **Kill switch.** Suspending an agent refuses all its requests immediately.
  An account admin can also suspend every agent in the account at once.
  Revoking an agent is permanent and revokes all its tokens.

## Set up an agent

For a walkthrough with examples (a GitHub token, basic auth, a website
login, a GitHub App) and a troubleshooting table, see
[Getting started with AI agents](getting-started-agents.md).

1. **Make a secret usable by agents.** Open the secret, go to its
   **Agent access** tab and choose **Make usable by agents**: give the
   credential a name, its kind and where it may be sent. Editors can do this.
2. **Create the agent.** Under **Identity → Agents**, choose **New agent**.
   Editors can create agents they own; account admins can name another owner,
   who must be a user in the account.
3. **Give it a credential to authenticate with.** On the agent's **Tokens**
   tab, create a token and copy it into the agent's configuration (for
   example `CITADEL_AGENT_TOKEN`). Or add a **Federation** binding so a CI job
   or pod can authenticate with its workload identity token.
4. **Grant credentials.** On the **Grants** tab, grant the credential. Prefer
   `use`; grant `reveal` only to tools that can't work through Citadel.
5. **Connect the agent.** See [agents-mcp.md](agents-mcp.md) for MCP
   clients, or call the Agent API directly.

The agent's owner and account admins manage it; viewers can see agents but
not change them. Every change is audited, including refused attempts.

## The Agent API

Agent endpoints accept only agent credentials (an agent token, or a
federated token). They never return secret values.

```bash
curl -H "Authorization: Bearer $CITADEL_AGENT_TOKEN" \
     -H "X-Citadel-Task-Id: run-42" \
     https://citadel.example.com/v1/agent/credentials
```

- `GET /v1/agent/whoami`: the calling agent, how it authenticated, and its
  token's expiry.
- `GET /v1/agent/credentials`: the credentials it has grants for (name, kind,
  description, allowed hosts and methods, actions) and whether each is usable
  right now (`reason`: `not_yet_valid`, `grant_expired`, `outside_window`,
  `credential_unavailable`).

Brokered requests, reveal and the MCP server build on the same checks.

`X-Citadel-Task-Id` (up to 128 characters of letters, digits and `-_.:/@#+=`)
is recorded on every audit event of the request, so you can follow one agent
task through the log.

With a federated token, send `X-Citadel-Agent-Id: agt_...` when the same
identity is bound to more than one agent; otherwise the request is refused as
ambiguous.

Because they never accept a session cookie, access key or SigV4, the agent
endpoints (`/v1/agent/*` and `/mcp`) skip the console's CSRF checks: a
cross-site request carries no ambient credential.

### Refusals

Errors are JSON `{"error", "message", "reason"}`:

| Status | `reason` | Meaning |
|---|---|---|
| 401 | `invalid_credential`, `token_expired`, `token_revoked`, `agent_revoked`, `federation_no_match`, `federation_ambiguous` | The credential doesn't authenticate an active agent |
| 403 | `agent_suspended` | The agent is suspended |
| 403 | `agents_suspended` | The account's kill switch is on |
| 429 | `rate_limited` | Too many requests (`Retry-After` is set) |

Access to a credential is refused with `no_grant` (also for credentials that
don't exist, so an agent can't discover them), `action_not_granted`,
`not_yet_valid`, `grant_expired`, `outside_window`, `rate_limited` or
`credential_unavailable` (the secret was deleted or is scheduled for
deletion).

## Using a credential: brokered HTTP

```http
POST /v1/agent/http
Authorization: Bearer cagt_...
Content-Type: application/json

{ "credential": "github-pat", "method": "GET",
  "url": "https://api.github.com/user/repos",
  "headers": { "Accept": "application/vnd.github+json" },
  "taskId": "fix-issue-1234" }
```

Citadel checks the agent's grant (it needs the `use` action), performs the
request with the credential injected, and returns the upstream's answer:

```json
{ "status": 200, "headers": { "Content-Type": "application/json; charset=utf-8" },
  "body": "[...]", "bodyEncoding": "text", "truncated": false, "redacted": false }
```

| Field | Meaning |
| --- | --- |
| `credential` | The credential's name (MCP: `list_credentials` lists them). |
| `method` | `GET` (default), `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or `OPTIONS`; the credential's `allowedMethods` may narrow this. |
| `url` | Absolute `https` URL. Plain `http` only when the credential allows it. |
| `headers` | Extra request headers (string values). |
| `body`, `bodyEncoding` | Request body, `text` (default) or `base64`; at most 1 MiB decoded. |
| `taskId` | Optional task or session ID for the audit log (also accepted as the `X-Citadel-Task-Id` header; they must agree). |

An upstream error status (404, 500...) is a successful brokered call: it
comes back in `status`. A text (UTF-8) body is returned as is, anything else
base64 encoded.

### How the credential is injected

| Kind | On the wire |
| --- | --- |
| `http_header` | `<headerName>: <headerPrefix><value>`. `headerName` defaults to `Authorization`; for a bearer token set `headerPrefix` to `Bearer ` (with the space). |
| `http_basic` | `Authorization: Basic ...` from the stored JSON `{"username": "...", "password": "..."}`. |
| `http_query` | The query parameter `<queryParam>=<value>`, replacing any the agent sent. |

`login` and `raw` credentials can't be brokered (`kind_not_brokerable`); they
are only usable through reveal (and `login` through `get_login` and
`get_totp_code`).

Minted credentials are injected as the token they mint (see
[Minted credentials](#minted-credentials)):

| Kind | On the wire |
| --- | --- |
| `github_app` | `Authorization: Bearer <installation token>`. |
| `oauth2_client_credentials` | `Authorization: Bearer <access token>`, or `oauth2.headerName: oauth2.headerPrefix<token>`. |
| `aws_sts` | The request is signed with AWS Signature Version 4 using the temporary credentials, for `awsSts.signingService` in `awsSts.signingRegion` (default `region`, then `us-east-1`). The agent's `X-Amz-Date`, `X-Amz-Security-Token` and `X-Amz-Content-Sha256` headers are dropped; other `X-Amz-*` headers (such as `X-Amz-Target`) are signed. Without a `signingService` the credential is reveal-only. |

### What the broker refuses

- **Hosts.** The URL's host must match the credential's `allowedHosts`: an
  exact host (`api.github.com`) or a suffix wildcard (`*.example.com`, which
  doesn't match `example.com` itself). Hosts are compared in lowercase without
  a trailing dot; internationalized names must be written in their punycode
  (`xn--`) form, so a look-alike Unicode name never matches. A URL with
  userinfo is refused. Only the scheme's default port is allowed unless the
  entry names one (`api.example.com:8443`).
- **Paths.** With `allowedPathPrefixes`, the path must fall under one of them
  by whole segments (`/repos` allows `/repos` and `/repos/x`, not `/reposx`).
  Dot segments (`/a/../b`, also percent-encoded) and backslashes are refused
  for every credential.
- **Addresses.** The resolved address of every connection is checked: loopback,
  link-local, private (RFC 1918, unique local, CGNAT, and NAT64/6to4 addresses
  that embed them), multicast and cloud metadata addresses are refused
  (`destination_blocked`) unless the credential's `allowedCIDRs` include
  them. DNS rebinding can't get around this; environment proxies are never
  used.
- **Headers.** Headers that could carry or override a credential are dropped
  from the agent's request: `Authorization`, `Proxy-*`, `Cookie`, the
  credential's own header, `Host`, hop-by-hop and framing headers,
  `Forwarded`/`X-Forwarded-*`, and `Accept-Encoding` (Citadel negotiates
  compression itself so that it can inspect the response).

### What comes back

- Redirects to the same host (and port; an http to https upgrade is fine) are
  followed, at most three, each re-checked against the credential. A redirect
  elsewhere is returned to the agent as is, with its `Location`.
- `Set-Cookie`, `Authorization`, `Proxy-Authenticate` and hop-by-hop headers
  are removed; `WWW-Authenticate` is kept. Repeated headers are joined with
  `, `.
- Every occurrence of the secret in the response headers and body, also
  base64, base64url, URL-escaped and JSON-escaped, is replaced with
  `[REDACTED]` and `redacted` is `true`. (Values shorter than four characters
  are not redacted; don't broker them.)
- The body is cut at 5 MiB (`truncated: true`); a secret cut off at the end
  is removed too. A response in a content encoding Citadel can't decode is
  refused (`unsupported_content_encoding`).
- Timeouts: 5 s to connect, 30 s overall (`upstream_timeout`).

### Errors

Errors are JSON with a stable `reason`:

```json
{ "error": "forbidden", "reason": "host_not_allowed", "message": "this credential may not be sent to that host" }
```

| Status | Reasons |
| --- | --- |
| 400 | `invalid_request`, `invalid_url`, `invalid_header`, `invalid_task_id`, `kind_not_brokerable`, `method_not_allowed` (a method the broker never sends) |
| 401 | the agent token is missing, wrong, expired or revoked |
| 403 | `no_grant`, `action_not_granted`, `not_yet_valid`, `grant_expired`, `outside_window`, `credential_unavailable`, `host_not_allowed`, `path_not_allowed`, `method_not_allowed`, `scheme_not_allowed`, `destination_blocked`, `agent_suspended`, `approval_required` (with `requestId`; see [Approvals and leases](#approvals-and-leases)) |
| 413 | `body_too_large` |
| 429 | `rate_limited` (with `Retry-After`) |
| 502 | `upstream_unreachable`, `unsupported_content_encoding`, `credential_invalid` (the stored value doesn't fit the credential's kind) |
| 503 | `broker_busy`: too many brokered requests in flight (32 per replica, 4 per agent) |
| 504 | `upstream_timeout` |

A credential the agent has no grant for and one that doesn't exist both
answer `no_grant`, so an agent can't discover credentials.

## Revealing a credential

```http
POST /v1/agent/credentials/reveal
Authorization: Bearer cagt_...

{ "credential": "deploy-key", "taskId": "release-42" }
```

returns `{"credential": "deploy-key", "kind": "raw", "value": "..."}`, only
when the agent's grant explicitly includes `reveal`. For `http_basic`
credentials the value is the stored JSON document; for `login` credentials
JSON `{"username", "password"}` (the TOTP seed is never revealed). Minted
credentials return the short-lived token with `expiresAt`, never the source
material (for `aws_sts`, an AWS CLI `credential_process` JSON document). The response is
never cached, and the disclosure is written to the audit log before the
value is returned: if the audit log can't be written, the value is withheld.
Prefer brokered use whenever the agent only needs to call an API.

A reveal made under a lease also returns `leaseId` and `leaseExpiresAt`;
treat the value as valid only until then.

## Logins for browser agents

A `login` credential holds a website login for an agent that drives a
browser: its secret is JSON `{"username", "password", "totpSeed"?}` and its
profile lists the pages it may be used on:

```json
{ "name": "crm-login", "project": "ops", "env": "prod", "key": "CRM_LOGIN", "kind": "login",
  "login": { "urlPatterns": ["https://crm.example.com/login", "https://*.example.org"] } }
```

A URL pattern is `https://host[:port][/path]`. The host is exact or a
`*.example.com` wildcard (which doesn't match `example.com` itself), the
port must match (443 when none is given), and the path matches by whole
segments (`/login` allows `/login` and `/login/sso`, not `/loginx`).

- **`POST /v1/agent/login`** (MCP `get_login`) `{"credential", "url"}`
  returns `{"credential", "username", "password", "urlPattern"}`. It needs a
  grant with `reveal`, and `url` (the page the agent is about to fill in)
  must match a pattern (`url_not_allowed` otherwise). Filling the page is the
  agent browser's job: Citadel never drives a browser.
- **`POST /v1/agent/totp`** (MCP `get_totp_code`) `{"credential"}` returns
  `{"credential", "code", "expiresAt", "secondsRemaining", "digits",
  "period", "algorithm"}`. It needs a grant with `totp`. The seed never
  leaves Citadel.

Both are audited (`citadel.AgentGetLogin` with the page's host and path,
never its query; `citadel.AgentTOTP`) before the value is returned, and
answered with `Cache-Control: no-store`.

**TOTP seeds.** `totpSeed` is an `otpauth://totp/...` URI (as in the QR code
a site shows) or a bare base32 seed, for which the profile's
`login.totpAlgorithm` (`SHA256` or `SHA512`), `totpDigits` (6–8) and
`totpPeriod` (seconds) apply. Codes follow RFC 6238.

> **SHA-1 seeds are refused.** Citadel runs Go's FIPS 140-3 module, in
> which HMAC-SHA-1 is not an approved algorithm, so it can't compute codes
> for SHA-1 seeds. That is the otpauth default (a URI without `algorithm=`)
> and what most sites use. Re-enrol the site's authenticator with SHA-256 or
> SHA-512 if it offers that. Citadel refuses SHA-1 seeds when you store them
> (`totp_sha1_unsupported`) and explains why if one was stored directly
> (`get_totp_code` answers `409 totp_sha1_unsupported`). Seeds shorter than
> 112 bits are refused for the same reason.

**In the console**, the secret's **Agent access** tab shows a login's fields:
username, password and TOTP seed. The seed is write-only (you can replace or
remove it, never read it back), and editors who may reveal values see a live
preview of the current code. **Add login** on the Agents page creates the
secret and its login credential in one step.

The console endpoints are `GET /v1/agents/credentials/login?name=[&code=true]`
(username, whether a password and seed are set, and with `code=true` the
current code; audited as `citadel.ReadAgentLogin`) and
`POST /v1/agents/credentials/login` `{"name", "username"?, "password"?,
"totpSeed"?, "clearTotpSeed"?}` (a new version of the secret; audited as
`citadel.PutAgentLogin`).

## Minted credentials

Instead of handing out a long-lived secret, a credential can be **minted on
use**: the secret holds the long-lived source material, the profile says how
to mint a short-lived token from it, and agents only ever use or receive the
token.

| Kind | Secret (source material) | Profile (`kind`'s member) |
| --- | --- | --- |
| `aws_sts` | JSON `{"accessKeyId", "secretAccessKey", "sessionToken"?}` | `awsSts`: `roleArn` (required), `endpoint` (default AWS's global STS; Citadel's own STS works too), `region`, `externalId`, `sessionName`, `sessionPolicy`, `durationSeconds` (900–43200, default 3600), `signingService`, `signingRegion` |
| `github_app` | The App's PEM private key (or JSON `{"privateKey"}`) | `githubApp`: `appId`, `installationId` (required), `baseUrl` (GitHub Enterprise Server: `https://HOST/api/v3`), default `repositories` and `permissions` |
| `oauth2_client_credentials` | The client secret, or JSON `{"clientId", "clientSecret"}` | `oauth2`: `tokenUrl` (required), `clientId`, `clientAuth` (`basic`, the default, or `post`), `scopes`, `audience`, `resource`, `headerName`, `headerPrefix` |

```json
{ "name": "gh-deploy", "project": "ci", "env": "prod", "key": "GH_APP_KEY", "kind": "github_app",
  "allowedHosts": ["api.github.com"], "allowedMethods": ["GET", "POST"],
  "githubApp": { "appId": "123456", "installationId": 7890123,
                 "repositories": ["api", "web"], "permissions": { "contents": "write", "pull_requests": "write" } } }
```

- **Brokered use** (`use`): Citadel mints (or reuses) a token and injects it
  (see [How the credential is injected](#how-the-credential-is-injected)).
  The usual host, method and path rules apply.
- **Reveal** (`reveal`): returns the token and its `expiresAt`.
- **Caching.** Tokens are cached per credential, source secret version and
  effective grant scope until a minute before they expire, and concurrent
  requests share one mint. Changing the profile or the secret takes effect
  at once.
- **Outbound calls** to STS, GitHub and token endpoints follow the broker's
  rules: https only (http only with `allowHttp`), no redirects, a timeout,
  and the resolved address is checked when connecting, so they can't reach
  loopback, link-local, private or metadata addresses unless the credential's
  `allowedCidrs` include them.
- **Errors.** A provider that refuses to issue a token gives
  `502 token_unavailable`, with its HTTP status and (validated) error code in
  the message; never the response body.

**Grant scopes.** A grant can narrow what its tokens may do with `scope`:

| Kind | `scope` |
| --- | --- |
| `github_app` | `repositories` (a subset of the credential's, when it lists any) and `permissions` (only the credential's permissions, at the same or a lower level). When the credential has no default repositories or permissions, every grant must set one of them: Citadel never mints installation-wide tokens. |
| `aws_sts` | `sessionPolicy`, an inline session policy, only when the credential has none (AWS can't intersect two). |
| `oauth2_client_credentials` | `scopes`, a subset of the credential's scopes when it lists any. |

```json
{ "agentId": "agt_...", "credential": "gh-deploy", "actions": ["use"],
  "scope": { "repositories": ["api"], "permissions": { "contents": "read" } } }
```

Changing a credential so that an existing grant's scope no longer fits is
refused (`409 grants_conflict`). A use made under an approval lease with no
grant uses the credential's defaults.

## Anomaly alerts

Citadel learns what each agent usually does from its last 14 days of
activity in the audit log: the hosts it reaches, the hours of the day (UTC)
it works and how many uses it makes in an hour. Every brokered request,
reveal, TOTP code and login, and every refusal, is checked against that
baseline (in memory on each replica, refreshed hourly):

| Kind | When |
| --- | --- |
| `new_host` | A host the agent hasn't reached in its baseline. |
| `off_hours` | Use in an hour of the day the agent hasn't worked in. |
| `rate_spike` | More than 5 times its usual hourly rate, and more than 20 uses in the last hour. |
| `repeated_denials` | 10 or more refused requests in 10 minutes. |

`new_host` and `off_hours` wait until the baseline is established (at least
20 uses over more than two days), so a new agent doesn't alert on everything.
Each kind is raised at most once per agent per hour (across replicas). An
anomaly is listed in the agent's **Activity** tab, audited as
`citadel.AgentAnomaly`, and sent to the notification channels subscribed to
`agent.anomaly` (see [notifications.md](notifications.md)).

Per agent, on the agent's **Overview** (or
`POST /v1/agents/anomaly-settings {"agentId", "alertsEnabled", "autoSuspend"}`):

- **Alerts** (on by default): turn the notifications off; anomalies are
  still recorded.
- **Auto-suspend** (off by default): suspend the agent on an anomaly. The
  suspension is like a console one (audited as `citadel.SuspendAgent` with
  the actor `anomaly-detector`, leases ended, `agent.suspended` sent); resume
  the agent once you've looked.

`GET /v1/agents/anomalies?agentId=` lists the anomalies, the settings and the
current baseline.

## Approvals and leases

Some credentials should only be used when a person says so. Citadel 2.3 adds
just-in-time access: an agent asks, a person approves in the console, and the
agent gets a **lease** for exactly that.

### When an agent needs approval

- **A grant with `requiresApproval`.** Using (or revealing) the credential
  without a lease is refused with `approval_required` and the ID of a pending
  access request:

  ```json
  { "error": "approval_required", "reason": "approval_required",
    "requestId": "aar_k2m4q6s8u2w4y6a3",
    "message": "a person must approve this use; poll GET /v1/agent/access-requests/aar_k2m4q6s8u2w4y6a3 and retry once it is approved" }
  ```

  Asking again while it is pending returns the same request (one per agent,
  credential, action and task ID).
- **Access the agent doesn't have.** The agent asks explicitly:

  ```http
  POST /v1/agent/access-requests
  Authorization: Bearer cagt_...
  X-Citadel-Task-Id: release-42

  { "credential": "deploy-key", "actions": ["reveal"],
    "reason": "Tag the release; the pipeline needs the deploy key", "duration": "15m" }
  ```

  `actions` default to `["use"]`; `reason` is required (at most 512
  characters, shown to approvers); `duration` (or `durationSeconds`) is how
  long it is wanted, 1 minute to 24 hours; `taskId` defaults to
  `X-Citadel-Task-Id`. The answer is `201` with the new request, or `200`
  with the pending one for the same credential, actions and task. A request
  for a credential that doesn't exist is accepted like any other, so agents
  can't discover names; it can only be denied. An agent has at most 20
  pending requests (`429 too_many_requests`).

The MCP tools `request_access` and `get_lease` do the same (see
[agents-mcp.md](agents-mcp.md)).

### Waiting for a decision

`GET /v1/agent/access-requests/{requestId}` returns the request with its
`status`: `pending`, `approved`, `denied` (with the approver's reason in
`decisionComment`), `expired` (nobody decided within an hour) or
`cancelled` (the agent was revoked). An approved request carries its
`lease`. `GET /v1/agent/leases` lists the agent's active leases. Then retry
the original call: it is made under the lease.

### Approving

Pending requests appear in the console's **Approvals** inbox (type *Agent
access*) and on the agent's **Requests** tab; the
`agent.approval_requested` notification links straight to the request.
Approvers are the agent's owner (an editor) and account admins:

- only in a console session. Access keys can list requests but never decide
  them, and an agent's own credentials never open a console session;
- when the organization requires MFA (**Administration → Organization
  settings**), a password session confirms the approval with a current code
  (or a recovery code). SSO sign-ins are exempt, as they are from the MFA
  requirement itself.

An approval chooses the lease's scope:

| Scope | The agent may... |
| --- | --- |
| Once | ...make one call. A second call needs a new approval. A single-use lease is consumed atomically, so two concurrent calls can't both use it. |
| Duration | ...call until the lease expires. |
| Task | ...call until the lease expires, only with the request's task ID. |

The lease lasts the requested duration, or an hour, and never longer than
24 hours, the grant's `leaseTtlSeconds` or the grant's `notAfter`. A denial
needs a reason, which the agent sees. Approving access the agent has no
grant for gives it exactly the approved actions for the lease's life; the
console warns about this, and requests for `reveal` are highlighted.

A decision raises `agent.access_decided` (see
[notifications.md](notifications.md)).

### When leases end

Leases end when they expire or their single use is made, when someone
revokes them (the agent's **Leases** tab, or
`POST /v1/agents/leases/revoke`), when the agent is suspended or revoked,
and when the account's kill switch is used. Resuming an agent does not bring
its leases back. Revoking an agent also cancels its pending requests.

Uses under a lease are attributed to it: `lease=als_...` in the
`citadel.AgentHTTP` and `citadel.AgentReveal` events, and refusals for
approval carry `request=aar_...`.

## Requiring workload identity federation

An agent can be set to **Require workload identity federation**
(`requireFederation` on create or update). Its tokens are then refused
(`403`, reason `federation_required`) and no new ones can be issued; it
authenticates only with a federated token matching one of its bindings.
Turning it off makes existing, unexpired tokens work again.

## Tokens

- Tokens are 256-bit random secrets. Citadel stores a PBKDF2 hash and a short
  non-secret prefix used to recognise the token in the console
  (`cagt_agt_..._abcdefgh…`).
- Revoking a token or suspending its agent takes effect on the next request.
- Last use is recorded (at most once a minute per agent and replica).
- Token values never appear in logs, audit events, error messages or metrics.

## Workload identity federation

A binding is `{issuer, subject, audience}`, all matched exactly:

- **Citadel's issuer** (`<KMS_PUBLIC_URL>/oidc`): the token must also name the
  agent's account (its `citadel.account` claim), so a token from another
  account never matches.
- **External issuers** must first be registered as an OIDC provider under
  **IAM** in the agent's account. Citadel fetches signing keys only from
  registered issuers.

Example for GitHub Actions: issuer `https://token.actions.githubusercontent.com`,
subject `repo:acme/app:ref:refs/heads/main`, audience `citadel`. The job
requests an ID token for audience `citadel` and sends it as the bearer token.

## Kill switch

- **One agent:** **Suspend** from the agent's row menu or detail page refuses
  every request until it is resumed. **Revoke** is permanent.
- **Every agent in the account:** **Administration → Settings → AI agents →
  Suspend all agents** (account admins). While on, every agent request in the
  account is refused with `agents_suspended`; each agent's own status is kept,
  so turning it off restores things as they were. A reason is recorded in the
  audit log.

## Audit

Agent activity is in the audit log with the agent's ID, its owner and the
task ID (`agentId`, `agentOwner`, `taskId`, also in exports and SIEM
streams). Requests an agent makes have actor type `agent`; console changes to
an agent carry its ID too. Filter with `?agent=agt_...` (the agent's
**Activity** tab links there).

Actions: `citadel.CreateAgent`, `UpdateAgent`, `DeleteAgent`, `SuspendAgent`,
`ResumeAgent`, `RevokeAgent`, `CreateAgentToken`, `RevokeAgentToken`,
`CreateAgentBinding`, `DeleteAgentBinding`, `PutAgentGrant`,
`DeleteAgentGrant`, `CreateAgentCredential`, `UpdateAgentCredential`,
`DeleteAgentCredential`, `SuspendAllAgents`, `ResumeAllAgents`,
`AgentWhoAmI`, `AgentListCredentials`, and `AgentAuth` (refused requests of
an identified agent, with the reason as the error type).

Logins, minted credentials and anomalies (2.4): `citadel.AgentTOTP`,
`AgentGetLogin`, `ReadAgentLogin`, `PutAgentLogin`, `AgentAnomaly` (actor
`anomaly-detector`) and `PutAgentAnomalySettings`.

Approvals and leases: `citadel.AgentRequestAccess` (a request opened or asked
again, by the agent or by a `requiresApproval` grant), `AgentGetAccessRequest`,
`AgentListLeases`, `ApproveAgentAccess` (with the lease, scope and actions),
`DenyAgentAccess`, `CreateAgentLease` (a lease opened by `leaseTtlSeconds`)
and `RevokeAgentLease` (one lease, or every lease ended by a suspension,
revocation or the kill switch).

### Brokered use, reveal and MCP

| Action | Recorded |
| --- | --- |
| `citadel.AgentHTTP` | Every brokered request, allowed or not: the agent, its owner and task ID (actor fields), the credential (`keyId`), and in `resource` the method, host, path without query string, upstream status, response and request bytes, redirects, `truncated`/`redacted`, and `via=api` or `via=mcp`. Denials carry the reason as the error type. |
| `citadel.AgentReveal` | Every reveal, allowed or not. |
| `citadel.AgentTOTP`, `citadel.AgentGetLogin` | Every TOTP code and login, allowed or not (`get_login`: the page's host and path, never its query). |
| `citadel.AgentListCredentials` | The MCP `list_credentials` tool. |
| `citadel.MCPInitialize`, `citadel.MCPEndSession` | An MCP session started (with the protocol version and client name) or ended. |

Secret values, request and response bodies, headers and query strings are
never recorded.

Prometheus metrics (labels are bounded codes, never credential names, agents,
hosts or values):

- `citadel_agent_http_requests_total{via, result, reason}`
- `citadel_agent_http_upstream_responses_total{class}` (`2xx`, `4xx`...)
- `citadel_agent_http_duration_seconds{via}`
- `citadel_agent_reveals_total{via, result, reason}`
- `citadel_mcp_requests_total{method, outcome}`
- `citadel_mcp_sessions_total{event}`

## Management API

The console uses `/v1/agents...` (session or access-key auth, scoped to the
current account); see the API reference (`docs/openapi.yaml`). The [Go SDK](sdk-go.md)
wraps the common calls (`CreateAgent`, `CreateAgentToken`,
`CreateAgentCredential`, `PutAgentGrant`, `SuspendAgent`,
`SetAgentsSuspended`, `ListAgentAccessRequests`, `ListAgentLeases`,
`RevokeAgentLease`, ...) and, configured with `AgentToken` (or
`CITADEL_AGENT_TOKEN`), the Agent API (`AgentWhoAmI`, `AgentCredentials`,
`AgentRequestAccess`, `AgentAccessRequest`, `WaitForAgentAccess`,
`AgentLeases`, `AgentTOTPCode`, `AgentGetLogin`, `AgentReveal`). For 2.4 it
also has `SetAgentLogin`, `GetAgentLogin`, `ListAgentAnomalies` and
`SetAgentAnomalySettings`, and the credential and grant inputs take the
`Login`, `AWSSTS`, `GitHubApp`, `OAuth2` and `Scope` settings. Approving and denying are console-only by design, so the SDK
doesn't do them.

Access request and lease endpoints:

| Operation | Endpoint | Who |
| --- | --- | --- |
| Ask for access | `POST /v1/agent/access-requests` | the agent |
| Poll a request | `GET /v1/agent/access-requests/{id}` | the agent |
| Active leases | `GET /v1/agent/leases?credential=` | the agent |
| List requests | `GET /v1/agents/access-requests?agentId=&status=pending` | viewer |
| Approve | `POST /v1/agents/access-requests/approve {requestId, scope, durationSeconds?, comment?, mfaCode?}` | owner or admin, console session |
| Deny | `POST /v1/agents/access-requests/deny {requestId, comment}` | owner or admin, console session |
| List leases | `GET /v1/agents/leases?agentId=&active=false` | viewer |
| Revoke a lease | `POST /v1/agents/leases/revoke {leaseId, reason?}` | owner or admin |
