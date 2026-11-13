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
  | `login` | JSON `{"username","password","totpSeed"?,"url"}` for browser agents (2.4) |
  | `raw` | An opaque value, only usable through reveal |

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
- **Kill switch.** Suspending an agent refuses all its requests immediately.
  An account admin can also suspend every agent in the account at once.
  Revoking an agent is permanent and revokes all its tokens.

## Set up an agent

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

## Management API

The console uses `/v1/agents...` (session or access-key auth, scoped to the
current account); see the API reference (`docs/openapi.yaml`). The Go SDK
wraps the common calls (`CreateAgent`, `CreateAgentToken`,
`CreateAgentCredential`, `PutAgentGrant`, `SuspendAgent`,
`SetAgentsSuspended`, ...) and, configured with `AgentToken` (or
`CITADEL_AGENT_TOKEN`), the Agent API (`AgentWhoAmI`, `AgentCredentials`).
