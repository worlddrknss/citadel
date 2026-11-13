# Getting started with AI agents

This guide takes you from nothing to an AI agent (Claude Code, Cursor, a
browser agent, a CI job) that calls an API with one of your secrets
**without ever holding it**. It takes about ten minutes. For the full
reference, see [Credentials for AI agents](agents.md) and
[Connecting MCP clients](agents-mcp.md).

## How it fits together

Four things are involved, and the one that trips people up is the third:

| Thing | What it is | Where you make it |
| --- | --- | --- |
| **Agent** | The identity an AI tool acts as. It has an owner, a status and an audit trail. | **Identity → Agents → New agent** |
| **Agent token** | How the agent proves who it is: `Authorization: Bearer cagt_...`. | The agent's **Tokens** tab |
| **Credential** | A secret plus an **agent usage profile**: a name agents refer to, how the secret is sent (a header, basic auth, a minted token...) and where it may go. | The secret's **Agent access** tab, **Make usable by agents** |
| **Grant** | Which credentials this agent may use, how (use, reveal, TOTP codes) and when. | The agent's **Grants** tab, **Grant credential** |

So a credential is not something you create on the Agents page: it is an
existing secret that you open in **Secrets** and give a usage profile.
Until at least one secret has a profile, the agent's **Grant credential**
button stays disabled.

```text
secret (Secrets)  ──Agent access tab──▶  credential "github-pat"
                                                │
agent "claude-code" ──Grants tab──▶ grant: use github-pat
        │
        └── token cagt_... ──▶ MCP client ──▶ Citadel injects the secret ──▶ api.github.com
```

## Before you start

- You need the **editor** role (or admin) in the account. Editors create
  agents they own and add usage profiles; viewers can only look.
- Store the secret first. In **Secrets**, open (or create with **New
  project** / **New environment**) the project and environment, then **Add
  secret**. In this guide the secret is `GITHUB_TOKEN` in `tools/dev`.

## Step 1: Create an agent

1. Go to **Identity → Agents** and choose **New agent**.
2. Give it a name such as `claude-code` (letters, digits, dots, dashes and
   underscores) and, optionally, a description. Account admins can name
   another owner; the owner is accountable for the agent and can approve its
   requests.
3. Choose **Create agent**. Citadel opens the new agent on its **Tokens** tab.

Create one agent per tool or workflow, so each has its own grants, activity
and kill switch.

## Step 2: Issue a token

1. On the agent's **Tokens** tab, choose **New token**.
2. Name it after where it will live (`laptop`, `ci`) and pick when it
   expires (7, 30 or 90 days, a year, or never; 90 days is the default).
3. Choose **Create token** and copy the `cagt_...` value. **It is shown
   once**: Citadel keeps only a hash.

Keep it in your shell or the tool's secret store, never in a file you
commit:

```sh
export CITADEL_AGENT_TOKEN=cagt_...
```

A CI job or Kubernetes pod can skip stored tokens altogether: add a
**Federation** binding (issuer, subject, audience) and it authenticates with
its workload identity token. See
[Workload identity federation](agents.md#workload-identity-federation).

## Step 3: Make a secret usable by agents

This is where the secret becomes a **credential**.

1. Go to **Secrets**, open the project and environment, and click the
   secret to open its drawer.
2. Choose the **Agent access** tab, then **Make usable by agents**.
3. Fill in the usage profile:
   - **Credential name**: what agents call it, e.g. `github-pat`
     (lowercase letters, digits, dots, dashes and underscores).
   - **How agents use it**: the kind (examples below).
   - **Allowed hosts**: where Citadel may send it, one per line
     (`api.github.com`, or `*.example.com`; add `:port` for a non-default
     port). Required for the HTTP kinds.
   - **Allowed methods** (only `GET` by default) and optional **Path
     prefixes**.
   - **Description**: agents see it, so say what the credential is for.
4. Choose **Save**. The profile, and later the agents granted it, are listed
   on the tab.

Requests go over `https` only, and private, loopback and cloud metadata
addresses are refused, unless you change that under **Network**.

The examples below show the settings for common cases.

### GitHub personal access token (HTTP header)

| Setting | Value |
| --- | --- |
| Secret value | The token, `github_pat_...` |
| Credential name | `github-pat` |
| How agents use it | **HTTP header** |
| Header / Value prefix | `Authorization` / `Bearer ` (with the trailing space; these are the defaults) |
| Allowed hosts | `api.github.com` |
| Allowed methods | `GET`, plus `POST`, `PATCH` if the agent should open issues or pull requests |
| Path prefixes | Optional, e.g. `/repos/acme/` to keep it to one organization |

Citadel sends `Authorization: Bearer <token>` on each brokered request, and
replaces the token with `[REDACTED]` if it appears in a response.

### An API with basic auth

Store the secret as JSON:

```json
{ "username": "svc-reports", "password": "..." }
```

and choose **HTTP basic auth** with **Allowed hosts** `reports.example.com`.
Citadel sends `Authorization: Basic ...`. If the API takes a key in the URL
instead, use **Query parameter** and name the parameter (`api_key`).

### A website login with TOTP

For a browser agent that signs in to a site. The quickest way is **Add
login** on the Agents page, which creates the secret and its credential in
one step: give a credential name, the project, environment and key to store
it under, the **Pages the login may be used on**
(`https://crm.example.com/login`), the username, password and, optionally,
the TOTP seed.

To do it by hand, store the secret as JSON
`{"username": "...", "password": "...", "totpSeed": "otpauth://totp/..."}`
and choose **Website login** with the pages it may be used on. The **Agent
access** tab then shows the login's **Username**, **Password** and **TOTP
seed**. The seed is write-only; **Show current code** previews the code an
agent would get.

The agent gets the username and password only for a page that matches one
of the patterns (MCP `get_login`, which needs a **Reveal** grant), and the
current one-time code (MCP `get_totp_code`, which needs a **TOTP codes**
grant). The seed never leaves Citadel.

> **SHA-1 TOTP seeds can't be used.** Citadel runs in FIPS 140-3 mode, in
> which HMAC-SHA-1 isn't an approved algorithm, and SHA-1 is what most sites
> use (and what an `otpauth://` URI without `algorithm=` means). Citadel
> refuses such a seed when you save it (`totp_sha1_unsupported`). Use a
> SHA-256 or SHA-512 seed if the site offers one; otherwise store the login
> without a seed.

### A GitHub App (minted token)

Instead of a long-lived token, Citadel can mint a short-lived GitHub App
installation token on each use.

| Setting | Value |
| --- | --- |
| Secret value | The App's private key (PEM) |
| How agents use it | **GitHub App** |
| App ID / Installation ID | From the App's settings and its installation |
| Default repositories / permissions | e.g. `api` and `contents=read`, one per line |
| Allowed hosts | `api.github.com` |

Citadel never mints installation-wide tokens: if the credential has no
default repositories or permissions, every grant must restrict them.

### An OAuth 2.0 client (minted token)

For an API that uses the client-credentials flow: the secret is the client
secret, and you choose **OAuth 2.0 client** with the **Token endpoint**
(`https://auth.example.com/oauth/token`), **Client ID**, optional
**Scopes** and **Audience**, and the API's host under **Allowed hosts**.
Citadel fetches an access token, caches it until shortly before it expires
and sends it as `Authorization: Bearer ...`.

**AWS role (STS)** works the same way for AWS: the secret holds access keys,
Citadel assumes the role and signs the agent's AWS requests. See
[Minted credentials](agents.md#minted-credentials).

## Step 4: Grant the credential

1. Back on the agent, open the **Grants** tab and choose **Grant
   credential**. (If it is disabled, no secret has a usage profile yet: go
   back to step 3.)
2. Pick the **Credential**.
3. Choose the **Actions**:
   - **Use** (recommended): Citadel injects the credential into requests the
     agent makes. The agent never sees it.
   - **Reveal** (marked *Risky*): the value is returned to the agent. Only
     for tools that can't work through Citadel, and for `get_login`.
   - **TOTP codes**: for a website login, the current one-time code.
4. Optionally limit it:
   - **From** / **Until**: when the grant is valid.
   - **Only at certain times**: a daily window in a time zone, optionally
     on some days.
   - **Uses per hour**: 0 means no limit.
   - For minted credentials, **Token restricted to**: narrower GitHub
     repositories and permissions, an AWS session policy, or OAuth scopes.
5. Choose **Grant**.

### Approval and leases

Tick **Requires approval** to have a person approve each use. The agent's
call is refused with `approval_required` and an access request appears in
**Approvals** (type *Agent access*) and on the agent's **Requests** tab. The
agent's owner or an account admin approves it **Once**, for a duration, or
for one task, which opens a **lease**; the agent then retries.

**Lease length (minutes)** caps how long an approval may last. Without
**Requires approval**, it makes the first use open a lease of that length,
so a burst of calls is grouped in the audit log. Leases are listed, and can
be revoked, on the agent's **Leases** tab. See
[Approvals and leases](agents.md#approvals-and-leases).

## Step 5: Connect an MCP client

Citadel's MCP server is at `https://<your-citadel>/mcp`. Replace
`https://citadel.example.com` below with your Citadel URL.

### Claude Code over HTTP

```sh
export CITADEL_AGENT_TOKEN=cagt_...
claude mcp add --transport http citadel https://citadel.example.com/mcp \
  --header "Authorization: Bearer ${CITADEL_AGENT_TOKEN}"
```

`claude mcp add` stores the expanded token in your settings. To keep it out
of the file, put the server in the project's `.mcp.json`, which Claude Code
expands when it starts:

```json
{
  "mcpServers": {
    "citadel": {
      "type": "http",
      "url": "https://citadel.example.com/mcp",
      "headers": { "Authorization": "Bearer ${CITADEL_AGENT_TOKEN}" }
    }
  }
}
```

### Claude Code through the stdio bridge

For clients that only start local servers, the TypeScript SDK ships a
bridge (Node.js 20 or later). It reads `CITADEL_AGENT_TOKEN` from the
environment:

```sh
claude mcp add citadel --env CITADEL_URL=https://citadel.example.com \
  -- npx -y @worlddrknss/citadel mcp
```

Check the connection with `claude mcp list`, or `/mcp` inside a session.
Claude Desktop, Cursor and VS Code are covered in
[Connecting MCP clients](agents-mcp.md).

### Without MCP

Anything that can make an HTTP request can use the Agent API directly:

```sh
curl -s https://citadel.example.com/v1/agent/http \
  -H "Authorization: Bearer $CITADEL_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credential": "github-pat", "method": "GET", "url": "https://api.github.com/user"}'
```

## Step 6: Try it

Ask the agent, in plain language:

- *"List the credentials you can use from Citadel."* It calls
  `list_credentials` and shows `github-pat` with its hosts and actions.
- *"Using the github-pat credential, get https://api.github.com/user and
  tell me my login."* It calls `http_request`:

  ```json
  { "credential": "github-pat", "method": "GET", "url": "https://api.github.com/user" }
  ```

  and gets back `{status, headers, body, ...}`, never the token.
- *"Get the CRM login for https://crm.example.com/login and the current
  one-time code."* (a website login) It calls `get_login` and
  `get_totp_code`.

The tools an agent sees follow its grants: `reveal_credential` and
`get_login` appear only with a **Reveal** grant, `get_totp_code` only with
a **TOTP codes** grant. A refused call comes back to the model as a tool
error starting with the reason (`host_not_allowed: ...`), so it can adjust;
the table below says what each reason means.

## Step 7: Watch what it does

### Activity and audit

The agent's **Activity** tab lists its requests, refusals and console
changes, and links to the **Audit log** filtered to the agent. Every
brokered request is recorded with the method, host and path (never the
query string, headers, bodies or the secret). Agents can send
`X-Citadel-Task-Id` to tie a task's requests together.

### Anomaly alerts

Citadel learns each agent's usual hosts, hours and rate from 14 days of
activity and flags a new host, off-hours use, a rate spike or repeated
refusals. Anomalies are listed on the **Activity** tab. Under **Anomaly
alerts** on the agent's **Overview**, **Send alerts** notifies the channels
subscribed to `agent.anomaly` (see [Notifications](notifications.md)), and
**Suspend automatically** suspends the agent on an anomaly. See
[Anomaly alerts](agents.md#anomaly-alerts).

### Kill switch

- **Suspend** one agent from its row menu on the Agents page, or from the
  agent's page. Every request it makes is refused until you **Resume** it,
  and its leases end. **Revoke** is permanent.
- Account admins can stop every agent at once: **Administration →
  Settings → AI agents → Suspend all agents**.
- If a token leaks, revoke it on the **Tokens** tab.

## Troubleshooting

Refusals carry a stable `reason`: in the JSON error of the Agent API, and
at the start of an MCP tool error.

| Reason | What it means | Fix |
| --- | --- | --- |
| `invalid_credential` (401) | The token is wrong or malformed. | Copy the whole `cagt_...` value again, or issue a new token. |
| `token_expired`, `token_revoked` (401) | The token expired or was revoked. | Issue a new token on the **Tokens** tab. |
| `agent_suspended` (403) | The agent is suspended (by a person, or by **Suspend automatically**). | Check its **Activity**, then **Resume** it. |
| `agent_revoked` (401) | The agent was revoked; this is permanent. | Create a new agent. |
| `agents_suspended` (403) | The account's kill switch is on. | An admin turns it off under **Administration → Settings → AI agents**. |
| `federation_required` (403) | The agent is set to **Require workload identity federation**, so tokens are refused. | Authenticate with a federation binding, or untick the setting on the agent's **Overview**. |
| `federation_no_match`, `federation_ambiguous` (401) | A workload identity token matched no binding, or more than one agent. | Check the binding's issuer, subject and audience; send `X-Citadel-Agent-Id` when one identity is bound to several agents. |
| `no_grant` (403) | The agent has no grant for that credential, or no credential has that name (the two look the same on purpose). | Check the name with `list_credentials`; grant the credential on the agent's **Grants** tab. |
| `action_not_granted` (403) | The grant doesn't include this action, e.g. a reveal with a use-only grant, or `get_totp_code` without **TOTP codes**. | Edit the grant's **Actions**, or use the credential through `http_request` instead of revealing it. |
| `not_yet_valid`, `grant_expired` (403) | Outside the grant's **From** / **Until**. | Edit the grant's dates. |
| `outside_window` (403) | Outside the grant's daily time window. | Wait for the window, or edit **Only at certain times** (check the time zone). |
| `rate_limited` (429) | The grant's **Uses per hour**, or the agent's request rate, was exceeded. | Wait for `Retry-After`, or raise **Uses per hour**. |
| `approval_required` (403) | The grant needs approval for each use; an access request was opened (`requestId`). | Approve it in **Approvals**, then retry. The agent can poll with `get_lease`. |
| `too_many_requests` (429) | The agent has 20 access requests waiting. | Approve or deny the pending requests on its **Requests** tab. |
| `credential_unavailable` (403) | The secret behind the credential was deleted or is scheduled for deletion. | Restore the secret, or point a new usage profile at another secret. |
| `host_not_allowed` (403) | The URL's host isn't in the profile's **Allowed hosts**. | Add the host (or a `*.example.com` wildcard) to the usage profile. |
| `path_not_allowed` (403) | The path isn't under one of the **Path prefixes**. | Add the prefix, or clear the list. |
| `method_not_allowed` (403) | The method isn't in **Allowed methods** (only `GET` by default). | Tick the method in the usage profile. |
| `scheme_not_allowed` (403) | A plain `http://` URL. | Use `https`, or tick **Allow plain http://** under **Network**. |
| `destination_blocked` (403) | The host resolves to a private, loopback, link-local or metadata address. | If that is intended, add the network under **Private networks allowed**. |
| `url_not_allowed` (403) | `get_login` for a page that matches none of the login's patterns. | Add the page to **Pages the login may be used on**. |
| `kind_not_brokerable` (400) | `http_request` with a **Website login** or **Raw value** credential. | Use `get_login` / `get_totp_code`, or reveal it with a **Reveal** grant. |
| `totp_sha1_unsupported` (409 when used, 400 when saved) | A SHA-1 TOTP seed, which FIPS 140-3 mode can't compute. | Use a SHA-256 or SHA-512 seed, or store the login without one. |
| `totp_not_configured` (409) | `get_totp_code` for a login without a seed. | Add the **TOTP seed** on the secret's **Agent access** tab. |
| `credential_invalid` (502) | The stored value doesn't fit the kind, e.g. basic auth that isn't `{"username", "password"}` JSON. | Fix the secret's value. |
| `token_unavailable` (502) | GitHub, the OAuth token endpoint or STS refused to mint a token; the message has its status and error code. | Check the App or installation ID, client ID and secret, token URL or role ARN. |
| `scope_invalid` (403) | The grant's token restriction no longer fits the credential. | Edit the grant's **Token restricted to**. |
| `upstream_unreachable`, `upstream_timeout` (502, 504) | Citadel couldn't reach the API, or it took longer than 30 seconds. | Check the URL and that Citadel can reach the host. |
| `broker_busy` (503) | Too many brokered requests in flight. | Retry shortly. |

Two problems that aren't refusals:

- **The Grant credential button is disabled.** No secret in the account has
  a usage profile yet. Do [step 3](#step-3-make-a-secret-usable-by-agents).
- **A tool is missing in the MCP client.** Tools follow the grants; see
  [Step 6](#step-6-try-it). Reconnect the client after changing grants.

All reasons, with their HTTP statuses, are in
[Credentials for AI agents](agents.md#errors).
