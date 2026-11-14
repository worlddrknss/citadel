# Go SDK

`github.com/worlddrknss/citadel/sdk/citadel` is the Go client for Citadel's
native `/v1` API. It uses only the standard library and covers secrets,
parameters, KMS, certificates, workload identity, agent management and the
Agent API, access requests and leases, logins and TOTP, notification
channels, and audit retention and chain verification.

To choose between this SDK, the TypeScript SDK and the AWS SDKs, see
[SDKs and client libraries](sdks.md). For the AWS-compatible APIs, use
`aws-sdk-go-v2` with a custom endpoint instead
([AWS compatibility](aws-compatibility.md)).

Every example on this page is also an `Example` function in
[`sdk/citadel/example_test.go`](../sdk/citadel/example_test.go), so it is
compiled and vetted with the SDK's tests.

## Install

```sh
go get github.com/worlddrknss/citadel/sdk/citadel@main
```

Always name a version. The repository's module path has no `/v2` suffix, so
Go ignores the `v2.x.y` release tags, and a bare `go get
github.com/worlddrknss/citadel/sdk/citadel` resolves to the last `v1`
release, whose SDK predates most of this page. To pin a release, use its
commit instead of `main`:

```sh
git ls-remote https://github.com/worlddrknss/citadel.git 'refs/tags/v2.5.1^{}'   # the release's commit
go get github.com/worlddrknss/citadel/sdk/citadel@<commit>
```

Go records it as a pseudo-version such as `v1.33.2-0.20261113203938-3001f2142816`.
The SDK needs Go 1.26 or later. It imports only the standard library, so it
adds no other packages to your build.

## Configure

```go
c, err := citadel.New(citadel.Config{
	BaseURL:         "https://citadel.example.com",
	AccessKeyID:     "AKIAEXAMPLE",
	SecretAccessKey: "secret",
	Timeout:         10 * time.Second,
	MaxRetries:      5,
})
if err != nil {
	log.Fatal(err)
}
fmt.Println(c.BaseURL())
```

Empty fields fall back to the environment and defaults, so
`citadel.New(citadel.Config{})` works when the variables are set:

| Field | Variable | Default |
| --- | --- | --- |
| `BaseURL` | `CITADEL_URL` | `http://localhost:8080` |
| `AccessKeyID`, `SecretAccessKey` | `CITADEL_ACCESS_KEY_ID`, `CITADEL_SECRET_ACCESS_KEY` | none |
| `AgentToken` | `CITADEL_AGENT_TOKEN` (used only when no access key is set) | none |
| `Timeout` | | 30 s per attempt |
| `MaxRetries` | | 3; negative disables retries |
| `RetryBaseDelay`, `RetryMaxDelay` | | 200 ms and 5 s |
| `HTTPClient` | | a new `http.Client` |
| `UserAgent` | | appended to `citadel-go/<version>` |

`New` returns `ErrNoCredentials` when neither an access key nor an agent
token is configured. A `Client` is safe for concurrent use; create one and
share it.

**Which credential?** An access key (created under **My account → Access
keys**) acts with its owner's role in the key's account and works for
everything except the Agent API. An agent token (`cagt_...`) works only for
the Agent API: the methods named `Agent...` that act as the calling agent.
The SDK sends either as `Authorization: Bearer ...`. A federated token (an
OIDC token matching one of an agent's
[federation bindings](agents.md#workload-identity-federation)) can be passed
as `AgentToken` too. See [Authentication](sdks.md#authentication).

## Secrets

```go
c, err := citadel.New(citadel.Config{})
if err != nil {
	log.Fatal(err)
}
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
v, err := c.GetSecret(ctx, citadel.SecretRef{Project: "shop", Env: "prod", Path: "api", Key: "DATABASE_URL"}, nil)
switch {
case citadel.IsNotFound(err):
	log.Fatal("no such secret")
case err != nil:
	log.Fatal(err)
}
fmt.Println(len(v.Value) > 0)
```

`GetSecret` takes `*GetSecretOptions` for a `VersionID`, a `VersionStage`
such as `AWSPREVIOUS`, or `Resolve` to expand `${...}` references. Binary
secrets come back in `BinaryValue`. Each read is an audited reveal.

```go
// One folder: keys and metadata, never values.
listing, err := c.ListSecrets(context.Background(), "shop", "prod", "api")
if err != nil {
	log.Fatal(err)
}
for _, item := range listing.Items {
	fmt.Println(item.Key, item.Version, item.UpdatedAt)
}
fmt.Println("sub-folders:", listing.Folders)
```

Writing:

```go
_, err = c.PutSecret(context.Background(), citadel.PutSecretInput{
	Project: "shop", Env: "prod", Path: "api", Key: "DATABASE_URL", Value: "postgres://...",
})
if citadel.IsApprovalRequired(err) {
	// prod is protected: changes go through a change request.
	log.Fatal("submit a change request instead")
}
var apiErr *citadel.APIError
if errors.As(err, &apiErr) {
	log.Fatalf("Citadel said %s (%d): %s", apiErr.Code, apiErr.StatusCode, apiErr.Message)
}
```

`DeleteSecret` schedules deletion (pass `&DeleteSecretOptions{Force: true}`
to delete now), `RestoreSecret` cancels it, and `ListSecretVersions` lists
versions without values. `ListProjects`, `CreateProject`,
`CreateEnvironment`, `CreateFolder` and their `Delete...` counterparts manage
the hierarchy.

## Parameters, KMS, certificates and workload identity

```go
_, err = c.PutParameter(ctx, citadel.PutParameterInput{
	Name: "/shop/prod/region", Type: citadel.ParameterString, Value: "eu-west-1", Overwrite: true,
})
if err != nil {
	log.Fatal(err)
}
// Version 0 is the latest; SecureString values come back decrypted.
p, err := c.GetParameter(ctx, "/shop/prod/region", 0)
if err != nil {
	log.Fatal(err)
}
fmt.Println(p.Value, p.Version)
```

```go
encCtx := map[string]string{"tenant": "42"}
out, err := c.Encrypt(ctx, "alias/default", []byte("card number"), encCtx)
if err != nil {
	log.Fatal(err)
}
plaintext, err := c.Decrypt(ctx, "alias/default", out.CiphertextBlob, encCtx)
if err != nil {
	log.Fatal(err)
}
fmt.Println(string(plaintext))
```

```go
tok, err := c.IssueWorkloadToken(context.Background(), citadel.WorkloadTokenInput{
	ClientID: "wic-123", Audience: "sts.amazonaws.com", TTL: 15 * time.Minute,
})
if err != nil {
	log.Fatal(err)
}
fmt.Println(tok.ExpiresAt.After(time.Now()))
```

Also available: `ListParameters`, `DeleteParameter`, `ParameterHistory`,
`ListKeys`, `ListCertificates`, `GetCertificate`, `IssueCertificate` (sign a
CSR) and `IssueGeneratedCertificate` (Citadel generates the key pair and
returns the private key once).

## Agents: management

With an access key, set up an agent, its token, a usage profile for a
secret, and a grant. See [Credentials for AI agents](agents.md) for the
concepts.

```go
c, err := citadel.New(citadel.Config{}) // an editor's access key
if err != nil {
	log.Fatal(err)
}
ctx := context.Background()

agent, err := c.CreateAgent(ctx, citadel.CreateAgentInput{
	Name: "release-bot", Description: "Tags releases", Labels: map[string]string{"team": "platform"},
})
if err != nil {
	log.Fatal(err)
}
tok, err := c.CreateAgentToken(ctx, agent.AgentID, "ci", 30) // expires in 30 days
if err != nil {
	log.Fatal(err)
}
// tok.Token (cagt_...) is shown only once: store it where the agent runs.
_ = tok.Token

err = c.CreateAgentCredential(ctx, citadel.AgentCredentialInput{
	Name:    "github-pat",
	Project: "shop", Env: "prod", Path: "ci", Key: "GITHUB_TOKEN",
	Kind:           "http_header",
	AllowedHosts:   []string{"api.github.com"},
	AllowedMethods: []string{"GET", "POST"},
	HeaderName:     "Authorization",
	HeaderPrefix:   "Bearer ",
})
if err != nil {
	log.Fatal(err)
}
grantID, err := c.PutAgentGrant(ctx, citadel.AgentGrantInput{
	AgentID:        agent.AgentID,
	Credential:     "github-pat",
	Actions:        []string{"use"},
	MaxUsesPerHour: 100,
})
if err != nil {
	log.Fatal(err)
}
fmt.Println(agent.AgentID, grantID)

// Stop one agent, or (admin) every agent in the account.
if _, err := c.SuspendAgent(ctx, agent.AgentID, "investigating"); err != nil {
	log.Fatal(err)
}
if err := c.SetAgentsSuspended(ctx, true, "incident 42"); err != nil {
	log.Fatal(err)
}
```

`AgentGrantInput` also takes `NotBefore`, `NotAfter`, a time-of-day
`Window`, `RequiresApproval` and `LeaseTTLSeconds` (approvals, 2.3), and a
`Scope` that narrows minted tokens (2.4). `AgentCredentialInput` takes the
kind's settings in `Login`, `AWSSTS`, `GitHubApp` or `OAuth2`. Other
management calls: `ListAgents`, `ResumeAgent`, `RevokeAgent`, `DeleteAgent`,
`RevokeAgentToken`, `ListAgentAnomalies` and `SetAgentAnomalySettings`.

### Logins for browser agents

```go
err = c.CreateAgentCredential(ctx, citadel.AgentCredentialInput{
	Name: "acme-admin", Project: "shop", Env: "prod", Key: "ACME_ADMIN_LOGIN", Kind: "login",
	Login: &citadel.AgentLoginConfig{URLPatterns: []string{"https://admin.acme.example"}},
})
if err != nil {
	log.Fatal(err)
}
user, pass := "bot@acme.example", os.Getenv("ACME_PASSWORD")
seed := os.Getenv("ACME_TOTP_URI") // otpauth://totp/...?secret=...&algorithm=SHA256
state, err := c.SetAgentLogin(ctx, citadel.AgentLoginInput{Name: "acme-admin", Username: &user, Password: &pass, TOTPSeed: &seed})
if err != nil {
	log.Fatal(err)
}
fmt.Println(state.HasPassword, state.HasTOTPSeed, state.TOTPStatus)
```

SHA-1 TOTP seeds are refused: Citadel runs in FIPS 140-3 mode. `GetAgentLogin`
reads the login's state (never the password) and, with `withCode`, its
current code.

### Access requests and leases

People approve and deny access requests in the console only; access keys
can't decide them. With an access key you can list requests and leases and
revoke leases:

```go
pending, err := c.ListAgentAccessRequests(ctx, "", true)
if err != nil {
	log.Fatal(err)
}
fmt.Println(len(pending), "requests waiting in the console's Approvals inbox")

leases, err := c.ListAgentLeases(ctx, "", true)
if err != nil {
	log.Fatal(err)
}
for _, l := range leases {
	if l.Credential == "deploy-key" {
		if _, err := c.RevokeAgentLease(ctx, l.LeaseID, "release finished"); err != nil {
			log.Fatal(err)
		}
	}
}
```

## Agents: the Agent API

Configured with an agent token, the client acts as the agent:

```go
c, err := citadel.New(citadel.Config{
	BaseURL:    "https://citadel.example.com",
	AgentToken: os.Getenv("CITADEL_AGENT_TOKEN"), // also read automatically when no access key is set
})
if err != nil {
	log.Fatal(err)
}
ctx := context.Background()
me, err := c.AgentWhoAmI(ctx)
if err != nil {
	log.Fatal(err)
}
fmt.Println("agent", me.Name, "via", me.AuthMethod)

creds, err := c.AgentCredentials(ctx)
if err != nil {
	log.Fatal(err)
}
for _, cr := range creds {
	fmt.Println(cr.Name, cr.Kind, cr.Actions, cr.Usable, cr.Reason)
}
```

The Go SDK has no method for brokered HTTP (`POST /v1/agent/http`). Call it
with `net/http` and the same bearer token (see
[Using a credential: brokered HTTP](agents.md#using-a-credential-brokered-http)),
or use the MCP server's `http_request` tool.

### Approval, then reveal

```go
c, err := citadel.New(citadel.Config{}) // CITADEL_AGENT_TOKEN
if err != nil {
	log.Fatal(err)
}
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
defer cancel()

// Asking again while a request is pending returns the same request,
// which is also how to find the request behind an approval_required
// error.
req, err := c.AgentRequestAccess(ctx, citadel.AgentAccessInput{
	Credential: "deploy-key",
	Actions:    []string{"reveal"},
	Reason:     "Tag the release; the pipeline needs the deploy key",
	Duration:   15 * time.Minute,
	TaskID:     "release-42",
})
if err != nil {
	log.Fatal(err)
}
approved, err := c.WaitForAgentAccess(ctx, req.RequestID, 5*time.Second)
if errors.Is(err, citadel.ErrAccessDenied) {
	log.Fatalf("access %s: %s", approved.Status, approved.DecisionComment)
} else if err != nil {
	log.Fatal(err)
}

// The reveal is made under the approval's lease.
v, err := c.AgentReveal(ctx, "deploy-key")
if err != nil {
	log.Fatal(err)
}
fmt.Println(len(v.Value) > 0, v.LeaseID, v.LeaseExpiresAt)
```

`AgentReveal` needs a grant with `reveal` (or an approved lease); prefer
brokered use when the agent only calls an API. Minted credentials reveal a
short-lived token with `ExpiresAt`. `AgentLeases` lists the agent's active
leases.

### Logins and TOTP

```go
login, err := c.AgentGetLogin(ctx, "acme-admin", "https://admin.acme.example/login") // reveal grant
if err != nil {
	log.Fatal(err)
}
code, err := c.AgentTOTPCode(ctx, "acme-admin") // totp grant
if err != nil {
	log.Fatal(err)
}
fmt.Println(login.Username, code.Code, code.SecondsRemaining)
```

## Notifications

Notification channels need an admin's access key:

```go
saved, err := c.CreateNotificationChannel(ctx, citadel.CreateNotificationChannelInput{
	Name:   "ops webhook",
	Type:   citadel.NotificationWebhook,
	URL:    "https://hooks.example.com/citadel",
	Events: []string{citadel.EventAgentApprovalRequested, citadel.EventAgentAnomaly, citadel.EventSecurityKillSwitch},
})
if err != nil {
	log.Fatal(err)
}
// The signing secret is returned once: store it with the receiver.
_ = saved.SigningSecret

eventID, err := c.TestNotificationChannel(ctx, saved.Channel.ID)
if err != nil {
	log.Fatal(err)
}
deliveries, err := c.ListNotificationDeliveries(ctx, saved.Channel.ID, 10)
if err != nil {
	log.Fatal(err)
}
fmt.Println(eventID, len(deliveries))
```

Also: `ListNotificationChannels` (with the event catalog),
`UpdateNotificationChannel`, `DeleteNotificationChannel`,
`RotateNotificationSigningSecret` and `RetryNotificationDelivery`. Event
types and payloads are in [Notifications](notifications.md).

### Verifying webhook signatures

Webhook deliveries carry `X-Citadel-Signature: t=<unix>,v1=<hex>`, an
HMAC-SHA256 of `<t>.<body>` with the channel's signing secret.
`VerifyNotificationSignature` checks it against the raw body and rejects
timestamps more than five minutes away (pass a tolerance to change that):

```go
secret := os.Getenv("CITADEL_WEBHOOK_SECRET")
http.HandleFunc("/citadel", func(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := citadel.VerifyNotificationSignature(secret, r.Header.Get("X-Citadel-Signature"), body, 0); err != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var ev citadel.NotificationEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch ev.Type {
	case citadel.EventAgentApprovalRequested:
		// Page the approver, open a ticket...
	case citadel.EventSecurityKillSwitch:
		// ...
	}
	w.WriteHeader(http.StatusNoContent)
})
```

Verify before parsing, and pass the body exactly as received: re-encoded
JSON doesn't match the signature. If the header carries more than one `v1`
signature, any one that matches passes.

## Audit retention and chain verification

```go
c, err := citadel.New(citadel.Config{}) // an admin's access key
if err != nil {
	log.Fatal(err)
}
ctx := context.Background()
cur, err := c.GetAuditRetention(ctx)
if err != nil {
	log.Fatal(err)
}
fmt.Println("retention:", cur.RetentionDays, "days, from", cur.Source)

preview, err := c.PreviewAuditRetention(ctx, 365)
if err != nil {
	log.Fatal(err)
}
fmt.Println(preview.PrunableEvents, "of", preview.Events, "events would be pruned")

days := 365
if _, err := c.SetAuditRetention(ctx, &days); err != nil { // nil: back to the deployment default
	log.Fatal(err)
}

status, err := c.VerifyAuditChain(ctx)
if err != nil {
	log.Fatal(err)
}
fmt.Println(status.Status, status.VerifiedThrough)
```

Retention is 0 (keep forever) or 7 to 3650 days. `VerifyAuditChain` returns
`verified`, `broken` (with `BrokenAt`) or `never`; after pruning it starts
from the signed `Anchor`. See [Audit log and retention](audit.md).

## Errors, retries and timeouts

Failed calls return an `*citadel.APIError` with the HTTP status
(`StatusCode`), the API's stable error code (`Code`), its `Message`, the
`Method` and `Path`, and the server's `RetryAfter` hint. Branch on the code,
never on the message:

```go
_, err = c.GetSecret(context.Background(), citadel.SecretRef{Project: "shop", Env: "prod", Key: "MISSING"}, nil)
switch citadel.ErrorCode(err) {
case "":
	// nil, or not an API error (network, context): check err itself.
case citadel.CodeNotFound:
	fmt.Println("no such secret")
case citadel.CodeRevealForbidden:
	fmt.Println("viewers can't read values in this account")
default:
	log.Fatal(err)
}
```

The helpers `IsNotFound`, `IsUnauthorized`, `IsForbidden`,
`IsApprovalRequired` and `IsRateLimited` work on wrapped errors too, and
the `Code...` constants name the common codes. Agent API refusals carry a
`reason` (such as `no_grant`) that `APIError` doesn't expose: `Code` is the
general code (`forbidden`) and `Message` explains. `approval_required` is
its own code; `AgentRequestAccess` returns the pending request to wait on.

Retries and timeouts:

- 429, 502, 503 and 504 are retried for every method; 500 and network
  errors only for GET and HEAD, since a write may already have happened.
- Backoff is exponential with full jitter (`RetryBaseDelay`,
  `RetryMaxDelay`); a `Retry-After` header takes precedence, capped at
  `RetryMaxDelay`. `MaxRetries` defaults to 3.
- `Timeout` bounds each attempt. The context you pass bounds the whole call,
  retries included.

## Tests

The SDK's tests run against the real Citadel server over the in-memory
store, so they check real API behaviour:

```sh
go test ./sdk/citadel/
```
