package citadel_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	citadel "github.com/worlddrknss/citadel/sdk/citadel/v2"
)

func ExampleNew() {
	// Empty fields fall back to CITADEL_URL, CITADEL_ACCESS_KEY_ID and
	// CITADEL_SECRET_ACCESS_KEY.
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
	// Output: https://citadel.example.com
}

func ExampleClient_GetSecret() {
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
}

func ExampleClient_PutSecret() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
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
}

func ExampleClient_Encrypt() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
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
}

func ExampleClient_IssueWorkloadToken() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	tok, err := c.IssueWorkloadToken(context.Background(), citadel.WorkloadTokenInput{
		ClientID: "wic-123", Audience: "sts.amazonaws.com", TTL: 15 * time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tok.ExpiresAt.After(time.Now()))
}

// The examples below are the ones in docs/sdk-go.md; change both together.

func ExampleClient_ListSecrets() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	// One folder: keys and metadata, never values.
	listing, err := c.ListSecrets(context.Background(), "shop", "prod", "api")
	if err != nil {
		log.Fatal(err)
	}
	for _, item := range listing.Items {
		fmt.Println(item.Key, item.Version, item.UpdatedAt)
	}
	fmt.Println("sub-folders:", listing.Folders)
}

func ExampleClient_GetParameter() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
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
}

// Setting up an agent with an access key: the agent, its token, a usage
// profile for a secret, and a grant.
func Example_agentManagement() {
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
}

// The Agent API takes an agent token instead of an access key.
func ExampleClient_AgentCredentials() {
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
}

func ExampleClient_WaitForAgentAccess() {
	c, err := citadel.New(citadel.Config{}) // CITADEL_AGENT_TOKEN
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Ask for access the agent has no grant for. (For a grant with
	// requiresApproval, the refusal names the request: see
	// ExampleApprovalRequestID.)
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
}

// Brokered HTTP: Citadel makes the request with the credential injected,
// so the agent never holds the secret.
func ExampleClient_AgentHTTP() {
	c, err := citadel.New(citadel.Config{}) // CITADEL_AGENT_TOKEN
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	res, err := c.AgentHTTP(ctx, citadel.AgentHTTPRequest{
		Credential: "github-pat",
		URL:        "https://api.github.com/user/repos",
		Header:     map[string]string{"Accept": "application/vnd.github+json"},
		TaskID:     "fix-issue-1234",
	})
	if err != nil {
		// Refusals carry a stable reason: no_grant, host_not_allowed,
		// destination_blocked, upstream_timeout...
		log.Fatalf("refused (%s): %v", citadel.ErrorReason(err), err)
	}
	// An upstream error status is a successful brokered call.
	if !res.OK() {
		log.Fatalf("GitHub answered %d: %s", res.Status, res.Text())
	}
	var repos []struct {
		FullName string `json:"full_name"`
	}
	if err := res.JSON(&repos); err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(repos), "repositories; redacted:", res.Redacted)

	// A JSON body (JSON), or Body: text is sent as is, other bytes base64.
	created, err := c.AgentHTTP(ctx, citadel.AgentHTTPRequest{
		Credential: "github-pat",
		Method:     "POST",
		URL:        "https://api.github.com/repos/acme/app/issues",
		JSON:       map[string]string{"title": "Flaky test in CI"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(created.Status)
}

// A grant with requiresApproval refuses with approval_required and the
// access request it opened: wait for it, then retry under the lease.
func ExampleApprovalRequestID() {
	c, err := citadel.New(citadel.Config{}) // CITADEL_AGENT_TOKEN
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	v, err := c.AgentReveal(ctx, "deploy-key")
	if requestID, ok := citadel.ApprovalRequestID(err); ok && requestID != "" {
		approved, werr := c.WaitForAgentAccess(ctx, requestID, 5*time.Second)
		if werr != nil {
			log.Fatalf("not approved (%v): %s", werr, approved.DecisionComment)
		}
		v, err = c.AgentReveal(ctx, "deploy-key")
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(v.Value) > 0, v.LeaseID)
}

// Brokered calls are POSTs, so the client doesn't repeat them after a 500,
// 502, 504 or a timeout: the upstream may already have acted. Opt in for an
// upstream call that is safe to repeat.
func ExampleWithRetryNonIdempotent() {
	c, err := citadel.New(citadel.Config{}) // CITADEL_AGENT_TOKEN
	if err != nil {
		log.Fatal(err)
	}
	ctx := citadel.WithRetryNonIdempotent(context.Background())
	res, err := c.AgentHTTP(ctx, citadel.AgentHTTPRequest{
		Credential: "payments",
		Method:     "POST",
		URL:        "https://pay.example.com/charges",
		Header:     map[string]string{"Idempotency-Key": "order-42"},
		JSON:       map[string]int{"amount": 100},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Status)
}

// Browser agents: a login's username and password for one page, and its
// current TOTP code.
func ExampleClient_AgentGetLogin() {
	c, err := citadel.New(citadel.Config{}) // CITADEL_AGENT_TOKEN
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	login, err := c.AgentGetLogin(ctx, "acme-admin", "https://admin.acme.example/login") // reveal grant
	if err != nil {
		log.Fatal(err)
	}
	code, err := c.AgentTOTPCode(ctx, "acme-admin") // totp grant
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(login.Username, code.Code, code.SecondsRemaining)
}

// Storing a website login (username, password and TOTP seed) for browser
// agents.
func ExampleClient_SetAgentLogin() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
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
}

func ExampleClient_RevokeAgentLease() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
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
}

func ExampleClient_CreateNotificationChannel() {
	c, err := citadel.New(citadel.Config{}) // an admin's access key
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
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
}

func ExampleVerifyNotificationSignature() {
	secret := "whsec_0123456789abcdef0123456789abcdef"
	body := []byte(`{"id":"evt_1","type":"test"}`)

	// What Citadel sends in X-Citadel-Signature:
	// t=<unix>,v1=hex(HMAC-SHA256(secret, "<t>.<body>")).
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	header := "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))

	fmt.Println(citadel.VerifyNotificationSignature(secret, header, body, 0))
	fmt.Println(citadel.VerifyNotificationSignature("whsec_a_different_secret_value", header, body, 0))
	// Output:
	// <nil>
	// citadel: invalid notification signature
}

// A webhook receiver: verify the raw body before trusting it.
func ExampleNotificationEvent() {
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
}

func ExampleClient_SetAuditRetention() {
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
}

func ExampleErrorCode() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
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
}
