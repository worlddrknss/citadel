package citadel_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/servertest"
	"github.com/worlddrknss/citadel/sdk/citadel"
)

// TestAgentHTTP drives brokered HTTP against the real server and a local
// upstream (allowed through the credential's allowHttp and allowedCidrs).
func TestAgentHTTP(t *testing.T) {
	const secret = "s3cret-token-value"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "no credential", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/echo":
			w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
			w.Header().Set("X-Method", r.Method)
			_, _ = w.Write(body)
		case "/leak":
			_, _ = w.Write([]byte("token=" + secret))
		case "/binary":
			_, _ = w.Write([]byte{0, 1, 0xfe, 0xff})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "http://")

	env := servertest.New(t)
	ctx := context.Background()
	editor := newClient(t, env, env.Editor)
	a, err := editor.CreateAgent(ctx, citadel.CreateAgentInput{Name: "broker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.CreateProject(ctx, "app", "App"); err != nil {
		t.Fatal(err)
	}
	if err := editor.CreateEnvironment(ctx, "app", "development", "Development"); err != nil {
		t.Fatal(err)
	}
	if _, err := editor.PutSecret(ctx, citadel.PutSecretInput{Project: "app", Env: "development", Key: "API_TOKEN", Value: secret}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"upstream", "gated"} {
		if err := editor.CreateAgentCredential(ctx, citadel.AgentCredentialInput{Name: name, Project: "app", Env: "development", Key: "API_TOKEN",
			Kind: "http_header", HeaderPrefix: "Bearer ", AllowedHosts: []string{host}, AllowedMethods: []string{"GET", "POST"}, AllowHTTP: true, AllowedCIDRs: []string{"127.0.0.1/32"}}); err != nil {
			t.Fatalf("CreateAgentCredential %s: %v", name, err)
		}
	}
	if _, err := editor.PutAgentGrant(ctx, citadel.AgentGrantInput{AgentID: a.AgentID, Credential: "upstream"}); err != nil {
		t.Fatal(err)
	}
	if _, err := editor.PutAgentGrant(ctx, citadel.AgentGrantInput{AgentID: a.AgentID, Credential: "gated", RequiresApproval: true}); err != nil {
		t.Fatal(err)
	}
	tok, err := editor.CreateAgentToken(ctx, a.AgentID, "ci", 1)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := citadel.New(citadel.Config{BaseURL: env.URL, AgentToken: tok.Token, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := agent.AgentHTTP(ctx, citadel.AgentHTTPRequest{Credential: "upstream", Method: "POST", URL: upstream.URL + "/echo",
		JSON: map[string]string{"hello": "world"}, TaskID: "task-1"})
	if err != nil || !resp.OK() || resp.Header["X-Method"] != "POST" {
		t.Fatalf("AgentHTTP echo = %+v, %v", resp, err)
	}
	var echoed map[string]string
	if err := resp.JSON(&echoed); err != nil || echoed["hello"] != "world" {
		t.Fatalf("echoed %q: %v", resp.Text(), err)
	}

	resp, err = agent.AgentHTTP(ctx, citadel.AgentHTTPRequest{Credential: "upstream", URL: upstream.URL + "/leak"})
	if err != nil || !resp.Redacted || strings.Contains(resp.Text(), secret) {
		t.Fatalf("AgentHTTP leak = %+v, %v", resp, err)
	}
	resp, err = agent.AgentHTTP(ctx, citadel.AgentHTTPRequest{Credential: "upstream", URL: upstream.URL + "/binary"})
	if err != nil || string(resp.Body) != string([]byte{0, 1, 0xfe, 0xff}) {
		t.Fatalf("AgentHTTP binary = %+v, %v", resp, err)
	}
	// An upstream error status is a successful brokered call.
	resp, err = agent.AgentHTTP(ctx, citadel.AgentHTTPRequest{Credential: "upstream", URL: upstream.URL + "/missing"})
	if err != nil || resp.Status != http.StatusNotFound || resp.OK() {
		t.Fatalf("AgentHTTP 404 = %+v, %v", resp, err)
	}

	// Denials carry the reason.
	_, err = agent.AgentHTTP(ctx, citadel.AgentHTTPRequest{Credential: "upstream", URL: "https://elsewhere.example.com/"})
	var apiErr *citadel.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden || apiErr.Reason != "host_not_allowed" {
		t.Fatalf("other host err = %#v", err)
	}
	if _, err := agent.AgentHTTP(ctx, citadel.AgentHTTPRequest{Credential: "nope", URL: upstream.URL + "/echo"}); citadel.ErrorReason(err) != "no_grant" {
		t.Fatalf("no grant err = %v", err)
	}

	// A grant that requires approval answers with the request to wait for.
	_, err = agent.AgentHTTP(ctx, citadel.AgentHTTPRequest{Credential: "gated", URL: upstream.URL + "/echo"})
	requestID, ok := citadel.ApprovalRequestID(err)
	if !ok || requestID == "" || citadel.ErrorReason(err) != "approval_required" {
		t.Fatalf("gated err = %v", err)
	}
	req, err := agent.AgentAccessRequest(ctx, requestID)
	if err != nil || req.Status != citadel.AccessRequestPending || req.Credential != "gated" || req.Origin != "policy" {
		t.Fatalf("AgentAccessRequest = %+v, %v", req, err)
	}
}
