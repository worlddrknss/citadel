package sdkgotest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/servertest"
	citadel "github.com/worlddrknss/citadel/sdk/citadel/v2"
)

func TestAgents(t *testing.T) {
	env := servertest.New(t)
	ctx := context.Background()
	admin := newClient(t, env, env.Admin)
	editor := newClient(t, env, env.Editor)

	a, err := editor.CreateAgent(ctx, citadel.CreateAgentInput{Name: "coder", Labels: map[string]string{"team": "ml"}})
	if err != nil || a.Status != "active" || !a.CanManage || a.Owner == "" {
		t.Fatalf("CreateAgent = %+v, %v", a, err)
	}
	if err := editor.CreateProject(ctx, "app", "App"); err != nil {
		t.Fatal(err)
	}
	if err := editor.CreateEnvironment(ctx, "app", "development", "Development"); err != nil {
		t.Fatal(err)
	}
	if _, err := editor.PutSecret(ctx, citadel.PutSecretInput{Project: "app", Env: "development", Key: "API_TOKEN", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := editor.CreateAgentCredential(ctx, citadel.AgentCredentialInput{Name: "api", Project: "app", Env: "development", Key: "API_TOKEN",
		Kind: "http_header", AllowedHosts: []string{"api.example.com"}, HeaderPrefix: "Bearer "}); err != nil {
		t.Fatalf("CreateAgentCredential: %v", err)
	}
	if _, err := editor.PutAgentGrant(ctx, citadel.AgentGrantInput{AgentID: a.AgentID, Credential: "api", MaxUsesPerHour: 10,
		Window: &citadel.AgentGrantWindow{Start: "00:00", End: "00:00", Timezone: "UTC"}}); err != nil {
		t.Fatalf("PutAgentGrant: %v", err)
	}
	tok, err := editor.CreateAgentToken(ctx, a.AgentID, "ci", 7)
	if err != nil || !strings.HasPrefix(tok.Token, "cagt_"+a.AgentID+"_") || tok.ExpiresAt == nil || tok.TokenID == "" {
		t.Fatalf("CreateAgentToken = %+v, %v", tok, err)
	}

	agent, err := citadel.New(citadel.Config{BaseURL: env.URL, AgentToken: tok.Token, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	who, err := agent.AgentWhoAmI(ctx)
	if err != nil || who.AgentID != a.AgentID || who.AuthMethod != "token" {
		t.Fatalf("AgentWhoAmI = %+v, %v", who, err)
	}
	creds, err := agent.AgentCredentials(ctx)
	if err != nil || len(creds) != 1 || creds[0].Name != "api" || !creds[0].Usable {
		t.Fatalf("AgentCredentials = %+v, %v", creds, err)
	}
	// An agent token is not a console credential.
	if _, err := agent.ListAgents(ctx); err == nil {
		t.Fatal("agent token listed agents")
	}

	if _, err := editor.SuspendAgent(ctx, a.AgentID, "test"); err != nil {
		t.Fatal(err)
	}
	var apiErr *citadel.APIError
	if _, err := agent.AgentWhoAmI(ctx); !errors.As(err, &apiErr) || apiErr.StatusCode != 403 {
		t.Fatalf("suspended whoami err = %v", err)
	}
	if _, err := editor.ResumeAgent(ctx, a.AgentID); err != nil {
		t.Fatal(err)
	}
	if err := editor.SetAgentsSuspended(ctx, true, "drill"); err == nil {
		t.Fatal("editor flipped the kill switch")
	}
	if err := admin.SetAgentsSuspended(ctx, true, "drill"); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.AgentWhoAmI(ctx); err == nil {
		t.Fatal("kill switch ignored")
	}
	if err := admin.SetAgentsSuspended(ctx, false, ""); err != nil {
		t.Fatal(err)
	}
	if err := editor.RevokeAgentToken(ctx, a.AgentID, tok.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.AgentWhoAmI(ctx); err == nil {
		t.Fatal("revoked token accepted")
	}
	list, err := admin.ListAgents(ctx)
	if err != nil || len(list) != 1 || list[0].GrantCount != 1 {
		t.Fatalf("ListAgents = %+v, %v", list, err)
	}
	if _, err := editor.RevokeAgent(ctx, a.AgentID, "done"); err != nil {
		t.Fatal(err)
	}
	if err := editor.DeleteAgent(ctx, a.AgentID); err != nil {
		t.Fatal(err)
	}
}
