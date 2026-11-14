package sdkgotest_test

import (
	"context"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/servertest"
	citadel "github.com/worlddrknss/citadel/sdk/citadel/v2"
)

func TestAgentLoginsAndAnomalies(t *testing.T) {
	env := servertest.New(t)
	ctx := context.Background()
	editor := newClient(t, env, env.Editor)

	if _, err := editor.PutSecret(ctx, citadel.PutSecretInput{Project: "web", Env: "dev", Key: "LOGIN", Value: `{"username":"bot","password":"pw-1"}`}); err != nil {
		t.Fatal(err)
	}
	if err := editor.CreateAgentCredential(ctx, citadel.AgentCredentialInput{Name: "site", Project: "web", Env: "dev", Key: "LOGIN", Kind: "login",
		Login: &citadel.AgentLoginConfig{URLPatterns: []string{"https://site.example.com/"}}}); err != nil {
		t.Fatal(err)
	}
	seed := "otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8"
	st, err := editor.SetAgentLogin(ctx, citadel.AgentLoginInput{Name: "site", TOTPSeed: &seed})
	if err != nil || !st.HasTOTPSeed || st.Username != "bot" {
		t.Fatalf("SetAgentLogin = %+v, %v", st, err)
	}
	sha1 := "otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if _, err := editor.SetAgentLogin(ctx, citadel.AgentLoginInput{Name: "site", TOTPSeed: &sha1}); citadel.ErrorCode(err) != "totp_sha1_unsupported" {
		t.Fatalf("SHA-1 seed: %v", err)
	}
	if st, err := editor.GetAgentLogin(ctx, "site", true); err != nil || st.TOTP == nil || len(st.TOTP.Code) != 8 {
		t.Fatalf("GetAgentLogin = %+v, %v", st, err)
	}

	a, err := editor.CreateAgent(ctx, citadel.CreateAgentInput{Name: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := editor.PutAgentGrant(ctx, citadel.AgentGrantInput{AgentID: a.AgentID, Credential: "site", Actions: []string{"totp", "reveal"}}); err != nil {
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
	code, err := agent.AgentTOTPCode(ctx, "site")
	if err != nil || len(code.Code) != 8 || code.Algorithm != "SHA512" || code.ExpiresAt.IsZero() {
		t.Fatalf("AgentTOTPCode = %+v, %v", code, err)
	}
	login, err := agent.AgentGetLogin(ctx, "site", "https://site.example.com/login")
	if err != nil || login.Username != "bot" || login.Password != "pw-1" {
		t.Fatalf("AgentGetLogin = %+v, %v", login, err)
	}
	if _, err := agent.AgentGetLogin(ctx, "site", "https://elsewhere.example.com/"); citadel.ErrorCode(err) != "forbidden" {
		t.Fatalf("other page: %v", err)
	}
	creds, err := agent.AgentCredentials(ctx)
	if err != nil || len(creds) != 1 || creds[0].URLPatterns[0] != "https://site.example.com/" {
		t.Fatalf("AgentCredentials = %+v, %v", creds, err)
	}
	rev, err := agent.AgentReveal(ctx, "site")
	if err != nil || rev.Value != `{"username":"bot","password":"pw-1"}` || rev.ExpiresAt != nil {
		t.Fatalf("AgentReveal = %+v, %v", rev, err)
	}

	set, err := editor.SetAgentAnomalySettings(ctx, a.AgentID, citadel.AgentAnomalySettings{AlertsEnabled: true, AutoSuspend: true})
	if err != nil || !set.AutoSuspend {
		t.Fatalf("SetAgentAnomalySettings = %+v, %v", set, err)
	}
	an, err := editor.ListAgentAnomalies(ctx, a.AgentID)
	if err != nil || !an.Settings.AutoSuspend || len(an.Anomalies) != 0 || an.Baseline == nil {
		t.Fatalf("ListAgentAnomalies = %+v, %v", an, err)
	}
}
