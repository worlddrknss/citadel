package storetest

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// AgentMintedStore runs the contract tests for the 2.4 agent additions:
// credential configs, grant scopes and anomaly settings and records.
func AgentMintedStore(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("ConfigAndScope", func(t *testing.T) { testAgentConfigScope(t, newStore(t)) })
	t.Run("AnomalySettings", func(t *testing.T) { testAgentAnomalySettings(t, newStore(t)) })
	t.Run("Anomalies", func(t *testing.T) { testAgentAnomalies(t, newStore(t)) })
}

func testAgentConfigScope(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "minter", now))
	c := store.AgentCredential{
		AccountID: AccountA, Name: "gh-app", SecretName: "app/prod/GH_APP_KEY", Kind: store.AgentCredentialGitHubApp,
		AllowedHosts: []string{"api.github.com"}, CreatedAt: now, UpdatedAt: now,
		Config: store.AgentCredentialConfig{GitHubApp: &store.AgentGitHubAppConfig{
			AppID: "12345", InstallationID: 678, Repositories: []string{"api", "web"}, Permissions: map[string]string{"contents": "write"},
		}},
	}
	if err := st.CreateAgentCredential(ctx, c); err != nil {
		t.Fatalf("CreateAgentCredential: %v", err)
	}
	got, err := st.GetAgentCredential(ctx, AccountA, "gh-app")
	if err != nil || !reflect.DeepEqual(got.Config, c.Config) {
		t.Fatalf("GetAgentCredential config = %+v, %v", got.Config, err)
	}
	// The returned config is a copy.
	got.Config.GitHubApp.Repositories[0] = "mutated"
	again, _ := st.GetAgentCredential(ctx, AccountA, "gh-app")
	if again.Config.GitHubApp.Repositories[0] != "api" {
		t.Fatal("config shares memory with the store")
	}
	upd := c
	upd.Kind = store.AgentCredentialLogin
	upd.Config = store.AgentCredentialConfig{Login: &store.AgentLoginConfig{URLPatterns: []string{"https://app.example.com/login"}, TOTPAlgorithm: "SHA256"}}
	if err := st.UpdateAgentCredential(ctx, upd); err != nil {
		t.Fatalf("UpdateAgentCredential: %v", err)
	}
	got, _ = st.GetAgentCredential(ctx, AccountA, "gh-app")
	if got.Config.GitHubApp != nil || got.Config.Login == nil || got.Config.Login.URLPatterns[0] != "https://app.example.com/login" {
		t.Fatalf("after update config = %+v", got.Config)
	}
	list, _ := st.ListAgentCredentials(ctx, AccountA)
	if len(list) != 1 || list[0].Config.Login == nil {
		t.Fatalf("ListAgentCredentials = %+v", list)
	}

	g := store.AgentGrant{
		AccountID: AccountA, GrantID: store.NewAgentObjectID("agr_"), AgentID: a.AgentID, Credential: "gh-app", Actions: []string{"use"},
		Scope:     store.AgentGrantScope{Repositories: []string{"api"}, Permissions: map[string]string{"contents": "read"}, Scopes: []string{"read"}},
		CreatedAt: now, UpdatedAt: now,
	}
	stored, err := st.PutAgentGrant(ctx, g)
	if err != nil || !reflect.DeepEqual(stored.Scope, g.Scope) {
		t.Fatalf("PutAgentGrant scope = %+v, %v", stored.Scope, err)
	}
	g.Scope = store.AgentGrantScope{SessionPolicy: `{"Version":"2012-10-17"}`}
	if stored, err = st.PutAgentGrant(ctx, g); err != nil || stored.Scope.SessionPolicy == "" || len(stored.Scope.Repositories) != 0 {
		t.Fatalf("PutAgentGrant replace scope = %+v, %v", stored.Scope, err)
	}
	grants, _ := st.ListAgentGrants(ctx, AccountA, a.AgentID)
	if len(grants) != 1 || grants[0].Scope.SessionPolicy != `{"Version":"2012-10-17"}` {
		t.Fatalf("ListAgentGrants = %+v", grants)
	}
	// A plain credential reads back with an empty config.
	plain := store.AgentCredential{AccountID: AccountA, Name: "plain", SecretName: "x", Kind: store.AgentCredentialRaw, CreatedAt: now, UpdatedAt: now}
	if err := st.CreateAgentCredential(ctx, plain); err != nil {
		t.Fatalf("CreateAgentCredential(plain): %v", err)
	}
	if got, _ := st.GetAgentCredential(ctx, AccountA, "plain"); !reflect.DeepEqual(got.Config, store.AgentCredentialConfig{}) {
		t.Fatalf("plain config = %+v", got.Config)
	}
}

func testAgentAnomalySettings(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "watched", now))
	got, err := st.GetAgentAnomalySettings(ctx, AccountA, a.AgentID)
	if err != nil || got.AlertsDisabled || got.AutoSuspend || got.AgentID != a.AgentID {
		t.Fatalf("default settings = %+v, %v", got, err)
	}
	in := store.AgentAnomalySettings{AccountID: AccountA, AgentID: a.AgentID, AlertsDisabled: true, AutoSuspend: true, UpdatedAt: now, UpdatedBy: "alice"}
	if err := st.PutAgentAnomalySettings(ctx, in); err != nil {
		t.Fatalf("PutAgentAnomalySettings: %v", err)
	}
	got, _ = st.GetAgentAnomalySettings(ctx, AccountA, a.AgentID)
	if !got.AlertsDisabled || !got.AutoSuspend || got.UpdatedBy != "alice" || !got.UpdatedAt.Equal(now) {
		t.Fatalf("settings = %+v", got)
	}
	if got, _ := st.GetAgentAnomalySettings(ctx, AccountB, a.AgentID); got.AutoSuspend {
		t.Fatal("settings leak across accounts")
	}
	in.AccountID = AccountB
	if err := st.PutAgentAnomalySettings(ctx, in); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("settings for an agent in another account: %v", err)
	}
}

func testAgentAnomalies(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	hour := now.Truncate(time.Hour)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "spiky", now))
	first := store.AgentAnomaly{AccountID: AccountA, AgentID: a.AgentID, AnomalyID: "aan_1", Kind: store.AgentAnomalyNewHost, Detail: "host=evil.example", Hour: hour, DetectedAt: now}
	if err := st.RecordAgentAnomaly(ctx, first); err != nil {
		t.Fatalf("RecordAgentAnomaly: %v", err)
	}
	dup := first
	dup.AnomalyID = "aan_2"
	if err := st.RecordAgentAnomaly(ctx, dup); !errors.Is(err, store.ErrAgentAnomalyDuplicate) {
		t.Fatalf("duplicate anomaly err = %v", err)
	}
	other := first
	other.AnomalyID, other.Kind, other.DetectedAt = "aan_3", store.AgentAnomalyRateSpike, now.Add(time.Second)
	if err := st.RecordAgentAnomaly(ctx, other); err != nil {
		t.Fatalf("other kind: %v", err)
	}
	next := first
	next.AnomalyID, next.Hour, next.DetectedAt = "aan_4", hour.Add(time.Hour), now.Add(time.Hour)
	if err := st.RecordAgentAnomaly(ctx, next); err != nil {
		t.Fatalf("next hour: %v", err)
	}
	if err := st.MarkAgentAnomalySuspended(ctx, AccountA, "aan_3"); err != nil {
		t.Fatalf("MarkAgentAnomalySuspended: %v", err)
	}
	list, err := st.ListAgentAnomalies(ctx, AccountA, a.AgentID, 10)
	if err != nil || len(list) != 3 {
		t.Fatalf("ListAgentAnomalies = %+v, %v", list, err)
	}
	if list[0].AnomalyID != "aan_4" || list[1].AnomalyID != "aan_3" || !list[1].Suspended || list[2].Detail != "host=evil.example" {
		t.Fatalf("order/fields = %+v", list)
	}
	if list, _ := st.ListAgentAnomalies(ctx, AccountA, a.AgentID, 1); len(list) != 1 {
		t.Fatalf("limit = %d", len(list))
	}
	if list, _ := st.ListAgentAnomalies(ctx, AccountB, a.AgentID, 10); len(list) != 0 {
		t.Fatal("anomalies leak across accounts")
	}
	missing := first
	missing.AgentID, missing.AnomalyID = store.NewAgentID(), "aan_5"
	if err := st.RecordAgentAnomaly(ctx, missing); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("anomaly for a missing agent: %v", err)
	}
}
