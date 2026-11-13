package storetest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// AgentStore exercises store.AgentStore against a fresh, empty store.
func AgentStore(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("Agents", func(t *testing.T) { testAgentsCRUD(t, newStore(t)) })
	t.Run("Tokens", func(t *testing.T) { testAgentTokens(t, newStore(t)) })
	t.Run("Bindings", func(t *testing.T) { testAgentBindings(t, newStore(t)) })
	t.Run("CredentialsAndGrants", func(t *testing.T) { testAgentCredentialsGrants(t, newStore(t)) })
	t.Run("Settings", func(t *testing.T) { testAgentSettings(t, newStore(t)) })
	t.Run("DeleteCascades", func(t *testing.T) { testAgentDeleteCascades(t, newStore(t)) })
	t.Run("AuditAttribution", func(t *testing.T) { testAgentAuditAttribution(t, newStore(t)) })
}

// testAgentAuditAttribution checks the agent fields round-trip, are covered
// by the chain MAC and can be filtered on.
func testAgentAuditAttribution(t *testing.T, st store.Store) {
	ctx := store.WithCallerAccount(context.Background(), AccountA)
	agentID := store.NewAgentID()
	for _, ev := range []store.AuditEvent{
		{Action: "citadel.AgentWhoAmI", Result: "ok", AuditOrigin: store.AuditOrigin{AccountID: AccountA, Actor: agentID, ActorType: store.AuditActorAgent, AgentID: agentID, AgentOwner: "alice", TaskID: "task-1"}},
		{Action: "citadel.ListSecrets", Result: "ok", AuditOrigin: store.AuditOrigin{AccountID: AccountA, Actor: "bob", ActorType: store.AuditActorConsole}},
	} {
		if err := st.RecordAudit(ctx, ev); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}
	got, err := st.QueryAuditEvents(ctx, store.AuditQuery{Agent: agentID})
	if err != nil || len(got) != 1 {
		t.Fatalf("QueryAuditEvents(agent) = %+v, %v", got, err)
	}
	if r := got[0]; r.AgentID != agentID || r.AgentOwner != "alice" || r.TaskID != "task-1" || r.ActorType != store.AuditActorAgent {
		t.Fatalf("record = %+v", r)
	}
	if got[0].HashValid != nil && !*got[0].HashValid {
		t.Fatal("agent fields break the event MAC")
	}
	if n, err := st.CountAuditEvents(ctx, store.AuditQuery{Agent: agentID}); err != nil || n != 1 {
		t.Fatalf("CountAuditEvents(agent) = %d, %v", n, err)
	}
	if n, _ := st.CountAuditEvents(ctx, store.AuditQuery{}); n != 2 {
		t.Fatalf("CountAuditEvents() = %d", n)
	}
	// A changed agent field no longer matches the MAC.
	r := got[0]
	r.TaskID = "task-2"
	if store.AuditMACValid([]byte("0123456789abcdef0123456789abcdef"), r) && store.AuditMACValid([]byte("0123456789abcdef0123456789abcdef"), got[0]) {
		t.Fatal("TaskID is not covered by the MAC")
	}
}

func newTestAgent(account, name string, now time.Time) store.Agent {
	return store.Agent{
		AccountID: account, AgentID: store.NewAgentID(), Name: name, Description: "d", Owner: "alice",
		Status: store.AgentStatusActive, Labels: map[string]string{"team": "ml"}, CreatedAt: now, CreatedBy: "alice", UpdatedAt: now,
	}
}

func mustCreateAgent(t *testing.T, st store.Store, a store.Agent) store.Agent {
	t.Helper()
	if err := st.CreateAgent(context.Background(), a); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	return a
}

func testAgentsCRUD(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "Coder", now))
	if err := st.CreateAgent(ctx, newTestAgent(AccountA, "coder", now)); !errors.Is(err, store.ErrAgentExists) {
		t.Fatalf("duplicate name (case-insensitive) err = %v", err)
	}
	// The same name in another account is fine.
	b := mustCreateAgent(t, st, newTestAgent(AccountB, "Coder", now))

	got, err := st.GetAgent(ctx, AccountA, a.AgentID)
	if err != nil || got.Name != "Coder" || got.Owner != "alice" || got.Labels["team"] != "ml" || got.Status != store.AgentStatusActive ||
		!got.CreatedAt.Equal(now) || got.LastUsedAt != nil {
		t.Fatalf("GetAgent = %+v, %v", got, err)
	}
	if _, err := st.GetAgent(ctx, AccountB, a.AgentID); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("GetAgent from another account err = %v", err)
	}
	if got, err := st.LookupAgent(ctx, b.AgentID); err != nil || got.AccountID != AccountB {
		t.Fatalf("LookupAgent = %+v, %v", got, err)
	}
	if _, err := st.LookupAgent(ctx, store.NewAgentID()); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("LookupAgent unknown err = %v", err)
	}
	mustCreateAgent(t, st, newTestAgent(AccountA, "analyst", now))
	list, err := st.ListAgents(ctx, AccountA)
	if err != nil || len(list) != 2 || list[0].Name != "analyst" || list[1].Name != "Coder" {
		t.Fatalf("ListAgents = %+v, %v", list, err)
	}

	a.Name, a.Description, a.Owner, a.Labels, a.UpdatedAt = "coder-2", "new", "bob", nil, now.Add(time.Minute)
	if err := st.UpdateAgent(ctx, a); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	got, _ = st.GetAgent(ctx, AccountA, a.AgentID)
	if got.Name != "coder-2" || got.Owner != "bob" || got.Description != "new" || len(got.Labels) != 0 || !got.UpdatedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("after update = %+v", got)
	}
	a.Name = "Analyst"
	if err := st.UpdateAgent(ctx, a); !errors.Is(err, store.ErrAgentExists) {
		t.Fatalf("rename onto existing name err = %v", err)
	}
	other := a
	other.AccountID = AccountB
	if err := st.UpdateAgent(ctx, other); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("update from another account err = %v", err)
	}

	at := now.Add(2 * time.Minute)
	sus, err := st.SetAgentStatus(ctx, AccountA, a.AgentID, store.AgentStatusSuspended, "carol", "investigating", at)
	if err != nil || sus.Status != store.AgentStatusSuspended || sus.StatusChangedBy != "carol" || sus.StatusReason != "investigating" ||
		sus.StatusChangedAt == nil || !sus.StatusChangedAt.Equal(at) {
		t.Fatalf("suspend = %+v, %v", sus, err)
	}
	if _, err := st.SetAgentStatus(ctx, AccountB, a.AgentID, store.AgentStatusActive, "x", "", at); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("status from another account err = %v", err)
	}
	if err := st.TouchAgentUsed(ctx, AccountA, a.AgentID, "", at); err != nil {
		t.Fatalf("TouchAgentUsed: %v", err)
	}
	got, _ = st.GetAgent(ctx, AccountA, a.AgentID)
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(at) || got.Status != store.AgentStatusSuspended {
		t.Fatalf("after touch = %+v", got)
	}
	if _, err := st.SetAgentStatus(ctx, AccountA, a.AgentID, store.AgentStatusRevoked, "carol", "done", at); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.SetAgentStatus(ctx, AccountA, a.AgentID, store.AgentStatusActive, "carol", "", at); !errors.Is(err, store.ErrAgentRevoked) {
		t.Fatalf("resume after revoke err = %v", err)
	}
}

func testAgentTokens(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	exp := now.Add(time.Hour)
	t1 := store.AgentToken{AccountID: AccountA, AgentID: a.AgentID, TokenID: store.NewAgentObjectID("atk_"), Name: "laptop", Hint: "abcdefgh", Hash: "h1", CreatedAt: now, CreatedBy: "alice", ExpiresAt: &exp}
	t2 := store.AgentToken{AccountID: AccountA, AgentID: a.AgentID, TokenID: store.NewAgentObjectID("atk_"), Name: "ci", Hint: "zzzzzzzz", Hash: "h2", CreatedAt: now.Add(time.Second), CreatedBy: "alice"}
	for _, tk := range []store.AgentToken{t1, t2} {
		if err := st.CreateAgentToken(ctx, tk); err != nil {
			t.Fatalf("CreateAgentToken: %v", err)
		}
	}
	bad := t1
	bad.TokenID, bad.AccountID = store.NewAgentObjectID("atk_"), AccountB
	if err := st.CreateAgentToken(ctx, bad); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("token for an agent in another account err = %v", err)
	}
	list, err := st.ListAgentTokens(ctx, AccountA, a.AgentID)
	if err != nil || len(list) != 2 || list[0].TokenID != t2.TokenID || list[1].ExpiresAt == nil || !list[1].ExpiresAt.Equal(exp) {
		t.Fatalf("ListAgentTokens = %+v, %v", list, err)
	}
	if list, _ := st.ListAgentTokens(ctx, AccountB, a.AgentID); len(list) != 0 {
		t.Fatalf("tokens visible from another account: %+v", list)
	}
	found, err := st.FindAgentTokens(ctx, a.AgentID, "abcdefgh")
	if err != nil || len(found) != 1 || found[0].Hash != "h1" || found[0].AccountID != AccountA {
		t.Fatalf("FindAgentTokens = %+v, %v", found, err)
	}
	if found, _ := st.FindAgentTokens(ctx, a.AgentID, "nomatch0"); len(found) != 0 {
		t.Fatalf("FindAgentTokens(no match) = %+v", found)
	}
	if !found[0].Active(now) || found[0].Active(exp) {
		t.Fatal("Active() ignores the expiry")
	}

	at := now.Add(time.Minute)
	if err := st.TouchAgentUsed(ctx, AccountA, a.AgentID, t1.TokenID, at); err != nil {
		t.Fatalf("TouchAgentUsed: %v", err)
	}
	if err := st.RevokeAgentToken(ctx, AccountB, a.AgentID, t1.TokenID, "x", at); !errors.Is(err, store.ErrAgentTokenNotFound) {
		t.Fatalf("revoke from another account err = %v", err)
	}
	if err := st.RevokeAgentToken(ctx, AccountA, a.AgentID, t1.TokenID, "bob", at); err != nil {
		t.Fatalf("RevokeAgentToken: %v", err)
	}
	// Revoking again keeps the first revocation.
	if err := st.RevokeAgentToken(ctx, AccountA, a.AgentID, t1.TokenID, "carol", at.Add(time.Minute)); err != nil {
		t.Fatalf("RevokeAgentToken again: %v", err)
	}
	found, _ = st.FindAgentTokens(ctx, a.AgentID, "abcdefgh")
	if len(found) != 1 || found[0].RevokedAt == nil || !found[0].RevokedAt.Equal(at) || found[0].RevokedBy != "bob" ||
		found[0].LastUsedAt == nil || !found[0].LastUsedAt.Equal(at) || found[0].Active(now) {
		t.Fatalf("after revoke = %+v", found)
	}

	// Revoking the agent revokes its remaining tokens.
	if _, err := st.SetAgentStatus(ctx, AccountA, a.AgentID, store.AgentStatusRevoked, "carol", "", at); err != nil {
		t.Fatalf("revoke agent: %v", err)
	}
	found, _ = st.FindAgentTokens(ctx, a.AgentID, "zzzzzzzz")
	if len(found) != 1 || found[0].RevokedAt == nil || found[0].RevokedBy != "carol" {
		t.Fatalf("token after agent revoked = %+v", found)
	}
}

func testAgentBindings(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "ci", now))
	b := mustCreateAgent(t, st, newTestAgent(AccountB, "ci", now))
	bind := store.AgentBinding{AccountID: AccountA, AgentID: a.AgentID, BindingID: store.NewAgentObjectID("abd_"), Issuer: "https://issuer.example",
		Subject: "repo:org/app:ref:refs/heads/main", Audience: "citadel", Description: "main", CreatedAt: now, CreatedBy: "alice"}
	if err := st.CreateAgentBinding(ctx, bind); err != nil {
		t.Fatalf("CreateAgentBinding: %v", err)
	}
	dup := bind
	dup.BindingID = store.NewAgentObjectID("abd_")
	if err := st.CreateAgentBinding(ctx, dup); !errors.Is(err, store.ErrAgentBindingExists) {
		t.Fatalf("duplicate binding err = %v", err)
	}
	dup.Audience = "other"
	if err := st.CreateAgentBinding(ctx, dup); err != nil {
		t.Fatalf("binding with another audience: %v", err)
	}
	inB := bind
	inB.BindingID, inB.AccountID, inB.AgentID = store.NewAgentObjectID("abd_"), AccountB, b.AgentID
	if err := st.CreateAgentBinding(ctx, inB); err != nil {
		t.Fatalf("same binding on another account's agent: %v", err)
	}
	cross := bind
	cross.BindingID, cross.AccountID = store.NewAgentObjectID("abd_"), AccountB
	if err := st.CreateAgentBinding(ctx, cross); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("binding to an agent in another account err = %v", err)
	}
	list, err := st.ListAgentBindings(ctx, AccountA, a.AgentID)
	if err != nil || len(list) != 2 || list[0].Subject != bind.Subject || list[0].Description != "main" {
		t.Fatalf("ListAgentBindings = %+v, %v", list, err)
	}
	found, err := st.FindAgentBindings(ctx, bind.Issuer, bind.Subject)
	if err != nil || len(found) != 3 {
		t.Fatalf("FindAgentBindings = %+v, %v", found, err)
	}
	if found, _ := st.FindAgentBindings(ctx, bind.Issuer, "other"); len(found) != 0 {
		t.Fatalf("FindAgentBindings(other subject) = %+v", found)
	}
	if err := st.DeleteAgentBinding(ctx, AccountB, a.AgentID, bind.BindingID); !errors.Is(err, store.ErrAgentBindingNotFound) {
		t.Fatalf("delete from another account err = %v", err)
	}
	if err := st.DeleteAgentBinding(ctx, AccountA, a.AgentID, bind.BindingID); err != nil {
		t.Fatalf("DeleteAgentBinding: %v", err)
	}
	if list, _ := st.ListAgentBindings(ctx, AccountA, a.AgentID); len(list) != 1 {
		t.Fatalf("after delete = %+v", list)
	}
}

func testAgentCredentialsGrants(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	c := store.AgentCredential{
		AccountID: AccountA, Name: "github-pat", SecretName: "app/prod/GITHUB_TOKEN", Kind: store.AgentCredentialHTTPHeader, Description: "GitHub",
		AllowedHosts: []string{"api.github.com"}, AllowedMethods: []string{"GET", "POST"}, AllowedPathPrefixes: []string{"/repos/"},
		HeaderName: "Authorization", HeaderPrefix: "Bearer ", AllowedCIDRs: []string{"10.0.0.0/8"}, AllowHTTP: true,
		CreatedAt: now, CreatedBy: "alice", UpdatedAt: now, UpdatedBy: "alice",
	}
	if err := st.CreateAgentCredential(ctx, c); err != nil {
		t.Fatalf("CreateAgentCredential: %v", err)
	}
	if err := st.CreateAgentCredential(ctx, c); !errors.Is(err, store.ErrAgentCredentialExists) {
		t.Fatalf("duplicate credential err = %v", err)
	}
	inB := c
	inB.AccountID = AccountB
	if err := st.CreateAgentCredential(ctx, inB); err != nil {
		t.Fatalf("same name in another account: %v", err)
	}
	got, err := st.GetAgentCredential(ctx, AccountA, "github-pat")
	if err != nil || got.SecretName != c.SecretName || !slices.Equal(got.AllowedMethods, c.AllowedMethods) || got.HeaderPrefix != "Bearer " ||
		!got.AllowHTTP || !slices.Equal(got.AllowedCIDRs, c.AllowedCIDRs) || !slices.Equal(got.AllowedPathPrefixes, c.AllowedPathPrefixes) {
		t.Fatalf("GetAgentCredential = %+v, %v", got, err)
	}
	upd := c
	upd.Kind, upd.QueryParam, upd.AllowedHosts, upd.AllowedCIDRs, upd.AllowHTTP = store.AgentCredentialHTTPQuery, "key", []string{"*.example.com"}, nil, false
	upd.UpdatedAt, upd.UpdatedBy, upd.CreatedBy = now.Add(time.Minute), "bob", "mallory"
	if err := st.UpdateAgentCredential(ctx, upd); err != nil {
		t.Fatalf("UpdateAgentCredential: %v", err)
	}
	got, _ = st.GetAgentCredential(ctx, AccountA, "github-pat")
	if got.Kind != store.AgentCredentialHTTPQuery || got.QueryParam != "key" || got.CreatedBy != "alice" || got.UpdatedBy != "bob" ||
		len(got.AllowedCIDRs) != 0 || got.AllowHTTP || got.AllowedHosts[0] != "*.example.com" {
		t.Fatalf("after update = %+v", got)
	}
	missing := c
	missing.Name = "nope"
	if err := st.UpdateAgentCredential(ctx, missing); !errors.Is(err, store.ErrAgentCredentialNotFound) {
		t.Fatalf("update unknown err = %v", err)
	}
	if list, _ := st.ListAgentCredentials(ctx, AccountA); len(list) != 1 {
		t.Fatalf("ListAgentCredentials = %+v", list)
	}

	tr := true
	ttl := 600
	nbf, naf := now, now.Add(24*time.Hour)
	g := store.AgentGrant{
		AccountID: AccountA, GrantID: store.NewAgentObjectID("agr_"), AgentID: a.AgentID, Credential: "github-pat", Actions: []string{"use"},
		NotBefore: &nbf, NotAfter: &naf, WindowStart: "09:00", WindowEnd: "17:00", WindowDays: []string{"mon", "fri"}, Timezone: "Europe/Dublin",
		MaxUsesPerHour: 30, RequiresApproval: &tr, LeaseTTLSeconds: &ttl, CreatedAt: now, CreatedBy: "alice", UpdatedAt: now, UpdatedBy: "alice",
	}
	stored, err := st.PutAgentGrant(ctx, g)
	if err != nil || stored.GrantID != g.GrantID || stored.MaxUsesPerHour != 30 || stored.RequiresApproval == nil || !*stored.RequiresApproval ||
		stored.LeaseTTLSeconds == nil || *stored.LeaseTTLSeconds != 600 || !slices.Equal(stored.WindowDays, g.WindowDays) || stored.Timezone != "Europe/Dublin" {
		t.Fatalf("PutAgentGrant = %+v, %v", stored, err)
	}
	// Replacing keeps the ID and creation, and clears what isn't set.
	g2 := g
	g2.GrantID, g2.Actions, g2.NotBefore, g2.RequiresApproval, g2.LeaseTTLSeconds, g2.CreatedBy, g2.UpdatedBy = store.NewAgentObjectID("agr_"), []string{"use", "reveal"}, nil, nil, nil, "mallory", "bob"
	stored, err = st.PutAgentGrant(ctx, g2)
	if err != nil || stored.GrantID != g.GrantID || stored.CreatedBy != "alice" || stored.UpdatedBy != "bob" || !stored.HasAction("reveal") ||
		stored.NotBefore != nil || stored.RequiresApproval != nil || stored.LeaseTTLSeconds != nil || stored.NotAfter == nil {
		t.Fatalf("PutAgentGrant replace = %+v, %v", stored, err)
	}
	list, err := st.ListAgentGrants(ctx, AccountA, a.AgentID)
	if err != nil || len(list) != 1 || list[0].GrantID != g.GrantID {
		t.Fatalf("ListAgentGrants = %+v, %v", list, err)
	}
	if all, _ := st.ListAgentGrants(ctx, AccountA, ""); len(all) != 1 {
		t.Fatalf("ListAgentGrants(all) = %+v", all)
	}
	if list, _ := st.ListAgentGrants(ctx, AccountB, ""); len(list) != 0 {
		t.Fatalf("grants visible from another account: %+v", list)
	}
	noCred := g
	noCred.GrantID, noCred.Credential = store.NewAgentObjectID("agr_"), "missing"
	if _, err := st.PutAgentGrant(ctx, noCred); !errors.Is(err, store.ErrAgentCredentialNotFound) {
		t.Fatalf("grant for unknown credential err = %v", err)
	}
	noAgent := g
	noAgent.GrantID, noAgent.AgentID = store.NewAgentObjectID("agr_"), store.NewAgentID()
	if _, err := st.PutAgentGrant(ctx, noAgent); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("grant for unknown agent err = %v", err)
	}
	if err := st.DeleteAgentCredential(ctx, AccountA, "github-pat"); !errors.Is(err, store.ErrAgentCredentialInUse) {
		t.Fatalf("delete credential in use err = %v", err)
	}
	if err := st.DeleteAgentGrant(ctx, AccountB, a.AgentID, g.GrantID); !errors.Is(err, store.ErrAgentGrantNotFound) {
		t.Fatalf("delete grant from another account err = %v", err)
	}
	if err := st.DeleteAgentGrant(ctx, AccountA, a.AgentID, g.GrantID); err != nil {
		t.Fatalf("DeleteAgentGrant: %v", err)
	}
	if err := st.DeleteAgentCredential(ctx, AccountA, "github-pat"); err != nil {
		t.Fatalf("DeleteAgentCredential: %v", err)
	}
	if _, err := st.GetAgentCredential(ctx, AccountA, "github-pat"); !errors.Is(err, store.ErrAgentCredentialNotFound) {
		t.Fatalf("get after delete err = %v", err)
	}
	if _, err := st.GetAgentCredential(ctx, AccountB, "github-pat"); err != nil {
		t.Fatalf("other account's credential was deleted: %v", err)
	}
}

func testAgentSettings(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	s, err := st.GetAgentSettings(ctx, AccountA)
	if err != nil || s.AgentsSuspended || s.AccountID != AccountA {
		t.Fatalf("GetAgentSettings (unset) = %+v, %v", s, err)
	}
	if err := st.PutAgentSettings(ctx, store.AgentSettings{AccountID: AccountA, AgentsSuspended: true, SuspendedAt: &now, SuspendedBy: "alice", Reason: "incident", UpdatedAt: now}); err != nil {
		t.Fatalf("PutAgentSettings: %v", err)
	}
	s, _ = st.GetAgentSettings(ctx, AccountA)
	if !s.AgentsSuspended || s.SuspendedBy != "alice" || s.Reason != "incident" || s.SuspendedAt == nil || !s.SuspendedAt.Equal(now) {
		t.Fatalf("after put = %+v", s)
	}
	if s, _ := st.GetAgentSettings(ctx, AccountB); s.AgentsSuspended {
		t.Fatal("kill switch leaked into another account")
	}
	if err := st.PutAgentSettings(ctx, store.AgentSettings{AccountID: AccountA, UpdatedAt: now}); err != nil {
		t.Fatalf("PutAgentSettings off: %v", err)
	}
	if s, _ := st.GetAgentSettings(ctx, AccountA); s.AgentsSuspended || s.SuspendedAt != nil {
		t.Fatalf("after turning off = %+v", s)
	}
}

func testAgentDeleteCascades(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	if err := st.CreateAgentToken(ctx, store.AgentToken{AccountID: AccountA, AgentID: a.AgentID, TokenID: store.NewAgentObjectID("atk_"), Hint: "abcdefgh", Hash: "h", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAgentBinding(ctx, store.AgentBinding{AccountID: AccountA, AgentID: a.AgentID, BindingID: store.NewAgentObjectID("abd_"), Issuer: "i", Subject: "s", Audience: "a", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAgentCredential(ctx, store.AgentCredential{AccountID: AccountA, Name: "c", SecretName: "x/y/z", Kind: store.AgentCredentialRaw, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutAgentGrant(ctx, store.AgentGrant{AccountID: AccountA, GrantID: store.NewAgentObjectID("agr_"), AgentID: a.AgentID, Credential: "c", Actions: []string{"use"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAgent(ctx, AccountB, a.AgentID); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("delete from another account err = %v", err)
	}
	if err := st.DeleteAgent(ctx, AccountA, a.AgentID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	if found, _ := st.FindAgentTokens(ctx, a.AgentID, "abcdefgh"); len(found) != 0 {
		t.Fatalf("tokens survived: %+v", found)
	}
	if found, _ := st.FindAgentBindings(ctx, "i", "s"); len(found) != 0 {
		t.Fatalf("bindings survived: %+v", found)
	}
	if list, _ := st.ListAgentGrants(ctx, AccountA, ""); len(list) != 0 {
		t.Fatalf("grants survived: %+v", list)
	}
	// The credential is no longer in use.
	if err := st.DeleteAgentCredential(ctx, AccountA, "c"); err != nil {
		t.Fatalf("DeleteAgentCredential after agent delete: %v", err)
	}
}
