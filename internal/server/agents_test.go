package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

func bearer(tok string) reqOpt { return withHeader("Authorization", "Bearer "+tok) }

// agentCreate creates an agent as cookie and returns its ID.
func (e *authEnv) agentCreate(cookie *http.Cookie, name string) string {
	e.t.Helper()
	rec := e.do(http.MethodPost, "/v1/agents", map[string]any{"name": name, "description": "test agent"}, cookie)
	wantStatus(e.t, rec, http.StatusCreated)
	return decode(e.t, rec)["agentId"].(string)
}

func (e *authEnv) agentToken(cookie *http.Cookie, agentID string, days int) string {
	e.t.Helper()
	rec := e.do(http.MethodPost, "/v1/agents/tokens", map[string]any{"agentId": agentID, "name": "t", "expiresInDays": days}, cookie)
	wantStatus(e.t, rec, http.StatusCreated)
	if rec.Header().Get("Cache-Control") != "no-store" {
		e.t.Fatal("token response is cacheable")
	}
	tok := decode(e.t, rec)["token"].(string)
	if _, _, ok := store.ParseAgentToken(tok); !ok {
		e.t.Fatalf("token %q has the wrong shape", tok)
	}
	return tok
}

func (e *authEnv) agentEvents(acct, agentID string) []store.AuditRecord {
	e.t.Helper()
	ev, err := e.st.QueryAuditEvents(store.WithCallerAccount(context.Background(), acct), store.AuditQuery{Agent: agentID, Limit: 500})
	if err != nil {
		e.t.Fatal(err)
	}
	return ev
}

func TestAgentLifecycleAndAuthentication(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)     // editor in A
	alice := e.session("alice", e.acctA) // admin in A
	carolB := e.session("carol", e.acctB)

	// Viewers can't create agents.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents", map[string]any{"name": "x"}, carolB), http.StatusForbidden)
	// Editors can't make someone else the owner.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents", map[string]any{"name": "x", "owner": "alice"}, bob), http.StatusForbidden)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents", map[string]any{"name": "bad name!"}, bob), http.StatusBadRequest)

	id := e.agentCreate(bob, "coder")
	wantStatus(t, e.do(http.MethodPost, "/v1/agents", map[string]any{"name": "Coder"}, bob), http.StatusConflict)
	if !e.audited("citadel.CreateAgent", "ok") {
		t.Fatal("create not audited")
	}

	// Another account can't see it.
	wantStatus(t, e.do(http.MethodGet, "/v1/agents/detail?agentId="+id, nil, e.session("bob", e.acctB)), http.StatusNotFound)
	list := decode(t, e.do(http.MethodGet, "/v1/agents", nil, carolB))["agents"].([]any)
	if len(list) != 0 {
		t.Fatalf("agents leaked across accounts: %v", list)
	}

	tok := e.agentToken(bob, id, 30)

	// whoami with the token; the task ID is audited with the agent.
	rec := e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok), withHeader(AgentTaskHeader, "task-42"))
	wantStatus(t, rec, http.StatusOK)
	who := decode(t, rec)
	if who["agentId"] != id || who["owner"] != "bob" || who["authMethod"] != "token" || who["taskId"] != "task-42" || who["accountId"] != e.acctA {
		t.Fatalf("whoami = %v", who)
	}
	found := false
	for _, ev := range e.agentEvents(e.acctA, id) {
		if ev.Action == "citadel.AgentWhoAmI" {
			found = true
			if ev.TaskID != "task-42" || ev.AgentOwner != "bob" || ev.ActorType != store.AuditActorAgent || ev.Actor != id || ev.ActorDisplayName != "coder" {
				t.Fatalf("whoami audit = %+v", ev)
			}
		}
	}
	if !found {
		t.Fatal("whoami not audited for the agent")
	}
	// The audit API filters by agent.
	evs := decode(t, e.do(http.MethodGet, "/v1/audit/events?agent="+id, nil, alice))["events"].([]any)
	if len(evs) == 0 {
		t.Fatal("audit filter by agent returned nothing")
	}
	for _, ev := range evs {
		if ev.(map[string]any)["agentId"] != id {
			t.Fatalf("audit filter returned %v", ev)
		}
	}
	wantStatus(t, e.do(http.MethodGet, "/v1/audit/events?agent=nope", nil, alice), http.StatusBadRequest)

	// Token never appears in the audit log.
	all, _ := e.st.QueryAuditEvents(store.WithCallerAccount(context.Background(), e.acctA), store.AuditQuery{Limit: 500})
	_, secret, _ := store.ParseAgentToken(tok)
	for _, ev := range all {
		if strings.Contains(ev.KeyID+ev.Resource+ev.ErrorType+ev.Actor+ev.AccessKeyID, secret) {
			t.Fatalf("token secret in audit event %+v", ev)
		}
	}

	// Bad task IDs, bad tokens, console sessions and access keys are refused.
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok), withHeader(AgentTaskHeader, "bad task id")), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok[:len(tok)-1]+"a")), http.StatusUnauthorized)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer("cagt_garbage")), http.StatusUnauthorized)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, bob), http.StatusUnauthorized)
	// An agent token is not a console credential.
	wantStatus(t, e.do(http.MethodGet, "/v1/secrets?project=p&env=e", nil, nil, bearer(tok)), http.StatusUnauthorized)

	// Suspend: refused with a reason; only owner/admin may do it.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/suspend", map[string]any{"agentId": id}, e.session("root", e.acctA)), http.StatusOK)
	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok))
	wantStatus(t, rec, http.StatusForbidden)
	if decode(t, rec)["reason"] != "agent_suspended" {
		t.Fatalf("suspended body = %s", rec.Body.String())
	}
	if !e.audited("citadel.AgentAuth", "denied") {
		t.Fatal("refusal of a suspended agent not audited")
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/suspend", map[string]any{"agentId": id}, bob), http.StatusConflict)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/resume", map[string]any{"agentId": id}, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok)), http.StatusOK)

	// Kill switch: admins only.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/settings", map[string]any{"agentsSuspended": true}, bob), http.StatusForbidden)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/settings", map[string]any{"agentsSuspended": true, "reason": "incident"}, alice), http.StatusOK)
	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok))
	wantStatus(t, rec, http.StatusForbidden)
	if decode(t, rec)["reason"] != "agents_suspended" {
		t.Fatalf("kill switch body = %s", rec.Body.String())
	}
	if st := decode(t, e.do(http.MethodGet, "/v1/agents/settings", nil, bob)); st["agentsSuspended"] != true || st["suspendedBy"] != "alice" {
		t.Fatalf("settings = %v", st)
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/settings", map[string]any{"agentsSuspended": false}, alice), http.StatusOK)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok)), http.StatusOK)
	if !e.audited("citadel.SuspendAllAgents", "ok") || !e.audited("citadel.ResumeAllAgents", "ok") {
		t.Fatal("kill switch not audited")
	}

	// Token revocation is immediate (even with the verification cache).
	tok2 := e.agentToken(bob, id, 0)
	detail := decode(t, e.do(http.MethodGet, "/v1/agents/detail?agentId="+id, nil, bob))
	tokens := detail["tokens"].([]any)
	if len(tokens) != 2 {
		t.Fatalf("tokens = %v", tokens)
	}
	var firstID string
	for _, tk := range tokens {
		m := tk.(map[string]any)
		if _, has := m["expiresAt"]; has {
			firstID = m["tokenId"].(string)
		}
		if p, _ := m["prefix"].(string); !strings.HasPrefix(p, "cagt_"+id+"_") || len(p) != len("cagt_"+id+"_")+store.AgentTokenHintLen {
			t.Fatalf("token prefix = %q", p)
		}
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/tokens/revoke", map[string]any{"agentId": id, "tokenId": firstID}, alice), http.StatusOK)
	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok))
	wantStatus(t, rec, http.StatusUnauthorized)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok2)), http.StatusOK)

	// Revoke: permanent; tokens stop working.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/revoke", map[string]any{"agentId": id, "reason": "retired"}, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok2)), http.StatusUnauthorized)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/resume", map[string]any{"agentId": id}, alice), http.StatusConflict)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/tokens", map[string]any{"agentId": id}, alice), http.StatusConflict)
	wantStatus(t, e.do(http.MethodDelete, "/v1/agents?agentId="+id, nil, alice), http.StatusOK)
	wantStatus(t, e.do(http.MethodGet, "/v1/agents/detail?agentId="+id, nil, alice), http.StatusNotFound)
}

func TestAgentOwnershipRules(t *testing.T) {
	e := newAuthEnv(t)
	alice := e.session("alice", e.acctA)
	bob := e.session("bob", e.acctA)
	// An admin creates an agent owned by alice; bob (editor, not owner)
	// can't manage it, and the refusal is audited against the agent.
	rec := e.do(http.MethodPost, "/v1/agents", map[string]any{"name": "ops"}, alice)
	wantStatus(t, rec, http.StatusCreated)
	id := decode(t, rec)["agentId"].(string)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/suspend", map[string]any{"agentId": id}, bob), http.StatusForbidden)
	denied := false
	for _, ev := range e.agentEvents(e.acctA, id) {
		if ev.Action == "citadel.SuspendAgent" && ev.Result == store.AuditResultDenied {
			denied = true
		}
	}
	if !denied {
		t.Fatal("denied suspend not attributed to the agent")
	}
	// Owner must belong to the account.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/update", map[string]any{"agentId": id, "name": "ops", "owner": "carol"}, alice), http.StatusBadRequest)
	// Admin hands it to bob; bob can now manage it.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/update", map[string]any{"agentId": id, "name": "ops", "owner": "bob"}, alice), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/suspend", map[string]any{"agentId": id}, bob), http.StatusOK)
	list := decode(t, e.do(http.MethodGet, "/v1/agents", nil, bob))
	if a := list["agents"].([]any)[0].(map[string]any); a["canManage"] != true || a["status"] != "suspended" {
		t.Fatalf("list = %v", list)
	}
}

func (e *authEnv) createSecret(acct, name, value string) {
	e.t.Helper()
	if _, _, err := e.st.CreateSecret(store.WithCallerAccount(context.Background(), acct), store.CreateSecretRequest{Name: name, SecretString: value}); err != nil {
		e.t.Fatal(err)
	}
}

func TestAgentCredentialsGrantsAndPolicy(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	e.createSecret(e.acctA, "app/prod/GITHUB_TOKEN", "ghp_secretvalue")
	id := e.agentCreate(bob, "coder")
	tok := e.agentToken(bob, id, 1)

	// Usage profile validation.
	for _, bad := range []map[string]any{
		{"name": "gh", "project": "app", "env": "prod", "key": "GITHUB_TOKEN", "kind": "http_header"},                                                     // no hosts
		{"name": "gh", "project": "app", "env": "prod", "key": "GITHUB_TOKEN", "kind": "http_header", "allowedHosts": []string{"*.com"}},                  // broad wildcard
		{"name": "gh", "project": "app", "env": "prod", "key": "GITHUB_TOKEN", "kind": "http_header", "allowedHosts": []string{"a.b"}, "headerName": "Host"}, // forbidden header
		{"name": "gh", "project": "app", "env": "prod", "key": "MISSING", "kind": "raw"},                                                                  // no secret
		{"name": "GH", "project": "app", "env": "prod", "key": "GITHUB_TOKEN", "kind": "raw"},                                                             // name
		{"name": "gh", "project": "app", "env": "prod", "key": "GITHUB_TOKEN", "kind": "http_query", "allowedHosts": []string{"a.b"}},                     // no param
		{"name": "gh", "project": "app", "env": "prod", "key": "GITHUB_TOKEN", "kind": "raw", "allowedCidrs": []string{"nope"}},
	} {
		wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", bad, bob), http.StatusBadRequest)
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{"name": "gh", "kind": "raw", "secret": "app/prod/GITHUB_TOKEN"}, e.session("carol", e.acctB)), http.StatusForbidden)
	rec := e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{
		"name": "github-pat", "project": "app", "env": "prod", "key": "GITHUB_TOKEN", "kind": "http_header",
		"allowedHosts": []string{"API.github.com"}, "headerPrefix": "Bearer ", "allowedCidrs": []string{"10.1.2.3/8"},
	}, bob)
	wantStatus(t, rec, http.StatusCreated)
	c := decode(t, rec)
	if c["headerName"] != "Authorization" || c["allowedHosts"].([]any)[0] != "api.github.com" || c["allowedMethods"].([]any)[0] != "GET" ||
		c["allowedCidrs"].([]any)[0] != "10.0.0.0/8" || c["project"] != "app" || c["key"] != "GITHUB_TOKEN" {
		t.Fatalf("credential = %v", c)
	}
	if strings.Contains(rec.Body.String(), "ghp_secretvalue") {
		t.Fatal("secret value in response")
	}
	// The secret drawer lists profiles for one secret.
	creds := decode(t, e.do(http.MethodGet, "/v1/agents/credentials?project=app&env=prod&key=GITHUB_TOKEN", nil, bob))["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("credentials for secret = %v", creds)
	}
	if other := decode(t, e.do(http.MethodGet, "/v1/agents/credentials?secret=other", nil, bob))["credentials"].([]any); len(other) != 0 {
		t.Fatalf("credentials for other secret = %v", other)
	}

	// Grants.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "nope"}, bob), http.StatusNotFound)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "github-pat", "actions": []string{"totp"}}, bob), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "github-pat", "window": map[string]any{"start": "09:00", "end": "17:00", "timezone": "Mars/Base"}}, bob), http.StatusBadRequest)
	rec = e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "github-pat", "maxUsesPerHour": 2}, bob)
	wantStatus(t, rec, http.StatusOK)
	g := decode(t, rec)
	if g["actions"].([]any)[0] != "use" || g["usableNow"] != true || g["requiresApproval"] != nil {
		t.Fatalf("grant = %v", g)
	}

	// The agent sees the credential, never its value.
	rec = e.do(http.MethodGet, "/v1/agent/credentials", nil, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	list := decode(t, rec)["credentials"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["name"] != "github-pat" || list[0].(map[string]any)["usable"] != true {
		t.Fatalf("agent credentials = %v", list)
	}
	if strings.Contains(rec.Body.String(), "ghp_secretvalue") || strings.Contains(rec.Body.String(), "GITHUB_TOKEN") {
		t.Fatal("agent listing leaks the secret or its location")
	}
	if !e.audited("citadel.AgentListCredentials", "ok") {
		t.Fatal("listing not audited")
	}

	// Policy evaluation.
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	agent, _ := e.st.GetAgent(ctx, e.acctA, id)
	now := time.Now().UTC()
	_, _, _, d := e.s.evaluateAgentAccess(ctx, agent, "github-pat", store.AgentActionReveal, now)
	if d.Allowed || d.Reason != "action_not_granted" {
		t.Fatalf("reveal = %+v", d)
	}
	_, _, _, d = e.s.evaluateAgentAccess(ctx, agent, "unknown", store.AgentActionUse, now)
	if d.Allowed || d.Reason != "no_grant" {
		t.Fatalf("unknown credential = %+v", d)
	}
	_, _, _, d = e.s.evaluateAgentAccess(ctx, agent, "github-pat", "delete", now)
	if d.Reason != "invalid_action" {
		t.Fatalf("invalid action = %+v", d)
	}
	grant, prof, ref, d := e.s.evaluateAgentAccess(ctx, agent, "github-pat", store.AgentActionUse, now)
	if !d.Allowed || grant.Credential != "github-pat" || prof.HeaderPrefix != "Bearer " || ref.SecretName != "app/prod/GITHUB_TOKEN" || ref.Key != "GITHUB_TOKEN" {
		t.Fatalf("use = %+v %+v %+v %+v", d, grant, prof, ref)
	}
	if v, err := e.s.agentSecretValue(ctx, e.acctA, ref); err != nil || v != "ghp_secretvalue" {
		t.Fatalf("agentSecretValue = %q, %v", v, err)
	}
	_, _, _, d = e.s.evaluateAgentAccess(ctx, agent, "github-pat", store.AgentActionUse, now)
	if !d.Allowed {
		t.Fatalf("second use = %+v", d)
	}
	_, _, _, d = e.s.evaluateAgentAccess(ctx, agent, "github-pat", store.AgentActionUse, now)
	if d.Allowed || d.Reason != "rate_limited" || d.RetryAfter <= 0 {
		t.Fatalf("third use within the hour = %+v", d)
	}

	// Dates and window.
	past := now.Add(-time.Hour).Format(time.RFC3339)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "github-pat", "notAfter": past}, bob), http.StatusOK)
	if _, _, _, d = e.s.evaluateAgentAccess(ctx, agent, "github-pat", store.AgentActionUse, now); d.Reason != "grant_expired" {
		t.Fatalf("expired grant = %+v", d)
	}
	// Deleting the credential is refused while granted.
	wantStatus(t, e.do(http.MethodDelete, "/v1/agents/credentials?name=github-pat", nil, bob), http.StatusConflict)

	// Suspension wins over a grant, even mid-request.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "github-pat"}, bob), http.StatusOK)
	if _, err := e.st.SetAgentStatus(ctx, e.acctA, id, store.AgentStatusSuspended, "bob", "", now); err != nil {
		t.Fatal(err)
	}
	if _, _, _, d = e.s.evaluateAgentAccess(ctx, agent, "github-pat", store.AgentActionUse, now); d.Reason != "agent_suspended" {
		t.Fatalf("suspended = %+v", d)
	}
	if _, err := e.st.SetAgentStatus(ctx, e.acctA, id, store.AgentStatusActive, "bob", "", now); err != nil {
		t.Fatal(err)
	}

	// A deleted secret makes the credential unavailable.
	if _, err := e.st.DeleteSecret(ctx, "app/prod/GITHUB_TOKEN", 0, true); err != nil {
		t.Fatal(err)
	}
	if _, _, _, d = e.s.evaluateAgentAccess(ctx, agent, "github-pat", store.AgentActionUse, now); d.Reason != "credential_unavailable" {
		t.Fatalf("deleted secret = %+v", d)
	}

	// Removing the grant, then the profile.
	grants := decode(t, e.do(http.MethodGet, "/v1/agents/detail?agentId="+id, nil, bob))["grants"].([]any)
	gid := grants[0].(map[string]any)["grantId"].(string)
	wantStatus(t, e.do(http.MethodDelete, "/v1/agents/grants?agentId="+id+"&grantId="+gid, nil, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodDelete, "/v1/agents/credentials?name=github-pat", nil, bob), http.StatusOK)
	for _, a := range []string{"citadel.CreateAgentCredential", "citadel.PutAgentGrant", "citadel.DeleteAgentGrant", "citadel.DeleteAgentCredential"} {
		if !e.audited(a, "ok") {
			t.Fatalf("%s not audited", a)
		}
	}
}

func TestAgentGrantWindow(t *testing.T) {
	// Monday 2026-11-16 10:30 UTC.
	mon := time.Date(2026, 11, 16, 10, 30, 0, 0, time.UTC)
	cases := []struct {
		name string
		g    store.AgentGrant
		at   time.Time
		want bool
	}{
		{"no window", store.AgentGrant{}, mon, true},
		{"inside", store.AgentGrant{WindowStart: "09:00", WindowEnd: "17:00"}, mon, true},
		{"before", store.AgentGrant{WindowStart: "11:00", WindowEnd: "17:00"}, mon, false},
		{"end exclusive", store.AgentGrant{WindowStart: "09:00", WindowEnd: "10:30"}, mon, false},
		{"weekday", store.AgentGrant{WindowDays: []string{"mon"}}, mon, true},
		{"other day", store.AgentGrant{WindowDays: []string{"tue"}}, mon, false},
		{"timezone", store.AgentGrant{WindowStart: "09:00", WindowEnd: "10:00", Timezone: "America/New_York"}, mon.Add(4 * time.Hour), true},
		{"overnight late", store.AgentGrant{WindowStart: "22:00", WindowEnd: "06:00"}, mon.Add(12 * time.Hour), true},
		{"overnight early counts the start day", store.AgentGrant{WindowStart: "22:00", WindowEnd: "06:00", WindowDays: []string{"sun"}}, mon.Add(-8 * time.Hour), true},
		{"overnight outside", store.AgentGrant{WindowStart: "22:00", WindowEnd: "06:00"}, mon, false},
		{"bad zone fails closed", store.AgentGrant{WindowStart: "00:00", WindowEnd: "23:59", Timezone: "Nowhere/Land"}, mon, false},
	}
	for _, c := range cases {
		if got := inAgentWindow(c.g, c.at); got != c.want {
			t.Errorf("%s: inAgentWindow = %v, want %v", c.name, got, c.want)
		}
	}
	nbf := mon.Add(time.Hour)
	if r := agentGrantTimeCheck(store.AgentGrant{NotBefore: &nbf}, mon); r != "not_yet_valid" {
		t.Errorf("notBefore = %q", r)
	}
	if r := agentGrantTimeCheck(store.AgentGrant{WindowDays: []string{"tue"}}, mon); r != "outside_window" {
		t.Errorf("window = %q", r)
	}
}

func TestAgentTokenExpiry(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	id := e.agentCreate(bob, "coder")
	tok := e.agentToken(bob, id, 1)
	// Age the token past its expiry in the store.
	_, secret, _ := store.ParseAgentToken(tok)
	tokens, _ := e.st.FindAgentTokens(context.Background(), id, secret[:store.AgentTokenHintLen])
	t0 := tokens[0]
	past := time.Now().Add(-time.Minute)
	t0.ExpiresAt = &past
	t0.TokenID = store.NewAgentObjectID("atk_")
	if err := e.st.RevokeAgentToken(context.Background(), e.acctA, id, tokens[0].TokenID, "x", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateAgentToken(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	rec := e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok))
	wantStatus(t, rec, http.StatusUnauthorized)
	expired := false
	for _, ev := range e.agentEvents(e.acctA, id) {
		if ev.Action == "citadel.AgentAuth" && (ev.ErrorType == "token_expired" || ev.ErrorType == "token_revoked") {
			expired = true
		}
	}
	if !expired {
		t.Fatal("expired token refusal not audited")
	}
}

func TestAgentFederation(t *testing.T) {
	e := newAuthEnv(t)
	e.s.identity().allowInsecureHTTP = true
	bob := e.session("bob", e.acctA)
	iss := newFakeOIDCIssuer(t)
	id := e.agentCreate(bob, "ci-agent")
	body := map[string]any{"agentId": id, "issuer": iss.srv.URL, "subject": "repo:org/app:ref:refs/heads/main", "audience": "citadel"}

	// The issuer must be registered in the account first.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/bindings", body, bob), http.StatusBadRequest)
	if err := e.st.CreateOIDCProvider(context.Background(), store.OIDCProvider{ProviderARN: "arn:aws:iam::" + e.acctA + ":oidc-provider/test", AccountID: e.acctA, URL: iss.srv.URL}); err != nil {
		t.Fatal(err)
	}
	rec := e.do(http.MethodPost, "/v1/agents/bindings", body, bob)
	wantStatus(t, rec, http.StatusCreated)
	bindingID := decode(t, rec)["bindingId"].(string)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/bindings", body, bob), http.StatusConflict)

	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(iss.token(t, "repo:org/app:ref:refs/heads/main", "citadel")))
	wantStatus(t, rec, http.StatusOK)
	if who := decode(t, rec); who["agentId"] != id || who["authMethod"] != "federation" || who["bindingId"] != bindingID {
		t.Fatalf("whoami = %v", who)
	}
	// Wrong audience or subject, or the wrong agent named.
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(iss.token(t, "repo:org/app:ref:refs/heads/main", "other"))), http.StatusUnauthorized)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(iss.token(t, "repo:org/app:ref:refs/heads/dev", "citadel"))), http.StatusUnauthorized)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(iss.token(t, "repo:org/app:ref:refs/heads/main", "citadel")), withHeader(AgentIDHeader, store.NewAgentID())), http.StatusUnauthorized)

	// A second agent with the same binding: ambiguous unless named.
	id2 := e.agentCreate(bob, "ci-agent-2")
	body["agentId"] = id2
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/bindings", body, bob), http.StatusCreated)
	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(iss.token(t, "repo:org/app:ref:refs/heads/main", "citadel")))
	wantStatus(t, rec, http.StatusUnauthorized)
	if decode(t, rec)["reason"] != "federation_ambiguous" {
		t.Fatalf("ambiguous body = %s", rec.Body.String())
	}
	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(iss.token(t, "repo:org/app:ref:refs/heads/main", "citadel")), withHeader(AgentIDHeader, id2))
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["agentId"] != id2 {
		t.Fatal("named agent not used")
	}

	// A token signed by someone else is refused.
	other := newFakeOIDCIssuer(t)
	forged := other.token(t, "repo:org/app:ref:refs/heads/main", "citadel")
	forged = strings.Replace(forged, strings.Split(forged, ".")[1], strings.Split(iss.token(t, "repo:org/app:ref:refs/heads/main", "citadel"), ".")[1], 1)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(forged), withHeader(AgentIDHeader, id2)), http.StatusUnauthorized)

	wantStatus(t, e.do(http.MethodDelete, "/v1/agents/bindings?agentId="+id+"&bindingId="+bindingID, nil, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(iss.token(t, "repo:org/app:ref:refs/heads/main", "citadel")), withHeader(AgentIDHeader, id)), http.StatusUnauthorized)
}

// TestAgentFederationCitadelIssuer: a token from Citadel's own workload
// issuer authenticates an agent whose binding matches it, only in the
// account the token names.
func TestAgentFederationCitadelIssuer(t *testing.T) {
	e := newWorkloadEnv(t)
	alice := e.session("alice", e.acctA)
	rec := e.do(http.MethodPost, "/v1/workload-identity/clients", map[string]any{"name": "ci", "audiences": []string{"citadel-agents"}, "tokenTtlSeconds": 900,
		"subjectFormat": "user:{username}", "auth": map[string]any{"method": "access-key", "allowedUsers": []string{"bob"}}}, alice)
	wantStatus(t, rec, http.StatusCreated)
	clientID := decode(t, rec)["clientId"].(string)
	rec = e.token(map[string]any{"clientId": clientID, "audience": "citadel-agents"}, withHeader("Authorization", "Bearer "+bobKey+":"+bobSec))
	wantStatus(t, rec, http.StatusOK)
	jwt := decode(t, rec)["token"].(string)

	id := e.agentCreate(alice, "wi-agent")
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/bindings", map[string]any{"agentId": id, "issuer": "https://citadel.test/oidc/", "subject": "user:bob", "audience": "citadel-agents"}, alice), http.StatusCreated)
	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(jwt))
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["agentId"] != id {
		t.Fatalf("whoami = %s", rec.Body.String())
	}

	// The same binding in another account doesn't match: the token names
	// account A.
	root := e.session("root", e.acctB)
	idB := e.agentCreate(root, "wi-agent")
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/bindings", map[string]any{"agentId": idB, "issuer": "https://citadel.test/oidc", "subject": "user:bob", "audience": "citadel-agents"}, root), http.StatusCreated)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(jwt), withHeader(AgentIDHeader, idB)), http.StatusUnauthorized)
	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(jwt))
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["agentId"] != id {
		t.Fatal("token matched another account's agent")
	}
}

func TestAgentTokenParsing(t *testing.T) {
	id := store.NewAgentID()
	if !store.IsAgentID(id) || len(id) != 24 {
		t.Fatalf("agent ID %q", id)
	}
	sec := store.NewAgentTokenSecret()
	tok := store.FormatAgentToken(id, sec)
	gotID, gotSec, ok := store.ParseAgentToken(tok)
	if !ok || gotID != id || gotSec != sec {
		t.Fatalf("ParseAgentToken(%q) = %q %q %v", tok, gotID, gotSec, ok)
	}
	for _, bad := range []string{"", "cagt_", tok + "x", tok[:len(tok)-1], strings.ToUpper(tok), "cagt_agt_" + strings.Repeat("a", 20) + "-" + sec} {
		if _, _, ok := store.ParseAgentToken(bad); ok {
			t.Errorf("ParseAgentToken(%q) accepted", bad)
		}
	}
	if !validAgentTaskID("run-1:step/2") || validAgentTaskID("has space") || validAgentTaskID(strings.Repeat("a", 129)) {
		t.Error("validAgentTaskID")
	}
}

func TestAgentEndpointsRateLimitFailures(t *testing.T) {
	e := newAuthEnv(t)
	h := e.s.Handler()
	var last int
	for range 40 {
		req := httptest.NewRequest(http.MethodGet, "/v1/agent/whoami", nil)
		req.Header.Set("Authorization", "Bearer cagt_nope")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("repeated failures: last status %d, want 429", last)
	}
}
