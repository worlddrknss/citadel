package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/store"
)

// approvalSetup creates (as bob, editor in A) an agent with a token, a
// credential "gh" on a secret, and a grant with the given extra fields.
func (e *authEnv) approvalSetup(grant map[string]any) (agentID, tok string) {
	e.t.Helper()
	bob := e.session("bob", e.acctA)
	e.createSecret(e.acctA, "app/prod/GITHUB_TOKEN", "ghp_secretvalue")
	agentID = e.agentCreate(bob, "coder")
	tok = e.agentToken(bob, agentID, 1)
	wantStatus(e.t, e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{
		"name": "gh", "project": "app", "env": "prod", "key": "GITHUB_TOKEN", "kind": "http_header", "allowedHosts": []string{"api.github.com"},
	}, bob), http.StatusCreated)
	if grant != nil {
		body := map[string]any{"agentId": agentID, "credential": "gh"}
		for k, v := range grant {
			body[k] = v
		}
		wantStatus(e.t, e.do(http.MethodPost, "/v1/agents/grants", body, bob), http.StatusOK)
	}
	return agentID, tok
}

// agentCtx is a request context for evaluateAgentAccess as the agent, with
// an optional task ID.
func (e *authEnv) agentCtx(agentID, task string) (context.Context, store.Agent) {
	e.t.Helper()
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	a, err := e.st.GetAgent(ctx, e.acctA, agentID)
	if err != nil {
		e.t.Fatal(err)
	}
	p := &AgentPrincipal{Agent: a, AccountID: e.acctA, Method: agentAuthToken, TaskID: task}
	ctx = context.WithValue(ctx, auditPrincipalCtxKey{}, agentPrincipalForAudit(p))
	return withAgentPrincipal(ctx, p), a
}

func (e *authEnv) evalUse(agentID, task, action string) AgentDecision {
	e.t.Helper()
	ctx, a := e.agentCtx(agentID, task)
	_, _, _, d := e.s.evaluateAgentAccess(ctx, a, "gh", action, time.Now().UTC())
	return d
}

func TestAgentApprovalRequiredOnceFlow(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	alice := e.session("alice", e.acctA)
	id, tok := e.approvalSetup(map[string]any{"actions": []string{"use", "reveal"}, "requiresApproval": true, "leaseTtlSeconds": 600})

	// Without a lease: approval_required with a request, reused while pending.
	d := e.evalUse(id, "", "use")
	if d.Allowed || d.Reason != "approval_required" || !store.IsAgentObjectID(d.RequestID, "aar_") {
		t.Fatalf("first use = %+v", d)
	}
	if d2 := e.evalUse(id, "", "use"); d2.RequestID != d.RequestID {
		t.Fatalf("second use opened another request: %+v", d2)
	}
	if !e.audited("citadel.AgentRequestAccess", "ok") {
		t.Fatal("request not audited")
	}
	// reveal is another request.
	if d3 := e.evalUse(id, "", "reveal"); d3.Reason != "approval_required" || d3.RequestID == d.RequestID {
		t.Fatalf("reveal = %+v", d3)
	}

	// The agent polls it.
	rec := e.do(http.MethodGet, "/v1/agent/access-requests/"+d.RequestID, nil, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	if got := decode(t, rec); got["status"] != "pending" || got["origin"] != "policy" || got["credential"] != "gh" {
		t.Fatalf("poll = %v", got)
	}
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/access-requests/aar_nope", nil, nil, bearer(tok)), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/access-requests/"+d.RequestID, nil, bob), http.StatusUnauthorized)

	// The console lists it; another account doesn't see it.
	list := decode(t, e.do(http.MethodGet, "/v1/agents/access-requests?status=pending", nil, alice))["requests"].([]any)
	if len(list) != 2 {
		t.Fatalf("pending = %v", list)
	}
	var row map[string]any
	for _, x := range list {
		if x.(map[string]any)["requestId"] == d.RequestID {
			row = x.(map[string]any)
		}
	}
	if row["canDecide"] != true || row["agentName"] != "coder" || row["maxDurationSeconds"].(float64) != 600 || row["grant"].(map[string]any)["requiresApproval"] != true {
		t.Fatalf("row = %v", row)
	}
	if other := decode(t, e.do(http.MethodGet, "/v1/agents/access-requests", nil, e.session("carol", e.acctB)))["requests"].([]any); len(other) != 0 {
		t.Fatalf("requests leaked across accounts: %v", other)
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "once"}, e.session("bob", e.acctB)), http.StatusForbidden)

	// Validation: scope, durations over the grant's leaseTtl, task without a task ID.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "forever"}, bob), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "duration", "durationSeconds": 3600}, bob), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "task"}, bob), http.StatusBadRequest)

	// The owner approves once.
	rec = e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "once", "comment": "go ahead"}, bob)
	wantStatus(t, rec, http.StatusOK)
	out := decode(t, rec)
	lease := out["lease"].(map[string]any)
	if lease["scope"] != "once" || lease["usesLeft"].(float64) != 1 || lease["createdBy"] != "bob" || out["request"].(map[string]any)["status"] != "approved" {
		t.Fatalf("approve = %v", out)
	}
	if !e.audited("citadel.ApproveAgentAccess", "ok") {
		t.Fatal("approval not audited")
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "once"}, alice), http.StatusConflict)

	// One use, attributed to the lease; the second needs a new approval.
	use := e.evalUse(id, "", "use")
	if !use.Allowed || use.LeaseID != lease["leaseId"] {
		t.Fatalf("use under lease = %+v", use)
	}
	again := e.evalUse(id, "", "use")
	if again.Allowed || again.Reason != "approval_required" || again.RequestID == d.RequestID {
		t.Fatalf("second use = %+v", again)
	}
	got := decode(t, e.do(http.MethodGet, "/v1/agent/access-requests/"+d.RequestID, nil, nil, bearer(tok)))
	if got["status"] != "approved" || got["scope"] != "once" || got["lease"].(map[string]any)["status"] != "used" || got["decisionComment"] != "go ahead" {
		t.Fatalf("poll after use = %v", got)
	}

	// Deny needs a reason; the agent sees it.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/deny", map[string]any{"requestId": again.RequestID}, alice), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/deny", map[string]any{"requestId": again.RequestID, "comment": "not now"}, alice), http.StatusOK)
	got = decode(t, e.do(http.MethodGet, "/v1/agent/access-requests/"+again.RequestID, nil, nil, bearer(tok)))
	if got["status"] != "denied" || got["decisionComment"] != "not now" || got["decidedBy"] != "alice" {
		t.Fatalf("denied poll = %v", got)
	}
	if !e.audited("citadel.DenyAgentAccess", "ok") {
		t.Fatal("deny not audited")
	}

	// A duration approval within the cap allows repeated use until revoked.
	d = e.evalUse(id, "", "use")
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "duration", "durationSeconds": 600}, alice), http.StatusOK)
	for i := 0; i < 3; i++ {
		if u := e.evalUse(id, "", "use"); !u.Allowed || u.LeaseID == "" {
			t.Fatalf("use %d under duration lease = %+v", i, u)
		}
	}
	leases := decode(t, e.do(http.MethodGet, "/v1/agents/leases?agentId="+id, nil, alice))["leases"].([]any)
	if len(leases) != 1 || leases[0].(map[string]any)["useCount"].(float64) != 3 || leases[0].(map[string]any)["canRevoke"] != true {
		t.Fatalf("active leases = %v", leases)
	}
	leaseID := leases[0].(map[string]any)["leaseId"].(string)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/leases/revoke", map[string]any{"leaseId": leaseID, "reason": "done"}, alice), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/leases/revoke", map[string]any{"leaseId": leaseID}, alice), http.StatusConflict)
	if u := e.evalUse(id, "", "use"); u.Allowed {
		t.Fatal("revoked lease still usable")
	}
	if all := decode(t, e.do(http.MethodGet, "/v1/agents/leases?active=false", nil, alice))["leases"].([]any); len(all) != 2 {
		t.Fatalf("all leases = %v", all)
	}
	if !e.audited("citadel.RevokeAgentLease", "ok") {
		t.Fatal("revoke not audited")
	}
}

func TestAgentApprovalTaskScopeAndSuspend(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	alice := e.session("alice", e.acctA)
	id, _ := e.approvalSetup(map[string]any{"requiresApproval": true})

	d := e.evalUse(id, "run-1", "use")
	if d.Reason != "approval_required" {
		t.Fatalf("use = %+v", d)
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "task", "durationSeconds": 86401}, bob), http.StatusBadRequest)
	rec := e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "task"}, bob)
	wantStatus(t, rec, http.StatusOK)
	if l := decode(t, rec)["lease"].(map[string]any); l["taskId"] != "run-1" || l["usesLeft"] != nil {
		t.Fatalf("task lease = %v", l)
	}
	for i := 0; i < 2; i++ {
		if u := e.evalUse(id, "run-1", "use"); !u.Allowed {
			t.Fatalf("task use = %+v", u)
		}
	}
	if u := e.evalUse(id, "run-2", "use"); u.Allowed || u.Reason != "approval_required" {
		t.Fatalf("other task = %+v", u)
	}
	if u := e.evalUse(id, "", "use"); u.Allowed {
		t.Fatalf("no task = %+v", u)
	}

	// Suspending ends the lease; resuming doesn't bring it back.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/suspend", map[string]any{"agentId": id}, bob), http.StatusOK)
	// Approvals wait for the agent to be active.
	pending := decode(t, e.do(http.MethodGet, "/v1/agents/access-requests?status=pending&agentId="+id, nil, alice))["requests"].([]any)
	if len(pending) == 0 {
		t.Fatal("no pending request")
	}
	pid := pending[0].(map[string]any)["requestId"].(string)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": pid, "scope": "once"}, alice), http.StatusConflict)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/resume", map[string]any{"agentId": id}, bob), http.StatusOK)
	if u := e.evalUse(id, "run-1", "use"); u.Allowed {
		t.Fatal("lease survived a suspension")
	}

	// The kill switch ends leases too.
	d = e.evalUse(id, "", "use")
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "duration"}, alice), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/settings", map[string]any{"agentsSuspended": true, "reason": "incident"}, alice), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/settings", map[string]any{"agentsSuspended": false}, alice), http.StatusOK)
	if u := e.evalUse(id, "", "use"); u.Allowed {
		t.Fatal("lease survived the kill switch")
	}

	// Revoking cancels pending requests.
	d = e.evalUse(id, "", "use")
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/revoke", map[string]any{"agentId": id}, bob), http.StatusOK)
	all := decode(t, e.do(http.MethodGet, "/v1/agents/access-requests?agentId="+id, nil, alice))["requests"].([]any)
	for _, x := range all {
		if x.(map[string]any)["requestId"] == d.RequestID && x.(map[string]any)["status"] != "cancelled" {
			t.Fatalf("request after revoke = %v", x)
		}
	}
}

func TestAgentRequestAccessEndpoint(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	id, tok := e.approvalSetup(nil) // no grant

	if d := e.evalUse(id, "", "use"); d.Reason != "no_grant" || d.RequestID != "" {
		t.Fatalf("no grant = %+v", d)
	}
	for _, bad := range []map[string]any{
		{"credential": "gh"}, // no reason
		{"credential": "GH!", "reason": "x"},
		{"credential": "gh", "reason": "x", "actions": []string{"delete"}},
		{"credential": "gh", "reason": "x", "duration": "10s"},
		{"credential": "gh", "reason": "x", "duration": "25h"},
		{"credential": "gh", "reason": "x", "duration": "soon"},
		{"credential": "gh", "reason": "x", "taskId": "bad task"},
	} {
		wantStatus(t, e.do(http.MethodPost, "/v1/agent/access-requests", bad, nil, bearer(tok)), http.StatusBadRequest)
	}
	// Console credentials can't ask on an agent's behalf.
	wantStatus(t, e.do(http.MethodPost, "/v1/agent/access-requests", map[string]any{"credential": "gh", "reason": "x"}, bob), http.StatusUnauthorized)

	body := map[string]any{"credential": "gh", "actions": []string{"use"}, "reason": "deploy the fix", "duration": "15m"}
	rec := e.do(http.MethodPost, "/v1/agent/access-requests", body, nil, bearer(tok), withHeader(AgentTaskHeader, "task-9"))
	wantStatus(t, rec, http.StatusCreated)
	req := decode(t, rec)
	if req["status"] != "pending" || req["durationSeconds"].(float64) != 900 || req["taskId"] != "task-9" || req["origin"] != "agent" {
		t.Fatalf("request = %v", req)
	}
	rid := req["requestId"].(string)
	rec = e.do(http.MethodPost, "/v1/agent/access-requests", body, nil, bearer(tok), withHeader(AgentTaskHeader, "task-9"))
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["requestId"] != rid {
		t.Fatal("asking again opened another request")
	}

	// The console sees there is no grant; approving uses the requested
	// duration by default.
	list := decode(t, e.do(http.MethodGet, "/v1/agents/access-requests", nil, bob))["requests"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["grant"] != nil || list[0].(map[string]any)["reason"] != "deploy the fix" || list[0].(map[string]any)["credentialKind"] != "http_header" {
		t.Fatalf("console list = %v", list)
	}
	rec = e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": rid, "scope": "once"}, bob)
	wantStatus(t, rec, http.StatusOK)
	exp, _ := time.Parse(time.RFC3339, decode(t, rec)["lease"].(map[string]any)["expiresAt"].(string))
	if left := time.Until(exp); left < 14*time.Minute || left > 16*time.Minute {
		t.Fatalf("lease lasts %v, want ~15m", left)
	}

	// The agent sees its lease, then uses it once without a grant.
	leases := decode(t, e.do(http.MethodGet, "/v1/agent/leases", nil, nil, bearer(tok)))["leases"].([]any)
	if len(leases) != 1 || leases[0].(map[string]any)["credential"] != "gh" {
		t.Fatalf("agent leases = %v", leases)
	}
	if !e.audited("citadel.AgentListLeases", "ok") {
		t.Fatal("lease listing not audited")
	}
	if d := e.evalUse(id, "", "reveal"); d.Allowed || d.Reason != "no_grant" {
		t.Fatalf("lease for use allowed reveal: %+v", d)
	}
	if d := e.evalUse(id, "", "use"); !d.Allowed || d.LeaseID == "" {
		t.Fatalf("use under lease = %+v", d)
	}
	if d := e.evalUse(id, "", "use"); d.Allowed || d.Reason != "no_grant" {
		t.Fatalf("second use = %+v", d)
	}

	// A request for a credential that doesn't exist looks the same to the
	// agent; the approver can only deny it.
	rec = e.do(http.MethodPost, "/v1/agent/access-requests", map[string]any{"credential": "nope", "reason": "x"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusCreated)
	nid := decode(t, rec)["requestId"].(string)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": nid, "scope": "once"}, bob), http.StatusConflict)

	// Another agent can't read the request.
	other := e.agentCreate(bob, "other")
	otherTok := e.agentToken(bob, other, 1)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/access-requests/"+rid, nil, nil, bearer(otherTok)), http.StatusNotFound)

	// Too many pending requests.
	e.s.agentRT().requests = ratelimit.New(time.Millisecond, 1000)
	for i := 0; i < maxPendingAgentRequests; i++ {
		rec = e.do(http.MethodPost, "/v1/agent/access-requests", map[string]any{"credential": "c" + itoa3(i), "reason": "x"}, nil, bearer(otherTok))
		wantStatus(t, rec, http.StatusCreated)
	}
	rec = e.do(http.MethodPost, "/v1/agent/access-requests", map[string]any{"credential": "one-more", "reason": "x"}, nil, bearer(otherTok))
	wantStatus(t, rec, http.StatusTooManyRequests)
	// Asking again for an open one still works.
	wantStatus(t, e.do(http.MethodPost, "/v1/agent/access-requests", map[string]any{"credential": "c000", "reason": "x"}, nil, bearer(otherTok)), http.StatusOK)

	// Request bodies never carry the secret.
	all, _ := e.st.QueryAuditEvents(store.WithCallerAccount(context.Background(), e.acctA), store.AuditQuery{Limit: 1000})
	for _, ev := range all {
		if strings.Contains(ev.KeyID+ev.Resource+ev.ErrorType, "ghp_secretvalue") {
			t.Fatalf("secret in audit %+v", ev)
		}
	}
}

func itoa3(i int) string {
	return string([]byte{'0' + byte(i/100%10), '0' + byte(i/10%10), '0' + byte(i%10)})
}

func TestAgentLeaseTTLGrant(t *testing.T) {
	e := newAuthEnv(t)
	id, _ := e.approvalSetup(map[string]any{"leaseTtlSeconds": 120})
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "gh", "leaseTtlSeconds": 30}, e.session("bob", e.acctA)), http.StatusBadRequest)
	d := e.evalUse(id, "", "use")
	if !d.Allowed || d.LeaseID == "" || time.Until(d.LeaseExpiresAt) > 2*time.Minute {
		t.Fatalf("first use = %+v", d)
	}
	if d2 := e.evalUse(id, "", "use"); !d2.Allowed || d2.LeaseID != d.LeaseID {
		t.Fatalf("second use = %+v", d2)
	}
	ctx, a := e.agentCtx(id, "")
	_, _, _, later := e.s.evaluateAgentAccess(ctx, a, "gh", "use", time.Now().UTC().Add(3*time.Minute))
	if !later.Allowed || later.LeaseID == d.LeaseID {
		t.Fatalf("after expiry = %+v", later)
	}
	if !e.audited("citadel.CreateAgentLease", "ok") {
		t.Fatal("policy lease not audited")
	}
}

func TestAgentApprovalConcurrentOnceUse(t *testing.T) {
	e := newAuthEnv(t)
	id, _ := e.approvalSetup(map[string]any{"requiresApproval": true})
	d := e.evalUse(id, "", "use")
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "once"}, e.session("alice", e.acctA)), http.StatusOK)
	var (
		wg   sync.WaitGroup
		wins atomic.Int32
	)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, a := e.agentCtx(id, "")
			if _, _, _, d := e.s.evaluateAgentAccess(ctx, a, "gh", "use", time.Now().UTC()); d.Allowed {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("single-use approval used %d times", wins.Load())
	}
}

func TestAgentApprovalNeedsSessionAndMFA(t *testing.T) {
	e := newWorkloadEnv(t)
	e.s.mfa().user = ratelimit.New(time.Millisecond, 100)
	id, _ := e.approvalSetup(map[string]any{"requiresApproval": true})
	d := e.evalUse(id, "", "use")

	// bob's own access key can't approve, even though bob owns the agent.
	rec := e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "once"}, nil, noCSRF,
		withHeader("Authorization", "Bearer "+bobKey+":"+bobSec))
	wantStatus(t, rec, http.StatusForbidden)
	if !strings.Contains(rec.Body.String(), "access key") {
		t.Fatalf("access key refusal = %s", rec.Body.String())
	}
	rows := decode(t, e.do(http.MethodGet, "/v1/agents/access-requests", nil, nil, noCSRF, withHeader("Authorization", "Bearer "+bobKey+":"+bobSec)))["requests"].([]any)
	if rows[0].(map[string]any)["canDecide"] != false {
		t.Fatalf("access key row = %v", rows[0])
	}

	// With requireMFA, a password session must confirm with a code.
	if err := e.st.PutOrgSettings(context.Background(), store.OrgSettings{RequireMFA: true, ApprovalMinApprovers: 1}); err != nil {
		t.Fatal(err)
	}
	e.s.auth().settingsFetched = time.Time{}
	alice := e.session("alice", e.acctA)
	rec = e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "once"}, alice)
	wantStatus(t, rec, http.StatusForbidden)
	if decode(t, rec)["error"] != "mfa_required" {
		t.Fatalf("no code = %s", rec.Body.String())
	}
	key, _, _, alice2 := e.mfaEnroll(alice)
	if alice2 != nil {
		alice = alice2
	}
	rows = decode(t, e.do(http.MethodGet, "/v1/agents/access-requests", nil, alice))["requests"].([]any)
	if rows[0].(map[string]any)["mfaRequired"] != true {
		t.Fatalf("row = %v", rows[0])
	}
	rec = e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "once", "mfaCode": "000000"}, alice)
	wantStatus(t, rec, http.StatusForbidden)
	if decode(t, rec)["error"] != "invalid_mfa_code" {
		t.Fatalf("wrong code = %s", rec.Body.String())
	}
	rec = e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": d.RequestID, "scope": "once", "mfaCode": nextCode(key, 1)}, alice)
	wantStatus(t, rec, http.StatusOK)
}

func TestAgentRequireFederation(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	id := e.agentCreate(bob, "ci")
	tok := e.agentToken(bob, id, 1)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok)), http.StatusOK)
	rec := e.do(http.MethodPost, "/v1/agents/update", map[string]any{"agentId": id, "name": "ci", "requireFederation": true}, bob)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["requireFederation"] != true {
		t.Fatalf("update = %s", rec.Body.String())
	}
	rec = e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok))
	wantStatus(t, rec, http.StatusForbidden)
	if decode(t, rec)["reason"] != "federation_required" {
		t.Fatalf("token with requireFederation = %s", rec.Body.String())
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/tokens", map[string]any{"agentId": id, "name": "t"}, bob), http.StatusConflict)
	// An update without the field keeps it.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/update", map[string]any{"agentId": id, "name": "ci", "description": "x"}, bob), http.StatusOK)
	if a, _ := e.st.GetAgent(context.Background(), e.acctA, id); !a.RequireFederation {
		t.Fatal("update without requireFederation cleared it")
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/update", map[string]any{"agentId": id, "name": "ci", "requireFederation": false}, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodGet, "/v1/agent/whoami", nil, nil, bearer(tok)), http.StatusOK)
}
