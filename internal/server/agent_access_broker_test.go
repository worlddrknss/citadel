package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

// TestAgentApprovalsThroughBrokerAndMCP: approval_required with a request ID
// from the broker, reveal and MCP; an approved once-lease serves one call
// (attributed to it in the audit log), the next needs approval again; MCP
// request_access and get_lease.
func TestAgentApprovalsThroughBrokerAndMCP(t *testing.T) {
	const secret = "approval-broker-secret-value"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer up.Close()
	host := strings.TrimPrefix(up.URL, "http://")

	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	alice := e.session("alice", e.acctA)
	e.createSecret(e.acctA, "app/prod/API_TOKEN", secret)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{
		"name": "api", "project": "app", "env": "prod", "key": "API_TOKEN", "kind": "http_header",
		"allowedHosts": []string{host}, "allowHttp": true, "allowedCidrs": []string{"127.0.0.1/32"},
	}, bob), http.StatusCreated)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{
		"name": "deploy", "project": "app", "env": "prod", "key": "API_TOKEN", "kind": "raw",
	}, bob), http.StatusCreated)
	id := e.agentCreate(bob, "coder")
	tok := e.agentToken(bob, id, 1)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "api", "requiresApproval": true}, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "deploy", "actions": []string{"reveal"}, "requiresApproval": true}, bob), http.StatusOK)

	brokered := func() *httptest.ResponseRecorder {
		return e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "api", "url": up.URL + "/x"}, nil, bearer(tok))
	}
	rec := brokered()
	wantStatus(t, rec, http.StatusForbidden)
	body := decode(t, rec)
	reqID, _ := body["requestId"].(string)
	if body["error"] != "approval_required" || body["reason"] != "approval_required" || !store.IsAgentObjectID(reqID, "aar_") {
		t.Fatalf("broker without approval: %s", rec.Body)
	}
	approve := func(id, scope string) {
		t.Helper()
		wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/approve", map[string]any{"requestId": id, "scope": scope}, alice), http.StatusOK)
	}
	approve(reqID, "once")
	wantStatus(t, brokered(), http.StatusOK)
	rec = brokered()
	wantStatus(t, rec, http.StatusForbidden)
	if r2 := decode(t, rec)["requestId"]; r2 == reqID || r2 == "" {
		t.Fatalf("second use: %s", rec.Body)
	}

	// Reveal under a lease reports it.
	rec = e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "deploy"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusForbidden)
	approve(decode(t, rec)["requestId"].(string), "duration")
	rec = e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "deploy"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	rv := decode(t, rec)
	if rv["value"] != secret || !store.IsAgentObjectID(rv["leaseId"].(string), "als_") || rv["leaseExpiresAt"] == "" {
		t.Fatalf("reveal under lease: %v", rv)
	}

	// MCP: approval_required names the request; request_access and get_lease.
	c := &mcpClient{e: &brokerEnv{t: t, h: e.h}, token: tok}
	c.initialize(mcpLatestVersion)
	tr := c.tool("http_request", map[string]any{"credential": "api", "url": up.URL + "/m"})
	if !tr.IsError || !strings.Contains(tr.Content[0].Text, "approval_required") || !strings.Contains(tr.Content[0].Text, "aar_") {
		t.Fatalf("mcp http_request: %+v", tr)
	}
	tr = c.tool("request_access", map[string]any{"credential": "other", "reason": "need it", "duration": "30m"})
	var opened map[string]any
	if tr.IsError || json.Unmarshal(tr.StructuredContent, &opened) != nil || opened["status"] != "pending" || opened["durationSeconds"].(float64) != 1800 {
		t.Fatalf("request_access: %+v", tr)
	}
	tr = c.tool("request_access", map[string]any{"credential": "other"})
	if !tr.IsError {
		t.Fatal("request_access without a reason succeeded")
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/access-requests/deny", map[string]any{"requestId": opened["requestId"], "comment": "no such credential"}, alice), http.StatusOK)
	tr = c.tool("get_lease", map[string]any{"requestId": opened["requestId"]})
	var polled map[string]any
	if tr.IsError || json.Unmarshal(tr.StructuredContent, &polled) != nil || polled["status"] != "denied" || polled["decisionComment"] != "no such credential" {
		t.Fatalf("get_lease(request): %+v", tr)
	}
	tr = c.tool("get_lease", map[string]any{})
	var leases struct {
		Leases []map[string]any `json:"leases"`
	}
	if tr.IsError || json.Unmarshal(tr.StructuredContent, &leases) != nil || len(leases.Leases) != 1 || leases.Leases[0]["credential"] != "deploy" {
		t.Fatalf("get_lease(): %+v", tr)
	}

	// The audit log attributes uses to the lease and refusals to the request.
	var leased, refused bool
	for _, ev := range e.agentEvents(e.acctA, id) {
		if strings.Contains(ev.KeyID+ev.Resource+ev.ErrorType, secret) {
			t.Fatalf("secret in audit event %+v", ev)
		}
		if ev.Action == actionAgentHTTP && ev.Result == store.AuditResultSuccess && strings.Contains(ev.Resource, " lease=als_") {
			leased = true
		}
		if ev.Action == actionAgentHTTP && ev.ErrorType == "approval_required" && strings.Contains(ev.Resource, "request="+reqID) {
			refused = true
		}
	}
	if !leased || !refused {
		t.Fatalf("audit: leased=%v refused=%v", leased, refused)
	}
}
