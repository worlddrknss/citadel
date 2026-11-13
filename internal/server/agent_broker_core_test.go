package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

// TestAgentBrokerWithAgentsCore drives the broker, reveal and MCP with real
// agents, tokens, usage profiles and grants (no fake): authentication,
// policy, suspension, write-ahead audit with the agent's identity.
func TestAgentBrokerWithAgentsCore(t *testing.T) {
	const secret = "core-broker-secret-value-123"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("auth=" + r.Header.Get("Authorization")))
	}))
	defer up.Close()
	host := strings.TrimPrefix(up.URL, "http://")

	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	e.createSecret(e.acctA, "app/prod/API_TOKEN", secret)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{
		"name": "api", "project": "app", "env": "prod", "key": "API_TOKEN", "kind": "http_header", "headerPrefix": "Bearer ",
		"allowedHosts": []string{host}, "allowHttp": true, "allowedCidrs": []string{"127.0.0.1/32"},
	}, bob), http.StatusCreated)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{
		"name": "deploy", "project": "app", "env": "prod", "key": "API_TOKEN", "kind": "raw",
	}, bob), http.StatusCreated)
	id := e.agentCreate(bob, "coder")
	tok := e.agentToken(bob, id, 1)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "api", "actions": []string{"use"}}, bob), http.StatusOK)

	// Brokered use with the real token.
	rec := e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "api", "url": up.URL + "/x?q=1"}, nil, bearer(tok), withHeader(AgentTaskHeader, "core-task"))
	wantStatus(t, rec, http.StatusOK)
	if body := decode(t, rec)["body"]; body != "auth=Bearer [REDACTED]" {
		t.Fatalf("broker body %v", body)
	}
	// A console session is not an agent credential.
	wantStatus(t, e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "api", "url": up.URL}, bob), http.StatusUnauthorized)
	// No grant for deploy; no reveal grant either.
	rec = e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "deploy", "url": up.URL}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusForbidden)
	if decode(t, rec)["reason"] != "no_grant" {
		t.Fatalf("deploy: %s", rec.Body)
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "api"}, nil, bearer(tok)), http.StatusForbidden)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "deploy", "actions": []string{"reveal"}}, bob), http.StatusOK)
	rec = e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "deploy"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["value"] != secret {
		t.Fatal("reveal returned the wrong value")
	}

	// MCP with the real token: reveal_credential is listed now.
	mcp := func(body string, sid string) *httptest.ResponseRecorder {
		opts := []reqOpt{bearer(tok), withHeader("Accept", "application/json, text/event-stream")}
		if sid != "" {
			opts = append(opts, withHeader(mcpSessionHeader, sid))
		}
		var v any
		_ = json.Unmarshal([]byte(body), &v)
		return e.do(http.MethodPost, "/mcp", v, nil, opts...)
	}
	rec = mcp(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, "")
	wantStatus(t, rec, http.StatusOK)
	sid := rec.Header().Get(mcpSessionHeader)
	rec = mcp(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, sid)
	if !strings.Contains(rec.Body.String(), `"reveal_credential"`) {
		t.Fatalf("tools/list: %s", rec.Body)
	}
	rec = mcp(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http_request","arguments":{"credential":"api","url":"`+up.URL+`/m"}}}`, sid)
	if !strings.Contains(rec.Body.String(), `Bearer [REDACTED]`) || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("http_request: %s", rec.Body)
	}

	// Suspension stops everything at once.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/suspend", map[string]any{"agentId": id}, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "api", "url": up.URL}, nil, bearer(tok)), http.StatusForbidden)
	wantStatus(t, mcp(`{"jsonrpc":"2.0","id":4,"method":"ping"}`, sid), http.StatusForbidden)

	// Audit: agent identity, task ID, write-ahead attempt, never the value.
	events := e.agentEvents(e.acctA, id)
	var apiOK, attempt, revealed, mcpHTTP bool
	for _, ev := range events {
		if strings.Contains(ev.KeyID+ev.Resource+ev.ErrorType, secret) {
			t.Fatalf("secret in audit event %+v", ev)
		}
		switch {
		case ev.Action == actionAgentHTTP && ev.Result == store.AuditResultSuccess && strings.Contains(ev.Resource, "via=api"):
			apiOK = ev.TaskID == "core-task" && ev.AgentOwner == "bob" && ev.ActorType == store.AuditActorAgent && !strings.Contains(ev.Resource, "q=1")
		case ev.Result == store.AuditResultPending && ev.Action == actionAgentHTTP:
			attempt = true
		case ev.Action == actionAgentReveal && ev.Result == store.AuditResultSuccess:
			revealed = true
		case ev.Action == actionAgentHTTP && strings.Contains(ev.Resource, "via=mcp"):
			mcpHTTP = true
		}
	}
	if !apiOK || !attempt || !revealed || !mcpHTTP {
		t.Fatalf("audit: api=%v attempt=%v reveal=%v mcp=%v in %d events", apiOK, attempt, revealed, mcpHTTP, len(events))
	}
}
