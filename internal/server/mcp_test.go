package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mcpClient drives /mcp like a Streamable HTTP client.
type mcpClient struct {
	e       *brokerEnv
	token   string
	session string
	version string
	nextID  int
}

func (c *mcpClient) post(body string, hdr map[string]string) *httptest.ResponseRecorder {
	c.e.t.Helper()
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.session != "" {
		req.Header.Set(mcpSessionHeader, c.session)
	}
	if c.version != "" {
		req.Header.Set(mcpVersionHeader, c.version)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	c.e.h.ServeHTTP(rec, req)
	return rec
}

type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

func (c *mcpClient) call(method string, params any) (rpcReply, *httptest.ResponseRecorder) {
	c.e.t.Helper()
	c.nextID++
	msg := map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method}
	if params != nil {
		msg["params"] = params
	}
	raw, _ := json.Marshal(msg)
	rec := c.post(string(raw), nil)
	var r rpcReply
	if rec.Code == http.StatusOK || strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
	}
	return r, rec
}

func (c *mcpClient) initialize(version string) rpcReply {
	c.e.t.Helper()
	r, rec := c.call("initialize", map[string]any{"protocolVersion": version, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "conformance test", "version": "1"}})
	if rec.Code != http.StatusOK || r.Error != nil {
		c.e.t.Fatalf("initialize: %d %s", rec.Code, rec.Body)
	}
	c.session = rec.Header().Get(mcpSessionHeader)
	if c.session == "" {
		c.e.t.Fatal("initialize issued no Mcp-Session-Id")
	}
	var res mcpInitializeResult
	_ = json.Unmarshal(r.Result, &res)
	c.version = res.ProtocolVersion
	if rec := c.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		c.e.t.Fatalf("notifications/initialized: %d %q", rec.Code, rec.Body)
	}
	return r
}

type toolCallResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent"`
	IsError           bool            `json:"isError"`
}

func (c *mcpClient) tool(name string, args any) toolCallResult {
	c.e.t.Helper()
	r, rec := c.call("tools/call", map[string]any{"name": name, "arguments": args})
	if rec.Code != http.StatusOK || r.Error != nil {
		c.e.t.Fatalf("tools/call %s: %d %s", name, rec.Code, rec.Body)
	}
	var tr toolCallResult
	if err := json.Unmarshal(r.Result, &tr); err != nil {
		c.e.t.Fatal(err)
	}
	return tr
}

func toolNames(t *testing.T, r rpcReply) []string {
	t.Helper()
	var res struct {
		Tools []struct {
			Name        string         `json:"name"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		if tool.InputSchema["type"] != "object" {
			t.Errorf("tool %s: inputSchema is not an object schema", tool.Name)
		}
		names = append(names, tool.Name)
	}
	return names
}

func TestMCPTransport(t *testing.T) {
	e := newBrokerEnv(t)
	c := &mcpClient{e: e, token: tokenAlpha}

	// GET (server-to-client stream) is not offered.
	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tokenAlpha)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || !strings.Contains(rec.Header().Get("Allow"), "POST") {
		t.Fatalf("GET: %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}

	// Authentication: Bearer only.
	if rec := (&mcpClient{e: e}).post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := c.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign Origin: %d", rec.Code)
	}

	// Before initialize there is no session.
	r, rec := c.call("tools/list", nil)
	if rec.Code != http.StatusBadRequest || r.Error == nil || r.Error.Code != rpcInvalidRequest {
		t.Fatalf("tools/list without session: %d %s", rec.Code, rec.Body)
	}

	// Version negotiation.
	init := c.initialize("2025-06-18")
	var ir mcpInitializeResult
	_ = json.Unmarshal(init.Result, &ir)
	if ir.ProtocolVersion != "2025-06-18" || ir.ServerInfo.Name != "citadel" || ir.Capabilities["tools"] == nil {
		t.Errorf("initialize result: %+v", ir)
	}
	if string(init.ID) != "2" {
		t.Errorf("initialize id: %s", init.ID)
	}
	old := &mcpClient{e: e, token: tokenAlpha}
	old.initialize("2025-03-26")
	if old.version != "2025-03-26" {
		t.Errorf("2025-03-26 not echoed: %s", old.version)
	}
	future := &mcpClient{e: e, token: tokenAlpha}
	future.initialize("2099-01-01")
	if future.version != mcpLatestVersion {
		t.Errorf("unknown version answered with %s", future.version)
	}

	// ping, string ids.
	if rec := c.post(`{"jsonrpc":"2.0","id":"abc","method":"ping"}`, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"id":"abc"`) || !strings.Contains(rec.Body.String(), `"result":{}`) {
		t.Errorf("ping: %d %s", rec.Code, rec.Body)
	}
	// Protocol errors.
	for name, tc := range map[string]struct {
		body   string
		hdr    map[string]string
		status int
		code   int
	}{
		"unknown method": {`{"jsonrpc":"2.0","id":2,"method":"resources/list"}`, nil, 200, rpcMethodNotFound},
		"parse error":    {`{"jsonrpc":`, nil, 400, rpcParseError},
		"batch":          {`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, nil, 400, rpcInvalidRequest},
		"no jsonrpc":     {`{"id":3,"method":"ping"}`, nil, 400, rpcInvalidRequest},
		"object id":      {`{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`, nil, 400, rpcInvalidRequest},
		"bad version":    {`{"jsonrpc":"2.0","id":4,"method":"ping"}`, map[string]string{mcpVersionHeader: "1999-01-01"}, 400, rpcInvalidRequest},
		"wrong version":  {`{"jsonrpc":"2.0","id":4,"method":"ping"}`, map[string]string{mcpVersionHeader: "2025-03-26"}, 400, rpcInvalidRequest},
		"bad session":    {`{"jsonrpc":"2.0","id":5,"method":"ping"}`, map[string]string{mcpSessionHeader: "mcs1.forged.sig"}, 404, rpcSessionError},
		"unknown tool":   {`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"rm_rf","arguments":{}}}`, nil, 200, rpcInvalidParams},
	} {
		rec := c.post(tc.body, tc.hdr)
		var r rpcReply
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		if rec.Code != tc.status || r.Error == nil || r.Error.Code != tc.code || r.JSONRPC != "2.0" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := c.post(`{"jsonrpc":"2.0","id":7,"method":"ping"}`, map[string]string{"Content-Type": "text/plain"}); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", rec.Code)
	}
	if rec := c.post(`{"jsonrpc":"2.0","id":7,"method":"ping"}`, map[string]string{"Accept": "text/html"}); rec.Code != http.StatusNotAcceptable {
		t.Errorf("Accept text/html: %d", rec.Code)
	}
	// A client response to a server request is accepted and ignored.
	if rec := c.post(`{"jsonrpc":"2.0","id":9,"result":{}}`, nil); rec.Code != http.StatusAccepted {
		t.Errorf("client response: %d", rec.Code)
	}
	// Without MCP-Protocol-Version the session's version is assumed.
	if rec := c.post(`{"jsonrpc":"2.0","id":8,"method":"ping"}`, map[string]string{mcpVersionHeader: ""}); rec.Code != 200 {
		t.Errorf("no version header: %d", rec.Code)
	}

	// A session belongs to its agent.
	beta := &mcpClient{e: e, token: tokenBeta, session: c.session, version: c.version}
	if r, rec := beta.call("ping", nil); rec.Code != http.StatusNotFound || r.Error == nil {
		t.Errorf("another agent's session: %d %s", rec.Code, rec.Body)
	}

	// DELETE ends the session.
	del := func(sid string) int {
		req := httptest.NewRequest("DELETE", "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+tokenAlpha)
		req.Header.Set(mcpSessionHeader, sid)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := del(c.session); code != http.StatusNoContent {
		t.Fatalf("DELETE: %d", code)
	}
	if _, rec := c.call("ping", nil); rec.Code != http.StatusNotFound {
		t.Errorf("ended session still works: %d", rec.Code)
	}
	if code := del(c.session); code != http.StatusNotFound {
		t.Errorf("second DELETE: %d", code)
	}

	if ev := e.lastAudit(actionMCPInitialize); ev.Actor != "agt_alpha" || !strings.Contains(ev.Resource, "client=conformance%20test") {
		t.Errorf("initialize audit: %+v", ev)
	}
	if ev := e.lastAudit(actionMCPEndSession); ev.Result != "success" {
		t.Errorf("end-session audit: %+v", ev)
	}
}

func TestMCPSessionExpiry(t *testing.T) {
	e := newBrokerEnv(t)
	c := &agentCaller{AccountID: e.acct, AgentID: "agt_alpha"}
	now := time.Now()
	sid, err := e.s.issueMCPSession(c, mcpLatestVersion, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.s.parseMCPSession(sid, c, now.Add(time.Hour)); !ok {
		t.Fatal("fresh session refused")
	}
	if _, ok := e.s.parseMCPSession(sid, c, now.Add(mcpSessionLifetime)); ok {
		t.Fatal("expired session accepted")
	}
	tampered := sid[:len(sid)-2] + "AA"
	if _, ok := e.s.parseMCPSession(tampered, c, now); ok {
		t.Fatal("tampered session accepted")
	}
	other := &agentCaller{AccountID: "other", AgentID: "agt_alpha"}
	if _, ok := e.s.parseMCPSession(sid, other, now); ok {
		t.Fatal("session accepted for another account")
	}
}

func TestMCPTools(t *testing.T) {
	e := newBrokerEnv(t)
	alpha := &mcpClient{e: e, token: tokenAlpha}
	alpha.initialize(mcpLatestVersion)
	beta := &mcpClient{e: e, token: tokenBeta}
	beta.initialize(mcpLatestVersion)

	r, _ := alpha.call("tools/list", map[string]any{})
	if got := strings.Join(toolNames(t, r), ","); got != "list_credentials,http_request,reveal_credential,request_access,get_lease" {
		t.Errorf("alpha tools: %s", got)
	}
	r, _ = beta.call("tools/list", nil)
	if got := strings.Join(toolNames(t, r), ","); got != "list_credentials,http_request,request_access,get_lease" {
		t.Errorf("beta tools (no reveal grant): %s", got)
	}

	lc := beta.tool("list_credentials", map[string]any{})
	if lc.IsError || len(lc.Content) != 1 || lc.Content[0].Type != "text" {
		t.Fatalf("list_credentials: %+v", lc)
	}
	var creds mcpCredentialsResult
	_ = json.Unmarshal(lc.StructuredContent, &creds)
	if len(creds.Credentials) != 1 || creds.Credentials[0].Name != "upstream" || creds.Credentials[0].Actions[0] != "use" {
		t.Errorf("beta credentials: %+v", creds)
	}
	if strings.Contains(lc.Content[0].Text, brokerSecret) {
		t.Fatal("list_credentials leaked a value")
	}

	hr := alpha.tool("http_request", map[string]any{"credential": "upstream", "url": e.up.URL + "/echo", "taskId": "mcp-task"})
	if hr.IsError {
		t.Fatalf("http_request: %+v", hr)
	}
	var resp struct {
		Status   int    `json:"status"`
		Body     string `json:"body"`
		Redacted bool   `json:"redacted"`
	}
	_ = json.Unmarshal(hr.StructuredContent, &resp)
	if resp.Status != 200 || !resp.Redacted || !strings.Contains(resp.Body, "Bearer [REDACTED]") || strings.Contains(hr.Content[0].Text, brokerSecret) {
		t.Errorf("http_request result: %+v", resp)
	}
	if ev := e.lastAudit(actionAgentHTTP); !strings.Contains(ev.Resource, "via=mcp") || ev.Result != "success" {
		t.Errorf("http_request audit: %+v", ev)
	}

	// Tool failures are results with isError, not protocol errors.
	denied := beta.tool("http_request", map[string]any{"credential": "query", "url": e.up.URL + "/echo"})
	if !denied.IsError || !strings.HasPrefix(denied.Content[0].Text, "no_grant:") {
		t.Errorf("denied http_request: %+v", denied)
	}
	badHost := alpha.tool("http_request", map[string]any{"credential": "upstream", "url": "https://evil.example/"})
	if !badHost.IsError || !strings.HasPrefix(badHost.Content[0].Text, "host_not_allowed:") {
		t.Errorf("bad host: %+v", badHost)
	}
	badArgs := alpha.tool("http_request", map[string]any{"credential": "upstream", "url": e.up.URL, "evil": true})
	if !badArgs.IsError || !strings.HasPrefix(badArgs.Content[0].Text, "invalid_arguments:") {
		t.Errorf("unknown argument: %+v", badArgs)
	}

	rv := alpha.tool("reveal_credential", map[string]any{"credential": "raw"})
	var rr agentRevealResponse
	_ = json.Unmarshal(rv.StructuredContent, &rr)
	if rv.IsError || rr.Value != `{"user":"x","pass":"y"}` {
		t.Errorf("reveal: %+v", rv)
	}
	if ev := e.lastAudit(actionAgentReveal); !strings.Contains(ev.Resource, "via=mcp") || ev.Result != "success" {
		t.Errorf("reveal audit: %+v", ev)
	}
	notGranted := beta.tool("reveal_credential", map[string]any{"credential": "upstream"})
	if !notGranted.IsError || !strings.HasPrefix(notGranted.Content[0].Text, "action_not_granted:") {
		t.Errorf("reveal without grant: %+v", notGranted)
	}
	if ev := e.lastAudit(actionAgentListCredentials); ev.Actor != "agt_beta" {
		t.Errorf("list audit: %+v", ev)
	}
	e.assertNoSecret()
}
