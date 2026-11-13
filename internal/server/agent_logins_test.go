package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/store"
)

const (
	testTOTPSeed256 = "otpauth://totp/Example:bot?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30"
	testTOTPSeedSHA = "otpauth://totp/Example:bot?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	testLoginPass   = "hunter2-correct-horse-battery"
)

// mcpCall runs one JSON-RPC message against /mcp with an agent token.
func (e *authEnv) mcpCall(tok, sid, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	opts := []reqOpt{bearer(tok), withHeader("Accept", "application/json, text/event-stream")}
	if sid != "" {
		opts = append(opts, withHeader(mcpSessionHeader, sid))
	}
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		e.t.Fatal(err)
	}
	return e.do(http.MethodPost, "/mcp", v, nil, opts...)
}

func (e *authEnv) mcpSession(tok string) string {
	e.t.Helper()
	rec := e.mcpCall(tok, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	wantStatus(e.t, rec, http.StatusOK)
	return rec.Header().Get(mcpSessionHeader)
}

func TestAgentLoginCredentials(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	doc, _ := json.Marshal(map[string]string{"username": "bot@example.com", "password": testLoginPass, "totpSeed": testTOTPSeed256})
	e.createSecret(e.acctA, "web/prod/APP_LOGIN", string(doc))

	// A login needs URL patterns; http patterns and SHA-1 profile algorithms are refused.
	base := map[string]any{"name": "app-login", "project": "web", "env": "prod", "key": "APP_LOGIN", "kind": "login"}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", base, bob), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", with(map[string]any{"login": map[string]any{"urlPatterns": []string{"http://app.example.com/"}}}), bob), http.StatusBadRequest)
	rec := e.do(http.MethodPost, "/v1/agents/credentials", with(map[string]any{"login": map[string]any{"urlPatterns": []string{"https://app.example.com/"}, "totpAlgorithm": "SHA1"}}), bob)
	wantStatus(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), "FIPS") {
		t.Fatalf("SHA1 refusal doesn't explain FIPS: %s", rec.Body)
	}
	rec = e.do(http.MethodPost, "/v1/agents/credentials", with(map[string]any{"login": map[string]any{"urlPatterns": []string{"https://APP.example.com/login", "https://*.example.org"}}}), bob)
	wantStatus(t, rec, http.StatusCreated)
	if pats := decode(t, rec)["login"].(map[string]any)["urlPatterns"].([]any); pats[0] != "https://app.example.com/login" || pats[1] != "https://*.example.org/" {
		t.Fatalf("patterns = %v", pats)
	}

	id := e.agentCreate(bob, "browser")
	tok := e.agentToken(bob, id, 1)
	// use is not a login action... it is allowed on logins only via reveal/totp.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "app-login", "actions": []string{"totp"}}, bob), http.StatusOK)

	// TOTP: the current code, never the seed.
	rec = e.do(http.MethodPost, "/v1/agent/totp", map[string]any{"credential": "app-login", "taskId": "login-1"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	out := decode(t, rec)
	gen, err := providertoken.ParseTOTPURI(testTOTPSeed256)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := gen.Code(time.Now())
	if out["code"] != want || out["algorithm"] != "SHA256" || out["digits"] != float64(6) || out["secondsRemaining"].(float64) > 30 {
		t.Fatalf("totp = %v (want code %s)", out, want)
	}
	if strings.Contains(rec.Body.String(), "JBSWY3DP") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("seed leaked or response cacheable: %s", rec.Body)
	}
	// get_login needs reveal.
	rec = e.do(http.MethodPost, "/v1/agent/login", map[string]any{"credential": "app-login", "url": "https://app.example.com/login"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusForbidden)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "app-login", "actions": []string{"totp", "reveal"}}, bob), http.StatusOK)
	for _, c := range []struct {
		url    string
		status int
		reason string
	}{
		{"https://app.example.com/login", 200, ""},
		{"https://app.example.com/login/sso?next=/x", 200, ""},
		{"https://app.example.com/loginx", 403, "url_not_allowed"},
		{"https://evil.example.com/login", 403, "url_not_allowed"},
		{"https://app.example.com:8443/login", 403, "url_not_allowed"},
		{"https://a.example.org/anything", 200, ""},
		{"https://example.org/", 403, "url_not_allowed"},
		{"http://app.example.com/login", 400, "invalid_url"},
	} {
		rec = e.do(http.MethodPost, "/v1/agent/login", map[string]any{"credential": "app-login", "url": c.url}, nil, bearer(tok))
		wantStatus(t, rec, c.status)
		got := decode(t, rec)
		if c.status == 200 && (got["username"] != "bot@example.com" || got["password"] != testLoginPass) {
			t.Fatalf("%s: %v", c.url, got)
		}
		if c.reason != "" && got["reason"] != c.reason {
			t.Fatalf("%s: reason %v", c.url, got["reason"])
		}
	}
	// Reveal of a login never includes the TOTP seed.
	rec = e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "app-login"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	if v := decode(t, rec)["value"].(string); strings.Contains(v, "totp") || !strings.Contains(v, testLoginPass) {
		t.Fatalf("reveal value %q", v)
	}

	// MCP: both tools are listed and work through the same checks.
	sid := e.mcpSession(tok)
	rec = e.mcpCall(tok, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if !strings.Contains(rec.Body.String(), `"get_totp_code"`) || !strings.Contains(rec.Body.String(), `"get_login"`) {
		t.Fatalf("tools/list: %s", rec.Body)
	}
	rec = e.mcpCall(tok, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_totp_code","arguments":{"credential":"app-login"}}}`)
	if !strings.Contains(rec.Body.String(), `"secondsRemaining"`) || strings.Contains(rec.Body.String(), "JBSWY3DP") {
		t.Fatalf("get_totp_code: %s", rec.Body)
	}
	rec = e.mcpCall(tok, sid, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_login","arguments":{"credential":"app-login","url":"https://evil.example.net/"}}}`)
	if !strings.Contains(rec.Body.String(), `url_not_allowed`) || !strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Fatalf("get_login refused: %s", rec.Body)
	}

	// Console: state without secrets, a live preview, write-only seed.
	rec = e.do(http.MethodGet, "/v1/agents/credentials/login?name=app-login&code=true", nil, bob)
	wantStatus(t, rec, http.StatusOK)
	st := decode(t, rec)
	if st["username"] != "bot@example.com" || st["hasPassword"] != true || st["hasTotpSeed"] != true || st["totpStatus"] != "ok" || st["totp"] == nil {
		t.Fatalf("login state = %v", st)
	}
	if strings.Contains(rec.Body.String(), testLoginPass) || strings.Contains(rec.Body.String(), "JBSWY3DP") {
		t.Fatalf("console state leaks secrets: %s", rec.Body)
	}
	rec = e.do(http.MethodPost, "/v1/agents/credentials/login", map[string]any{"name": "app-login", "totpSeed": testTOTPSeedSHA}, bob)
	wantStatus(t, rec, http.StatusBadRequest)
	if decode(t, rec)["error"] != "totp_sha1_unsupported" {
		t.Fatalf("SHA1 seed: %s", rec.Body)
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials/login", map[string]any{"name": "app-login", "password": "new-password-value-1"}, e.session("carol", e.acctB)), http.StatusForbidden)
	rec = e.do(http.MethodPost, "/v1/agents/credentials/login", map[string]any{"name": "app-login", "password": "new-password-value-1"}, bob)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["hasTotpSeed"] != true {
		t.Fatal("changing the password dropped the seed")
	}
	rec = e.do(http.MethodPost, "/v1/agent/login", map[string]any{"credential": "app-login", "url": "https://app.example.com/login"}, nil, bearer(tok))
	if decode(t, rec)["password"] != "new-password-value-1" {
		t.Fatalf("new password not used: %s", rec.Body)
	}
	rec = e.do(http.MethodPost, "/v1/agents/credentials/login", map[string]any{"name": "app-login", "clearTotpSeed": true}, bob)
	wantStatus(t, rec, http.StatusOK)
	rec = e.do(http.MethodPost, "/v1/agent/totp", map[string]any{"credential": "app-login"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusConflict)
	if decode(t, rec)["reason"] != "totp_not_configured" {
		t.Fatalf("no seed: %s", rec.Body)
	}

	// A SHA-1 seed stored directly gets the FIPS explanation from the agent API too.
	doc, _ = json.Marshal(map[string]string{"username": "u", "password": "p", "totpSeed": testTOTPSeedSHA})
	e.createSecret(e.acctA, "web/prod/OLD_LOGIN", string(doc))
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{"name": "old-login", "project": "web", "env": "prod", "key": "OLD_LOGIN", "kind": "login",
		"login": map[string]any{"urlPatterns": []string{"https://old.example.com/"}}}, bob), http.StatusCreated)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "old-login", "actions": []string{"totp"}}, bob), http.StatusOK)
	rec = e.do(http.MethodPost, "/v1/agent/totp", map[string]any{"credential": "old-login"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusConflict)
	if got := decode(t, rec); got["reason"] != "totp_sha1_unsupported" || !strings.Contains(got["message"].(string), "FIPS 140-3") {
		t.Fatalf("SHA1 via agent: %v", got)
	}

	// Audit: TOTP and logins with host and path (no query), never values.
	var totpOK, loginOK, readLogin, putLogin bool
	for _, ev := range e.agentEvents(e.acctA, id) {
		if strings.Contains(ev.Resource+ev.KeyID, testLoginPass) || strings.Contains(ev.Resource, "next=") {
			t.Fatalf("audit leaks: %+v", ev)
		}
		switch {
		case ev.Action == actionAgentTOTP && ev.Result == store.AuditResultSuccess:
			totpOK = totpOK || ev.TaskID == "login-1"
		case ev.Action == actionAgentGetLogin && ev.Result == store.AuditResultSuccess:
			loginOK = loginOK || strings.Contains(ev.Resource, "host=app.example.com path=/login/sso ")
		}
	}
	readLogin, putLogin = e.audited(auditReadAgentLogin, "ok"), e.audited(auditPutAgentLogin, "ok")
	if !totpOK || !loginOK || !readLogin || !putLogin {
		t.Fatalf("audit: totp=%v login=%v read=%v put=%v", totpOK, loginOK, readLogin, putLogin)
	}
}

func TestMatchLoginURL(t *testing.T) {
	pats := []string{"https://app.example.com/login", "https://*.example.org/", "https://h.example.net:8443/a/"}
	for raw, want := range map[string]bool{
		"https://app.example.com/login":       true,
		"https://APP.example.com./login":      true,
		"https://app.example.com:443/login":   true,
		"https://app.example.com/login/":      true,
		"https://app.example.com/log":         false,
		"https://app.example.com/a/../login":  false,
		"https://u:p@app.example.com/login":   false,
		"https://x.y.example.org/q":           true,
		"https://example.org/":                false,
		"https://h.example.net:8443/a/b":      true,
		"https://h.example.net/a/b":           false,
		"https://app.example.com/%2e%2e/x":    false,
		"javascript:alert(1)":                 false,
		"https://app.example.com.evil/login":  false,
		"https://app.example.com/login?x=../": true,
	} {
		if _, got := matchLoginURL(pats, raw); got != want {
			t.Errorf("matchLoginURL(%q) = %v, want %v", raw, got, want)
		}
	}
}
