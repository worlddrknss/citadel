package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/agentbroker"
	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// fakeAgentAccess stands in for the agents core in handler tests.
type fakeAgentAccess struct {
	mu      sync.Mutex
	tokens  map[string]*agentCaller // bearer token -> agent
	creds   map[string]fakeCredential
	grants  map[string]map[string][]string // agentID -> credential -> actions
	limited map[string]bool                // credential -> rate limited
	evals   int
}

type fakeCredential struct {
	info    agentCredentialInfo
	profile agentbroker.Profile
	secret  string
}

func (f *fakeAgentAccess) authenticate(w http.ResponseWriter, r *http.Request, _ string) (*agentCaller, context.Context, bool) {
	tok := bearerFrom(r)
	f.mu.Lock()
	c, ok := f.tokens[tok]
	f.mu.Unlock()
	if tok == "" || !ok {
		writeAgentBrokerError(w, http.StatusUnauthorized, "unauthorized", "invalid_credential", "invalid or inactive agent credential")
		return nil, nil, false
	}
	cc := *c
	if v := r.Header.Get("X-Citadel-Task-Id"); v != "" {
		cc.TaskID = v
	}
	return &cc, store.WithCallerAccount(r.Context(), cc.AccountID), true
}

func bearerFrom(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if len(a) < 7 || !strings.EqualFold(a[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(a[7:])
}

func (f *fakeAgentAccess) evaluate(_ context.Context, c *agentCaller, name, action string) agentUse {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evals++
	cred, ok := f.creds[name]
	actions, granted := f.grants[c.AgentID][name]
	if !ok || !granted {
		return agentUse{Reason: "no_grant"}
	}
	has := false
	for _, a := range actions {
		has = has || a == action
	}
	if !has {
		return agentUse{Reason: "action_not_granted"}
	}
	if f.limited[name] {
		return agentUse{Reason: "rate_limited", RetryAfter: 90 * time.Second}
	}
	info := cred.info
	info.Actions = actions
	return agentUse{Allowed: true, Credential: info, Profile: cred.profile, ref: name}
}

func (f *fakeAgentAccess) minter(_ context.Context, _ *agentCaller, u agentUse) (providertoken.Minter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, _ := u.ref.(string)
	c, ok := f.creds[name]
	if !ok {
		return nil, errors.New("gone")
	}
	return providertoken.Static{Value: c.secret}, nil
}

func (f *fakeAgentAccess) credentials(_ context.Context, c *agentCaller) ([]agentCredentialInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []agentCredentialInfo
	for name, actions := range f.grants[c.AgentID] {
		info := f.creds[name].info
		info.Actions = actions
		info.Status = "available"
		out = append(out, info)
	}
	return out, nil
}

func (f *fakeAgentAccess) auditOrigin(r *http.Request, c *agentCaller) store.AuditOrigin {
	return store.AuditOrigin{AccountID: c.AccountID, Actor: c.AgentID, ActorType: "agent", ActorDisplayName: c.Name, SourceIP: "192.0.2.1", UserAgent: r.UserAgent()}
}

const (
	brokerSecret = "ghp_s3cr3tValueThatMustNeverLeak"
	tokenAlpha   = "cagt_alpha"
	tokenBeta    = "cagt_beta"
)

type brokerEnv struct {
	t    *testing.T
	s    *Server
	st   store.Store
	h    http.Handler
	fake *fakeAgentAccess
	acct string
	up   *httptest.Server
	host string // upstream host:port
}

func newBrokerEnv(t *testing.T) *brokerEnv {
	t.Helper()
	st := &memory.Store{DefaultKey: sampleKey(1)}
	acct, err := st.CreateUIAccount(context.Background(), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertUIUser(context.Background(), store.UIUser{Username: "admin", Role: "admin", PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	e := &brokerEnv{t: t, st: st, acct: acct}
	e.up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Add("Set-Cookie", "upstream=1")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization": r.Header.Get("Authorization"),
				"cookie":        r.Header.Get("Cookie"),
				"method":        r.Method,
				"query":         r.URL.RawQuery,
				"b64":           base64.StdEncoding.EncodeToString([]byte(brokerSecret)),
			})
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte("x"), 6<<20))
		case "/status":
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte("teapot"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(e.up.Close)
	e.host = strings.TrimPrefix(e.up.URL, "http://")
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	e.fake = &fakeAgentAccess{
		tokens: map[string]*agentCaller{
			tokenAlpha: {AccountID: acct, AgentID: "agt_alpha", Name: "alpha-bot", Owner: "admin"},
			tokenBeta:  {AccountID: acct, AgentID: "agt_beta", Name: "beta-bot", Owner: "admin"},
		},
		creds: map[string]fakeCredential{
			"upstream": {
				info:    agentCredentialInfo{Name: "upstream", Kind: agentbroker.KindHTTPHeader, Description: "test API", AllowedHosts: []string{e.host}},
				profile: agentbroker.Profile{Kind: agentbroker.KindHTTPHeader, HeaderPrefix: "Bearer ", AllowedHosts: []string{e.host}, AllowHTTP: true, AllowedCIDRs: loopback},
				secret:  brokerSecret,
			},
			"no-cidr": {
				info:    agentCredentialInfo{Name: "no-cidr", Kind: agentbroker.KindHTTPHeader, AllowedHosts: []string{e.host}},
				profile: agentbroker.Profile{Kind: agentbroker.KindHTTPHeader, AllowedHosts: []string{e.host}, AllowHTTP: true},
				secret:  brokerSecret,
			},
			"query": {
				info:    agentCredentialInfo{Name: "query", Kind: agentbroker.KindHTTPQuery, AllowedHosts: []string{e.host}},
				profile: agentbroker.Profile{Kind: agentbroker.KindHTTPQuery, QueryParam: "key", AllowedHosts: []string{e.host}, AllowHTTP: true, AllowedCIDRs: loopback},
				secret:  brokerSecret,
			},
			"raw": {
				info:    agentCredentialInfo{Name: "raw", Kind: "raw"},
				profile: agentbroker.Profile{Kind: "raw"},
				secret:  `{"user":"x","pass":"y"}`,
			},
		},
		grants: map[string]map[string][]string{
			"agt_alpha": {"upstream": {"use"}, "no-cidr": {"use"}, "query": {"use"}, "raw": {"use", "reveal"}},
			"agt_beta":  {"upstream": {"use"}},
		},
		limited: map[string]bool{},
	}
	e.s = &Server{cfg: config.Config{SessionIdleTTL: 30 * time.Minute, SessionAbsTTL: 12 * time.Hour}, store: st}
	e.s.agentBrokerRT().access = e.fake
	e.h = e.s.Handler()
	return e
}

func (e *brokerEnv) do(method, path, token string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rdr = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *brokerEnv) audit() []store.AuditRecord {
	e.t.Helper()
	recs, err := e.st.ListAuditEvents(store.WithCallerAccount(context.Background(), e.acct), 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return recs
}

// lastAudit returns the newest event with action.
func (e *brokerEnv) lastAudit(action string) store.AuditRecord {
	e.t.Helper()
	var found *store.AuditRecord
	for _, r := range e.audit() {
		if r.Action == action && (found == nil || r.ID > found.ID) {
			rc := r
			found = &rc
		}
	}
	if found == nil {
		e.t.Fatalf("no %s audit event", action)
	}
	return *found
}

// assertNoSecret fails if the secret (or its base64 form) appears in any
// audit record or in the metrics.
func (e *brokerEnv) assertNoSecret() {
	e.t.Helper()
	forms := []string{brokerSecret, base64.StdEncoding.EncodeToString([]byte(brokerSecret))}
	raw, _ := json.Marshal(e.audit())
	rec := httptest.NewRecorder()
	e.s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, f := range forms {
		if bytes.Contains(raw, []byte(f)) {
			e.t.Fatal("secret found in the audit log")
		}
		if strings.Contains(rec.Body.String(), f) {
			e.t.Fatal("secret found in metrics")
		}
	}
	for _, label := range []string{"upstream", "agt_alpha", "127.0.0.1"} {
		if strings.Contains(rec.Body.String(), `"`+label+`"`) {
			e.t.Fatalf("metrics carry a high-cardinality label value %q", label)
		}
	}
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestAgentHTTPAuthentication(t *testing.T) {
	e := newBrokerEnv(t)
	body := map[string]any{"credential": "upstream", "url": e.up.URL + "/echo"}
	if rec := e.do("POST", "/v1/agent/http", "", body, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := e.do("POST", "/v1/agent/http", "nope", body, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
	// A console cookie is no credential here, and a cross-origin request
	// is not CSRF-rejected (there is no ambient credential to abuse): it
	// just fails authentication.
	req := httptest.NewRequest("POST", "/v1/agent/http", strings.NewReader(`{"credential":"upstream","url":"`+e.up.URL+`/echo"}`))
	req.AddCookie(&http.Cookie{Name: "citadel_session", Value: "whatever"})
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie request: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/v1/agent/http", tokenAlpha, body, map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusOK {
		t.Fatalf("cross-origin bearer request: %d %s", rec.Code, rec.Body)
	}
}

func TestAgentHTTPBrokersWithInjectionAndRedaction(t *testing.T) {
	e := newBrokerEnv(t)
	rec := e.do("POST", "/v1/agent/http", tokenAlpha, map[string]any{
		"credential": "upstream", "method": "post", "url": e.up.URL + "/echo?page=2&token=abc",
		"headers": map[string]string{"Authorization": "Bearer agent", "Cookie": "a=b", "Accept": "application/json"},
		"body":    "hello", "taskId": "task-42",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), brokerSecret) || strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString([]byte(brokerSecret))) {
		t.Fatal("secret leaked to the agent")
	}
	var resp agentbroker.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var upstream map[string]string
	if err := json.Unmarshal([]byte(resp.Body), &upstream); err != nil {
		t.Fatalf("body %q: %v", resp.Body, err)
	}
	if upstream["authorization"] != "Bearer [REDACTED]" || upstream["b64"] != "[REDACTED]" || upstream["cookie"] != "" || upstream["method"] != "POST" {
		t.Errorf("upstream saw %v", upstream)
	}
	if !resp.Redacted || resp.Status != 200 || resp.Headers["Set-Cookie"] != "" {
		t.Errorf("response %+v", resp)
	}
	ev := e.lastAudit(actionAgentHTTP)
	if ev.Result != store.AuditResultSuccess || ev.KeyID != "upstream" || ev.Actor != "agt_alpha" {
		t.Errorf("audit %+v", ev)
	}
	for _, want := range []string{"credential=upstream", "method=POST", "host=127.0.0.1", "path=/echo ", "status=200", "via=api", "redacted=true"} {
		if !strings.Contains(ev.Resource+" ", want) {
			t.Errorf("audit resource %q lacks %q", ev.Resource, want)
		}
	}
	if strings.Contains(ev.Resource, "page=2") || strings.Contains(ev.Resource, "token=abc") {
		t.Errorf("audit resource carries the query string: %q", ev.Resource)
	}
	// Upstream error statuses are results, not broker failures.
	rec = e.do("POST", "/v1/agent/http", tokenAlpha, map[string]any{"credential": "upstream", "url": e.up.URL + "/status"}, nil)
	if rec.Code != http.StatusOK || decodeMap(t, rec)["status"].(float64) != http.StatusTeapot {
		t.Errorf("upstream 418: %d %s", rec.Code, rec.Body)
	}
	// The query credential is added and any agent-supplied value replaced.
	rec = e.do("POST", "/v1/agent/http", tokenAlpha, map[string]any{"credential": "query", "url": e.up.URL + "/echo?key=mine"}, nil)
	var qr agentbroker.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &qr)
	if !strings.Contains(qr.Body, `"query":"key=[REDACTED]"`) {
		t.Errorf("query injection: %s", qr.Body)
	}
	e.assertNoSecret()
}

func TestAgentHTTPDenials(t *testing.T) {
	e := newBrokerEnv(t)
	cases := []struct {
		name   string
		token  string
		body   map[string]any
		status int
		reason string
	}{
		{"no grant", tokenBeta, map[string]any{"credential": "query", "url": e.up.URL + "/echo"}, 403, "no_grant"},
		{"unknown credential", tokenAlpha, map[string]any{"credential": "missing", "url": e.up.URL + "/echo"}, 403, "no_grant"},
		{"host", tokenAlpha, map[string]any{"credential": "upstream", "url": "http://evil.example/echo"}, 403, "host_not_allowed"},
		{"scheme", tokenAlpha, map[string]any{"credential": "upstream", "url": "ftp://" + e.host + "/"}, 400, "invalid_url"},
		{"userinfo", tokenAlpha, map[string]any{"credential": "upstream", "url": "http://u:p@" + e.host + "/"}, 400, "invalid_url"},
		{"raw kind", tokenAlpha, map[string]any{"credential": "raw", "url": e.up.URL}, 400, "kind_not_brokerable"},
		{"missing credential", tokenAlpha, map[string]any{"url": e.up.URL}, 400, "invalid_request"},
		{"bad task id", tokenAlpha, map[string]any{"credential": "upstream", "url": e.up.URL, "taskId": "has space"}, 400, "invalid_task_id"},
		{"ssrf", tokenAlpha, map[string]any{"credential": "no-cidr", "url": e.up.URL + "/echo"}, 403, "destination_blocked"},
		{"body too large", tokenAlpha, map[string]any{"credential": "upstream", "url": e.up.URL, "body": strings.Repeat("a", 1<<20+1)}, 413, "body_too_large"},
	}
	for _, c := range cases {
		rec := e.do("POST", "/v1/agent/http", c.token, c.body, nil)
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d: %s", c.name, rec.Code, c.status, rec.Body)
			continue
		}
		if got := decodeMap(t, rec)["reason"]; got != c.reason {
			t.Errorf("%s: reason %v, want %s", c.name, got, c.reason)
		}
		ev := e.lastAudit(actionAgentHTTP)
		if ev.ErrorType != c.reason || ev.Result == store.AuditResultSuccess {
			t.Errorf("%s: audit %s/%s", c.name, ev.Result, ev.ErrorType)
		}
	}
	if rec := e.do("POST", "/v1/agent/http", tokenAlpha, `{"credential":"upstream","url":"x","extra":1}`, nil); rec.Code != 400 {
		t.Errorf("unknown member: %d", rec.Code)
	}
	e.fake.limited["upstream"] = true
	rec := e.do("POST", "/v1/agent/http", tokenAlpha, map[string]any{"credential": "upstream", "url": e.up.URL + "/echo"}, nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "91" {
		t.Errorf("rate limited: %d Retry-After=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	e.assertNoSecret()
}

func TestAgentHTTPSizeCapAndTLS(t *testing.T) {
	e := newBrokerEnv(t)
	rec := e.do("POST", "/v1/agent/http", tokenAlpha, map[string]any{"credential": "upstream", "url": e.up.URL + "/big"}, nil)
	var resp agentbroker.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != 200 || !resp.Truncated || len(resp.Body) != agentbroker.DefaultMaxResponseBody {
		t.Errorf("big: %d truncated=%v len=%d", rec.Code, resp.Truncated, len(resp.Body))
	}
	if ev := e.lastAudit(actionAgentHTTP); !strings.Contains(ev.Resource, "truncated=true") {
		t.Errorf("audit: %q", ev.Resource)
	}

	tlsUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls " + r.Header.Get("Authorization")))
	}))
	defer tlsUp.Close()
	host := strings.TrimPrefix(tlsUp.URL, "https://")
	e.fake.creds["tls"] = fakeCredential{
		info:    agentCredentialInfo{Name: "tls", Kind: agentbroker.KindHTTPHeader, AllowedHosts: []string{host}},
		profile: agentbroker.Profile{Kind: agentbroker.KindHTTPHeader, HeaderPrefix: "Bearer ", AllowedHosts: []string{host}, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
		secret:  brokerSecret,
	}
	e.fake.grants["agt_alpha"]["tls"] = []string{"use"}
	pool := x509.NewCertPool()
	pool.AddCert(tlsUp.Certificate())
	e.s.agentBrokerRT().client = func(allowed []netip.Prefix) *http.Client {
		c := newGuardedHTTPClient(allowed, 10*time.Second)
		c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		return c
	}
	rec = e.do("POST", "/v1/agent/http", tokenAlpha, map[string]any{"credential": "tls", "url": tlsUp.URL + "/"}, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != 200 || resp.Body != "tls Bearer [REDACTED]" {
		t.Errorf("tls: %d %+v", rec.Code, resp)
	}
	// Plain http is refused for a credential without allowHttp.
	rec = e.do("POST", "/v1/agent/http", tokenAlpha, map[string]any{"credential": "tls", "url": "http://" + host + "/"}, nil)
	if rec.Code != http.StatusForbidden || decodeMap(t, rec)["reason"] != "scheme_not_allowed" {
		t.Errorf("http for https-only credential: %d %s", rec.Code, rec.Body)
	}
	e.assertNoSecret()
}

func TestAgentReveal(t *testing.T) {
	e := newBrokerEnv(t)
	rec := e.do("POST", "/v1/agent/credentials/reveal", tokenAlpha, map[string]any{"credential": "upstream"}, nil)
	if rec.Code != http.StatusForbidden || decodeMap(t, rec)["reason"] != "action_not_granted" {
		t.Fatalf("reveal without grant: %d %s", rec.Code, rec.Body)
	}
	if ev := e.lastAudit(actionAgentReveal); ev.Result != store.AuditResultDenied || ev.ErrorType != "action_not_granted" {
		t.Errorf("denied reveal audit: %+v", ev)
	}
	rec = e.do("POST", "/v1/agent/credentials/reveal", tokenAlpha, map[string]any{"credential": "raw", "taskId": "t-1"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reveal: %d %s", rec.Code, rec.Body)
	}
	m := decodeMap(t, rec)
	if m["value"] != `{"user":"x","pass":"y"}` || m["kind"] != "raw" || m["credential"] != "raw" {
		t.Errorf("reveal body: %v", m)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("reveal response is cacheable")
	}
	ev := e.lastAudit(actionAgentReveal)
	if ev.Result != store.AuditResultSuccess || ev.KeyID != "raw" || strings.Contains(ev.Resource, "pass") {
		t.Errorf("reveal audit: %+v", ev)
	}
	if rec := e.do("POST", "/v1/agent/credentials/reveal", "", map[string]any{"credential": "raw"}, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("reveal without token: %d", rec.Code)
	}
}

func TestAgentBrokerConcurrencyCap(t *testing.T) {
	rt := &agentBrokerRuntime{global: make(chan struct{}, 2), active: map[string]int{}}
	r1, ok1 := rt.acquire("a")
	r2, ok2 := rt.acquire("b")
	if !ok1 || !ok2 {
		t.Fatal("slots refused")
	}
	if _, ok := rt.acquire("c"); ok {
		t.Fatal("global cap exceeded")
	}
	r1()
	r2()
	var releases []func()
	for i := 0; i < agentBrokerMaxConcurrentPerAgent; i++ {
		rt.global = make(chan struct{}, 100)
		r, ok := rt.acquire("a")
		if !ok {
			t.Fatal("per-agent slot refused")
		}
		releases = append(releases, r)
	}
	if _, ok := rt.acquire("a"); ok {
		t.Fatal("per-agent cap exceeded")
	}
	_ = releases
}

func TestMetricReason(t *testing.T) {
	for in, want := range map[string]string{"": "none", "no_grant": "no_grant", "Bad Value": "other", strings.Repeat("a", 41): "other"} {
		if got := metricReason(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if h, p := auditURLParts("https://user:pw@Host.example/a/b?q=1#f"); h != "host.example" || p != "/a/b" {
		t.Errorf("auditURLParts: %q %q", h, p)
	}
	if h, _ := auditURLParts("ftp://x"); h != "" {
		t.Error("non-http URL parsed")
	}
}
