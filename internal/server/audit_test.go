package server

import (
	"bytes"
	"context"
	"encoding/csv"
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

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

const (
	auditAcctA = "111111111111"
	auditAcctB = "222222222222"
)

// auditTestServer has console users admin-a (admin, account A), viewer-a
// (viewer, account A) and admin-b (admin, account B), each with a session
// whose cookie value is the username.
func auditTestServer(t *testing.T) (*Server, *memory.Store, http.Handler) {
	t.Helper()
	st := newTenantTestStore()
	users := map[string]store.UIUser{
		"admin-a":  {Username: "admin-a", Role: "admin", DisplayName: "Admin A", Accounts: []string{auditAcctA}},
		"viewer-a": {Username: "viewer-a", Role: "viewer", Accounts: []string{auditAcctA}},
		"admin-b":  {Username: "admin-b", Role: "admin", Accounts: []string{auditAcctB}},
	}
	cfg := config.Config{
		UIUsers:        users,
		SessionIdleTTL: time.Hour,
		SessionAbsTTL:  time.Hour,
		WrappingKey:    bytes.Repeat([]byte{9}, 32),
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	s := &Server{cfg: cfg, store: st}
	now := time.Now().UTC()
	for name, acct := range map[string]string{"admin-a": auditAcctA, "viewer-a": auditAcctA, "admin-b": auditAcctB} {
		if err := st.CreateConsoleSession(context.Background(), store.ConsoleSession{
			ID: name, TokenHash: hashSessionToken(name), Username: name, AccountID: acct,
			Method: store.SessionMethodPassword, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return s, st, s.Handler()
}

func auditDo(t *testing.T, h http.Handler, user, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.RemoteAddr = "10.1.2.3:4444" // a trusted proxy
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 10.9.9.9")
	req.Header.Set("User-Agent", "audit-test/1")
	if user != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: user})
		req.Header.Set(csrfHeader, "1")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type eventsPage struct {
	Events []auditEventJSON `json:"events"`
	Total  int              `json:"total"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
}

func listEvents(t *testing.T, h http.Handler, user, query string) eventsPage {
	t.Helper()
	rec := auditDo(t, h, user, http.MethodGet, "/v1/audit/events"+query, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list events %s: %d %s", query, rec.Code, rec.Body.String())
	}
	var page eventsPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func TestAuditRecordsAuthenticatedIdentity(t *testing.T) {
	_, _, h := auditTestServer(t)
	rec := auditDo(t, h, "admin-a", http.MethodPost, "/v1/audit/stream", map[string]any{"enabled": false, "url": "", "format": "json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("put stream: %d %s", rec.Code, rec.Body.String())
	}
	page := listEvents(t, h, "viewer-a", "?action=PutAuditStream")
	if page.Total != 1 || len(page.Events) != 1 {
		t.Fatalf("events: %+v", page)
	}
	e := page.Events[0]
	if e.Actor != "admin-a" || e.ActorType != store.AuditActorConsole || e.ActorDisplayName != "Admin A" {
		t.Fatalf("actor = %q/%q/%q", e.Actor, e.ActorType, e.ActorDisplayName)
	}
	if e.SourceIP != "198.51.100.9" || e.UserAgent != "audit-test/1" || e.Result != "success" {
		t.Fatalf("origin: %+v", e)
	}
	if e.HashValid == nil || !*e.HashValid || e.Hash == "" {
		t.Fatalf("hash: %+v", e)
	}
}

func TestAuditSigV4CallerIdentity(t *testing.T) {
	st := &memory.Store{DefaultKey: sampleKey(1), AccountID: "123456789012"}
	s := &Server{cfg: config.Config{ExpectedAccessKey: "AKIASTATIC", SecretAccessKey: "static-secret"}, store: st}
	h := s.Handler()
	if rec := postSigned(t, h, "TrentService.Encrypt", map[string]any{"KeyId": "key-1", "Plaintext": "aGVsbG8="}, "AKIASTATIC", "static-secret", time.Now()); rec.Code != http.StatusOK {
		t.Fatalf("Encrypt: %d %s", rec.Code, rec.Body.String())
	}
	recs, _ := st.QueryAuditEvents(store.WithCallerAccount(context.Background(), "123456789012"), store.AuditQuery{Action: "Encrypt"})
	if len(recs) != 1 {
		t.Fatalf("events: %+v", recs)
	}
	r := recs[0]
	if r.Actor != "deployment-credential" || r.ActorType != store.AuditActorDeployment || r.AccessKeyID != "AKIASTATIC" || r.AccountID != "123456789012" {
		t.Fatalf("identity: %+v", r.AuditOrigin)
	}
	if r.SourceIP != "192.0.2.1" { // httptest default; no trusted proxies configured
		t.Fatalf("source ip %q", r.SourceIP)
	}
}

func TestClientIPTrustedProxies(t *testing.T) {
	s := &Server{cfg: config.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}
	cases := []struct {
		remote, xff, real, want string
	}{
		{"203.0.113.5:1", "1.2.3.4", "", "203.0.113.5"},             // untrusted peer: headers ignored
		{"10.0.0.1:1", "1.2.3.4", "", "1.2.3.4"},                    // trusted peer
		{"10.0.0.1:1", "6.6.6.6, 1.2.3.4, 10.0.0.2", "", "1.2.3.4"}, // spoofed left entries ignored
		{"10.0.0.1:1", "", "5.6.7.8", "5.6.7.8"},                    // X-Real-IP from a trusted peer
		{"10.0.0.1:1", "garbage", "", "10.0.0.1"},                   // malformed hop
		{"[::ffff:10.0.0.1]:1", "2001:db8::1", "", "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.real != "" {
			r.Header.Set("X-Real-IP", c.real)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("clientIP(%s, xff=%q, real=%q) = %q, want %q", c.remote, c.xff, c.real, got, c.want)
		}
	}
}

func TestAuditEventsIsolationAndValidation(t *testing.T) {
	_, st, h := auditTestServer(t)
	_ = st.RecordAudit(store.WithCallerAccount(context.Background(), auditAcctA), store.AuditEvent{Action: "kms.Encrypt", Result: "ok", AuditOrigin: store.AuditOrigin{Actor: "alice"}})
	_ = st.RecordAudit(store.WithCallerAccount(context.Background(), auditAcctB), store.AuditEvent{Action: "kms.Encrypt", Result: "ok", AuditOrigin: store.AuditOrigin{Actor: "bob"}})

	if page := listEvents(t, h, "admin-b", ""); page.Total != 1 || page.Events[0].Actor != "bob" {
		t.Fatalf("account B sees %+v", page)
	}
	if page := listEvents(t, h, "viewer-a", "?actor=bob"); page.Total != 0 {
		t.Fatalf("account A finds B's event: %+v", page)
	}
	// Legacy endpoint is account scoped too.
	rec := auditDo(t, h, "admin-b", http.MethodGet, "/v1/audit", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("legacy list: %d %s", rec.Code, rec.Body.String())
	}

	for _, q := range []string{"?limit=0", "?limit=501", "?offset=-1", "?result=maybe", "?from=yesterday", "?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", "?actor=" + strings.Repeat("x", 300)} {
		if rec := auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/events"+q, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, rec.Code)
		}
	}
	if rec := auditDo(t, h, "", http.MethodGet, "/v1/audit/events", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	page := listEvents(t, h, "viewer-a", "?limit=1&offset=0&result=success")
	if page.Limit != 1 || page.Offset != 0 || page.Total != 1 {
		t.Fatalf("page: %+v", page)
	}
}

func TestAuditVerifyEndpoint(t *testing.T) {
	_, st, h := auditTestServer(t)
	actx := store.WithCallerAccount(context.Background(), auditAcctA)
	for i := 0; i < 3; i++ {
		_ = st.RecordAudit(actx, store.AuditEvent{Action: "kms.Encrypt", Result: "ok"})
	}
	var status auditChainStatusJSON
	rec := auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/verify", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	if rec.Code != http.StatusOK || status.Status != "never" {
		t.Fatalf("before verify: %d %s", rec.Code, rec.Body.String())
	}
	rec = auditDo(t, h, "viewer-a", http.MethodPost, "/v1/audit/verify", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	if rec.Code != http.StatusOK || status.Status != "verified" || status.VerifiedThrough == 0 || status.TotalEvents == nil || *status.TotalEvents != 3 {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	// Full re-walks are admin only.
	if rec := auditDo(t, h, "viewer-a", http.MethodPost, "/v1/audit/verify?full=true", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer full verify: %d", rec.Code)
	}
	st.TamperAuditForTest(2, func(r *store.AuditRecord) { r.Action = "kms.Decrypt" })
	rec = auditDo(t, h, "admin-a", http.MethodPost, "/v1/audit/verify?full=true", nil)
	status = auditChainStatusJSON{}
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	if status.Status != "broken" || status.BrokenAt == nil || *status.BrokenAt != 2 {
		t.Fatalf("tampered verify: %s", rec.Body.String())
	}
	// Account B's chain is unaffected and separate.
	rec = auditDo(t, h, "admin-b", http.MethodPost, "/v1/audit/verify", nil)
	status = auditChainStatusJSON{}
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	if status.Status != "verified" || *status.TotalEvents != 0 {
		t.Fatalf("account B verify: %s", rec.Body.String())
	}
}

func TestAuditExportCSVEscapingAndAudit(t *testing.T) {
	_, st, h := auditTestServer(t)
	actx := store.WithCallerAccount(context.Background(), auditAcctA)
	_ = st.RecordAudit(actx, store.AuditEvent{Action: "kms.Encrypt", Result: "ok", AuditOrigin: store.AuditOrigin{Actor: `=HYPERLINK("http://evil","x")`, UserAgent: "+cmd|' /C calc'!A0", Resource: "@SUM(1)"}})
	_ = st.RecordAudit(actx, store.AuditEvent{Action: "kms.Decrypt", Result: "ok", AuditOrigin: store.AuditOrigin{Actor: "-2+3", Resource: "plain, \"quoted\""}})

	rec := auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/export?format=csv", nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d %v", rec.Code, rec.Header())
	}
	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v\n%s", err, rec.Body.String())
	}
	if len(rows) != 3 || rows[0][0] != "id" {
		t.Fatalf("rows: %v", rows)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@\t\r|", rune(cell[0])) {
				t.Fatalf("unescaped formula cell %q", cell)
			}
		}
	}
	if !strings.Contains(rec.Body.String(), `'=HYPERLINK`) || !strings.Contains(rec.Body.String(), `"plain, ""quoted"""`) {
		t.Fatalf("escaping lost content: %s", rec.Body.String())
	}
	// The export itself is audited (and not part of its own output).
	page := listEvents(t, h, "viewer-a", "?action=ExportAudit")
	if page.Total != 1 || page.Events[0].Actor != "viewer-a" {
		t.Fatalf("export audit: %+v", page)
	}

	rec = auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/export?format=json&action=kms.", nil)
	var out []auditEventJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 2 {
		t.Fatalf("json export: %v %s", err, rec.Body.String())
	}
	if rec := auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/export?format=xml", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad format: %d", rec.Code)
	}
	// Account B's export holds none of A's events.
	rec = auditDo(t, h, "admin-b", http.MethodGet, "/v1/audit/export?format=json", nil)
	if strings.Contains(rec.Body.String(), "HYPERLINK") {
		t.Fatalf("cross-account export: %s", rec.Body.String())
	}
}

func TestAuditExportRateLimited(t *testing.T) {
	_, _, h := auditTestServer(t)
	for i := 0; i < auditExportPerMinute; i++ {
		if rec := auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/export", nil); rec.Code != http.StatusOK {
			t.Fatalf("export %d: %d", i, rec.Code)
		}
	}
	rec := auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/export", nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over limit: %d %v", rec.Code, rec.Header())
	}
	// Another user is not affected.
	if rec := auditDo(t, h, "admin-a", http.MethodGet, "/v1/audit/export", nil); rec.Code != http.StatusOK {
		t.Fatalf("other user: %d", rec.Code)
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"=1+1": "'=1+1", "+1": "'+1", "-1": "'-1", "@x": "'@x", "\tx": "'\tx", "｜": "｜", "＝1": "'＝1", "ok": "ok", "": ""} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuditStreamSettingsAndDelivery(t *testing.T) {
	s, st, h := auditTestServer(t)
	var mu sync.Mutex
	var got []*http.Request
	var bodies []string
	hook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r)
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer hook.Close()
	s.audit.client = hook.Client()

	// Role and validation.
	if rec := auditDo(t, h, "viewer-a", http.MethodPost, "/v1/audit/stream", map[string]any{"enabled": true, "url": hook.URL, "format": "json"}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer save: %d", rec.Code)
	}
	for _, bad := range []map[string]any{
		{"enabled": true, "url": "http://siem.example/hook", "format": "json"},
		{"enabled": true, "url": "https://user:pw@siem.example/", "format": "json"},
		{"enabled": true, "url": hook.URL, "format": "xml"},
		{"enabled": true, "url": hook.URL, "format": "json", "token": "bad\r\nX-Injected: 1"},
	} {
		if rec := auditDo(t, h, "admin-a", http.MethodPost, "/v1/audit/stream", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: status %d, want 400", bad, rec.Code)
		}
	}

	rec := auditDo(t, h, "admin-a", http.MethodPost, "/v1/audit/stream", map[string]any{"enabled": true, "url": hook.URL, "format": "cef", "token": "s3cr3t-token"})
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "s3cr3t") {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	cfg, _ := st.GetAuditStreamConfig(context.Background(), auditAcctA)
	if bytes.Contains(cfg.TokenSealed, []byte("s3cr3t")) || len(cfg.TokenSealed) == 0 {
		t.Fatal("token stored in clear")
	}
	var view auditStreamJSON
	rec = auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/stream", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if !view.Enabled || view.Format != "cef" || !view.HasToken || view.URL != hook.URL {
		t.Fatalf("view: %s", rec.Body.String())
	}
	// Omitting the token keeps it.
	auditDo(t, h, "admin-a", http.MethodPost, "/v1/audit/stream", map[string]any{"enabled": true, "url": hook.URL, "format": "cef"})
	rec = auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/stream", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if !view.HasToken {
		t.Fatal("token dropped when omitted")
	}
	// Account B does not see A's settings.
	rec = auditDo(t, h, "admin-b", http.MethodGet, "/v1/audit/stream", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view.Enabled || view.URL != "" {
		t.Fatalf("account B sees A's stream: %s", rec.Body.String())
	}

	// Test delivery.
	rec = auditDo(t, h, "admin-a", http.MethodPost, "/v1/audit/stream/test", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"delivered":true`) || !strings.Contains(rec.Body.String(), `"status":202`) {
		t.Fatalf("test: %d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	if len(got) != 1 || got[0].Header.Get("Authorization") != "Bearer s3cr3t-token" || !strings.HasPrefix(bodies[0], "CEF:0|Citadel|Citadel|") {
		t.Fatalf("webhook got %d requests: %v", len(got), bodies)
	}
	mu.Unlock()
	if rec := auditDo(t, h, "admin-b", http.MethodPost, "/v1/audit/stream/test", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfigured test: %d", rec.Code)
	}

	// Outbox: events recorded while enabled are delivered by the job.
	s.deliverAuditOutbox(context.Background())
	mu.Lock()
	delivered := len(got)
	mu.Unlock()
	if delivered < 2 {
		t.Fatalf("outbox delivered %d events", delivered-1)
	}
	if items, _ := st.ClaimAuditOutbox(context.Background(), 100, 0); len(items) != 0 {
		t.Fatalf("outbox not drained: %d", len(items))
	}
}

func TestAuditStreamJobStartStop(t *testing.T) {
	s, _, _ := auditTestServer(t)
	s.startAuditStreamJob()
	s.startAuditStreamJob() // idempotent
	s.Close()
	s.Close()
}

func TestAuditStreamClientRefusesLoopback(t *testing.T) {
	s := &Server{}
	hook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer hook.Close()
	_, err := s.sendAuditEvent(context.Background(), store.AuditStreamConfig{URL: hook.URL, Format: "json"}, store.AuditRecord{Action: "x"})
	if err == nil {
		t.Fatal("delivery to loopback was allowed")
	}
}

func TestAuditCEFEscaping(t *testing.T) {
	line := auditCEF(store.AuditRecord{Action: "a|b", Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: store.AuditOrigin{Actor: "x=y\\z\nq", SourceIP: "not-an-ip"}})
	if !strings.HasPrefix(line, `CEF:0|Citadel|Citadel|1|a\|b|a\|b|7|`) {
		t.Fatalf("header: %s", line)
	}
	if !strings.Contains(line, `suser=x\=y\\z\nq`) || strings.Contains(line, "src=") || strings.Contains(line, "\n") {
		t.Fatalf("extension: %s", line)
	}
}

// failingAuditStore fails every audit write.
type failingAuditStore struct{ *memory.Store }

func (failingAuditStore) RecordAudit(context.Context, store.AuditEvent) error {
	return errors.New("disk full")
}

func TestAuditFailClosed(t *testing.T) {
	st := failingAuditStore{&memory.Store{DefaultKey: sampleKey(1)}}
	s := &Server{cfg: config.Config{ExpectedAccessKey: "AKIASTATIC", SecretAccessKey: "static-secret"}, store: st}
	h := s.Handler()
	// A cryptographic operation whose audit record cannot be written fails...
	rec := postSigned(t, h, "TrentService.Encrypt", map[string]any{"KeyId": "key-1", "Plaintext": "aGVsbG8="}, "AKIASTATIC", "static-secret", time.Now())
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "CiphertextBlob") {
		t.Fatalf("Encrypt with audit down: %d %s", rec.Code, rec.Body.String())
	}
	// ...a metadata read does not.
	if rec := postSigned(t, h, "TrentService.ListKeys", map[string]any{}, "AKIASTATIC", "static-secret", time.Now()); rec.Code != http.StatusOK {
		t.Fatalf("ListKeys with audit down: %d %s", rec.Code, rec.Body.String())
	}
	for action, want := range map[string]bool{"kms.CreateKey": true, "Decrypt": true, "secretsmanager.GetSecretValue": true, "citadel.RevealSecret": true, "ListKeys": false, "citadel.ListSecrets": false, "DescribeKey": false, "GetPublicKey": false} {
		if got := auditFailClosed(action); got != want {
			t.Errorf("auditFailClosed(%s) = %v, want %v", action, got, want)
		}
	}
}
