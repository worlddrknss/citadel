package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// retentionTestServer is auditTestServer plus a platform admin ("plat",
// account A) and a deployment default retention.
func retentionTestServer(t *testing.T, defaultDays int) (*Server, *memory.Store, http.Handler) {
	t.Helper()
	st := newTenantTestStore()
	users := map[string]store.UIUser{
		"admin-a":  {Username: "admin-a", Role: "admin", Accounts: []string{auditAcctA}},
		"viewer-a": {Username: "viewer-a", Role: "viewer", Accounts: []string{auditAcctA}},
		"admin-b":  {Username: "admin-b", Role: "admin", Accounts: []string{auditAcctB}},
		"plat":     {Username: "plat", Role: "admin", Accounts: []string{auditAcctA}, PlatformAdmin: true},
	}
	cfg := config.Config{
		UIUsers:            users,
		SessionIdleTTL:     time.Hour,
		SessionAbsTTL:      time.Hour,
		WrappingKey:        bytes.Repeat([]byte{9}, 32),
		TrustedProxies:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		AuditRetentionDays: defaultDays,
	}
	s := &Server{cfg: cfg, store: st}
	now := time.Now().UTC()
	for name, u := range users {
		if err := st.CreateConsoleSession(context.Background(), store.ConsoleSession{
			ID: name, TokenHash: hashSessionToken(name), Username: name, AccountID: u.Accounts[0],
			Method: store.SessionMethodPassword, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return s, st, s.Handler()
}

func decodeRetention(t *testing.T, rec *httptest.ResponseRecorder) auditRetentionJSON {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out auditRetentionJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAuditRetentionSettingsAPI(t *testing.T) {
	_, st, h := retentionTestServer(t, 0)
	got := decodeRetention(t, auditDo(t, h, "viewer-a", "GET", "/v1/audit/retention", nil))
	if got.RetentionDays != 0 || got.Source != "deployment" || got.AccountDays != nil || got.MinDays != 7 || got.Storage != nil || got.Anchor != nil {
		t.Fatalf("default = %+v", got)
	}
	if rec := auditDo(t, h, "", "GET", "/v1/audit/retention", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", rec.Code)
	}
	if rec := auditDo(t, h, "viewer-a", "POST", "/v1/audit/retention", map[string]any{"retentionDays": 30}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer set = %d", rec.Code)
	}
	for _, body := range []any{map[string]any{}, map[string]any{"retentionDays": 3}, map[string]any{"retentionDays": 4000},
		map[string]any{"retentionDays": "30"}, map[string]any{"retentionDays": 1.5}} {
		if rec := auditDo(t, h, "admin-a", "POST", "/v1/audit/retention", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v = %d %s", body, rec.Code, rec.Body.String())
		}
	}
	got = decodeRetention(t, auditDo(t, h, "admin-a", "POST", "/v1/audit/retention", map[string]any{"retentionDays": 30}))
	if got.RetentionDays != 30 || got.Source != "account" || got.AccountDays == nil || *got.AccountDays != 30 || got.UpdatedBy != "admin-a" {
		t.Fatalf("after set = %+v", got)
	}
	// Another account is unaffected.
	if b := decodeRetention(t, auditDo(t, h, "admin-b", "GET", "/v1/audit/retention", nil)); b.Source != "deployment" || b.RetentionDays != 0 {
		t.Fatalf("account B = %+v", b)
	}
	// The change is audited with the old and new values, in account A only.
	ctxA := store.WithCallerAccount(context.Background(), auditAcctA)
	evs, _ := st.QueryAuditEvents(ctxA, store.AuditQuery{Action: "citadel.PutAuditRetention", Result: store.AuditResultSuccess})
	if len(evs) != 1 || evs[0].Resource != "audit-retention: default(forever) -> 30d" || evs[0].Actor != "admin-a" || evs[0].CorrelationID == "" {
		t.Fatalf("audit = %+v", evs)
	}
	// null returns to the deployment default.
	got = decodeRetention(t, auditDo(t, h, "admin-a", "POST", "/v1/audit/retention", map[string]any{"retentionDays": nil}))
	if got.Source != "deployment" || got.AccountDays != nil {
		t.Fatalf("after reset = %+v", got)
	}
	// Platform admins also see the table size and the last run.
	if p := decodeRetention(t, auditDo(t, h, "plat", "GET", "/v1/audit/retention", nil)); p.Storage == nil {
		t.Fatalf("platform admin view = %+v", p)
	}
}

func TestAuditRetentionPreview(t *testing.T) {
	_, _, h := retentionTestServer(t, 0)
	auditDo(t, h, "admin-a", "GET", "/v1/audit/events", nil)
	if rec := auditDo(t, h, "viewer-a", "GET", "/v1/audit/retention/preview?days=30", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer preview = %d", rec.Code)
	}
	for _, q := range []string{"", "days=abc", "days=2", "days=-1"} {
		if rec := auditDo(t, h, "admin-a", "GET", "/v1/audit/retention/preview?"+q, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%q = %d", q, rec.Code)
		}
	}
	rec := auditDo(t, h, "admin-a", "GET", "/v1/audit/retention/preview?days=30", nil)
	var p auditRetentionPreviewJSON
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &p) != nil || p.RetentionDays != 30 || p.Cutoff == "" || p.PrunableEvents != 0 {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuditRetentionJob(t *testing.T) {
	s, st, h := retentionTestServer(t, 0)
	ctxA := store.WithCallerAccount(context.Background(), auditAcctA)
	ctxB := store.WithCallerAccount(context.Background(), auditAcctB)
	for i := 0; i < 20; i++ {
		_ = st.RecordAudit(ctxA, store.AuditEvent{Action: "kms.Encrypt", Result: "ok"})
		_ = st.RecordAudit(ctxB, store.AuditEvent{Action: "kms.Encrypt", Result: "ok"})
	}
	// Keep forever everywhere: the job does nothing at all.
	if n, err := s.runAuditRetention(context.Background(), time.Now().Add(400*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("no retention = %d %v", n, err)
	}
	if rec := auditDo(t, h, "admin-a", "POST", "/v1/audit/retention", map[string]any{"retentionDays": 30}); rec.Code != http.StatusOK {
		t.Fatalf("set = %d", rec.Code)
	}
	countA, _ := st.CountAuditEvents(ctxA, store.AuditQuery{})
	countB, _ := st.CountAuditEvents(ctxB, store.AuditQuery{})
	// Sixty days on, everything in A is past its 30-day window except what
	// the run itself writes; B keeps everything.
	later := time.Now().Add(60 * 24 * time.Hour)
	n, err := s.runAuditRetention(context.Background(), later)
	if err != nil || n != int64(countA) {
		t.Fatalf("pruned %d (%v), want %d", n, err, countA)
	}
	if got, _ := st.CountAuditEvents(ctxB, store.AuditQuery{}); got != countB {
		t.Fatalf("account B has %d events, want %d", got, countB)
	}
	left, _ := st.QueryAuditEvents(ctxA, store.AuditQuery{Limit: 10})
	if len(left) != 2 || left[0].Action != "citadel.PruneAuditEvents" || left[1].Result != store.AuditResultPending ||
		left[0].CorrelationID != left[1].CorrelationID || !strings.Contains(left[0].Resource, "event(s) before") ||
		left[0].Actor != "system:audit-retention" {
		t.Fatalf("left = %+v", left)
	}
	// Verification starts from the anchor and both views show it.
	rec := auditDo(t, h, "admin-a", "POST", "/v1/audit/verify", nil)
	var v auditChainStatusJSON
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil || v.Status != "verified" || v.Anchor == nil || v.Anchor.PrunedEvents != int64(countA) {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body.String())
	}
	full := auditDo(t, h, "plat", "POST", "/v1/audit/verify?full=true", nil)
	if !strings.Contains(full.Body.String(), `"status":"verified"`) {
		t.Fatalf("full verify = %s", full.Body.String())
	}
	if r := decodeRetention(t, auditDo(t, h, "viewer-a", "GET", "/v1/audit/retention", nil)); r.Anchor == nil || r.Anchor.ChainSeq == 0 {
		t.Fatalf("retention view = %+v", r)
	}
	if r := decodeRetention(t, auditDo(t, h, "plat", "GET", "/v1/audit/retention", nil)); r.LastRun == nil || r.LastRun.PrunedEvents != int64(countA) {
		t.Fatalf("platform view = %+v", r.LastRun)
	}
	// Metrics.
	mrec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(mrec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(mrec.Body.String(), "citadel_audit_pruned_events_total") || !strings.Contains(mrec.Body.String(), `citadel_audit_retention_runs_total{result="ok"} 1`) {
		t.Fatalf("metrics:\n%s", mrec.Body.String())
	}
	// A run whose cut-off is before every remaining event does nothing and
	// writes nothing.
	before, _ := st.CountAuditEvents(ctxA, store.AuditQuery{})
	if n, err := s.runAuditRetention(context.Background(), time.Now().Add(29*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("second run = %d %v", n, err)
	}
	if after, _ := st.CountAuditEvents(ctxA, store.AuditQuery{}); after != before {
		t.Fatalf("second run wrote %d events", after-before)
	}
}

func TestAuditRetentionJobLease(t *testing.T) {
	s, st, _ := retentionTestServer(t, 30)
	if ok, _ := st.ClaimAuditPruneRun(context.Background(), "other-replica", time.Now(), 1000*24*time.Hour); !ok {
		t.Fatal("claim")
	}
	ctxA := store.WithCallerAccount(context.Background(), auditAcctA)
	for i := 0; i < 3; i++ {
		_ = st.RecordAudit(ctxA, store.AuditEvent{Action: "kms.Encrypt", Result: "ok"})
	}
	if n, err := s.runAuditRetention(context.Background(), time.Now().Add(60*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("run while another replica holds the lease = %d %v", n, err)
	}
	mrec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(mrec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(mrec.Body.String(), `citadel_audit_retention_runs_total{result="skipped"} 1`) {
		t.Fatalf("metrics:\n%s", mrec.Body.String())
	}
}
