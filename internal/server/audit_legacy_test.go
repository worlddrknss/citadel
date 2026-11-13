package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// legacyChain records n events in account A and turns the first legacy of
// them into pre-2.0 (hash version 1) rows. It returns the events by chain
// position (index 0 is seq 1).
func legacyChain(t *testing.T, st *memory.Store, n, legacy int) []store.AuditRecord {
	t.Helper()
	actx := store.WithCallerAccount(context.Background(), auditAcctA)
	for i := 0; i < n; i++ {
		if err := st.RecordAudit(actx, store.AuditEvent{Action: "kms.Encrypt", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := st.AuditChainBatch(context.Background(), auditAcctA, 0, n)
	if err != nil || len(recs) != n {
		t.Fatalf("chain = %d, %v", len(recs), err)
	}
	for _, r := range recs[:legacy] {
		st.TamperAuditForTest(r.ID, func(r *store.AuditRecord) { r.HashVersion = 1 })
	}
	return recs
}

func verifyAudit(t *testing.T, h http.Handler, user string, full bool) (auditChainStatusJSON, int) {
	t.Helper()
	target := "/v1/audit/verify"
	if full {
		target += "?full=true"
	}
	rec := auditDo(t, h, user, http.MethodPost, target, nil)
	var out auditChainStatusJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out, rec.Code
}

func deref(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

// TestAuditVerifyLegacyLinkBreaks: broken links among pre-2.0 events (1.x's
// unlocked appends) are counted and don't fail verification.
func TestAuditVerifyLegacyLinkBreaks(t *testing.T) {
	_, st, h := auditTestServer(t)
	recs := legacyChain(t, st, 8, 5)
	// Two 1.x requests raced twice: events 2 and 4 link to an older event.
	st.TamperAuditForTest(recs[1].ID, func(r *store.AuditRecord) { r.PrevHash = recs[0].PrevHash })
	st.TamperAuditForTest(recs[3].ID, func(r *store.AuditRecord) { r.PrevHash = recs[1].PrevHash })

	v, code := verifyAudit(t, h, "admin-a", true)
	if code != http.StatusOK || v.Status != store.AuditChainVerified {
		t.Fatalf("status = %d %+v, want verified", code, v)
	}
	if deref(v.LegacyLinkBreaks) != 2 || deref(v.LegacyEvents) != 5 || deref(v.FirstLegacyBreakSeq) != 2 || deref(v.FirstLegacyBreakID) != recs[1].ID {
		t.Fatalf("legacy counts = events %d breaks %d first seq %d id %d", deref(v.LegacyEvents), deref(v.LegacyLinkBreaks), deref(v.FirstLegacyBreakSeq), deref(v.FirstLegacyBreakID))
	}
	if v.VerifiedThrough != recs[7].ID {
		t.Fatalf("verified through %d, want the last event %d", v.VerifiedThrough, recs[7].ID)
	}

	// An incremental run after new events keeps the legacy counts.
	_ = st.RecordAudit(store.WithCallerAccount(context.Background(), auditAcctA), store.AuditEvent{Action: "kms.Decrypt", Result: "ok"})
	v, _ = verifyAudit(t, h, "viewer-a", false)
	if v.Status != store.AuditChainVerified || deref(v.LegacyLinkBreaks) != 2 || deref(v.LegacyEvents) != 5 {
		t.Fatalf("incremental = %+v", v)
	}
	// GET reports the stored result with the same fields.
	rec := auditDo(t, h, "viewer-a", http.MethodGet, "/v1/audit/verify", nil)
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["legacyLinkBreaks"] != float64(2) || got["firstLegacyBreakSeq"] != float64(2) || got["legacyEvents"] != float64(5) {
		t.Fatalf("GET verify = %v", got)
	}
}

// TestAuditVerifyV2TamperStillBroken: any failure in a 2.0 event is a broken
// chain, even when the legacy part has tolerated breaks.
func TestAuditVerifyV2TamperStillBroken(t *testing.T) {
	_, st, h := auditTestServer(t)
	recs := legacyChain(t, st, 8, 4)
	st.TamperAuditForTest(recs[1].ID, func(r *store.AuditRecord) { r.PrevHash = "x" })
	st.TamperAuditForTest(recs[6].ID, func(r *store.AuditRecord) { r.Action = "kms.Decrypt" })
	v, _ := verifyAudit(t, h, "admin-a", true)
	if v.Status != store.AuditChainBroken || v.BrokenAt == nil || *v.BrokenAt != recs[6].ID {
		t.Fatalf("v2 tamper = %+v, want broken at %d", v, recs[6].ID)
	}

	// A broken link between two 2.0 events is broken too.
	_, st, h = auditTestServer(t)
	recs = legacyChain(t, st, 6, 2)
	st.TamperAuditForTest(recs[4].ID, func(r *store.AuditRecord) { r.PrevHash = recs[2].EventHash })
	if v, _ := verifyAudit(t, h, "admin-a", true); v.Status != store.AuditChainBroken {
		t.Fatalf("v2 link break = %+v", v)
	}

	// A gap in the legacy sequence (a deleted pre-2.0 event) is not tolerated.
	_, st, h = auditTestServer(t)
	recs = legacyChain(t, st, 6, 4)
	st.TamperAuditForTest(recs[2].ID, func(r *store.AuditRecord) { r.ChainSeq = 99 })
	if v, _ := verifyAudit(t, h, "admin-a", true); v.Status != store.AuditChainBroken {
		t.Fatalf("legacy gap = %+v", v)
	}
}

// TestAuditVerifyLegacyBoundaryStrict: the first 2.0 event must link to the
// last legacy event.
func TestAuditVerifyLegacyBoundaryStrict(t *testing.T) {
	_, st, h := auditTestServer(t)
	recs := legacyChain(t, st, 6, 3)
	// Rewrite the last legacy event's hash: legacy rows aren't MAC'd, but
	// the first 2.0 event no longer links to it.
	st.TamperAuditForTest(recs[2].ID, func(r *store.AuditRecord) { r.EventHash = "rewritten" })
	v, _ := verifyAudit(t, h, "admin-a", true)
	if v.Status != store.AuditChainBroken || v.BrokenAt == nil || *v.BrokenAt != recs[3].ID {
		t.Fatalf("boundary = %+v, want broken at the first 2.0 event %d", v, recs[3].ID)
	}
}

// TestAuditFullVerifyPlatformAdminOnly: a full re-walk needs a platform
// admin; an account admin can run the incremental check.
func TestAuditFullVerifyPlatformAdminOnly(t *testing.T) {
	_, st, h := auditTestServer(t)
	ctx := context.Background()
	if err := st.UpsertUIUser(ctx, store.UIUser{Username: "acct-admin", PasswordHash: "x", Role: "admin", Accounts: []string{auditAcctA}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.CreateConsoleSession(ctx, store.ConsoleSession{
		ID: "acct-admin", TokenHash: hashSessionToken("acct-admin"), Username: "acct-admin", AccountID: auditAcctA,
		Method: store.SessionMethodPassword, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, code := verifyAudit(t, h, "acct-admin", true); code != http.StatusForbidden {
		t.Fatalf("account admin full verify = %d, want 403", code)
	}
	if _, code := verifyAudit(t, h, "acct-admin", false); code != http.StatusOK {
		t.Fatalf("account admin incremental verify = %d", code)
	}
	if _, code := verifyAudit(t, h, "admin-a", true); code != http.StatusOK {
		t.Fatalf("platform admin full verify = %d", code)
	}
}
