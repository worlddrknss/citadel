package memory

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

func ev(action, actor string) store.AuditEvent {
	return store.AuditEvent{Action: action, Result: "ok", AuditOrigin: store.AuditOrigin{Actor: actor}}
}

func TestAuditChainTamperDetection(t *testing.T) {
	st := &Store{}
	ctx := store.WithCallerAccount(context.Background(), "111111111111")
	for i := 0; i < 4; i++ {
		if err := st.RecordAudit(ctx, ev(fmt.Sprintf("citadel.Op%d", i), "alice")); err != nil {
			t.Fatal(err)
		}
	}
	v, err := st.VerifyAuditChain(ctx, "111111111111", false)
	if err != nil || v.Status != store.AuditChainVerified || v.VerifiedSeq != 4 {
		t.Fatalf("clean chain: %+v %v", v, err)
	}
	// Rewriting the checkpoint row is caught even by an incremental run.
	var lastID int64
	recs, _ := st.QueryAuditEvents(ctx, store.AuditQuery{Limit: 1})
	lastID = recs[0].ID
	st.TamperAuditForTest(lastID, func(r *store.AuditRecord) { r.Result = store.AuditResultDenied })
	v, _ = st.VerifyAuditChain(ctx, "111111111111", false)
	if v.Status != store.AuditChainBroken || v.BrokenID != lastID {
		t.Fatalf("checkpoint tamper: %+v", v)
	}
	st.TamperAuditForTest(lastID, func(r *store.AuditRecord) { r.Result = store.AuditResultSuccess })
	if v, _ = st.VerifyAuditChain(ctx, "111111111111", true); v.Status != store.AuditChainVerified {
		t.Fatalf("restored chain: %+v", v)
	}
	// An older row: found by a full run.
	st.TamperAuditForTest(2, func(r *store.AuditRecord) { r.SourceIP = "198.51.100.1" })
	if v, _ = st.VerifyAuditChain(ctx, "111111111111", true); v.Status != store.AuditChainBroken || v.BrokenID != 2 {
		t.Fatalf("full run after tamper: %+v", v)
	}
	if got, _ := st.GetAuditVerification(ctx, "111111111111"); got.Status != store.AuditChainBroken {
		t.Fatalf("stored status: %+v", got)
	}
	if got, _ := st.GetAuditVerification(ctx, "999999999999"); got.Status != store.AuditChainNever {
		t.Fatalf("unverified account: %+v", got)
	}
}

func TestAuditConcurrentAppends(t *testing.T) {
	st := &Store{}
	ctx := store.WithCallerAccount(context.Background(), "111111111111")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_ = st.RecordAudit(ctx, ev("citadel.Concurrent", "bob"))
			}
		}()
	}
	wg.Wait()
	v, err := st.VerifyAuditChain(ctx, "111111111111", true)
	if err != nil || v.Status != store.AuditChainVerified || v.TotalEvents != 200 || v.VerifiedSeq != 200 {
		t.Fatalf("chain: %+v %v", v, err)
	}
}

func TestAuditIsolationAndFilters(t *testing.T) {
	st := &Store{AccountID: "123456789012"}
	ctxA := store.WithCallerAccount(context.Background(), "111111111111")
	ctxB := store.WithCallerAccount(context.Background(), "222222222222")
	_ = st.RecordAudit(ctxA, ev("kms.Encrypt", "alice"))
	_ = st.RecordAudit(ctxA, store.AuditEvent{Action: "kms.Decrypt", Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: store.AuditOrigin{Actor: "mallory"}})
	_ = st.RecordAudit(ctxB, ev("kms.Encrypt", "bob"))
	// No caller account: the deployment account's (empty) log.
	_ = st.RecordAudit(context.Background(), ev("citadel.Startup", ""))

	if recs, _ := st.QueryAuditEvents(ctxB, store.AuditQuery{}); len(recs) != 1 || recs[0].Actor != "bob" {
		t.Fatalf("B sees %+v", recs)
	}
	if recs, _ := st.ListAuditEvents(ctxB, 50); len(recs) != 1 {
		t.Fatalf("legacy list for B sees %d events", len(recs))
	}
	if recs, _ := st.QueryAuditEvents(context.Background(), store.AuditQuery{}); len(recs) != 1 || recs[0].Actor != store.AuditActorAnonymous || recs[0].AccountID != "123456789012" {
		t.Fatalf("deployment account sees %+v", recs)
	}
	if recs, _ := st.QueryAuditEvents(ctxA, store.AuditQuery{Result: store.AuditResultDenied}); len(recs) != 1 || recs[0].Actor != "mallory" {
		t.Fatalf("denied filter: %+v", recs)
	}
	if n, _ := st.CountAuditEvents(ctxA, store.AuditQuery{Actor: "ALI"}); n != 1 {
		t.Fatalf("actor filter count = %d", n)
	}
	if recs, _ := st.QueryAuditEvents(ctxA, store.AuditQuery{Limit: 1, Offset: 1}); len(recs) != 1 || recs[0].Action != "kms.Encrypt" {
		t.Fatalf("paging: %+v", recs)
	}
}

func TestAuditOutboxOnlyWhenEnabled(t *testing.T) {
	st := &Store{}
	ctx := store.WithCallerAccount(context.Background(), "111111111111")
	_ = st.RecordAudit(ctx, ev("citadel.Before", "a"))
	_ = st.PutAuditStreamConfig(ctx, store.AuditStreamConfig{AccountID: "111111111111", Enabled: true, URL: "https://x.example", Format: "json"})
	_ = st.RecordAudit(ctx, ev("citadel.After", "a"))
	items, _ := st.ClaimAuditOutbox(ctx, 10, 0)
	if len(items) != 1 || items[0].Event.Action != "citadel.After" {
		t.Fatalf("outbox: %+v", items)
	}
	_ = st.CompleteAuditOutbox(ctx, items[0].ID)
	if items, _ := st.ClaimAuditOutbox(ctx, 10, 0); len(items) != 0 {
		t.Fatalf("outbox after complete: %+v", items)
	}
}
