package memory

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestAuditRetentionContract(t *testing.T) {
	st := &Store{AccountID: "000000000000"}
	storetest.AuditRetention(t, st, func(t *testing.T, id int64) {
		if !st.TamperAuditForTest(id, func(r *store.AuditRecord) { r.Action = "tampered" }) {
			t.Fatalf("event %d not found", id)
		}
	})
}

func TestAuditAnchorTamperBreaksVerification(t *testing.T) {
	const acct = "000000000001"
	st := &Store{AccountID: "000000000000"}
	ctx := store.WithCallerAccount(context.Background(), acct)
	for i := 0; i < 4; i++ {
		if err := st.RecordAudit(ctx, store.AuditEvent{Action: "a", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	recs, _ := st.QueryAuditEvents(ctx, store.AuditQuery{Limit: 10})
	cutoff := recs[0].CreatedAt // newest first: everything before the head
	if res, err := st.PruneAuditEvents(ctx, acct, cutoff, 10); err != nil || res.Pruned != 3 {
		t.Fatalf("prune = %+v %v", res, err)
	}
	if v, _ := st.VerifyAuditChain(ctx, acct, true); v.Status != store.AuditChainVerified {
		t.Fatalf("verify = %+v", v)
	}
	// An edited anchor (here: fewer pruned events) fails its MAC.
	st.TamperAuditAnchorForTest(acct, func(a *store.AuditAnchor) { a.PrunedEvents = 1 })
	if v, _ := st.VerifyAuditChain(ctx, acct, true); v.Status != store.AuditChainBroken {
		t.Fatalf("verify with tampered anchor = %+v", v)
	}
	if res, err := st.PruneAuditEvents(ctx, acct, cutoff, 10); err != nil || res.Stop != store.AuditPruneStopBadAnchor {
		t.Fatalf("prune with tampered anchor = %+v %v", res, err)
	}
}
