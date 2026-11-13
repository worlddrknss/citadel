package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func openRetentionStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	db := testDB(t)
	st, err := Open(context.Background(), db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	return st, db
}

func TestAuditRetentionContract(t *testing.T) {
	st, db := openRetentionStore(t)
	storetest.AuditRetention(t, st, func(t *testing.T, id int64) {
		if _, err := db.Exec(`UPDATE kms_audit_events SET action = 'tampered' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAuditAnchorTamperBreaksVerification(t *testing.T) {
	st, db := openRetentionStore(t)
	const acct = "000000000001"
	ctx := store.WithCallerAccount(context.Background(), acct)
	for i := 0; i < 4; i++ {
		if err := st.RecordAudit(ctx, store.AuditEvent{Action: "a", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	recs, _ := st.QueryAuditEvents(ctx, store.AuditQuery{Limit: 10})
	if res, err := st.PruneAuditEvents(ctx, acct, recs[0].CreatedAt, 10); err != nil || res.Pruned != 3 {
		t.Fatalf("prune = %+v %v", res, err)
	}
	if v, _ := st.VerifyAuditChain(ctx, acct, true); v.Status != store.AuditChainVerified {
		t.Fatalf("verify = %+v", v)
	}
	// Moving the anchor forward over rows deleted by hand doesn't verify.
	if _, err := db.Exec(`UPDATE audit_chain_anchors SET pruned_events = 1 WHERE account_id = $1`, acct); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.VerifyAuditChain(ctx, acct, true); v.Status != store.AuditChainBroken {
		t.Fatalf("verify with tampered anchor = %+v", v)
	}
	if res, err := st.PruneAuditEvents(ctx, acct, recs[0].CreatedAt, 10); err != nil || res.Stop != store.AuditPruneStopBadAnchor {
		t.Fatalf("prune with tampered anchor = %+v %v", res, err)
	}
}

// TestAuditPruneDeletedByHandStillBreaks: deleting old rows directly (not
// through PruneAuditEvents) leaves no anchor, so verification reports it.
func TestAuditPruneDeletedByHandStillBreaks(t *testing.T) {
	st, db := openRetentionStore(t)
	const acct = "000000000002"
	ctx := store.WithCallerAccount(context.Background(), acct)
	for i := 0; i < 5; i++ {
		if err := st.RecordAudit(ctx, store.AuditEvent{Action: "a", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`DELETE FROM kms_audit_events WHERE account_id = $1 AND chain_seq <= 2`, acct); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.VerifyAuditChain(ctx, acct, true); v.Status != store.AuditChainBroken {
		t.Fatalf("verify = %+v", v)
	}
}

// TestAuditRetentionStatsTableSize: the catalog numbers come back.
func TestAuditRetentionStatsTableSize(t *testing.T) {
	st, _ := openRetentionStore(t)
	ctx := store.WithCallerAccount(context.Background(), "000000000003")
	if err := st.RecordAudit(ctx, store.AuditEvent{Action: "a", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	cut := time.Now().Add(time.Hour)
	stats, err := st.AuditRetentionStats(ctx, "000000000003", &cut)
	if err != nil || stats.Events != 1 || stats.Prunable != 1 || stats.TableBytes <= 0 {
		t.Fatalf("stats = %+v %v", stats, err)
	}
}
