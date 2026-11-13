package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// WriteAheadAudit checks the store side of write-ahead audit: pending
// attempts and correlation IDs round-trip, are covered by the chain MAC,
// filter by correlation, and the "is there work" counts answer.
func WriteAheadAudit(t *testing.T, st store.Store, accountID string) {
	t.Helper()
	ctx := store.WithCallerAccount(context.Background(), accountID)
	const corr = "0123456789abcdef0123456789abcdef"
	if err := st.RecordAudit(ctx, store.AuditEvent{Action: "kms.CreateKey", Result: store.AuditResultPending,
		AuditOrigin: store.AuditOrigin{Actor: "alice", ActorType: store.AuditActorConsole, CorrelationID: corr}}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAudit(ctx, store.AuditEvent{Action: "kms.CreateKey", Result: "ok", KeyID: "k1",
		AuditOrigin: store.AuditOrigin{Actor: "alice", ActorType: store.AuditActorConsole, CorrelationID: corr}}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAudit(ctx, store.AuditEvent{Action: "kms.ListKeys", Result: "ok", AuditOrigin: store.AuditOrigin{Actor: "alice"}}); err != nil {
		t.Fatal(err)
	}
	linked, err := st.QueryAuditEvents(ctx, store.AuditQuery{Correlation: corr})
	if err != nil {
		t.Fatal(err)
	}
	if len(linked) != 2 || linked[0].Result != store.AuditResultSuccess || linked[1].Result != store.AuditResultPending {
		t.Fatalf("linked events = %+v", linked)
	}
	for _, rec := range linked {
		if rec.CorrelationID != corr {
			t.Fatalf("correlation = %q", rec.CorrelationID)
		}
	}
	pending, err := st.QueryAuditEvents(ctx, store.AuditQuery{Result: store.AuditResultPending})
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %v %v", pending, err)
	}
	v, err := st.VerifyAuditChain(ctx, accountID, true)
	if err != nil || v.Status != store.AuditChainVerified {
		t.Fatalf("verify = %+v %v", v, err)
	}
	if _, err := st.SecretsDueForPurge(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n, err := st.CertificatesDueForExpiry(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("certificates due = %d %v", n, err)
	}
}
