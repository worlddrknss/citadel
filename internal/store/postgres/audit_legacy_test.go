package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

// TestAuditLegacyLinkBreaksPostgres: broken prev_hash links among
// hash_version 1 rows (Citadel 1.x's unlocked appends) are counted, stored
// and carried by incremental runs; 2.0 rows and the boundary stay strict.
func TestAuditLegacyLinkBreaksPostgres(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	const acct = "111111111111"
	actx := store.WithCallerAccount(ctx, acct)
	for i := 0; i < 8; i++ {
		if err := st.RecordAudit(actx, auditEvent(fmt.Sprintf("citadel.Op%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Seqs 1-5 become 1.x rows; seqs 2 and 4 link to an older event.
	exec(`UPDATE kms_audit_events SET hash_version = 1 WHERE account_id = $1 AND chain_seq <= 5`, acct)
	exec(`UPDATE kms_audit_events SET prev_hash = 'raced' WHERE account_id = $1 AND chain_seq IN (2, 4)`, acct)

	v := mustVerify(t, st, acct, true)
	if v.Status != store.AuditChainVerified || v.LegacyEvents != 5 || v.LegacyLinkBreaks != 2 || v.FirstLegacyBreakSeq != 2 || v.FirstLegacyBreakID == 0 || v.VerifiedSeq != 8 {
		t.Fatalf("legacy breaks: %+v", v)
	}
	stored, err := st.GetAuditVerification(ctx, acct)
	if err != nil || stored.LegacyLinkBreaks != 2 || stored.LegacyEvents != 5 || stored.FirstLegacyBreakSeq != 2 {
		t.Fatalf("stored: %+v, %v", stored, err)
	}
	if err := st.RecordAudit(actx, auditEvent("citadel.Later")); err != nil {
		t.Fatal(err)
	}
	if v := mustVerify(t, st, acct, false); v.Status != store.AuditChainVerified || v.LegacyLinkBreaks != 2 || v.VerifiedSeq != 9 {
		t.Fatalf("incremental: %+v", v)
	}

	// Boundary: the first 2.0 row must link to the last legacy row.
	exec(`UPDATE kms_audit_events SET event_hash = 'rewritten' WHERE account_id = $1 AND chain_seq = 5`, acct)
	if v := mustVerify(t, st, acct, true); v.Status != store.AuditChainBroken || v.BrokenSeq != 6 {
		t.Fatalf("boundary: %+v", v)
	}
}
