package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

// TestAuditRepairAfterRollingUpgrade reproduces a 1.x replica that keeps
// writing audit events after the 2.0 migrations ran (a rolling upgrade): its
// rows have no account and no chain position. Opening the store must repair
// them, advance the chain head, accept new events, and verify.
func TestAuditRepairAfterRollingUpgrade(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	// A 1.x database with some history.
	if _, err := db.ExecContext(ctx, ms[0].sql); err != nil {
		t.Fatalf("legacy DDL: %v", err)
	}
	// Like 1.x: each event links to the previous event's hash, globally.
	prev := ""
	insertLegacy := func(n int, from int) {
		for i := 0; i < n; i++ {
			h := fmt.Sprintf("legacy-hash-%d", from+i)
			if _, err := db.ExecContext(ctx,
				`INSERT INTO kms_audit_events (action, key_id, result, actor, prev_hash, event_hash) VALUES ($1, 'k', 'ok', '10.0.0.1', $2, $3)`,
				"TrentService.Encrypt", prev, h); err != nil {
				t.Fatal(err)
			}
			prev = h
		}
	}
	insertLegacy(5, 0)

	// 2.0 migrates (as its first, killed start did)...
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// ...while the 1.x replica keeps serving and writing old-style rows.
	insertLegacy(3, 5)

	opts := testOptions()
	st, err := Open(ctx, db, opts)
	if err != nil {
		t.Fatalf("Open after a rolling upgrade: %v", err)
	}
	var unrepaired int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kms_audit_events WHERE account_id = '' OR chain_seq IS NULL`).Scan(&unrepaired); err != nil {
		t.Fatal(err)
	}
	if unrepaired != 0 {
		t.Fatalf("%d audit rows still have no account or chain position", unrepaired)
	}

	acct := st.accountID
	actx := store.WithCallerAccount(ctx, acct)
	for i := 0; i < 2; i++ {
		if err := st.RecordAudit(actx, store.AuditEvent{Action: "citadel.Test", Result: "success", AuditOrigin: store.AuditOrigin{AccountID: acct, Actor: "alice"}}); err != nil {
			t.Fatalf("append after repair: %v", err)
		}
	}
	v, err := st.VerifyAuditChain(ctx, acct, true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Status != store.AuditChainVerified {
		t.Fatalf("chain status %q after repair, want verified", v.Status)
	}

	// Idempotent: a second start changes nothing and still works.
	if _, err := Open(ctx, db, opts); err != nil {
		t.Fatalf("second Open: %v", err)
	}
}
