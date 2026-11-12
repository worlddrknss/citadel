package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

func auditEvent(action string) store.AuditEvent {
	return store.AuditEvent{Action: action, Result: "ok", AuditOrigin: store.AuditOrigin{Actor: "alice", ActorType: store.AuditActorConsole, SourceIP: "203.0.113.7", UserAgent: "test"}}
}

func mustVerify(t *testing.T, st *Store, account string, full bool) store.AuditVerification {
	t.Helper()
	v, err := st.VerifyAuditChain(context.Background(), account, full)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	return v
}

func TestAuditChainTamperDetection(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	const acct = "111111111111"
	actx := store.WithCallerAccount(ctx, acct)
	for i := 0; i < 5; i++ {
		if err := st.RecordAudit(actx, auditEvent(fmt.Sprintf("citadel.Op%d", i))); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}
	if v := mustVerify(t, st, acct, false); v.Status != store.AuditChainVerified || v.TotalEvents != 5 || v.VerifiedSeq != 5 {
		t.Fatalf("clean chain: %+v", v)
	}
	recs, err := st.QueryAuditEvents(actx, store.AuditQuery{Limit: 10})
	if err != nil || len(recs) != 5 {
		t.Fatalf("query: %v %d", err, len(recs))
	}
	for _, r := range recs {
		if r.HashValid == nil || !*r.HashValid || r.AccountID != acct || r.Actor != "alice" || r.SourceIP != "203.0.113.7" {
			t.Fatalf("record not stored faithfully: %+v", r)
		}
	}

	// Rewrite the third event's actor directly in the database.
	third := recs[2] // newest first: seq 3
	if _, err := db.Exec(`UPDATE kms_audit_events SET actor = 'mallory' WHERE id = $1`, third.ID); err != nil {
		t.Fatal(err)
	}
	// The incremental run starts after seq 5 and re-checks only that row...
	if v := mustVerify(t, st, acct, false); v.Status != store.AuditChainVerified {
		t.Fatalf("incremental run should not re-walk old rows: %+v", v)
	}
	// ...a full run finds the edit.
	v := mustVerify(t, st, acct, true)
	if v.Status != store.AuditChainBroken || v.BrokenID != third.ID {
		t.Fatalf("full run after tamper: %+v (want broken at %d)", v, third.ID)
	}
	// Once broken, a plain run re-walks from the start and stays broken.
	if v := mustVerify(t, st, acct, false); v.Status != store.AuditChainBroken {
		t.Fatalf("broken chain reported %+v", v)
	}
	got, _ := st.QueryAuditEvents(actx, store.AuditQuery{Actor: "mallory"})
	if len(got) != 1 || got[0].HashValid == nil || *got[0].HashValid {
		t.Fatalf("tampered row should report hashValid=false: %+v", got)
	}
}

func TestAuditChainDetectsDeletedTail(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	const acct = "111111111111"
	actx := store.WithCallerAccount(ctx, acct)
	for i := 0; i < 3; i++ {
		if err := st.RecordAudit(actx, auditEvent("citadel.Op")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`DELETE FROM kms_audit_events WHERE account_id = $1 AND chain_seq = 3`, acct); err != nil {
		t.Fatal(err)
	}
	if v := mustVerify(t, st, acct, true); v.Status != store.AuditChainBroken {
		t.Fatalf("deleted tail not detected: %+v", v)
	}
}

// TestAuditConcurrentAppendsNoFork appends from many goroutines through two
// Store instances (two "replicas") sharing one database.
func TestAuditConcurrentAppendsNoFork(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	const acct = "111111111111"
	actx := store.WithCallerAccount(ctx, acct)
	const workers, each = 8, 10
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := a
			if i%2 == 1 {
				st = b
			}
			for j := 0; j < each; j++ {
				if err := st.RecordAudit(actx, auditEvent("citadel.Concurrent")); err != nil {
					errs[i] = err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("concurrent appends: %v", err)
	}
	v := mustVerify(t, a, acct, true)
	if v.Status != store.AuditChainVerified || v.TotalEvents != workers*each || v.VerifiedSeq != workers*each {
		t.Fatalf("chain after concurrent appends: %+v", v)
	}
	var forks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM (SELECT prev_hash FROM kms_audit_events WHERE account_id = $1 GROUP BY prev_hash HAVING COUNT(*) > 1) f`, acct).Scan(&forks); err != nil {
		t.Fatal(err)
	}
	if forks != 0 {
		t.Fatalf("%d predecessors have more than one successor", forks)
	}
}

func TestAuditTenantIsolation(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctxA := store.WithCallerAccount(ctx, "111111111111")
	ctxB := store.WithCallerAccount(ctx, "222222222222")
	if err := st.RecordAudit(ctxA, auditEvent("citadel.OnlyA")); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAudit(ctxB, auditEvent("citadel.OnlyB")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ctx  context.Context
		want string
	}{{ctxA, "citadel.OnlyA"}, {ctxB, "citadel.OnlyB"}} {
		recs, err := st.QueryAuditEvents(tc.ctx, store.AuditQuery{})
		if err != nil || len(recs) != 1 || recs[0].Action != tc.want {
			t.Fatalf("query sees %+v (err %v), want only %s", recs, err, tc.want)
		}
		legacy, err := st.ListAuditEvents(tc.ctx, 100)
		if err != nil || len(legacy) != 1 || legacy[0].Action != tc.want {
			t.Fatalf("legacy list sees %+v (err %v), want only %s", legacy, err, tc.want)
		}
		if n, _ := st.CountAuditEvents(tc.ctx, store.AuditQuery{}); n != 1 {
			t.Fatalf("count = %d, want 1", n)
		}
	}
	// Each account has its own chain starting at 1.
	for _, acct := range []string{"111111111111", "222222222222"} {
		if v := mustVerify(t, st, acct, true); v.Status != store.AuditChainVerified || v.VerifiedSeq != 1 {
			t.Fatalf("account %s chain: %+v", acct, v)
		}
	}
}

func TestAuditQueryFilters(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	actx := store.WithCallerAccount(ctx, "111111111111")
	events := []store.AuditEvent{
		{Action: "kms.Encrypt", KeyID: "key-1", Result: "ok", AuditOrigin: store.AuditOrigin{Actor: "alice"}},
		{Action: "kms.Decrypt", KeyID: "key-2", Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: store.AuditOrigin{Actor: "bob_100%"}},
		{Action: "citadel.PutSecret", Result: "error", ErrorType: "ValidationException", AuditOrigin: store.AuditOrigin{Actor: "carol", Resource: "payments/prod/DB"}},
	}
	for _, e := range events {
		if err := st.RecordAudit(actx, e); err != nil {
			t.Fatal(err)
		}
	}
	check := func(q store.AuditQuery, want ...string) {
		t.Helper()
		recs, err := st.QueryAuditEvents(actx, q)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range recs {
			got = append(got, r.Action)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("query %+v = %v, want %v", q, got, want)
		}
		n, _ := st.CountAuditEvents(actx, q)
		if q.Limit == 0 && q.Offset == 0 && n != len(want) {
			t.Fatalf("count %+v = %d, want %d", q, n, len(want))
		}
	}
	check(store.AuditQuery{}, "citadel.PutSecret", "kms.Decrypt", "kms.Encrypt")
	check(store.AuditQuery{Result: store.AuditResultDenied}, "kms.Decrypt")
	check(store.AuditQuery{Result: store.AuditResultSuccess}, "kms.Encrypt")
	check(store.AuditQuery{Result: store.AuditResultError}, "citadel.PutSecret")
	check(store.AuditQuery{Actor: "ALICE"}, "kms.Encrypt")
	check(store.AuditQuery{Actor: "_100%"}, "kms.Decrypt")
	check(store.AuditQuery{Actor: "%"}, "kms.Decrypt") // LIKE metacharacters are literal
	check(store.AuditQuery{Resource: "key-"}, "kms.Decrypt", "kms.Encrypt")
	check(store.AuditQuery{Resource: "prod/db"}, "citadel.PutSecret")
	check(store.AuditQuery{Action: "kms."}, "kms.Decrypt", "kms.Encrypt")
	check(store.AuditQuery{Limit: 1, Offset: 1}, "kms.Decrypt")
	future := time.Now().Add(time.Hour)
	check(store.AuditQuery{From: &future})
}

func TestAuditLegacyRowsUpgrade(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	// A pre-0200 database with a legacy global chain.
	if _, err := db.ExecContext(ctx, ms[0].sql); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO kms_settings (setting_key, setting_value) VALUES ('aws_account_id', '123456789012')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO kms_audit_events (action, key_id, result, error_type, actor, prev_hash, event_hash) VALUES
 ('Encrypt', 'k', 'ok', '', '10.0.0.1:5555', '', 'h1'),
 ('Decrypt', 'k', 'error', 'AccessDeniedException', '10.0.0.1:5555', 'h1', 'h2')`); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	actx := store.WithCallerAccount(ctx, "123456789012")
	if err := st.RecordAudit(actx, auditEvent("citadel.AfterUpgrade")); err != nil {
		t.Fatal(err)
	}
	v := mustVerify(t, st, "123456789012", true)
	if v.Status != store.AuditChainVerified || v.TotalEvents != 3 || v.VerifiedSeq != 3 {
		t.Fatalf("upgraded chain: %+v", v)
	}
	recs, _ := st.QueryAuditEvents(actx, store.AuditQuery{Result: store.AuditResultDenied})
	if len(recs) != 1 || recs[0].Action != "Decrypt" {
		t.Fatalf("legacy denied row not normalized: %+v", recs)
	}
}

func TestAuditStreamOutbox(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	const acct = "111111111111"
	actx := store.WithCallerAccount(ctx, acct)
	if err := st.RecordAudit(actx, auditEvent("citadel.BeforeEnable")); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAuditStreamConfig(ctx, store.AuditStreamConfig{AccountID: acct, Enabled: true, URL: "https://siem.example/hook", Format: "cef", TokenSealed: []byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	cfg, err := st.GetAuditStreamConfig(ctx, acct)
	if err != nil || !cfg.Enabled || cfg.Format != "cef" || len(cfg.TokenSealed) != 3 {
		t.Fatalf("stream config: %+v %v", cfg, err)
	}
	if err := st.RecordAudit(actx, auditEvent("citadel.AfterEnable")); err != nil {
		t.Fatal(err)
	}
	items, err := st.ClaimAuditOutbox(ctx, 10, time.Minute)
	if err != nil || len(items) != 1 || items[0].Event.Action != "citadel.AfterEnable" {
		t.Fatalf("claim: %+v %v", items, err)
	}
	// Leased: a second claim gets nothing.
	if again, _ := st.ClaimAuditOutbox(ctx, 10, time.Minute); len(again) != 0 {
		t.Fatalf("leased item claimed twice: %+v", again)
	}
	if err := st.RetryAuditOutbox(ctx, items[0].ID, time.Now().Add(-time.Second), "HTTP 500", false); err != nil {
		t.Fatal(err)
	}
	retry, _ := st.ClaimAuditOutbox(ctx, 10, time.Minute)
	if len(retry) != 1 || retry[0].Attempts != 1 {
		t.Fatalf("retry claim: %+v", retry)
	}
	if err := st.CompleteAuditOutbox(ctx, retry[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := st.RetryAuditOutbox(ctx, retry[0].ID, time.Now(), "", true); err != nil {
		t.Fatal(err)
	}
	if left, _ := st.ClaimAuditOutbox(ctx, 10, 0); len(left) != 0 {
		t.Fatalf("completed item still queued: %+v", left)
	}
}
