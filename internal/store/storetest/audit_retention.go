package storetest

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// AuditTamper rewrites a stored audit event's action in place (a backend
// test hook), so the contract can check that pruning stops at a row that
// doesn't verify.
type AuditTamper func(t *testing.T, eventID int64)

// AuditRetention checks the retention contract shared by the stores:
// overrides, batched pruning with an authenticated anchor, verification from
// the anchor, and every rule that holds pruning back. Each sub-test uses its
// own fresh account, so it can run against a shared database.
func AuditRetention(t *testing.T, st store.Store, tamper AuditTamper) {
	t.Helper()
	newAccount := func() (string, context.Context) {
		n, _ := strconv.ParseUint(cryptoutil.RandomHex(5), 16, 64)
		acct := fmt.Sprintf("9%011d", n)
		return acct, store.WithCallerAccount(context.Background(), acct)
	}
	record := func(t *testing.T, ctx context.Context, n int, ev store.AuditEvent) {
		t.Helper()
		for i := 0; i < n; i++ {
			e := ev
			if e.Action == "" {
				e.Action = fmt.Sprintf("test.Event%d", i)
			}
			if e.Result == "" {
				e.Result = "ok"
			}
			if e.Actor == "" {
				e.Actor = "tester"
			}
			if err := st.RecordAudit(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
	}
	// cut returns a cut-off after every event so far; later events are
	// newer than it.
	cut := func() time.Time {
		c := time.Now().UTC().Truncate(time.Microsecond).Add(time.Microsecond)
		time.Sleep(3 * time.Millisecond)
		return c
	}
	verify := func(t *testing.T, ctx context.Context, acct string, full bool) store.AuditVerification {
		t.Helper()
		v, err := st.VerifyAuditChain(ctx, acct, full)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	ids := func(t *testing.T, ctx context.Context) []store.AuditRecord {
		t.Helper()
		recs, err := st.QueryAuditEvents(ctx, store.AuditQuery{Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		// oldest first
		for i, j := 0, len(recs)-1; i < j; i, j = i+1, j-1 {
			recs[i], recs[j] = recs[j], recs[i]
		}
		return recs
	}

	t.Run("Settings", func(t *testing.T) {
		acct, ctx := newAccount()
		got, err := st.GetAuditRetention(ctx, acct)
		if err != nil || got.Days != nil {
			t.Fatalf("default = %+v %v", got, err)
		}
		d := 30
		if err := st.PutAuditRetention(ctx, store.AuditRetentionSetting{AccountID: acct, Days: &d, UpdatedBy: "alice"}); err != nil {
			t.Fatal(err)
		}
		got, err = st.GetAuditRetention(ctx, acct)
		if err != nil || got.Days == nil || *got.Days != 30 || got.UpdatedBy != "alice" || got.UpdatedAt.IsZero() {
			t.Fatalf("after put = %+v %v", got, err)
		}
		zero := 0
		if err := st.PutAuditRetention(ctx, store.AuditRetentionSetting{AccountID: acct, Days: &zero}); err != nil {
			t.Fatal(err)
		}
		list, err := st.ListAuditRetention(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, v := range list {
			if v.AccountID == acct {
				found = v.Days != nil && *v.Days == 0
			}
		}
		if !found {
			t.Fatalf("list = %+v", list)
		}
		bad := 3
		if err := st.PutAuditRetention(ctx, store.AuditRetentionSetting{AccountID: acct, Days: &bad}); err == nil {
			t.Fatal("3 days accepted")
		}
		if err := st.PutAuditRetention(ctx, store.AuditRetentionSetting{AccountID: acct}); err != nil {
			t.Fatal(err)
		}
		if got, _ := st.GetAuditRetention(ctx, acct); got.Days != nil {
			t.Fatalf("after clear = %+v", got)
		}
	})

	t.Run("BatchesAndAnchor", func(t *testing.T) {
		acct, ctx := newAccount()
		record(t, ctx, 10, store.AuditEvent{})
		cutoff := cut()
		record(t, ctx, 3, store.AuditEvent{})
		if v := verify(t, ctx, acct, false); v.Status != store.AuditChainVerified {
			t.Fatalf("before prune = %+v", v)
		}
		if _, ok, _ := st.GetAuditAnchor(ctx, acct); ok {
			t.Fatal("anchor before any prune")
		}
		stats, err := st.AuditRetentionStats(ctx, acct, &cutoff)
		if err != nil || stats.Events != 13 || stats.Prunable != 10 || stats.Oldest.IsZero() {
			t.Fatalf("stats = %+v %v", stats, err)
		}
		all := ids(t, ctx)
		var pruned []int64
		for _, want := range []int64{4, 4, 2, 0} {
			res, err := st.PruneAuditEvents(ctx, acct, cutoff, 4)
			if err != nil {
				t.Fatal(err)
			}
			if res.Pruned != want {
				t.Fatalf("pruned %d, want %d (%+v)", res.Pruned, want, res)
			}
			pruned = append(pruned, res.Pruned)
		}
		a, ok, err := st.GetAuditAnchor(ctx, acct)
		if err != nil || !ok {
			t.Fatalf("anchor = %v %v", ok, err)
		}
		last := all[9]
		if a.ChainSeq != last.ChainSeq || a.EventID != last.ID || a.EventHash != last.EventHash ||
			!a.PrunedBefore.Equal(last.CreatedAt) || a.PrunedEvents != 10 || a.MAC == "" {
			t.Fatalf("anchor = %+v, last pruned = %+v", a, last)
		}
		left := ids(t, ctx)
		if len(left) != 3 || left[0].ChainSeq != last.ChainSeq+1 {
			t.Fatalf("left = %d events, first seq %d", len(left), left[0].ChainSeq)
		}
		for _, full := range []bool{false, true} {
			v := verify(t, ctx, acct, full)
			if v.Status != store.AuditChainVerified || v.TotalEvents != 3 || v.VerifiedID != left[2].ID {
				t.Fatalf("verify full=%t after prune = %+v", full, v)
			}
		}
		// New events keep chaining from the head as before.
		record(t, ctx, 2, store.AuditEvent{})
		if v := verify(t, ctx, acct, false); v.Status != store.AuditChainVerified || v.TotalEvents != 5 {
			t.Fatalf("verify after append = %+v", v)
		}
	})

	t.Run("CheckpointPruned", func(t *testing.T) {
		acct, ctx := newAccount()
		record(t, ctx, 6, store.AuditEvent{})
		if v := verify(t, ctx, acct, false); v.Status != store.AuditChainVerified {
			t.Fatalf("first verify = %+v", v)
		}
		cutoff := cut()
		record(t, ctx, 2, store.AuditEvent{})
		if res, err := st.PruneAuditEvents(ctx, acct, cutoff, 100); err != nil || res.Pruned != 6 {
			t.Fatalf("prune = %+v %v", res, err)
		}
		// The remembered checkpoint (the 6th event) is gone; the incremental
		// walk continues from the anchor.
		if v := verify(t, ctx, acct, false); v.Status != store.AuditChainVerified || v.TotalEvents != 2 {
			t.Fatalf("incremental verify after prune = %+v", v)
		}
	})

	t.Run("KeepsHead", func(t *testing.T) {
		acct, ctx := newAccount()
		record(t, ctx, 5, store.AuditEvent{})
		future := time.Now().Add(time.Hour)
		res, err := st.PruneAuditEvents(ctx, acct, future, 100)
		if err != nil || res.Pruned != 4 || res.Stop != store.AuditPruneStopHead {
			t.Fatalf("prune = %+v %v", res, err)
		}
		if v := verify(t, ctx, acct, true); v.Status != store.AuditChainVerified || v.TotalEvents != 1 {
			t.Fatalf("verify = %+v", v)
		}
	})

	t.Run("PendingAttempts", func(t *testing.T) {
		acct, ctx := newAccount()
		attempt := func(corr string) store.AuditEvent {
			return store.AuditEvent{Action: "kms.CreateKey", Result: store.AuditResultPending,
				AuditOrigin: store.AuditOrigin{Actor: "alice", CorrelationID: corr}}
		}
		outcome := func(corr string) store.AuditEvent {
			return store.AuditEvent{Action: "kms.CreateKey", Result: "ok",
				AuditOrigin: store.AuditOrigin{Actor: "alice", CorrelationID: corr}}
		}
		const done, unknown, open = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"
		record(t, ctx, 1, attempt(done))    // seq 1: outcome also old -> prunable
		record(t, ctx, 1, outcome(done))    // seq 2
		record(t, ctx, 1, attempt(unknown)) // seq 3: never got an outcome -> prunable
		record(t, ctx, 1, store.AuditEvent{})
		record(t, ctx, 1, attempt(open)) // seq 5: outcome inside the window -> kept
		record(t, ctx, 2, store.AuditEvent{})
		cutoff := cut()
		record(t, ctx, 1, outcome(open))
		res, err := st.PruneAuditEvents(ctx, acct, cutoff, 100)
		if err != nil || res.Pruned != 4 || res.Stop != store.AuditPruneStopPending {
			t.Fatalf("prune = %+v %v", res, err)
		}
		left := ids(t, ctx)
		if left[0].CorrelationID != open || left[0].Result != store.AuditResultPending {
			t.Fatalf("first kept = %+v", left[0])
		}
		if v := verify(t, ctx, acct, true); v.Status != store.AuditChainVerified {
			t.Fatalf("verify = %+v", v)
		}
		// Once the outcome itself is old, both go.
		later := cut()
		record(t, ctx, 1, store.AuditEvent{})
		res, err = st.PruneAuditEvents(ctx, acct, later, 100)
		if err != nil || res.Pruned != 4 || res.Stop != store.AuditPruneStopWindow {
			t.Fatalf("second prune = %+v %v", res, err)
		}
	})

	t.Run("StopsAtUnverifiedEvent", func(t *testing.T) {
		if tamper == nil {
			t.Skip("no tamper hook")
		}
		acct, ctx := newAccount()
		record(t, ctx, 6, store.AuditEvent{})
		cutoff := cut()
		record(t, ctx, 1, store.AuditEvent{})
		all := ids(t, ctx)
		tamper(t, all[3].ID)
		res, err := st.PruneAuditEvents(ctx, acct, cutoff, 100)
		if err != nil || res.Pruned != 3 || res.Stop != store.AuditPruneStopUnverified {
			t.Fatalf("prune = %+v %v", res, err)
		}
		// The evidence stays: verification still reports the break.
		if v := verify(t, ctx, acct, true); v.Status != store.AuditChainBroken || v.BrokenID != all[3].ID {
			t.Fatalf("verify = %+v", v)
		}
	})

	t.Run("StreamOutbox", func(t *testing.T) {
		acct, ctx := newAccount()
		if err := st.PutAuditStreamConfig(ctx, store.AuditStreamConfig{AccountID: acct, Enabled: true, URL: "https://siem.example/x", Format: "json"}); err != nil {
			t.Fatal(err)
		}
		record(t, ctx, 4, store.AuditEvent{})
		cutoff := cut()
		record(t, ctx, 1, store.AuditEvent{})
		res, err := st.PruneAuditEvents(ctx, acct, cutoff, 100)
		if err != nil || res.Pruned != 0 || res.Stop != store.AuditPruneStopStream {
			t.Fatalf("undelivered prune = %+v %v", res, err)
		}
		all := ids(t, ctx)
		// Claim this account's items (other sub-tests may have queued none;
		// the store is shared, so filter).
		items, err := st.ClaimAuditOutbox(ctx, 1000, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		mine := map[int64]int64{}
		for _, it := range items {
			if it.Event.AccountID == acct {
				mine[it.Event.ID] = it.ID
			}
		}
		if len(mine) != 5 {
			t.Fatalf("claimed %d of this account's items", len(mine))
		}
		// Deliver the first two, give up on the third: pruning then stops at
		// the fourth (still queued).
		for _, rec := range all[:2] {
			if err := st.CompleteAuditOutbox(ctx, mine[rec.ID]); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.RetryAuditOutbox(ctx, mine[all[2].ID], time.Now(), "HTTP 500", true); err != nil {
			t.Fatal(err)
		}
		res, err = st.PruneAuditEvents(ctx, acct, cutoff, 100)
		if err != nil || res.Pruned != 3 || res.Stop != store.AuditPruneStopStream {
			t.Fatalf("partly delivered prune = %+v %v", res, err)
		}
		if err := st.PutAuditStreamConfig(ctx, store.AuditStreamConfig{AccountID: acct, Enabled: false, Format: "json"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ConcurrentPruners", func(t *testing.T) {
		acct, ctx := newAccount()
		record(t, ctx, 60, store.AuditEvent{})
		cutoff := cut()
		record(t, ctx, 1, store.AuditEvent{})
		var total atomic.Int64
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 200; i++ {
					res, err := st.PruneAuditEvents(ctx, acct, cutoff, 7)
					if err != nil {
						errs <- err
						return
					}
					total.Add(res.Pruned)
					if res.Pruned == 0 && res.Stop != store.AuditPruneStopBusy {
						return
					}
					if res.Stop == store.AuditPruneStopBusy {
						time.Sleep(time.Millisecond)
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		if total.Load() != 60 {
			t.Fatalf("pruned %d in total, want 60", total.Load())
		}
		a, _, _ := st.GetAuditAnchor(ctx, acct)
		if a.PrunedEvents != 60 {
			t.Fatalf("anchor = %+v", a)
		}
		if v := verify(t, ctx, acct, true); v.Status != store.AuditChainVerified || v.TotalEvents != 1 {
			t.Fatalf("verify = %+v", v)
		}
	})

	t.Run("RunLease", func(t *testing.T) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Microsecond)
		a, b := "replica-a-"+cryptoutil.RandomHex(4), "replica-b-"+cryptoutil.RandomHex(4)
		if ok, err := st.ClaimAuditPruneRun(ctx, a, now, time.Minute); err != nil || !ok {
			t.Fatalf("a claim = %v %v", ok, err)
		}
		if ok, err := st.ClaimAuditPruneRun(ctx, b, now.Add(time.Second), time.Minute); err != nil || ok {
			t.Fatalf("b claim while a holds = %v %v", ok, err)
		}
		run := store.AuditPruneRun{StartedAt: now, FinishedAt: now.Add(time.Second), PrunedEvents: 42}
		if err := st.FinishAuditPruneRun(ctx, a, run); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetAuditPruneRun(ctx)
		if err != nil || got.PrunedEvents != 42 || !got.FinishedAt.Equal(run.FinishedAt) {
			t.Fatalf("run = %+v %v", got, err)
		}
		// Released: b may run now; and an expired lease is taken over.
		if ok, err := st.ClaimAuditPruneRun(ctx, b, now.Add(2*time.Second), time.Minute); err != nil || !ok {
			t.Fatalf("b claim after release = %v %v", ok, err)
		}
		if ok, err := st.ClaimAuditPruneRun(ctx, a, now.Add(2*time.Minute), time.Minute); err != nil || !ok {
			t.Fatalf("a claim after b's lease expired = %v %v", ok, err)
		}
		// b's late finish doesn't clobber a's lease.
		if err := st.FinishAuditPruneRun(ctx, b, store.AuditPruneRun{PrunedEvents: 1}); err != nil {
			t.Fatal(err)
		}
		if ok, _ := st.ClaimAuditPruneRun(ctx, b, now.Add(2*time.Minute+time.Second), time.Minute); ok {
			t.Fatal("b took a's running lease")
		}
		_ = st.FinishAuditPruneRun(ctx, a, store.AuditPruneRun{})
	})

	t.Run("AuditAccounts", func(t *testing.T) {
		acct, ctx := newAccount()
		record(t, ctx, 1, store.AuditEvent{})
		accts, err := st.AuditAccounts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range accts {
			if a == acct {
				return
			}
		}
		t.Fatalf("%s not in %v", acct, accts)
	})
}
