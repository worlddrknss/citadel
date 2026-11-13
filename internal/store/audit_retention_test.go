package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// pruningSource prunes the account once, right after the walk has read its
// first batch, as another replica would mid-verification.
type pruningSource struct {
	*memory.Store
	t      *testing.T
	cutoff time.Time
	done   bool
}

func (p *pruningSource) AuditChainBatch(ctx context.Context, acct string, after int64, limit int) ([]store.AuditRecord, error) {
	recs, err := p.Store.AuditChainBatch(ctx, acct, after, limit)
	if !p.done && after > 0 {
		p.done = true
		if res, err := p.Store.PruneAuditEvents(ctx, acct, p.cutoff, 1000); err != nil || res.Pruned == 0 {
			p.t.Fatalf("prune = %+v %v", res, err)
		}
	}
	return recs, err
}

func TestVerificationFollowsConcurrentPrune(t *testing.T) {
	const acct = "000000000007"
	st := &memory.Store{AccountID: acct, AuditHMACKey: []byte("0123456789abcdef0123456789abcdef")}
	ctx := store.WithCallerAccount(context.Background(), acct)
	for i := 0; i < 1500; i++ {
		if err := st.RecordAudit(ctx, store.AuditEvent{Action: "a", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Now().Add(time.Microsecond)
	time.Sleep(2 * time.Millisecond)
	for i := 0; i < 10; i++ {
		if err := st.RecordAudit(ctx, store.AuditEvent{Action: "b", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	// The walk reads events 1-1000, then the prune removes 1-1500; the next
	// batch starts at 1501 and the walk continues from the new anchor.
	src := &pruningSource{Store: st, t: t, cutoff: cutoff}
	v, err := store.RunAuditVerification(ctx, src, st.AuditHMACKey, acct, true, time.Now())
	if err != nil || v.Status != store.AuditChainVerified {
		t.Fatalf("verify = %+v %v", v, err)
	}
}

func TestAuditPrunePrefixRules(t *testing.T) {
	key := []byte("0123456789abcdef")
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(seq int64, prev string, at time.Time) store.AuditRecord {
		r := store.AuditRecord{ID: seq, ChainSeq: seq, HashVersion: store.AuditHashVersion, Action: "a", Result: "success",
			PrevHash: prev, CreatedAt: at, AuditOrigin: store.AuditOrigin{AccountID: "1"}}
		r.EventHash = store.AuditMAC(key, r)
		return r
	}
	r1 := mk(1, "", now.Add(-3*time.Hour))
	r2 := mk(2, r1.EventHash, now.Add(-2*time.Hour))
	r3 := mk(3, r2.EventHash, now.Add(-time.Hour))
	cands := []store.AuditPruneCandidate{{Record: r1}, {Record: r2}, {Record: r3}}
	if n, stop := store.AuditPrunePrefix(key, store.AuditAnchor{}, false, cands, now, 10); n != 3 || stop != "" {
		t.Fatalf("all old = %d %q", n, stop)
	}
	if n, stop := store.AuditPrunePrefix(key, store.AuditAnchor{}, false, cands, now.Add(-90*time.Minute), 10); n != 2 || stop != store.AuditPruneStopWindow {
		t.Fatalf("window = %d %q", n, stop)
	}
	if n, stop := store.AuditPrunePrefix(key, store.AuditAnchor{}, false, cands, now, 3); n != 2 || stop != store.AuditPruneStopHead {
		t.Fatalf("head = %d %q", n, stop)
	}
	// A gap (seq 2 missing) stops before the row after it.
	gap := []store.AuditPruneCandidate{{Record: r1}, {Record: r3}}
	if n, stop := store.AuditPrunePrefix(key, store.AuditAnchor{}, false, gap, now, 10); n != 1 || stop != store.AuditPruneStopUnverified {
		t.Fatalf("gap = %d %q", n, stop)
	}
	// Starting after an anchor: the first row must link to it.
	anchor := store.AuditAnchor{ChainSeq: 1, EventHash: r1.EventHash}
	if n, _ := store.AuditPrunePrefix(key, anchor, true, cands[1:], now, 10); n != 2 {
		t.Fatalf("after anchor = %d", n)
	}
	if n, stop := store.AuditPrunePrefix(key, store.AuditAnchor{ChainSeq: 1, EventHash: "bogus"}, true, cands[1:], now, 10); n != 0 || stop != store.AuditPruneStopUnverified {
		t.Fatalf("bad link to anchor = %d %q", n, stop)
	}
	held := []store.AuditPruneCandidate{{Record: r1}, {Record: r2, OutcomeInWindow: true}}
	if n, stop := store.AuditPrunePrefix(key, store.AuditAnchor{}, false, held, now, 10); n != 1 || stop != store.AuditPruneStopPending {
		t.Fatalf("pending = %d %q", n, stop)
	}
	queued := []store.AuditPruneCandidate{{Record: r1, Undelivered: true}}
	if n, stop := store.AuditPrunePrefix(key, store.AuditAnchor{}, false, queued, now, 10); n != 0 || stop != store.AuditPruneStopStream {
		t.Fatalf("stream = %d %q", n, stop)
	}
}

func TestValidAuditRetentionDays(t *testing.T) {
	for d, want := range map[int]bool{0: true, 1: false, 6: false, 7: true, 90: true, 3650: true, 3651: false, -1: false} {
		if store.ValidAuditRetentionDays(d) != want {
			t.Errorf("%d: want %t", d, want)
		}
	}
}
