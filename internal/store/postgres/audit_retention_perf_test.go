package postgres

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/worlddrknss/citadel/internal/store"
)

// TestAuditPrunePerformance seeds an audit log the size of production's
// (~300k events over 120 days, one account) and prunes it to 30 days the
// way the retention job does, while another goroutine keeps appending. It
// reports timings with t.Logf. Opt in with CITADEL_PRUNE_PERF=1 (and
// CITADEL_PRUNE_PERF_EVENTS to change the size):
//
//	CITADEL_PRUNE_PERF=1 CITADEL_TEST_DB_URL=... go test -run TestAuditPrunePerformance -v ./internal/store/postgres/
func TestAuditPrunePerformance(t *testing.T) {
	if os.Getenv("CITADEL_PRUNE_PERF") == "" {
		t.Skip("set CITADEL_PRUNE_PERF=1 to run the pruning performance test")
	}
	total := 300000
	if v, err := strconv.Atoi(os.Getenv("CITADEL_PRUNE_PERF_EVENTS")); err == nil && v > 0 {
		total = v
	}
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	_, acct := st.DeploymentIdentity()
	key := st.auditHMACKey

	// ---- seed --------------------------------------------------------------
	seedStart := time.Now()
	now := time.Now().UTC().Truncate(time.Microsecond)
	start := now.Add(-120 * 24 * time.Hour)
	step := (120 * 24 * time.Hour) / time.Duration(total)
	ua := "external-secrets/v0.10.4 (linux/amd64) aws-sdk-go/1.55.5 (go1.23.2; linux; amd64) " + strings.Repeat("x", 60)
	prev := ""
	const chunk = 5000
	cols := make([][]string, 12)
	flush := func() {
		if len(cols[0]) == 0 {
			return
		}
		_, err := db.ExecContext(ctx, `
INSERT INTO kms_audit_events (account_id, chain_seq, hash_version, action, key_id, result, error_type,
	actor, actor_type, actor_display_name, access_key_id, resource, source_ip, user_agent,
	prev_hash, event_hash, created_at, correlation_id, agent_id, agent_owner, task_id)
SELECT $1, s::bigint, 2, a, '', r, '', 'eso-reader', 'access-key', '', 'AKIAEXAMPLE000000001', res, '10.42.0.17', $2,
	p, h, c::timestamptz, corr, '', '', ''
FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[])
	AS t(s, a, r, res, p, h, c, corr)`,
			acct, ua, pq.Array(cols[0]), pq.Array(cols[1]), pq.Array(cols[2]), pq.Array(cols[3]),
			pq.Array(cols[4]), pq.Array(cols[5]), pq.Array(cols[6]), pq.Array(cols[7]))
		if err != nil {
			t.Fatal(err)
		}
		for i := range cols {
			cols[i] = cols[i][:0]
		}
	}
	corr := ""
	for i := 1; i <= total; i++ {
		rec := store.AuditRecord{
			ChainSeq: int64(i), HashVersion: store.AuditHashVersion, Action: "secretsmanager.GetSecretValue",
			Result: store.AuditResultSuccess, PrevHash: prev, CreatedAt: start.Add(time.Duration(i) * step),
			AuditOrigin: store.AuditOrigin{AccountID: acct, Actor: "eso-reader", ActorType: "access-key",
				AccessKeyID: "AKIAEXAMPLE000000001", Resource: "prod/payments/db-" + strconv.Itoa(i%40),
				SourceIP: "10.42.0.17", UserAgent: ua},
		}
		// Every 50th event is a write-ahead attempt; its outcome follows.
		switch {
		case i%50 == 0:
			corr = strconv.FormatInt(int64(i), 16) + strings.Repeat("0", 24)
			rec.Action, rec.Result, rec.CorrelationID = "secretsmanager.PutSecretValue", store.AuditResultPending, corr
		case i%50 == 1 && corr != "":
			rec.Action, rec.CorrelationID = "secretsmanager.PutSecretValue", corr
		}
		rec.EventHash = store.AuditMAC(key, rec)
		prev = rec.EventHash
		for j, v := range []string{strconv.Itoa(i), rec.Action, rec.Result, rec.Resource, rec.PrevHash, rec.EventHash,
			store.AuditTimestamp(rec.CreatedAt), rec.CorrelationID} {
			cols[j] = append(cols[j], v)
		}
		if len(cols[0]) == chunk {
			flush()
		}
	}
	flush()
	if _, err := db.ExecContext(ctx, `
INSERT INTO audit_chain_heads (account_id, chain_seq, head_hash, head_event_id)
SELECT account_id, chain_seq, event_hash, id FROM kms_audit_events WHERE account_id = $1 ORDER BY chain_seq DESC LIMIT 1
ON CONFLICT (account_id) DO UPDATE SET chain_seq = EXCLUDED.chain_seq, head_hash = EXCLUDED.head_hash, head_event_id = EXCLUDED.head_event_id`, acct); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ANALYZE kms_audit_events`); err != nil {
		t.Fatal(err)
	}
	t.Logf("seeded %d events in %s", total, time.Since(seedStart).Round(time.Millisecond))

	sizeOf := func() string {
		var size string
		_ = db.QueryRowContext(ctx, `SELECT pg_size_pretty(pg_total_relation_size('kms_audit_events'))`).Scan(&size)
		return size
	}
	t.Logf("table size before: %s", sizeOf())

	// ---- verification and preview before -----------------------------------
	vStart := time.Now()
	v, err := st.VerifyAuditChain(ctx, acct, true)
	if err != nil || v.Status != store.AuditChainVerified {
		t.Fatalf("verify before = %+v %v", v, err)
	}
	t.Logf("full verification of %d events: %s", v.TotalEvents, time.Since(vStart).Round(time.Millisecond))
	for _, days := range []int{90, 30, 7} {
		cut := now.Add(-time.Duration(days) * 24 * time.Hour)
		pStart := time.Now()
		stats, err := st.AuditRetentionStats(ctx, acct, &cut)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("preview %d days: %d of %d prunable, %s", days, stats.Prunable, stats.Events, time.Since(pStart).Round(time.Millisecond))
	}

	// ---- prune to 30 days while appending ----------------------------------
	cutoff := now.Add(-30 * 24 * time.Hour)
	var stop atomic.Bool
	var appendMax atomic.Int64
	var appends atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		actx := store.WithCallerAccount(ctx, acct)
		for !stop.Load() {
			t0 := time.Now()
			if err := st.RecordAudit(actx, store.AuditEvent{Action: "kms.Decrypt", Result: "ok"}); err != nil {
				t.Errorf("append during prune: %v", err)
				return
			}
			d := time.Since(t0).Microseconds()
			for {
				cur := appendMax.Load()
				if d <= cur || appendMax.CompareAndSwap(cur, d) {
					break
				}
			}
			appends.Add(1)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	var batches []time.Duration
	var pruned int64
	pStart := time.Now()
	for {
		b0 := time.Now()
		res, err := st.PruneAuditEvents(ctx, acct, cutoff, 5000)
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, time.Since(b0))
		pruned += res.Pruned
		if res.Pruned < 5000 || res.Stop != store.AuditPruneStopWindow {
			t.Logf("last batch stop=%q", res.Stop)
			break
		}
		time.Sleep(200 * time.Millisecond) // the job's pause
	}
	elapsed := time.Since(pStart)
	stop.Store(true)
	wg.Wait()
	sort.Slice(batches, func(i, j int) bool { return batches[i] < batches[j] })
	var sum time.Duration
	for _, b := range batches {
		sum += b
	}
	t.Logf("pruned %d events in %d batches: wall %s (incl. 200ms pauses), in transactions %s; batch median %s, p95 %s, max %s",
		pruned, len(batches), elapsed.Round(time.Millisecond), sum.Round(time.Millisecond),
		batches[len(batches)/2].Round(time.Millisecond), batches[len(batches)*95/100].Round(time.Millisecond),
		batches[len(batches)-1].Round(time.Millisecond))
	t.Logf("%d appends during the prune, slowest %s", appends.Load(), time.Duration(appendMax.Load())*time.Microsecond)
	t.Logf("table size after (before VACUUM): %s", sizeOf())

	// ---- verification after -----------------------------------------------
	vStart = time.Now()
	v, err = st.VerifyAuditChain(ctx, acct, true)
	if err != nil || v.Status != store.AuditChainVerified {
		t.Fatalf("verify after = %+v %v", v, err)
	}
	t.Logf("full verification after prune (%d events, from the anchor): %s", v.TotalEvents, time.Since(vStart).Round(time.Millisecond))
	if _, err := db.ExecContext(ctx, `VACUUM (ANALYZE) kms_audit_events`); err == nil {
		t.Logf("table size after plain VACUUM: %s (space is reused, not returned to the OS)", sizeOf())
	}
	if _, err := db.ExecContext(ctx, `VACUUM FULL kms_audit_events`); err == nil {
		t.Logf("table size after VACUUM FULL: %s", sizeOf())
	}
}
