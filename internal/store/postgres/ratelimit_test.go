package postgres

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRateLimitCounters(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	hits := []RateLimitHit{
		{Limiter: "login-user", KeyHash: "u1", Window: time.Hour},
		{Limiter: "login-ip", KeyHash: "ip1", Window: time.Hour},
	}
	for want := int64(1); want <= 3; want++ {
		got, err := st.CountRateLimitHits(ctx, hits)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].Hits != want || got[1].Hits != want {
			t.Fatalf("round %d: %+v", want, got)
		}
		if got[0].ResetIn <= 0 || got[0].ResetIn > time.Hour {
			t.Fatalf("resetIn = %v", got[0].ResetIn)
		}
	}
	// Another key, limiter or replica-local order has its own counter.
	got, err := st.CountRateLimitHits(ctx, []RateLimitHit{{Limiter: "login-ip", KeyHash: "ip2", Window: time.Hour}, {Limiter: "login-user", KeyHash: "u1", Window: time.Hour}})
	if err != nil || got[0].Hits != 1 || got[1].Hits != 4 {
		t.Fatalf("mixed = %+v, %v", got, err)
	}

	// Concurrent increments from two replicas never lose a count.
	other, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		s := st
		if i%2 == 1 {
			s = other
		}
		go func() {
			defer wg.Done()
			if _, err := s.CountRateLimitHits(ctx, []RateLimitHit{{Limiter: "wi-token-ip", KeyHash: "hot", Window: time.Hour}, {Limiter: "wi-token-client", KeyHash: "c", Window: time.Hour}}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, _ = st.CountRateLimitHits(ctx, []RateLimitHit{{Limiter: "wi-token-ip", KeyHash: "hot", Window: time.Hour}})
	if got[0].Hits != 41 {
		t.Fatalf("after concurrent increments: %d, want 41", got[0].Hits)
	}

	// The purge removes old windows only.
	if _, err := db.Exec(`UPDATE rate_limit_counters SET window_start = window_start - INTERVAL '3 hours' WHERE key_hash = 'u1'`); err != nil {
		t.Fatal(err)
	}
	n, err := st.PurgeRateLimits(ctx, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("purged %d, %v", n, err)
	}
	var left int
	_ = db.QueryRow(`SELECT COUNT(*) FROM rate_limit_counters`).Scan(&left)
	if left != 4 {
		t.Fatalf("%d rows left, want 4", left)
	}
}
