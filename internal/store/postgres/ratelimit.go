package postgres

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Shared rate limiting (migration 0903): fixed-window counters every replica
// increments with one UPSERT, so a limit holds across the deployment. See
// docs/configuration.md ("Rate limits") for the design.

// RateLimitHit is one event to count: key under limiter in windows of
// Window (whole seconds, at least one).
type RateLimitHit struct {
	Limiter string
	KeyHash string
	Window  time.Duration
}

// RateLimitCount is the count of a hit's current window after counting it,
// and how long until that window ends.
type RateLimitCount struct {
	Hits    int64
	ResetIn time.Duration
}

// CountRateLimitHits counts each hit in its current window and returns the
// windows' totals, in the order of hits, in one round trip. Windows are
// aligned to the database clock, so replicas with skewed clocks share them.
// Distinct (limiter, key) pairs are expected; rows are locked in sorted
// order, so concurrent callers can't deadlock.
func (s *Store) CountRateLimitHits(ctx context.Context, hits []RateLimitHit) ([]RateLimitCount, error) {
	if len(hits) == 0 {
		return nil, nil
	}
	order := make([]int, len(hits))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		ha, hb := hits[order[a]], hits[order[b]]
		if ha.Limiter != hb.Limiter {
			return ha.Limiter < hb.Limiter
		}
		return ha.KeyHash < hb.KeyHash
	})
	var (
		values strings.Builder
		args   []any
	)
	for n, i := range order {
		h := hits[i]
		secs := int64(h.Window / time.Second)
		if secs < 1 {
			secs = 1
		}
		if n > 0 {
			values.WriteString(", ")
		}
		p := len(args)
		fmt.Fprintf(&values, "($%d::text, $%d::text, to_timestamp(floor(extract(epoch FROM clock_timestamp()) / $%d) * $%d), 1)", p+1, p+2, p+3, p+3)
		args = append(args, h.Limiter, h.KeyHash, secs)
	}
	q := `INSERT INTO rate_limit_counters (limiter, key_hash, window_start, hits) VALUES ` + values.String() + `
ON CONFLICT (limiter, key_hash, window_start) DO UPDATE SET hits = rate_limit_counters.hits + 1
RETURNING limiter, key_hash, hits, extract(epoch FROM window_start - clock_timestamp())`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("count rate limit hits: %w", err)
	}
	defer rows.Close()
	type res struct {
		hits  int64
		start float64 // seconds from now to window start (<= 0)
	}
	got := map[[2]string]res{}
	for rows.Next() {
		var lim, key string
		var r res
		if err := rows.Scan(&lim, &key, &r.hits, &r.start); err != nil {
			return nil, err
		}
		got[[2]string{lim, key}] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]RateLimitCount, len(hits))
	for i, h := range hits {
		r, ok := got[[2]string{h.Limiter, h.KeyHash}]
		if !ok {
			return nil, fmt.Errorf("count rate limit hits: no result for %s", h.Limiter)
		}
		reset := time.Duration((r.start)*float64(time.Second)) + h.Window
		if reset < 0 {
			reset = 0
		}
		out[i] = RateLimitCount{Hits: r.hits, ResetIn: reset}
	}
	return out, nil
}

// PurgeRateLimits deletes windows that started more than olderThan ago.
func (s *Store) PurgeRateLimits(ctx context.Context, olderThan time.Duration) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_counters WHERE window_start < NOW() - make_interval(secs => $1)`, olderThan.Seconds())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
