package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// Shared rate limits.
//
// The in-process token buckets (internal/ratelimit) limit each replica on
// its own. With PostgreSQL, the endpoints attackers aim at (password login,
// first-run bootstrap, SSO start and the workload token endpoint) also count
// requests in shared fixed-window counters, so a limit holds across every
// replica instead of multiplying by their number.
//
//   - The local bucket runs first and refuses floods without touching the
//     database; only requests it lets through are counted centrally.
//   - All the counters a request needs are incremented by one UPSERT
//     statement (one round trip, typically well under a millisecond), with a
//     short timeout. If the database is slow or failing the request is
//     allowed (fail open) and the local bucket still applies.
//   - One row per limiter, key and window: contention is limited to requests
//     for the same key (one IP, user or client) in the same window, never a
//     global row. Keys are stored as a SHA-256 prefix.
//   - Fixed windows can let up to twice the limit through around a window
//     boundary; the limits below are set with that in mind.
//   - The table is UNLOGGED, and a job deletes old windows.
//
// The memory store (one process) uses the local buckets only.

// sharedLimit is one shared limit: at most Limit requests per key per Window,
// deployment-wide.
type sharedLimit struct {
	Name   string
	Limit  int64
	Window time.Duration
}

// The shared limits. Each allows at least what one replica's token bucket
// allows over the window (burst plus refill), so a single-replica deployment
// behaves as before.
var (
	sharedLimitLoginIP     = sharedLimit{"login-ip", 40, time.Minute}         // bucket: 20 burst + 1/3s
	sharedLimitLoginUser   = sharedLimit{"login-user", 20, time.Minute}       // bucket: 10 burst + 1/6s
	sharedLimitBootstrapIP = sharedLimit{"bootstrap-ip", 10, 5 * time.Minute} // bucket: 5 burst + 1/min
	sharedLimitSSOIP       = sharedLimit{"sso-ip", 90, time.Minute}           // bucket: 30 burst + 1/s
	sharedLimitTokenIP     = sharedLimit{"wi-token-ip", 90, time.Minute}      // bucket: 30 burst + 1/s
	sharedLimitTokenClient = sharedLimit{"wi-token-client", 360, time.Minute} // bucket: 60 burst + 5/s
)

// sharedLimitTimeout bounds the counter round trip.
const sharedLimitTimeout = 250 * time.Millisecond

// sharedLimitRetention is how long old windows are kept before the purge job
// deletes them (longer than any window).
const sharedLimitRetention = time.Hour

// sharedLimiterStore is implemented by stores with shared counters
// (*postgres.Store).
type sharedLimiterStore interface {
	CountRateLimitHits(ctx context.Context, hits []postgres.RateLimitHit) ([]postgres.RateLimitCount, error)
	PurgeRateLimits(ctx context.Context, olderThan time.Duration) (int64, error)
}

// sharedLimitCheck is one limit to apply to one key.
type sharedLimitCheck struct {
	limit sharedLimit
	key   string
}

func rateLimitKeyHash(limiter, key string) string {
	sum := sha256.Sum256([]byte(limiter + "\x00" + key))
	return hex.EncodeToString(sum[:16])
}

var sharedLimitErrLogged atomic.Int64 // unix seconds of the last logged failure

// sharedAllow counts the request against every check in one round trip. It
// reports whether all are within their limits and, when not, how long until
// the exceeded window ends. Stores without shared counters always allow.
func (s *Server) sharedAllow(ctx context.Context, checks ...sharedLimitCheck) (bool, time.Duration) {
	ls, ok := s.store.(sharedLimiterStore)
	if !ok || len(checks) == 0 {
		return true, 0
	}
	hits := make([]postgres.RateLimitHit, 0, len(checks))
	for _, c := range checks {
		l := s.effectiveSharedLimit(c.limit)
		hits = append(hits, postgres.RateLimitHit{Limiter: l.Name, KeyHash: rateLimitKeyHash(l.Name, c.key), Window: l.Window})
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sharedLimitTimeout)
	defer cancel()
	counts, err := ls.CountRateLimitHits(ctx, hits)
	if err != nil {
		// Fail open: the local bucket already applied. Log at most once a
		// minute so an outage doesn't flood the log.
		now := time.Now().Unix()
		if last := sharedLimitErrLogged.Load(); now-last >= 60 && sharedLimitErrLogged.CompareAndSwap(last, now) {
			slog.Warn("shared rate limit unavailable; using per-replica limits only", "error", err)
		}
		return true, 0
	}
	allowed, wait := true, time.Duration(0)
	for i, c := range counts {
		if l := s.effectiveSharedLimit(checks[i].limit); c.Hits > l.Limit {
			allowed = false
			wait = max(wait, c.ResetIn)
		}
	}
	return allowed, wait
}

// effectiveSharedLimit applies a test override.
func (s *Server) effectiveSharedLimit(l sharedLimit) sharedLimit {
	if o, ok := s.sharedLimitOverrides[l.Name]; ok {
		return o
	}
	return l
}

// purgeSharedLimitsJob deletes expired windows.
func (s *Server) purgeSharedLimitsJob(ctx context.Context) error {
	ls, ok := s.store.(sharedLimiterStore)
	if !ok {
		return nil
	}
	_, err := ls.PurgeRateLimits(ctx, sharedLimitRetention)
	return err
}
