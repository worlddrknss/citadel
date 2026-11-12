// Package ratelimit provides small in-process rate limiters keyed by an
// arbitrary string (a username, a client IP, an account ID...).
//
// Limiter is a token bucket per key: Allow spends one token, and tokens
// refill at a steady rate up to a burst. Backoff is a failure counter per key
// that, after a number of free failures, blocks the key for an exponentially
// growing period (login lockout).
//
// Both are local to one process. Behind several replicas each replica limits
// independently, so the effective limit is multiplied by the replica count;
// that is acceptable for brute-force throttling, which only needs to make
// guessing impractically slow.
package ratelimit

import (
	"sync"
	"time"
)

// DefaultMaxKeys bounds the number of keys a limiter tracks so a flood of
// distinct keys (random usernames, spoofed addresses) cannot exhaust memory.
const DefaultMaxKeys = 100_000

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a keyed token-bucket rate limiter. The zero value is not usable;
// build one with New. It is safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	buckets map[string]*bucket
	now     func() time.Time
}

// New returns a limiter allowing burst events at once per key, refilling
// at one token every interval.
func New(interval time.Duration, burst int) *Limiter {
	if interval <= 0 {
		interval = time.Second
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    1 / interval.Seconds(),
		burst:   float64(burst),
		maxKeys: DefaultMaxKeys,
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// Allow reports whether an event for key may happen now, spending a token
// when it may.
func (l *Limiter) Allow(key string) bool {
	ok, _ := l.Reserve(key)
	return ok
}

// Reserve is Allow that also reports, when the event is refused, how long
// until a token is available (for a Retry-After header).
func (l *Limiter) Reserve(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.sweepLocked(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// sweepLocked drops buckets that have refilled completely (they carry no
// state), and if that frees nothing, half of the remaining ones.
func (l *Limiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) < l.maxKeys {
		return
	}
	n := len(l.buckets) / 2
	for k := range l.buckets {
		if n == 0 {
			break
		}
		delete(l.buckets, k)
		n--
	}
}

type failState struct {
	failures     int
	blockedUntil time.Time
	last         time.Time
}

// Backoff blocks a key for an exponentially growing period after repeated
// failures. Build one with NewBackoff; it is safe for concurrent use.
type Backoff struct {
	mu        sync.Mutex
	free      int
	base, max time.Duration
	forget    time.Duration
	maxKeys   int
	state     map[string]*failState
	now       func() time.Time
}

// NewBackoff returns a Backoff that lets free failures through unpunished,
// then blocks for base, 2*base, 4*base... capped at max. A key's failures are
// forgotten after it has been quiet for forget.
func NewBackoff(free int, base, max, forget time.Duration) *Backoff {
	if base <= 0 {
		base = time.Second
	}
	if max < base {
		max = base
	}
	if forget <= 0 {
		forget = 15 * time.Minute
	}
	return &Backoff{
		free:    free,
		base:    base,
		max:     max,
		forget:  forget,
		maxKeys: DefaultMaxKeys,
		state:   map[string]*failState{},
		now:     time.Now,
	}
}

// Blocked reports whether key is currently locked out and, if so, for how
// much longer.
func (b *Backoff) Blocked(key string) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.state[key]
	if !ok {
		return false, 0
	}
	now := b.now()
	if now.Before(st.blockedUntil) {
		return true, st.blockedUntil.Sub(now)
	}
	return false, 0
}

// Fail records a failure for key and returns the lockout it now carries
// (zero while failures are still free).
func (b *Backoff) Fail(key string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	st, ok := b.state[key]
	if ok && now.Sub(st.last) > b.forget && !now.Before(st.blockedUntil) {
		st.failures = 0
	}
	if !ok {
		if len(b.state) >= b.maxKeys {
			b.sweepLocked(now)
		}
		st = &failState{}
		b.state[key] = st
	}
	st.failures++
	st.last = now
	over := st.failures - b.free
	if over <= 0 {
		return 0
	}
	d := b.base
	for i := 1; i < over && d < b.max; i++ {
		d *= 2
	}
	d = min(d, b.max)
	st.blockedUntil = now.Add(d)
	return d
}

// Reset forgets key's failures (after a success).
func (b *Backoff) Reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.state, key)
}

// sweepLocked drops forgotten keys, then if still full the keys that are not
// currently blocked, so a flood of distinct keys cannot clear real lockouts.
func (b *Backoff) sweepLocked(now time.Time) {
	for k, st := range b.state {
		if now.Sub(st.last) > b.forget && !now.Before(st.blockedUntil) {
			delete(b.state, k)
		}
	}
	if len(b.state) < b.maxKeys {
		return
	}
	for k, st := range b.state {
		if !now.Before(st.blockedUntil) {
			delete(b.state, k)
		}
	}
}
