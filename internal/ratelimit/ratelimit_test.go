package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestLimiterBurstAndRefill(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	l := New(10*time.Second, 3)
	l.now = c.now
	for i := range 3 {
		if !l.Allow("a") {
			t.Fatalf("event %d within burst refused", i)
		}
	}
	ok, wait := l.Reserve("a")
	if ok || wait <= 0 || wait > 10*time.Second {
		t.Fatalf("over burst: ok=%v wait=%v", ok, wait)
	}
	if !l.Allow("b") {
		t.Fatal("keys must be independent")
	}
	c.advance(10 * time.Second)
	if !l.Allow("a") {
		t.Fatal("token should refill after the interval")
	}
	if l.Allow("a") {
		t.Fatal("only one token refills per interval")
	}
}

func TestLimiterBoundsKeys(t *testing.T) {
	l := New(time.Hour, 1)
	l.maxKeys = 10
	for i := range 100 {
		l.Allow(fmt.Sprint(i))
	}
	if len(l.buckets) > 10 {
		t.Fatalf("tracked %d keys, max 10", len(l.buckets))
	}
}

func TestBackoffExponential(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	b := NewBackoff(2, time.Second, 8*time.Second, time.Hour)
	b.now = c.now
	want := []time.Duration{0, 0, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}
	for i, w := range want {
		if got := b.Fail("u"); got != w {
			t.Fatalf("failure %d: lockout %v, want %v", i+1, got, w)
		}
	}
	if blocked, d := b.Blocked("u"); !blocked || d != 8*time.Second {
		t.Fatalf("Blocked = %v %v", blocked, d)
	}
	c.advance(9 * time.Second)
	if blocked, _ := b.Blocked("u"); blocked {
		t.Fatal("lockout should expire")
	}
	b.Reset("u")
	if got := b.Fail("u"); got != 0 {
		t.Fatalf("after reset first failure should be free, got %v", got)
	}
}

func TestBackoffForgetsQuietKeys(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	b := NewBackoff(1, time.Second, time.Minute, 10*time.Minute)
	b.now = c.now
	b.Fail("u")
	b.Fail("u")
	c.advance(11 * time.Minute)
	if got := b.Fail("u"); got != 0 {
		t.Fatalf("failures should be forgotten after a quiet period, got lockout %v", got)
	}
}

func TestBackoffSweepKeepsBlockedKeys(t *testing.T) {
	b := NewBackoff(0, time.Hour, time.Hour, time.Hour)
	b.maxKeys = 5
	b.Fail("victim")
	for i := range 50 {
		b.state[fmt.Sprint("x", i)] = &failState{failures: 0, last: b.now()}
	}
	b.Fail("new")
	if blocked, _ := b.Blocked("victim"); !blocked {
		t.Fatal("sweep must not clear an active lockout")
	}
}

func TestConcurrentUse(t *testing.T) {
	l := New(time.Millisecond, 5)
	b := NewBackoff(3, time.Millisecond, time.Second, time.Minute)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 200 {
				k := fmt.Sprint(i, j%7)
				l.Allow(k)
				b.Fail(k)
				b.Blocked(k)
				if j%13 == 0 {
					b.Reset(k)
				}
			}
		}()
	}
	wg.Wait()
}
