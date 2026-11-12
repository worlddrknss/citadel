package jose

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type jwksServer struct {
	*httptest.Server
	hits         atomic.Int32
	mu           sync.Mutex
	set          *JWKSet
	cacheControl string
	status       int
	body         string
}

func newJWKSServer(t *testing.T, set *JWKSet) *jwksServer {
	s := &jwksServer{set: set, status: 200}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.cacheControl != "" {
			w.Header().Set("Cache-Control", s.cacheControl)
		}
		w.WriteHeader(s.status)
		if s.body != "" {
			w.Write([]byte(s.body))
			return
		}
		json.NewEncoder(w).Encode(s.set)
	}))
	t.Cleanup(s.Close)
	return s
}

func newTestFetcher(t *testing.T, url string, clk *fakeClock) *Fetcher {
	f, err := NewFetcher(FetcherConfig{URL: url, AllowInsecureHTTP: true, Now: clk.Now, MinRefreshInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFetcherHTTPSOnly(t *testing.T) {
	if _, err := NewFetcher(FetcherConfig{URL: "http://example.com/jwks"}); err == nil {
		t.Fatal("http accepted without AllowInsecureHTTP")
	}
	for _, u := range []string{"ftp://x/jwks", "https:///jwks", "https://u:p@x/jwks", "/jwks"} {
		if _, err := NewFetcher(FetcherConfig{URL: u}); err == nil {
			t.Fatalf("accepted %s", u)
		}
	}
	// Redirects to http are refused even when the initial URL is https.
	c := SecureHTTPClient(nil, false)
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	if err := c.CheckRedirect(req, nil); err == nil {
		t.Fatal("redirect to http allowed")
	}
}

func TestFetcherCachingAndKidMiss(t *testing.T) {
	ctx := context.Background()
	s1, _ := NewLocalSigner(mustEC(t, elliptic.P256()), ES256, "k1")
	s2, _ := NewLocalSigner(mustEC(t, elliptic.P256()), ES256, "k2")
	srv := newJWKSServer(t, &JWKSet{Keys: []JWK{NewJWK(s1)}})
	srv.cacheControl = "public, max-age=600"
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := newTestFetcher(t, srv.URL, clk)

	if _, err := f.Key(ctx, "k1", ES256); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Key(ctx, "k1", ES256); err != nil {
		t.Fatal(err)
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("hits=%d want 1 (cached)", n)
	}

	// Rotation: k2 appears upstream. A kid miss within MinRefreshInterval of
	// the last fetch is rate limited.
	srv.mu.Lock()
	srv.set = &JWKSet{Keys: []JWK{NewJWK(s1), NewJWK(s2)}}
	srv.mu.Unlock()
	if _, err := f.Key(ctx, "k2", ES256); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("want rate-limited miss, got %v", err)
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("hits=%d want 1 (rate limited)", n)
	}
	clk.Add(61 * time.Second)
	if _, err := f.Key(ctx, "k2", ES256); err != nil {
		t.Fatalf("kid-miss refetch: %v", err)
	}
	if n := srv.hits.Load(); n != 2 {
		t.Fatalf("hits=%d want 2", n)
	}
	// Repeated misses for an unknown kid do not hammer the server.
	for i := 0; i < 10; i++ {
		f.Key(ctx, "nope", ES256)
	}
	if n := srv.hits.Load(); n != 2 {
		t.Fatalf("hits=%d want 2 after misses", n)
	}
	// max-age honoured: refetch after 600s.
	clk.Add(601 * time.Second)
	f.Key(ctx, "k1", ES256)
	if n := srv.hits.Load(); n != 3 {
		t.Fatalf("hits=%d want 3 after max-age", n)
	}
}

func TestFetcherMaxAgeFloorAndStale(t *testing.T) {
	ctx := context.Background()
	s1, _ := NewLocalSigner(mustEC(t, elliptic.P256()), ES256, "k1")
	srv := newJWKSServer(t, &JWKSet{Keys: []JWK{NewJWK(s1)}})
	srv.cacheControl = "max-age=0"
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := newTestFetcher(t, srv.URL, clk)
	for i := 0; i < 5; i++ {
		if _, err := f.Key(ctx, "k1", ES256); err != nil {
			t.Fatal(err)
		}
		clk.Add(time.Second)
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("max-age=0 not floored: hits=%d", n)
	}
	// Upstream fails: the stale set is served.
	srv.mu.Lock()
	srv.status = 500
	srv.mu.Unlock()
	clk.Add(2 * time.Minute)
	if _, err := f.Key(ctx, "k1", ES256); err != nil {
		t.Fatalf("stale set not served: %v", err)
	}
	// ...but not forever.
	clk.Add(25 * time.Hour)
	if _, err := f.Key(ctx, "k1", ES256); err == nil {
		t.Fatal("stale set served past MaxTTL")
	}
}

func TestFetcherSizeLimit(t *testing.T) {
	srv := newJWKSServer(t, nil)
	srv.body = `{"keys":[],"pad":"` + strings.Repeat("a", 2048) + `"}`
	f, _ := NewFetcher(FetcherConfig{URL: srv.URL, AllowInsecureHTTP: true, MaxBytes: 1024})
	if _, err := f.Keys(context.Background()); err == nil {
		t.Fatal("oversized JWKS accepted")
	}
}

func TestFetcherTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	f, _ := NewFetcher(FetcherConfig{URL: srv.URL, AllowInsecureHTTP: true, Timeout: 50 * time.Millisecond})
	if _, err := f.Keys(context.Background()); err == nil {
		t.Fatal("timeout not enforced")
	}
}
