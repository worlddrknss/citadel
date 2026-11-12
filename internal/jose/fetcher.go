package jose

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FetcherConfig configures a JWKS Fetcher. Zero values get safe defaults.
type FetcherConfig struct {
	// URL of the JWKS document. Must be https unless AllowInsecureHTTP.
	URL string
	// Client is the base HTTP client (default http.DefaultClient's
	// transport). It is cloned; redirects to non-https URLs are refused.
	Client *http.Client
	// MinRefreshInterval is the floor between two fetches of any kind,
	// including kid-miss refetches and max-age=0 responses (default 1m).
	MinRefreshInterval time.Duration
	// DefaultTTL is used when the response has no Cache-Control max-age
	// (default 1h).
	DefaultTTL time.Duration
	// MaxTTL caps the max-age honoured from Cache-Control (default 24h).
	MaxTTL time.Duration
	// ErrorRetryInterval is the floor between fetch attempts after a failure
	// while no keys are cached (default 5s).
	ErrorRetryInterval time.Duration
	// MaxBytes bounds the response body (default 1 MiB).
	MaxBytes int64
	// Timeout bounds each fetch (default 10s).
	Timeout time.Duration
	// AllowInsecureHTTP permits http:// URLs. For tests only.
	AllowInsecureHTTP bool
	// Now defaults to time.Now.
	Now func() time.Time
}

// Fetcher retrieves and caches a remote JWKS. It is safe for concurrent use
// and implements KeySource.
type Fetcher struct {
	cfg    FetcherConfig
	client *http.Client

	fetchMu sync.Mutex // serialises network fetches

	mu          sync.Mutex
	set         *JWKSet
	expires     time.Time
	lastAttempt time.Time
	lastErr     error
}

// NewFetcher validates cfg and returns a Fetcher. No network I/O happens
// until the first Key or Keys call.
func NewFetcher(cfg FetcherConfig) (*Fetcher, error) {
	if err := CheckURL(cfg.URL, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if cfg.MinRefreshInterval <= 0 {
		cfg.MinRefreshInterval = time.Minute
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = time.Hour
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = 24 * time.Hour
	}
	if cfg.ErrorRetryInterval <= 0 {
		cfg.ErrorRetryInterval = 5 * time.Second
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 1 << 20
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Fetcher{cfg: cfg, client: SecureHTTPClient(cfg.Client, cfg.AllowInsecureHTTP)}, nil
}

// CheckURL requires an absolute https URL (or http when allowHTTP), with a
// host and no userinfo or fragment.
func CheckURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("jose: bad URL: %w", err)
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return fmt.Errorf("jose: URL %q must use https", raw)
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("jose: URL %q must have a host and no userinfo or fragment", raw)
	}
	return nil
}

// SecureHTTPClient returns a copy of base (nil means a default client) that
// refuses redirects to non-https URLs (unless allowHTTP) and caps redirects
// at 5. It never disables TLS verification.
func SecureHTTPClient(base *http.Client, allowHTTP bool) *http.Client {
	c := &http.Client{}
	if base != nil {
		*c = *base
	}
	prev := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("jose: too many redirects")
		}
		if req.URL.Scheme != "https" && !(allowHTTP && req.URL.Scheme == "http") {
			return fmt.Errorf("jose: refusing redirect to %s", req.URL.Scheme)
		}
		if prev != nil {
			return prev(req, via)
		}
		return nil
	}
	return c
}

// GetLimited performs a GET with a timeout and body size limit, returning
// the body and response headers. Non-200 responses are errors.
func GetLimited(ctx context.Context, c *http.Client, rawURL string, maxBytes int64, timeout time.Duration, accept string) ([]byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, nil, fmt.Errorf("jose: GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, nil, fmt.Errorf("jose: GET %s: response exceeds %d bytes", rawURL, maxBytes)
	}
	return body, resp.Header, nil
}

// Keys returns the cached key set, fetching it when absent or expired. If a
// refresh fails while an older set is cached, the stale set is returned for
// at most MaxTTL past its expiry.
func (f *Fetcher) Keys(ctx context.Context) (*JWKSet, error) {
	f.mu.Lock()
	set, fresh := f.set, f.set != nil && f.cfg.Now().Before(f.expires)
	f.mu.Unlock()
	if fresh {
		return set, nil
	}
	return f.refresh(ctx, false)
}

// Key implements KeySource. On a kid miss it refetches the set, at most once
// per MinRefreshInterval, to pick up newly rotated keys.
func (f *Fetcher) Key(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	set, err := f.Keys(ctx)
	if err != nil {
		return nil, err
	}
	k, err := set.Lookup(kid, alg)
	if err == nil {
		return k.Key, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	set, rerr := f.refresh(ctx, true)
	if rerr != nil {
		return nil, err
	}
	k, err = set.Lookup(kid, alg)
	if err != nil {
		return nil, err
	}
	return k.Key, nil
}

func (f *Fetcher) refresh(ctx context.Context, force bool) (*JWKSet, error) {
	f.fetchMu.Lock()
	defer f.fetchMu.Unlock()

	f.mu.Lock()
	now := f.cfg.Now()
	set := f.set
	if set != nil && !force && now.Before(f.expires) {
		f.mu.Unlock()
		return set, nil // another goroutine refreshed meanwhile
	}
	if !f.lastAttempt.IsZero() {
		since := now.Sub(f.lastAttempt)
		if set != nil && since < f.cfg.MinRefreshInterval {
			f.mu.Unlock()
			return set, nil // rate limited; serve what we have
		}
		if set == nil && f.lastErr != nil && since < f.cfg.ErrorRetryInterval {
			err := f.lastErr
			f.mu.Unlock()
			return nil, err
		}
	}
	f.lastAttempt = now
	f.mu.Unlock()

	body, hdr, err := GetLimited(ctx, f.client, f.cfg.URL, f.cfg.MaxBytes, f.cfg.Timeout, "application/json, application/jwk-set+json")
	var fetched *JWKSet
	if err == nil {
		fetched, err = ParseJWKSet(body)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.lastErr = fmt.Errorf("jose: fetch JWKS %s: %w", f.cfg.URL, err)
		// Serve a stale set for a bounded time (MaxTTL past expiry) so a
		// provider outage does not break sign-in, without trusting removed
		// keys indefinitely.
		if f.set != nil && f.cfg.Now().Before(f.expires.Add(f.cfg.MaxTTL)) {
			return f.set, nil
		}
		f.set = nil
		return nil, f.lastErr
	}
	f.lastErr = nil
	f.set = fetched
	f.expires = f.cfg.Now().Add(f.ttl(hdr.Get("Cache-Control")))
	return fetched, nil
}

func (f *Fetcher) ttl(cacheControl string) time.Duration {
	ttl := f.cfg.DefaultTTL
	for _, d := range strings.Split(cacheControl, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "no-store" || d == "no-cache":
			return f.cfg.MinRefreshInterval
		case strings.HasPrefix(d, "max-age="):
			if n, err := strconv.ParseInt(strings.Trim(d[len("max-age="):], `"`), 10, 64); err == nil && n >= 0 {
				if n > int64(f.cfg.MaxTTL/time.Second) {
					ttl = f.cfg.MaxTTL
				} else {
					ttl = time.Duration(n) * time.Second
				}
			}
		}
	}
	if ttl < f.cfg.MinRefreshInterval {
		ttl = f.cfg.MinRefreshInterval
	}
	if ttl > f.cfg.MaxTTL {
		ttl = f.cfg.MaxTTL
	}
	return ttl
}
