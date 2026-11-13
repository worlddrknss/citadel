package providertoken

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testClientSecret = "client secret/with+specials"

type fakeOAuth struct {
	calls   atomic.Int32
	mu      sync.Mutex
	form    url.Values
	auth    string
	reply   string
	ctype   string
	status  int
	release chan struct{}
}

func (f *fakeOAuth) handler(w http.ResponseWriter, r *http.Request) {
	n := f.calls.Add(1)
	if f.release != nil {
		<-f.release
	}
	b, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(b))
	f.mu.Lock()
	f.form, f.auth = form, r.Header.Get("Authorization")
	f.mu.Unlock()
	ct := f.ctype
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	reply := f.reply
	if reply == "" {
		reply = fmt.Sprintf(`{"access_token":"at-%d","token_type":"Bearer","expires_in":3600,"scope":"read write"}`, n)
	}
	io.WriteString(w, reply)
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestOAuth(t *testing.T, f *fakeOAuth, mod func(*OAuth2Config)) (*OAuth2ClientCredentials, *testClock) {
	t.Helper()
	srv, client := newTLS(t, f.handler)
	clock := &testClock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	cfg := OAuth2Config{TokenURL: srv.URL + "/oauth/token", ClientID: "agent client", ClientSecret: testClientSecret, Scopes: []string{"read"}, Now: clock.Now}
	if mod != nil {
		mod(&cfg)
	}
	o, err := NewOAuth2ClientCredentials(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	return o, clock
}

func TestOAuth2Basic(t *testing.T) {
	f := &fakeOAuth{}
	o, _ := newTestOAuth(t, f, func(c *OAuth2Config) { c.Audience = "https://api.example.com" })
	tok, err := o.Mint(context.Background(), Params{})
	if err != nil {
		t.Fatal(err)
	}
	// RFC 6749 §2.3.1: both parts form-encoded, then Basic.
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape("agent client")+":"+url.QueryEscape(testClientSecret)))
	if f.auth != want {
		t.Fatalf("Authorization = %q, want %q", f.auth, want)
	}
	if f.form.Get("grant_type") != "client_credentials" || f.form.Get("scope") != "read" || f.form.Get("audience") != "https://api.example.com" {
		t.Fatalf("form = %v", f.form)
	}
	if f.form.Has("client_secret") || f.form.Has("client_id") {
		t.Fatal("credentials sent in the body with client_secret_basic")
	}
	if tok.Value != "at-1" || tok.Kind != KindOAuth2Client || !tok.ExpiresAt.Equal(time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("token = %v", tok)
	}
	if tok.Metadata["tokenType"] != "bearer" || tok.Metadata["scope"] != "read write" {
		t.Fatalf("metadata = %v", tok.Metadata)
	}
}

func TestOAuth2Post(t *testing.T) {
	f := &fakeOAuth{}
	o, _ := newTestOAuth(t, f, func(c *OAuth2Config) { c.AuthStyle = AuthStylePost })
	if _, err := o.Mint(context.Background(), Params{Scopes: []string{"a", "b"}, Resource: "https://api.example.com/"}); err != nil {
		t.Fatal(err)
	}
	if f.auth != "" || f.form.Get("client_id") != "agent client" || f.form.Get("client_secret") != testClientSecret {
		t.Fatalf("client_secret_post not used: auth=%v form=%v", f.auth != "", f.form.Has("client_secret"))
	}
	if f.form.Get("scope") != "a b" || f.form.Get("resource") != "https://api.example.com/" {
		t.Fatalf("form = %v", f.form)
	}
}

func TestOAuth2Cache(t *testing.T) {
	f := &fakeOAuth{}
	o, clock := newTestOAuth(t, f, nil)
	ctx := context.Background()
	a, _ := o.Mint(ctx, Params{})
	b, _ := o.Mint(ctx, Params{})
	if a.Value != "at-1" || b.Value != "at-1" || f.calls.Load() != 1 {
		t.Fatalf("not cached: %s %s calls=%d", a.Value, b.Value, f.calls.Load())
	}
	// Mutating returned metadata does not affect the cache.
	b.Metadata["scope"] = "admin"
	if c, _ := o.Mint(ctx, Params{}); c.Metadata["scope"] != "read write" {
		t.Fatal("cache shares metadata maps with callers")
	}
	// Different scopes are a different cache entry; order does not matter.
	x, _ := o.Mint(ctx, Params{Scopes: []string{"b", "a"}})
	y, _ := o.Mint(ctx, Params{Scopes: []string{"a", "b"}})
	if x.Value != "at-2" || y.Value != "at-2" {
		t.Fatalf("scope keyed cache: %s %s", x.Value, y.Value)
	}
	// Refreshed DefaultRefreshBefore ahead of expiry.
	clock.Advance(58 * time.Minute)
	if c, _ := o.Mint(ctx, Params{}); c.Value != "at-1" {
		t.Fatalf("refreshed too early: %s", c.Value)
	}
	clock.Advance(90 * time.Second)
	if c, _ := o.Mint(ctx, Params{}); c.Value != "at-3" {
		t.Fatalf("not refreshed before expiry: %s", c.Value)
	}
	o.Invalidate()
	if c, _ := o.Mint(ctx, Params{}); c.Value != "at-4" {
		t.Fatalf("Invalidate did not drop the cache: %s", c.Value)
	}
}

func TestOAuth2Singleflight(t *testing.T) {
	f := &fakeOAuth{release: make(chan struct{})}
	o, _ := newTestOAuth(t, f, nil)
	const n = 20
	var wg sync.WaitGroup
	vals := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := o.Mint(context.Background(), Params{})
			vals[i], errs[i] = tok.Value, err
		}()
	}
	// A caller that gives up does not cancel the shared fetch.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { _, err := o.Mint(ctx, Params{}); done <- err }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller err = %v", err)
	}
	close(f.release)
	wg.Wait()
	for i := range n {
		if errs[i] != nil || vals[i] != "at-1" {
			t.Fatalf("caller %d: %q %v", i, vals[i], errs[i])
		}
	}
	if c := f.calls.Load(); c != 1 {
		t.Fatalf("token endpoint called %d times, want 1", c)
	}
}

func TestOAuth2Responses(t *testing.T) {
	ctx := context.Background()
	t.Run("error code kept, description dropped", func(t *testing.T) {
		f := &fakeOAuth{status: 401, reply: `{"error":"invalid_client","error_description":"secret ` + testClientSecret + ` is wrong"}`}
		o, _ := newTestOAuth(t, f, nil)
		_, err := o.Mint(ctx, Params{})
		var pe *ProviderError
		if !errors.As(err, &pe) || pe.Code != "invalid_client" || pe.Status != 401 {
			t.Fatalf("err = %v", err)
		}
		noSecrets(t, err, testClientSecret, "is wrong")
		// Errors are not cached.
		f.status, f.reply = 0, ""
		if tok, err := o.Mint(ctx, Params{}); err != nil || tok.Value == "" {
			t.Fatalf("retry after error: %v", err)
		}
	})
	t.Run("expires_in as string", func(t *testing.T) {
		f := &fakeOAuth{reply: `{"access_token":"tok","expires_in":"120"}`}
		o, clock := newTestOAuth(t, f, nil)
		tok, err := o.Mint(ctx, Params{})
		if err != nil || !tok.ExpiresAt.Equal(clock.Now().Add(2*time.Minute)) {
			t.Fatalf("tok=%v err=%v", tok, err)
		}
	})
	t.Run("no expires_in is not cached", func(t *testing.T) {
		f := &fakeOAuth{reply: `{"access_token":"tok","token_type":"bearer"}`}
		o, _ := newTestOAuth(t, f, nil)
		o.Mint(ctx, Params{})
		tok, err := o.Mint(ctx, Params{})
		if err != nil || !tok.ExpiresAt.IsZero() || f.calls.Load() != 2 {
			t.Fatalf("tok=%v err=%v calls=%d", tok, err, f.calls.Load())
		}
	})
	t.Run("form-encoded response", func(t *testing.T) {
		f := &fakeOAuth{ctype: "application/x-www-form-urlencoded", reply: "access_token=formtok&token_type=bearer&expires_in=60"}
		o, _ := newTestOAuth(t, f, nil)
		tok, err := o.Mint(ctx, Params{})
		if err != nil || tok.Value != "formtok" || tok.ExpiresAt.IsZero() {
			t.Fatalf("tok=%v err=%v", tok, err)
		}
	})
	t.Run("invalid expires_in", func(t *testing.T) {
		f := &fakeOAuth{reply: `{"access_token":"tok-secret-xyz","expires_in":"soon"}`}
		o, _ := newTestOAuth(t, f, nil)
		_, err := o.Mint(ctx, Params{})
		if err == nil {
			t.Fatal("accepted")
		}
		noSecrets(t, err, "tok-secret-xyz")
	})
	t.Run("missing access_token", func(t *testing.T) {
		f := &fakeOAuth{reply: `{"token_type":"bearer"}`}
		o, _ := newTestOAuth(t, f, nil)
		if _, err := o.Mint(ctx, Params{}); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("bad params", func(t *testing.T) {
		o, _ := newTestOAuth(t, &fakeOAuth{}, nil)
		if _, err := o.Mint(ctx, Params{Scopes: []string{"has space"}}); err == nil {
			t.Fatal("bad scope accepted")
		}
		if _, err := o.Mint(ctx, Params{Resource: "not a uri"}); err == nil {
			t.Fatal("bad resource accepted")
		}
	})
}

func TestNewOAuth2Validation(t *testing.T) {
	base := OAuth2Config{TokenURL: "https://idp.example.com/token", ClientID: "id", ClientSecret: testClientSecret}
	for name, mod := range map[string]func(*OAuth2Config){
		"http":       func(c *OAuth2Config) { c.TokenURL = "http://idp.example.com/token" },
		"no secret":  func(c *OAuth2Config) { c.ClientSecret = "" },
		"bad style":  func(c *OAuth2Config) { c.AuthStyle = 7 },
		"bad scope":  func(c *OAuth2Config) { c.Scopes = []string{`a"b`} },
		"query in u": func(c *OAuth2Config) { c.TokenURL = "https://idp.example.com/token?secret=" + testClientSecret },
	} {
		cfg := base
		mod(&cfg)
		_, err := NewOAuth2ClientCredentials(cfg, &http.Client{})
		if err == nil {
			t.Errorf("%s accepted", name)
		}
		noSecrets(t, err, testClientSecret, strings.Split(testClientSecret, " ")[0]+" secret")
	}
}
