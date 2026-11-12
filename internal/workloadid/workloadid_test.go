package workloadid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
)

func ecSigner(t *testing.T, kid string) *jose.LocalSigner {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewLocalSigner(k, jose.ES256, kid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type auditEntry struct {
	w   Workload
	c   Client
	jti string
	aud string
	exp time.Time
}

type env struct {
	srv     *httptest.Server
	issuer  *Issuer
	ring    *KeyRing
	clients *MemoryClientStore
	now     time.Time
	mu      sync.Mutex
	audit   []auditEntry
}

func newEnv(t *testing.T, auth Authenticator) *env {
	e := &env{now: time.Now().Truncate(time.Second)}
	e.ring, _ = NewKeyRing(ecSigner(t, "key-1"))
	e.clients = NewMemoryClientStore(nil)
	mux := http.NewServeMux()
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	if auth == nil {
		auth = AuthenticatorFunc(func(ctx context.Context, r *AuthRequest) (Workload, error) {
			if r.Credential != "good-key" {
				return Workload{}, ErrUnauthenticated
			}
			return Workload{AccountRef: r.Client.AccountRef, ClientID: r.Client.ID, Subject: "AKIDEXAMPLE", Attributes: map[string]string{"repo": "acme/api"}}, nil
		})
	}
	var err error
	e.issuer, err = New(Config{
		IssuerURL: e.srv.URL + "/wi", Signers: e.ring, Clients: e.clients, Authenticator: auth,
		Clock: func() time.Time { return e.now }, MaxTTL: time.Hour, AllowInsecureIssuer: true,
		OnIssue: func(ctx context.Context, w Workload, c Client, jti, aud string, exp time.Time) {
			e.mu.Lock()
			e.audit = append(e.audit, auditEntry{w, c, jti, aud, exp})
			e.mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/wi/", e.issuer.Handler())
	_, err = e.clients.Create(context.Background(), Client{
		ID: "ci-deploy", AccountRef: "acct-1", Name: "CI", AllowedAudiences: []string{"sts.amazonaws.com", "vault"},
		TTL: 30 * time.Minute, SubjectTemplate: "account:{account}:client:{client}:repo:{repo}", AuthMethod: AuthAccessKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) request(t *testing.T, body string, bearer string) (*http.Response, map[string]any) {
	req, _ := http.NewRequest("POST", e.srv.URL+"/wi/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// verify checks a token the way a relying party would: discovery, then the
// served JWKS via the jose fetcher, then claims.
func (e *env) verify(t *testing.T, tok, aud string, now time.Time) (jose.Claims, error) {
	t.Helper()
	resp, err := http.Get(e.srv.URL + "/wi/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc DiscoveryDocument
	json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc.Issuer != e.srv.URL+"/wi" || doc.JWKSURI != doc.Issuer+"/jwks.json" || doc.TokenEndpoint != doc.Issuer+"/token" ||
		doc.ResponseTypesSupported[0] != "id_token" || doc.SubjectTypesSupported[0] != "public" || doc.IDTokenSigningAlgValuesSupported[0] != "ES256" {
		t.Fatalf("discovery %+v", doc)
	}
	f, err := jose.NewFetcher(jose.FetcherConfig{URL: doc.JWKSURI, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	j, err := jose.Verify(context.Background(), tok, f, doc.IDTokenSigningAlgValuesSupported...)
	if err != nil {
		return nil, err
	}
	c, err := jose.ParseClaims(j.Payload)
	if err != nil {
		return nil, err
	}
	return c, jose.Validator{Issuer: doc.Issuer, Audience: aud, Now: func() time.Time { return now }, Required: []string{"sub", "jti", "nbf"}, RequireIssuedAt: true}.Validate(c)
}

func TestIssueAndVerify(t *testing.T) {
	e := newEnv(t, nil)
	resp, out := e.request(t, `{"client_id":"ci-deploy","audience":"sts.amazonaws.com","credential":"good-key"}`, "")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d %v", resp.StatusCode, out)
	}
	tok := out["token"].(string)
	if out["expires_in"].(float64) != 1800 {
		t.Fatalf("expires_in %v", out["expires_in"])
	}
	exp, err := time.Parse(time.RFC3339, out["expires_at"].(string))
	if err != nil || !exp.Equal(e.now.Add(30*time.Minute)) {
		t.Fatalf("expires_at %v %v", out["expires_at"], err)
	}
	c, err := e.verify(t, tok, "sts.amazonaws.com", e.now)
	if err != nil {
		t.Fatal(err)
	}
	if sub, _ := c.String("sub"); sub != "account:acct-1:client:ci-deploy:repo:acme/api" {
		t.Fatalf("sub %q", sub)
	}
	ns := c["citadel"].(map[string]any)
	if ns["account"] != "acct-1" || ns["client_id"] != "ci-deploy" || ns["auth_method"] != "access_key" ||
		ns["workload"] != "AKIDEXAMPLE" || ns["attributes"].(map[string]any)["repo"] != "acme/api" {
		t.Fatalf("custom claims %v", ns)
	}
	if aud, _ := c.Audience(); len(aud) != 1 || aud[0] != "sts.amazonaws.com" {
		t.Fatal(aud)
	}
	if len(e.audit) != 1 || e.audit[0].jti != c["jti"] || e.audit[0].aud != "sts.amazonaws.com" || !e.audit[0].exp.Equal(exp) {
		t.Fatalf("audit %+v", e.audit)
	}
	// Expired from the relying party's point of view after 30 minutes.
	if _, err := e.verify(t, tok, "sts.amazonaws.com", e.now.Add(31*time.Minute)); !errors.Is(err, jose.ErrExpired) {
		t.Fatalf("want expired: %v", err)
	}
	// Bearer credential and form encoding.
	req, _ := http.NewRequest("POST", e.srv.URL+"/wi/token", strings.NewReader("client_id=ci-deploy&audience=vault&ttl_seconds=120"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer good-key")
	r2, err := http.DefaultClient.Do(req)
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("form request: %v %d", err, r2.StatusCode)
	}
	r2.Body.Close()
}

func TestJWKSCacheableAndRoutes(t *testing.T) {
	e := newEnv(t, nil)
	resp, err := http.Get(e.srv.URL + "/wi/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "max-age=") {
		t.Fatalf("jwks cache-control %q", resp.Header.Get("Cache-Control"))
	}
	resp.Body.Close()
	resp, _ = http.Get(e.srv.URL + "/wi/token")
	if resp.StatusCode != 405 {
		t.Fatalf("GET /token: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, _ = http.Get(e.srv.URL + "/wi/other")
	if resp.StatusCode != 404 {
		t.Fatalf("unknown path: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestTokenErrors(t *testing.T) {
	e := newEnv(t, nil)
	cases := []struct {
		body   string
		status int
		code   string
	}{
		{`{"client_id":"ci-deploy","audience":"evil.example","credential":"good-key"}`, 400, "invalid_target"},
		{`{"client_id":"ci-deploy","audience":"vault","credential":"bad-key"}`, 401, "invalid_client"},
		{`{"client_id":"nope","audience":"vault","credential":"good-key"}`, 401, "invalid_client"},
		{`{"client_id":"ci-deploy","credential":"good-key"}`, 400, "invalid_request"},
		{`{"client_id":"ci-deploy","audience":"vault","credential":"good-key","ttl_seconds":-5}`, 400, "invalid_request"},
		{`{"client_id":"ci-deploy","audience":"vault","extra":1}`, 400, "invalid_request"},
		{`not json`, 400, "invalid_request"},
	}
	for _, tc := range cases {
		resp, out := e.request(t, tc.body, "")
		if resp.StatusCode != tc.status || out["error"] != tc.code {
			t.Errorf("%s: got %d %v", tc.body, resp.StatusCode, out)
		}
	}
	if len(e.audit) != 0 {
		t.Fatal("audit hook called on failure")
	}
}

func TestAuthenticatorCannotCrossAccounts(t *testing.T) {
	e := newEnv(t, AuthenticatorFunc(func(ctx context.Context, r *AuthRequest) (Workload, error) {
		return Workload{AccountRef: "acct-other", ClientID: r.Client.ID}, nil
	}))
	resp, out := e.request(t, `{"client_id":"ci-deploy","audience":"vault"}`, "")
	if resp.StatusCode != 403 || out["error"] != "access_denied" {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
}

func TestMissingSubjectAttribute(t *testing.T) {
	e := newEnv(t, AuthenticatorFunc(func(ctx context.Context, r *AuthRequest) (Workload, error) {
		return Workload{AccountRef: r.Client.AccountRef, ClientID: r.Client.ID}, nil // no repo attribute
	}))
	resp, out := e.request(t, `{"client_id":"ci-deploy","audience":"vault"}`, "")
	if resp.StatusCode != 403 {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
}

func TestTTLClamping(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	issue := func(clientTTL, requested time.Duration) int64 {
		c, _ := e.clients.Get(ctx, "ci-deploy")
		c.TTL = clientTTL
		if _, err := e.clients.Update(ctx, c); err != nil {
			t.Fatal(err)
		}
		tok, err := e.issuer.Issue(ctx, TokenRequest{ClientID: "ci-deploy", Audience: "vault", TTL: requested, Credential: "good-key"})
		if err != nil {
			t.Fatal(err)
		}
		j, _ := jose.ParseCompact(tok.Token)
		cl, _ := jose.ParseClaims(j.Payload)
		exp, _, _ := cl.Time("exp")
		iat, _, _ := cl.Time("iat")
		if int64(exp.Sub(iat)/time.Second) != tok.ExpiresIn {
			t.Fatalf("exp-iat %v != expires_in %d", exp.Sub(iat), tok.ExpiresIn)
		}
		return tok.ExpiresIn
	}
	for _, tc := range []struct {
		client, req time.Duration
		want        int64
	}{
		{30 * time.Minute, 0, 1800},              // client default
		{30 * time.Minute, 5 * time.Minute, 300}, // shorter request honoured
		{30 * time.Minute, 2 * time.Hour, 1800},  // clamped to client TTL
		{3 * time.Hour, 2 * time.Hour, 3600},     // client TTL clamped to MaxTTL
		{0, 0, 900},                              // issuer default
		{30 * time.Minute, 10 * time.Second, 60}, // MinTTL floor
	} {
		if got := issue(tc.client, tc.req); got != tc.want {
			t.Errorf("client %v req %v: got %d want %d", tc.client, tc.req, got, tc.want)
		}
	}
}

func TestKeyRotation(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	old, err := e.issuer.Issue(ctx, TokenRequest{ClientID: "ci-deploy", Audience: "vault", Credential: "good-key"})
	if err != nil {
		t.Fatal(err)
	}
	// Stage: published but not yet used.
	if err := e.ring.Stage(ecSigner(t, "key-2")); err != nil {
		t.Fatal(err)
	}
	set, _ := e.issuer.JWKS(ctx)
	if len(set.Keys) != 2 {
		t.Fatalf("staged key not published: %d", len(set.Keys))
	}
	if err := e.ring.Stage(ecSigner(t, "key-1")); err == nil {
		t.Fatal("duplicate kid accepted")
	}
	if err := e.ring.Promote(); err != nil {
		t.Fatal(err)
	}
	fresh, _ := e.issuer.Issue(ctx, TokenRequest{ClientID: "ci-deploy", Audience: "vault", Credential: "good-key"})
	jf, _ := jose.ParseCompact(fresh.Token)
	if jf.Header.Kid != "key-2" {
		t.Fatalf("new token kid %q", jf.Header.Kid)
	}
	// Old token still verifies while key-1 is published as previous.
	if _, err := e.verify(t, old.Token, "vault", e.now); err != nil {
		t.Fatalf("old token after rotation: %v", err)
	}
	if _, err := e.verify(t, fresh.Token, "vault", e.now); err != nil {
		t.Fatal(err)
	}
	// After retirement it no longer verifies.
	if err := e.ring.Retire("key-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.verify(t, old.Token, "vault", e.now); !errors.Is(err, jose.ErrKeyNotFound) {
		t.Fatalf("retired key: %v", err)
	}
}

func TestRSASigner(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := jose.NewLocalSigner(k, jose.PS256, "rsa-1")
	e := newEnv(t, nil)
	if err := e.ring.Rotate(s); err != nil {
		t.Fatal(err)
	}
	doc, _ := e.issuer.Discovery(context.Background())
	if len(doc.IDTokenSigningAlgValuesSupported) != 2 {
		t.Fatalf("algs %v", doc.IDTokenSigningAlgValuesSupported)
	}
	tok, err := e.issuer.Issue(context.Background(), TokenRequest{ClientID: "ci-deploy", Audience: "vault", Credential: "good-key"})
	if err != nil {
		t.Fatal(err)
	}
	set, _ := e.issuer.JWKS(context.Background())
	if _, err := jose.Verify(context.Background(), tok.Token, set); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	ring, _ := NewKeyRing(ecSigner(t, "k"))
	store := NewMemoryClientStore(nil)
	auth := AuthenticatorFunc(nil)
	for _, u := range []string{"http://citadel.example", "https://citadel.example/", "https://citadel.example?x=1", "citadel.example"} {
		if _, err := New(Config{IssuerURL: u, Signers: ring, Clients: store, Authenticator: auth}); err == nil {
			t.Errorf("accepted issuer %q", u)
		}
	}
	if _, err := NewKeyRing(nil); err == nil {
		t.Fatal("nil signer accepted")
	}
	bad := []Client{
		{ID: "", AccountRef: "a", AllowedAudiences: []string{"x"}, AuthMethod: AuthAccessKey},
		{ID: "c", AccountRef: "", AllowedAudiences: []string{"x"}, AuthMethod: AuthAccessKey},
		{ID: "c", AccountRef: "a", AuthMethod: AuthAccessKey},
		{ID: "c", AccountRef: "a", AllowedAudiences: []string{"x"}, AuthMethod: "password"},
		{ID: "c", AccountRef: "a", AllowedAudiences: []string{"x"}, AuthMethod: AuthKubernetes},
		{ID: "c", AccountRef: "a", AllowedAudiences: []string{"x"}, AuthMethod: AuthKubernetes, Kubernetes: &KubernetesConfig{APIServer: "https://k8s"}},
		{ID: "c", AccountRef: "a", AllowedAudiences: []string{"x"}, AuthMethod: AuthAccessKey, SubjectTemplate: "x:{}"},
	}
	for i, c := range bad {
		if _, err := store.Create(context.Background(), c); err == nil {
			t.Errorf("bad client %d accepted", i)
		}
	}
}

func TestMemoryClientStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryClientStore(nil)
	c := Client{ID: "a", AccountRef: "acct", AllowedAudiences: []string{"x"}, AuthMethod: AuthAccessKey}
	created, err := s.Create(ctx, c)
	if err != nil || created.CreatedAt.IsZero() {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, c); !errors.Is(err, ErrClientExists) {
		t.Fatal(err)
	}
	created.AllowedAudiences[0] = "mutated"
	got, _ := s.Get(ctx, "a")
	if got.AllowedAudiences[0] != "x" {
		t.Fatal("store aliased caller slice")
	}
	got.AccountRef = "other"
	got.Name = "renamed"
	upd, err := s.Update(ctx, got)
	if err != nil || upd.AccountRef != "acct" || upd.Name != "renamed" {
		t.Fatalf("update: %v %+v", err, upd)
	}
	if l, _ := s.List(ctx, "acct"); len(l) != 1 {
		t.Fatal("list")
	}
	if l, _ := s.List(ctx, "nope"); len(l) != 0 {
		t.Fatal("list other")
	}
	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "a"); !errors.Is(err, ErrClientNotFound) {
		t.Fatal(err)
	}
}
