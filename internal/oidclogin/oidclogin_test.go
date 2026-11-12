package oidclogin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
)

const (
	clientID     = "citadel-console"
	clientSecret = "s3cr3t:with/specials"
	redirectURL  = "https://citadel.test/auth/oidc/callback"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type codeGrant struct {
	nonce, challenge string
}

// fakeProvider is a minimal OIDC provider: discovery, JWKS, token, userinfo.
type fakeProvider struct {
	t      *testing.T
	srv    *httptest.Server
	clk    *clock
	signer *jose.LocalSigner
	rsaKey *rsa.PrivateKey

	mu            sync.Mutex
	codes         map[string]codeGrant
	authMethod    string // expected client auth
	issuerInDoc   string // overrides discovery issuer
	mutate        func(c map[string]any)
	forge         func(claims map[string]any) string // replaces the signed ID token
	userinfo      map[string]any
	tokenRequests int
}

func newFakeProvider(t *testing.T, clk *clock) *fakeProvider {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := jose.NewLocalSigner(ek, jose.ES256, "ec-1")
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{t: t, clk: clk, signer: s, rsaKey: rk, codes: map[string]codeGrant{}, authMethod: AuthClientSecretBasic}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/userinfo", p.userinfoHandler)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) issuer() string { return p.srv.URL }

func (p *fakeProvider) discovery(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	iss := p.issuer()
	if p.issuerInDoc != "" {
		iss = p.issuerInDoc
	}
	p.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                p.issuer() + "/authorize?tenant=t1",
		"token_endpoint":                        p.issuer() + "/token",
		"userinfo_endpoint":                     p.issuer() + "/userinfo",
		"jwks_uri":                              p.issuer() + "/jwks",
		"id_token_signing_alg_values_supported": []string{"ES256", "RS256", "HS256", "none"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
	})
}

func (p *fakeProvider) jwks(w http.ResponseWriter, r *http.Request) {
	set := jose.JWKSet{Keys: []jose.JWK{jose.NewJWK(p.signer), {Key: &p.rsaKey.PublicKey, KeyID: "rsa-1", Use: "sig"}}}
	w.Header().Set("Cache-Control", "max-age=300")
	json.NewEncoder(w).Encode(set)
}

// authorize simulates the user approving at the provider and returns the
// callback URL the browser would be sent to.
func (p *fakeProvider) authorize(authURL string) (state, code string) {
	u, err := url.Parse(authURL)
	if err != nil {
		p.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("tenant") != "t1" || q.Get("response_type") != "code" || q.Get("client_id") != clientID ||
		q.Get("redirect_uri") != redirectURL || q.Get("code_challenge_method") != "S256" || !strings.Contains(q.Get("scope"), "openid") {
		p.t.Fatalf("bad authorization request: %s", authURL)
	}
	code = "code-" + q.Get("state")[:8]
	p.mu.Lock()
	p.codes[code] = codeGrant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	p.mu.Unlock()
	return q.Get("state"), code
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenRequests++
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	var id, secret string
	switch p.authMethod {
	case AuthClientSecretBasic:
		u, pw, ok := r.BasicAuth()
		if !ok || r.PostForm.Get("client_secret") != "" {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		id, _ = url.QueryUnescape(u)
		secret, _ = url.QueryUnescape(pw)
	case AuthClientSecretPost:
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != clientID || secret != clientSecret {
		http.Error(w, `{"error":"invalid_client"}`, 401)
		return
	}
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != redirectURL ||
		jose_b64(sum[:]) != g.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, 400)
		return
	}
	now := p.clk.Now()
	claims := map[string]any{
		"iss":                p.issuer(),
		"sub":                "user-123",
		"aud":                clientID,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"nonce":              g.nonce,
		"email":              "Alice@Example.com",
		"email_verified":     true,
		"name":               "Alice",
		"preferred_username": "alice",
		"groups":             []string{"citadel-admins", "devs"},
	}
	if p.mutate != nil {
		p.mutate(claims)
	}
	var idt string
	if p.forge != nil {
		idt = p.forge(claims)
	} else {
		var err error
		idt, err = jose.SignJWT(r.Context(), p.signer, claims)
		if err != nil {
			p.t.Error(err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id_token": idt, "access_token": "at-xyz", "token_type": "Bearer"})
}

func (p *fakeProvider) userinfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer at-xyz" {
		http.Error(w, "unauthorized", 401)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(p.userinfo)
}

func jose_b64(b []byte) string { return b64.EncodeToString(b) }

type harness struct {
	rp  *RelyingParty
	p   *fakeProvider
	clk *clock
}

func newHarness(t *testing.T, mod func(*ProviderConfig)) *harness {
	clk := &clock{t: time.Now()}
	p := newFakeProvider(t, clk)
	pc := ProviderConfig{
		ID: "okta", Name: "Okta", Issuer: p.issuer(), ClientID: clientID, ClientSecret: clientSecret,
		RedirectURL: redirectURL,
	}
	if mod != nil {
		mod(&pc)
	}
	rp, err := New(Config{
		Providers:         []ProviderConfig{pc},
		CookieKeys:        [][]byte{[]byte("0123456789abcdef0123456789abcdef")},
		AllowInsecureHTTP: true,
		InsecureCookies:   true,
		Now:               clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{rp: rp, p: p, clk: clk}
}

// login runs Start, the simulated provider approval, and builds the callback
// request. edit may tamper with the callback query.
func (h *harness) login(t *testing.T, returnTo string) (*http.Request, *http.Cookie) {
	t.Helper()
	authURL, cookie, err := h.rp.Start(context.Background(), "okta", returnTo)
	if err != nil {
		t.Fatal(err)
	}
	state, code := h.p.authorize(authURL)
	req := httptest.NewRequest("GET", redirectURL+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	req.AddCookie(cookie)
	return req, cookie
}

func TestLoginHappyPath(t *testing.T) {
	h := newHarness(t, func(pc *ProviderConfig) {
		pc.AllowedEmailDomains = []string{"example.com"}
		pc.UseUserInfo = true
	})
	h.p.userinfo = map[string]any{"sub": "user-123", "department": "eng", "email": "evil@other.com", "iss": "x"}
	authURL, cookie, err := h.rp.Start(context.Background(), "okta", "/secrets/app?env=prod")
	if err != nil {
		t.Fatal(err)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge != 600 {
		t.Fatalf("cookie attributes: %+v", cookie)
	}
	if strings.Contains(cookie.Value, "/secrets") {
		t.Fatal("cookie is not encrypted")
	}
	state, code := h.p.authorize(authURL)
	req := httptest.NewRequest("GET", redirectURL+"?code="+code+"&state="+state, nil)
	req.AddCookie(cookie)
	id, err := h.rp.Callback(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "okta" || id.Subject != "user-123" || id.Email != "Alice@Example.com" || !id.EmailVerified ||
		id.Username != "alice" || id.Name != "Alice" || id.ReturnTo != "/secrets/app?env=prod" ||
		len(id.Groups) != 2 || id.Groups[0] != "citadel-admins" {
		t.Fatalf("identity: %+v", id)
	}
	if id.RawClaims["department"] != "eng" || id.RawClaims["email"] != "Alice@Example.com" {
		t.Fatalf("userinfo merge: %v", id.RawClaims)
	}
	if c := h.rp.ClearCookie(); c.MaxAge >= 0 || c.Name != cookie.Name {
		t.Fatalf("clear cookie %+v", c)
	}
	m := RoleMapping{Rules: []RoleRule{{Group: "devs", Account: "acme", Role: RoleEditor}, {Group: "citadel-admins", Account: "acme", Role: RoleAdmin}, {Group: "ops", Account: "beta", Role: RoleAdmin}}, DefaultAccount: "sandbox", DefaultRole: RoleViewer}
	ms, err := m.Resolve(id.Groups)
	if err != nil || len(ms) != 2 || ms[0] != (Membership{"acme", RoleAdmin}) || ms[1] != (Membership{"sandbox", RoleViewer}) {
		t.Fatalf("memberships %v %v", ms, err)
	}
}

func TestClientSecretPost(t *testing.T) {
	h := newHarness(t, func(pc *ProviderConfig) { pc.TokenEndpointAuth = AuthClientSecretPost })
	h.p.authMethod = AuthClientSecretPost
	req, _ := h.login(t, "")
	id, err := h.rp.Callback(context.Background(), req)
	if err != nil || id.ReturnTo != "/" {
		t.Fatalf("%v %+v", err, id)
	}
}

func TestStateFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("missing cookie", func(t *testing.T) {
		h := newHarness(t, nil)
		req, _ := h.login(t, "/")
		req.Header.Del("Cookie")
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrStateMissing) {
			t.Fatal(err)
		}
	})
	t.Run("bad state", func(t *testing.T) {
		h := newHarness(t, nil)
		req, _ := h.login(t, "/")
		q := req.URL.Query()
		q.Set("state", "attacker-state")
		req.URL.RawQuery = q.Encode()
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrStateInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("other browser's cookie", func(t *testing.T) {
		h := newHarness(t, nil)
		req, _ := h.login(t, "/")
		_, otherCookie, _ := h.rp.Start(ctx, "okta", "/")
		req.Header.Del("Cookie")
		req.AddCookie(otherCookie)
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrStateInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("tampered cookie", func(t *testing.T) {
		h := newHarness(t, nil)
		req, cookie := h.login(t, "/")
		v := []byte(cookie.Value)
		v[10] ^= 1
		req.Header.Del("Cookie")
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: string(v)})
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrStateInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("cookie under another key", func(t *testing.T) {
		h := newHarness(t, nil)
		req, _ := h.login(t, "/")
		other, _ := New(Config{CookieKeys: [][]byte{[]byte("ffffffffffffffffffffffffffffffff")}, InsecureCookies: true})
		st, _ := h.rp.sealer.open(req.Cookies()[0].Value)
		forged, _ := other.sealer.seal(st)
		req.Header.Del("Cookie")
		req.AddCookie(&http.Cookie{Name: h.rp.cfg.CookieName, Value: forged})
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrStateInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("replayed state", func(t *testing.T) {
		h := newHarness(t, nil)
		req, _ := h.login(t, "/")
		if _, err := h.rp.Callback(ctx, req); err != nil {
			t.Fatal(err)
		}
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrStateReplayed) {
			t.Fatalf("replay: %v", err)
		}
	})
	t.Run("expired state", func(t *testing.T) {
		h := newHarness(t, nil)
		req, _ := h.login(t, "/")
		h.clk.Add(11 * time.Minute)
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrStateInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("provider error", func(t *testing.T) {
		h := newHarness(t, nil)
		req, _ := h.login(t, "/")
		q := req.URL.Query()
		q.Del("code")
		q.Set("error", "access_denied")
		req.URL.RawQuery = q.Encode()
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrProvider) {
			t.Fatal(err)
		}
	})
	t.Run("iss mix-up", func(t *testing.T) {
		h := newHarness(t, nil)
		req, _ := h.login(t, "/")
		req.URL.RawQuery += "&iss=" + url.QueryEscape("https://evil.example")
		if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrProvider) {
			t.Fatal(err)
		}
	})
}

func TestIDTokenFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c map[string]any)
		forge  func(h *harness) func(c map[string]any) string
	}{
		{name: "wrong nonce", mutate: func(c map[string]any) { c["nonce"] = "other" }},
		{name: "missing nonce", mutate: func(c map[string]any) { delete(c, "nonce") }},
		{name: "wrong aud", mutate: func(c map[string]any) { c["aud"] = "someone-else" }},
		{name: "multi aud without azp", mutate: func(c map[string]any) { c["aud"] = []string{clientID, "other"} }},
		{name: "azp mismatch", mutate: func(c map[string]any) { c["azp"] = "other" }},
		{name: "wrong iss", mutate: func(c map[string]any) { c["iss"] = "https://evil.example" }},
		{name: "expired", mutate: func(c map[string]any) {
			c["exp"] = time.Now().Add(-2 * time.Minute).Unix()
		}},
		{name: "iat in future", mutate: func(c map[string]any) { c["iat"] = time.Now().Add(10 * time.Minute).Unix() }},
		{name: "no sub", mutate: func(c map[string]any) { delete(c, "sub") }},
		{name: "at_hash mismatch", mutate: func(c map[string]any) { c["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" }},
		{name: "alg none", forge: func(h *harness) func(map[string]any) string {
			return func(c map[string]any) string {
				hdr := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
				body, _ := json.Marshal(c)
				return hdr + "." + b64.EncodeToString(body) + "."
			}
		}},
		{name: "HS256 with RSA public key as secret", forge: func(h *harness) func(map[string]any) string {
			return func(c map[string]any) string {
				der, _ := x509.MarshalPKIXPublicKey(&h.p.rsaKey.PublicKey)
				secret := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
				hdr := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"rsa-1","typ":"JWT"}`))
				body, _ := json.Marshal(c)
				input := hdr + "." + b64.EncodeToString(body)
				m := hmac.New(sha256.New, secret)
				m.Write([]byte(input))
				return input + "." + b64.EncodeToString(m.Sum(nil))
			}
		}},
		{name: "signed by unknown key", forge: func(h *harness) func(map[string]any) string {
			return func(c map[string]any) string {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				s, _ := jose.NewLocalSigner(k, jose.ES256, "ec-1") // same kid, different key
				tok, _ := jose.SignJWT(context.Background(), s, c)
				return tok
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.p.mutate = tc.mutate
			if tc.forge != nil {
				h.p.forge = tc.forge(h)
			}
			req, _ := h.login(t, "/")
			if _, err := h.rp.Callback(context.Background(), req); !errors.Is(err, ErrIDToken) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	h := newHarness(t, nil)
	h.p.issuerInDoc = "https://evil.example"
	if _, _, err := h.rp.Start(context.Background(), "okta", "/"); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("got %v", err)
	}
	h2 := newHarness(t, nil)
	h2.p.issuerInDoc = h2.p.issuer() + "/"
	if _, _, err := h2.rp.Start(context.Background(), "okta", "/"); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("trailing slash: got %v", err)
	}
}

func TestUnknownProvider(t *testing.T) {
	h := newHarness(t, nil)
	if _, _, err := h.rp.Start(context.Background(), "nope", "/"); !errors.Is(err, ErrUnknownProvider) {
		t.Fatal(err)
	}
}

func TestReturnToValidation(t *testing.T) {
	good := []string{"/", "/secrets", "/secrets/app?env=prod#x", "/a/b%20c"}
	bad := []string{
		"//evil.com", "/\\evil.com", "\\\\evil.com", "https://evil.com", "http:evil.com", "javascript:alert(1)",
		"evil.com", "/%2F%2Fevil.com", "/%5Cevil.com/", "/ok\\..\\x", "/\t/evil.com", "/\n", " /x",
		"///evil.com", "/" + strings.Repeat("a", 3000),
	}
	for _, s := range good {
		if _, err := ValidateReturnTo(s); err != nil {
			t.Errorf("rejected %q", s)
		}
	}
	h := newHarness(t, nil)
	for _, s := range bad {
		if _, err := ValidateReturnTo(s); err == nil {
			t.Errorf("accepted %q", s)
		}
		if _, _, err := h.rp.Start(context.Background(), "okta", s); !errors.Is(err, ErrInvalidReturnTo) {
			t.Errorf("Start accepted %q: %v", s, err)
		}
	}
}

func TestEmailDomainAllowlist(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, func(pc *ProviderConfig) { pc.AllowedEmailDomains = []string{"corp.example"} })
	req, _ := h.login(t, "/")
	if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrEmailDomain) {
		t.Fatalf("disallowed domain: %v", err)
	}
	// Suffix tricks.
	h = newHarness(t, func(pc *ProviderConfig) { pc.AllowedEmailDomains = []string{"example.com"} })
	h.p.mutate = func(c map[string]any) { c["email"] = "alice@evilexample.com" }
	req, _ = h.login(t, "/")
	if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrEmailDomain) {
		t.Fatalf("suffix: %v", err)
	}
	// Unverified email.
	h = newHarness(t, func(pc *ProviderConfig) { pc.AllowedEmailDomains = []string{"example.com"} })
	h.p.mutate = func(c map[string]any) { c["email_verified"] = false }
	req, _ = h.login(t, "/")
	if _, err := h.rp.Callback(ctx, req); !errors.Is(err, ErrEmailDomain) {
		t.Fatalf("unverified: %v", err)
	}
	// ...accepted when the provider is trusted for unverified emails.
	h = newHarness(t, func(pc *ProviderConfig) {
		pc.AllowedEmailDomains = []string{"EXAMPLE.com"}
		pc.AllowUnverifiedEmail = true
	})
	h.p.mutate = func(c map[string]any) { delete(c, "email_verified") }
	req, _ = h.login(t, "/")
	if _, err := h.rp.Callback(ctx, req); err != nil {
		t.Fatal(err)
	}
}

func TestNestedGroupsClaim(t *testing.T) {
	h := newHarness(t, func(pc *ProviderConfig) { pc.GroupsClaim = "realm_access.roles" })
	h.p.mutate = func(c map[string]any) { c["realm_access"] = map[string]any{"roles": []string{"r1"}} }
	req, _ := h.login(t, "/")
	id, err := h.rp.Callback(context.Background(), req)
	if err != nil || len(id.Groups) != 1 || id.Groups[0] != "r1" {
		t.Fatalf("%v %v", err, id.Groups)
	}
}

func TestConfigValidation(t *testing.T) {
	base := ProviderConfig{ID: "x", Issuer: "https://idp.example", ClientID: "c", ClientSecret: "s", RedirectURL: "https://citadel/cb"}
	key := [][]byte{make([]byte, 32)}
	if _, err := New(Config{Providers: []ProviderConfig{base}, CookieKeys: [][]byte{make([]byte, 16)}}); err == nil {
		t.Fatal("short cookie key accepted")
	}
	http := base
	http.Issuer = "http://idp.example"
	if _, err := New(Config{Providers: []ProviderConfig{http}, CookieKeys: key}); err == nil {
		t.Fatal("http issuer accepted")
	}
	if _, err := New(Config{Providers: []ProviderConfig{base, base}, CookieKeys: key}); err == nil {
		t.Fatal("duplicate provider accepted")
	}
	rp, err := New(Config{Providers: []ProviderConfig{base}, CookieKeys: key})
	if err != nil {
		t.Fatal(err)
	}
	if c := rp.ClearCookie(); !c.Secure || !strings.HasPrefix(c.Name, "__Host-") {
		t.Fatalf("production cookie: %+v", c)
	}
	if err := (RoleMapping{Rules: []RoleRule{{Group: "g", Account: "a", Role: "root"}}}).Validate(); err == nil {
		t.Fatal("bad role accepted")
	}
	if _, err := (RoleMapping{Rules: []RoleRule{{Group: "g", Account: "a", Role: RoleViewer}}}).Resolve([]string{"x"}); !errors.Is(err, ErrNoMembership) {
		t.Fatal(err)
	}
}

func TestCookieKeyRotation(t *testing.T) {
	oldKey := []byte("old-old-old-old-old-old-old-old-")
	newKey := []byte("new-new-new-new-new-new-new-new-")
	a, _ := newSealer([][]byte{oldKey}, "n")
	b, _ := newSealer([][]byte{newKey, oldKey}, "n")
	v, _ := a.seal(flowState{State: "s"})
	if st, err := b.open(v); err != nil || st.State != "s" {
		t.Fatalf("rotation: %v", err)
	}
	c, _ := newSealer([][]byte{oldKey}, "other-name")
	if _, err := c.open(v); err == nil {
		t.Fatal("cookie accepted under a different name binding")
	}
}
