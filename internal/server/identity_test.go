package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/sigv4"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
	"github.com/worlddrknss/citadel/internal/workloadid"
)

const testBootstrapToken = "test-bootstrap-token-0001"

// ---- bootstrap token -------------------------------------------------------

func TestBootstrapTokenRequiredAndConsumed(t *testing.T) {
	s, st, h := newBootstrapEnv(t)
	body := map[string]string{"organizationName": "Acme", "accountName": "Production", "username": "founder", "password": "a-long-password-1"}
	rec := doReq(t, h, "POST", "/v1/bootstrap", body, nil)
	wantStatus(t, rec, http.StatusUnauthorized)
	if decode(t, rec)["error"] != "invalid_bootstrap_token" {
		t.Fatalf("missing token: %s", rec.Body.String())
	}
	body["bootstrapToken"] = "wrong-token-wrong-token"
	wantStatus(t, doReq(t, h, "POST", "/v1/bootstrap", body, nil), http.StatusUnauthorized)
	if n, _ := st.CountUIUsers(context.Background()); n != 0 {
		t.Fatal("a user was created without the token")
	}
	if !auditedIn(t, st, "citadel.Bootstrap", "denied", "anonymous", "") {
		t.Fatal("rejected bootstrap not audited")
	}
	body["bootstrapToken"] = testBootstrapToken
	wantStatus(t, doReq(t, h, "POST", "/v1/bootstrap", body, nil), http.StatusCreated)
	if s.checkBootstrapToken(testBootstrapToken) {
		t.Fatal("bootstrap token still valid after setup")
	}
}

func TestBootstrapTokenGeneratedWhenUnset(t *testing.T) {
	st := &memory.Store{DefaultKey: sampleKey(1)}
	s := &Server{store: st}
	tok := s.initBootstrapToken()
	if len(tok) != 32 || s.initBootstrapToken() != tok {
		t.Fatalf("generated token %q unstable or wrong length", tok)
	}
	if s.checkBootstrapToken("") || s.checkBootstrapToken(tok+"x") || !s.checkBootstrapToken(tok) {
		t.Fatal("token comparison wrong")
	}
	s.consumeBootstrapToken()
	if s.initBootstrapToken() != "" || s.checkBootstrapToken(tok) {
		t.Fatal("consumed token must not come back")
	}
}

func TestOrgSettingsHaveNoSelfApproval(t *testing.T) {
	e := newAuthEnv(t)
	root := e.session("root", e.acctA)
	if _, ok := decode(t, e.do("GET", "/v1/admin/settings", nil, root))["allowSelfApproval"]; ok {
		t.Fatal("allowSelfApproval still exposed")
	}
	in := map[string]any{"approvalEnvironments": []string{}, "approvalMinApprovers": 1, "allowSelfApproval": true, "sessionIdleMinutes": 15, "sessionMaxHours": 8}
	wantStatus(t, e.do("POST", "/v1/admin/settings", in, root), http.StatusBadRequest)
}

// ---- fake OIDC provider ----------------------------------------------------

type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	signer *jose.LocalSigner
	mu     sync.Mutex
	codes  map[string]map[string]any // code -> claims (with nonce)
}

func newFakeIdP(t *testing.T) *fakeIdP {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sg, _ := jose.NewLocalSigner(k, jose.ES256, "idp-1")
	p := &fakeIdP{t: t, signer: sg, codes: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize", "token_endpoint": p.srv.URL + "/token",
			"jwks_uri": p.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"ES256"},
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JWKSet{Keys: []jose.JWK{jose.NewJWK(p.signer)}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if id, secret, ok := r.BasicAuth(); !ok || id != "citadel" || secret != "s3cret" {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		p.mu.Lock()
		claims, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		tok, err := jose.SignJWT(r.Context(), p.signer, claims)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": tok, "access_token": "at", "token_type": "Bearer"})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// authorize simulates the user signing in at the IdP and returns the
// callback path (with state and code) the browser is sent to.
func (p *fakeIdP) authorize(authURL string, claims map[string]any) string {
	u, err := url.Parse(authURL)
	if err != nil {
		p.t.Fatal(err)
	}
	q := u.Query()
	now := time.Now().Unix()
	c := map[string]any{"iss": p.srv.URL, "aud": "citadel", "iat": now, "exp": now + 300, "nonce": q.Get("nonce")}
	for k, v := range claims {
		c[k] = v
	}
	code := "code-" + q.Get("state")[:10]
	p.mu.Lock()
	p.codes[code] = c
	p.mu.Unlock()
	redirect, _ := url.Parse(q.Get("redirect_uri"))
	return redirect.Path + "?" + url.Values{"state": {q.Get("state")}, "code": {code}}.Encode()
}

type identityEnv struct {
	*authEnv
	idp *fakeIdP
}

func newIdentityEnv(t *testing.T) *identityEnv {
	e := newAuthEnv(t)
	e.s.cfg.PublicURL = "https://citadel.test"
	e.s.cfg.WrappingKey = bytes.Repeat([]byte{7}, 32)
	e.s.identity().allowInsecureHTTP = true
	return &identityEnv{authEnv: e, idp: newFakeIdP(t)}
}

func (e *identityEnv) createProvider(cookie *http.Cookie, mut func(map[string]any)) (*httptest.ResponseRecorder, string) {
	in := map[string]any{
		"name": "Acme IdP", "issuer": e.idp.srv.URL, "clientId": "citadel", "clientSecret": "s3cret",
		"scopes": []string{"openid", "email", "profile"}, "groupClaim": "groups",
		"roleMappings": []map[string]string{{"group": "eng", "accountId": e.acctA, "role": "editor"}, {"group": "ops", "accountId": "*", "role": "viewer"}},
		"defaultRole":  "none", "enabled": true, "allowedEmailDomains": []string{"example.com"},
	}
	if mut != nil {
		mut(in)
	}
	rec := e.do("POST", "/v1/admin/sso/providers", in, cookie)
	if rec.Code != http.StatusCreated {
		return rec, ""
	}
	return rec, decode(e.t, rec)["id"].(string)
}

// login runs start -> IdP -> callback and returns the callback response.
func (e *identityEnv) login(id string, claims map[string]any) *httptest.ResponseRecorder {
	e.t.Helper()
	start := e.do("GET", "/v1/auth/oidc/"+id+"/start?returnTo=/app/secrets", nil, nil)
	wantStatus(e.t, start, http.StatusFound)
	var stateCookie *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == "citadel-oidc" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		e.t.Fatalf("no state cookie; location %s", start.Header().Get("Location"))
	}
	cb := e.idp.authorize(start.Header().Get("Location"), claims)
	rec := e.do("GET", cb, nil, stateCookie)
	rec.Header().Set("X-Test-Callback", cb)
	return rec
}

func ssoErr(rec *httptest.ResponseRecorder) string {
	loc, _ := url.Parse(rec.Header().Get("Location"))
	return loc.Query().Get("sso_error")
}

func TestSSOEndToEnd(t *testing.T) {
	e := newIdentityEnv(t)
	root := e.session("root", e.acctA)
	rec, id := e.createProvider(root, nil)
	wantStatus(t, rec, http.StatusCreated)
	if got := decode(t, rec)["redirectUri"]; got != "https://citadel.test/v1/auth/oidc/"+id+"/callback" {
		t.Fatalf("redirectUri = %v", got)
	}
	provs := decode(t, e.do("GET", "/v1/auth/providers", nil, nil))["providers"].([]any)
	if len(provs) != 1 || provs[0].(map[string]any)["id"] != id || provs[0].(map[string]any)["type"] != "oidc" {
		t.Fatalf("providers = %v", provs)
	}

	claims := map[string]any{"sub": "idp-user-1", "email": "dana@example.com", "email_verified": true, "preferred_username": "dana", "name": "Dana", "groups": []string{"eng", "ops"}}
	rec = e.login(id, claims)
	wantStatus(t, rec, http.StatusFound)
	if loc := rec.Header().Get("Location"); loc != "/app/secrets" {
		t.Fatalf("redirect = %s", loc)
	}
	sess := sessionCookie(rec)
	if sess == nil {
		t.Fatal("no session cookie")
	}
	me := decode(t, e.do("GET", "/v1/me", nil, sess))
	if me["username"] != "dana" || me["accountId"] != e.acctA || me["role"] != "editor" || me["platformAdmin"] != false {
		t.Fatalf("me = %v", me)
	}
	if accts := me["accounts"].([]any); len(accts) != 2 {
		t.Fatalf("accounts = %v (want A editor + B viewer)", accts)
	}
	u, _ := e.st.GetUIUser(context.Background(), "dana")
	if !strings.HasPrefix(u.PasswordHash, "$pbkdf2-sha256$") || u.PlatformAdmin {
		t.Fatalf("JIT user = %+v", u)
	}
	if !auditedIn(t, e.st, "citadel.LoginSSO", "ok", "dana", e.acctA) {
		t.Fatal("SSO login not audited")
	}
	sessions, _ := e.st.ListConsoleSessions(context.Background(), "dana")
	if len(sessions) != 1 || sessions[0].Method != store.SessionMethodSSO {
		t.Fatalf("sessions = %+v", sessions)
	}

	// Replaying the callback (same state and cookie) is refused.
	cb := rec.Header().Get("X-Test-Callback")
	start := e.do("GET", "/v1/auth/oidc/"+id+"/start", nil, nil)
	_ = start
	replay := e.do("GET", cb, nil, nil)
	if ssoErr(replay) != ssoErrStateMismatch {
		t.Fatalf("replay without cookie: %s", replay.Header().Get("Location"))
	}

	// The same subject maps to the same user even with a new email; group
	// changes resync memberships.
	claims["email"] = "dana.new@example.com"
	claims["groups"] = []string{"ops"}
	rec = e.login(id, claims)
	wantStatus(t, rec, http.StatusFound)
	me = decode(t, e.do("GET", "/v1/me", nil, sessionCookie(rec)))
	if me["username"] != "dana" || me["role"] != "viewer" {
		t.Fatalf("relogin me = %v", me)
	}

	// An IdP identity claiming an existing local username (or email) never
	// takes over that user.
	rec = e.login(id, map[string]any{"sub": "other", "email": "bob@example.com", "email_verified": true, "preferred_username": "bob", "groups": []string{"eng"}})
	wantStatus(t, rec, http.StatusFound)
	me = decode(t, e.do("GET", "/v1/me", nil, sessionCookie(rec)))
	if me["username"] == "bob" || !strings.HasPrefix(me["username"].(string), "bob-") {
		t.Fatalf("collision user = %v", me["username"])
	}
	bob, _ := e.st.GetUIUser(context.Background(), "bob")
	if bob.PasswordHash != testPasswordHash(t) {
		t.Fatal("local user bob was modified")
	}
}

func TestSSODenials(t *testing.T) {
	e := newIdentityEnv(t)
	root := e.session("root", e.acctA)
	_, id := e.createProvider(root, nil)

	// No mapped group and no default role.
	rec := e.login(id, map[string]any{"sub": "u-norole", "email": "x@example.com", "email_verified": true, "groups": []string{"sales"}})
	if ssoErr(rec) != ssoErrNoRole || sessionCookie(rec) != nil {
		t.Fatalf("no role: %s", rec.Header().Get("Location"))
	}
	// Email domain not allowed.
	rec = e.login(id, map[string]any{"sub": "u-dom", "email": "x@evil.com", "email_verified": true, "groups": []string{"eng"}})
	if ssoErr(rec) != ssoErrAccessDenied {
		t.Fatalf("domain: %s", rec.Header().Get("Location"))
	}
	if _, err := e.st.GetExternalIdentity(context.Background(), id, "u-dom"); err == nil {
		t.Fatal("denied identity was provisioned")
	}
	if !auditedIn(t, e.st, "citadel.LoginSSO", "denied", "", e.acctA) {
		t.Fatal("denied SSO login not audited")
	}
	// State replay: reuse a consumed state with its cookie.
	start := e.do("GET", "/v1/auth/oidc/"+id+"/start", nil, nil)
	var sc *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == "citadel-oidc" {
			sc = c
		}
	}
	cb := e.idp.authorize(start.Header().Get("Location"), map[string]any{"sub": "u-r", "email": "r@example.com", "email_verified": true, "groups": []string{"eng"}})
	wantStatus(t, e.do("GET", cb, nil, sc), http.StatusFound)
	if again := e.do("GET", cb, nil, sc); ssoErr(again) != ssoErrStateMismatch {
		t.Fatalf("replay: %s", again.Header().Get("Location"))
	}
	// Tampered state.
	if bad := e.do("GET", "/v1/auth/oidc/"+id+"/callback?state=forged&code=x", nil, sc); ssoErr(bad) != ssoErrStateMismatch {
		t.Fatalf("forged state: %s", bad.Header().Get("Location"))
	}
	// Disabled provider: hidden from the sign-in screen and refused.
	upd := map[string]any{"id": id, "name": "Acme IdP", "issuer": e.idp.srv.URL, "clientId": "citadel", "groupClaim": "groups",
		"roleMappings": []map[string]string{{"group": "eng", "accountId": e.acctA, "role": "editor"}}, "defaultRole": "none", "enabled": false}
	wantStatus(t, e.do("POST", "/v1/admin/sso/providers/update", upd, root), http.StatusOK)
	if provs := decode(t, e.do("GET", "/v1/auth/providers", nil, nil))["providers"].([]any); len(provs) != 0 {
		t.Fatalf("disabled provider listed: %v", provs)
	}
	if rec := e.do("GET", "/v1/auth/oidc/"+id+"/start", nil, nil); ssoErr(rec) != ssoErrProvider {
		t.Fatalf("disabled start: %s", rec.Header().Get("Location"))
	}
	if rec := e.do("GET", "/v1/auth/oidc/nope/start", nil, nil); ssoErr(rec) != ssoErrProvider {
		t.Fatalf("unknown provider: %s", rec.Header().Get("Location"))
	}
	// Open redirect attempts fall back to /app/.
	upd["enabled"] = true
	wantStatus(t, e.do("POST", "/v1/admin/sso/providers/update", upd, root), http.StatusOK)
	start = e.do("GET", "/v1/auth/oidc/"+id+"/start?returnTo=//evil.com/x", nil, nil)
	for _, c := range start.Result().Cookies() {
		if c.Name == "citadel-oidc" {
			sc = c
		}
	}
	cb = e.idp.authorize(start.Header().Get("Location"), map[string]any{"sub": "u-r2", "email": "r2@example.com", "email_verified": true, "groups": []string{"eng"}})
	if rec := e.do("GET", cb, nil, sc); rec.Header().Get("Location") != "/app/" {
		t.Fatalf("returnTo not sanitized: %s", rec.Header().Get("Location"))
	}
}

func TestSSOAdmin(t *testing.T) {
	e := newIdentityEnv(t)
	root := e.session("root", e.acctA)
	alice := e.session("alice", e.acctA) // account admin of A
	bob := e.session("bob", e.acctA)     // editor

	// Org-wide providers ("*" mapping) need a platform admin.
	rec, _ := e.createProvider(alice, nil)
	wantStatus(t, rec, http.StatusForbidden)
	rec, _ = e.createProvider(bob, nil)
	wantStatus(t, rec, http.StatusForbidden)
	_, orgID := e.createProvider(root, nil)
	own := func(in map[string]any) {
		in["name"] = "Alpha IdP"
		in["roleMappings"] = []map[string]string{{"group": "eng", "accountId": e.acctA, "role": "admin"}}
		in["defaultRole"] = "viewer"
	}
	rec, aliceID := e.createProvider(alice, own)
	wantStatus(t, rec, http.StatusCreated)

	// Validation.
	for _, mut := range []func(map[string]any){
		func(in map[string]any) { own(in); in["issuer"] = "ftp://x" },
		func(in map[string]any) { own(in); delete(in, "clientSecret") },
		func(in map[string]any) { own(in); in["defaultRole"] = "owner" },
		func(in map[string]any) {
			own(in)
			in["roleMappings"] = []map[string]string{{"group": "g", "accountId": "999999999999", "role": "viewer"}}
		},
		func(in map[string]any) { own(in); in["allowedEmailDomains"] = []string{"not a domain"} },
	} {
		rec, _ := e.createProvider(alice, mut)
		wantStatus(t, rec, http.StatusBadRequest)
	}

	// Listing: secrets never returned; account admins see their account's.
	rec = e.do("GET", "/v1/admin/sso/providers", nil, root)
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "s3cret") || strings.Contains(rec.Body.String(), "clientSecret\"") {
		t.Fatalf("secret leaked: %s", rec.Body.String())
	}
	if n := len(decode(t, rec)["providers"].([]any)); n != 2 {
		t.Fatalf("root sees %d providers", n)
	}
	carol := e.session("carol", e.acctB)
	wantStatus(t, e.do("GET", "/v1/admin/sso/providers", nil, carol), http.StatusForbidden)
	ps := decode(t, e.do("GET", "/v1/admin/sso/providers", nil, alice))["providers"].([]any)
	if len(ps) != 2 { // both live in account A; the org-wide one is read-only to alice
		t.Fatalf("alice sees %v", ps)
	}
	p0 := ps[0].(map[string]any)
	if p0["clientSecretSet"] != true {
		t.Fatalf("clientSecretSet = %v", p0)
	}

	// Alice cannot change or delete the org-wide provider, nor widen hers.
	wantStatus(t, e.do("DELETE", "/v1/admin/sso/providers?id="+orgID, nil, alice), http.StatusForbidden)
	widen := map[string]any{"id": aliceID, "name": "Alpha", "issuer": e.idp.srv.URL, "clientId": "citadel", "defaultRole": "none", "enabled": true,
		"roleMappings": []map[string]string{{"group": "eng", "accountId": e.acctB, "role": "admin"}}}
	wantStatus(t, e.do("POST", "/v1/admin/sso/providers/update", widen, alice), http.StatusForbidden)
	// Update without clientSecret keeps it (login still works).
	widen["roleMappings"] = []map[string]string{{"group": "eng", "accountId": e.acctA, "role": "editor"}}
	wantStatus(t, e.do("POST", "/v1/admin/sso/providers/update", widen, alice), http.StatusOK)
	if rec := e.login(aliceID, map[string]any{"sub": "s1", "groups": []string{"eng"}}); sessionCookie(rec) == nil {
		t.Fatalf("login after keep-secret update: %s", rec.Header().Get("Location"))
	}
	if !e.audited("citadel.UpdateSSOProvider", "ok") || !e.audited("citadel.CreateSSOProvider", "ok") {
		t.Fatal("provider changes not audited")
	}

	// Test endpoint fetches discovery.
	got := decode(t, e.do("POST", "/v1/admin/sso/providers/test", map[string]string{"id": aliceID}, alice))
	if got["ok"] != true || got["authorizationEndpoint"] != e.idp.srv.URL+"/authorize" {
		t.Fatalf("test = %v", got)
	}

	// Cross-account: an admin of B cannot see A's providers.
	wantStatus(t, e.do("DELETE", "/v1/admin/sso/providers?id="+aliceID, nil, e.session("root", e.acctB)), http.StatusOK)
	if !e.audited("citadel.DeleteSSOProvider", "ok") {
		t.Fatal("delete not audited")
	}
	wantStatus(t, e.do("DELETE", "/v1/admin/sso/providers?id="+aliceID, nil, alice), http.StatusNotFound)
}

func TestSSORequiresPublicURL(t *testing.T) {
	e := newIdentityEnv(t)
	e.s.cfg.PublicURL = ""
	rec, _ := e.createProvider(e.session("root", e.acctA), nil)
	wantStatus(t, rec, http.StatusConflict)
}

// ---- workload identity -----------------------------------------------------

// akStore adds access keys to the memory store, which has none.
type akStore struct {
	*memory.Store
	keys map[string][3]string // id -> owner, account, secret
}

func (a *akStore) GetAccessKeyByID(_ context.Context, id string) (string, string, string, string, error) {
	k, ok := a.keys[id]
	if !ok {
		return "", "", "", "", store.ErrAccessKeyNotFound
	}
	return k[0], k[1], k[2], "active", nil
}

func (a *akStore) TouchAccessKeyLastUsed(context.Context, string) error { return nil }

const (
	bobKey   = "AKIABOBKEY0000000001"
	bobSec   = "bob-secret-0123456789abcdefghijklmnopq"
	carolKey = "AKIACAROLKEY00000001"
	carolSec = "carol-secret-0123456789abcdefghijklmno"
)

func newWorkloadEnv(t *testing.T) *identityEnv {
	e := newIdentityEnv(t)
	e.s.store = &akStore{Store: e.st, keys: map[string][3]string{
		bobKey: {"bob", e.acctA, bobSec}, carolKey: {"carol", e.acctB, carolSec},
	}}
	return e
}

func signV4(t *testing.T, req *http.Request, body []byte, key, secret string) {
	t.Helper()
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	sum := sha256.Sum256(body)
	ch := "host:" + req.Host + "\nx-amz-date:" + amzDate + "\n"
	canonical := strings.Join([]string{req.Method, req.URL.EscapedPath(), "", ch, "host;x-amz-date", hex.EncodeToString(sum[:])}, "\n")
	hc := sha256.Sum256([]byte(canonical))
	scope := date + "/us-east-1/citadel/aws4_request"
	sts := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(hc[:])}, "\n")
	sig := hex.EncodeToString(sigv4.HMACSHA256(sigv4.DeriveSigningKey(secret, date, "us-east-1", "citadel"), []byte(sts)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+key+"/"+scope+", SignedHeaders=host;x-amz-date, Signature="+sig)
}

func (e *identityEnv) token(body map[string]any, opts ...reqOpt) *httptest.ResponseRecorder {
	e.t.Helper()
	return doReq(e.t, e.h, "POST", "/v1/workload-identity/token", body, nil, append([]reqOpt{func(r *http.Request) { r.Header.Del(csrfHeader) }}, opts...)...)
}

// verifyToken checks tok against the JWKS served at /oidc/jwks.json.
func (e *identityEnv) verifyToken(tok, aud string) jose.Claims {
	e.t.Helper()
	rec := e.do("GET", "/oidc/jwks.json", nil, nil)
	wantStatus(e.t, rec, http.StatusOK)
	set, err := jose.ParseJWKSet(rec.Body.Bytes())
	if err != nil {
		e.t.Fatal(err)
	}
	j, err := jose.Verify(context.Background(), tok, set)
	if err != nil {
		e.t.Fatalf("verify: %v", err)
	}
	claims, err := jose.ParseClaims(j.Payload)
	if err != nil {
		e.t.Fatal(err)
	}
	v := jose.Validator{Issuer: "https://citadel.test/oidc", Audience: aud, Now: time.Now}
	if err := v.Validate(claims); err != nil {
		e.t.Fatalf("claims: %v", err)
	}
	return claims
}

func accessKeyClient(e *identityEnv, users ...string) map[string]any {
	return map[string]any{"name": "ci", "audiences": []string{"sts.amazonaws.com"}, "tokenTtlSeconds": 900,
		"subjectFormat": "user:{username}", "auth": map[string]any{"method": "access-key", "allowedUsers": users}}
}

func TestWorkloadIssuerAdmin(t *testing.T) {
	e := newWorkloadEnv(t)
	root := e.session("root", e.acctA)
	alice := e.session("alice", e.acctA)
	info := decode(t, e.do("GET", "/v1/workload-identity/issuer", nil, e.session("carol", e.acctB)))
	if info["issuer"] != "https://citadel.test/oidc" || info["signingKey"] != nil || info["tokenEndpoint"] != "https://citadel.test/v1/workload-identity/token" ||
		info["jwksUrl"] != "https://citadel.test/oidc/jwks.json" || info["rotationDays"] != 90.0 {
		t.Fatalf("issuer = %v", info)
	}
	set := map[string]any{"algorithm": "ES384", "rotationDays": 30}
	wantStatus(t, e.do("POST", "/v1/workload-identity/issuer/settings", set, alice), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/workload-identity/issuer/settings", map[string]any{"algorithm": "HS256", "rotationDays": 30}, root), http.StatusBadRequest)
	wantStatus(t, e.do("POST", "/v1/workload-identity/issuer/settings", map[string]any{"algorithm": "ES256", "rotationDays": 3}, root), http.StatusBadRequest)
	wantStatus(t, e.do("POST", "/v1/workload-identity/issuer/settings", set, root), http.StatusOK)
	wantStatus(t, e.do("POST", "/v1/workload-identity/issuer/rotate", nil, alice), http.StatusForbidden)
	rec := e.do("POST", "/v1/workload-identity/issuer/rotate", nil, root)
	wantStatus(t, rec, http.StatusOK)
	k := decode(t, rec)["signingKey"].(map[string]any)
	if k["algorithm"] != "ES384" || k["kmsKeyId"] == "" || k["kid"] == "" {
		t.Fatalf("signing key = %v", k)
	}
	if !e.audited("citadel.RotateWorkloadSigningKey", "ok") || !e.audited("citadel.UpdateWorkloadIssuerSettings", "ok") {
		// root's session account is A
		t.Fatal("issuer changes not audited")
	}
	// The KMS key backs the signer: ECC_NIST_P384 SIGN_VERIFY.
	key, err := e.st.ResolveByID(e.s.deploymentCtx(context.Background()), k["kmsKeyId"].(string))
	if err != nil || key.KeySpec != store.KeySpecECCP384 || key.KeyUsage != store.KeyUsageSignVerify {
		t.Fatalf("kms key = %+v, %v", key, err)
	}
	// Changing the algorithm rotates at once.
	rec = e.do("POST", "/v1/workload-identity/issuer/settings", map[string]any{"algorithm": "PS256", "rotationDays": 30}, root)
	info = decode(t, rec)
	if info["signingKey"].(map[string]any)["algorithm"] != "PS256" || len(info["previousKeys"].([]any)) != 1 {
		t.Fatalf("after algorithm change = %v", info)
	}
	disc := decode(t, e.do("GET", "/oidc/.well-known/openid-configuration", nil, nil))
	if disc["issuer"] != "https://citadel.test/oidc" || disc["jwks_uri"] != "https://citadel.test/oidc/jwks.json" {
		t.Fatalf("discovery = %v", disc)
	}
}

func TestWorkloadClientsCRUD(t *testing.T) {
	e := newWorkloadEnv(t)
	alice := e.session("alice", e.acctA)
	bob := e.session("bob", e.acctA)
	carol := e.session("carol", e.acctB)
	wantStatus(t, e.do("POST", "/v1/workload-identity/clients", accessKeyClient(e, "bob"), bob), http.StatusForbidden)
	for _, bad := range []map[string]any{
		accessKeyClient(e, "carol"),  // not a member of A
		accessKeyClient(e, "nobody"), // unknown user
		accessKeyClient(e),           // no users
		func() map[string]any { c := accessKeyClient(e, "bob"); c["subjectFormat"] = "x:{namespace}"; return c }(),
		func() map[string]any { c := accessKeyClient(e, "bob"); c["tokenTtlSeconds"] = 7200; return c }(),
		func() map[string]any { c := accessKeyClient(e, "bob"); c["name"] = "a:b"; return c }(),
		{"name": "k", "audiences": []string{"a"}, "tokenTtlSeconds": 600, "subjectFormat": "s", "auth": map[string]any{"method": "k8s-token-review", "apiServer": "https://k", "serviceAccounts": []string{"ns:sa"}, "reviewAudience": "citadel"}}, // no reviewer token configured
	} {
		wantStatus(t, e.do("POST", "/v1/workload-identity/clients", bad, alice), http.StatusBadRequest)
	}
	rec := e.do("POST", "/v1/workload-identity/clients", accessKeyClient(e, "bob"), alice)
	wantStatus(t, rec, http.StatusCreated)
	id := decode(t, rec)["clientId"].(string)
	list := decode(t, e.do("GET", "/v1/workload-identity/clients", nil, bob))["clients"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["clientId"] != id || list[0].(map[string]any)["auth"].(map[string]any)["allowedUsers"].([]any)[0] != "bob" {
		t.Fatalf("list = %v", list)
	}
	if l := decode(t, e.do("GET", "/v1/workload-identity/clients", nil, carol))["clients"].([]any); len(l) != 0 {
		t.Fatalf("account B sees A's clients: %v", l)
	}
	upd := accessKeyClient(e, "bob", "alice")
	upd["clientId"] = id
	wantStatus(t, e.do("POST", "/v1/workload-identity/clients/update", upd, e.session("root", e.acctB)), http.StatusNotFound)
	wantStatus(t, e.do("POST", "/v1/workload-identity/clients/update", upd, alice), http.StatusOK)
	wantStatus(t, e.do("DELETE", "/v1/workload-identity/clients?clientId="+id, nil, e.session("root", e.acctB)), http.StatusNotFound)
	wantStatus(t, e.do("DELETE", "/v1/workload-identity/clients?clientId="+id, nil, alice), http.StatusOK)
	if !e.audited("citadel.CreateWorkloadClient", "ok") || !e.audited("citadel.UpdateWorkloadClient", "ok") || !e.audited("citadel.DeleteWorkloadClient", "ok") {
		t.Fatal("client changes not audited")
	}
}

func TestWorkloadTokenAccessKey(t *testing.T) {
	e := newWorkloadEnv(t)
	alice := e.session("alice", e.acctA)
	rec := e.do("POST", "/v1/workload-identity/clients", accessKeyClient(e, "bob"), alice)
	id := decode(t, rec)["clientId"].(string)
	body := map[string]any{"clientId": id, "audience": "sts.amazonaws.com"}

	// Bearer access key.
	rec = e.token(body, withHeader("Authorization", "Bearer "+bobKey+":"+bobSec))
	wantStatus(t, rec, http.StatusOK)
	out := decode(t, rec)
	claims := e.verifyToken(out["token"].(string), "sts.amazonaws.com")
	if sub, _ := claims.String("sub"); sub != "user:bob" || out["tokenType"] != "id_token" || out["expiresAt"] == "" {
		t.Fatalf("token = %v claims = %v", out, claims)
	}
	if !auditedIn(t, e.st, "citadel.IssueWorkloadToken", "ok", "bob", e.acctA) {
		t.Fatal("issued token not audited")
	}

	// SigV4-signed request.
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/workload-identity/token", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	signV4(t, req, raw, bobKey, bobSec)
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	wantStatus(t, rr, http.StatusOK)
	e.verifyToken(decode(t, rr)["token"].(string), "sts.amazonaws.com")
	// A tampered SigV4 body is refused.
	req = httptest.NewRequest("POST", "/v1/workload-identity/token", bytes.NewReader(raw))
	signV4(t, req, []byte(`{}`), bobKey, bobSec)
	rr = httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	wantStatus(t, rr, http.StatusUnauthorized)

	// The OAuth-style issuer endpoint works too.
	form := url.Values{"client_id": {id}, "audience": {"sts.amazonaws.com"}}.Encode()
	req = httptest.NewRequest("POST", "/oidc/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+bobKey+":"+bobSec)
	rr = httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	wantStatus(t, rr, http.StatusOK)

	// Denials, all audited.
	wantStatus(t, e.token(body, withHeader("Authorization", "Bearer "+carolKey+":"+carolSec)), http.StatusForbidden) // other account / not allowed
	wantStatus(t, e.token(body, withHeader("Authorization", "Bearer "+bobKey+":wrong")), http.StatusUnauthorized)
	wantStatus(t, e.token(body), http.StatusUnauthorized)
	wantStatus(t, e.token(map[string]any{"clientId": id, "audience": "other"}, withHeader("Authorization", "Bearer "+bobKey+":"+bobSec)), http.StatusBadRequest)
	wantStatus(t, e.token(map[string]any{"clientId": "nope", "audience": "x"}), http.StatusUnauthorized)
	if !auditedIn(t, e.st, "citadel.IssueWorkloadToken", "denied", "carol", e.acctA) {
		t.Fatal("denied token request not audited with the caller")
	}
	// Removing bob from the client denies him.
	upd := accessKeyClient(e, "alice")
	upd["clientId"] = id
	wantStatus(t, e.do("POST", "/v1/workload-identity/clients/update", upd, alice), http.StatusOK)
	wantStatus(t, e.token(body, withHeader("Authorization", "Bearer "+bobKey+":"+bobSec)), http.StatusForbidden)
}

func TestWorkloadTokenRotationOverlap(t *testing.T) {
	e := newWorkloadEnv(t)
	alice := e.session("alice", e.acctA)
	root := e.session("root", e.acctA)
	id := decode(t, e.do("POST", "/v1/workload-identity/clients", accessKeyClient(e, "bob"), alice))["clientId"].(string)
	body := map[string]any{"clientId": id, "audience": "sts.amazonaws.com"}
	auth := withHeader("Authorization", "Bearer "+bobKey+":"+bobSec)
	tok1 := decode(t, e.token(body, auth))["token"].(string)
	wantStatus(t, e.do("POST", "/v1/workload-identity/issuer/rotate", nil, root), http.StatusOK)
	tok2 := decode(t, e.token(body, auth))["token"].(string)
	j1, _ := jose.ParseCompact(tok1)
	j2, _ := jose.ParseCompact(tok2)
	if j1.Header.Kid == j2.Header.Kid {
		t.Fatal("rotation did not change the signing key")
	}
	e.verifyToken(tok1, "sts.amazonaws.com") // previous key still published
	e.verifyToken(tok2, "sts.amazonaws.com")

	// After the overlap window the job unpublishes the old key; after the
	// rotation period it rotates on its own.
	st := e.s.identity()
	st.now = func() time.Time { return time.Now().Add(91 * 24 * time.Hour) }
	e.s.workloadSigners().invalidate()
	if err := e.s.workloadRotationJob(context.Background()); err != nil {
		t.Fatal(err)
	}
	set, _ := jose.ParseJWKSet(e.do("GET", "/oidc/jwks.json", nil, nil).Body.Bytes())
	if _, err := set.Lookup(j1.Header.Kid, j1.Header.Alg); err == nil {
		t.Fatal("expired key still published")
	}
	if _, err := set.Lookup(j2.Header.Kid, j2.Header.Alg); err != nil {
		t.Fatal("previous key must stay published during its overlap")
	}
	cur, keys, _ := e.s.currentWorkloadKey(context.Background())
	if cur.KID == j2.Header.Kid || len(keys) != 2 {
		t.Fatalf("job did not rotate: cur=%s keys=%d", cur.KID, len(keys))
	}
}

func TestWorkloadTokenRateLimit(t *testing.T) {
	e := newWorkloadEnv(t)
	e.s.identity().tokenIP = ratelimit.New(time.Hour, 2)
	body := map[string]any{"clientId": "nope", "audience": "x"}
	e.token(body)
	e.token(body)
	rec := e.token(body)
	wantStatus(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
}

func TestWorkloadTokenKubernetes(t *testing.T) {
	e := newWorkloadEnv(t)
	e.s.cfg.WorkloadK8sReviewerToken = "reviewer-token"
	var gotAuth string
	var gotAud []string
	user := "system:serviceaccount:ci:builder"
	k8s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var tr struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&tr)
		gotAud = tr.Spec.Audiences
		ok := tr.Spec.Token == "sa-token"
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{
			"authenticated": ok, "audiences": tr.Spec.Audiences,
			"user": map[string]any{"username": user, "uid": "u1", "extra": map[string][]string{"authentication.kubernetes.io/pod-name": {"builder-1"}}},
		}})
	}))
	defer k8s.Close()
	alice := e.session("alice", e.acctA)
	client := map[string]any{"name": "k8s", "audiences": []string{"vault"}, "tokenTtlSeconds": 600,
		"subjectFormat": "system:serviceaccount:{namespace}:{serviceAccount}",
		"auth":          map[string]any{"method": "k8s-token-review", "apiServer": k8s.URL, "serviceAccounts": []string{"ci:builder"}, "reviewAudience": "citadel"}}
	bad := map[string]any{}
	for k, v := range client {
		bad[k] = v
	}
	bad["auth"] = map[string]any{"method": "k8s-token-review", "apiServer": k8s.URL, "serviceAccounts": []string{"ci:builder"}}
	wantStatus(t, e.do("POST", "/v1/workload-identity/clients", bad, alice), http.StatusBadRequest) // no dedicated audience
	rec := e.do("POST", "/v1/workload-identity/clients", client, alice)
	wantStatus(t, rec, http.StatusCreated)
	id := decode(t, rec)["clientId"].(string)

	rec = e.token(map[string]any{"clientId": id, "audience": "vault", "kubernetesToken": "sa-token"})
	wantStatus(t, rec, http.StatusOK)
	claims := e.verifyToken(decode(t, rec)["token"].(string), "vault")
	if sub, _ := claims.String("sub"); sub != user {
		t.Fatalf("sub = %q", sub)
	}
	if gotAuth != "Bearer reviewer-token" || len(gotAud) != 1 || gotAud[0] != "citadel" {
		t.Fatalf("TokenReview auth=%q audiences=%v", gotAuth, gotAud)
	}
	if !auditedIn(t, e.st, "citadel.IssueWorkloadToken", "ok", user, e.acctA) {
		t.Fatal("k8s token not audited")
	}
	wantStatus(t, e.token(map[string]any{"clientId": id, "audience": "vault", "kubernetesToken": "bad"}), http.StatusUnauthorized)
	user = "system:serviceaccount:other:builder"
	wantStatus(t, e.token(map[string]any{"clientId": id, "audience": "vault", "kubernetesToken": "sa-token"}), http.StatusForbidden)
	if !auditedIn(t, e.st, "citadel.IssueWorkloadToken", "denied", "", e.acctA) {
		t.Fatal("denied k8s token not audited")
	}
}

func TestWorkloadAttrsRejectSeparator(t *testing.T) {
	c := workloadid.Client{ID: "wic-1", Name: "ci", AccountRef: "111111111111"}
	if _, err := workloadAttrs(c, map[string]string{"username": "a:b"}); err == nil {
		t.Fatal("':' accepted in an attribute")
	}
	if _, err := workloadAttrs(c, map[string]string{"namespace": "ns\n"}); err == nil {
		t.Fatal("control character accepted")
	}
	if a, err := workloadAttrs(c, map[string]string{"username": "bob"}); err != nil || a["clientId"] != "wic-1" || a["username"] != "bob" {
		t.Fatalf("attrs = %v, %v", a, err)
	}
}
