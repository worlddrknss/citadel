package server

import (
	"bytes"
	"context"
	"crypto/fips140"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

const testPassword = "correct-horse-battery"

var (
	testHashOnce sync.Once
	testHash     string
)

// testPasswordHash hashes testPassword once per test binary (PBKDF2 is slow).
func testPasswordHash(t *testing.T) string {
	t.Helper()
	testHashOnce.Do(func() {
		h, err := cryptoutil.HashPassword(testPassword)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		testHash = h
	})
	return testHash
}

type authEnv struct {
	t     *testing.T
	s     *Server
	st    *memory.Store
	h     http.Handler
	acctA string
	acctB string
}

// newAuthEnv builds a server over a memory store with two accounts and:
//
//	root   global admin, platform admin, admin in A and B
//	alice  global viewer, admin in A (account admin)
//	bob    global viewer, editor in A, viewer in B
//	carol  global viewer, viewer in B only
func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	ctx := context.Background()
	st := &memory.Store{DefaultKey: sampleKey(1)}
	e := &authEnv{t: t, st: st}
	var err error
	if e.acctA, err = st.CreateUIAccount(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	if e.acctB, err = st.CreateUIAccount(ctx, "beta"); err != nil {
		t.Fatal(err)
	}
	hash := testPasswordHash(t)
	for _, u := range []store.UIUser{
		{Username: "root", Role: "admin", PlatformAdmin: true, DisplayName: "Root"},
		{Username: "alice", Role: "viewer", DisplayName: "Alice"},
		{Username: "bob", Role: "viewer", DisplayName: "Bob"},
		{Username: "carol", Role: "viewer", DisplayName: "Carol"},
	} {
		u.PasswordHash = hash
		if err := st.UpsertUIUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []struct{ user, acct, role string }{
		{"root", e.acctA, "admin"}, {"root", e.acctB, "admin"},
		{"alice", e.acctA, "admin"},
		{"bob", e.acctA, "editor"}, {"bob", e.acctB, "viewer"},
		{"carol", e.acctB, "viewer"},
	} {
		if err := st.AddUserAccount(ctx, m.user, m.acct, m.role); err != nil {
			t.Fatal(err)
		}
	}
	e.s = &Server{cfg: config.Config{SessionIdleTTL: 30 * time.Minute, SessionAbsTTL: 12 * time.Hour}, store: st}
	e.h = e.s.Handler()
	return e
}

// session creates a live session directly in the store (no PBKDF2) and
// returns its cookie.
func (e *authEnv) session(username, accountID string) *http.Cookie {
	e.t.Helper()
	return e.sessionAt(username, accountID, time.Now().UTC(), time.Now().UTC(), time.Now().UTC().Add(time.Hour))
}

func (e *authEnv) sessionAt(username, accountID string, created, lastSeen, expires time.Time) *http.Cookie {
	e.t.Helper()
	token := cryptoutil.RandomHex(32)
	err := e.st.CreateConsoleSession(context.Background(), store.ConsoleSession{
		ID: cryptoutil.RandomHex(8), TokenHash: hashSessionToken(token), Username: username, AccountID: accountID,
		Method: store.SessionMethodPassword, CreatedAt: created, LastSeenAt: lastSeen, ExpiresAt: expires,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookieInsecure, Value: token}
}

type reqOpt func(*http.Request)

func noCSRF(r *http.Request) { r.Header.Del(csrfHeader) }

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func (e *authEnv) do(method, path string, body any, cookie *http.Cookie, opts ...reqOpt) *httptest.ResponseRecorder {
	e.t.Helper()
	return doReq(e.t, e.h, method, path, body, cookie, opts...)
}

func doReq(t *testing.T, h http.Handler, method, path string, body any, cookie *http.Cookie, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeader, "1")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return m
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status %d, want %d; body %s", rec.Code, want, rec.Body.String())
	}
}

func (e *authEnv) audited(action, result string) bool {
	e.t.Helper()
	events, err := e.st.ListAuditEvents(context.Background(), 500)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Action == action && ev.Result == result {
			return true
		}
	}
	return false
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieInsecure && c.Value != "" {
			return c
		}
	}
	return nil
}

// ---- login and sessions ----------------------------------------------------

func TestLoginCreatesPersistentHashedSession(t *testing.T) {
	e := newAuthEnv(t)
	rec := e.do("POST", "/v1/login", map[string]string{"accountId": e.acctA, "username": "bob", "password": testPassword}, nil)
	wantStatus(t, rec, http.StatusOK)
	me := decode(t, rec)
	if me["role"] != "editor" || me["accountId"] != e.acctA {
		t.Fatalf("login role should come from the membership: %v", me)
	}
	c := sessionCookie(rec)
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v", c)
	}
	rows, _ := e.st.ListConsoleSessions(context.Background(), "bob")
	if len(rows) != 1 || rows[0].TokenHash == c.Value || rows[0].TokenHash != hashSessionToken(c.Value) || rows[0].Method != "password" {
		t.Fatalf("stored session must hold only the token hash: %+v", rows)
	}
	if !e.audited("citadel.Login", "ok") {
		t.Fatal("successful login not audited")
	}

	// A second server over the same store (a restart, or another replica)
	// accepts the session.
	other := &Server{cfg: e.s.cfg, store: e.st}
	rec = doReq(t, other.Handler(), "GET", "/v1/me", nil, c)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["username"] != "bob" {
		t.Fatal("session did not survive across servers")
	}

	// Logout revokes it everywhere.
	wantStatus(t, e.do("POST", "/v1/logout", nil, c), http.StatusOK)
	wantStatus(t, doReq(t, other.Handler(), "GET", "/v1/me", nil, c), http.StatusUnauthorized)
}

func TestLoginFailures(t *testing.T) {
	e := newAuthEnv(t)
	cases := []struct {
		name string
		body map[string]string
	}{
		{"wrong password", map[string]string{"accountId": e.acctA, "username": "bob", "password": "nope"}},
		{"unknown user", map[string]string{"accountId": e.acctA, "username": "mallory", "password": testPassword}},
		{"not a member", map[string]string{"accountId": e.acctA, "username": "carol", "password": testPassword}},
	}
	var msgs []string
	for _, c := range cases {
		rec := e.do("POST", "/v1/login", c.body, nil)
		wantStatus(t, rec, http.StatusUnauthorized)
		if sessionCookie(rec) != nil {
			t.Fatalf("%s: cookie set on failure", c.name)
		}
		msgs = append(msgs, rec.Body.String())
	}
	if msgs[0] != msgs[1] || msgs[1] != msgs[2] {
		t.Fatalf("failure responses differ (enumeration): %q", msgs)
	}
	if !e.audited("citadel.Login", "denied") {
		t.Fatal("failed login not audited")
	}
	wantStatus(t, e.do("POST", "/v1/login", map[string]string{"username": "bob"}, nil), http.StatusBadRequest)
}

func TestLoginLockoutAndRateLimit(t *testing.T) {
	e := newAuthEnv(t)
	a := e.s.auth()
	a.failUser = ratelimit.NewBackoff(1, time.Minute, time.Hour, time.Hour)
	bad := map[string]string{"accountId": e.acctA, "username": "bob", "password": "wrong"}
	wantStatus(t, e.do("POST", "/v1/login", bad, nil), http.StatusUnauthorized)
	wantStatus(t, e.do("POST", "/v1/login", bad, nil), http.StatusUnauthorized)
	// Locked: even the right password is refused, without a verification.
	good := map[string]string{"accountId": e.acctA, "username": "BOB", "password": testPassword}
	rec := e.do("POST", "/v1/login", good, nil)
	wantStatus(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	// Another user from the same address is unaffected by bob's lockout.
	wantStatus(t, e.do("POST", "/v1/login", map[string]string{"accountId": e.acctB, "username": "carol", "password": testPassword}, nil), http.StatusOK)

	// Per-address token bucket.
	a.loginIP = ratelimit.New(time.Hour, 1)
	e.do("POST", "/v1/login", map[string]string{"accountId": e.acctB, "username": "x", "password": "y"}, nil)
	wantStatus(t, e.do("POST", "/v1/login", map[string]string{"accountId": e.acctB, "username": "z", "password": "y"}, nil), http.StatusTooManyRequests)
}

func TestSessionLifetimes(t *testing.T) {
	e := newAuthEnv(t)
	now := time.Now().UTC()
	idle := e.sessionAt("bob", e.acctA, now.Add(-time.Hour), now.Add(-31*time.Minute), now.Add(time.Hour))
	wantStatus(t, e.do("GET", "/v1/me", nil, idle), http.StatusUnauthorized)
	expired := e.sessionAt("bob", e.acctA, now.Add(-2*time.Hour), now, now.Add(-time.Second))
	wantStatus(t, e.do("GET", "/v1/me", nil, expired), http.StatusUnauthorized)
	tooOld := e.sessionAt("bob", e.acctA, now.Add(-13*time.Hour), now, now.Add(time.Hour))
	wantStatus(t, e.do("GET", "/v1/me", nil, tooOld), http.StatusUnauthorized)
	rows, _ := e.st.ListConsoleSessions(context.Background(), "bob")
	if len(rows) != 0 {
		t.Fatalf("expired sessions should be deleted on use, %d left", len(rows))
	}

	// Org settings shorten the idle timeout.
	if err := e.st.PutOrgSettings(context.Background(), store.OrgSettings{SessionIdleMinutes: 5, SessionMaxHours: 12, ApprovalMinApprovers: 1}); err != nil {
		t.Fatal(err)
	}
	e.s.invalidateOrgSettings()
	c := e.sessionAt("bob", e.acctA, now.Add(-time.Hour), now.Add(-6*time.Minute), now.Add(time.Hour))
	wantStatus(t, e.do("GET", "/v1/me", nil, c), http.StatusUnauthorized)
}

func TestPurgeExpiredSessionsJob(t *testing.T) {
	e := newAuthEnv(t)
	now := time.Now().UTC()
	e.sessionAt("bob", e.acctA, now.Add(-time.Hour), now.Add(-31*time.Minute), now.Add(time.Hour))
	e.sessionAt("bob", e.acctA, now.Add(-time.Hour), now, now.Add(-time.Minute))
	live := e.session("bob", e.acctA)
	if err := e.s.purgeExpiredSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, _ := e.st.ListConsoleSessions(context.Background(), "bob")
	if len(rows) != 1 {
		t.Fatalf("%d sessions after purge, want 1", len(rows))
	}
	wantStatus(t, e.do("GET", "/v1/me", nil, live), http.StatusOK)
	// STS purge is a no-op on the memory store, not an error.
	if err := e.s.purgeExpiredSTSSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionReflectsMembershipChanges(t *testing.T) {
	e := newAuthEnv(t)
	c := e.session("bob", e.acctA)
	if decode(t, e.do("GET", "/v1/me", nil, c))["role"] != "editor" {
		t.Fatal("want editor")
	}
	_ = e.st.AddUserAccount(context.Background(), "bob", e.acctA, "viewer")
	if decode(t, e.do("GET", "/v1/me", nil, c))["role"] != "viewer" {
		t.Fatal("demotion must apply to the live session")
	}
	_ = e.st.RemoveUserAccount(context.Background(), "bob", e.acctA)
	wantStatus(t, e.do("GET", "/v1/me", nil, c), http.StatusUnauthorized)
}

func TestSwitchAccount(t *testing.T) {
	e := newAuthEnv(t)
	c := e.session("bob", e.acctA)
	rec := e.do("POST", "/v1/session/account", map[string]string{"accountId": e.acctB}, c)
	wantStatus(t, rec, http.StatusOK)
	if me := decode(t, rec); me["accountId"] != e.acctB || me["role"] != "viewer" {
		t.Fatalf("after switch: %v", me)
	}
	if me := decode(t, e.do("GET", "/v1/me", nil, c)); me["accountId"] != e.acctB || me["role"] != "viewer" {
		t.Fatalf("switch not persisted: %v", me)
	}
	if !e.audited("citadel.SwitchAccount", "ok") {
		t.Fatal("switch not audited")
	}
	// carol is only in B.
	cc := e.session("carol", e.acctB)
	wantStatus(t, e.do("POST", "/v1/session/account", map[string]string{"accountId": e.acctA}, cc), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/session/account", map[string]string{}, cc), http.StatusBadRequest)
	wantStatus(t, e.do("POST", "/v1/session/account", map[string]string{"accountId": e.acctA}, nil), http.StatusUnauthorized)
}

func TestMyOrganization(t *testing.T) {
	e := newAuthEnv(t)
	_ = e.st.PutOrgSettings(context.Background(), store.OrgSettings{OrganizationName: "Acme", ApprovalMinApprovers: 1})
	rec := e.do("GET", "/v1/me/organization", nil, e.session("bob", e.acctA))
	wantStatus(t, rec, http.StatusOK)
	var body struct {
		Organization struct{ Name string }
		Accounts     []orgAccountJSON
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Organization.Name != "Acme" || len(body.Accounts) != 2 {
		t.Fatalf("organization = %+v", body)
	}
	for _, a := range body.Accounts {
		want := map[string]string{e.acctA: "editor", e.acctB: "viewer"}[a.AccountID]
		if a.Role != want || (a.Name != "alpha" && a.Name != "beta") {
			t.Fatalf("account %+v", a)
		}
	}
	rec = e.do("GET", "/v1/me/organization", nil, e.session("carol", e.acctB))
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Accounts) != 1 || body.Accounts[0].AccountID != e.acctB {
		t.Fatalf("carol must only see her account: %+v", body.Accounts)
	}
	wantStatus(t, e.do("GET", "/v1/me/organization", nil, nil), http.StatusUnauthorized)
}

func TestSecretsSummaryIsAccountScoped(t *testing.T) {
	e := newAuthEnv(t)
	ctxA := store.WithCallerAccount(context.Background(), e.acctA)
	for _, n := range []string{"app/prod/A", "app/prod/B", "app/dev/A", "web/prod/X", "not-native"} {
		if _, _, err := e.st.CreateSecret(ctxA, store.CreateSecretRequest{Name: n, SecretString: "v"}); err != nil {
			t.Fatal(err)
		}
	}
	rec := e.do("GET", "/v1/secrets/summary", nil, e.session("bob", e.acctA))
	wantStatus(t, rec, http.StatusOK)
	got := decode(t, rec)
	if got["total"] != 4.0 || got["projects"] != 2.0 || got["environments"] != 3.0 {
		t.Fatalf("summary A = %v", got)
	}
	got = decode(t, e.do("GET", "/v1/secrets/summary", nil, e.session("carol", e.acctB)))
	if got["total"] != 0.0 || got["projects"] != 0.0 {
		t.Fatalf("account B must not see A's secrets: %v", got)
	}
}

// ---- bootstrap -------------------------------------------------------------

func newBootstrapEnv(t *testing.T) (*Server, *memory.Store, http.Handler) {
	st := &memory.Store{DefaultKey: sampleKey(1)}
	s := &Server{cfg: config.Config{SessionIdleTTL: 30 * time.Minute, SessionAbsTTL: 12 * time.Hour}, store: st}
	return s, st, s.Handler()
}

func TestBootstrapFlow(t *testing.T) {
	_, st, h := newBootstrapEnv(t)
	rec := doReq(t, h, "GET", "/v1/bootstrap", nil, nil)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["required"] != true {
		t.Fatal("bootstrap should be required")
	}
	// The API is closed in bootstrap mode, except the sign-in screen's calls.
	rec = doReq(t, h, "GET", "/v1/projects", nil, nil)
	wantStatus(t, rec, http.StatusUnauthorized)
	if decode(t, rec)["error"] != "bootstrap_required" {
		t.Fatalf("gate error = %s", rec.Body.String())
	}
	wantStatus(t, doReq(t, h, "GET", "/v1/server/info", nil, nil), http.StatusOK)
	wantStatus(t, doReq(t, h, "GET", "/v1/auth/providers", nil, nil), http.StatusOK)

	body := map[string]string{"organizationName": "Acme", "accountName": "Production", "username": "founder", "password": "a-long-password-1"}
	wantStatus(t, doReq(t, h, "POST", "/v1/bootstrap", body, nil, noCSRF), http.StatusForbidden)
	short := map[string]string{"organizationName": "Acme", "accountName": "Production", "username": "founder", "password": "short"}
	wantStatus(t, doReq(t, h, "POST", "/v1/bootstrap", short, nil), http.StatusBadRequest)
	badUser := map[string]string{"organizationName": "Acme", "accountName": "Production", "username": "../x", "password": "a-long-password-1"}
	wantStatus(t, doReq(t, h, "POST", "/v1/bootstrap", badUser, nil), http.StatusBadRequest)

	rec = doReq(t, h, "POST", "/v1/bootstrap", body, nil)
	wantStatus(t, rec, http.StatusCreated)
	out := decode(t, rec)
	acct, _ := out["accountId"].(string)
	if len(acct) != 12 || out["organization"] != "Acme" || out["username"] != "founder" {
		t.Fatalf("bootstrap response = %v", out)
	}
	c := sessionCookie(rec)
	if c == nil {
		t.Fatal("bootstrap should sign the admin in")
	}
	rec = doReq(t, h, "GET", "/v1/me", nil, c)
	wantStatus(t, rec, http.StatusOK)
	me := decode(t, rec)
	if me["role"] != "admin" || me["accountId"] != acct || me["platformAdmin"] != true {
		t.Fatalf("bootstrap admin = %v", me)
	}
	u, err := st.GetUIUser(context.Background(), "founder")
	if err != nil || !strings.HasPrefix(u.PasswordHash, "$pbkdf2-sha256$") {
		t.Fatalf("admin must be stored with a PBKDF2 hash: %+v %v", u, err)
	}
	wantStatus(t, doReq(t, h, "GET", "/v1/projects", nil, c), http.StatusOK)
	if decode(t, doReq(t, h, "GET", "/v1/bootstrap", nil, nil))["required"] != false {
		t.Fatal("bootstrap still required after setup")
	}
	rec = doReq(t, h, "POST", "/v1/bootstrap", body, nil)
	wantStatus(t, rec, http.StatusConflict)
	if decode(t, rec)["error"] != "already_bootstrapped" {
		t.Fatal("want already_bootstrapped")
	}
	events, _ := st.ListAuditEvents(context.Background(), 50)
	found := false
	for _, ev := range events {
		found = found || (ev.Action == "citadel.Bootstrap" && ev.Actor == "founder")
	}
	if !found {
		t.Fatal("bootstrap not audited with the admin as actor")
	}
}

func TestBootstrapConcurrentRequests(t *testing.T) {
	s, st, h := newBootstrapEnv(t)
	s.auth().bootstrapIP = ratelimit.New(time.Millisecond, 100)
	const n = 6
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := map[string]string{"organizationName": "Org", "accountName": "acct" + string(rune('a'+i)), "username": "admin" + string(rune('a'+i)), "password": "a-long-password-1"}
			codes[i] = doReq(t, h, "POST", "/v1/bootstrap", body, nil).Code
		}()
	}
	wg.Wait()
	created := 0
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
		default:
			t.Fatalf("unexpected status %d", c)
		}
	}
	if n, _ := st.CountUIUsers(context.Background()); created != 1 || n != 1 {
		t.Fatalf("created=%d users=%d, want exactly one", created, n)
	}
}

func TestBootstrapRateLimited(t *testing.T) {
	_, _, h := newBootstrapEnv(t)
	bad := map[string]string{"organizationName": "Acme", "accountName": "P", "username": "u", "password": "short"}
	for range 5 {
		wantStatus(t, doReq(t, h, "POST", "/v1/bootstrap", bad, nil), http.StatusBadRequest)
	}
	wantStatus(t, doReq(t, h, "POST", "/v1/bootstrap", bad, nil), http.StatusTooManyRequests)
}

func TestBootstrapNotOfferedWithUsers(t *testing.T) {
	e := newAuthEnv(t)
	if decode(t, e.do("GET", "/v1/bootstrap", nil, nil))["required"] != false {
		t.Fatal("bootstrap offered although users exist")
	}
	body := map[string]string{"organizationName": "Acme", "accountName": "Production", "username": "evil", "password": "a-long-password-1"}
	wantStatus(t, e.do("POST", "/v1/bootstrap", body, nil), http.StatusConflict)
}

// ---- public endpoints ------------------------------------------------------

func TestPublicEndpoints(t *testing.T) {
	e := newAuthEnv(t)
	rec := e.do("GET", "/v1/auth/providers", nil, nil)
	wantStatus(t, rec, http.StatusOK)
	if got := rec.Body.String(); !strings.Contains(got, `"providers":[]`) {
		t.Fatalf("providers = %s", got)
	}
	info := decode(t, e.do("GET", "/v1/server/info", nil, nil))
	if info["fips"] != fips140.Enabled() || info["sessionIdleMinutes"] != 30.0 || info["sessionMaxHours"] != 12.0 {
		t.Fatalf("server info = %v", info)
	}
	if _, ok := info["version"]; ok {
		t.Fatal("server info must not disclose the version")
	}
}

// ---- account self-service --------------------------------------------------

func TestUpdateProfile(t *testing.T) {
	e := newAuthEnv(t)
	c := e.session("bob", e.acctA)
	rec := e.do("POST", "/v1/account/profile", map[string]string{"displayName": "Robert"}, c)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["displayName"] != "Robert" {
		t.Fatal("display name not returned")
	}
	u, _ := e.st.GetUIUser(context.Background(), "bob")
	if u.DisplayName != "Robert" || u.Role != "viewer" || u.PasswordHash == "" {
		t.Fatalf("profile update clobbered the user: %+v", u)
	}
	wantStatus(t, e.do("POST", "/v1/account/profile", map[string]string{"displayName": ""}, c), http.StatusBadRequest)
	wantStatus(t, e.do("POST", "/v1/account/profile", map[string]string{"displayName": "a\x00b"}, c), http.StatusBadRequest)
	wantStatus(t, e.do("POST", "/v1/account/profile", map[string]string{"displayName": "x"}, nil), http.StatusUnauthorized)
	if !e.audited("citadel.UpdateProfile", "ok") {
		t.Fatal("not audited")
	}
}

func TestAccountSessions(t *testing.T) {
	e := newAuthEnv(t)
	cur := e.session("bob", e.acctA)
	e.session("bob", e.acctB)
	e.session("bob", e.acctA)
	carols := e.session("carol", e.acctB)

	rec := e.do("GET", "/v1/account/sessions", nil, cur)
	wantStatus(t, rec, http.StatusOK)
	var body struct{ Sessions []sessionJSON }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Sessions) != 3 {
		t.Fatalf("sessions = %+v", body.Sessions)
	}
	var currentID, otherID string
	for _, s := range body.Sessions {
		if s.Current {
			currentID = s.ID
		} else {
			otherID = s.ID
		}
		if s.Method != "password" || s.ExpiresAt == "" {
			t.Fatalf("session %+v", s)
		}
	}
	if currentID == "" {
		t.Fatal("current session not flagged")
	}
	wantStatus(t, e.do("DELETE", "/v1/account/sessions?id="+currentID, nil, cur), http.StatusBadRequest)
	// Carol cannot revoke Bob's sessions.
	wantStatus(t, e.do("DELETE", "/v1/account/sessions?id="+otherID, nil, carols), http.StatusNotFound)
	wantStatus(t, e.do("DELETE", "/v1/account/sessions?id="+otherID, nil, cur), http.StatusOK)
	if !e.audited("citadel.RevokeSession", "ok") {
		t.Fatal("revoke not audited")
	}
	rec = e.do("POST", "/v1/account/sessions/revoke-others", nil, cur)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["revoked"] != 1.0 {
		t.Fatalf("revoke-others = %s", rec.Body.String())
	}
	wantStatus(t, e.do("GET", "/v1/me", nil, cur), http.StatusOK)
	wantStatus(t, e.do("GET", "/v1/me", nil, carols), http.StatusOK)
}

// ---- admin: settings, users, accounts --------------------------------------

func TestOrgSettings(t *testing.T) {
	e := newAuthEnv(t)
	root := e.session("root", e.acctA)
	alice := e.session("alice", e.acctA)
	bob := e.session("bob", e.acctA)

	rec := e.do("GET", "/v1/admin/settings", nil, alice)
	wantStatus(t, rec, http.StatusOK)
	def := decode(t, rec)
	if def["allowSelfApproval"] != false || def["approvalMinApprovers"] != 1.0 || def["sessionIdleMinutes"] != 30.0 {
		t.Fatalf("defaults = %v", def)
	}
	wantStatus(t, e.do("GET", "/v1/admin/settings", nil, bob), http.StatusForbidden)

	in := map[string]any{"approvalEnvironments": []string{"prod"}, "approvalMinApprovers": 2, "allowSelfApproval": false, "sessionIdleMinutes": 15, "sessionMaxHours": 8}
	wantStatus(t, e.do("POST", "/v1/admin/settings", in, alice), http.StatusForbidden)
	rec = e.do("POST", "/v1/admin/settings", in, root)
	wantStatus(t, rec, http.StatusOK)
	got := decode(t, rec)
	if got["updatedBy"] != "root" || got["sessionIdleMinutes"] != 15.0 || got["updatedAt"] == nil {
		t.Fatalf("saved = %v", got)
	}
	if !e.audited("citadel.UpdateOrgSettings", "ok") {
		t.Fatal("not audited")
	}
	for _, bad := range []map[string]any{
		{"approvalEnvironments": []string{"bad env"}, "approvalMinApprovers": 1, "sessionIdleMinutes": 15, "sessionMaxHours": 8},
		{"approvalEnvironments": []string{}, "approvalMinApprovers": 0, "sessionIdleMinutes": 15, "sessionMaxHours": 8},
		{"approvalEnvironments": []string{}, "approvalMinApprovers": 1, "sessionIdleMinutes": 1, "sessionMaxHours": 8},
		{"approvalEnvironments": []string{}, "approvalMinApprovers": 1, "sessionIdleMinutes": 600, "sessionMaxHours": 1},
	} {
		wantStatus(t, e.do("POST", "/v1/admin/settings", bad, root), http.StatusBadRequest)
	}
	// The new lifetimes apply to sessions.
	info := decode(t, e.do("GET", "/v1/server/info", nil, nil))
	if info["sessionIdleMinutes"] != 15.0 || info["sessionMaxHours"] != 8.0 {
		t.Fatalf("server info after settings = %v", info)
	}
}

func TestAdminUsersScoping(t *testing.T) {
	e := newAuthEnv(t)
	root := e.session("root", e.acctA)
	alice := e.session("alice", e.acctA)

	var body struct{ Users []nativeUser }
	rec := e.do("GET", "/v1/admin/users", nil, root)
	wantStatus(t, rec, http.StatusOK)
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Users) != 4 {
		t.Fatalf("platform admin sees %d users", len(body.Users))
	}
	for _, u := range body.Users {
		if u.Username == "bob" && len(u.Memberships) != 2 {
			t.Fatalf("bob memberships = %+v", u.Memberships)
		}
		if u.Username == "root" && !u.PlatformAdmin {
			t.Fatal("root should be flagged platform admin")
		}
	}

	rec = e.do("GET", "/v1/admin/users", nil, alice)
	wantStatus(t, rec, http.StatusOK)
	body.Users = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	names := map[string]nativeUser{}
	for _, u := range body.Users {
		names[u.Username] = u
		for _, m := range u.Memberships {
			if m.AccountID != e.acctA {
				t.Fatalf("account admin sees another account's membership: %+v", u)
			}
		}
	}
	if _, ok := names["carol"]; ok || len(names) != 3 {
		t.Fatalf("account admin sees %v", names)
	}
	if names["bob"].Role != "editor" {
		t.Fatalf("bob's role for alice = %q", names["bob"].Role)
	}
	wantStatus(t, e.do("GET", "/v1/admin/users", nil, e.session("bob", e.acctA)), http.StatusForbidden)

	// Account admins cannot touch users who belong to other accounts...
	wantStatus(t, e.do("DELETE", "/v1/admin/users?username=bob", nil, alice), http.StatusForbidden)
	wantStatus(t, e.do("DELETE", "/v1/admin/users?username=carol", nil, alice), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/admin/users", map[string]any{"username": "bob", "role": "admin", "password": "new-password-1"}, alice), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/admin/users", map[string]any{"username": "root", "role": "viewer"}, alice), http.StatusForbidden)
	// ...nor grant platform admin or other accounts.
	wantStatus(t, e.do("POST", "/v1/admin/users", map[string]any{"username": "dave", "role": "viewer", "password": "new-password-1", "platformAdmin": true}, alice), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/admin/users", map[string]any{"username": "dave", "role": "viewer", "password": "new-password-1", "accounts": []string{e.acctB}}, alice), http.StatusForbidden)

	// An account admin creates a user into their own account.
	rec = e.do("POST", "/v1/admin/users", map[string]any{"username": "dave", "displayName": "Dave", "role": "admin", "password": "new-password-1"}, alice)
	wantStatus(t, rec, http.StatusOK)
	dave, _ := e.st.GetUIUser(context.Background(), "dave")
	if dave.Role != "viewer" || dave.PlatformAdmin {
		t.Fatalf("account admin must not set a global role: %+v", dave)
	}
	ms, _ := e.st.ListUserAccounts(context.Background(), "dave")
	if len(ms) != 1 || ms[0].AccountID != e.acctA || ms[0].Role != "admin" {
		t.Fatalf("dave memberships = %+v", ms)
	}
	// ...and may delete such a user.
	wantStatus(t, e.do("DELETE", "/v1/admin/users?username=dave", nil, alice), http.StatusOK)
	wantStatus(t, e.do("DELETE", "/v1/admin/users?username=alice", nil, alice), http.StatusBadRequest)
	wantStatus(t, e.do("POST", "/v1/admin/users", map[string]any{"username": "bad name", "role": "viewer", "password": "new-password-1"}, root), http.StatusBadRequest)

	// Platform admins can do both.
	wantStatus(t, e.do("DELETE", "/v1/admin/users?username=carol", nil, root), http.StatusOK)
	if !e.audited("citadel.DeleteUser", "ok") {
		t.Fatal("delete not audited")
	}
}

func TestAdminAccountsScoping(t *testing.T) {
	e := newAuthEnv(t)
	root := e.session("root", e.acctA)
	alice := e.session("alice", e.acctA)

	wantStatus(t, e.do("POST", "/v1/admin/accounts", map[string]string{"name": "gamma"}, alice), http.StatusForbidden)
	wantStatus(t, e.do("DELETE", "/v1/admin/accounts?accountId="+e.acctB, nil, alice), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/admin/accounts/assign", map[string]string{"username": "alice", "accountId": e.acctB, "role": "admin"}, alice), http.StatusForbidden)
	wantStatus(t, e.do("DELETE", "/v1/admin/accounts/assign?username=bob&accountId="+e.acctB, nil, alice), http.StatusForbidden)

	var body struct{ Accounts []nativeAccount }
	_ = json.Unmarshal(e.do("GET", "/v1/admin/accounts", nil, alice).Body.Bytes(), &body)
	if len(body.Accounts) != 1 || body.Accounts[0].AccountID != e.acctA {
		t.Fatalf("account admin sees accounts %+v", body.Accounts)
	}

	// Within their own account an account admin manages memberships.
	wantStatus(t, e.do("POST", "/v1/admin/accounts/assign", map[string]string{"username": "carol", "accountId": e.acctA, "role": "editor"}, alice), http.StatusOK)
	wantStatus(t, e.do("POST", "/v1/admin/accounts/assign", map[string]string{"username": "carol", "accountId": e.acctA, "role": "owner"}, alice), http.StatusBadRequest)
	wantStatus(t, e.do("POST", "/v1/admin/accounts/assign", map[string]string{"username": "ghost", "accountId": e.acctA, "role": "viewer"}, alice), http.StatusNotFound)
	wantStatus(t, e.do("DELETE", "/v1/admin/accounts/assign?username=bob&accountId="+e.acctA, nil, alice), http.StatusOK)

	rec := e.do("POST", "/v1/admin/accounts", map[string]string{"name": "gamma"}, root)
	wantStatus(t, rec, http.StatusOK)
	body.Accounts = nil
	_ = json.Unmarshal(e.do("GET", "/v1/admin/accounts", nil, root).Body.Bytes(), &body)
	if len(body.Accounts) != 3 {
		t.Fatalf("platform admin sees %d accounts", len(body.Accounts))
	}
}

func TestEnvAdminIsPlatformAdmin(t *testing.T) {
	s := &Server{cfg: config.Config{UIUsers: map[string]store.UIUser{"ops": {Username: "ops", Role: "admin"}, "dev": {Username: "dev", Role: "editor"}}}, store: &memory.Store{}}
	if !s.isPlatformAdmin(store.UIUser{Username: "ops", Role: "admin"}) {
		t.Fatal("env-configured admin should be a platform admin")
	}
	if s.isPlatformAdmin(store.UIUser{Username: "dev", Role: "editor"}) || s.isPlatformAdmin(store.UIUser{Username: "x", Role: "admin"}) {
		t.Fatal("only env admins and flagged admins are platform admins")
	}
	if s.isPlatformAdmin(store.UIUser{Username: "y", Role: "editor", PlatformAdmin: true}) {
		t.Fatal("the flag requires the global admin role")
	}
}

// ---- CSRF and headers ------------------------------------------------------

func TestCSRFProtection(t *testing.T) {
	e := newAuthEnv(t)
	c := e.session("bob", e.acctA)
	body := map[string]string{"displayName": "B"}
	rec := e.do("POST", "/v1/account/profile", body, c, noCSRF)
	wantStatus(t, rec, http.StatusForbidden)
	if decode(t, rec)["error"] != "csrf_rejected" {
		t.Fatal("want csrf_rejected")
	}
	wantStatus(t, e.do("POST", "/v1/account/profile", body, c, withHeader("Origin", "https://evil.example")), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/account/profile", body, c, withHeader("Origin", "null")), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/account/profile", body, c, withHeader("Referer", "https://evil.example/x")), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/account/profile", body, c, withHeader("Origin", "http://example.com")), http.StatusOK)
	// Login also requires the header (login CSRF).
	wantStatus(t, e.do("POST", "/v1/login", map[string]string{"accountId": e.acctA, "username": "bob", "password": "x"}, nil, noCSRF), http.StatusForbidden)
	// Safe methods and bearer-token requests are exempt.
	wantStatus(t, e.do("GET", "/v1/me", nil, c, noCSRF), http.StatusOK)
	rec = e.do("POST", "/v1/projects", map[string]string{"slug": "x"}, nil, noCSRF, withHeader("Authorization", "Bearer AKIAXXXX:secret"))
	if rec.Code == http.StatusForbidden {
		t.Fatalf("bearer request hit the CSRF check: %s", rec.Body.String())
	}
}

func TestSecurityHeadersOnAllResponses(t *testing.T) {
	e := newAuthEnv(t)
	e.s.webFS = fstest.MapFS{
		"index.html": {Data: []byte(`<!doctype html><html><head><script>var a=1;</script><script src="/app/x.js"></script></head><body><script>
start()
</script></body></html>`)},
		"_app/x.js": {Data: []byte("1")},
	}
	h := e.s.Handler()
	for _, p := range []string{"/healthz", "/v1/server/info", "/v1/me", "/app/", "/app/_app/x.js", "/crl/none", "/nope"} {
		rec := doReq(t, h, "GET", p, nil, nil)
		hd := rec.Header()
		if hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("X-Frame-Options") != "DENY" ||
			!strings.Contains(hd.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("%s: missing security headers: %v", p, hd)
		}
		if hd.Get("Strict-Transport-Security") != "" {
			t.Fatalf("%s: HSTS without TLS", p)
		}
		if strings.HasPrefix(p, "/v1/") && hd.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: Cache-Control %q", p, hd.Get("Cache-Control"))
		}
	}
	csp := doReq(t, h, "GET", "/app/secrets", nil, nil).Header().Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self' 'sha256-", "object-src 'none'", "default-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("app CSP %q lacks %q", csp, want)
		}
	}
	if scriptSrc := strings.SplitN(strings.SplitN(csp, "script-src", 2)[1], ";", 2)[0]; strings.Contains(scriptSrc, "unsafe-inline") {
		t.Fatalf("script-src must not allow unsafe-inline: %q", csp)
	}
	if got := inlineScriptHashes([]byte(`<script>var a=1;</script><script src="x"></script><script type="module">
start()
</script>`)); len(got) != 2 || got[0] != "'sha256-gaaMFNHZyRta8zB2VHkWLMP4tMxJ+d8v3dTW7nw2r6M='" {
		t.Fatalf("inline script hashes = %v", got)
	}

	tlsServer := &Server{cfg: config.Config{TLSCertFile: "c", TLSKeyFile: "k"}, store: e.st}
	if doReq(t, tlsServer.Handler(), "GET", "/healthz", nil, nil).Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing with TLS configured")
	}
}

// ---- jobs ------------------------------------------------------------------

func TestJobRunner(t *testing.T) {
	j := newJobRunner()
	var mu sync.Mutex
	runs := map[string]int{}
	tick := func(name string) func(context.Context) error {
		return func(context.Context) error {
			mu.Lock()
			runs[name]++
			mu.Unlock()
			if name == "boom" {
				panic("boom")
			}
			return nil
		}
	}
	j.Every("a", 5*time.Millisecond, tick("a"))
	j.Every("a", time.Millisecond, tick("dup")) // ignored
	j.Every("boom", 5*time.Millisecond, tick("boom"))
	ctx, cancel := context.WithCancel(context.Background())
	j.Start(ctx)
	j.Every("late", 5*time.Millisecond, tick("late"))
	time.Sleep(40 * time.Millisecond)
	cancel()
	j.Wait()
	mu.Lock()
	defer mu.Unlock()
	if runs["a"] < 2 || runs["late"] < 1 || runs["boom"] < 2 || runs["dup"] != 0 {
		t.Fatalf("runs = %v", runs)
	}
	var nilRunner *jobRunner
	nilRunner.Every("x", time.Second, tick("x"))
	nilRunner.Start(ctx)
	nilRunner.Wait()
}
