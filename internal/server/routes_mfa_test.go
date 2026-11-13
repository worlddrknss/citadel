package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/totp"
)

// mfaEnroll enrols username through the API with cookie and returns the
// shared secret and recovery codes.
func (e *authEnv) mfaEnroll(cookie *http.Cookie) ([]byte, []string, map[string]any, *http.Cookie) {
	e.t.Helper()
	rec := e.do("POST", "/v1/account/mfa/enroll/start", nil, cookie)
	wantStatus(e.t, rec, http.StatusOK)
	start := decode(e.t, rec)
	if start["algorithm"] != "SHA256" || !strings.Contains(start["otpauthUri"].(string), "algorithm=SHA256") {
		e.t.Fatalf("start = %v", start)
	}
	key, err := totp.DecodeSecret(start["secret"].(string))
	if err != nil || len(key) != totp.SecretSize {
		e.t.Fatalf("secret %v %v", key, err)
	}
	rec = e.do("POST", "/v1/account/mfa/enroll/confirm", map[string]string{"code": totp.Code(key, totp.Step(time.Now()))}, cookie)
	wantStatus(e.t, rec, http.StatusOK)
	out := decode(e.t, rec)
	var codes []string
	for _, c := range out["recoveryCodes"].([]any) {
		codes = append(codes, c.(string))
	}
	return key, codes, out, sessionCookie(rec)
}

// mfaLogin signs in with the password and returns the pending-login token.
func (e *authEnv) mfaLogin(username, account string) string {
	e.t.Helper()
	rec := e.do("POST", "/v1/login", map[string]string{"accountId": account, "username": username, "password": testPassword}, nil)
	wantStatus(e.t, rec, http.StatusOK)
	if sessionCookie(rec) != nil {
		e.t.Fatal("password step of an MFA user set a session cookie")
	}
	m := decode(e.t, rec)
	if m["mfaRequired"] != true || m["mfaToken"] == "" {
		e.t.Fatalf("login = %v", m)
	}
	return m["mfaToken"].(string)
}

func nextCode(key []byte, d int64) string { return totp.Code(key, totp.Step(time.Now())+d) }

func TestMFAEnrolSignInReplayAndRecovery(t *testing.T) {
	e := newAuthEnv(t)
	e.s.mfa().user = ratelimit.New(time.Millisecond, 100)
	cookie := e.session("bob", e.acctA)
	other := e.session("bob", e.acctB)

	// Wrong confirmation code: not enabled.
	wantStatus(t, e.do("POST", "/v1/account/mfa/enroll/start", nil, cookie), http.StatusOK)
	wantStatus(t, e.do("POST", "/v1/account/mfa/enroll/confirm", map[string]string{"code": "000000"}, cookie), http.StatusBadRequest)
	st := decode(t, e.do("GET", "/v1/account/mfa", nil, cookie))
	if st["enabled"] != false || st["pending"] != true {
		t.Fatalf("status while pending = %v", st)
	}

	key, codes, _, _ := e.mfaEnroll(cookie)
	if len(codes) != 10 || len(codes[0]) != 14 {
		t.Fatalf("recovery codes = %v", codes)
	}
	if !e.audited("citadel.MFAEnroll", "ok") || !e.audited("citadel.MFAEnroll", "denied") {
		t.Fatal("enrolment not audited")
	}
	st = decode(t, e.do("GET", "/v1/account/mfa", nil, cookie))
	if st["enabled"] != true || st["recoveryCodesLeft"] != float64(10) {
		t.Fatalf("status = %v", st)
	}
	if strings.Contains(e.do("GET", "/v1/account/mfa", nil, cookie).Body.String(), totp.EncodeSecret(key)) {
		t.Fatal("status leaks the secret")
	}
	// Enabling MFA ended the user's other sessions; a second start is refused.
	wantStatus(t, e.do("GET", "/v1/me", nil, other), http.StatusUnauthorized)
	wantStatus(t, e.do("POST", "/v1/account/mfa/enroll/start", nil, cookie), http.StatusConflict)

	// The enrolment code's step is spent: replay with it fails.
	tok := e.mfaLogin("bob", e.acctA)
	wantStatus(t, e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok, "code": nextCode(key, 0)}, nil), http.StatusUnauthorized)
	if !e.audited("citadel.LoginMFA", "denied") {
		t.Fatal("failed MFA not audited")
	}
	rec := e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok, "code": nextCode(key, 1)}, nil)
	wantStatus(t, rec, http.StatusOK)
	c := sessionCookie(rec)
	if c == nil || decode(t, rec)["username"] != "bob" {
		t.Fatal("no session after MFA")
	}
	wantStatus(t, e.do("GET", "/v1/me", nil, c), http.StatusOK)
	if !e.audited("citadel.LoginMFA", "ok") {
		t.Fatal("MFA sign-in not audited")
	}
	// Same code again with a fresh token: replay refused.
	tok2 := e.mfaLogin("bob", e.acctA)
	wantStatus(t, e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok2, "code": nextCode(key, 1)}, nil), http.StatusUnauthorized)

	// Recovery code: works once, in any case or spacing.
	rec = e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok2, "recoveryCode": strings.ToUpper(codes[0])}, nil)
	wantStatus(t, rec, http.StatusOK)
	if !e.audited("citadel.MFARecoveryCodeUsed", "ok") {
		t.Fatal("recovery code use not audited")
	}
	// The token is single-use.
	wantStatus(t, e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok2, "recoveryCode": codes[1]}, nil), http.StatusUnauthorized)
	tok3 := e.mfaLogin("bob", e.acctA)
	wantStatus(t, e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok3, "recoveryCode": codes[0]}, nil), http.StatusUnauthorized)
	st = decode(t, e.do("GET", "/v1/account/mfa", nil, c))
	if st["recoveryCodesLeft"] != float64(8) {
		t.Fatalf("recovery codes left = %v", st["recoveryCodesLeft"])
	}
}

func TestMFATokenValidation(t *testing.T) {
	e := newAuthEnv(t)
	key, _, _, _ := e.mfaEnroll(e.session("bob", e.acctA))
	tok := e.mfaLogin("bob", e.acctA)
	tampered := tok[:len(tok)-2] + "AA"
	if tampered == tok {
		tampered = tok[:len(tok)-2] + "BB"
	}
	expired, err := e.s.signMFAToken(mfaPendingClaims{Username: "bob", AccountID: e.acctA, ID: "x", Expires: time.Now().Add(-time.Second).Unix(), Purpose: mfaTokenPurpose})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "garbage", tampered, expired} {
		rec := e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": bad, "code": nextCode(key, 1)}, nil)
		wantStatus(t, rec, http.StatusUnauthorized)
		if sessionCookie(rec) != nil {
			t.Fatal("cookie for a bad token")
		}
	}
	// CSRF header required, as for /v1/login.
	wantStatus(t, e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok, "code": nextCode(key, 1)}, nil, noCSRF), http.StatusForbidden)
}

func TestMFARateLimitAndLockout(t *testing.T) {
	e := newAuthEnv(t)
	key, _, _, _ := e.mfaEnroll(e.session("bob", e.acctA))
	tok := e.mfaLogin("bob", e.acctA)
	limited := false
	for range 8 {
		rec := e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok, "code": "123456"}, nil)
		if rec.Code == http.StatusTooManyRequests {
			limited = rec.Header().Get("Retry-After") != ""
			break
		}
		wantStatus(t, rec, http.StatusUnauthorized)
	}
	if !limited {
		t.Fatal("repeated MFA failures were never throttled")
	}
	// Locked out: even the right code is refused for now.
	wantStatus(t, e.do("POST", "/v1/login/mfa", map[string]string{"mfaToken": tok, "code": nextCode(key, 1)}, nil), http.StatusTooManyRequests)

	// The lockout (Backoff) applies on its own, independent of the bucket.
	m := newAuthEnv(t).s.mfa()
	for range 6 {
		m.failUser.Fail("carol")
	}
	if blocked, _ := m.failUser.Blocked("carol"); !blocked {
		t.Fatal("six failures did not lock the user out")
	}
}

func TestMFAForcedEnrolment(t *testing.T) {
	e := newAuthEnv(t)
	root := e.session("root", e.acctA)
	rec := e.do("GET", "/v1/admin/settings", nil, root)
	wantStatus(t, rec, http.StatusOK)
	set := decode(t, rec)
	if set["requireMFA"] != false {
		t.Fatalf("default requireMFA = %v", set["requireMFA"])
	}
	set["requireMFA"] = true
	delete(set, "updatedAt")
	delete(set, "updatedBy")
	wantStatus(t, e.do("POST", "/v1/admin/settings", set, root), http.StatusOK)
	e.s.invalidateOrgSettings()

	rec = e.do("POST", "/v1/login", map[string]string{"accountId": e.acctA, "username": "bob", "password": testPassword}, nil)
	wantStatus(t, rec, http.StatusOK)
	me := decode(t, rec)
	restricted := sessionCookie(rec)
	if me["mfaEnrollmentRequired"] != true || restricted == nil {
		t.Fatalf("login under requireMFA = %v", me)
	}
	// Only the enrolment endpoints are reachable.
	wantStatus(t, e.do("GET", "/v1/me", nil, restricted), http.StatusOK)
	wantStatus(t, e.do("GET", "/v1/account/mfa", nil, restricted), http.StatusOK)
	for _, p := range []string{"/v1/projects", "/v1/me/organization", "/v1/account/sessions", "/v1/account/keys"} {
		rec := e.do("GET", p, nil, restricted)
		wantStatus(t, rec, http.StatusForbidden)
		if decode(t, rec)["error"] != "mfa_enrollment_required" {
			t.Fatalf("%s: %s", p, rec.Body.String())
		}
	}
	wantStatus(t, e.do("POST", "/v1/session/account", map[string]string{"accountId": e.acctB}, restricted), http.StatusForbidden)

	_, _, out, full := e.mfaEnroll(restricted)
	meAfter, ok := out["me"].(map[string]any)
	if !ok || meAfter["mfaEnrollmentRequired"] != nil {
		t.Fatalf("confirm response = %v", out)
	}
	// The restricted session is gone; the new cookie is a full session.
	wantStatus(t, e.do("GET", "/v1/me", nil, restricted), http.StatusUnauthorized)
	if full == nil {
		t.Fatal("no full session cookie after enrolment")
	}
	wantStatus(t, e.do("GET", "/v1/me/organization", nil, full), http.StatusOK)

	// Disabling is refused while the organization requires MFA.
	wantStatus(t, e.do("POST", "/v1/account/mfa/disable", map[string]string{"password": testPassword, "code": "123456"}, full), http.StatusConflict)
}

func TestMFADisableAndRegenerate(t *testing.T) {
	e := newAuthEnv(t)
	// This test makes several verified calls in a row; lift the per-user
	// attempt bucket (the lockout still applies).
	e.s.mfa().user = ratelimit.New(time.Millisecond, 100)
	cookie := e.session("bob", e.acctA)
	key, codes, _, _ := e.mfaEnroll(cookie)

	wantStatus(t, e.do("POST", "/v1/account/mfa/recovery-codes", map[string]string{"password": "wrong-password", "code": nextCode(key, 1)}, cookie), http.StatusForbidden)
	wantStatus(t, e.do("POST", "/v1/account/mfa/recovery-codes", map[string]string{"password": testPassword, "code": "000000"}, cookie), http.StatusForbidden)
	rec := e.do("POST", "/v1/account/mfa/recovery-codes", map[string]string{"password": testPassword, "code": nextCode(key, 1)}, cookie)
	wantStatus(t, rec, http.StatusOK)
	fresh := decode(t, rec)["recoveryCodes"].([]any)
	if len(fresh) != 10 {
		t.Fatalf("new codes = %v", fresh)
	}
	// Old codes are gone.
	wantStatus(t, e.do("POST", "/v1/account/mfa/disable", map[string]string{"password": testPassword, "recoveryCode": codes[0]}, cookie), http.StatusForbidden)
	rec = e.do("POST", "/v1/account/mfa/disable", map[string]string{"password": testPassword, "recoveryCode": fresh[0].(string)}, cookie)
	wantStatus(t, rec, http.StatusOK)
	if !e.audited("citadel.MFADisable", "ok") {
		t.Fatal("disable not audited")
	}
	rec = e.do("POST", "/v1/login", map[string]string{"accountId": e.acctA, "username": "bob", "password": testPassword}, nil)
	wantStatus(t, rec, http.StatusOK)
	if sessionCookie(rec) == nil {
		t.Fatal("password-only sign-in after disabling MFA failed")
	}
}

func TestMFAAdminReset(t *testing.T) {
	e := newAuthEnv(t)
	e.mfaEnroll(e.session("bob", e.acctA))
	bobSession := e.session("bob", e.acctA)
	alice := e.session("alice", e.acctA)
	root := e.session("root", e.acctA)

	users := decode(t, e.do("GET", "/v1/admin/users", nil, root))["users"].([]any)
	found := false
	for _, u := range users {
		m := u.(map[string]any)
		if m["username"] == "bob" {
			found = m["mfaEnabled"] == true
		}
	}
	if !found {
		t.Fatal("users list does not show bob's MFA")
	}
	// Account admin of A cannot reset bob (also in B).
	wantStatus(t, e.do("POST", "/v1/admin/users/mfa/reset", map[string]string{"username": "bob", "confirm": "bob"}, alice), http.StatusForbidden)
	// Confirmation must repeat the username.
	wantStatus(t, e.do("POST", "/v1/admin/users/mfa/reset", map[string]string{"username": "bob", "confirm": "bo"}, root), http.StatusBadRequest)
	// Non-admins cannot reset at all.
	wantStatus(t, e.do("POST", "/v1/admin/users/mfa/reset", map[string]string{"username": "carol", "confirm": "carol"}, bobSession), http.StatusForbidden)

	rec := e.do("POST", "/v1/admin/users/mfa/reset", map[string]string{"username": "bob", "confirm": "bob"}, root)
	wantStatus(t, rec, http.StatusOK)
	if !e.audited("citadel.MFAReset", "ok") {
		t.Fatal("reset not audited")
	}
	wantStatus(t, e.do("GET", "/v1/me", nil, bobSession), http.StatusUnauthorized)
	if _, err := e.st.GetMFA(context.Background(), "bob"); err != store.ErrMFANotFound {
		t.Fatalf("MFA after reset: %v", err)
	}
	wantStatus(t, e.do("POST", "/v1/admin/users/mfa/reset", map[string]string{"username": "bob", "confirm": "bob"}, root), http.StatusNotFound)
}

func TestMFASecretSealedAndBoundToUser(t *testing.T) {
	e := newAuthEnv(t)
	key, _, _, _ := e.mfaEnroll(e.session("bob", e.acctA))
	en, err := e.st.GetMFA(context.Background(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(en.SecretEnc), string(key)) {
		t.Fatal("secret stored in the clear")
	}
	if got, err := e.s.openMFASecret("bob", en.SecretEnc); err != nil || string(got) != string(key) {
		t.Fatal("cannot open bob's secret")
	}
	if _, err := e.s.openMFASecret("carol", en.SecretEnc); err == nil {
		t.Fatal("bob's sealed secret opened for carol")
	}
}
