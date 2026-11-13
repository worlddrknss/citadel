package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/totp"
)

// Console multi-factor authentication (TOTP, RFC 6238).
//
//   - Enrolment is self-service (My account → Security): start returns the
//     otpauth:// URI (the browser renders the QR code locally), confirm
//     activates it with a valid code and returns ten single-use recovery
//     codes, shown once. Secrets are sealed with AES-256-GCM under a key
//     HKDF-derived from the deployment root secret, bound to the username.
//   - Sign-in: a correct password for a user with MFA returns
//     {mfaRequired, mfaToken} and no cookie. mfaToken is an HMAC-SHA256
//     signed, 5-minute, single-use pending-login token; POST /v1/login/mfa
//     with it and a code (or recovery code) issues the session.
//   - Codes are single-use: the last accepted time step is stored per user
//     and only later steps are accepted. Attempts are rate limited per user
//     and per client address (locally and deployment-wide), and repeated
//     failures lock the user out with exponential backoff.
//   - Organization policy requireMFA: a password sign-in by a user without
//     MFA gets a restricted session (store.SessionMethodMFAEnrollment) that
//     reaches only the enrolment endpoints. SSO sign-ins and access-key
//     tokens are exempt.

const (
	mfaTokenTTL       = 5 * time.Minute
	mfaRecoveryCount  = 10
	mfaTokenPurpose   = "login"
	maxMFATokenLength = 1024
)

// MFA attempt limits. The local buckets run first; the shared counters
// (PostgreSQL) hold the limits across replicas. Each shared limit allows at
// least what one replica's bucket allows over the window.
var (
	sharedLimitMFAIP   = sharedLimit{"mfa-ip", 40, time.Minute}       // bucket: 20 burst + 1/3s
	sharedLimitMFAUser = sharedLimit{"mfa-user", 15, 5 * time.Minute} // bucket: 5 burst + 2/min
)

type mfaState struct {
	ip       *ratelimit.Limiter
	user     *ratelimit.Limiter
	failIP   *ratelimit.Backoff
	failUser *ratelimit.Backoff

	ephemeralOnce sync.Once
	ephemeral     []byte
}

var mfaStates sync.Map // *Server -> *mfaState

func (s *Server) mfa() *mfaState {
	if v, ok := mfaStates.Load(s); ok {
		return v.(*mfaState)
	}
	st := &mfaState{
		ip:       ratelimit.New(3*time.Second, 20),
		user:     ratelimit.New(30*time.Second, 5),
		failIP:   ratelimit.NewBackoff(20, time.Second, 15*time.Minute, time.Hour),
		failUser: ratelimit.NewBackoff(5, 30*time.Second, 15*time.Minute, time.Hour),
	}
	v, _ := mfaStates.LoadOrStore(s, st)
	return v.(*mfaState)
}

// registerMFARoutes wires the MFA endpoints.
func (s *Server) registerMFARoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/login/mfa", s.handleV1LoginMFA)
	mux.HandleFunc("GET /v1/account/mfa", s.handleV1MFAStatus)
	mux.HandleFunc("POST /v1/account/mfa/enroll/start", s.handleV1MFAEnrollStart)
	mux.HandleFunc("POST /v1/account/mfa/enroll/confirm", s.handleV1MFAEnrollConfirm)
	mux.HandleFunc("POST /v1/account/mfa/disable", s.handleV1MFADisable)
	mux.HandleFunc("POST /v1/account/mfa/recovery-codes", s.handleV1MFARegenerateCodes)
	mux.HandleFunc("POST /v1/admin/users/mfa/reset", s.handleV1AdminResetMFA)
}

// mfaEnrollmentAllowed lists what a restricted (enrolment-only) session may
// reach.
func mfaEnrollmentAllowed(r *http.Request) bool {
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/me", "GET /v1/account/mfa", "POST /v1/account/mfa/enroll/start", "POST /v1/account/mfa/enroll/confirm":
		return true
	}
	return false
}

// ---- keys, sealing and pending-login tokens --------------------------------

// mfaRoot is the secret MFA keys derive from: the deployment secret, or for
// the in-memory store (whose data dies with the process anyway) a random
// per-process value. PostgreSQL deployments always have a root secret.
func (s *Server) mfaRoot() ([]byte, bool) {
	if root := s.deploymentSecret(); len(root) > 0 {
		return root, true
	}
	if s.dbBacked() {
		return nil, false
	}
	m := s.mfa()
	m.ephemeralOnce.Do(func() {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err == nil {
			m.ephemeral = b
		}
	})
	return m.ephemeral, len(m.ephemeral) > 0
}

func mfaAAD(username string) []byte { return []byte("citadel-mfa-totp|" + username) }

func (s *Server) sealMFASecret(username string, secret []byte) ([]byte, error) {
	root, ok := s.mfaRoot()
	if !ok {
		return nil, errors.New("no deployment secret")
	}
	return cryptoutil.GCMSeal(cryptoutil.DeriveMFASecretKey(root), secret, mfaAAD(username))
}

func (s *Server) openMFASecret(username string, sealed []byte) ([]byte, error) {
	root, ok := s.mfaRoot()
	if !ok {
		return nil, errors.New("no deployment secret")
	}
	return cryptoutil.GCMOpen(cryptoutil.DeriveMFASecretKey(root), sealed, mfaAAD(username))
}

type mfaPendingClaims struct {
	Username  string `json:"u"`
	AccountID string `json:"a"`
	ID        string `json:"j"`
	Expires   int64  `json:"e"`
	Purpose   string `json:"p"`
}

var b64url = base64.RawURLEncoding

func (s *Server) signMFAToken(c mfaPendingClaims) (string, error) {
	root, ok := s.mfaRoot()
	if !ok {
		return "", errors.New("no deployment secret")
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, cryptoutil.DeriveMFATokenKey(root))
	mac.Write(payload)
	return b64url.EncodeToString(payload) + "." + b64url.EncodeToString(mac.Sum(nil)), nil
}

// parseMFAToken verifies a pending-login token's signature, purpose and
// expiry. Whether it was already used is checked by the store.
func (s *Server) parseMFAToken(tok string, now time.Time) (mfaPendingClaims, bool) {
	root, ok := s.mfaRoot()
	if !ok || tok == "" || len(tok) > maxMFATokenLength {
		return mfaPendingClaims{}, false
	}
	p, sig, found := strings.Cut(tok, ".")
	if !found {
		return mfaPendingClaims{}, false
	}
	payload, err1 := b64url.DecodeString(p)
	got, err2 := b64url.DecodeString(sig)
	if err1 != nil || err2 != nil {
		return mfaPendingClaims{}, false
	}
	mac := hmac.New(sha256.New, cryptoutil.DeriveMFATokenKey(root))
	mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return mfaPendingClaims{}, false
	}
	var c mfaPendingClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return mfaPendingClaims{}, false
	}
	if c.Purpose != mfaTokenPurpose || c.Username == "" || c.ID == "" || now.Unix() >= c.Expires {
		return mfaPendingClaims{}, false
	}
	return c, true
}

// ---- recovery codes --------------------------------------------------------

const recoveryAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// newRecoveryCodes returns n fresh codes ("abcd-efgh-ijkl", 60 random bits
// each) and their PBKDF2 hashes.
func newRecoveryCodes(n int) (codes, hashes []string, err error) {
	for range n {
		b := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, nil, err
		}
		for i := range b {
			b[i] = recoveryAlphabet[b[i]&31]
		}
		raw := string(b)
		h, err := cryptoutil.HashRecoveryCode(raw)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, raw[0:4]+"-"+raw[4:8]+"-"+raw[8:12])
		hashes = append(hashes, h)
	}
	return codes, hashes, nil
}

// normalizeRecoveryCode lowercases and strips separators; "" when the input
// cannot be a recovery code.
func normalizeRecoveryCode(in string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(in) {
		switch {
		case c == '-' || c == ' ':
			continue
		case strings.ContainsRune(recoveryAlphabet, c):
			b.WriteRune(c)
		default:
			return ""
		}
	}
	if b.Len() != 12 {
		return ""
	}
	return b.String()
}

// ---- verification and throttling -------------------------------------------

// mfaThrottled applies the MFA attempt limits and lockouts for a client
// address and user, returning how long to wait when refused.
func (s *Server) mfaThrottled(ctx context.Context, ip, userKey string) (time.Duration, bool) {
	m := s.mfa()
	if blocked, d := m.failIP.Blocked(ip); blocked {
		return d, true
	}
	if blocked, d := m.failUser.Blocked(userKey); blocked {
		return d, true
	}
	if ok, d := m.ip.Reserve(ip); !ok {
		return d, true
	}
	if ok, d := m.user.Reserve(userKey); !ok {
		return d, true
	}
	ok, d := s.sharedAllow(ctx, sharedLimitCheck{sharedLimitMFAIP, ip}, sharedLimitCheck{sharedLimitMFAUser, userKey})
	return d, !ok
}

func (s *Server) mfaFailed(ip, userKey string) {
	m := s.mfa()
	m.failIP.Fail(ip)
	m.failUser.Fail(userKey)
}

func (s *Server) mfaSucceeded(ip, userKey string) {
	m := s.mfa()
	m.failIP.Reset(ip)
	m.failUser.Reset(userKey)
}

func writeMFAThrottled(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	writeNativeError(w, http.StatusTooManyRequests, "rate_limited", "too many verification attempts; try again later")
}

var errMFAState = errors.New("mfa state unavailable")

// checkSecondFactor verifies a TOTP code (refusing reused steps) or, when
// recovery is set, a recovery code, which it consumes. ok is false for a
// wrong, malformed or reused factor; err reports a storage or crypto
// failure.
func (s *Server) checkSecondFactor(ctx context.Context, e store.MFAEnrollment, code, recovery string) (usedRecovery, ok bool, err error) {
	if !e.Enabled {
		return false, false, nil
	}
	if strings.TrimSpace(recovery) != "" {
		norm := normalizeRecoveryCode(recovery)
		if norm == "" {
			return true, false, nil
		}
		hashes, err := s.store.ListMFARecoveryCodeHashes(ctx, e.Username)
		if err != nil {
			return true, false, err
		}
		match := ""
		for _, h := range hashes {
			if cryptoutil.VerifyPassword(h, norm) && match == "" {
				match = h
			}
		}
		if match == "" {
			return true, false, nil
		}
		won, err := s.store.ConsumeMFARecoveryCode(ctx, e.Username, match)
		return true, won, err
	}
	key, err := s.openMFASecret(e.Username, e.SecretEnc)
	if err != nil {
		return false, false, errMFAState
	}
	step, valid := totp.Verify(key, code, time.Now(), e.LastStep)
	if !valid {
		return false, false, nil
	}
	won, err := s.store.AdvanceMFAStep(ctx, e.Username, step)
	return false, won, err
}

// ---- sign-in ---------------------------------------------------------------

// mfaAfterPassword runs after handleV1Login has verified the password and
// membership. It handles the response itself (returning true) when the user
// has MFA (pending-login token) or must enrol (restricted session).
func (s *Server) mfaAfterPassword(w http.ResponseWriter, r *http.Request, user store.UIUser, accountID string) bool {
	e, err := s.store.GetMFA(r.Context(), user.Username)
	if err != nil && !errors.Is(err, store.ErrMFANotFound) {
		log.Printf("login: load MFA state failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not complete sign-in")
		return true
	}
	if err == nil && e.Enabled {
		tok, err := s.signMFAToken(mfaPendingClaims{
			Username: user.Username, AccountID: accountID, ID: cryptoutil.RandomHex(16),
			Expires: time.Now().Add(mfaTokenTTL).Unix(), Purpose: mfaTokenPurpose,
		})
		if err != nil {
			log.Printf("login: sign MFA token failed: %v", err)
			writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not complete sign-in")
			return true
		}
		writeNativeJSON(w, http.StatusOK, map[string]any{"mfaRequired": true, "mfaToken": tok})
		return true
	}
	if !s.orgSettings(r.Context()).RequireMFA {
		return false
	}
	sess, err := s.issueConsoleSession(r.Context(), w, r, user.Username, accountID, store.SessionMethodMFAEnrollment)
	if err != nil {
		log.Printf("create console session failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not create a session")
		return true
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.Login", KeyID: accountID, Result: "ok", ErrorType: "MFAEnrollmentRequired", AuditOrigin: s.userAuditOrigin(r, user.Username, accountID)})
	me, err := s.sessionFromRow(r.Context(), sess)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not create a session")
		return true
	}
	writeNativeJSON(w, http.StatusOK, meResponse(me))
	return true
}

type loginMFARequest struct {
	MFAToken     string `json:"mfaToken"`
	Code         string `json:"code"`
	RecoveryCode string `json:"recoveryCode"`
}

// handleV1LoginMFA completes a password sign-in with the second factor.
func (s *Server) handleV1LoginMFA(w http.ResponseWriter, r *http.Request) {
	var req loginMFARequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if len(req.Code) > 16 || len(req.RecoveryCode) > 64 || (strings.TrimSpace(req.Code) == "" && strings.TrimSpace(req.RecoveryCode) == "") {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "a code or recovery code is required")
		return
	}
	ip := s.clientIP(r)
	now := time.Now()
	claims, ok := s.parseMFAToken(strings.TrimSpace(req.MFAToken), now)
	if !ok {
		// Count bad tokens against the address so they cannot be probed.
		m := s.mfa()
		wait, limited := time.Duration(0), false
		if blocked, d := m.failIP.Blocked(ip); blocked {
			wait, limited = d, true
		} else if ok, d := m.ip.Reserve(ip); !ok {
			wait, limited = d, true
		} else if ok, d := s.sharedAllow(r.Context(), sharedLimitCheck{sharedLimitMFAIP, ip}); !ok {
			wait, limited = d, true
		}
		if limited {
			writeMFAThrottled(w, wait)
			return
		}
		m.failIP.Fail(ip)
		writeNativeError(w, http.StatusUnauthorized, "mfa_token_invalid", "the sign-in has expired; enter your password again")
		return
	}
	userKey := strings.ToLower(claims.Username)
	origin := s.userAuditOrigin(r, claims.Username, auditAccountFor(claims.AccountID))
	if wait, limited := s.mfaThrottled(r.Context(), ip, userKey); limited {
		log.Printf("MFA sign-in throttled ip=%s", ip)
		writeMFAThrottled(w, wait)
		return
	}
	e, err := s.store.GetMFA(r.Context(), claims.Username)
	if err != nil && !errors.Is(err, store.ErrMFANotFound) {
		log.Printf("login MFA: load state failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not complete sign-in")
		return
	}
	usedRecovery, ok, err := s.checkSecondFactor(r.Context(), e, req.Code, req.RecoveryCode)
	if err != nil {
		log.Printf("login MFA: verify failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not complete sign-in")
		return
	}
	if !ok {
		s.mfaFailed(ip, userKey)
		errType := "InvalidCode"
		if usedRecovery {
			errType = "InvalidRecoveryCode"
		}
		s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.LoginMFA", KeyID: claims.AccountID, Result: "denied", ErrorType: errType, AuditOrigin: origin})
		writeNativeError(w, http.StatusUnauthorized, "invalid_code", "invalid or already used code")
		return
	}
	if usedRecovery {
		s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.MFARecoveryCodeUsed", KeyID: claims.Username, Result: "ok", AuditOrigin: origin})
	}
	fresh, err := s.store.UseMFALoginToken(r.Context(), claims.ID, time.Unix(claims.Expires, 0), now)
	if err != nil {
		log.Printf("login MFA: spend token failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not complete sign-in")
		return
	}
	if !fresh {
		s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.LoginMFA", KeyID: claims.AccountID, Result: "denied", ErrorType: "TokenReused", AuditOrigin: origin})
		writeNativeError(w, http.StatusUnauthorized, "mfa_token_invalid", "the sign-in has expired; enter your password again")
		return
	}
	s.mfaSucceeded(ip, userKey)
	s.auth().failUser.Reset(userKey)
	sess, err := s.issueConsoleSession(r.Context(), w, r, claims.Username, claims.AccountID, store.SessionMethodPassword)
	if err != nil {
		log.Printf("create console session failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not create a session")
		return
	}
	me, err := s.sessionFromRow(r.Context(), sess)
	if err != nil {
		// The user was deleted or lost the account since the password step.
		_ = s.store.DeleteConsoleSession(r.Context(), sess.Username, sess.ID)
		s.clearSessionCookie(w)
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials or account access denied")
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.LoginMFA", KeyID: claims.AccountID, Result: "ok", AuditOrigin: origin})
	writeNativeJSON(w, http.StatusOK, meResponse(me))
}

// ---- self-service ----------------------------------------------------------

type mfaStatusJSON struct {
	Enabled           bool   `json:"enabled"`
	Pending           bool   `json:"pending"`
	EnabledAt         string `json:"enabledAt,omitempty"`
	RecoveryCodesLeft int    `json:"recoveryCodesLeft"`
	Required          bool   `json:"required"`
	Algorithm         string `json:"algorithm"`
	Digits            int    `json:"digits"`
	Period            int    `json:"period"`
}

func (s *Server) handleV1MFAStatus(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	out := mfaStatusJSON{Required: s.orgSettings(ctx).RequireMFA, Algorithm: totp.Algorithm, Digits: totp.Digits, Period: totp.Period}
	e, err := s.store.GetMFA(ctx, sess.Username)
	switch {
	case errors.Is(err, store.ErrMFANotFound):
	case err != nil:
		log.Printf("MFA status: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "load_failed", "could not load MFA status")
		return
	default:
		out.Enabled, out.Pending = e.Enabled, !e.Enabled
		if e.Enabled {
			out.EnabledAt = e.EnabledAt.Format(time.RFC3339)
			out.RecoveryCodesLeft = e.RecoveryCodesLeft
		}
	}
	writeNativeJSON(w, http.StatusOK, out)
}

// mfaIssuer names the deployment in authenticator apps: the organization
// name when set, else the product name. ':' would break the URI label.
func (s *Server) mfaIssuer(ctx context.Context) string {
	name := strings.TrimSpace(strings.ReplaceAll(s.orgSettings(ctx).OrganizationName, ":", " "))
	if name == "" {
		return AppName
	}
	return name
}

func (s *Server) handleV1MFAEnrollStart(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		log.Printf("MFA enrol: random: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "enroll_failed", "could not start enrolment")
		return
	}
	sealed, err := s.sealMFASecret(sess.Username, secret)
	if err != nil {
		log.Printf("MFA enrol: seal: %v", err)
		writeNativeError(w, http.StatusServiceUnavailable, "enroll_failed", "multi-factor authentication needs a deployment secret")
		return
	}
	err = s.store.PutPendingMFA(ctx, sess.Username, sealed, time.Now().UTC())
	if errors.Is(err, store.ErrMFAAlreadyEnabled) {
		writeNativeError(w, http.StatusConflict, "mfa_enabled", "multi-factor authentication is already on")
		return
	}
	if err != nil {
		log.Printf("MFA enrol: store: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "enroll_failed", "could not start enrolment")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFAEnrollStart", KeyID: sess.Username, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	issuer := s.mfaIssuer(ctx)
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"secret":     totp.EncodeSecret(secret),
		"otpauthUri": totp.URI(issuer, sess.Username, secret),
		"issuer":     issuer,
		"account":    sess.Username,
		"algorithm":  totp.Algorithm,
		"digits":     totp.Digits,
		"period":     totp.Period,
	})
}

type mfaCodeRequest struct {
	Code         string `json:"code"`
	RecoveryCode string `json:"recoveryCode,omitempty"`
	Password     string `json:"password,omitempty"`
}

func (s *Server) handleV1MFAEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	var req mfaCodeRequest
	if err := decodeJSONBody(r, &req); err != nil || len(req.Code) > 16 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "a 6-digit code is required")
		return
	}
	ip, userKey := s.clientIP(r), strings.ToLower(sess.Username)
	if wait, limited := s.mfaThrottled(ctx, ip, userKey); limited {
		writeMFAThrottled(w, wait)
		return
	}
	e, err := s.store.GetMFA(ctx, sess.Username)
	if errors.Is(err, store.ErrMFANotFound) || (err == nil && e.Enabled) {
		writeNativeError(w, http.StatusConflict, "no_pending_enrollment", "start enrolment first")
		return
	}
	if err != nil {
		log.Printf("MFA confirm: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "enroll_failed", "could not confirm enrolment")
		return
	}
	key, err := s.openMFASecret(sess.Username, e.SecretEnc)
	if err != nil {
		writeNativeError(w, http.StatusConflict, "no_pending_enrollment", "start enrolment again")
		return
	}
	step, valid := totp.Verify(key, req.Code, time.Now(), 0)
	if !valid {
		s.mfaFailed(ip, userKey)
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFAEnroll", KeyID: sess.Username, Result: "denied", ErrorType: "InvalidCode", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusBadRequest, "invalid_code", "that code is not valid; check the time on your device and try again")
		return
	}
	codes, hashes, err := newRecoveryCodes(mfaRecoveryCount)
	if err != nil {
		log.Printf("MFA confirm: recovery codes: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "enroll_failed", "could not confirm enrolment")
		return
	}
	err = s.store.EnableMFA(ctx, sess.Username, e.SecretEnc, step, hashes, time.Now().UTC())
	if errors.Is(err, store.ErrMFANotFound) {
		writeNativeError(w, http.StatusConflict, "no_pending_enrollment", "the enrolment changed; start again")
		return
	}
	if err != nil {
		log.Printf("MFA confirm: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "enroll_failed", "could not confirm enrolment")
		return
	}
	s.mfaSucceeded(ip, userKey)
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFAEnroll", KeyID: sess.Username, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	out := map[string]any{"enabled": true, "recoveryCodes": codes}
	if sess.Method == store.SessionMethodMFAEnrollment {
		// Swap the restricted session for a full one (new token).
		if err := s.store.DeleteConsoleSession(r.Context(), sess.Username, sess.SessionID); err != nil && !errors.Is(err, store.ErrConsoleSessionNotFound) {
			log.Printf("MFA confirm: drop restricted session: %v", err)
		}
		row, err := s.issueConsoleSession(r.Context(), w, r, sess.Username, sess.AccountID, store.SessionMethodPassword)
		if err != nil {
			log.Printf("MFA confirm: create session: %v", err)
			s.clearSessionCookie(w)
		} else if me, err := s.sessionFromRow(r.Context(), row); err == nil {
			out["me"] = meResponse(me)
		}
	} else if _, err := s.store.DeleteUserConsoleSessions(r.Context(), sess.Username, sess.SessionID); err != nil {
		// Sessions signed in without the second factor end.
		log.Printf("MFA confirm: revoke other sessions: %v", err)
	}
	writeNativeJSON(w, http.StatusOK, out)
}

// verifyPasswordAndFactor is the re-authentication for disabling MFA and
// regenerating recovery codes: the current password plus a valid code (or
// recovery code). It writes the error response and returns false on failure.
func (s *Server) verifyPasswordAndFactor(w http.ResponseWriter, r *http.Request, ctx context.Context, sess *uiSession, req mfaCodeRequest, action string) (store.MFAEnrollment, bool) {
	ip, userKey := s.clientIP(r), strings.ToLower(sess.Username)
	if wait, limited := s.mfaThrottled(ctx, ip, userKey); limited {
		writeMFAThrottled(w, wait)
		return store.MFAEnrollment{}, false
	}
	e, err := s.store.GetMFA(ctx, sess.Username)
	if errors.Is(err, store.ErrMFANotFound) || (err == nil && !e.Enabled) {
		writeNativeError(w, http.StatusConflict, "mfa_not_enabled", "multi-factor authentication is not on")
		return store.MFAEnrollment{}, false
	}
	if err != nil {
		log.Printf("MFA re-auth: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "verify_failed", "could not verify")
		return store.MFAEnrollment{}, false
	}
	user, found := s.lookupUser(ctx, sess.Username)
	stored := dummyPasswordHash
	if found {
		stored = user.StoredCredential()
	}
	if len(req.Password) > maxPasswordLen || !cryptoutil.VerifyPassword(stored, req.Password) {
		s.mfaFailed(ip, userKey)
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: sess.Username, Result: "denied", ErrorType: "InvalidCredentials", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "invalid_credentials", "current password or code is incorrect")
		return store.MFAEnrollment{}, false
	}
	usedRecovery, ok, err := s.checkSecondFactor(ctx, e, req.Code, req.RecoveryCode)
	if err != nil {
		log.Printf("MFA re-auth: verify: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "verify_failed", "could not verify")
		return store.MFAEnrollment{}, false
	}
	if !ok {
		s.mfaFailed(ip, userKey)
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: sess.Username, Result: "denied", ErrorType: "InvalidCode", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "invalid_credentials", "current password or code is incorrect")
		return store.MFAEnrollment{}, false
	}
	if usedRecovery {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFARecoveryCodeUsed", KeyID: sess.Username, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	}
	s.mfaSucceeded(ip, userKey)
	return e, true
}

func (s *Server) handleV1MFADisable(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	var req mfaCodeRequest
	if err := decodeJSONBody(r, &req); err != nil || len(req.Code) > 16 || len(req.RecoveryCode) > 64 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "password and code are required")
		return
	}
	if s.orgSettings(ctx).RequireMFA {
		writeNativeError(w, http.StatusConflict, "mfa_required", "your organization requires multi-factor authentication; regenerate recovery codes or ask an admin to reset it instead")
		return
	}
	if _, ok := s.verifyPasswordAndFactor(w, r, ctx, sess, req, "citadel.MFADisable"); !ok {
		return
	}
	if _, err := s.store.DeleteMFA(ctx, sess.Username); err != nil {
		log.Printf("MFA disable: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "disable_failed", "could not turn off multi-factor authentication")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFADisable", KeyID: sess.Username, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"disabled": true})
}

func (s *Server) handleV1MFARegenerateCodes(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	var req mfaCodeRequest
	if err := decodeJSONBody(r, &req); err != nil || len(req.Code) > 16 || len(req.RecoveryCode) > 64 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "password and code are required")
		return
	}
	if _, ok := s.verifyPasswordAndFactor(w, r, ctx, sess, req, "citadel.MFARecoveryCodesRegenerate"); !ok {
		return
	}
	codes, hashes, err := newRecoveryCodes(mfaRecoveryCount)
	if err == nil {
		err = s.store.ReplaceMFARecoveryCodes(ctx, sess.Username, hashes)
	}
	if err != nil {
		log.Printf("MFA regenerate codes: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "regenerate_failed", "could not create new recovery codes")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFARecoveryCodesRegenerate", KeyID: sess.Username, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// ---- admin reset -----------------------------------------------------------

type adminResetMFARequest struct {
	Username string `json:"username"`
	Confirm  string `json:"confirm"`
}

// handleV1AdminResetMFA removes a user's MFA (lost device) and signs them out
// everywhere. Platform admins may reset anyone; account admins only users
// they may manage (see adminCanManageUser). The confirm field must repeat
// the username.
func (s *Server) handleV1AdminResetMFA(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	if sess.ViaToken {
		writeNativeError(w, http.StatusForbidden, "forbidden", "this action requires a console session")
		return
	}
	var req adminResetMFARequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || len(username) > 128 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username is required")
		return
	}
	if req.Confirm != username {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "type the username to confirm")
		return
	}
	if strings.EqualFold(username, sess.Username) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "manage your own MFA from My account → Security")
		return
	}
	user, found := s.lookupUser(ctx, username)
	if !found {
		writeNativeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if !s.adminCanManageUser(ctx, sess, user) {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFAReset", KeyID: user.Username, Result: "denied", ErrorType: "AccessDenied", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "forbidden", "that user belongs to other accounts; ask a platform admin")
		return
	}
	existed, err := s.store.DeleteMFA(ctx, user.Username)
	if err != nil {
		log.Printf("MFA reset: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "reset_failed", "could not reset MFA")
		return
	}
	if !existed {
		writeNativeError(w, http.StatusNotFound, "not_enrolled", "that user has no multi-factor authentication")
		return
	}
	n, err := s.store.DeleteUserConsoleSessions(ctx, user.Username, "")
	if err != nil {
		log.Printf("MFA reset: revoke sessions: %v", err)
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFAReset", KeyID: user.Username, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"reset": true, "sessionsRevoked": n})
}

// mfaEnabledSet returns the usernames with active MFA, for the users list.
func (s *Server) mfaEnabledSet(ctx context.Context) map[string]bool {
	users, err := s.store.ListMFAEnabledUsers(ctx)
	if err != nil {
		log.Printf("list MFA users: %v", err)
	}
	out := make(map[string]bool, len(users))
	for _, u := range users {
		out[u] = true
	}
	return out
}
