package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/store"
)

// Login credentials for browser agents (2.4).
//
// A login credential's secret is JSON {username, password, totpSeed?}; its
// usage profile lists the URL patterns the login may be used on.
//
//   - POST /v1/agent/totp (MCP get_totp_code): the current TOTP code, with
//     the totp action. Never the seed.
//   - POST /v1/agent/login (MCP get_login): username and password, with the
//     reveal action, for a page URL matching the credential's patterns.
//   - GET/POST /v1/agents/credentials/login: the console reads the login's
//     non-secret state (and a live code preview) and writes its fields; the
//     TOTP seed is write-only.

const (
	actionAgentTOTP     = "citadel.AgentTOTP"
	actionAgentGetLogin = "citadel.AgentGetLogin"
	auditReadAgentLogin = "citadel.ReadAgentLogin"
	auditPutAgentLogin  = "citadel.PutAgentLogin"

	maxLoginFieldLen = 1024
	maxTOTPSeedLen   = 2048
)

// loginDoc is the JSON value of a login credential's secret.
type loginDoc struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPSeed string `json:"totpSeed,omitempty"`
}

func parseLoginDoc(v string) (loginDoc, error) {
	var d loginDoc
	if err := json.Unmarshal([]byte(v), &d); err != nil {
		return loginDoc{}, errors.New("the login's secret is not JSON {username, password, totpSeed?}")
	}
	return d, nil
}

// loginRevealValue is what reveal returns for a login: username and
// password, never the TOTP seed.
func loginRevealValue(v string) (string, error) {
	d, err := parseLoginDoc(v)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{d.Username, d.Password})
	return string(b), err
}

func loginURLPatterns(c store.AgentCredential) []string {
	if c.Kind != store.AgentCredentialLogin || c.Config.Login == nil {
		return nil
	}
	return c.Config.Login.URLPatterns
}

// matchLoginURL returns the first pattern raw falls under: the same scheme
// (https), host (exact, or a *.suffix wildcard that doesn't match the bare
// suffix), port, and a path under the pattern's path by whole segments.
func matchLoginURL(patterns []string, raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if port == "443" {
		port = ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") || strings.Contains(strings.ToLower(path), "%2e%2e") {
		return "", false
	}
	for _, p := range patterns {
		rest := strings.TrimPrefix(p, "https://")
		ph, pp, _ := strings.Cut(rest, "/")
		pp = "/" + pp
		pport := ""
		if h, prt, ok := strings.Cut(ph, ":"); ok {
			ph, pport = h, prt
			if pport == "443" {
				pport = ""
			}
		}
		if pport != port {
			continue
		}
		if suffix, ok := strings.CutPrefix(ph, "*."); ok {
			if !strings.HasSuffix(host, "."+suffix) {
				continue
			}
		} else if host != ph {
			continue
		}
		if pp == "/" || path == pp || strings.HasPrefix(path, strings.TrimSuffix(pp, "/")+"/") {
			return p, true
		}
	}
	return "", false
}

// loginTOTP builds the code generator for a login's seed: an otpauth://
// URI, or a bare base32 seed with the profile's algorithm, digits and period.
func loginTOTP(cfg *store.AgentLoginConfig, seed string) (*providertoken.TOTP, error) {
	seed = strings.TrimSpace(seed)
	if strings.HasPrefix(strings.ToLower(seed), "otpauth://") {
		return providertoken.ParseTOTPURI(seed)
	}
	var alg string
	var digits, period int
	if cfg != nil {
		alg, digits, period = cfg.TOTPAlgorithm, cfg.TOTPDigits, cfg.TOTPPeriod
	}
	return providertoken.ParseTOTPSeed(seed, alg, digits, period)
}

// totpFailure maps a seed that can't produce codes onto a failure.
func totpFailure(err error) *agentFailure {
	if errors.Is(err, providertoken.ErrSHA1Unsupported) {
		return &agentFailure{Status: http.StatusConflict, Code: "unsupported", Reason: "totp_sha1_unsupported", Message: agentFIPSSHA1Message}
	}
	return &agentFailure{Status: http.StatusBadGateway, Code: "upstream_error", Reason: "credential_invalid", Message: "the login's TOTP seed is not usable (" + strings.TrimPrefix(err.Error(), "providertoken: totp: ") + ")"}
}

// agentTOTPResponse is a TOTP code. Never the seed.
type agentTOTPResponse struct {
	Credential       string `json:"credential"`
	Code             string `json:"code"`
	ExpiresAt        string `json:"expiresAt"`
	SecondsRemaining int    `json:"secondsRemaining"`
	Digits           int    `json:"digits"`
	Period           int    `json:"period"`
	Algorithm        string `json:"algorithm"`
}

func totpResponse(name string, tok providertoken.Token, now time.Time) *agentTOTPResponse {
	digits, _ := strconv.Atoi(tok.Metadata["digits"])
	period, _ := strconv.Atoi(tok.Metadata["period"])
	remaining := int(tok.ExpiresAt.Sub(now).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	return &agentTOTPResponse{Credential: name, Code: tok.Value, ExpiresAt: fmtTime(tok.ExpiresAt), SecondsRemaining: remaining,
		Digits: digits, Period: period, Algorithm: tok.Metadata["algorithm"]}
}

// agentLoginSecret reads the login document behind an allowed use.
func (s *Server) agentLoginSecret(ctx context.Context, c *agentCaller, u agentUse) (loginDoc, store.AgentCredential, error) {
	cu, ok := u.ref.(agentCoreUse)
	if !ok {
		return loginDoc{}, store.AgentCredential{}, errors.New("no credential reference")
	}
	v, err := s.agentSecretValue(ctx, c.AccountID, cu.ref)
	if err != nil {
		return loginDoc{}, cu.cred, err
	}
	d, err := parseLoginDoc(v)
	return d, cu.cred, err
}

// agentTOTPRequest is the body of POST /v1/agent/totp.
type agentTOTPRequest struct {
	Credential string `json:"credential"`
	TaskID     string `json:"taskId,omitempty"`
}

// agentTOTPCode returns the current TOTP code of a login credential the
// agent holds a totp grant for. Audited as citadel.AgentTOTP before the
// code is returned.
func (s *Server) agentTOTPCode(ctx context.Context, r *http.Request, c *agentCaller, req agentTOTPRequest, via string) (*agentTOTPResponse, *agentFailure) {
	acc := s.agentAccess()
	record := func(result, reason string) {
		res := "credential=" + auditToken(req.Credential) + " via=" + via
		s.recordAudit(ctx, store.AuditEvent{Action: actionAgentTOTP, KeyID: req.Credential, Result: result, ErrorType: reason, AuditOrigin: withResource(acc.auditOrigin(r, c), res)})
	}
	fail := func(f *agentFailure, result string) (*agentTOTPResponse, *agentFailure) {
		record(result, f.Reason)
		return nil, f
	}
	if !validCredentialName(req.Credential) {
		return fail(&agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_request", Message: "credential is required"}, store.AuditResultDenied)
	}
	if f := applyTaskID(c, req.TaskID); f != nil {
		return fail(f, store.AuditResultDenied)
	}
	use := acc.evaluate(ctx, c, req.Credential, store.AgentActionTOTP)
	if !use.Allowed {
		f := denialFailure(use)
		result := store.AuditResultDenied
		if f.Status >= 500 {
			result = store.AuditResultError
		}
		return fail(f, result)
	}
	if use.Credential.Kind != store.AgentCredentialLogin {
		return fail(&agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "kind_not_login", Message: "TOTP codes come only from login credentials"}, store.AuditResultDenied)
	}
	doc, cred, err := s.agentLoginSecret(ctx, c, use)
	if err != nil {
		log.Printf("agent totp: login unavailable: %v", err)
		return fail(&agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: agentDenyCredentialUnavailable, Message: "the credential's secret is not available"}, store.AuditResultError)
	}
	if strings.TrimSpace(doc.TOTPSeed) == "" {
		return fail(&agentFailure{Status: http.StatusConflict, Code: "not_configured", Reason: "totp_not_configured", Message: "this login has no TOTP seed"}, store.AuditResultError)
	}
	gen, err := loginTOTP(cred.Config.Login, doc.TOTPSeed)
	if err != nil {
		return fail(totpFailure(err), store.AuditResultError)
	}
	now := time.Now()
	tok, err := gen.Mint(ctx, providertoken.Params{At: now})
	if err != nil {
		return fail(&agentFailure{Status: http.StatusInternalServerError, Code: "internal_error", Reason: "internal_error", Message: "the code could not be computed"}, store.AuditResultError)
	}
	record(store.AuditResultSuccess, "")
	if info := auditInfoFrom(ctx); info != nil && info.hasFailed() {
		return nil, &agentFailure{Status: http.StatusInternalServerError, Code: "audit_unavailable", Reason: "audit_unavailable", Message: "the audit log could not be written; the code is withheld"}
	}
	return totpResponse(req.Credential, tok, now), nil
}

// agentLoginRequest is the body of POST /v1/agent/login.
type agentLoginRequest struct {
	Credential string `json:"credential"`
	URL        string `json:"url"`
	TaskID     string `json:"taskId,omitempty"`
}

// agentLoginResponse carries a login's username and password.
type agentLoginResponse struct {
	Credential string `json:"credential"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	// URLPattern is the credential's pattern the page matched.
	URLPattern string `json:"urlPattern"`
}

// agentGetLogin returns a login's username and password for a page URL that
// matches the credential's patterns; it needs the reveal action. Audited as
// citadel.AgentGetLogin (host and path, never the query) before returning.
func (s *Server) agentGetLogin(ctx context.Context, r *http.Request, c *agentCaller, req agentLoginRequest, via string) (*agentLoginResponse, *agentFailure) {
	acc := s.agentAccess()
	host, path := auditURLParts(req.URL)
	record := func(result, reason string) {
		res := "credential=" + auditToken(req.Credential)
		if host != "" {
			res += " host=" + auditToken(host) + " path=" + auditToken(path)
		}
		res += " via=" + via
		s.recordAudit(ctx, store.AuditEvent{Action: actionAgentGetLogin, KeyID: req.Credential, Result: result, ErrorType: reason, AuditOrigin: withResource(acc.auditOrigin(r, c), res)})
	}
	fail := func(f *agentFailure, result string) (*agentLoginResponse, *agentFailure) {
		record(result, f.Reason)
		return nil, f
	}
	if !validCredentialName(req.Credential) {
		return fail(&agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_request", Message: "credential is required"}, store.AuditResultDenied)
	}
	if f := applyTaskID(c, req.TaskID); f != nil {
		return fail(f, store.AuditResultDenied)
	}
	if u, err := url.Parse(req.URL); req.URL == "" || len(req.URL) > 8192 || err != nil || u.Scheme != "https" || u.Host == "" {
		return fail(&agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_url", Message: "url must be the absolute https URL of the page the login is for"}, store.AuditResultDenied)
	}
	use := acc.evaluate(ctx, c, req.Credential, store.AgentActionReveal)
	if !use.Allowed {
		f := denialFailure(use)
		result := store.AuditResultDenied
		if f.Status >= 500 {
			result = store.AuditResultError
		}
		return fail(f, result)
	}
	if use.Credential.Kind != store.AgentCredentialLogin {
		return fail(&agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "kind_not_login", Message: "get_login works only with login credentials"}, store.AuditResultDenied)
	}
	pattern, ok := matchLoginURL(use.Credential.URLPatterns, req.URL)
	if !ok {
		return fail(&agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: "url_not_allowed", Message: "this login may not be used on that page; see the credential's urlPatterns"}, store.AuditResultDenied)
	}
	doc, _, err := s.agentLoginSecret(ctx, c, use)
	if err != nil || doc.Username == "" {
		if err == nil {
			err = errors.New("empty username")
		}
		log.Printf("agent login: login unavailable: %v", err)
		return fail(&agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: agentDenyCredentialUnavailable, Message: "the credential's secret is not available"}, store.AuditResultError)
	}
	record(store.AuditResultSuccess, "")
	if info := auditInfoFrom(ctx); info != nil && info.hasFailed() {
		return nil, &agentFailure{Status: http.StatusInternalServerError, Code: "audit_unavailable", Reason: "audit_unavailable", Message: "the audit log could not be written; the login is withheld"}
	}
	return &agentLoginResponse{Credential: req.Credential, Username: doc.Username, Password: doc.Password, URLPattern: pattern}, nil
}

// handleAgentTOTP is POST /v1/agent/totp.
func (s *Server) handleAgentTOTP(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.agentAccess().authenticate(w, r, actionAgentTOTP)
	if !ok {
		return
	}
	var req agentTOTPRequest
	if f := decodeAgentJSON(w, r, 16<<10, &req); f != nil {
		f.write(w)
		return
	}
	resp, f := s.agentTOTPCode(ctx, r, c, req, "api")
	if f != nil {
		f.write(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeNativeJSON(w, http.StatusOK, resp)
}

// handleAgentLogin is POST /v1/agent/login.
func (s *Server) handleAgentLogin(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.agentAccess().authenticate(w, r, actionAgentGetLogin)
	if !ok {
		return
	}
	var req agentLoginRequest
	if f := decodeAgentJSON(w, r, 16<<10, &req); f != nil {
		f.write(w)
		return
	}
	resp, f := s.agentGetLogin(ctx, r, c, req, "api")
	if f != nil {
		f.write(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeNativeJSON(w, http.StatusOK, resp)
}

// ---- console: login fields --------------------------------------------------

// agentLoginStateJSON is a login's non-secret state for the console. The
// password and TOTP seed are never returned.
type agentLoginStateJSON struct {
	Name        string `json:"name"`
	Username    string `json:"username"`
	HasPassword bool   `json:"hasPassword"`
	HasTOTPSeed bool   `json:"hasTotpSeed"`
	// TOTPStatus is "" (no seed), "ok", "sha1_unsupported" or "invalid";
	// TOTPMessage explains a problem.
	TOTPStatus  string `json:"totpStatus,omitempty"`
	TOTPMessage string `json:"totpMessage,omitempty"`
	// TOTP is the current code when the request asked for a preview.
	TOTP *agentTOTPResponse `json:"totp,omitempty"`
}

// loadLoginCredential reads a login credential and its secret's native
// coordinates for the console handlers.
func (s *Server) loadLoginCredential(w http.ResponseWriter, ctx context.Context, sess *uiSession, name string) (store.AgentCredential, parsedItem, bool) {
	if !agentCredNameRe.MatchString(name) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return store.AgentCredential{}, parsedItem{}, false
	}
	cred, err := s.store.GetAgentCredential(ctx, s.agentAccount(ctx, sess), name)
	if errors.Is(err, store.ErrAgentCredentialNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "agent credential not found")
		return store.AgentCredential{}, parsedItem{}, false
	}
	if err != nil {
		log.Printf("agents: credential read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not read the credential")
		return store.AgentCredential{}, parsedItem{}, false
	}
	if cred.Kind != store.AgentCredentialLogin {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "the credential is not a login")
		return store.AgentCredential{}, parsedItem{}, false
	}
	pi, ok := parseSecretName(cred.SecretName)
	if !ok {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "login fields can be edited only for secrets in a project and environment")
		return store.AgentCredential{}, parsedItem{}, false
	}
	return cred, pi, true
}

// loginState describes doc for the console.
func loginState(name string, cred store.AgentCredential, doc loginDoc, preview bool, now time.Time) agentLoginStateJSON {
	out := agentLoginStateJSON{Name: name, Username: doc.Username, HasPassword: doc.Password != "", HasTOTPSeed: strings.TrimSpace(doc.TOTPSeed) != ""}
	if !out.HasTOTPSeed {
		return out
	}
	gen, err := loginTOTP(cred.Config.Login, doc.TOTPSeed)
	switch {
	case errors.Is(err, providertoken.ErrSHA1Unsupported):
		out.TOTPStatus, out.TOTPMessage = "sha1_unsupported", agentFIPSSHA1Message
	case err != nil:
		out.TOTPStatus, out.TOTPMessage = "invalid", totpFailure(err).Message
	default:
		out.TOTPStatus = "ok"
		if preview {
			if tok, err := gen.Mint(context.Background(), providertoken.Params{At: now}); err == nil {
				out.TOTP = totpResponse(name, tok, now)
			}
		}
	}
	return out
}

// handleV1GetAgentLogin is GET /v1/agents/credentials/login?name=[&code=true]:
// the login's username, whether a password and TOTP seed are set, and with
// code=true the current TOTP code (a live preview for the console).
func (s *Server) handleV1GetAgentLogin(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	cred, _, ok := s.loadLoginCredential(w, ctx, sess, strings.TrimSpace(q.Get("name")))
	if !ok {
		return
	}
	if !s.requireReveal(w, r, ctx, sess, auditReadAgentLogin) {
		return
	}
	ref, err := s.agentSecretRef(ctx, cred.AccountID, cred.SecretName)
	var doc loginDoc
	if err == nil {
		var v string
		if v, err = s.agentSecretValue(ctx, cred.AccountID, ref); err == nil {
			doc, err = parseLoginDoc(v)
		}
	}
	if err != nil {
		writeNativeError(w, http.StatusConflict, "credential_unavailable", "the login's secret is missing or is not JSON {username, password, totpSeed?}")
		return
	}
	preview := q.Get("code") == "true"
	o := s.auditOrigin(r)
	o.Resource = cred.SecretName
	if preview {
		o.Resource += " totpPreview=true"
	}
	s.recordAudit(ctx, store.AuditEvent{Action: auditReadAgentLogin, KeyID: cred.Name, Result: "ok", AuditOrigin: o})
	w.Header().Set("Cache-Control", "no-store")
	writeNativeJSON(w, http.StatusOK, loginState(cred.Name, cred, doc, preview, time.Now()))
}

// agentLoginInput is the body of POST /v1/agents/credentials/login. Omitted
// fields keep their current values.
type agentLoginInput struct {
	Name          string  `json:"name"`
	Username      *string `json:"username"`
	Password      *string `json:"password"`
	TOTPSeed      *string `json:"totpSeed"`
	ClearTOTPSeed bool    `json:"clearTotpSeed"`
}

// handleV1PutAgentLogin is POST /v1/agents/credentials/login: writes the
// login's username, password and TOTP seed as a new version of its secret.
// A seed that can't produce codes (SHA-1 in FIPS mode, malformed) is
// refused.
func (s *Server) handleV1PutAgentLogin(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentLoginInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	cred, pi, ok := s.loadLoginCredential(w, ctx, sess, strings.TrimSpace(in.Name))
	if !ok {
		return
	}
	coord := itemCoord{Project: pi.Project, Env: pi.Env, Folder: pi.Folder, Key: pi.Key}
	if !s.requireNoApproval(w, r, ctx, coord.Project, coord.Env, auditPutAgentLogin) {
		return
	}
	var doc loginDoc
	if ref, err := s.agentSecretRef(ctx, cred.AccountID, cred.SecretName); err == nil {
		if v, err := s.agentSecretValue(ctx, cred.AccountID, ref); err == nil {
			doc, _ = parseLoginDoc(v) // a non-JSON value is replaced
		}
	}
	changed := []string{}
	if in.Username != nil {
		u := strings.TrimSpace(*in.Username)
		if !printable(u, maxLoginFieldLen) {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "username must be 1-1024 printable characters")
			return
		}
		doc.Username = u
		changed = append(changed, "username")
	}
	if in.Password != nil {
		if len(*in.Password) > maxLoginFieldLen {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "password must be at most 1024 characters")
			return
		}
		doc.Password = *in.Password
		changed = append(changed, "password")
	}
	switch {
	case in.ClearTOTPSeed:
		doc.TOTPSeed = ""
		changed = append(changed, "totpSeed")
	case in.TOTPSeed != nil && strings.TrimSpace(*in.TOTPSeed) != "":
		seed := strings.TrimSpace(*in.TOTPSeed)
		if len(seed) > maxTOTPSeedLen {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "the TOTP seed is too long")
			return
		}
		if _, err := loginTOTP(cred.Config.Login, seed); err != nil {
			if errors.Is(err, providertoken.ErrSHA1Unsupported) {
				writeNativeError(w, http.StatusBadRequest, "totp_sha1_unsupported", agentFIPSSHA1Message)
				return
			}
			writeNativeError(w, http.StatusBadRequest, "invalid_totp_seed", "the TOTP seed is not usable: "+strings.TrimPrefix(err.Error(), "providertoken: totp: "))
			return
		}
		doc.TOTPSeed = seed
		changed = append(changed, "totpSeed")
	}
	if doc.Username == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "the login needs a username")
		return
	}
	if len(changed) == 0 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "nothing to change")
		return
	}
	value, err := json.Marshal(doc)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not encode the login")
		return
	}
	if _, err := s.secretsSvc().PutItem(ctx, coord, string(value), ""); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "put_failed", err)
		return
	}
	o := s.auditOrigin(r)
	o.Resource = cred.SecretName + " fields=" + strings.Join(changed, ",")
	s.recordAudit(ctx, store.AuditEvent{Action: auditPutAgentLogin, KeyID: cred.Name, Result: "ok", AuditOrigin: o})
	writeNativeJSON(w, http.StatusOK, loginState(cred.Name, cred, doc, false, time.Now()))
}
