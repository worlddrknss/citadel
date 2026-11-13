package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/oidclogin"
	"github.com/worlddrknss/citadel/internal/store"
)

// Console single sign-on (OIDC authorization code flow with PKCE).
//
//	GET /v1/auth/oidc/{id}/start?returnTo=/app/...  -> 302 to the IdP
//	GET /v1/auth/oidc/{id}/callback                 -> session cookie, 302 returnTo
//
// The callback URL registered at the IdP is
// <KMS_PUBLIC_URL>/v1/auth/oidc/{id}/callback, so SSO needs KMS_PUBLIC_URL.
// The per-login state lives in a cookie sealed with keys HKDF-derived from
// the wrapping key, and each state is consumed once in the store (shared by
// replicas). Users are provisioned just in time, keyed by (provider,
// subject) — never by email — and their memberships follow the provider's
// group-to-role mapping on every sign-in. Failures redirect to
// /app/?sso_error=access_denied|no_role|state_mismatch|provider_error and
// are audited as citadel.LoginSSO.

const (
	ssoErrAccessDenied  = "access_denied"
	ssoErrNoRole        = "no_role"
	ssoErrStateMismatch = "state_mismatch"
	ssoErrProvider      = "provider_error"
	ssoDefaultReturn    = "/app/"
)

// ssoRedirectURI is the callback URL for provider id ("" without
// KMS_PUBLIC_URL).
func (s *Server) ssoRedirectURI(id string) string {
	base := s.publicURL()
	if base == "" {
		return ""
	}
	return base + "/v1/auth/oidc/" + url.PathEscape(id) + "/callback"
}

// storeReplay adapts the store's single-use table to oidclogin.ReplayStore.
type storeReplay struct{ st store.Store }

func (r storeReplay) Consume(ctx context.Context, id string, expires time.Time) (bool, error) {
	return r.st.ConsumeOnce(ctx, "oidc-state:"+id, expires)
}

func (s *Server) sealSSOSecret(providerID, secret string) ([]byte, error) {
	key, ok := s.deriveIdentityKey("sso-client-secret")
	if !ok {
		return nil, errors.New("no wrapping key configured")
	}
	return cryptoutil.GCMSeal(key, []byte(secret), []byte("citadel-sso-client-secret|"+providerID))
}

func (s *Server) openSSOSecret(providerID string, sealed []byte) (string, error) {
	key, ok := s.deriveIdentityKey("sso-client-secret")
	if !ok {
		return "", errors.New("no wrapping key configured")
	}
	plain, err := cryptoutil.GCMOpen(key, sealed, []byte("citadel-sso-client-secret|"+providerID))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ssoRelyingParty returns the relying party for provider p, cached per
// provider version so discovery results are reused.
func (s *Server) ssoRelyingParty(ctx context.Context, p store.SSOProvider) (*oidclogin.RelyingParty, error) {
	redirect := s.ssoRedirectURI(p.ID)
	if redirect == "" {
		return nil, errors.New("KMS_PUBLIC_URL is not set")
	}
	cookieKey, ok := s.deriveIdentityKey("sso-state-cookie")
	if !ok {
		return nil, errors.New("no wrapping key configured")
	}
	st := s.identity()
	cacheKey := p.ID + "\x00" + strconv.FormatInt(p.UpdatedAt.UnixNano(), 10)
	st.rpMu.Lock()
	rp, ok := st.rps[cacheKey]
	st.rpMu.Unlock()
	if ok {
		return rp, nil
	}
	sealed, err := s.store.GetSSOProviderSecret(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if len(sealed) == 0 {
		return nil, errors.New("provider has no client secret")
	}
	secret, err := s.openSSOSecret(p.ID, sealed)
	if err != nil {
		return nil, fmt.Errorf("open client secret: %w", err)
	}
	rp, err = oidclogin.New(oidclogin.Config{
		Providers: []oidclogin.ProviderConfig{{
			ID: p.ID, Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: secret,
			Scopes: p.Scopes, RedirectURL: redirect, GroupsClaim: p.GroupClaim,
			AllowedEmailDomains: p.AllowedEmailDomains,
		}},
		CookieKeys:        [][]byte{cookieKey},
		InsecureCookies:   !s.cfg.UISecureCookies,
		HTTPClient:        st.httpClient,
		AllowInsecureHTTP: s.insecureIdentityURLs(),
		ReplayStore:       storeReplay{s.store},
		Now:               st.now,
	})
	if err != nil {
		return nil, err
	}
	st.rpMu.Lock()
	for k := range st.rps {
		if strings.HasPrefix(k, p.ID+"\x00") {
			delete(st.rps, k)
		}
	}
	st.rps[cacheKey] = rp
	st.rpMu.Unlock()
	return rp, nil
}

func ssoErrorRedirect(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, ssoDefaultReturn+"?sso_error="+url.QueryEscape(code), http.StatusFound)
}

// auditSSO records a citadel.LoginSSO event. actor is the signed-in user, or
// "sso:<provider>[:<subject>]" when no user was resolved.
func (s *Server) auditSSO(r *http.Request, providerID, actor, accountID, result, errType string) {
	if actor == "" {
		actor = "sso:" + providerID
	}
	ev := store.AuditEvent{Action: "citadel.LoginSSO", KeyID: providerID, Result: result, ErrorType: errType, AuditOrigin: s.userAuditOrigin(r, truncate(actor, 200), accountID)}
	ctx := r.Context()
	if accountID != "" {
		ctx = store.WithCallerAccount(ctx, accountID)
	}
	s.recordAudit(ctx, ev)
}

// enabledSSOProvider loads provider id when it exists and is enabled.
func (s *Server) enabledSSOProvider(ctx context.Context, id string) (store.SSOProvider, bool) {
	if id == "" || len(id) > 64 {
		return store.SSOProvider{}, false
	}
	p, err := s.store.GetSSOProvider(ctx, id)
	if err != nil {
		if !errors.Is(err, store.ErrSSOProviderNotFound) {
			slog.Error("sso: load provider", "error", err)
		}
		return store.SSOProvider{}, false
	}
	return p, p.Enabled
}

func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ip := s.clientIP(r)
	ok, _ := s.identity().ssoIP.Reserve(ip)
	if ok {
		ok, _ = s.sharedAllow(r.Context(), sharedLimitCheck{sharedLimitSSOIP, ip})
	}
	if !ok {
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	p, ok := s.enabledSSOProvider(r.Context(), id)
	if !ok {
		s.auditSSO(r, truncate(id, 64), "", "", "denied", "ProviderUnavailable")
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	rp, err := s.ssoRelyingParty(r.Context(), p)
	if err != nil {
		slog.Error("sso: provider", "provider", p.ID, "error", err)
		s.auditSSO(r, p.ID, "", p.AccountID, "error", "ProviderMisconfigured")
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	returnTo, err := oidclogin.ValidateReturnTo(r.URL.Query().Get("returnTo"))
	if err != nil || returnTo == "/" {
		returnTo = ssoDefaultReturn
	}
	authURL, cookie, err := rp.Start(r.Context(), p.ID, returnTo)
	if err != nil {
		slog.Error("sso: start", "provider", p.ID, "error", err)
		s.auditSSO(r, p.ID, "", p.AccountID, "error", "DiscoveryFailed")
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ssoErrorCode maps a Callback error to the redirect code and audit type.
func ssoErrorCode(err error) (code, errType string) {
	switch {
	case errors.Is(err, oidclogin.ErrStateMissing), errors.Is(err, oidclogin.ErrStateInvalid),
		errors.Is(err, oidclogin.ErrStateReplayed), errors.Is(err, oidclogin.ErrUnknownProvider):
		return ssoErrStateMismatch, "StateMismatch"
	case errors.Is(err, oidclogin.ErrEmailDomain):
		return ssoErrAccessDenied, "EmailDomainNotAllowed"
	case errors.Is(err, oidclogin.ErrProvider) && strings.Contains(err.Error(), "access_denied"):
		return ssoErrAccessDenied, "AccessDenied"
	}
	return ssoErrProvider, "ProviderError"
}

func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, ok := s.enabledSSOProvider(r.Context(), id)
	if !ok {
		s.auditSSO(r, truncate(id, 64), "", "", "denied", "ProviderUnavailable")
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	rp, err := s.ssoRelyingParty(r.Context(), p)
	if err != nil {
		slog.Error("sso: provider", "provider", p.ID, "error", err)
		s.auditSSO(r, p.ID, "", p.AccountID, "error", "ProviderMisconfigured")
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	ident, err := rp.Callback(r.Context(), r)
	http.SetCookie(w, rp.ClearCookie())
	if err != nil {
		code, errType := ssoErrorCode(err)
		slog.Error("sso: callback", "provider", p.ID, "error", err)
		s.auditSSO(r, p.ID, "", p.AccountID, "denied", errType)
		ssoErrorRedirect(w, r, code)
		return
	}
	subjectActor := "sso:" + p.ID + ":" + ident.Subject
	memberships, err := s.ssoMemberships(r.Context(), p, ident.Groups)
	if err != nil {
		if !errors.Is(err, oidclogin.ErrNoMembership) {
			slog.Error("sso: role mapping", "provider", p.ID, "error", err)
		}
		s.auditSSO(r, p.ID, subjectActor, p.AccountID, "denied", "NoRole")
		ssoErrorRedirect(w, r, ssoErrNoRole)
		return
	}
	// Write-ahead: provisioning and the session are changes.
	attemptCtx := r.Context()
	if p.AccountID != "" {
		attemptCtx = store.WithCallerAccount(attemptCtx, p.AccountID)
	}
	if err := s.beginAuditAttempt(attemptCtx, store.AuditEvent{Action: "citadel.LoginSSO", KeyID: p.ID, AuditOrigin: s.userAuditOrigin(r, truncate(subjectActor, 200), p.AccountID)}); err != nil {
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	username, err := s.ssoProvisionUser(r.Context(), p, ident)
	if err != nil {
		slog.Error("sso: provision", "provider", p.ID, "error", err)
		s.auditSSO(r, p.ID, subjectActor, p.AccountID, "error", "ProvisioningFailed")
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	if err := s.syncSSOMemberships(r.Context(), username, memberships); err != nil {
		slog.Error("sso: memberships", "user", username, "error", err)
		s.auditSSO(r, p.ID, username, p.AccountID, "error", "ProvisioningFailed")
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	account := memberships[0].Account
	for _, m := range memberships {
		if m.Account == p.AccountID {
			account = m.Account
		}
	}
	if _, err := s.issueConsoleSession(r.Context(), w, r, username, account, store.SessionMethodSSO); err != nil {
		slog.Error("sso: create session", "error", err)
		s.auditSSO(r, p.ID, username, account, "error", "SessionFailed")
		ssoErrorRedirect(w, r, ssoErrProvider)
		return
	}
	s.auditSSO(r, p.ID, username, account, "ok", "")
	returnTo := ident.ReturnTo
	if returnTo == "" || returnTo == "/" {
		returnTo = ssoDefaultReturn
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// ssoMemberships resolves the provider's mapping for groups: rules for "*"
// expand to every account, the default role applies to the provider's
// account, and accounts that no longer exist are dropped.
func (s *Server) ssoMemberships(ctx context.Context, p store.SSOProvider, groups []string) ([]oidclogin.Membership, error) {
	accounts, err := s.store.ListUIAccounts(ctx)
	if err != nil {
		return nil, err
	}
	exists := map[string]bool{}
	for _, a := range accounts {
		exists[a.AccountID] = true
	}
	m := oidclogin.RoleMapping{}
	for _, rm := range p.RoleMappings {
		if rm.AccountID == "*" {
			for _, a := range accounts {
				m.Rules = append(m.Rules, oidclogin.RoleRule{Group: rm.Group, Account: a.AccountID, Role: oidclogin.Role(rm.Role)})
			}
			continue
		}
		if exists[rm.AccountID] {
			m.Rules = append(m.Rules, oidclogin.RoleRule{Group: rm.Group, Account: rm.AccountID, Role: oidclogin.Role(rm.Role)})
		}
	}
	if p.DefaultRole != "" && p.DefaultRole != "none" && exists[p.AccountID] {
		m.DefaultAccount, m.DefaultRole = p.AccountID, oidclogin.Role(p.DefaultRole)
	}
	return m.Resolve(groups)
}

var usernameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._@-]+`)

// ssoUsernameCandidate derives a readable username from the identity.
func ssoUsernameCandidate(ident oidclogin.Identity) string {
	for _, c := range []string{ident.Username, ident.Email} {
		c = strings.Trim(usernameUnsafe.ReplaceAllString(strings.TrimSpace(c), "-"), "-._@")
		if len(c) > 48 {
			c = c[:48]
		}
		if usernameRe.MatchString(c) {
			return c
		}
	}
	return "sso-user"
}

// ssoProvisionUser returns the console user linked to (provider, subject),
// creating one on first sign-in. A new user never takes over an existing
// username: on a clash a random suffix is added.
func (s *Server) ssoProvisionUser(ctx context.Context, p store.SSOProvider, ident oidclogin.Identity) (string, error) {
	now := time.Now().UTC()
	email := truncate(ident.Email, 320)
	if link, err := s.store.GetExternalIdentity(ctx, p.ID, ident.Subject); err == nil {
		if _, found := s.lookupUser(ctx, link.Username); found {
			if err := s.store.TouchExternalIdentity(ctx, p.ID, ident.Subject, email, now); err != nil {
				slog.Error("sso: touch identity", "error", err)
			}
			return link.Username, nil
		}
		return "", errors.New("linked user no longer exists")
	} else if !errors.Is(err, store.ErrExternalIdentityNotFound) {
		return "", err
	}
	if ident.Subject == "" || len(ident.Subject) > 255 {
		return "", errors.New("unusable subject")
	}
	base := ssoUsernameCandidate(ident)
	username := ""
	for i := 0; i < 5; i++ {
		cand := base
		if i > 0 {
			cand = base + "-" + cryptoutil.RandomHex(3)
		}
		if _, err := s.store.GetUIUser(ctx, cand); errors.Is(err, store.ErrUIUserNotFound) {
			if _, env := s.envUsers()[cand]; !env {
				username = cand
				break
			}
		} else if err != nil {
			return "", err
		}
	}
	if username == "" {
		return "", errors.New("no free username")
	}
	// SSO users have no usable password: a hash of a random secret nobody
	// knows (never a plaintext value, which VerifyPassword would accept).
	hash, err := cryptoutil.HashPassword(cryptoutil.RandomHex(32))
	if err != nil {
		return "", err
	}
	display := strings.TrimSpace(ident.Name)
	if !validDisplayText(display, 100) {
		display = username
	}
	if err := s.store.UpsertUIUser(ctx, store.UIUser{Username: username, PasswordHash: hash, Role: "viewer", DisplayName: display}); err != nil {
		return "", err
	}
	err = s.store.CreateExternalIdentity(ctx, store.ExternalIdentity{ProviderID: p.ID, Subject: ident.Subject, Username: username, Email: email, CreatedAt: now, LastLoginAt: now})
	if errors.Is(err, store.ErrExternalIdentityExists) {
		// A concurrent first sign-in won; use its user.
		_ = s.store.DeleteUIUser(ctx, username)
		link, gerr := s.store.GetExternalIdentity(ctx, p.ID, ident.Subject)
		if gerr != nil {
			return "", gerr
		}
		return link.Username, nil
	}
	if err != nil {
		_ = s.store.DeleteUIUser(ctx, username)
		return "", err
	}
	return username, nil
}

// syncSSOMemberships makes username's memberships exactly ms.
func (s *Server) syncSSOMemberships(ctx context.Context, username string, ms []oidclogin.Membership) error {
	current, err := s.store.ListUserAccounts(ctx, username)
	if err != nil {
		return err
	}
	want := map[string]string{}
	for _, m := range ms {
		want[m.Account] = string(m.Role)
	}
	for _, c := range current {
		if _, keep := want[c.AccountID]; !keep {
			if err := s.store.RemoveUserAccount(ctx, username, c.AccountID); err != nil {
				return err
			}
		}
	}
	for acct, role := range want {
		have := slices.IndexFunc(current, func(c store.UserAccountInfo) bool { return c.AccountID == acct && strings.EqualFold(c.Role, role) })
		if have >= 0 {
			continue
		}
		if err := s.store.AddUserAccount(ctx, username, acct, role); err != nil {
			return err
		}
	}
	return nil
}
