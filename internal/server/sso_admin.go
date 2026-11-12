package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/jose"
	"github.com/worlddrknss/citadel/internal/store"
)

// Console SSO provider administration (/v1/admin/sso/providers).
//
// A provider belongs to the account it was created in: its default role is
// granted there. A provider "applies org-wide" when a role mapping targets
// every account ("*") or any account other than its own; only platform
// admins may create, change, delete or test such providers. An account
// admin manages the providers of their current account that stay within it.
// Client secrets are sealed with AES-256-GCM under a key HKDF-derived from
// the wrapping key and are never returned.

type ssoProviderJSON struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Issuer              string                 `json:"issuer"`
	ClientID            string                 `json:"clientId"`
	ClientSecretSet     bool                   `json:"clientSecretSet"`
	Scopes              []string               `json:"scopes"`
	GroupClaim          string                 `json:"groupClaim"`
	RoleMappings        []store.SSORoleMapping `json:"roleMappings"`
	DefaultRole         string                 `json:"defaultRole"`
	Enabled             bool                   `json:"enabled"`
	RedirectURI         string                 `json:"redirectUri"`
	AccountID           string                 `json:"accountId"`
	AllowedEmailDomains []string               `json:"allowedEmailDomains"`
	CreatedAt           string                 `json:"createdAt"`
	UpdatedAt           string                 `json:"updatedAt"`
}

type ssoProviderInput struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Issuer              string                 `json:"issuer"`
	ClientID            string                 `json:"clientId"`
	ClientSecret        *string                `json:"clientSecret"`
	Scopes              []string               `json:"scopes"`
	GroupClaim          string                 `json:"groupClaim"`
	RoleMappings        []store.SSORoleMapping `json:"roleMappings"`
	DefaultRole         string                 `json:"defaultRole"`
	Enabled             bool                   `json:"enabled"`
	AllowedEmailDomains []string               `json:"allowedEmailDomains"`
}

func (s *Server) ssoProviderOut(p store.SSOProvider) ssoProviderJSON {
	out := ssoProviderJSON{
		ID: p.ID, Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID, ClientSecretSet: p.ClientSecretSet,
		Scopes: p.Scopes, GroupClaim: p.GroupClaim, RoleMappings: p.RoleMappings, DefaultRole: p.DefaultRole,
		Enabled: p.Enabled, RedirectURI: s.ssoRedirectURI(p.ID), AccountID: p.AccountID,
		AllowedEmailDomains: p.AllowedEmailDomains,
		CreatedAt:           p.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: p.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if out.Scopes == nil {
		out.Scopes = []string{}
	}
	if out.RoleMappings == nil {
		out.RoleMappings = []store.SSORoleMapping{}
	}
	if out.AllowedEmailDomains == nil {
		out.AllowedEmailDomains = []string{}
	}
	if out.DefaultRole == "" {
		out.DefaultRole = "none"
	}
	return out
}

// ssoOrgWide reports whether p grants roles outside its own account.
func ssoOrgWide(p store.SSOProvider) bool {
	for _, m := range p.RoleMappings {
		if m.AccountID != p.AccountID {
			return true
		}
	}
	return false
}

// canManageSSO reports whether sess may administer p.
func canManageSSO(sess *uiSession, p store.SSOProvider) bool {
	if sess.PlatformAdmin {
		return true
	}
	return p.AccountID == sess.AccountID && !ssoOrgWide(p)
}

var (
	scopeRe       = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]{1,64}$`)
	claimNameRe   = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	emailDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

func printable(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validateSSOInput checks in and fills p (except ID, timestamps, account).
func (s *Server) validateSSOInput(ctx context.Context, in ssoProviderInput, p *store.SSOProvider) string {
	p.Name = strings.TrimSpace(in.Name)
	p.Issuer = strings.TrimSpace(in.Issuer)
	p.ClientID = strings.TrimSpace(in.ClientID)
	p.GroupClaim = strings.TrimSpace(in.GroupClaim)
	p.DefaultRole = strings.ToLower(strings.TrimSpace(in.DefaultRole))
	p.Enabled = in.Enabled
	if !validDisplayText(p.Name, 100) {
		return "name must be 1-100 characters"
	}
	if err := jose.CheckURL(p.Issuer, s.insecureIdentityURLs()); err != nil || len(p.Issuer) > 512 || strings.ContainsAny(p.Issuer, "?#") {
		return "issuer must be an https URL without query or fragment"
	}
	if !printable(p.ClientID, 256) {
		return "clientId must be 1-256 printable characters"
	}
	if p.GroupClaim != "" && !claimNameRe.MatchString(p.GroupClaim) {
		return "invalid groupClaim"
	}
	switch p.DefaultRole {
	case "":
		p.DefaultRole = "none"
	case "none", "viewer", "editor", "admin":
	default:
		return "defaultRole must be none, viewer, editor or admin"
	}
	if len(in.Scopes) > 20 {
		return "at most 20 scopes"
	}
	p.Scopes = nil
	for _, sc := range in.Scopes {
		sc = strings.TrimSpace(sc)
		if !scopeRe.MatchString(sc) {
			return "invalid scope"
		}
		if !slices.Contains(p.Scopes, sc) {
			p.Scopes = append(p.Scopes, sc)
		}
	}
	if len(in.RoleMappings) > 100 {
		return "at most 100 role mappings"
	}
	accounts, err := s.store.ListUIAccounts(ctx)
	if err != nil {
		slog.Error("sso admin: list accounts", "error", err)
		return "could not validate accounts"
	}
	p.RoleMappings = nil
	for _, m := range in.RoleMappings {
		m.Group = strings.TrimSpace(m.Group)
		m.AccountID = strings.TrimSpace(m.AccountID)
		m.Role = strings.ToLower(strings.TrimSpace(m.Role))
		if !printable(m.Group, 256) {
			return "role mapping group must be 1-256 printable characters"
		}
		if !validRoleName(m.Role) {
			return "role mapping role must be viewer, editor or admin"
		}
		if m.AccountID != "*" && !slices.ContainsFunc(accounts, func(a store.UIAccountInfo) bool { return a.AccountID == m.AccountID }) {
			return "role mapping account does not exist"
		}
		p.RoleMappings = append(p.RoleMappings, m)
	}
	if len(in.AllowedEmailDomains) > 50 {
		return "at most 50 email domains"
	}
	p.AllowedEmailDomains = nil
	for _, d := range in.AllowedEmailDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !emailDomainRe.MatchString(d) || len(d) > 253 {
			return "invalid email domain"
		}
		if !slices.Contains(p.AllowedEmailDomains, d) {
			p.AllowedEmailDomains = append(p.AllowedEmailDomains, d)
		}
	}
	return ""
}

func (s *Server) handleV1ListSSOProviders(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	ps, err := s.store.ListSSOProviders(ctx, false)
	if err != nil {
		slog.Error("sso admin: list", "error", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list SSO providers")
		return
	}
	out := []ssoProviderJSON{}
	for _, p := range ps {
		if sess.PlatformAdmin || p.AccountID == sess.AccountID {
			out = append(out, s.ssoProviderOut(p))
		}
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

// ssoAdminSession requires an admin console session (access keys cannot
// manage sign-in configuration).
func (s *Server) ssoAdminSession(w http.ResponseWriter, r *http.Request) (*uiSession, context.Context, bool) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return nil, nil, false
	}
	if sess.ViaToken {
		writeNativeError(w, http.StatusForbidden, "forbidden", "this action requires a console session")
		return nil, nil, false
	}
	return sess, ctx, true
}

func (s *Server) handleV1CreateSSOProvider(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.CreateSSOProvider"
	sess, ctx, ok := s.ssoAdminSession(w, r)
	if !ok {
		return
	}
	var in ssoProviderInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if s.publicURL() == "" {
		writeNativeError(w, http.StatusConflict, "not_configured", "set KMS_PUBLIC_URL to use single sign-on")
		return
	}
	p := store.SSOProvider{AccountID: sess.AccountID}
	if msg := s.validateSSOInput(ctx, in, &p); msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	if in.ClientSecret == nil || !printable(*in.ClientSecret, 1024) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "clientSecret is required")
		return
	}
	if !canManageSSO(sess, p) {
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "denied", ErrorType: "AccessDenied", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "forbidden", "only platform admins can map roles outside the current account")
		return
	}
	p.ID = "sso-" + cryptoutil.RandomHex(6)
	sealed, err := s.sealSSOSecret(p.ID, *in.ClientSecret)
	if err != nil {
		slog.Error("sso admin: seal secret", "error", err)
		writeNativeError(w, http.StatusConflict, "not_configured", "single sign-on needs a configured wrapping key")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	p.CreatedAt, p.UpdatedAt = now, now
	if err := s.store.CreateSSOProvider(ctx, p, sealed); err != nil {
		slog.Error("sso admin: create", "error", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the SSO provider")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: p.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusCreated, map[string]string{"id": p.ID, "redirectUri": s.ssoRedirectURI(p.ID)})
}

// loadManagedSSO loads provider id and checks sess may manage it. It writes
// the error response (404 for providers the caller may not see).
func (s *Server) loadManagedSSO(w http.ResponseWriter, r *http.Request, ctx context.Context, sess *uiSession, id, action string) (store.SSOProvider, bool) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 64 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return store.SSOProvider{}, false
	}
	p, err := s.store.GetSSOProvider(ctx, id)
	if errors.Is(err, store.ErrSSOProviderNotFound) || (err == nil && !sess.PlatformAdmin && p.AccountID != sess.AccountID) {
		writeNativeError(w, http.StatusNotFound, "not_found", "SSO provider not found")
		return store.SSOProvider{}, false
	}
	if err != nil {
		slog.Error("sso admin: load", "error", err)
		writeNativeError(w, http.StatusInternalServerError, "load_failed", "could not load the SSO provider")
		return store.SSOProvider{}, false
	}
	if !canManageSSO(sess, p) {
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: p.ID, Result: "denied", ErrorType: "AccessDenied", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "forbidden", "this provider applies outside your account; only platform admins can manage it")
		return store.SSOProvider{}, false
	}
	return p, true
}

func (s *Server) handleV1UpdateSSOProvider(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.UpdateSSOProvider"
	sess, ctx, ok := s.ssoAdminSession(w, r)
	if !ok {
		return
	}
	var in ssoProviderInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	cur, ok := s.loadManagedSSO(w, r, ctx, sess, in.ID, action)
	if !ok {
		return
	}
	next := store.SSOProvider{ID: cur.ID, AccountID: cur.AccountID, CreatedAt: cur.CreatedAt}
	if msg := s.validateSSOInput(ctx, in, &next); msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	if !canManageSSO(sess, next) {
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: cur.ID, Result: "denied", ErrorType: "AccessDenied", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "forbidden", "only platform admins can map roles outside the provider's account")
		return
	}
	var sealed []byte
	if in.ClientSecret != nil {
		if !printable(*in.ClientSecret, 1024) {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "clientSecret must be 1-1024 printable characters")
			return
		}
		var err error
		if sealed, err = s.sealSSOSecret(cur.ID, *in.ClientSecret); err != nil {
			slog.Error("sso admin: seal secret", "error", err)
			writeNativeError(w, http.StatusConflict, "not_configured", "single sign-on needs a configured wrapping key")
			return
		}
	}
	next.UpdatedAt = time.Now().UTC()
	if !next.UpdatedAt.After(cur.UpdatedAt) {
		next.UpdatedAt = cur.UpdatedAt.Add(time.Millisecond)
	}
	if err := s.store.UpdateSSOProvider(ctx, next, sealed); err != nil {
		slog.Error("sso admin: update", "error", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not update the SSO provider")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: cur.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"id": cur.ID, "updated": true})
}

func (s *Server) handleV1DeleteSSOProvider(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.DeleteSSOProvider"
	sess, ctx, ok := s.ssoAdminSession(w, r)
	if !ok {
		return
	}
	p, ok := s.loadManagedSSO(w, r, ctx, sess, r.URL.Query().Get("id"), action)
	if !ok {
		return
	}
	if err := s.store.DeleteSSOProvider(ctx, p.ID); err != nil {
		slog.Error("sso admin: delete", "error", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the SSO provider")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: p.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// handleV1TestSSOProvider fetches the provider's discovery document and
// reports whether it is usable. Only categorized messages are returned.
func (s *Server) handleV1TestSSOProvider(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.ssoAdminSession(w, r)
	if !ok {
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	p, ok := s.loadManagedSSO(w, r, ctx, sess, in.ID, "citadel.TestSSOProvider")
	if !ok {
		return
	}
	rp, err := s.ssoRelyingParty(ctx, p)
	if err != nil {
		slog.Warn("sso admin: provider test failed", "provider", p.ID, "error", err)
		writeNativeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "the provider configuration is incomplete (KMS_PUBLIC_URL, client secret or wrapping key)"})
		return
	}
	doc, err := rp.Discover(ctx, p.ID)
	if err != nil {
		slog.Warn("sso admin: provider test failed", "provider", p.ID, "error", err)
		writeNativeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "could not fetch a valid discovery document from the issuer (check the issuer URL; it must match the document's issuer exactly and support S256 PKCE)"})
		return
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "discovery document fetched", "authorizationEndpoint": doc.AuthorizationEndpoint})
}
