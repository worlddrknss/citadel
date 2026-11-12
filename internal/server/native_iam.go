package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"
)

// Native /v1 IAM endpoints backing the web console's Identity & Access page.
// These manage the OIDC providers and roles consumed by Citadel's STS service.
// They are JSON (not the AWS Query protocol) and reuse the existing native
// session/account-scoping plumbing.

type nativeOIDCProvider struct {
	ProviderArn string   `json:"providerArn"`
	Url         string   `json:"url"`
	ClientIds   []string `json:"clientIds"`
	CreatedAt   string   `json:"createdAt"`
}

type nativeTrustPolicy struct {
	Type        string   `json:"type"`
	ProviderUrl string   `json:"providerUrl,omitempty"`
	Audiences   []string `json:"audiences,omitempty"`
	Subjects    []string `json:"subjects,omitempty"`
	Principals  []string `json:"principals,omitempty"`
}

type nativeRole struct {
	RoleArn        string            `json:"roleArn"`
	RoleName       string            `json:"roleName"`
	Description    string            `json:"description"`
	Trust          nativeTrustPolicy `json:"trust"`
	MaxSessionSecs int               `json:"maxSessionSeconds"`
	CreatedAt      string            `json:"createdAt"`
	UpdatedAt      string            `json:"updatedAt"`
}

// ---- OIDC providers --------------------------------------------------------

func (s *Server) handleV1ListOIDCProviders(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	providers, err := s.store.ListOIDCProviders(ctx, sess.AccountID)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]nativeOIDCProvider, 0, len(providers))
	for _, p := range providers {
		out = append(out, nativeOIDCProvider{
			ProviderArn: p.ProviderARN,
			Url:         p.URL,
			ClientIds:   p.ClientIDs,
			CreatedAt:   p.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

type createOIDCProviderRequest struct {
	Url       string   `json:"url"`
	ClientIds []string `json:"clientIds"`
}

func (s *Server) handleV1CreateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req createOIDCProviderRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	issuer := store.NormalizeIssuerURL(req.Url)
	host, err := issuerHost(issuer)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "url must be a valid https issuer URL")
		return
	}
	providerARN := arn.Build("iam", "", sess.AccountID, "oidc-provider/"+host)
	clientIDs := trimList(req.ClientIds)
	if len(clientIDs) == 0 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "at least one client ID (audience) is required")
		return
	}
	// The store upserts; creating over an existing provider would silently
	// replace its client IDs, so that is an explicit update instead.
	if _, found, err := s.findOIDCProvider(ctx, sess.AccountID, providerARN); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "create_failed", err.Error())
		return
	} else if found {
		writeNativeError(w, http.StatusConflict, "already_exists", "an OIDC provider for that issuer is already registered")
		return
	}
	provider := store.OIDCProvider{
		ProviderARN: providerARN,
		AccountID:   sess.AccountID,
		URL:         issuer,
		ClientIDs:   clientIDs,
	}
	if err := s.store.CreateOIDCProvider(ctx, provider); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateOIDCProvider", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"providerArn": providerARN})
}

type updateOIDCProviderRequest struct {
	ProviderArn string   `json:"providerArn"`
	ClientIds   []string `json:"clientIds"`
}

// handleV1UpdateOIDCProvider replaces a provider's client IDs (audiences).
// The issuer URL is the provider's identity and can't change.
func (s *Server) handleV1UpdateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req updateOIDCProviderRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	providerARN := strings.TrimSpace(req.ProviderArn)
	if providerARN == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "providerArn is required")
		return
	}
	clientIDs := trimList(req.ClientIds)
	if len(clientIDs) == 0 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "at least one client ID (audience) is required")
		return
	}
	existing, found, err := s.findOIDCProvider(ctx, sess.AccountID, providerARN)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	if !found {
		writeNativeError(w, http.StatusNotFound, "not_found", "OIDC provider not found")
		return
	}
	existing.ClientIDs = clientIDs
	if err := s.store.CreateOIDCProvider(ctx, existing); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpdateOIDCProvider", KeyID: providerARN, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"providerArn": providerARN, "updated": true})
}

// findOIDCProvider looks a provider up by ARN within the account.
func (s *Server) findOIDCProvider(ctx context.Context, accountID, providerARN string) (store.OIDCProvider, bool, error) {
	providers, err := s.store.ListOIDCProviders(ctx, accountID)
	if err != nil {
		return store.OIDCProvider{}, false, err
	}
	for _, p := range providers {
		if p.ProviderARN == providerARN {
			return p, true, nil
		}
	}
	return store.OIDCProvider{}, false, nil
}

func (s *Server) handleV1DeleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	providerARN := strings.TrimSpace(r.URL.Query().Get("providerArn"))
	if providerARN == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "providerArn is required")
		return
	}
	if err := s.store.DeleteOIDCProvider(ctx, sess.AccountID, providerARN); err != nil {
		if errors.Is(err, store.ErrOIDCProviderNotFound) {
			writeNativeError(w, http.StatusNotFound, "not_found", "OIDC provider not found")
			return
		}
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteOIDCProvider", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- roles -----------------------------------------------------------------

func (s *Server) handleV1ListRoles(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	roles, err := s.store.ListIAMRoles(ctx, sess.AccountID)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]nativeRole, 0, len(roles))
	for _, role := range roles {
		out = append(out, toNativeRole(role))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"roles": out})
}

type createRoleRequest struct {
	RoleName       string            `json:"roleName"`
	Description    string            `json:"description"`
	Trust          nativeTrustPolicy `json:"trust"`
	MaxSessionSecs int               `json:"maxSessionSeconds"`
}

func (s *Server) handleV1CreateRole(w http.ResponseWriter, r *http.Request) {
	s.saveRole(w, r, false)
}

// handleV1UpdateRole changes an existing role's description, trust policy
// and maximum session length; the name (and so the ARN) is fixed.
func (s *Server) handleV1UpdateRole(w http.ResponseWriter, r *http.Request) {
	s.saveRole(w, r, true)
}

func (s *Server) saveRole(w http.ResponseWriter, r *http.Request, update bool) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req createRoleRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	roleName := strings.TrimSpace(req.RoleName)
	if len(roleName) > maxRoleNameLen || !nativeSegmentRe.MatchString(roleName) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "roleName must be 1-64 letters, numbers, '.', '_' and '-'")
		return
	}
	// The store upserts, so existence decides create (409 when taken) vs
	// update (404 when missing) here.
	_, err := s.store.GetIAMRole(ctx, sess.AccountID, roleName)
	switch {
	case err != nil && !errors.Is(err, store.ErrIAMRoleNotFound):
		writeNativeError(w, http.StatusInternalServerError, "lookup_failed", err.Error())
		return
	case err == nil && !update:
		writeNativeError(w, http.StatusConflict, "already_exists", "a role with that name already exists")
		return
	case err != nil && update:
		writeNativeError(w, http.StatusNotFound, "not_found", "role not found")
		return
	}
	trust, err := validateTrustPolicy(ctx, s, sess.AccountID, req.Trust)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	maxSecs := req.MaxSessionSecs
	if maxSecs <= 0 {
		maxSecs = 3600
	}
	if maxSecs < 900 {
		maxSecs = 900
	}
	if maxSecs > 43200 {
		maxSecs = 43200
	}
	role := store.IAMRole{
		RoleARN:        arn.Build("iam", "", sess.AccountID, "role/"+roleName),
		AccountID:      sess.AccountID,
		RoleName:       roleName,
		Description:    strings.TrimSpace(req.Description),
		Trust:          trust,
		MaxSessionSecs: maxSecs,
	}
	if err := s.store.CreateIAMRole(ctx, role); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "save_failed", err.Error())
		return
	}
	if update {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpdateRole", KeyID: role.RoleARN, Result: "ok", AuditOrigin: s.auditOrigin(r)})
		writeNativeJSON(w, http.StatusOK, map[string]any{"roleArn": role.RoleARN, "updated": true})
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateRole", KeyID: role.RoleARN, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"roleArn": role.RoleARN})
}

func (s *Server) handleV1DeleteRole(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	roleName := strings.TrimSpace(r.URL.Query().Get("roleName"))
	if roleName == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "roleName is required")
		return
	}
	if err := s.store.DeleteIAMRole(ctx, sess.AccountID, roleName); err != nil {
		if errors.Is(err, store.ErrIAMRoleNotFound) {
			writeNativeError(w, http.StatusNotFound, "not_found", "role not found")
			return
		}
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteRole", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- helpers ---------------------------------------------------------------

func toNativeRole(role store.IAMRole) nativeRole {
	return nativeRole{
		RoleArn:     role.RoleARN,
		RoleName:    role.RoleName,
		Description: role.Description,
		Trust: nativeTrustPolicy{
			Type:        role.Trust.Type,
			ProviderUrl: role.Trust.ProviderURL,
			Audiences:   role.Trust.Audiences,
			Subjects:    role.Trust.Subjects,
			Principals:  role.Trust.Principals,
		},
		MaxSessionSecs: role.MaxSessionSecs,
		CreatedAt:      role.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      role.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// validateTrustPolicy normalizes and validates a UI-supplied trust policy. For
// OIDC trust it confirms the referenced provider is registered for the account.
func validateTrustPolicy(ctx context.Context, s *Server, accountID string, in nativeTrustPolicy) (store.TrustPolicy, error) {
	out := store.TrustPolicy{
		Type:       strings.TrimSpace(in.Type),
		Audiences:  trimList(in.Audiences),
		Subjects:   trimList(in.Subjects),
		Principals: trimList(in.Principals),
	}
	switch out.Type {
	case trustTypeOIDC:
		out.ProviderURL = store.NormalizeIssuerURL(in.ProviderUrl)
		if out.ProviderURL == "" {
			return store.TrustPolicy{}, errTrust("providerUrl is required for an OIDC trust policy")
		}
		provider, err := s.store.GetOIDCProviderByURL(ctx, accountID, out.ProviderURL)
		if err != nil {
			return store.TrustPolicy{}, errTrust("no OIDC provider is registered for that issuer URL")
		}
		if len(out.Audiences) == 0 {
			return store.TrustPolicy{}, errTrust("at least one audience is required for an OIDC trust policy")
		}
		for _, a := range out.Audiences {
			if !slices.Contains(provider.ClientIDs, a) {
				return store.TrustPolicy{}, errTrust(fmt.Sprintf("audience %q is not a client ID of that provider", a))
			}
		}
		if len(out.Subjects) == 0 {
			return store.TrustPolicy{}, errTrust("at least one subject is required for an OIDC trust policy")
		}
		for _, sub := range out.Subjects {
			// A bare "*" would trust every token the issuer mints; a "*"
			// anywhere but the end is not a pattern SubjectAllowed matches.
			if sub == "*" {
				return store.TrustPolicy{}, errTrust("a bare * subject trusts every token from the issuer; narrow it to a prefix")
			}
			if i := strings.Index(sub, "*"); i >= 0 && i != len(sub)-1 {
				return store.TrustPolicy{}, errTrust(fmt.Sprintf("subject %q: * is only allowed at the end", sub))
			}
		}
		if len(out.Principals) > 0 {
			return store.TrustPolicy{}, errTrust("principals only apply to account trust")
		}
	case trustTypeAccount:
		if len(out.Principals) == 0 {
			return store.TrustPolicy{}, errTrust("at least one principal account ID is required")
		}
		for _, p := range out.Principals {
			if !arn.IsValidAccountID(p) {
				return store.TrustPolicy{}, errTrust(fmt.Sprintf("principal %q is not a 12-digit account ID", p))
			}
		}
	default:
		return store.TrustPolicy{}, errTrust("trust type must be 'oidc' or 'account'")
	}
	return out, nil
}

// maxRoleNameLen matches AWS IAM's role name limit.
const maxRoleNameLen = 64

type trustError string

func (e trustError) Error() string { return string(e) }
func errTrust(msg string) error    { return trustError(msg) }

// issuerHost extracts the host[/path] portion of an issuer URL for the provider
// ARN (mirrors AWS, which strips the https:// scheme). Issuers must be https
// URLs with a host and no credentials, query or fragment.
func issuerHost(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errTrust("issuer must be an https URL")
	}
	host := u.Host
	if u.Path != "" && u.Path != "/" {
		host += strings.TrimRight(u.Path, "/")
	}
	return host, nil
}

func trimList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
