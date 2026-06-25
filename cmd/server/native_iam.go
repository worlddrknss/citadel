package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
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

func (s *server) handleV1ListOIDCProviders(w http.ResponseWriter, r *http.Request) {
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

func (s *server) handleV1CreateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req createOIDCProviderRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	issuer := normalizeIssuerURL(req.Url)
	host, err := issuerHost(issuer)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "url must be a valid https issuer URL")
		return
	}
	providerARN := arnFor("iam", "", sess.AccountID, "oidc-provider/"+host)
	clientIDs := trimList(req.ClientIds)
	if len(clientIDs) == 0 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "at least one client ID (audience) is required")
		return
	}
	provider := oidcProvider{
		ProviderARN: providerARN,
		AccountID:   sess.AccountID,
		URL:         issuer,
		ClientIDs:   clientIDs,
	}
	if err := s.store.CreateOIDCProvider(ctx, provider); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateOIDCProvider", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"providerArn": providerARN})
}

func (s *server) handleV1DeleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
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
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteOIDCProvider", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- roles -----------------------------------------------------------------

func (s *server) handleV1ListRoles(w http.ResponseWriter, r *http.Request) {
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

func (s *server) handleV1CreateRole(w http.ResponseWriter, r *http.Request) {
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
	if !nativeSegmentRe.MatchString(roleName) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "roleName may contain only letters, numbers, '.', '_' and '-'")
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
	role := iamRole{
		RoleARN:        arnFor("iam", "", sess.AccountID, "role/"+roleName),
		AccountID:      sess.AccountID,
		RoleName:       roleName,
		Description:    strings.TrimSpace(req.Description),
		Trust:          trust,
		MaxSessionSecs: maxSecs,
	}
	if err := s.store.CreateIAMRole(ctx, role); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateRole", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"roleArn": role.RoleARN})
}

func (s *server) handleV1DeleteRole(w http.ResponseWriter, r *http.Request) {
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
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteRole", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- helpers ---------------------------------------------------------------

func toNativeRole(role iamRole) nativeRole {
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
func validateTrustPolicy(ctx context.Context, s *server, accountID string, in nativeTrustPolicy) (trustPolicy, error) {
	out := trustPolicy{
		Type:       strings.TrimSpace(in.Type),
		Audiences:  trimList(in.Audiences),
		Subjects:   trimList(in.Subjects),
		Principals: trimList(in.Principals),
	}
	switch out.Type {
	case trustTypeOIDC:
		out.ProviderURL = normalizeIssuerURL(in.ProviderUrl)
		if out.ProviderURL == "" {
			return trustPolicy{}, errTrust("providerUrl is required for an OIDC trust policy")
		}
		if _, err := s.store.GetOIDCProviderByURL(ctx, accountID, out.ProviderURL); err != nil {
			return trustPolicy{}, errTrust("no OIDC provider is registered for that issuer URL")
		}
		if len(out.Audiences) == 0 {
			return trustPolicy{}, errTrust("at least one audience is required for an OIDC trust policy")
		}
		if len(out.Subjects) == 0 {
			return trustPolicy{}, errTrust("at least one subject is required for an OIDC trust policy")
		}
	case trustTypeAccount:
		if len(out.Principals) == 0 {
			return trustPolicy{}, errTrust("at least one principal account ID is required")
		}
	default:
		return trustPolicy{}, errTrust("trust type must be 'oidc' or 'account'")
	}
	return out, nil
}

type trustError string

func (e trustError) Error() string { return string(e) }
func errTrust(msg string) error    { return trustError(msg) }

// issuerHost extracts the host[/path] portion of an issuer URL for the provider
// ARN (mirrors AWS, which strips the https:// scheme).
func issuerHost(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "", err
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
