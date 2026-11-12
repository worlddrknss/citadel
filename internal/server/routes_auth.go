package server

import (
	"context"
	"crypto/fips140"
	"errors"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// registerAuthRoutes wires the console authentication, shell, self-service
// session and organization settings endpoints.
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/auth/providers", s.handleV1AuthProviders)
	mux.HandleFunc("GET /v1/bootstrap", s.handleV1BootstrapStatus)
	mux.HandleFunc("POST /v1/bootstrap", s.handleV1Bootstrap)
	mux.HandleFunc("GET /v1/server/info", s.handleV1ServerInfo)
	mux.HandleFunc("GET /v1/me/organization", s.handleV1MyOrganization)
	mux.HandleFunc("POST /v1/session/account", s.handleV1SwitchAccount)
	mux.HandleFunc("GET /v1/secrets/summary", s.handleV1SecretsSummary)
	mux.HandleFunc("POST /v1/account/profile", s.handleV1UpdateProfile)
	mux.HandleFunc("GET /v1/account/sessions", s.handleV1ListSessions)
	mux.HandleFunc("DELETE /v1/account/sessions", s.handleV1RevokeSession)
	mux.HandleFunc("POST /v1/account/sessions/revoke-others", s.handleV1RevokeOtherSessions)
	mux.HandleFunc("GET /v1/admin/settings", s.handleV1GetOrgSettings)
	mux.HandleFunc("POST /v1/admin/settings", s.handleV1PutOrgSettings)
}

// authMeResponse is the Me shape (/v1/me, login, account switch) plus
// whether the caller is a platform admin.
type authMeResponse struct {
	nativeMeResponse
	PlatformAdmin bool `json:"platformAdmin"`
}

func meResponse(sess *uiSession) authMeResponse {
	accounts := sess.Accounts
	if accounts == nil {
		accounts = []string{}
	}
	return authMeResponse{
		nativeMeResponse: nativeMeResponse{
			Username:    sess.Username,
			DisplayName: sess.DisplayName,
			Role:        store.NormalizeUIRole(sess.Role),
			AccountID:   sess.AccountID,
			Accounts:    accounts,
		},
		PlatformAdmin: sess.PlatformAdmin,
	}
}

// ---- public: providers, server info, bootstrap -----------------------------

type authProviderJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// handleV1AuthProviders lists the enabled console SSO providers for the
// sign-in screen. Public: it reveals only provider IDs and display names.
func (s *Server) handleV1AuthProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.store.ListSSOProviders(r.Context(), true)
	if err != nil {
		log.Printf("list SSO providers failed: %v", err)
		providers = nil
	}
	out := make([]authProviderJSON, 0, len(providers))
	for _, p := range providers {
		out = append(out, authProviderJSON{ID: p.ID, Name: p.Name, Type: "oidc"})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

// handleV1ServerInfo reports public server facts the shell shows before
// sign-in. The version is deliberately not disclosed.
func (s *Server) handleV1ServerInfo(w http.ResponseWriter, r *http.Request) {
	idle, abs := s.sessionTTLs(r.Context())
	out := map[string]any{"fips": fips140.Enabled(), "sessionMaxHours": int(abs / time.Hour)}
	if idle > 0 {
		out["sessionIdleMinutes"] = int(idle / time.Minute)
	}
	writeNativeJSON(w, http.StatusOK, out)
}

func (s *Server) handleV1BootstrapStatus(w http.ResponseWriter, r *http.Request) {
	writeNativeJSON(w, http.StatusOK, map[string]any{"required": s.bootstrapRequired(r.Context())})
}

type bootstrapRequest struct {
	OrganizationName string `json:"organizationName"`
	AccountName      string `json:"accountName"`
	Username         string `json:"username"`
	Password         string `json:"password"`
}

var (
	usernameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	accountNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$`)
)

const (
	bootstrapMinPassword = 12
	maxPasswordLen       = 1024
)

// validDisplayText accepts 1..max printable characters without control
// characters.
func validDisplayText(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// handleV1Bootstrap performs first-run setup: it creates the organization's
// first account and a platform admin, then signs that admin in. It works only
// while no console user exists, is rate limited per client address, and is
// serialized in the store so concurrent attempts cannot both succeed.
func (s *Server) handleV1Bootstrap(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if ok, wait := s.auth().bootstrapIP.Reserve(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeNativeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts; try again later")
		return
	}
	if !s.bootstrapRequired(r.Context()) {
		writeNativeError(w, http.StatusConflict, "already_bootstrapped", "Citadel is already set up")
		return
	}
	var req bootstrapRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	org := strings.TrimSpace(req.OrganizationName)
	accountName := strings.TrimSpace(req.AccountName)
	username := strings.TrimSpace(req.Username)
	switch {
	case !validDisplayText(org, 100):
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "organization name must be 1-100 characters")
		return
	case !accountNameRe.MatchString(accountName):
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "account name must be 1-63 letters, digits, spaces, dots, dashes or underscores")
		return
	case !usernameRe.MatchString(username):
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username must be 1-64 letters, digits, dots, dashes, underscores or @")
		return
	case len(req.Password) < bootstrapMinPassword || len(req.Password) > maxPasswordLen:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "password must be at least 12 characters")
		return
	}
	hash, err := cryptoutil.HashPassword(req.Password)
	if err != nil {
		log.Printf("bootstrap: hash password: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "bootstrap_failed", "could not complete setup")
		return
	}
	accountID, err := s.store.Bootstrap(r.Context(), store.BootstrapRequest{
		OrganizationName: org, AccountName: accountName, Username: username, DisplayName: username, PasswordHash: hash,
	})
	if errors.Is(err, store.ErrAlreadyBootstrapped) {
		writeNativeError(w, http.StatusConflict, "already_bootstrapped", "Citadel is already set up")
		return
	}
	if err != nil {
		log.Printf("bootstrap failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "bootstrap_failed", "could not complete setup")
		return
	}
	s.auth().bootstrapped.Store(true)
	s.invalidateOrgSettings()
	if _, err := s.store.EnsureAccountDefaultKey(r.Context(), accountID); err != nil {
		log.Printf("warning: failed to provision default key for account %s: %v", accountID, err)
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.Bootstrap", KeyID: accountID, Result: "ok", Actor: username})
	if _, err := s.issueConsoleSession(r.Context(), w, r, username, accountID, store.SessionMethodPassword); err != nil {
		// Setup is done; the admin can still sign in with the password.
		log.Printf("bootstrap: create session failed: %v", err)
	}
	writeNativeJSON(w, http.StatusCreated, map[string]any{"accountId": accountID, "organization": org, "username": username})
}

// ---- shell: organization, account switch, secrets summary ------------------

type orgAccountJSON struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	Role      string `json:"role,omitempty"`
}

// handleV1MyOrganization returns the organization name and the accounts the
// caller can use, with their role in each.
func (s *Server) handleV1MyOrganization(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	var ms []membership
	switch {
	case sess.ViaToken:
		ms = []membership{{AccountID: sess.AccountID, Role: sess.Role}}
	default:
		if user, found := s.lookupUser(ctx, sess.Username); found {
			ms = s.userMemberships(ctx, user)
		} else if sess.AccountID != "" {
			ms = []membership{{AccountID: sess.AccountID, Role: sess.Role}}
		}
	}
	accounts := make([]orgAccountJSON, 0, len(ms))
	for _, m := range ms {
		name := m.AccountID
		if info, err := s.store.GetUIAccount(ctx, m.AccountID); err == nil && info.Name != "" {
			name = info.Name
		}
		accounts = append(accounts, orgAccountJSON{AccountID: m.AccountID, Name: name, Role: m.Role})
	}
	name := s.orgSettings(ctx).OrganizationName
	if name == "" {
		name = AppName
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"organization": map[string]string{"name": name}, "accounts": accounts})
}

type switchAccountRequest struct {
	AccountID string `json:"accountId"`
}

// handleV1SwitchAccount re-scopes the caller's session to another account
// they belong to; the role is recomputed for that account.
func (s *Server) handleV1SwitchAccount(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	if sess.SessionID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "only console sessions can switch accounts")
		return
	}
	var req switchAccountRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	target := strings.TrimSpace(req.AccountID)
	if target == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "accountId is required")
		return
	}
	if !slices.Contains(sess.Accounts, target) {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.SwitchAccount", KeyID: target, Result: "denied", ErrorType: "AccessDenied", Actor: sess.Username})
		writeNativeError(w, http.StatusForbidden, "forbidden", "you do not belong to that account")
		return
	}
	if err := s.store.SetConsoleSessionAccount(r.Context(), sess.SessionID, target); err != nil {
		log.Printf("switch account failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "switch_failed", "could not switch account")
		return
	}
	row := store.ConsoleSession{ID: sess.SessionID, Username: sess.Username, AccountID: target, Method: sess.Method, CreatedAt: sess.CreatedAt, LastSeenAt: sess.LastSeenAt}
	next, err := s.sessionFromRow(r.Context(), row)
	if err != nil {
		writeNativeError(w, http.StatusForbidden, "forbidden", "you do not belong to that account")
		return
	}
	s.recordAudit(store.WithCallerAccount(r.Context(), target), store.AuditEvent{Action: "citadel.SwitchAccount", KeyID: target, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, meResponse(next))
}

// handleV1SecretsSummary counts the caller account's items, projects and
// environments for the Overview page.
func (s *Server) handleV1SecretsSummary(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	projects, err := s.secretsSvc().ListProjects(ctx)
	if err != nil {
		log.Printf("secrets summary: list projects: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not summarize secrets")
		return
	}
	secrets, err := s.store.ListSecrets(ctx)
	if err != nil {
		log.Printf("secrets summary: list secrets: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not summarize secrets")
		return
	}
	total := 0
	for _, sec := range secrets {
		if _, ok := parseSecretName(sec.Name); ok {
			total++
		}
	}
	envs := 0
	for _, p := range projects {
		envs += len(p.Environments)
	}
	writeNativeJSON(w, http.StatusOK, map[string]int{"total": total, "projects": len(projects), "environments": envs})
}

// ---- account self-service: profile and sessions ----------------------------

type updateProfileRequest struct {
	DisplayName string `json:"displayName"`
}

// requireConsoleUser is nativeSession for self-service endpoints, which act
// on the signed-in person and so refuse access-key tokens.
func (s *Server) requireConsoleUser(w http.ResponseWriter, r *http.Request) (*uiSession, context.Context, bool) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return nil, nil, false
	}
	if sess.ViaToken || sess.SessionID == "" {
		writeNativeError(w, http.StatusForbidden, "forbidden", "this action requires a console session")
		return nil, nil, false
	}
	return sess, ctx, true
}

func (s *Server) handleV1UpdateProfile(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	var req updateProfileRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if !validDisplayText(name, 100) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "display name must be 1-100 characters")
		return
	}
	user, err := s.store.GetUIUser(ctx, sess.Username)
	if errors.Is(err, store.ErrUIUserNotFound) {
		writeNativeError(w, http.StatusConflict, "managed_by_config", "this user is defined in the server configuration")
		return
	}
	if err != nil {
		log.Printf("update profile: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not update the profile")
		return
	}
	user.DisplayName = name
	if err := s.store.UpsertUIUser(ctx, user); err != nil {
		log.Printf("update profile: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not update the profile")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpdateProfile", KeyID: user.Username, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]string{"username": user.Username, "displayName": name})
}

type sessionJSON struct {
	ID         string `json:"id"`
	Current    bool   `json:"current"`
	CreatedAt  string `json:"createdAt"`
	LastSeenAt string `json:"lastSeenAt"`
	ExpiresAt  string `json:"expiresAt"`
	IP         string `json:"ip,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
	AccountID  string `json:"accountId,omitempty"`
	Method     string `json:"method,omitempty"`
}

// handleV1ListSessions lists the caller's live sessions. The reported expiry
// is the earlier of the absolute and the idle deadline.
func (s *Server) handleV1ListSessions(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	rows, err := s.store.ListConsoleSessions(r.Context(), sess.Username)
	if err != nil {
		log.Printf("list sessions: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list sessions")
		return
	}
	now := time.Now().UTC()
	idle, abs := s.sessionTTLs(ctx)
	out := make([]sessionJSON, 0, len(rows))
	for _, row := range rows {
		if !now.Before(row.ExpiresAt) || sessionExpired(uiSession{CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt}, now, idle, abs) {
			continue
		}
		expires := row.ExpiresAt
		if d := row.CreatedAt.Add(abs); d.Before(expires) {
			expires = d
		}
		if idle > 0 {
			if d := row.LastSeenAt.Add(idle); d.Before(expires) {
				expires = d
			}
		}
		out = append(out, sessionJSON{
			ID: row.ID, Current: row.ID == sess.SessionID,
			CreatedAt: row.CreatedAt.Format(time.RFC3339), LastSeenAt: row.LastSeenAt.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
			IP: row.IP, UserAgent: row.UserAgent, AccountID: row.AccountID, Method: row.Method,
		})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleV1RevokeSession signs out one of the caller's other sessions.
func (s *Server) handleV1RevokeSession(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" || len(id) > 64 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	if id == sess.SessionID {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "use sign out to end the current session")
		return
	}
	err := s.store.DeleteConsoleSession(r.Context(), sess.Username, id)
	if errors.Is(err, store.ErrConsoleSessionNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if err != nil {
		log.Printf("revoke session: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "revoke_failed", "could not revoke the session")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevokeSession", KeyID: id, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// handleV1RevokeOtherSessions signs out every session of the caller except
// the current one.
func (s *Server) handleV1RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requireConsoleUser(w, r)
	if !ok {
		return
	}
	n, err := s.store.DeleteUserConsoleSessions(r.Context(), sess.Username, sess.SessionID)
	if err != nil {
		log.Printf("revoke other sessions: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "revoke_failed", "could not revoke sessions")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevokeSession", KeyID: "others:" + strconv.FormatInt(n, 10), Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]int64{"revoked": n})
}

// ---- admin: organization settings ------------------------------------------

type orgSettingsJSON struct {
	ApprovalEnvironments []string `json:"approvalEnvironments"`
	ApprovalMinApprovers int      `json:"approvalMinApprovers"`
	AllowSelfApproval    bool     `json:"allowSelfApproval"`
	SessionIdleMinutes   int      `json:"sessionIdleMinutes"`
	SessionMaxHours      int      `json:"sessionMaxHours"`
	UpdatedAt            string   `json:"updatedAt,omitempty"`
	UpdatedBy            string   `json:"updatedBy,omitempty"`
}

func (s *Server) orgSettingsJSON(ctx context.Context, st store.OrgSettings) orgSettingsJSON {
	idle, abs := s.sessionTTLs(ctx)
	out := orgSettingsJSON{
		ApprovalEnvironments: st.ApprovalEnvironments,
		ApprovalMinApprovers: max(st.ApprovalMinApprovers, 1),
		AllowSelfApproval:    st.AllowSelfApproval,
		SessionIdleMinutes:   int(idle / time.Minute),
		SessionMaxHours:      int(abs / time.Hour),
		UpdatedBy:            st.UpdatedBy,
	}
	if out.ApprovalEnvironments == nil {
		out.ApprovalEnvironments = []string{}
	}
	if !st.UpdatedAt.IsZero() {
		out.UpdatedAt = st.UpdatedAt.Format(time.RFC3339)
	}
	return out
}

// handleV1GetOrgSettings returns the organization settings (any admin).
func (s *Server) handleV1GetOrgSettings(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	st, err := s.store.GetOrgSettings(ctx)
	if err != nil {
		log.Printf("get org settings: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "load_failed", "could not load settings")
		return
	}
	writeNativeJSON(w, http.StatusOK, s.orgSettingsJSON(ctx, st))
}

// handleV1PutOrgSettings saves the organization settings. They span every
// account, so only platform admins may change them. allowSelfApproval is
// stored and audited; it defaults to false.
func (s *Server) handleV1PutOrgSettings(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	if !sess.PlatformAdmin {
		writeNativeError(w, http.StatusForbidden, "forbidden", "only platform admins can change organization settings")
		return
	}
	var req orgSettingsJSON
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	envs := make([]string, 0, len(req.ApprovalEnvironments))
	for _, e := range req.ApprovalEnvironments {
		e = strings.TrimSpace(e)
		if e == "" || slices.Contains(envs, e) {
			continue
		}
		if !nativeSegmentRe.MatchString(e) || len(e) > 64 {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid environment name")
			return
		}
		envs = append(envs, e)
	}
	switch {
	case len(envs) > 50:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "at most 50 approval environments")
		return
	case req.ApprovalMinApprovers < 1 || req.ApprovalMinApprovers > 10:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "approvalMinApprovers must be 1-10")
		return
	case req.SessionIdleMinutes < 5 || req.SessionIdleMinutes > 1440:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "sessionIdleMinutes must be 5-1440")
		return
	case req.SessionMaxHours < 1 || req.SessionMaxHours > 720:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "sessionMaxHours must be 1-720")
		return
	case req.SessionIdleMinutes > req.SessionMaxHours*60:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "the idle timeout cannot exceed the maximum session length")
		return
	}
	current, err := s.store.GetOrgSettings(ctx)
	if err != nil {
		log.Printf("put org settings: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save settings")
		return
	}
	next := store.OrgSettings{
		OrganizationName:     current.OrganizationName,
		ApprovalEnvironments: envs,
		ApprovalMinApprovers: req.ApprovalMinApprovers,
		AllowSelfApproval:    req.AllowSelfApproval,
		SessionIdleMinutes:   req.SessionIdleMinutes,
		SessionMaxHours:      req.SessionMaxHours,
		UpdatedAt:            time.Now().UTC().Truncate(time.Second),
		UpdatedBy:            sess.Username,
	}
	if err := s.store.PutOrgSettings(ctx, next); err != nil {
		log.Printf("put org settings: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save settings")
		return
	}
	s.invalidateOrgSettings()
	resource := "org-settings"
	if next.AllowSelfApproval {
		resource = "org-settings:allowSelfApproval=true"
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpdateOrgSettings", KeyID: resource, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, s.orgSettingsJSON(ctx, next))
}
