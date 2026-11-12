package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Native Citadel admin/action API (/v1)
//
// These endpoints back the action buttons on the Svelte control plane so every
// screen (Secrets, KMS, Certificates, Account, Master Admin) is fully usable
// without the legacy html/template pages. They reuse the existing store methods
// and business logic; the cert handlers bridge JSON onto the form-based helpers
// in admin_certificates_ui.go so the certificate cryptography is shared, not
// duplicated.

// ---- session login / logout ------------------------------------------------

type nativeLoginRequest struct {
	AccountID string `json:"accountId"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// handleV1Login authenticates a user and establishes the session cookie that
// the SPA (and the rest of /v1) relies on. Attempts are rate limited per
// client address and per username, failures back off exponentially, and
// every failure is audited. Unknown users, wrong passwords and accounts the
// user does not belong to get the same response after the same work.
func (s *Server) handleV1Login(w http.ResponseWriter, r *http.Request) {
	if s.cfg.InsecureDev && !s.hasConsoleUsers(r.Context()) {
		// Auth disabled (local dev): every caller is the local admin, so
		// report success without a cookie.
		writeNativeJSON(w, http.StatusOK, map[string]any{
			"username":  "local",
			"role":      "admin",
			"accountId": "",
			"authOff":   true,
		})
		return
	}
	var req nativeLoginRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	accountID := strings.TrimSpace(req.AccountID)
	username := strings.TrimSpace(req.Username)
	if accountID == "" || username == "" || len(username) > 128 || len(req.Password) > 1024 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "account ID, username and password are required")
		return
	}

	a := s.auth()
	ip := clientIP(r)
	userKey := strings.ToLower(username)
	if wait, limited := loginThrottled(a, ip, userKey); limited {
		log.Printf("login throttled ip=%s", ip)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeNativeError(w, http.StatusTooManyRequests, "rate_limited", "too many sign-in attempts; try again later")
		return
	}

	user, found := s.lookupUser(r.Context(), username)
	// Always run a verification to keep timing constant and avoid
	// user-enumeration via response timing.
	stored := dummyPasswordHash
	if found {
		stored = user.StoredCredential()
	}
	passwordOK := cryptoutil.VerifyPassword(stored, req.Password)
	member := false
	if found && passwordOK {
		_, member = accountRole(s.userMemberships(r.Context(), user), accountID)
	}
	if !found || !passwordOK || !member {
		a.failUser.Fail(userKey)
		a.failIP.Fail(ip)
		s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.Login", KeyID: accountID, Result: "denied", ErrorType: "InvalidCredentials", Actor: truncate(username, 128)})
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials or account access denied")
		return
	}
	a.failUser.Reset(userKey)
	a.failIP.Reset(ip)
	s.rehashOnLogin(r.Context(), user, req.Password)

	sess, err := s.issueConsoleSession(r.Context(), w, r, user.Username, accountID, store.SessionMethodPassword)
	if err != nil {
		log.Printf("create console session failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not create a session")
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.Login", KeyID: accountID, Result: "ok", Actor: user.Username})
	me, err := s.sessionFromRow(r.Context(), sess)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "login_failed", "could not create a session")
		return
	}
	writeNativeJSON(w, http.StatusOK, meResponse(me))
}

// loginThrottled applies the login rate limits and lockouts. It reports how
// long to wait when the attempt must be refused.
func loginThrottled(a *authState, ip, userKey string) (time.Duration, bool) {
	if blocked, d := a.failIP.Blocked(ip); blocked {
		return d, true
	}
	if blocked, d := a.failUser.Blocked(userKey); blocked {
		return d, true
	}
	if ok, d := a.loginIP.Reserve(ip); !ok {
		return d, true
	}
	if ok, d := a.loginUser.Reserve(userKey); !ok {
		return d, true
	}
	return 0, false
}

// handleV1Logout revokes the active session and clears the cookie.
func (s *Server) handleV1Logout(w http.ResponseWriter, r *http.Request) {
	if token := s.sessionToken(r); token != "" {
		if row, err := s.store.GetConsoleSessionByTokenHash(r.Context(), hashSessionToken(token)); err == nil {
			if err := s.store.DeleteConsoleSession(r.Context(), row.Username, row.ID); err != nil && !errors.Is(err, store.ErrConsoleSessionNotFound) {
				log.Printf("logout: delete session failed: %v", err)
			}
			s.recordAudit(r.Context(), store.AuditEvent{Action: "citadel.Logout", KeyID: row.AccountID, Result: "ok", Actor: row.Username})
		}
	}
	s.clearSessionCookie(w)
	writeNativeJSON(w, http.StatusOK, map[string]any{"loggedOut": true})
}

// ---- KMS key management ----------------------------------------------------

type nativeCreateKMSKeyRequest struct {
	Description string `json:"description"`
	KeyUsage    string `json:"keyUsage"`
	KeySpec     string `json:"keySpec"`
}

// handleV1CreateKMSKey provisions a new customer master key.
func (s *Server) handleV1CreateKMSKey(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeCreateKMSKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	usage := strings.TrimSpace(req.KeyUsage)
	if usage == "" {
		usage = store.KeyUsageEncryptDecrypt
	}
	spec := strings.TrimSpace(req.KeySpec)
	if spec == "" {
		spec = store.KeySpecSymmetricDefault
	}
	key, err := s.store.CreateKey(ctx, strings.TrimSpace(req.Description), usage, spec)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateKey", KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": key.ID, "arn": key.ARN, "created": true})
}

type nativeKMSKeyActionRequest struct {
	KeyID      string `json:"keyId"`
	Enabled    bool   `json:"enabled"`
	WindowDays int    `json:"windowDays"`
}

// handleV1SetKMSKeyEnabled enables or disables a key.
func (s *Server) handleV1SetKMSKeyEnabled(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeKMSKeyActionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "keyId is required")
		return
	}
	if err := s.store.SetKeyEnabled(ctx, keyID, req.Enabled); err != nil {
		writeNativeError(w, http.StatusBadRequest, "update_failed", err.Error())
		return
	}
	action := "citadel.DisableKey"
	if req.Enabled {
		action = "citadel.EnableKey"
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: keyID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": keyID, "enabled": req.Enabled})
}

// handleV1ScheduleKMSKeyDeletion schedules a key for deletion.
func (s *Server) handleV1ScheduleKMSKeyDeletion(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeKMSKeyActionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "keyId is required")
		return
	}
	window := req.WindowDays
	if window == 0 {
		window = 30
	}
	when, err := s.store.ScheduleKeyDeletion(ctx, keyID, window)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ScheduleKeyDeletion", KeyID: keyID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": keyID, "deletionDate": when.UTC().Format(time.RFC3339)})
}

// handleV1CancelKMSKeyDeletion cancels a pending key deletion.
func (s *Server) handleV1CancelKMSKeyDeletion(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeKMSKeyActionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "keyId is required")
		return
	}
	if err := s.store.CancelKeyDeletion(ctx, keyID); err != nil {
		writeNativeError(w, http.StatusBadRequest, "cancel_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CancelKeyDeletion", KeyID: keyID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": keyID, "restored": true})
}

// ---- account self-service: access keys + password -------------------------

type nativeAccessKey struct {
	AccessKeyID string `json:"accessKeyId"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
	LastUsedAt  string `json:"lastUsedAt,omitempty"`
}

// handleV1ListAccessKeys lists the caller's access keys for their current account.
func (s *Server) handleV1ListAccessKeys(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	keys, err := s.store.ListAccessKeys(ctx, sess.Username, sess.AccountID)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]nativeAccessKey, 0, len(keys))
	for _, k := range keys {
		nk := nativeAccessKey{AccessKeyID: k.AccessKeyID, Status: k.Status, CreatedAt: k.CreatedAt.UTC().Format(time.RFC3339)}
		if k.LastUsedAt != nil {
			nk.LastUsedAt = k.LastUsedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, nk)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"accessKeys": out})
}

// handleV1CreateAccessKey mints a new access key for the caller. The secret is
// returned exactly once.
func (s *Server) handleV1CreateAccessKey(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	secret, err := s.store.CreateAccessKey(ctx, sess.Username, sess.AccountID)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateAccessKey", Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"accessKeyId": secret.AccessKeyID,
		"secretKey":   secret.SecretKey,
	})
}

type nativeAccessKeyIDRequest struct {
	AccessKeyID string `json:"accessKeyId"`
	Status      string `json:"status"`
}

// handleV1DeleteAccessKey deletes one of the caller's access keys.
func (s *Server) handleV1DeleteAccessKey(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	keyID := strings.TrimSpace(r.URL.Query().Get("accessKeyId"))
	if keyID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "accessKeyId is required")
		return
	}
	if err := s.guardOwnAccessKey(ctx, sess, keyID); err != nil {
		writeNativeError(w, http.StatusForbidden, "forbidden", err.Error())
		return
	}
	if err := s.store.DeleteAccessKey(ctx, keyID); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteAccessKey", Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// handleV1SetAccessKeyStatus activates or deactivates one of the caller's keys.
func (s *Server) handleV1SetAccessKeyStatus(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	var req nativeAccessKeyIDRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	keyID := strings.TrimSpace(req.AccessKeyID)
	status := strings.TrimSpace(req.Status)
	if keyID == "" || (status != "Active" && status != "Inactive") {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "accessKeyId and status (Active|Inactive) are required")
		return
	}
	if err := s.guardOwnAccessKey(ctx, sess, keyID); err != nil {
		writeNativeError(w, http.StatusForbidden, "forbidden", err.Error())
		return
	}
	if err := s.store.SetAccessKeyStatus(ctx, keyID, status); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.SetAccessKeyStatus", Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"accessKeyId": keyID, "status": status})
}

// guardOwnAccessKey ensures a caller can only act on their own access keys,
// or, as an admin, on keys in their account, preventing cross-user and
// cross-account key tampering.
func (s *Server) guardOwnAccessKey(ctx context.Context, sess *uiSession, keyID string) error {
	owner, accountID, _, _, err := s.store.GetAccessKeyByID(ctx, keyID)
	if err != nil {
		return err
	}
	if strings.EqualFold(owner, sess.Username) {
		return nil
	}
	// Admins may manage other users' keys, but only in their own account
	// unless they are platform admins.
	if uiRoleAtLeast(sess.Role, "admin") && (sess.PlatformAdmin || accountID == sess.AccountID) {
		return nil
	}
	return store.ErrAccessKeyNotFound
}

type nativeChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// handleV1ChangePassword updates the caller's password after verifying the
// current one.
func (s *Server) handleV1ChangePassword(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	var req nativeChangePasswordRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(req.NewPassword) < 8 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "new password must be at least 8 characters")
		return
	}
	if len(req.NewPassword) > maxPasswordLen {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "new password is too long")
		return
	}
	if sess.ViaToken || sess.SessionID == "" {
		writeNativeError(w, http.StatusForbidden, "forbidden", "this action requires a console session")
		return
	}
	current, err := s.store.GetUIUser(ctx, sess.Username)
	if err != nil {
		env, isEnv := s.envUsers()[sess.Username]
		if !errors.Is(err, store.ErrUIUserNotFound) || !isEnv || s.dbBacked() {
			writeNativeError(w, http.StatusInternalServerError, "update_failed", "failed to verify credentials")
			return
		}
		current = env
	}
	if !cryptoutil.VerifyPassword(current.StoredCredential(), req.CurrentPassword) {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ChangePassword", Result: "denied", ErrorType: "InvalidCredentials", Actor: sess.Username})
		writeNativeError(w, http.StatusForbidden, "forbidden", "current password is incorrect")
		return
	}
	hashed, err := cryptoutil.HashPassword(req.NewPassword)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "failed to hash password")
		return
	}
	current.PasswordHash = hashed
	current.Password = ""
	if err := s.store.UpsertUIUser(ctx, current); err != nil {
		log.Printf("change password: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not update the password")
		return
	}
	// A new password ends the user's other sessions.
	if _, err := s.store.DeleteUserConsoleSessions(ctx, sess.Username, sess.SessionID); err != nil {
		log.Printf("change password: revoke sessions: %v", err)
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ChangePassword", Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

// ---- master admin: users ---------------------------------------------------
//
// Platform admins manage every user and account; account admins only their
// session's account (see the role model in admin_auth.go).

type nativeMembership struct {
	AccountID string `json:"accountId"`
	Role      string `json:"role"`
}

type nativeUser struct {
	Username      string             `json:"username"`
	DisplayName   string             `json:"displayName"`
	Role          string             `json:"role"`
	Accounts      []string           `json:"accounts"`
	Memberships   []nativeMembership `json:"memberships"`
	PlatformAdmin bool               `json:"platformAdmin"`
}

// adminCanManageUser reports whether sess may modify or delete user: platform
// admins may modify anyone; account admins only users who belong to no
// account but the session's own and are not platform admins.
func (s *Server) adminCanManageUser(ctx context.Context, sess *uiSession, user store.UIUser) bool {
	if sess.PlatformAdmin {
		return true
	}
	if s.isPlatformAdmin(user) {
		return false
	}
	ms := s.userMemberships(ctx, user)
	if len(ms) == 0 {
		return false
	}
	for _, m := range ms {
		if m.AccountID != sess.AccountID {
			return false
		}
	}
	return true
}

// handleV1ListUsers lists console users with their memberships. Account
// admins see only the members of their account, and only that membership.
func (s *Server) handleV1ListUsers(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	users, err := s.store.ListUIUsers(ctx)
	if err != nil {
		log.Printf("list users: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list users")
		return
	}
	if !s.dbBacked() {
		// The memory store does not hold env-configured users.
		have := map[string]bool{}
		for _, u := range users {
			have[u.Username] = true
		}
		for name, u := range s.envUsers() {
			if !have[name] {
				users = append(users, u)
			}
		}
		slices.SortFunc(users, func(a, b store.UIUser) int { return strings.Compare(a.Username, b.Username) })
	}
	out := make([]nativeUser, 0, len(users))
	for _, u := range users {
		ms := s.userMemberships(ctx, u)
		nu := nativeUser{Username: u.Username, DisplayName: u.DisplayName, Role: store.NormalizeUIRole(u.Role), Accounts: []string{}, Memberships: []nativeMembership{}, PlatformAdmin: s.isPlatformAdmin(u)}
		for _, m := range ms {
			if !sess.PlatformAdmin && m.AccountID != sess.AccountID {
				continue
			}
			nu.Accounts = append(nu.Accounts, m.AccountID)
			nu.Memberships = append(nu.Memberships, nativeMembership{AccountID: m.AccountID, Role: m.Role})
		}
		if !sess.PlatformAdmin {
			if len(nu.Memberships) == 0 {
				continue
			}
			// The global role is not account information; show the
			// account role instead.
			nu.Role = nu.Memberships[0].Role
		}
		out = append(out, nu)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"users": out})
}

type nativeUpsertUserRequest struct {
	Username      string   `json:"username"`
	DisplayName   string   `json:"displayName"`
	Role          string   `json:"role"`
	Password      string   `json:"password"`
	Accounts      []string `json:"accounts"`
	PlatformAdmin *bool    `json:"platformAdmin,omitempty"`
}

// handleV1UpsertUser creates or updates a console user.
//
// Platform admins set the global role, static accounts and (optionally) the
// platformAdmin flag. Account admins create users into their own account
// (global role viewer, membership with the requested role) and may update
// only users who belong to their account alone; for them role sets the
// account role and the global role is untouched.
func (s *Server) handleV1UpsertUser(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeUpsertUserRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	username := strings.TrimSpace(req.Username)
	if !usernameRe.MatchString(username) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username must be 1-64 letters, digits, dots, dashes, underscores or @")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = username
	}
	if !validDisplayText(displayName, 100) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "display name must be 1-100 characters")
		return
	}
	if req.Role != "" && !validRoleName(req.Role) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "role must be viewer, editor or admin")
		return
	}
	role := store.NormalizeUIRole(req.Role)
	if !sess.PlatformAdmin {
		if req.PlatformAdmin != nil {
			writeNativeError(w, http.StatusForbidden, "forbidden", "only platform admins can grant platform admin")
			return
		}
		for _, a := range req.Accounts {
			if strings.TrimSpace(a) != sess.AccountID {
				writeNativeError(w, http.StatusForbidden, "forbidden", "account admins can only manage their own account")
				return
			}
		}
	}

	existing, err := s.store.GetUIUser(ctx, username)
	isNew := errors.Is(err, store.ErrUIUserNotFound)
	if err != nil && !isNew {
		log.Printf("upsert user: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save the user")
		return
	}
	if !isNew && !s.adminCanManageUser(ctx, sess, existing) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "that user belongs to other accounts; ask a platform admin")
		return
	}

	user := store.UIUser{Username: username, DisplayName: displayName}
	if isNew {
		user.Role = role
		user.Accounts = req.Accounts
		if !sess.PlatformAdmin {
			user.Role = "viewer"
			user.Accounts = nil
		}
	} else {
		user.PasswordHash = existing.PasswordHash
		user.PlatformAdmin = existing.PlatformAdmin
		user.Role = existing.Role
		user.Accounts = existing.Accounts
		if sess.PlatformAdmin {
			user.Role = role
			if len(req.Accounts) > 0 {
				user.Accounts = req.Accounts
			}
		}
	}
	if sess.PlatformAdmin && req.PlatformAdmin != nil {
		if !*req.PlatformAdmin && strings.EqualFold(username, sess.Username) {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "you cannot remove your own platform admin flag")
			return
		}
		user.PlatformAdmin = *req.PlatformAdmin
	}
	if sess.PlatformAdmin && strings.EqualFold(username, sess.Username) && store.NormalizeUIRole(user.Role) != "admin" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "you cannot demote yourself")
		return
	}
	if req.Password != "" {
		if len(req.Password) < 8 || len(req.Password) > maxPasswordLen {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "password must be at least 8 characters")
			return
		}
		hashed, err := cryptoutil.HashPassword(req.Password)
		if err != nil {
			log.Printf("upsert user: hash: %v", err)
			writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save the user")
			return
		}
		user.PasswordHash = hashed
	} else if isNew || user.PasswordHash == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "password is required for a new user")
		return
	}
	if err := s.store.UpsertUIUser(ctx, user); err != nil {
		log.Printf("upsert user: %v", err)
		writeNativeError(w, http.StatusBadRequest, "save_failed", "could not save the user")
		return
	}
	if !sess.PlatformAdmin && sess.AccountID != "" {
		// Account admins set the role in their own account.
		if err := s.store.AddUserAccount(ctx, username, sess.AccountID, role); err != nil {
			log.Printf("upsert user: membership: %v", err)
			writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save the membership")
			return
		}
	}
	if req.Password != "" && !isNew {
		// A reset password ends the user's existing sessions.
		if _, err := s.store.DeleteUserConsoleSessions(ctx, username, ""); err != nil {
			log.Printf("upsert user: revoke sessions: %v", err)
		}
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpsertUser", KeyID: username, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"username": username, "created": isNew})
}

// handleV1DeleteUser removes a console user (and, with them, their sessions
// and memberships).
func (s *Server) handleV1DeleteUser(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username is required")
		return
	}
	if strings.EqualFold(username, sess.Username) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "you cannot delete your own account")
		return
	}
	user, err := s.store.GetUIUser(ctx, username)
	if errors.Is(err, store.ErrUIUserNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if err != nil {
		log.Printf("delete user: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the user")
		return
	}
	if !s.adminCanManageUser(ctx, sess, user) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "that user belongs to other accounts; ask a platform admin")
		return
	}
	if err := s.store.DeleteUIUser(ctx, username); err != nil {
		log.Printf("delete user: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the user")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteUser", KeyID: username, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- master admin: accounts ------------------------------------------------

type nativeAccount struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

// handleV1ListAccounts lists accounts: all of them for platform admins, the
// caller's own accounts otherwise.
func (s *Server) handleV1ListAccounts(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	accounts, err := s.store.ListUIAccounts(ctx)
	if err != nil {
		log.Printf("list accounts: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list accounts")
		return
	}
	out := make([]nativeAccount, 0, len(accounts))
	for _, a := range accounts {
		if !sess.PlatformAdmin && !slices.Contains(sess.Accounts, a.AccountID) {
			continue
		}
		out = append(out, nativeAccount{AccountID: a.AccountID, Name: a.Name, CreatedAt: a.CreatedAt})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

type nativeCreateAccountRequest struct {
	Name string `json:"name"`
}

// requirePlatformAdmin is nativeSession(admin) restricted to platform admins.
func (s *Server) requirePlatformAdmin(w http.ResponseWriter, r *http.Request) (*uiSession, context.Context, bool) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return nil, nil, false
	}
	if !sess.PlatformAdmin {
		writeNativeError(w, http.StatusForbidden, "forbidden", "only platform admins can do that")
		return nil, nil, false
	}
	return sess, ctx, true
}

// handleV1CreateAccount creates a new account (platform admins only).
func (s *Server) handleV1CreateAccount(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	var req nativeCreateAccountRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if !accountNameRe.MatchString(name) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "account name must be 1-63 letters, digits, spaces, dots, dashes or underscores")
		return
	}
	accountID, err := s.store.CreateUIAccount(ctx, name)
	if err != nil {
		log.Printf("create account: %v", err)
		writeNativeError(w, http.StatusBadRequest, "create_failed", "could not create the account (is the name taken?)")
		return
	}
	// Provision the account's immutable default key (alias/default). Best-effort:
	// a failure here is logged but does not fail account creation, and the
	// startup backfill will retry on the next restart.
	if _, err := s.store.EnsureAccountDefaultKey(ctx, accountID); err != nil {
		log.Printf("warning: failed to provision default key for account %s: %v", accountID, err)
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateAccount", KeyID: accountID, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"accountId": accountID, "created": true})
}

// handleV1DeleteAccount deletes an account (platform admins only).
func (s *Server) handleV1DeleteAccount(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	accountID := strings.TrimSpace(r.URL.Query().Get("accountId"))
	if accountID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "accountId is required")
		return
	}
	if accountID == strings.TrimSpace(sess.AccountID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "you cannot delete the account you are signed into")
		return
	}
	if err := s.store.DeleteUIAccount(ctx, accountID); err != nil {
		if errors.Is(err, store.ErrUIAccountNotFound) {
			writeNativeError(w, http.StatusNotFound, "not_found", "account not found")
			return
		}
		log.Printf("delete account: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the account")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteAccount", KeyID: accountID, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

type nativeUserAccountRequest struct {
	Username  string `json:"username"`
	AccountID string `json:"accountId"`
	Role      string `json:"role"`
}

// adminCanManageAccount reports whether sess may change accountID's
// memberships: platform admins any account, account admins their own.
func adminCanManageAccount(sess *uiSession, accountID string) bool {
	return sess.PlatformAdmin || accountID == sess.AccountID
}

// handleV1AssignUserAccount grants a user membership in an account, or
// changes their role there.
func (s *Server) handleV1AssignUserAccount(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeUserAccountRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	username := strings.TrimSpace(req.Username)
	accountID := strings.TrimSpace(req.AccountID)
	if username == "" || accountID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username and accountId are required")
		return
	}
	if req.Role != "" && !validRoleName(req.Role) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "role must be viewer, editor or admin")
		return
	}
	if !adminCanManageAccount(sess, accountID) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "account admins can only manage their own account")
		return
	}
	if _, found := s.lookupUser(ctx, username); !found {
		writeNativeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if err := s.store.AddUserAccount(ctx, username, accountID, store.NormalizeUIRole(req.Role)); err != nil {
		log.Printf("assign membership: %v", err)
		writeNativeError(w, http.StatusBadRequest, "assign_failed", "could not assign the membership")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.AssignUserAccount", KeyID: accountID + ":" + username, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"assigned": true})
}

// handleV1RemoveUserAccount revokes a user's membership in an account.
func (s *Server) handleV1RemoveUserAccount(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	accountID := strings.TrimSpace(r.URL.Query().Get("accountId"))
	if username == "" || accountID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username and accountId are required")
		return
	}
	if !adminCanManageAccount(sess, accountID) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "account admins can only manage their own account")
		return
	}
	if err := s.store.RemoveUserAccount(ctx, username, accountID); err != nil {
		log.Printf("remove membership: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "remove_failed", "could not remove the membership")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RemoveUserAccount", KeyID: accountID + ":" + username, Result: "ok", Actor: sess.Username})
	writeNativeJSON(w, http.StatusOK, map[string]any{"removed": true})
}

// ---- certificates: create CA / issue / revoke ------------------------------

// bridgeForm returns a shallow copy of r whose form values are populated from
// the supplied map and whose context is scoped to ctx. It lets the native JSON
// handlers reuse the existing form-based certificate helpers without
// duplicating their cryptography.
func bridgeForm(r *http.Request, ctx context.Context, values map[string]string) *http.Request {
	form := url.Values{}
	for k, v := range values {
		form.Set(k, v)
	}
	r2 := r.Clone(ctx)
	r2.PostForm = form
	r2.Form = form
	return r2
}

type nativeCreateCARequest struct {
	CAType           string `json:"caType"`
	KeyAlgorithm     string `json:"keyAlgorithm"`
	SigningAlgorithm string `json:"signingAlgorithm"`
	CommonName       string `json:"commonName"`
	Organization     string `json:"organization"`
	Country          string `json:"country"`
}

// handleV1CreateCA provisions a new private certificate authority.
func (s *Server) handleV1CreateCA(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeCreateCARequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	bridged := bridgeForm(r, ctx, map[string]string{
		"ca_type":           req.CAType,
		"key_algorithm":     req.KeyAlgorithm,
		"signing_algorithm": req.SigningAlgorithm,
		"common_name":       req.CommonName,
		"organization":      req.Organization,
		"country":           req.Country,
	})
	caID, err := s.adminCreateCA(bridged)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateCA", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"caId": caID, "created": true})
}

type nativeIssueCertRequest struct {
	CAARN            string `json:"caArn"`
	CSRPEM           string `json:"csrPem"`
	ValidityDays     string `json:"validityDays"`
	SigningAlgorithm string `json:"signingAlgorithm"`
	OverrideCN       string `json:"overrideCommonName"`
	SANNames         string `json:"sanNames"`
}

// handleV1IssueCert signs a CSR with a private CA and stores the certificate.
func (s *Server) handleV1IssueCert(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeIssueCertRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	bridged := bridgeForm(r, ctx, map[string]string{
		"ca_arn":            req.CAARN,
		"csr_pem":           req.CSRPEM,
		"validity_days":     req.ValidityDays,
		"signing_algorithm": req.SigningAlgorithm,
		"override_cn":       req.OverrideCN,
		"san_names":         req.SANNames,
	})
	if err := s.adminIssueCert(bridged); err != nil {
		writeNativeError(w, http.StatusBadRequest, "issue_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.IssueCertificate", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"issued": true})
}

type nativeRevokeCertRequest struct {
	CertID string `json:"certId"`
	Reason string `json:"reason"`
}

// handleV1RevokeCert revokes an issued certificate.
func (s *Server) handleV1RevokeCert(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeRevokeCertRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	bridged := bridgeForm(r, ctx, map[string]string{
		"cert_id": req.CertID,
		"reason":  req.Reason,
	})
	if err := s.adminRevokeCert(bridged); err != nil {
		writeNativeError(w, http.StatusBadRequest, "revoke_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevokeCertificate", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

type nativeImportCARequest struct {
	CACertPEM   string `json:"caCertPem"`
	CAKeyPEM    string `json:"caKeyPem"`
	Description string `json:"description"`
}

// handleV1ImportCA imports an externally generated CA certificate and key.
func (s *Server) handleV1ImportCA(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeImportCARequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	bridged := bridgeForm(r, ctx, map[string]string{
		"ca_cert_pem": req.CACertPEM,
		"ca_key_pem":  req.CAKeyPEM,
		"description": req.Description,
	})
	caID, err := s.adminImportCA(bridged)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "import_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ImportCA", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"caId": caID, "imported": true})
}

type nativeRenewCertRequest struct {
	CertID       string `json:"certId"`
	ValidityDays string `json:"validityDays"`
}

// handleV1RenewCert re-issues an existing certificate with a fresh validity window.
func (s *Server) handleV1RenewCert(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeRenewCertRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	bridged := bridgeForm(r, ctx, map[string]string{
		"cert_id":       req.CertID,
		"validity_days": req.ValidityDays,
	})
	if err := s.adminRenewCert(bridged); err != nil {
		writeNativeError(w, http.StatusBadRequest, "renew_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RenewCertificate", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"renewed": true})
}

// handleV1GetLESettings returns the configured ACME/Let's Encrypt directory and
// contact email so the console can pre-populate the settings form.
func (s *Server) handleV1GetLESettings(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	directoryURL := s.acmeLEDirectoryURL(ctx)
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"environment":  leDirectoryEnvLabel(directoryURL),
		"directoryUrl": directoryURL,
		"contactEmail": s.acmeLEContactEmail(ctx),
	})
}

type nativeLESettingsRequest struct {
	Environment  string `json:"environment"`
	DirectoryURL string `json:"directoryUrl"`
	ContactEmail string `json:"contactEmail"`
}

// handleV1SaveLESettings persists the ACME directory selection and contact email.
func (s *Server) handleV1SaveLESettings(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeLESettingsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	bridged := bridgeForm(r, ctx, map[string]string{
		"le_environment":   req.Environment,
		"le_directory_url": req.DirectoryURL,
		"le_contact_email": req.ContactEmail,
	})
	if err := s.adminSaveLESettings(bridged); err != nil {
		writeNativeError(w, http.StatusBadRequest, "save_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.SaveLESettings", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

type nativeRequestLECertRequest struct {
	Domains string `json:"domains"`
}

// handleV1RequestLECert issues a publicly-trusted certificate from Let's Encrypt.
func (s *Server) handleV1RequestLECert(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeRequestLECertRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	bridged := bridgeForm(r, ctx, map[string]string{
		"le_domains": req.Domains,
	})
	if err := s.adminRequestLECert(bridged); err != nil {
		writeNativeError(w, http.StatusBadRequest, "request_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RequestLetsEncrypt", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"requested": true})
}

type nativeBeginLEDNSRequest struct {
	Domains string `json:"domains"`
}

// handleV1BeginLEDNSOrder starts a manual DNS-01 Let's Encrypt order and returns
// the TXT records the operator must publish at their DNS provider.
func (s *Server) handleV1BeginLEDNSOrder(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeBeginLEDNSRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	orderID, records, err := s.beginLEDNSOrder(ctx, []string{req.Domains})
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "begin_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.BeginLetsEncryptDNS", Result: "ok", Actor: r.RemoteAddr})
	recs := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		recs = append(recs, map[string]any{"domain": rec.Domain, "name": rec.Name, "value": rec.Value})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"orderId": orderID, "records": recs})
}

type nativeCompleteLEDNSRequest struct {
	OrderID string `json:"orderId"`
}

// handleV1CompleteLEDNSOrder validates the published DNS-01 records and
// finalizes issuance for a previously-begun manual order.
func (s *Server) handleV1CompleteLEDNSOrder(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeCompleteLEDNSRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if strings.TrimSpace(req.OrderID) == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "orderId is required")
		return
	}
	cert, err := s.completeLEDNSOrder(ctx, strings.TrimSpace(req.OrderID))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "complete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CompleteLetsEncryptDNS", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"certId": cert.CertID, "domains": cert.Domains, "issued": true})
}

// rehashOnLogin replaces a verified legacy credential (Argon2id, plaintext or
// an outdated PBKDF2 hash) with a current PBKDF2 hash, in the database and in
// the store. Failures are logged, never fatal: the login already succeeded.
func (s *Server) rehashOnLogin(ctx context.Context, user store.UIUser, password string) {
	if !cryptoutil.NeedsRehash(user.StoredCredential()) {
		return
	}
	hashed, err := cryptoutil.HashPassword(password)
	if err != nil {
		log.Printf("password rehash for %q: %v", user.Username, err)
		return
	}
	user.PasswordHash = hashed
	user.Password = ""
	if err := s.store.UpsertUIUser(ctx, user); err != nil {
		log.Printf("password rehash for %q: %v", user.Username, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RehashPassword", Result: "ok", Actor: user.Username})
}
