package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
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
// the SPA (and the rest of /v1) relies on. It is the JSON-native replacement
// for the legacy /login html form.
func (s *server) handleV1Login(w http.ResponseWriter, r *http.Request) {
	runtime := s.uiRuntime()
	if !runtime.enabled {
		// Auth disabled (local dev / bootstrap): every caller is the local
		// admin, so report success without a cookie.
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
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	accountID := strings.TrimSpace(req.AccountID)
	username := strings.TrimSpace(req.Username)
	if accountID == "" || username == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "account ID and username are required")
		return
	}

	runtime.mu.Lock()
	user, ok := runtime.users[username]
	runtime.mu.Unlock()

	// Always run a verification to keep timing roughly constant and avoid
	// user-enumeration via response timing.
	stored := dummyArgon2Hash
	if ok {
		stored = user.storedCredential()
	}
	if !verifyPassword(stored, req.Password) || !ok {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials")
		return
	}

	// Confirm the user may access the requested account. Prefer the DB-backed
	// junction table; fall back to statically-configured accounts.
	found := false
	if userAccounts, err := s.store.ListUserAccounts(r.Context(), username); err == nil {
		for _, ua := range userAccounts {
			if ua.AccountID == accountID {
				found = true
				break
			}
		}
	}
	if !found {
		for _, a := range user.Accounts {
			if a == accountID {
				found = true
				break
			}
		}
	}
	if !found {
		writeNativeError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials or account access denied")
		return
	}

	sessionID := randomHex(24)
	now := time.Now().UTC()
	session := uiSession{
		SessionID:   sessionID,
		Username:    user.Username,
		AccountID:   accountID,
		Role:        user.Role,
		DisplayName: user.DisplayName,
		Accounts:    append([]string(nil), user.Accounts...),
		CreatedAt:   now,
		LastSeenAt:  now,
	}
	runtime.mu.Lock()
	runtime.sessions[sessionID] = session
	runtime.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookieName, Value: sessionID, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: runtime.secureCookies})
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"username":    session.Username,
		"displayName": session.DisplayName,
		"role":        session.Role,
		"accountId":   session.AccountID,
		"accounts":    session.Accounts,
	})
}

// handleV1Logout clears the active session and cookie.
func (s *server) handleV1Logout(w http.ResponseWriter, r *http.Request) {
	runtime := s.uiRuntime()
	if cookie, err := r.Cookie(adminSessionCookieName); err == nil {
		runtime.mu.Lock()
		delete(runtime.sessions, cookie.Value)
		runtime.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookieName, Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeNativeJSON(w, http.StatusOK, map[string]any{"loggedOut": true})
}

// ---- KMS key management ----------------------------------------------------

type nativeCreateKMSKeyRequest struct {
	Description string `json:"description"`
	KeyUsage    string `json:"keyUsage"`
	KeySpec     string `json:"keySpec"`
}

// handleV1CreateKMSKey provisions a new customer master key.
func (s *server) handleV1CreateKMSKey(w http.ResponseWriter, r *http.Request) {
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
		usage = keyUsageEncryptDecrypt
	}
	spec := strings.TrimSpace(req.KeySpec)
	if spec == "" {
		spec = keySpecSymmetricDefault
	}
	key, err := s.store.CreateKey(ctx, strings.TrimSpace(req.Description), usage, spec)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateKey", KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": key.ID, "arn": key.ARN, "created": true})
}

type nativeKMSKeyActionRequest struct {
	KeyID      string `json:"keyId"`
	Enabled    bool   `json:"enabled"`
	WindowDays int    `json:"windowDays"`
}

// handleV1SetKMSKeyEnabled enables or disables a key.
func (s *server) handleV1SetKMSKeyEnabled(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: action, KeyID: keyID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": keyID, "enabled": req.Enabled})
}

// handleV1ScheduleKMSKeyDeletion schedules a key for deletion.
func (s *server) handleV1ScheduleKMSKeyDeletion(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.ScheduleKeyDeletion", KeyID: keyID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": keyID, "deletionDate": when.UTC().Format(time.RFC3339)})
}

// handleV1CancelKMSKeyDeletion cancels a pending key deletion.
func (s *server) handleV1CancelKMSKeyDeletion(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.CancelKeyDeletion", KeyID: keyID, Result: "ok", Actor: r.RemoteAddr})
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
func (s *server) handleV1ListAccessKeys(w http.ResponseWriter, r *http.Request) {
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
func (s *server) handleV1CreateAccessKey(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	secret, err := s.store.CreateAccessKey(ctx, sess.Username, sess.AccountID)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateAccessKey", Result: "ok", Actor: r.RemoteAddr})
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
func (s *server) handleV1DeleteAccessKey(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteAccessKey", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// handleV1SetAccessKeyStatus activates or deactivates one of the caller's keys.
func (s *server) handleV1SetAccessKeyStatus(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.SetAccessKeyStatus", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"accessKeyId": keyID, "status": status})
}

// guardOwnAccessKey ensures a non-admin caller can only act on access keys that
// belong to their own username, preventing cross-user key tampering.
func (s *server) guardOwnAccessKey(ctx context.Context, sess *uiSession, keyID string) error {
	owner, _, _, _, err := s.store.GetAccessKeyByID(ctx, keyID)
	if err != nil {
		return err
	}
	if !strings.EqualFold(owner, sess.Username) && !uiRoleAtLeast(sess.Role, "admin") {
		return errAccessKeyNotFound
	}
	return nil
}

type nativeChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// handleV1ChangePassword updates the caller's password after verifying the
// current one.
func (s *server) handleV1ChangePassword(w http.ResponseWriter, r *http.Request) {
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
	users, err := s.store.ListUIUsers(ctx)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "failed to verify credentials")
		return
	}
	var current *uiUserConfig
	for i := range users {
		if users[i].Username == sess.Username {
			current = &users[i]
			break
		}
	}
	if current == nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if !verifyPassword(current.storedCredential(), req.CurrentPassword) {
		writeNativeError(w, http.StatusForbidden, "forbidden", "current password is incorrect")
		return
	}
	hashed, err := hashPassword(req.NewPassword)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "failed to hash password")
		return
	}
	current.PasswordHash = hashed
	current.Password = ""
	if err := s.store.UpsertUIUser(ctx, *current); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.ChangePassword", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

// ---- master admin: users ---------------------------------------------------

type nativeUser struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Role        string   `json:"role"`
	Accounts    []string `json:"accounts"`
}

// handleV1ListUsers lists the admin-console users.
func (s *server) handleV1ListUsers(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	users, err := s.store.ListUIUsers(ctx)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]nativeUser, 0, len(users))
	for _, u := range users {
		out = append(out, nativeUser{Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Accounts: u.Accounts})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"users": out})
}

type nativeUpsertUserRequest struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Role        string   `json:"role"`
	Password    string   `json:"password"`
	Accounts    []string `json:"accounts"`
}

// handleV1UpsertUser creates or updates an admin-console user.
func (s *server) handleV1UpsertUser(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeUpsertUserRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username is required")
		return
	}
	user := uiUserConfig{
		Username:    username,
		DisplayName: strings.TrimSpace(req.DisplayName),
		Role:        normalizeUIRole(req.Role),
		Accounts:    req.Accounts,
	}
	if user.DisplayName == "" {
		user.DisplayName = username
	}
	// A password is required when creating a brand-new user; for updates it is
	// optional and only changed when supplied.
	existing, _ := s.store.ListUIUsers(ctx)
	isNew := true
	for _, u := range existing {
		if u.Username == username {
			isNew = false
			user.PasswordHash = u.PasswordHash
			if len(req.Accounts) == 0 {
				user.Accounts = u.Accounts
			}
			break
		}
	}
	if strings.TrimSpace(req.Password) != "" {
		if len(req.Password) < 8 {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "password must be at least 8 characters")
			return
		}
		hashed, err := hashPassword(req.Password)
		if err != nil {
			writeNativeError(w, http.StatusInternalServerError, "create_failed", "failed to hash password")
			return
		}
		user.PasswordHash = hashed
	} else if isNew {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "password is required for a new user")
		return
	}
	if err := s.store.UpsertUIUser(ctx, user); err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.UpsertUser", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"username": username, "created": isNew})
}

// handleV1DeleteUser removes an admin-console user.
func (s *server) handleV1DeleteUser(w http.ResponseWriter, r *http.Request) {
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
	if err := s.store.DeleteUIUser(ctx, username); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteUser", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- master admin: accounts ------------------------------------------------

type nativeAccount struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

// handleV1ListAccounts lists the deployment's accounts (organizations).
func (s *server) handleV1ListAccounts(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	accounts, err := s.store.ListUIAccounts(ctx)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]nativeAccount, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, nativeAccount{AccountID: a.AccountID, Name: a.Name, CreatedAt: a.CreatedAt})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

type nativeCreateAccountRequest struct {
	Name string `json:"name"`
}

// handleV1CreateAccount creates a new account.
func (s *server) handleV1CreateAccount(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeCreateAccountRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "account name is required")
		return
	}
	accountID, err := s.store.CreateUIAccount(ctx, req.Name)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	// Provision the account's immutable default key (alias/default). Best-effort:
	// a failure here is logged but does not fail account creation, and the
	// startup backfill will retry on the next restart.
	if _, err := s.store.EnsureAccountDefaultKey(ctx, accountID); err != nil {
		log.Printf("warning: failed to provision default key for account %s: %v", accountID, err)
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateAccount", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"accountId": accountID, "created": true})
}

// handleV1DeleteAccount deletes an account.
func (s *server) handleV1DeleteAccount(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
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
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteAccount", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

type nativeUserAccountRequest struct {
	Username  string `json:"username"`
	AccountID string `json:"accountId"`
	Role      string `json:"role"`
}

// handleV1AssignUserAccount grants a user membership in an account.
func (s *server) handleV1AssignUserAccount(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeUserAccountRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	username := strings.TrimSpace(req.Username)
	accountID := strings.TrimSpace(req.AccountID)
	if username == "" || accountID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username and accountId are required")
		return
	}
	if err := s.store.AddUserAccount(ctx, username, accountID, normalizeUIRole(req.Role)); err != nil {
		writeNativeError(w, http.StatusBadRequest, "assign_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.AssignUserAccount", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"assigned": true})
}

// handleV1RemoveUserAccount revokes a user's membership in an account.
func (s *server) handleV1RemoveUserAccount(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	accountID := strings.TrimSpace(r.URL.Query().Get("accountId"))
	if username == "" || accountID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "username and accountId are required")
		return
	}
	if err := s.store.RemoveUserAccount(ctx, username, accountID); err != nil {
		writeNativeError(w, http.StatusInternalServerError, "remove_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.RemoveUserAccount", Result: "ok", Actor: r.RemoteAddr})
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
func (s *server) handleV1CreateCA(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.CreateCA", Result: "ok", Actor: r.RemoteAddr})
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
func (s *server) handleV1IssueCert(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.IssueCertificate", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"issued": true})
}

type nativeRevokeCertRequest struct {
	CertID string `json:"certId"`
	Reason string `json:"reason"`
}

// handleV1RevokeCert revokes an issued certificate.
func (s *server) handleV1RevokeCert(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.RevokeCertificate", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

type nativeImportCARequest struct {
	CACertPEM   string `json:"caCertPem"`
	CAKeyPEM    string `json:"caKeyPem"`
	Description string `json:"description"`
}

// handleV1ImportCA imports an externally generated CA certificate and key.
func (s *server) handleV1ImportCA(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.ImportCA", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"caId": caID, "imported": true})
}

type nativeRenewCertRequest struct {
	CertID       string `json:"certId"`
	ValidityDays string `json:"validityDays"`
}

// handleV1RenewCert re-issues an existing certificate with a fresh validity window.
func (s *server) handleV1RenewCert(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.RenewCertificate", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"renewed": true})
}

// handleV1GetLESettings returns the configured ACME/Let's Encrypt directory and
// contact email so the console can pre-populate the settings form.
func (s *server) handleV1GetLESettings(w http.ResponseWriter, r *http.Request) {
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
func (s *server) handleV1SaveLESettings(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.SaveLESettings", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

type nativeRequestLECertRequest struct {
	Domains string `json:"domains"`
}

// handleV1RequestLECert issues a publicly-trusted certificate from Let's Encrypt.
func (s *server) handleV1RequestLECert(w http.ResponseWriter, r *http.Request) {
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
	s.recordAudit(ctx, auditEvent{Action: "citadel.RequestLetsEncrypt", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"requested": true})
}
