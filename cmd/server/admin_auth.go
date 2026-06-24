package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const adminSessionCookieName = "go_kms_admin_session"

type uiUserConfig struct {
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	PasswordHash string   `json:"passwordHash"`
	Role         string   `json:"role"`
	DisplayName  string   `json:"displayName"`
	Accounts     []string `json:"accounts"`
}

// UnmarshalJSON accepts both the current "accounts" key and the legacy "tenants"
// key so previously persisted user configuration (including SOPS-encrypted env
// JSON) keeps working after the tenant->account rename.
func (u *uiUserConfig) UnmarshalJSON(data []byte) error {
	type alias uiUserConfig
	aux := struct {
		*alias
		LegacyTenants []string `json:"tenants"`
	}{alias: (*alias)(u)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(u.Accounts) == 0 && len(aux.LegacyTenants) > 0 {
		u.Accounts = aux.LegacyTenants
	}
	return nil
}

// storedCredential returns the secret used to verify a login attempt. An
// Argon2id PHC hash is preferred; the plaintext Password field is only a
// fallback for legacy/env-configured users.
func (u uiUserConfig) storedCredential() string {
	if strings.TrimSpace(u.PasswordHash) != "" {
		return u.PasswordHash
	}
	return u.Password
}

type uiSession struct {
	SessionID   string
	Username    string
	AccountID   string // Current account context for this session
	Role        string
	DisplayName string
	Accounts    []string // All accounts the user belongs to
	CreatedAt   time.Time
	LastSeenAt  time.Time
}

type uiRuntime struct {
	enabled       bool
	users         map[string]uiUserConfig
	sessions      map[string]uiSession
	idleTTL       time.Duration
	absoluteTTL   time.Duration
	secureCookies bool
	mu            sync.Mutex
}

// dummyArgon2Hash is a fixed, valid Argon2id hash used to spend comparable CPU
// time when an unknown username is supplied, mitigating user-enumeration via
// response-timing differences. It corresponds to no real password.
const dummyArgon2Hash = "$argon2id$v=19$m=65536,t=3,p=2$+Zzc6FCiVBHCPF1Llgz3pQ$ZHroDCBLTiLB04VvCEgi3y0p/p4AyUyYe3rT8HAkYvc"

func loadUIUsersFromEnv() (map[string]uiUserConfig, error) {
	if raw := strings.TrimSpace(os.Getenv("KMS_UI_USERS_JSON")); raw != "" {
		var users []uiUserConfig
		if err := json.Unmarshal([]byte(raw), &users); err != nil {
			return nil, errors.New("decode KMS_UI_USERS_JSON: invalid JSON")
		}
		return normalizeUIUsers(users)
	}
	password := os.Getenv("KMS_UI_PASSWORD")
	if strings.TrimSpace(password) == "" {
		return nil, nil
	}
	return normalizeUIUsers([]uiUserConfig{{
		Username:    envOrDefault("KMS_UI_USERNAME", "admin"),
		Password:    password,
		Role:        envOrDefault("KMS_UI_ROLE", "admin"),
		DisplayName: envOrDefault("KMS_UI_DISPLAY_NAME", "Admin"),
		Accounts:    splitCommaList(envOrDefault("KMS_UI_ACCOUNTS", os.Getenv("KMS_UI_TENANTS"))),
	}})
}

func normalizeUIUsers(users []uiUserConfig) (map[string]uiUserConfig, error) {
	out := make(map[string]uiUserConfig, len(users))
	for _, user := range users {
		user.Username = strings.TrimSpace(user.Username)
		user.Password = strings.TrimSpace(user.Password)
		user.PasswordHash = strings.TrimSpace(user.PasswordHash)
		user.Role = normalizeUIRole(user.Role)
		if user.DisplayName == "" {
			user.DisplayName = user.Username
		}
		user.Accounts = normalizeAccounts(user.Accounts)
		if user.Username == "" || (user.Password == "" && user.PasswordHash == "") {
			return nil, errors.New("ui users require username and password (or passwordHash)")
		}
		out[user.Username] = user
	}
	return out, nil
}

func newUIRuntime(cfg config) *uiRuntime {
	users := cfg.uiUsers
	if users == nil {
		users = map[string]uiUserConfig{}
	}
	return &uiRuntime{
		enabled:       len(users) > 0,
		users:         users,
		sessions:      map[string]uiSession{},
		idleTTL:       cfg.sessionIdleTTL,
		absoluteTTL:   cfg.sessionAbsTTL,
		secureCookies: cfg.uiSecureCookies,
	}
}

func (s *server) uiRuntime() *uiRuntime {
	if s.ui == nil {
		s.ui = newUIRuntime(s.cfg)
	}
	return s.ui
}

func (s *server) requireUISession(w http.ResponseWriter, r *http.Request, minRole string) (*uiSession, bool) {
	runtime := s.uiRuntime()
	if !runtime.enabled {
		return &uiSession{Username: "local", Role: "admin", DisplayName: "Local Admin"}, true
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return nil, false
	}
	runtime.mu.Lock()
	session, ok := runtime.sessions[cookie.Value]
	now := time.Now().UTC()
	if ok && sessionExpired(session, now, runtime.idleTTL, runtime.absoluteTTL) {
		delete(runtime.sessions, cookie.Value)
		ok = false
	}
	if ok {
		session.LastSeenAt = now
		runtime.sessions[cookie.Value] = session
	}
	runtime.mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return nil, false
	}
	if !uiRoleAtLeast(session.Role, minRole) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return &session, true
}

func uiRoleAtLeast(actual, required string) bool {
	return uiRoleRank(actual) >= uiRoleRank(required)
}

func uiRoleRank(role string) int {
	switch normalizeUIRole(role) {
	case "admin":
		return 3
	case "editor":
		return 2
	default:
		return 1
	}
}

func normalizeUIRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "editor", "viewer":
		return strings.ToLower(strings.TrimSpace(role))
	default:
		return "viewer"
	}
}

func sanitizeAdminNextPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if strings.HasPrefix(raw, "//") {
		return "/"
	}
	allowedPrefixes := []string{"/", "/secrets", "/audit", "/admin"}
	for _, p := range allowedPrefixes {
		if strings.HasPrefix(raw, p) {
			return raw
		}
	}
	return "/"
}

func normalizeAccounts(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func splitCommaList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}
