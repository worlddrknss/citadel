package main

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const adminSessionCookieName = "go_kms_admin_session"

var adminLoginTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_login.html"))

type uiUserConfig struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	Role        string   `json:"role"`
	DisplayName string   `json:"displayName"`
	Tenants     []string `json:"tenants"`
}

type uiSession struct {
	SessionID   string
	Username    string
	Role        string
	DisplayName string
	Tenants     []string
	CreatedAt   time.Time
	LastSeenAt  time.Time
}

type uiRuntime struct {
	enabled  bool
	users    map[string]uiUserConfig
	sessions map[string]uiSession
	mu       sync.Mutex
}

type adminLoginView struct {
	NextPath string
	Error    string
	AuthOff  bool
}

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
		Tenants:     splitCommaList(os.Getenv("KMS_UI_TENANTS")),
	}})
}

func normalizeUIUsers(users []uiUserConfig) (map[string]uiUserConfig, error) {
	out := make(map[string]uiUserConfig, len(users))
	for _, user := range users {
		user.Username = strings.TrimSpace(user.Username)
		user.Password = strings.TrimSpace(user.Password)
		user.Role = normalizeUIRole(user.Role)
		if user.DisplayName == "" {
			user.DisplayName = user.Username
		}
		user.Tenants = normalizeTenants(user.Tenants)
		if user.Username == "" || user.Password == "" {
			return nil, errors.New("ui users require username and password")
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
	return &uiRuntime{enabled: len(users) > 0, users: users, sessions: map[string]uiSession{}}
}

func (s *server) uiRuntime() *uiRuntime {
	if s.ui == nil {
		s.ui = newUIRuntime(s.cfg)
	}
	return s.ui
}

func (s *server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	runtime := s.uiRuntime()
	if !runtime.enabled {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	nextPath := sanitizeAdminNextPath(r.URL.Query().Get("next"))
	if r.Method == http.MethodGet {
		s.renderAdminLogin(w, adminLoginView{NextPath: nextPath})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	runtime.mu.Lock()
	user, ok := runtime.users[username]
	runtime.mu.Unlock()
	if !ok || !compareSecret(user.Password, password) {
		s.renderAdminLogin(w, adminLoginView{NextPath: nextPath, Error: "Invalid username or password"})
		return
	}
	sessionID := randomHex(24)
	now := time.Now().UTC()
	session := uiSession{SessionID: sessionID, Username: user.Username, Role: user.Role, DisplayName: user.DisplayName, Tenants: append([]string(nil), user.Tenants...), CreatedAt: now, LastSeenAt: now}
	runtime.mu.Lock()
	runtime.sessions[sessionID] = session
	runtime.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookieName, Value: sessionID, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: false})
	http.Redirect(w, r, nextPath, http.StatusSeeOther)
}

func (s *server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	runtime := s.uiRuntime()
	if cookie, err := r.Cookie(adminSessionCookieName); err == nil {
		runtime.mu.Lock()
		delete(runtime.sessions, cookie.Value)
		runtime.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookieName, Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (s *server) requireUISession(w http.ResponseWriter, r *http.Request, minRole string) (*uiSession, bool) {
	runtime := s.uiRuntime()
	if !runtime.enabled {
		return &uiSession{Username: "local", Role: "admin", DisplayName: "Local Admin"}, true
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		http.Redirect(w, r, "/admin/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return nil, false
	}
	runtime.mu.Lock()
	session, ok := runtime.sessions[cookie.Value]
	if ok {
		session.LastSeenAt = time.Now().UTC()
		runtime.sessions[cookie.Value] = session
	}
	runtime.mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/admin/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return nil, false
	}
	if !uiRoleAtLeast(session.Role, minRole) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return &session, true
}

func (s *server) renderAdminLogin(w http.ResponseWriter, view adminLoginView) {
	if view.NextPath == "" {
		view.NextPath = "/admin"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminLoginTemplate.Execute(w, view); err != nil {
		http.Error(w, "failed to render login view", http.StatusInternalServerError)
	}
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
	if raw == "" || !strings.HasPrefix(raw, "/admin") {
		return "/admin"
	}
	return raw
}

func normalizeTenants(values []string) []string {
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