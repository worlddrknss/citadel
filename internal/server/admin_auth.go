package server

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store"
)

const adminSessionCookieName = "go_kms_admin_session"

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
	users         map[string]store.UIUser
	sessions      map[string]uiSession
	idleTTL       time.Duration
	absoluteTTL   time.Duration
	secureCookies bool
	mu            sync.Mutex
}

// dummyPasswordHash is a fixed, valid PBKDF2 hash (current parameters) used to
// spend comparable CPU time when an unknown username is supplied, mitigating
// user-enumeration via response-timing differences. It corresponds to no real
// password.
const dummyPasswordHash = "$pbkdf2-sha256$i=600000$Y0q6S1JhYRMtaRnYXtT+1g$vWWUOxgQ7EVskOU4UldrOnx5wdUEiGPel/mlNcG/O+0"

func newUIRuntime(cfg config.Config) *uiRuntime {
	users := cfg.UIUsers
	if users == nil {
		users = map[string]store.UIUser{}
	}
	return &uiRuntime{
		enabled:       len(users) > 0,
		users:         users,
		sessions:      map[string]uiSession{},
		idleTTL:       cfg.SessionIdleTTL,
		absoluteTTL:   cfg.SessionAbsTTL,
		secureCookies: cfg.UISecureCookies,
	}
}

func (s *Server) uiRuntime() *uiRuntime {
	if s.ui == nil {
		s.ui = newUIRuntime(s.cfg)
	}
	return s.ui
}

func (s *Server) requireUISession(w http.ResponseWriter, r *http.Request, minRole string) (*uiSession, bool) {
	runtime := s.uiRuntime()
	if !runtime.enabled {
		if s.cfg.InsecureDev {
			return &uiSession{Username: "local", Role: "admin", DisplayName: "Local Admin"}, true
		}
		http.Error(w, "no console users are configured", http.StatusUnauthorized)
		return nil, false
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
	switch store.NormalizeUIRole(role) {
	case "admin":
		return 3
	case "editor":
		return 2
	default:
		return 1
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
