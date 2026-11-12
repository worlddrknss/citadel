package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// Console sessions are persisted in the store (console_sessions), keyed by
// the SHA-256 of a random 256-bit token carried in an HttpOnly cookie, so
// they survive restarts and work across replicas. Idle and absolute
// lifetimes come from the organization settings when set, else from
// KMS_UI_SESSION_IDLE_TTL / KMS_UI_SESSION_MAX_TTL. Expired rows are purged
// by the "console-session-purge" job.

const (
	sessionCookieSecure   = "__Host-citadel_session"
	sessionCookieInsecure = "citadel_session"

	defaultSessionAbsTTL = 12 * time.Hour
	// sessionTouchInterval bounds how often a request writes last_seen_at.
	sessionTouchInterval = 30 * time.Second
	orgSettingsCacheTTL  = 15 * time.Second
)

var errSessionInvalid = errors.New("session invalid")

// authState holds the process-local authentication machinery: rate limiters,
// the bootstrap latch and a short-lived org settings cache.
type authState struct {
	loginIP     *ratelimit.Limiter
	loginUser   *ratelimit.Limiter
	failIP      *ratelimit.Backoff
	failUser    *ratelimit.Backoff
	bootstrapIP *ratelimit.Limiter

	// bootstrapped latches true once any console user is known to exist.
	bootstrapped atomic.Bool
	// envUsers are the console users configured through the environment
	// (not the database). nil when the server was not built by New.
	envUsers map[string]store.UIUser

	settingsMu      sync.Mutex
	settings        store.OrgSettings
	settingsFetched time.Time
}

func newAuthState() *authState {
	return &authState{
		// Attempts are throttled per client address and per username;
		// failures additionally back off exponentially (lockout).
		loginIP:     ratelimit.New(3*time.Second, 20),
		loginUser:   ratelimit.New(6*time.Second, 10),
		failIP:      ratelimit.NewBackoff(20, time.Second, 15*time.Minute, time.Hour),
		failUser:    ratelimit.NewBackoff(5, time.Second, 15*time.Minute, time.Hour),
		bootstrapIP: ratelimit.New(time.Minute, 5),
	}
}

// auth returns the server's authState, creating it on first use (servers
// built directly in tests have none).
func (s *Server) auth() *authState {
	s.authOnce.Do(func() {
		if s.authV == nil {
			s.authV = newAuthState()
		}
	})
	return s.authV
}

func (s *Server) dbBacked() bool {
	_, ok := s.store.(*postgres.Store)
	return ok
}

// envUsers returns the environment-configured console users.
func (s *Server) envUsers() map[string]store.UIUser {
	if u := s.auth().envUsers; u != nil {
		return u
	}
	return s.cfg.UIUsers
}

// lookupUser returns a console user from the store, falling back for the
// in-memory store to the environment-configured users (which it does not
// hold). The PostgreSQL store holds every user, env ones included.
func (s *Server) lookupUser(ctx context.Context, username string) (store.UIUser, bool) {
	u, err := s.store.GetUIUser(ctx, username)
	if err == nil {
		return u, true
	}
	if !errors.Is(err, store.ErrUIUserNotFound) {
		log.Printf("console user lookup failed: %v", err)
		return store.UIUser{}, false
	}
	if !s.dbBacked() {
		if u, ok := s.envUsers()[username]; ok {
			return u, true
		}
	}
	return store.UIUser{}, false
}

// isPlatformAdmin reports whether user may administer every account (see the
// role model in admin_auth.go).
func (s *Server) isPlatformAdmin(user store.UIUser) bool {
	if store.NormalizeUIRole(user.Role) != "admin" {
		return false
	}
	if user.PlatformAdmin {
		return true
	}
	env, ok := s.envUsers()[user.Username]
	return ok && store.NormalizeUIRole(env.Role) == "admin"
}

// membership is one account a user belongs to, with the effective role.
type membership struct {
	AccountID string
	Role      string
}

// userMemberships returns every account user belongs to with the effective
// role there: the membership's own role when valid, else the global role.
func (s *Server) userMemberships(ctx context.Context, user store.UIUser) []membership {
	var out []membership
	seen := map[string]bool{}
	rows, err := s.store.ListUserAccounts(ctx, user.Username)
	if err != nil {
		log.Printf("list memberships failed: %v", err)
	}
	for _, ua := range rows {
		id := strings.TrimSpace(ua.AccountID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		role := store.NormalizeUIRole(user.Role)
		if validRoleName(ua.Role) {
			role = store.NormalizeUIRole(ua.Role)
		}
		out = append(out, membership{AccountID: id, Role: role})
	}
	for _, a := range user.Accounts {
		id := strings.TrimSpace(a)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, membership{AccountID: id, Role: store.NormalizeUIRole(user.Role)})
	}
	return out
}

// accountRole returns user's effective role in accountID and whether they
// belong to it at all.
func accountRole(ms []membership, accountID string) (string, bool) {
	for _, m := range ms {
		if m.AccountID == accountID {
			return m.Role, true
		}
	}
	return "", false
}

func membershipIDs(ms []membership) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.AccountID)
	}
	return out
}

// orgSettings returns the organization settings, cached briefly so the
// per-request session check does not hit the store each time.
func (s *Server) orgSettings(ctx context.Context) store.OrgSettings {
	a := s.auth()
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	if !a.settingsFetched.IsZero() && time.Since(a.settingsFetched) < orgSettingsCacheTTL {
		return a.settings
	}
	st, err := s.store.GetOrgSettings(ctx)
	if err != nil {
		log.Printf("load org settings failed: %v", err)
		return a.settings
	}
	a.settings = st
	a.settingsFetched = time.Now()
	return st
}

func (s *Server) invalidateOrgSettings() {
	a := s.auth()
	a.settingsMu.Lock()
	a.settingsFetched = time.Time{}
	a.settingsMu.Unlock()
}

// sessionTTLs returns the effective idle and absolute session lifetimes.
// The absolute lifetime is never unbounded.
func (s *Server) sessionTTLs(ctx context.Context) (idle, abs time.Duration) {
	idle, abs = s.cfg.SessionIdleTTL, s.cfg.SessionAbsTTL
	st := s.orgSettings(ctx)
	if st.SessionIdleMinutes > 0 {
		idle = time.Duration(st.SessionIdleMinutes) * time.Minute
	}
	if st.SessionMaxHours > 0 {
		abs = time.Duration(st.SessionMaxHours) * time.Hour
	}
	if abs <= 0 {
		abs = defaultSessionAbsTTL
	}
	return idle, abs
}

func (s *Server) sessionCookieName() string {
	if s.cfg.UISecureCookies {
		return sessionCookieSecure
	}
	return sessionCookieInsecure
}

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// sessionToken returns the session cookie value, or "".
func (s *Server) sessionToken(r *http.Request) string {
	c, err := r.Cookie(s.sessionCookieName())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}

// clientIP is the TCP peer address. Forwarding headers are not trusted:
// they are client-controlled unless a proxy is known to set them.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// issueConsoleSession creates a persistent session for username scoped to
// accountID and sets the session cookie. method is store.SessionMethodPassword
// or store.SessionMethodSSO. The caller must have authenticated the user and
// checked their membership in accountID.
func (s *Server) issueConsoleSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username, accountID, method string) (store.ConsoleSession, error) {
	token := cryptoutil.RandomHex(32)
	now := time.Now().UTC()
	_, abs := s.sessionTTLs(ctx)
	sess := store.ConsoleSession{
		ID:         cryptoutil.RandomHex(16),
		TokenHash:  hashSessionToken(token),
		Username:   username,
		AccountID:  accountID,
		Method:     method,
		IP:         truncate(clientIP(r), 64),
		UserAgent:  truncate(r.UserAgent(), 512),
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(abs),
	}
	if err := s.store.CreateConsoleSession(ctx, sess); err != nil {
		return store.ConsoleSession{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   int(abs / time.Second),
		HttpOnly: true,
		Secure:   s.cfg.UISecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	return sess, nil
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.sessionCookieName(), Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: s.cfg.UISecureCookies, SameSite: http.SameSiteStrictMode,
	})
}

// resolveSession turns a session cookie token into the caller, enforcing the
// idle and absolute lifetimes and re-resolving the user and their role in the
// session's account. Invalid sessions are deleted.
func (s *Server) resolveSession(ctx context.Context, token string) (*uiSession, error) {
	row, err := s.store.GetConsoleSessionByTokenHash(ctx, hashSessionToken(token))
	if err != nil {
		if !errors.Is(err, store.ErrConsoleSessionNotFound) {
			log.Printf("session lookup failed: %v", err)
		}
		return nil, errSessionInvalid
	}
	drop := func() (*uiSession, error) {
		if err := s.store.DeleteConsoleSession(ctx, row.Username, row.ID); err != nil && !errors.Is(err, store.ErrConsoleSessionNotFound) {
			log.Printf("delete invalid session failed: %v", err)
		}
		return nil, errSessionInvalid
	}
	now := time.Now().UTC()
	idle, abs := s.sessionTTLs(ctx)
	if !now.Before(row.ExpiresAt) || sessionExpired(uiSession{CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt}, now, idle, abs) {
		return drop()
	}
	if now.Sub(row.LastSeenAt) >= sessionTouchInterval {
		if err := s.store.TouchConsoleSession(ctx, row.ID, now); err != nil {
			log.Printf("touch session failed: %v", err)
		}
		row.LastSeenAt = now
	}
	sess, err := s.sessionFromRow(ctx, row)
	if err != nil {
		return drop()
	}
	return sess, nil
}

// sessionFromRow builds the caller for a stored session, re-resolving the
// user and their effective role in the session's account. It fails when the
// user no longer exists or no longer belongs to that account.
func (s *Server) sessionFromRow(ctx context.Context, row store.ConsoleSession) (*uiSession, error) {
	user, ok := s.lookupUser(ctx, row.Username)
	if !ok {
		return nil, errSessionInvalid
	}
	ms := s.userMemberships(ctx, user)
	role, member := accountRole(ms, row.AccountID)
	if !member {
		return nil, errSessionInvalid
	}
	return &uiSession{
		SessionID:     row.ID,
		Username:      user.Username,
		AccountID:     row.AccountID,
		Role:          role,
		DisplayName:   user.DisplayName,
		Accounts:      membershipIDs(ms),
		PlatformAdmin: s.isPlatformAdmin(user),
		Method:        row.Method,
		CreatedAt:     row.CreatedAt,
		LastSeenAt:    row.LastSeenAt,
	}, nil
}

// bootstrapRequired reports whether the server is in bootstrap mode: not
// insecure dev, and no console user exists in the store or the environment.
// Once users exist the answer is latched (users are never all deleted: an
// admin cannot delete themselves).
func (s *Server) bootstrapRequired(ctx context.Context) bool {
	a := s.auth()
	if a.bootstrapped.Load() || s.cfg.InsecureDev {
		return false
	}
	if len(s.envUsers()) > 0 {
		a.bootstrapped.Store(true)
		return false
	}
	n, err := s.store.CountUIUsers(ctx)
	if err != nil {
		log.Printf("count console users failed: %v", err)
		// Fail closed: treat as bootstrap mode (API closed) without
		// offering bootstrap, which re-checks inside the store.
		return true
	}
	if n > 0 {
		a.bootstrapped.Store(true)
		return false
	}
	return true
}

// hasConsoleUsers reports whether any console user exists.
func (s *Server) hasConsoleUsers(ctx context.Context) bool {
	if s.auth().bootstrapped.Load() || len(s.envUsers()) > 0 {
		return true
	}
	n, err := s.store.CountUIUsers(ctx)
	return err != nil || n > 0
}

// purgeExpiredSessions is the console-session-purge job.
func (s *Server) purgeExpiredSessions(ctx context.Context) error {
	now := time.Now().UTC()
	idle, _ := s.sessionTTLs(ctx)
	var idleCutoff time.Time
	if idle > 0 {
		idleCutoff = now.Add(-idle)
	}
	n, err := s.store.DeleteExpiredConsoleSessions(ctx, now, idleCutoff)
	if err != nil {
		return err
	}
	if n > 0 {
		log.Printf("purged %d expired console sessions", n)
	}
	return nil
}

// purgeExpiredSTSSessions is the sts-session-purge job.
func (s *Server) purgeExpiredSTSSessions(ctx context.Context) error {
	n, err := s.store.DeleteExpiredSTSSessions(ctx)
	if errors.Is(err, store.ErrUnsupported) {
		return nil
	}
	if err != nil {
		return err
	}
	if n > 0 {
		log.Printf("purged %d expired STS sessions", n)
	}
	return nil
}
