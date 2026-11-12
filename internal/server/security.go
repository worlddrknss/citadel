package server

import (
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// HTTP middleware
// ---------------------------------------------------------------------------

// withPanicRecovery converts unhandled panics into a generic 500 and logs the
// stack server-side, preventing a single bad request from crashing the process.
func withPanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %v\n%s", rec, debug.Stack())
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"__type":"InternalFailure","message":"internal error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders adds defensive headers, primarily for the admin UI.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/login" || r.URL.Path == "/logout" || r.URL.Path == "/secrets" || r.URL.Path == "/audit" || strings.HasPrefix(r.URL.Path, "/admin") {
			h := w.Header()
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

// sessionExpired reports whether a UI session has exceeded its idle or absolute
// lifetime.
func sessionExpired(sess uiSession, now time.Time, idleTTL, absoluteTTL time.Duration) bool {
	if absoluteTTL > 0 && now.Sub(sess.CreatedAt) > absoluteTTL {
		return true
	}
	if idleTTL > 0 && now.Sub(sess.LastSeenAt) > idleTTL {
		return true
	}
	return false
}
