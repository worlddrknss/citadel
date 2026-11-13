package server

import (
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
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

const (
	// apiCSP applies to every non-console response (JSON, AWS APIs, ACME,
	// CRLs): nothing in them may load or run anything.
	apiCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	// hstsValue is sent when TLS is configured.
	hstsValue = "max-age=63072000; includeSubDomains"
)

// appCSP is the console's policy. scriptHashes are the quoted 'sha256-...'
// sources for the inline scripts of the HTML page being served (the
// SvelteKit bootstrap and the theme script); assets come from 'self'.
// Svelte transitions inject style elements at runtime, hence the inline
// styles allowance.
func appCSP(scriptHashes []string) string {
	script := "script-src 'self'"
	if len(scriptHashes) > 0 {
		script += " " + strings.Join(scriptHashes, " ")
	}
	return "default-src 'self'; " + script + "; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
		"connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
}

// withSecurityHeaders sets defensive headers on every response: no sniffing,
// no referrer, no framing, a CSP (strict for the API, hash-based for the
// console, which handleApp refines per page), HSTS when TLS is configured,
// and no caching of /v1 responses. Handlers may override a header.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	tls := s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != ""
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.URL.Path == "/app" || strings.HasPrefix(r.URL.Path, "/app/") {
			h.Set("Content-Security-Policy", appCSP(nil))
		} else {
			h.Set("Content-Security-Policy", apiCSP)
		}
		if tls || r.TLS != nil {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// csrfHeader must accompany state-changing /v1 requests made with the
// session cookie. Cross-site forms cannot set custom headers, and a
// cross-site fetch that does triggers a CORS preflight Citadel never
// approves.
const csrfHeader = "X-Citadel-Request"

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// withCSRFProtection guards state-changing /v1 requests:
//
//   - When an Origin header is present it must name this host; failing that,
//     a Referer header, when present, must.
//   - Requests carrying the session cookie, and the session-establishing
//     endpoints (login, logout, bootstrap), must send X-Citadel-Request: 1.
//     Requests authenticated by an Authorization header (bearer tokens,
//     SigV4) carry no ambient credential and are exempt.
func (s *Server) withCSRFProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) || !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOriginRequest(r) {
			writeNativeError(w, http.StatusForbidden, "csrf_rejected", "cross-origin request rejected")
			return
		}
		if strings.TrimSpace(r.Header.Get("Authorization")) == "" && s.needsCSRFHeader(r) && r.Header.Get(csrfHeader) != "1" {
			writeNativeError(w, http.StatusForbidden, "csrf_rejected", "missing "+csrfHeader+" header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) needsCSRFHeader(r *http.Request) bool {
	switch r.URL.Path {
	case "/v1/login", "/v1/logout", "/v1/bootstrap":
		return true
	}
	return s.sessionToken(r) != ""
}

// sameOriginRequest checks Origin (or, without it, Referer) against the
// request host. Requests with neither (non-browser clients) pass.
func sameOriginRequest(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return hostMatches(origin, r.Host)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return hostMatches(ref, r.Host)
	}
	return true
}

func hostMatches(raw, host string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// bootstrapOpenPaths are the /v1 endpoints reachable in bootstrap mode.
var bootstrapOpenPaths = map[string]bool{
	"/v1/bootstrap":      true,
	"/v1/server/info":    true,
	"/v1/auth/providers": true,
	"/v1/login":          true,
	// Describes the API; holds no data.
	"/v1/openapi.yaml": true,
}

// withBootstrapGate closes the /v1 API while the server is in bootstrap mode
// (no console users yet), except first-run setup and the sign-in screen's
// own calls.
func (s *Server) withBootstrapGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") && !bootstrapOpenPaths[r.URL.Path] && s.bootstrapRequired(r.Context()) {
			writeNativeError(w, http.StatusUnauthorized, "bootstrap_required", "Citadel has not been set up yet")
			return
		}
		next.ServeHTTP(w, r)
	})
}
