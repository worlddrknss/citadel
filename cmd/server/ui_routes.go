package main

import (
	"net/http"
	"strings"
)

// handleRoot serves the operator UI for browser traffic while preserving
// AWS-compatible JSON-RPC behavior for API clients that post to '/'.
func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if strings.TrimSpace(r.Header.Get("X-Amz-Target")) != "" || strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/x-amz-json") {
			// Use DB-backed SigV4 verification if available
			s.handleKMSWithDBBackedAuth(w, r)
			return
		}
	}
	// P7: the Svelte SPA is now the primary control plane. Browser traffic to
	// the site root is sent to /app/. Legacy html/template pages remain
	// reachable at their own paths (e.g. /login, /admin) until fully retired.
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		http.Redirect(w, r, "/app/", http.StatusFound)
		return
	}
	s.handleAdmin(w, r)
}
