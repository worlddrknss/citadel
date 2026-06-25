package main

import (
	"net/http"
	"strings"
)

// handleRoot serves the operator UI for browser traffic while preserving
// AWS-compatible JSON-RPC behavior for API clients that post to '/'.
func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// STS speaks the AWS Query protocol (form-encoded, Action=...) rather
		// than the X-Amz-Target JSON-RPC dialect used by the other services.
		if isSTSRequest(r) {
			s.handleSTS(w, r)
			return
		}
		if strings.TrimSpace(r.Header.Get("X-Amz-Target")) != "" || strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/x-amz-json") {
			// Use DB-backed SigV4 verification if available
			s.handleKMSWithDBBackedAuth(w, r)
			return
		}
	}
	// The Svelte SPA is the only control plane. Browser traffic to any
	// non-API path is sent to /app/; the legacy html/template pages have been
	// retired in favor of the native /v1 API consumed by the SPA.
	http.Redirect(w, r, "/app/", http.StatusFound)
}
