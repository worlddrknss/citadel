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
			s.handleKMS(w, r)
			return
		}
	}
	s.handleAdmin(w, r)
}
