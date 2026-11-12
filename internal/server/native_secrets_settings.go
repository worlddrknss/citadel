package server

import (
	"log"
	"net/http"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Per-account secrets settings (see secrets_access.go for what they govern).
//
//	GET  /v1/secrets/settings (viewer) -> {viewersCanReveal, updatedAt?, updatedBy?}
//	POST /v1/secrets/settings (admin)  {viewersCanReveal} -> same; audit citadel.UpdateSecretSettings

func secretSettingsJSON(st store.SecretSettings) map[string]any {
	out := map[string]any{"viewersCanReveal": st.ViewersCanReveal}
	if !st.UpdatedAt.IsZero() {
		out["updatedAt"] = st.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if st.UpdatedBy != "" {
		out["updatedBy"] = st.UpdatedBy
	}
	return out
}

func (s *Server) handleV1GetSecretSettings(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	st, err := s.store.GetSecretSettings(ctx)
	if err != nil {
		log.Printf("secret settings: get: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not read secrets settings")
		return
	}
	writeNativeJSON(w, http.StatusOK, secretSettingsJSON(st))
}

type nativeSecretSettingsRequest struct {
	ViewersCanReveal *bool `json:"viewersCanReveal"`
}

func (s *Server) handleV1PutSecretSettings(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeSecretSettingsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	if req.ViewersCanReveal == nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "viewersCanReveal is required")
		return
	}
	in := store.SecretSettings{ViewersCanReveal: *req.ViewersCanReveal, UpdatedBy: sess.Username}
	if err := s.store.PutSecretSettings(ctx, in); err != nil {
		log.Printf("secret settings: put: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save secrets settings")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpdateSecretSettings", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	saved, err := s.store.GetSecretSettings(ctx)
	if err != nil {
		saved = in
	}
	writeNativeJSON(w, http.StatusOK, secretSettingsJSON(saved))
}
