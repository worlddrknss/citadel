package server

import (
	"log"
	"log/slog"
	"net/http"
	"time"
)

// Native read-only /v1 endpoints that back the Svelte parity screens for KMS,
// Certificates, and Audit (PLAN.md §6 P7). They reuse the existing store
// methods and the same cookie/token auth as the rest of the native API, so the
// SPA can render every service without falling back to the legacy
// html/template pages.

type nativeKMSKey struct {
	KeyID        string   `json:"keyId"`
	ARN          string   `json:"arn"`
	Description  string   `json:"description"`
	Enabled      bool     `json:"enabled"`
	KeyUsage     string   `json:"keyUsage"`
	KeySpec      string   `json:"keySpec"`
	CreatedAt    string   `json:"createdAt"`
	DeletionDate string   `json:"deletionDate,omitempty"`
	Aliases      []string `json:"aliases"`
	nativeKMSKeyExtras
}

// handleV1ListKMSKeys returns the KMS keys visible to the caller.
func (s *Server) handleV1ListKMSKeys(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	keys, err := s.store.ListKeys(ctx)
	if err != nil {
		slog.Error("v1 kms: list keys", "err", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "listing keys failed")
		return
	}
	aliasesByKey := map[string][]string{}
	if aliases, aerr := s.store.ListAliases(ctx); aerr == nil {
		for _, a := range aliases {
			aliasesByKey[a.TargetKeyID] = append(aliasesByKey[a.TargetKeyID], a.AliasName)
		}
	}
	out := make([]nativeKMSKey, 0, len(keys))
	for _, k := range keys {
		nk := nativeKMSKey{
			KeyID:       k.ID,
			ARN:         k.ARN,
			Description: k.Description,
			Enabled:     k.Enabled,
			KeyUsage:    k.KeyUsage,
			KeySpec:     k.KeySpec,
			CreatedAt:   k.CreatedAt.UTC().Format(time.RFC3339),
			Aliases:     aliasesByKey[k.ID],

			nativeKMSKeyExtras: kmsKeyExtras(k),
		}
		if nk.Aliases == nil {
			nk.Aliases = []string{}
		}
		if k.DeletionDate != nil {
			nk.DeletionDate = k.DeletionDate.UTC().Format(time.RFC3339)
		}
		out = append(out, nk)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

type nativeAuditEvent struct {
	ID        int64  `json:"id"`
	Action    string `json:"action"`
	KeyID     string `json:"keyId,omitempty"`
	Result    string `json:"result"`
	ErrorType string `json:"errorType,omitempty"`
	Actor     string `json:"actor"`
	CreatedAt string `json:"createdAt"`
}

// handleV1ListAudit returns the most recent audit events.
func (s *Server) handleV1ListAudit(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	records, err := s.store.ListAuditEvents(ctx, 500)
	if err != nil {
		log.Printf("audit list failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "failed to list audit events")
		return
	}
	out := make([]nativeAuditEvent, 0, len(records))
	for _, rec := range records {
		out = append(out, nativeAuditEvent{
			ID:        rec.ID,
			Action:    rec.Action,
			KeyID:     rec.KeyID,
			Result:    rec.Result,
			ErrorType: rec.ErrorType,
			Actor:     rec.Actor,
			CreatedAt: rec.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"events": out})
}
