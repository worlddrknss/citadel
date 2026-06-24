package main

import (
	"errors"
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
}

// handleV1ListKMSKeys returns the KMS keys visible to the caller.
func (s *server) handleV1ListKMSKeys(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	keys, err := s.store.ListKeys(ctx)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
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

type nativeCertificate struct {
	Source     string `json:"source"`
	ID         string `json:"id"`
	Subject    string `json:"subject"`
	Status     string `json:"status"`
	NotBefore  string `json:"notBefore,omitempty"`
	NotAfter   string `json:"notAfter,omitempty"`
	CAType     string `json:"caType,omitempty"`
	IssuerCAID string `json:"issuerCaId,omitempty"`
}

// handleV1ListCertificates returns issued certificates across the private CA
// hierarchy and any Let's Encrypt certificates.
func (s *server) handleV1ListCertificates(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	out := make([]nativeCertificate, 0)
	cas, err := s.store.ListCertificateAuthorities(ctx)
	if err != nil {
		// Stores without certificate support (e.g. the in-memory dev store)
		// simply have no certificates to show rather than erroring the screen.
		if errors.Is(err, errUnsupported) {
			writeNativeJSON(w, http.StatusOK, map[string]any{"certificates": out})
			return
		}
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	for _, ca := range cas {
		out = append(out, nativeCertificate{
			Source:    "pca-ca",
			ID:        ca.CAID,
			Subject:   ca.SubjectDN,
			Status:    ca.State,
			NotBefore: ca.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  ca.NotAfter.UTC().Format(time.RFC3339),
			CAType:    ca.Type,
		})
		certs, cerr := s.store.ListCertificates(ctx, ca.CAID)
		if cerr != nil {
			continue
		}
		for _, c := range certs {
			out = append(out, nativeCertificate{
				Source:     "pca-cert",
				ID:         c.CertID,
				Subject:    c.Serial,
				Status:     c.Status,
				NotBefore:  c.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:   c.NotAfter.UTC().Format(time.RFC3339),
				IssuerCAID: ca.CAID,
			})
		}
	}
	leCerts, lerr := s.store.ListACMELECertificates(ctx)
	if lerr == nil {
		for _, c := range leCerts {
			out = append(out, nativeCertificate{
				Source:    "lets-encrypt",
				ID:        c.CertID,
				Subject:   c.Domains,
				Status:    c.Status,
				NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
			})
		}
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"certificates": out})
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
func (s *server) handleV1ListAudit(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	records, err := s.store.ListAuditEvents(ctx, 500)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
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
