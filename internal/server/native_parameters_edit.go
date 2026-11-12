package server

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

// Parameter edits beyond create/overwrite:
//
//	POST   /v1/parameters/update {name, expectedVersion, type?, value?, description?, kmsKeyId?, tier?}
//	       -> {parameter}; 409 version_conflict when expectedVersion is stale;
//	       omitting value keeps the current one (re-encrypted when the type or
//	       KMS key changes); audit citadel.PutParameter
//	DELETE /v1/parameters/label?name=&version=&labels=a,b -> {name, removed[]};
//	       audit citadel.UnlabelParameterVersion

type nativeUpdateParameterRequest struct {
	Name            string  `json:"name"`
	ExpectedVersion int64   `json:"expectedVersion"`
	Type            string  `json:"type"`
	Value           *string `json:"value"`
	Description     *string `json:"description"`
	KMSKeyID        *string `json:"kmsKeyId"`
	Tier            string  `json:"tier"`
}

// parameterValueLimit is the value size limit for a tier, in bytes.
func parameterValueLimit(tier string) int {
	if tier == parameterTierAdvanced {
		return 8192
	}
	return 4096
}

func (s *Server) handleV1UpdateParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeUpdateParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	name, err := normalizeParameterName(req.Name)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.ExpectedVersion < 1 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "expectedVersion is required")
		return
	}
	current, err := s.store.GetParameter(ctx, name)
	if err != nil {
		writeParameterNativeError(w, err)
		return
	}
	if current.Version != req.ExpectedVersion {
		writeNativeError(w, http.StatusConflict, "version_conflict", "the parameter was changed by someone else; reload and try again")
		return
	}
	typ := current.Type
	if strings.TrimSpace(req.Type) != "" {
		if typ, err = normalizeParameterType(req.Type); err != nil {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}
	tier := current.Tier
	if strings.TrimSpace(req.Tier) != "" {
		tier = normalizeParameterTier(req.Tier)
	}
	description := current.Description
	if req.Description != nil {
		description = strings.TrimSpace(*req.Description)
	}
	var value string
	if req.Value != nil {
		value = *req.Value
	} else if current.IsEncrypted {
		if value, err = s.decryptParameterValue(ctx, current.KMSKeyID, current.Value); err != nil {
			log.Printf("parameter update: decrypt current value: %v", err)
			writeNativeError(w, http.StatusInternalServerError, "decrypt_failed", "could not decrypt the current value")
			return
		}
	} else {
		value = current.Value
	}
	if typ != parameterTypeSecureString && strings.TrimSpace(value) == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "value is required")
		return
	}
	if len(value) > parameterValueLimit(tier) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "value is larger than "+strconv.Itoa(parameterValueLimit(tier))+" bytes for the "+tier+" tier")
		return
	}
	rec := store.ParameterRecord{Name: name, Type: typ, Tier: tier, Description: description}
	if typ == parameterTypeSecureString {
		kms := ""
		if current.IsEncrypted {
			kms = current.KMSKeyID
		}
		if req.KMSKeyID != nil {
			kms = strings.TrimSpace(*req.KMSKeyID)
		}
		cipherB64, keyID, err := s.encryptParameterValue(ctx, kms, value)
		if err != nil {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "could not encrypt with that KMS key")
			return
		}
		rec.Value, rec.KMSKeyID, rec.IsEncrypted = cipherB64, keyID, true
	} else {
		rec.Value = value
	}
	saved, err := s.store.UpdateParameter(ctx, rec, req.ExpectedVersion)
	if errors.Is(err, store.ErrParameterVersionConflict) {
		writeNativeError(w, http.StatusConflict, "version_conflict", "the parameter was changed by someone else; reload and try again")
		return
	}
	if err != nil {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PutParameter", KeyID: rec.KMSKeyID, Result: "error", ErrorType: classifyParameterError(err), AuditOrigin: s.auditOrigin(r)})
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PutParameter", KeyID: saved.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"parameter": nativeParameterFrom(saved)})
}

func (s *Server) handleV1UnlabelParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	name, err := normalizeParameterName(q.Get("name"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	version, err := strconv.ParseInt(strings.TrimSpace(q.Get("version")), 10, 64)
	if err != nil || version < 1 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "version must be a positive number")
		return
	}
	labels := []string{}
	for _, l := range strings.Split(q.Get("labels"), ",") {
		if l = strings.TrimSpace(l); l != "" {
			labels = append(labels, l)
		}
	}
	if len(labels) == 0 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "labels is required")
		return
	}
	removed, err := s.store.UnlabelParameterVersion(ctx, name, version, labels)
	if err != nil {
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UnlabelParameterVersion", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name, "removed": removed})
}
