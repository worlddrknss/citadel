package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Native (/v1/parameters) Parameter Store API consumed by the Citadel SPA. It
// mirrors the SSM data model but speaks protocol-clean JSON. SecureString
// values are encrypted with the deployment's KMS keys; the reveal endpoint
// performs decryption on demand for authorized callers.

// paramStore returns the parameter persistence layer when the active store
// supports it. The in-memory dev store and the Postgres store both implement
// parameterStore; this guard keeps the call sites tidy.
func (s *server) paramStore() (parameterStore, bool) {
	ps, ok := s.store.(parameterStore)
	return ps, ok
}

// encryptParameterValue encrypts a SecureString value, returning the base64
// ciphertext and the resolved KMS key ID. An empty kmsKeyID resolves the
// deployment default key (same behaviour as Secrets Manager).
func (s *server) encryptParameterValue(ctx context.Context, kmsKeyID, value string) (cipherB64, keyID string, err error) {
	keyID, cipherB64, _, err = buildSecretCiphertext(ctx, s.store.ResolveByID, s.store.ResolveDefault, kmsKeyID, value, "")
	return cipherB64, keyID, err
}

// decryptParameterValue decrypts a SecureString ciphertext blob.
func (s *server) decryptParameterValue(ctx context.Context, keyID, cipherB64 string) (string, error) {
	key, err := s.store.ResolveByID(ctx, keyID)
	if err != nil {
		return "", err
	}
	encoded, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", err
	}
	_, rawBlob, err := decodeCipherBlob(encoded)
	if err != nil {
		return "", err
	}
	raw, err := decryptBlob(key.MasterKeyRaw, rawBlob, nil)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// nativeParameter is the list/detail projection of a parameter. Values are only
// included by the reveal endpoint.
type nativeParameter struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Tier         string `json:"tier"`
	Version      int64  `json:"version"`
	Description  string `json:"description"`
	KMSKeyID     string `json:"kmsKeyId,omitempty"`
	LastModified string `json:"lastModified"`
}

func nativeParameterFrom(rec parameterRecord) nativeParameter {
	return nativeParameter{
		Name:         rec.Name,
		Type:         rec.Type,
		Tier:         rec.Tier,
		Version:      rec.Version,
		Description:  rec.Description,
		KMSKeyID:     rec.KMSKeyID,
		LastModified: rec.UpdatedAt.Format(time.RFC3339),
	}
}

// handleV1ListParameters returns every parameter for the caller's account. The
// SPA builds the folder tree client-side from the slash-style names.
func (s *server) handleV1ListParameters(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	recs, err := ps.ListParameters(ctx)
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]nativeParameter, 0, len(recs))
	for _, rec := range recs {
		out = append(out, nativeParameterFrom(rec))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"parameters": out})
}

type nativePutParameterRequest struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	KMSKeyID    string `json:"kmsKeyId"`
	Tier        string `json:"tier"`
	Description string `json:"description"`
	Overwrite   bool   `json:"overwrite"`
}

// handleV1PutParameter creates or updates a parameter.
func (s *server) handleV1PutParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	var req nativePutParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	rec, err := s.buildParameterRecord(ctx, req.Name, req.Type, req.Value, req.KMSKeyID, req.Tier, req.Description)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	saved, err := ps.PutParameter(ctx, rec, req.Overwrite)
	if err != nil {
		s.recordAudit(ctx, auditEvent{Action: "citadel.PutParameter", KeyID: rec.KMSKeyID, Result: "error", ErrorType: classifyParameterError(err), Actor: r.RemoteAddr})
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.PutParameter", KeyID: saved.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"parameter": nativeParameterFrom(saved)})
}

// buildParameterRecord validates inputs and encrypts SecureString values.
func (s *server) buildParameterRecord(ctx context.Context, name, ptype, value, kmsKeyID, tier, description string) (parameterRecord, error) {
	canonical, err := normalizeParameterName(name)
	if err != nil {
		return parameterRecord{}, err
	}
	typ, err := normalizeParameterType(ptype)
	if err != nil {
		return parameterRecord{}, err
	}
	if strings.TrimSpace(value) == "" && typ != parameterTypeSecureString {
		return parameterRecord{}, errors.New("value is required")
	}
	rec := parameterRecord{
		Name:        canonical,
		Type:        typ,
		Tier:        normalizeParameterTier(tier),
		Description: strings.TrimSpace(description),
	}
	if typ == parameterTypeSecureString {
		cipherB64, keyID, err := s.encryptParameterValue(ctx, kmsKeyID, value)
		if err != nil {
			return parameterRecord{}, err
		}
		rec.Value = cipherB64
		rec.KMSKeyID = keyID
		rec.IsEncrypted = true
	} else {
		rec.Value = value
	}
	return rec, nil
}

// handleV1DeleteParameter removes a parameter and its history.
func (s *server) handleV1DeleteParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	name, err := normalizeParameterName(r.URL.Query().Get("name"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := ps.DeleteParameter(ctx, name); err != nil {
		s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteParameter", Result: "error", ErrorType: classifyParameterError(err), Actor: r.RemoteAddr})
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.DeleteParameter", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

// handleV1RevealParameter returns the decrypted value of a parameter.
func (s *server) handleV1RevealParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	name, err := normalizeParameterName(r.URL.Query().Get("name"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	rec, err := ps.GetParameter(ctx, name)
	if err != nil {
		writeParameterNativeError(w, err)
		return
	}
	value := rec.Value
	if rec.IsEncrypted {
		plain, derr := s.decryptParameterValue(ctx, rec.KMSKeyID, rec.Value)
		if derr != nil {
			writeNativeError(w, http.StatusInternalServerError, "decrypt_failed", "could not decrypt parameter")
			return
		}
		value = plain
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.GetParameter", KeyID: rec.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"parameter": nativeParameterFrom(rec),
		"value":     value,
	})
}

// handleV1ParameterHistory returns the version history of a parameter.
func (s *server) handleV1ParameterHistory(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	name, err := normalizeParameterName(r.URL.Query().Get("name"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	history, err := ps.GetParameterHistory(ctx, name)
	if err != nil {
		writeParameterNativeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(history))
	for _, h := range history {
		labels := h.Labels
		if labels == nil {
			labels = []string{}
		}
		out = append(out, map[string]any{
			"name":        h.Name,
			"version":     h.Version,
			"type":        h.Type,
			"tier":        h.Tier,
			"description": h.Description,
			"labels":      labels,
			"modifiedAt":  h.ModifiedAt.Format(time.RFC3339),
		})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name, "history": out})
}

type nativeLabelParameterRequest struct {
	Name    string   `json:"name"`
	Version int64    `json:"version"`
	Labels  []string `json:"labels"`
}

// handleV1LabelParameterVersion attaches labels to a parameter version.
func (s *server) handleV1LabelParameterVersion(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	var req nativeLabelParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	name, err := normalizeParameterName(req.Name)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	labels, err := ps.LabelParameterVersion(ctx, name, req.Version, req.Labels)
	if err != nil {
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.LabelParameterVersion", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name, "labels": labels})
}

// handleV1ListParameterTags returns the tags on a parameter.
func (s *server) handleV1ListParameterTags(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	name, err := normalizeParameterName(r.URL.Query().Get("name"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tags, err := ps.ListParameterTags(ctx, name)
	if err != nil {
		writeParameterNativeError(w, err)
		return
	}
	out := make([]map[string]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, map[string]string{"key": t.Key, "value": t.Value})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name, "tags": out})
}

type nativeTagParameterRequest struct {
	Name string            `json:"name"`
	Tags map[string]string `json:"tags"`
}

// handleV1TagParameter adds or updates tags on a parameter.
func (s *server) handleV1TagParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	var req nativeTagParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	name, err := normalizeParameterName(req.Name)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tags := make([]paramTag, 0, len(req.Tags))
	for k, v := range req.Tags {
		if strings.TrimSpace(k) == "" {
			continue
		}
		tags = append(tags, paramTag{Key: k, Value: v})
	}
	if err := ps.TagParameter(ctx, name, tags); err != nil {
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.TagParameter", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name})
}

// handleV1UntagParameter removes tags from a parameter. Keys are supplied as a
// comma-separated "keys" query parameter.
func (s *server) handleV1UntagParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	ps, ok := s.paramStore()
	if !ok {
		writeNativeError(w, http.StatusNotImplemented, "unsupported", "parameter store is not available")
		return
	}
	name, err := normalizeParameterName(r.URL.Query().Get("name"))
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	var keys []string
	for _, k := range strings.Split(r.URL.Query().Get("keys"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "keys are required")
		return
	}
	if err := ps.UntagParameter(ctx, name, keys); err != nil {
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.UntagParameter", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name})
}

// classifyParameterError maps store errors to stable audit error types.
func classifyParameterError(err error) string {
	switch {
	case errors.Is(err, errParameterNotFound):
		return "ParameterNotFound"
	case errors.Is(err, errParameterExists):
		return "ParameterAlreadyExists"
	default:
		return "InternalError"
	}
}

// writeParameterNativeError translates store errors into native JSON errors.
func writeParameterNativeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errParameterNotFound):
		writeNativeError(w, http.StatusNotFound, "not_found", "parameter not found")
	case errors.Is(err, errParameterExists):
		writeNativeError(w, http.StatusConflict, "already_exists", "parameter already exists; set overwrite to update")
	default:
		writeNativeError(w, http.StatusInternalServerError, "internal_error", err.Error())
	}
}

// parameterVersionFromQuery parses an optional version query parameter.
func parameterVersionFromQuery(raw string) int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
		return v
	}
	return 0
}
