package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Native (/v1/parameters) Parameter Store API consumed by the Citadel SPA. It
// mirrors the SSM data model but speaks protocol-clean JSON. SecureString
// values are encrypted with the deployment's KMS keys; the reveal endpoint
// performs decryption on demand for authorized callers.

// paramStore returns the parameter persistence layer when the active store
// supports it. The in-memory dev store and the Postgres store both implement
// ParameterStore; this guard keeps the call sites tidy.
func (s *Server) paramStore() (store.ParameterStore, bool) {
	ps, ok := s.store.(store.ParameterStore)
	return ps, ok
}

// encryptParameterValue encrypts a SecureString value, returning the base64
// ciphertext and the resolved KMS key ID. An empty kmsKeyID resolves the
// deployment default key (same behaviour as Secrets Manager).
func (s *Server) encryptParameterValue(ctx context.Context, kmsKeyID, value string) (cipherB64, keyID string, err error) {
	keyID, cipherB64, _, err = store.BuildSecretCiphertext(ctx, s.store.ResolveByID, s.store.ResolveDefault, kmsKeyID, value, "")
	return cipherB64, keyID, err
}

// decryptParameterValue decrypts a SecureString ciphertext blob.
func (s *Server) decryptParameterValue(ctx context.Context, keyID, cipherB64 string) (string, error) {
	key, err := s.store.ResolveByID(ctx, keyID)
	if err != nil {
		return "", err
	}
	encoded, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", err
	}
	raw, err := key.DecryptBlob(encoded, nil)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// nativeParameter is the list/detail projection of a parameter. The list
// includes Value for String and StringList parameters (they are not secret, and
// this saves the console one reveal per row); SecureString values are only
// ever returned by the reveal endpoint.
type nativeParameter struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	Tier         string  `json:"tier"`
	Version      int64   `json:"version"`
	Description  string  `json:"description"`
	KMSKeyID     string  `json:"kmsKeyId,omitempty"`
	LastModified string  `json:"lastModified"`
	Value        *string `json:"value,omitempty"`
}

func nativeParameterFrom(rec store.ParameterRecord) nativeParameter {
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
func (s *Server) handleV1ListParameters(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
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
		log.Printf("list parameters: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list parameters")
		return
	}
	out := make([]nativeParameter, 0, len(recs))
	for _, rec := range recs {
		np := nativeParameterFrom(rec)
		if !rec.IsEncrypted && rec.Type != parameterTypeSecureString {
			v := rec.Value
			np.Value = &v
		}
		out = append(out, np)
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
func (s *Server) handleV1PutParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
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
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PutParameter", KeyID: rec.KMSKeyID, Result: "error", ErrorType: classifyParameterError(err), AuditOrigin: s.auditOrigin(r)})
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PutParameter", KeyID: saved.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"parameter": nativeParameterFrom(saved)})
}

// buildParameterRecord validates inputs and encrypts SecureString values.
func (s *Server) buildParameterRecord(ctx context.Context, name, ptype, value, kmsKeyID, tier, description string) (store.ParameterRecord, error) {
	canonical, err := normalizeParameterName(name)
	if err != nil {
		return store.ParameterRecord{}, err
	}
	typ, err := normalizeParameterType(ptype)
	if err != nil {
		return store.ParameterRecord{}, err
	}
	if strings.TrimSpace(value) == "" && typ != parameterTypeSecureString {
		return store.ParameterRecord{}, errors.New("value is required")
	}
	rec := store.ParameterRecord{
		Name:        canonical,
		Type:        typ,
		Tier:        normalizeParameterTier(tier),
		Description: strings.TrimSpace(description),
	}
	// Same limit as /v1/parameters/update (and SSM): 4 KB Standard, 8 KB Advanced.
	if limit := parameterValueLimit(rec.Tier); len(value) > limit {
		return store.ParameterRecord{}, fmt.Errorf("value is larger than %d bytes for the %s tier", limit, rec.Tier)
	}
	if typ == parameterTypeSecureString {
		cipherB64, keyID, err := s.encryptParameterValue(ctx, kmsKeyID, value)
		if err != nil {
			return store.ParameterRecord{}, err
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
func (s *Server) handleV1DeleteParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
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
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteParameter", Result: "error", ErrorType: classifyParameterError(err), AuditOrigin: s.auditOrigin(r)})
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteParameter", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

// handleV1RevealParameter returns the decrypted value of a parameter, or of
// one of its versions with ?version=N. SecureString values follow the
// account's viewersCanReveal setting.
func (s *Server) handleV1RevealParameter(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.secretsSession(w, r, "viewer")
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
	if raw := strings.TrimSpace(r.URL.Query().Get("version")); raw != "" {
		version, perr := strconv.ParseInt(raw, 10, 64)
		if perr != nil || version < 1 {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "version must be a positive number")
			return
		}
		history, herr := ps.GetParameterHistory(ctx, name)
		if herr != nil {
			writeParameterNativeError(w, herr)
			return
		}
		found := false
		for _, h := range history {
			if h.Version == version {
				rec = store.ParameterRecord{Name: rec.Name, Type: h.Type, Value: h.Value, IsEncrypted: h.IsEncrypted, KMSKeyID: h.KMSKeyID, Tier: h.Tier, Version: h.Version, Description: h.Description, CreatedAt: rec.CreatedAt, UpdatedAt: h.ModifiedAt}
				found = true
				break
			}
		}
		if !found {
			writeNativeError(w, http.StatusNotFound, "not_found", "parameter version not found")
			return
		}
	}
	if rec.IsEncrypted && !s.requireReveal(w, r, ctx, sess, "citadel.GetParameter") {
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
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.GetParameter", KeyID: rec.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"parameter": nativeParameterFrom(rec),
		"value":     value,
	})
}

// handleV1ParameterHistory returns the version history of a parameter.
func (s *Server) handleV1ParameterHistory(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
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
func (s *Server) handleV1LabelParameterVersion(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
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
	// The SSM label rules; without them a label containing a comma could
	// never be removed (DELETE /v1/parameters/label splits on commas).
	if len(req.Labels) == 0 || len(req.Labels) > 10 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "labels must contain between 1 and 10 labels")
		return
	}
	for _, l := range req.Labels {
		if !validSSMLabel(l) {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("label %q must be letters, digits, period, dash or underscore, at most 100 characters, and not start with a digit, aws or ssm", l))
			return
		}
	}
	labels, err := ps.LabelParameterVersion(ctx, name, req.Version, req.Labels)
	if err != nil {
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.LabelParameterVersion", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name, "labels": labels})
}

// handleV1ListParameterTags returns the tags on a parameter.
func (s *Server) handleV1ListParameterTags(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
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
func (s *Server) handleV1TagParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
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
	tags := make([]store.ParamTag, 0, len(req.Tags))
	for k, v := range req.Tags {
		if strings.TrimSpace(k) == "" {
			continue
		}
		tags = append(tags, store.ParamTag{Key: k, Value: v})
	}
	if err := ps.TagParameter(ctx, name, tags); err != nil {
		writeParameterNativeError(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.TagParameter", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name})
}

// handleV1UntagParameter removes tags from a parameter. Keys are supplied as a
// comma-separated "keys" query parameter.
func (s *Server) handleV1UntagParameter(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
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
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UntagParameter", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"name": name})
}

// classifyParameterError maps store errors to stable audit error types.
func classifyParameterError(err error) string {
	switch {
	case errors.Is(err, store.ErrParameterNotFound):
		return "ParameterNotFound"
	case errors.Is(err, store.ErrParameterExists):
		return "ParameterAlreadyExists"
	default:
		return "InternalError"
	}
}

// writeParameterNativeError translates store errors into native JSON errors.
func writeParameterNativeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrParameterNotFound):
		writeNativeError(w, http.StatusNotFound, "not_found", "parameter not found")
	case errors.Is(err, store.ErrParameterExists):
		writeNativeError(w, http.StatusConflict, "already_exists", "parameter already exists; set overwrite to update")
	default:
		log.Printf("parameter store: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "the parameter operation failed")
	}
}

// parameterVersionFromQuery parses an optional version query parameter.
func parameterVersionFromQuery(raw string) int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
		return v
	}
	return 0
}
