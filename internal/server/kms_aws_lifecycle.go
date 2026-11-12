package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// AWS KMS key rotation, tagging, DeleteAlias and GenerateRandom.

type rotationRequest struct {
	KeyID                string `json:"KeyId"`
	RotationPeriodInDays int    `json:"RotationPeriodInDays"`
}

type rotationStatusResponse struct {
	KeyID                string              `json:"KeyId"`
	KeyRotationEnabled   bool                `json:"KeyRotationEnabled"`
	RotationPeriodInDays int                 `json:"RotationPeriodInDays,omitempty"`
	NextRotationDate     *store.AWSTimestamp `json:"NextRotationDate,omitempty"`
}

type listRotationsRequest struct {
	KeyID  string `json:"KeyId"`
	Limit  int    `json:"Limit"`
	Marker string `json:"Marker"`
}

type rotationEntry struct {
	KeyID         string             `json:"KeyId"`
	KeyMaterialID string             `json:"KeyMaterialId,omitempty"`
	RotationDate  store.AWSTimestamp `json:"RotationDate"`
	RotationType  string             `json:"RotationType"`
}

type listRotationsResponse struct {
	Rotations  []rotationEntry `json:"Rotations"`
	NextMarker string          `json:"NextMarker,omitempty"`
	Truncated  bool            `json:"Truncated"`
}

type awsTag struct {
	TagKey   string `json:"TagKey"`
	TagValue string `json:"TagValue"`
}

type tagResourceRequest struct {
	KeyID string   `json:"KeyId"`
	Tags  []awsTag `json:"Tags"`
}

type untagResourceRequest struct {
	KeyID   string   `json:"KeyId"`
	TagKeys []string `json:"TagKeys"`
}

type listResourceTagsRequest struct {
	KeyID  string `json:"KeyId"`
	Limit  int    `json:"Limit"`
	Marker string `json:"Marker"`
}

type listResourceTagsResponse struct {
	Tags       []awsTag `json:"Tags"`
	NextMarker string   `json:"NextMarker,omitempty"`
	Truncated  bool     `json:"Truncated"`
}

type generateRandomRequest struct {
	NumberOfBytes    int    `json:"NumberOfBytes"`
	CustomKeyStoreID string `json:"CustomKeyStoreId"`
}

// handleKMSLifecycleTarget dispatches the key rotation, tagging and
// GenerateRandom actions; it reports whether it handled the target.
func (s *Server) handleKMSLifecycleTarget(w http.ResponseWriter, r *http.Request, target string) bool {
	switch target {
	case "TrentService.EnableKeyRotation":
		s.handleSetKeyRotation(w, r, true)
	case "TrentService.DisableKeyRotation":
		s.handleSetKeyRotation(w, r, false)
	case "TrentService.GetKeyRotationStatus":
		s.handleGetKeyRotationStatus(w, r)
	case "TrentService.RotateKeyOnDemand":
		s.handleRotateKeyOnDemand(w, r)
	case "TrentService.ListKeyRotations":
		s.handleListKeyRotations(w, r)
	case "TrentService.TagResource":
		s.handleTagResource(w, r)
	case "TrentService.UntagResource":
		s.handleUntagResource(w, r)
	case "TrentService.ListResourceTags":
		s.handleListResourceTags(w, r)
	case "TrentService.GenerateRandom":
		s.handleGenerateRandom(w, r)
	default:
		return false
	}
	return true
}

func rotationTypeAWS(kind string) string {
	if kind == store.RotationKindOnDemand {
		return "ON_DEMAND"
	}
	return "AUTOMATIC"
}

// awsKeyCall is the common prologue of a key-scoped AWS handler: decode the
// body, require KeyId, resolve the key in the caller's account and check the
// key policy (and grants) for policyAction. On failure it has written the
// error and audited it, and returns ok=false.
func (s *Server) awsKeyCall(w http.ResponseWriter, r *http.Request, action, policyAction string, body any, keyIDOf func() string) (store.KMSKey, bool) {
	fail := func(keyID, typ, msg string) {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, typ, msg)
	}
	if err := decodeJSONBody(r, body); err != nil {
		fail("", "ValidationException", "request body is not valid JSON for this action")
		return store.KMSKey{}, false
	}
	keyID := strings.TrimSpace(keyIDOf())
	if keyID == "" {
		fail("", "ValidationException", "KeyId is required")
		return store.KMSKey{}, false
	}
	key, err := s.resolveKMSKey(r.Context(), keyID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("kms key lookup failed", "action", action, "err", err)
		}
		fail(keyID, "NotFoundException", "key not found")
		return store.KMSKey{}, false
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, policyAction); err != nil {
		fail(key.ID, "AccessDeniedException", "access denied by key policy")
		return store.KMSKey{}, false
	}
	return key, true
}

// writeLifecycleError maps store lifecycle errors to AWS errors.
func (s *Server) writeLifecycleError(w http.ResponseWriter, r *http.Request, action, keyID string, err error) {
	typ, msg, status := "KMSInternalException", "the operation failed", http.StatusInternalServerError
	switch {
	case errors.Is(err, store.ErrRotationUnsupported):
		typ, msg, status = "UnsupportedOperationException", err.Error(), http.StatusBadRequest
	case errors.Is(err, store.ErrInvalidRotationPeriod):
		typ, msg, status = "ValidationException", err.Error(), http.StatusBadRequest
	case errors.Is(err, store.ErrRotationLimit):
		typ, msg, status = "LimitExceededException", err.Error(), http.StatusBadRequest
	case errors.Is(err, store.ErrKeyNotUsable):
		typ, msg, status = "KMSInvalidStateException", err.Error(), http.StatusBadRequest
	case errors.Is(err, store.ErrImmutableManagedKey):
		typ, msg, status = "UnsupportedOperationException", err.Error(), http.StatusBadRequest
	case errors.Is(err, store.ErrInvalidTags):
		typ, msg, status = "TagException", err.Error(), http.StatusBadRequest
	case errors.Is(err, sql.ErrNoRows):
		typ, msg, status = "NotFoundException", "key not found", http.StatusBadRequest
	default:
		slog.Error("kms operation failed", "action", action, "key_id", keyID, "err", err)
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
	writeAWSJSONError(w, status, typ, msg)
}

func (s *Server) handleSetKeyRotation(w http.ResponseWriter, r *http.Request, enable bool) {
	action, policyAction := "TrentService.DisableKeyRotation", "kms:DisableKeyRotation"
	if enable {
		action, policyAction = "TrentService.EnableKeyRotation", "kms:EnableKeyRotation"
	}
	var req rotationRequest
	key, ok := s.awsKeyCall(w, r, action, policyAction, &req, func() string { return req.KeyID })
	if !ok {
		return
	}
	if !enable && req.RotationPeriodInDays != 0 {
		s.writeLifecycleError(w, r, action, key.ID, store.ErrInvalidRotationPeriod)
		return
	}
	if err := keyUsable(key); err != nil {
		typ := writeKMSOpError(w, err, "rotation update failed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	if _, err := s.store.SetKeyRotation(r.Context(), key.ID, enable, req.RotationPeriodInDays); err != nil {
		s.writeLifecycleError(w, r, action, key.ID, err)
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleGetKeyRotationStatus(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.GetKeyRotationStatus"
	var req rotationRequest
	key, ok := s.awsKeyCall(w, r, action, "kms:GetKeyRotationStatus", &req, func() string { return req.KeyID })
	if !ok {
		return
	}
	if !key.IsSymmetric() {
		s.writeLifecycleError(w, r, action, key.ID, store.ErrRotationUnsupported)
		return
	}
	resp := rotationStatusResponse{KeyID: key.ARN, KeyRotationEnabled: key.RotationEnabled}
	if key.RotationEnabled {
		resp.RotationPeriodInDays = key.RotationPeriodDays
		resp.NextRotationDate = awsTimePtr(key.NextRotationAt)
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRotateKeyOnDemand(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.RotateKeyOnDemand"
	var req rotationRequest
	key, ok := s.awsKeyCall(w, r, action, "kms:RotateKeyOnDemand", &req, func() string { return req.KeyID })
	if !ok {
		return
	}
	if _, err := s.store.RotateKeyMaterial(r.Context(), key.ID, store.RotationKindOnDemand, time.Now().UTC()); err != nil {
		s.writeLifecycleError(w, r, action, key.ID, err)
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{"KeyId": kmsKeyARN(key)})
}

func (s *Server) handleListKeyRotations(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListKeyRotations"
	var req listRotationsRequest
	key, ok := s.awsKeyCall(w, r, action, "kms:ListKeyRotations", &req, func() string { return req.KeyID })
	if !ok {
		return
	}
	if !key.IsSymmetric() {
		s.writeLifecycleError(w, r, action, key.ID, store.ErrRotationUnsupported)
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	rotations, err := s.store.ListKeyRotations(r.Context(), key.ID)
	if err != nil {
		s.writeLifecycleError(w, r, action, key.ID, err)
		return
	}
	out := make([]rotationEntry, 0, len(rotations))
	for _, rot := range rotations {
		out = append(out, rotationEntry{KeyID: key.ARN, KeyMaterialID: rot.MaterialID, RotationDate: store.AWSTimestamp(rot.RotatedAt), RotationType: rotationTypeAWS(rot.Kind)})
	}
	page, next, truncated, err := paginateList(out, req.Marker, limit, func(e rotationEntry) string { return e.KeyMaterialID })
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidMarkerException", "Marker is invalid")
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, listRotationsResponse{Rotations: page, NextMarker: next, Truncated: truncated})
}

func (s *Server) handleTagResource(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.TagResource"
	var req tagResourceRequest
	key, ok := s.awsKeyCall(w, r, action, "kms:TagResource", &req, func() string { return req.KeyID })
	if !ok {
		return
	}
	tags := make([]store.KMSTag, 0, len(req.Tags))
	for _, t := range req.Tags {
		tags = append(tags, store.KMSTag{Key: t.TagKey, Value: t.TagValue})
	}
	if _, err := store.NormalizeTags(tags); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "TagException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "TagException", err.Error())
		return
	}
	if err := s.store.TagKey(r.Context(), key.ID, tags); err != nil {
		s.writeLifecycleError(w, r, action, key.ID, err)
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleUntagResource(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.UntagResource"
	var req untagResourceRequest
	key, ok := s.awsKeyCall(w, r, action, "kms:UntagResource", &req, func() string { return req.KeyID })
	if !ok {
		return
	}
	if len(req.TagKeys) == 0 {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "TagKeys is required")
		return
	}
	if err := s.store.UntagKey(r.Context(), key.ID, req.TagKeys); err != nil {
		s.writeLifecycleError(w, r, action, key.ID, err)
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleListResourceTags(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListResourceTags"
	var req listResourceTagsRequest
	key, ok := s.awsKeyCall(w, r, action, "kms:ListResourceTags", &req, func() string { return req.KeyID })
	if !ok {
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	tags, err := s.store.ListKeyTags(r.Context(), key.ID)
	if err != nil {
		s.writeLifecycleError(w, r, action, key.ID, err)
		return
	}
	out := make([]awsTag, 0, len(tags))
	for _, t := range tags {
		out = append(out, awsTag{TagKey: t.Key, TagValue: t.Value})
	}
	page, next, truncated, err := paginateList(out, req.Marker, limit, func(t awsTag) string { return t.TagKey })
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidMarkerException", "Marker is invalid")
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, listResourceTagsResponse{Tags: page, NextMarker: next, Truncated: truncated})
}

// handleGenerateRandom returns 1-1024 bytes from crypto/rand (the FIPS 140-3
// DRBG under GODEBUG=fips140=only).
func (s *Server) handleGenerateRandom(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.GenerateRandom"
	var req generateRandomRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "request body is not valid JSON for GenerateRandom")
		return
	}
	if req.CustomKeyStoreID != "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "CustomKeyStoreNotFoundException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "CustomKeyStoreNotFoundException", "custom key stores are not supported")
		return
	}
	if req.NumberOfBytes < 1 || req.NumberOfBytes > 1024 {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "NumberOfBytes must be between 1 and 1024")
		return
	}
	buf := make([]byte, req.NumberOfBytes)
	if _, err := rand.Read(buf); err != nil {
		slog.Error("kms GenerateRandom failed", "err", err)
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "random generation failed")
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{"Plaintext": base64.StdEncoding.EncodeToString(buf)})
}
