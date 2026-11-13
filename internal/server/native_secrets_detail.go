package server

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/worlddrknss/citadel/internal/store"
)

// Native Citadel API (/v1) — single-item detail surface.
//
// These handlers back the SPA "secret detail" drawer with full parity to the
// retired admin templates: overview metadata, version promotion, tags,
// resource policy, and rotation configuration. They all operate on a single
// item identified by the project/env/path/key query coordinate and reuse the
// shared secretsService business layer.

type nativeItemDetail struct {
	Project           string         `json:"project"`
	Env               string         `json:"env"`
	Path              string         `json:"path"`
	Key               string         `json:"key"`
	ARN               string         `json:"arn"`
	Description       string         `json:"description"`
	KMSKeyID          string         `json:"kmsKeyId"`
	CurrentVersionID  string         `json:"currentVersionId"`
	PreviousVersionID string         `json:"previousVersionId,omitempty"`
	Status            string         `json:"status"`
	CreatedAt         string         `json:"createdAt"`
	UpdatedAt         string         `json:"updatedAt"`
	DeletionDate      string         `json:"deletionDate,omitempty"`
	Tags              []nativeTag    `json:"tags"`
	PolicyDocument    string         `json:"policyDocument"`
	Rotation          nativeRotation `json:"rotation"`
	// ValueLength is the current value's length in characters (bytes for a
	// binary value); Fingerprint is its keyed fingerprint ("hmac:" + 12 hex,
	// HMAC-SHA256 under a per-deployment key, never a plain hash). Both are
	// omitted for a secret scheduled for deletion.
	ValueLength *int   `json:"valueLength,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	UpdatedBy   string `json:"updatedBy,omitempty"`
	// Version is the number of stored versions.
	Version int `json:"version,omitempty"`
}

type nativeTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type nativeRotation struct {
	Enabled          bool   `json:"enabled"`
	LambdaARN        string `json:"lambdaArn,omitempty"`
	AfterDays        int    `json:"afterDays,omitempty"`
	NextRotationDate string `json:"nextRotationDate,omitempty"`
	// Due is set when NextRotationDate has passed: a built-in rotator runs
	// within a minute; a Lambda schedule is a prompt for an operator.
	Due bool `json:"due,omitempty"`
	// RotatorType is the built-in rotator ("" for a Lambda schedule) and
	// Status its state (see GET /v1/secrets/rotation).
	RotatorType string `json:"rotatorType,omitempty"`
	Status      string `json:"status,omitempty"`
}

// handleV1SecretDetail returns the full metadata projection for one item.
func (s *Server) handleV1SecretDetail(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	coord, err := coordFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	d, err := s.secretsSvc().DescribeItem(ctx, coord)
	if err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
		return
	}
	status := "active"
	deletion := ""
	if d.DeletionDate != nil {
		status = "scheduled-deletion"
		deletion = d.DeletionDate.Format(time.RFC3339)
	}
	tags := make([]nativeTag, 0, len(d.Tags))
	for _, t := range d.Tags {
		tags = append(tags, nativeTag{Key: t.Key, Value: t.Value})
	}
	rot := nativeRotation{Enabled: d.RotationEnabled, LambdaARN: d.RotationLambdaARN, AfterDays: d.RotationDays}
	if d.NextRotationDate != nil {
		rot.NextRotationDate = d.NextRotationDate.Format(time.RFC3339)
		rot.Due = d.RotationEnabled && d.DeletionDate == nil && !d.NextRotationDate.After(time.Now())
	}
	if rr, err := s.store.GetSecretRotation(ctx, coord.backingName()); err == nil {
		rot.RotatorType, rot.Status = rr.RotatorType, rr.Status
	}
	out := nativeItemDetail{
		Project:           d.Project,
		Env:               d.Env,
		Path:              d.Path,
		Key:               d.Key,
		ARN:               d.ARN,
		Description:       d.Description,
		KMSKeyID:          d.KMSKeyID,
		CurrentVersionID:  d.CurrentVersionID,
		PreviousVersionID: d.PreviousVersionID,
		Status:            status,
		CreatedAt:         d.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         d.UpdatedAt.Format(time.RFC3339),
		DeletionDate:      deletion,
		Tags:              tags,
		PolicyDocument:    d.PolicyDocument,
		Rotation:          rot,
		UpdatedBy:         d.UpdatedBy,
		Version:           d.VersionCount,
	}
	if d.DeletionDate == nil {
		if v, err := s.secretsSvc().RevealItem(ctx, coord, "", ""); err == nil {
			var raw []byte
			n := 0
			if v.SecretString != nil {
				raw = []byte(*v.SecretString)
				n = utf8.RuneCount(raw)
			} else if b, err := base64.StdEncoding.DecodeString(v.SecretBinary); err == nil {
				raw, n = b, len(b)
			}
			if raw != nil {
				out.ValueLength = &n
				out.Fingerprint = "hmac:" + s.valueFingerprint(string(raw))
			}
		}
	}
	writeNativeJSON(w, http.StatusOK, out)
}

type nativeUpdateMetadataRequest struct {
	Project     string `json:"project"`
	Env         string `json:"env"`
	Path        string `json:"path"`
	Key         string `json:"key"`
	Description string `json:"description"`
	KMSKeyID    string `json:"kmsKeyId"`
}

// handleV1UpdateSecretMetadata updates description and/or KMS key for an item.
func (s *Server) handleV1UpdateSecretMetadata(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeUpdateMetadataRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().UpdateItemMetadata(ctx, coord, req.Description, req.KMSKeyID); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "update_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpdateItemMetadata", KeyID: strings.TrimSpace(req.KMSKeyID), Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

type nativeReKeyRequest struct {
	Project  string `json:"project"`
	Env      string `json:"env"`
	Path     string `json:"path"`
	Key      string `json:"key"`
	KMSKeyID string `json:"kmsKeyId"`
}

// handleV1ReKeySecret re-encrypts an item under a new KMS key. When key is set
// it rotates a single item; when key is empty it rotates every item in the
// environment, re-encrypting each current value under the new key.
func (s *Server) handleV1ReKeySecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeReKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	newKey := strings.TrimSpace(req.KMSKeyID)
	if newKey == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "kmsKeyId is required")
		return
	}
	if strings.TrimSpace(req.Key) != "" {
		coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
		if err != nil {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := s.secretsSvc().ReKeyItem(ctx, coord, newKey); err != nil {
			writeSecretsFailure(w, http.StatusBadRequest, "rekey_failed", err)
			return
		}
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ReKeyItem", KeyID: newKey, Result: "ok", AuditOrigin: s.auditOrigin(r)})
		writeNativeJSON(w, http.StatusOK, map[string]any{"rekeyed": 1, "failed": []string{}})
		return
	}
	rekeyed, failed, err := s.secretsSvc().ReKeyEnvironment(ctx, strings.TrimSpace(req.Project), strings.TrimSpace(req.Env), newKey)
	if err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "rekey_failed", err)
		return
	}
	result := "ok"
	if len(failed) > 0 {
		result = "partial"
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ReKeyEnvironment", KeyID: newKey, Result: result, AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"rekeyed": rekeyed, "failed": failed})
}

type nativePromoteVersionRequest struct {
	Project   string `json:"project"`
	Env       string `json:"env"`
	Path      string `json:"path"`
	Key       string `json:"key"`
	VersionID string `json:"versionId"`
}

// handleV1PromoteVersion moves AWSCURRENT to the requested version.
func (s *Server) handleV1PromoteVersion(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativePromoteVersionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.requireNoApproval(w, r, ctx, coord.Project, coord.Env, "citadel.PromoteItemVersion") {
		return
	}
	if err := s.secretsSvc().PromoteItemVersion(ctx, coord, req.VersionID); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "promote_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PromoteItemVersion", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"promoted": true, "versionId": strings.TrimSpace(req.VersionID)})
}

type nativeTagRequest struct {
	Project string      `json:"project"`
	Env     string      `json:"env"`
	Path    string      `json:"path"`
	Key     string      `json:"key"`
	Tags    []nativeTag `json:"tags"`
}

// handleV1TagSecret adds or updates tags on an item.
func (s *Server) handleV1TagSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeTagRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tags := make([]store.SecretTag, 0, len(req.Tags))
	for _, t := range req.Tags {
		tags = append(tags, store.SecretTag{Key: strings.TrimSpace(t.Key), Value: t.Value})
	}
	if err := s.secretsSvc().TagItem(ctx, coord, tags); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "tag_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.TagItem", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"tagged": true})
}

// handleV1UntagSecret removes tags from an item by key (query param tagKey,
// repeatable).
func (s *Server) handleV1UntagSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	coord, err := coordFromQuery(q)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	keys := make([]string, 0)
	for _, k := range q["tagKey"] {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	if err := s.secretsSvc().UntagItem(ctx, coord, keys); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "untag_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UntagItem", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"untagged": true})
}

// handleV1GetSecretPolicy returns the resource policy attached to an item.
func (s *Server) handleV1GetSecretPolicy(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	coord, err := coordFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	doc, err := s.secretsSvc().GetItemPolicy(ctx, coord)
	if err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
		return
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"key": coord.Key, "policyDocument": doc})
}

type nativePolicyRequest struct {
	Project        string `json:"project"`
	Env            string `json:"env"`
	Path           string `json:"path"`
	Key            string `json:"key"`
	PolicyDocument string `json:"policyDocument"`
}

// handleV1PutSecretPolicy attaches (or clears, when empty) a resource policy.
func (s *Server) handleV1PutSecretPolicy(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativePolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().PutItemPolicy(ctx, coord, req.PolicyDocument); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "policy_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PutItemPolicy", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// handleV1CancelRotation disables rotation for an item.
func (s *Server) handleV1CancelRotation(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	coord, err := coordFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().CancelItemRotation(ctx, coord); err != nil {
		writeSecretsFailure(w, http.StatusBadRequest, "rotation_failed", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CancelItemRotation", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"cancelled": true})
}

// coordFromParts builds and validates an item coordinate from JSON body fields.
func coordFromParts(project, env, path, key string) (itemCoord, error) {
	folder, err := normalizeFolder(path)
	if err != nil {
		return itemCoord{}, err
	}
	coord := itemCoord{
		Project: strings.TrimSpace(project),
		Env:     strings.TrimSpace(env),
		Folder:  folder,
		Key:     strings.TrimSpace(key),
	}
	if err := coord.validate(); err != nil {
		return itemCoord{}, err
	}
	return coord, nil
}
