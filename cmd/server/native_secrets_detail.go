package main

import (
	"net/http"
	"strings"
	"time"
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
}

// handleV1SecretDetail returns the full metadata projection for one item.
func (s *server) handleV1SecretDetail(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
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
	}
	writeNativeJSON(w, http.StatusOK, nativeItemDetail{
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
	})
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
func (s *server) handleV1UpdateSecretMetadata(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
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
		writeNativeError(w, http.StatusBadRequest, "update_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.UpdateItemMetadata", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

type nativePromoteVersionRequest struct {
	Project   string `json:"project"`
	Env       string `json:"env"`
	Path      string `json:"path"`
	Key       string `json:"key"`
	VersionID string `json:"versionId"`
}

// handleV1PromoteVersion moves AWSCURRENT to the requested version.
func (s *server) handleV1PromoteVersion(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
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
	if err := s.secretsSvc().PromoteItemVersion(ctx, coord, req.VersionID); err != nil {
		writeNativeError(w, http.StatusBadRequest, "promote_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.PromoteItemVersion", Result: "ok", Actor: r.RemoteAddr})
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
func (s *server) handleV1TagSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
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
	tags := make([]secretTag, 0, len(req.Tags))
	for _, t := range req.Tags {
		tags = append(tags, secretTag{Key: strings.TrimSpace(t.Key), Value: t.Value})
	}
	if err := s.secretsSvc().TagItem(ctx, coord, tags); err != nil {
		writeNativeError(w, http.StatusBadRequest, "tag_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.TagItem", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"tagged": true})
}

// handleV1UntagSecret removes tags from an item by key (query param tagKey,
// repeatable).
func (s *server) handleV1UntagSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
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
		writeNativeError(w, http.StatusBadRequest, "untag_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.UntagItem", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"untagged": true})
}

// handleV1GetSecretPolicy returns the resource policy attached to an item.
func (s *server) handleV1GetSecretPolicy(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
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
func (s *server) handleV1PutSecretPolicy(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
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
		writeNativeError(w, http.StatusBadRequest, "policy_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.PutItemPolicy", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

type nativeRotationRequest struct {
	Project           string `json:"project"`
	Env               string `json:"env"`
	Path              string `json:"path"`
	Key               string `json:"key"`
	LambdaARN         string `json:"lambdaArn"`
	AfterDays         int    `json:"afterDays"`
	RotateImmediately bool   `json:"rotateImmediately"`
}

// handleV1ConfigureRotation enables or updates rotation configuration.
func (s *server) handleV1ConfigureRotation(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeRotationRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().ConfigureItemRotation(ctx, coord, req.LambdaARN, req.AfterDays, req.RotateImmediately); err != nil {
		writeNativeError(w, http.StatusBadRequest, "rotation_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.ConfigureItemRotation", Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"configured": true})
}

// handleV1CancelRotation disables rotation for an item.
func (s *server) handleV1CancelRotation(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	coord, err := coordFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.secretsSvc().CancelItemRotation(ctx, coord); err != nil {
		writeNativeError(w, http.StatusBadRequest, "rotation_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.CancelItemRotation", Result: "ok", Actor: r.RemoteAddr})
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

// nativeBulkDeleteRequest deletes/restores several items in one call.
type nativeBulkRequest struct {
	Project            string   `json:"project"`
	Env                string   `json:"env"`
	Path               string   `json:"path"`
	Keys               []string `json:"keys"`
	Action             string   `json:"action"` // "delete" | "restore"
	Force              bool     `json:"force"`
	RecoveryWindowDays int      `json:"recoveryWindowDays"`
}

// handleV1BulkSecrets applies delete or restore to multiple items at once.
func (s *server) handleV1BulkSecrets(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeBulkRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "delete" && action != "restore" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "action must be delete or restore")
		return
	}
	svc := s.secretsSvc()
	applied := 0
	failed := make([]string, 0)
	for _, key := range req.Keys {
		coord, err := coordFromParts(req.Project, req.Env, req.Path, key)
		if err != nil {
			failed = append(failed, strings.TrimSpace(key))
			continue
		}
		if action == "delete" {
			err = svc.DeleteItem(ctx, coord, req.RecoveryWindowDays, req.Force)
		} else {
			err = svc.RestoreItem(ctx, coord)
		}
		if err != nil {
			failed = append(failed, coord.Key)
			continue
		}
		applied++
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.Bulk:" + action, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"applied": applied, "failed": failed})
}
