package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

type tagEntry struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type listSecretVersionIDsRequest struct {
	SecretID   string `json:"SecretId"`
	MaxResults int    `json:"MaxResults"`
	NextToken  string `json:"NextToken"`
}

type listSecretVersionIDsResponse struct {
	Versions   []store.SecretVersionListEntry `json:"Versions"`
	NextToken  string                         `json:"NextToken,omitempty"`
	SecretName string                         `json:"Name,omitempty"`
	ARN        string                         `json:"ARN,omitempty"`
}

type tagSecretRequest struct {
	SecretID string     `json:"SecretId"`
	Tags     []tagEntry `json:"Tags"`
}

type untagSecretRequest struct {
	SecretID string   `json:"SecretId"`
	TagKeys  []string `json:"TagKeys"`
}

type secretPolicyRequest struct {
	SecretID          string `json:"SecretId"`
	ResourcePolicy    string `json:"ResourcePolicy,omitempty"`
	BlockPublicPolicy bool   `json:"BlockPublicPolicy,omitempty"`
}

type getSecretResourcePolicyResponse struct {
	ARN            string `json:"ARN"`
	Name           string `json:"Name"`
	ResourcePolicy string `json:"ResourcePolicy"`
}

type validateSecretResourcePolicyResponse struct {
	PolicyValidationPassed bool     `json:"PolicyValidationPassed"`
	ValidationErrors       []string `json:"ValidationErrors,omitempty"`
}

type rotateSecretRequest struct {
	SecretID               string `json:"SecretId"`
	ClientRequestToken     string `json:"ClientRequestToken"`
	RotationLambdaARN      string `json:"RotationLambdaARN"`
	RotateImmediately      *bool  `json:"RotateImmediately"`
	AutomaticallyAfterDays int    `json:"AutomaticallyAfterDays"`
}

type rotateSecretResponse struct {
	ARN       string `json:"ARN"`
	Name      string `json:"Name"`
	VersionID string `json:"VersionId,omitempty"`
}

type cancelRotateSecretRequest struct {
	SecretID string `json:"SecretId"`
}

type updateSecretVersionStageRequest struct {
	SecretID            string `json:"SecretId"`
	VersionStage        string `json:"VersionStage"`
	MoveToVersionID     string `json:"MoveToVersionId"`
	RemoveFromVersionID string `json:"RemoveFromVersionId"`
}

func (s *server) handleListSecretVersionIDs(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.ListSecretVersionIds"
	var req listSecretVersionIDsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		return
	}
	limit, err := normalizeSecretListLimit(req.MaxResults)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:ListSecretVersionIds"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	versions, err := s.store.ListSecretVersionIDs(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	versions, nextToken, _, err := paginateList(versions, req.NextToken, limit, func(item store.SecretVersionListEntry) string { return item.VersionID })
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		return
	}
	writeJSON(w, http.StatusOK, listSecretVersionIDsResponse{Versions: versions, NextToken: nextToken, SecretName: meta.Name, ARN: meta.ARN})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
}

func (s *server) handleTagSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.TagResource"
	var req tagSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:TagResource"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.store.TagSecret(r.Context(), req.SecretID, toSecretTags(req.Tags)); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
}

func (s *server) handleUntagSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.UntagResource"
	var req untagSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:UntagResource"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.store.UntagSecret(r.Context(), req.SecretID, req.TagKeys); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
}

func (s *server) handleGetSecretResourcePolicy(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.GetResourcePolicy"
	var req secretPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:GetResourcePolicy"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	policy, err := s.store.GetSecretResourcePolicy(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	writeJSON(w, http.StatusOK, getSecretResourcePolicyResponse{ARN: meta.ARN, Name: meta.Name, ResourcePolicy: policy})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
}

func (s *server) handlePutSecretResourcePolicy(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.PutResourcePolicy"
	var req secretPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		return
	}
	if strings.TrimSpace(req.ResourcePolicy) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "ResourcePolicy is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:PutResourcePolicy"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	policy, err := normalizePolicyDocument(req.ResourcePolicy)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "MalformedPolicyDocumentException", "ResourcePolicy must be valid JSON")
		return
	}
	if err := s.store.PutSecretResourcePolicy(r.Context(), req.SecretID, policy); err != nil {
		secretError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
}

func (s *server) handleValidateSecretResourcePolicy(w http.ResponseWriter, r *http.Request) {
	var req secretPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	policy, err := normalizePolicyDocument(req.ResourcePolicy)
	if err != nil {
		writeJSON(w, http.StatusOK, validateSecretResourcePolicyResponse{PolicyValidationPassed: false, ValidationErrors: []string{"policy must be valid JSON"}})
		return
	}
	writeJSON(w, http.StatusOK, validateSecretResourcePolicyResponse{PolicyValidationPassed: policy != ""})
}

func (s *server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.RotateSecret"
	var req rotateSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	rotateImmediately := true
	if req.RotateImmediately != nil {
		rotateImmediately = *req.RotateImmediately
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:RotateSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	result, err := s.store.RotateSecret(r.Context(), req.SecretID, req.RotationLambdaARN, req.AutomaticallyAfterDays, rotateImmediately, req.ClientRequestToken)
	if err != nil {
		secretError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rotateSecretResponse{ARN: result.Metadata.ARN, Name: result.Metadata.Name, VersionID: result.VersionID})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: result.Metadata.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
}

func (s *server) handleCancelRotateSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.CancelRotateSecret"
	var req cancelRotateSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:CancelRotateSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	meta, err = s.store.CancelRotateSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, restoreSecretResponse{ARN: meta.ARN, Name: meta.Name})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
}

func (s *server) handleUpdateSecretVersionStage(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.UpdateSecretVersionStage"
	var req updateSecretVersionStageRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:UpdateSecretVersionStage"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	meta, err = s.store.UpdateSecretVersionStage(r.Context(), req.SecretID, req.VersionStage, req.MoveToVersionID, req.RemoveFromVersionID)
	if err != nil {
		secretError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
}

func (s *dbStore) ListSecretVersionIDs(ctx context.Context, secretID string) ([]store.SecretVersionListEntry, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return nil, err
	}
	const q = `
SELECT version_id, version_created_at
FROM sm_secret_versions
WHERE secret_name = $1
ORDER BY version_created_at ASC
`
	rows, err := s.db.QueryContext(ctx, q, meta.Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.SecretVersionListEntry, 0)
	for rows.Next() {
		var entry store.SecretVersionListEntry
		var createdAt time.Time
		if err := rows.Scan(&entry.VersionID, &createdAt); err != nil {
			return nil, err
		}
		entry.CreatedDate = store.AWSTimestamp(createdAt)
		entry.VersionStages = store.SecretStagesForVersion(meta, entry.VersionID)
		entry.KMSKeyIDs = []string{meta.KMSKeyID}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func (s *dbStore) TagSecret(ctx context.Context, secretID string, tags []store.SecretTag) error {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		if strings.TrimSpace(tag.Key) == "" {
			continue
		}
		const q = `
INSERT INTO sm_secret_tags (secret_name, tag_key, tag_value)
VALUES ($1, $2, $3)
ON CONFLICT (secret_name, tag_key) DO UPDATE SET tag_value = EXCLUDED.tag_value
`
		if _, err := s.db.ExecContext(ctx, q, meta.Name, tag.Key, tag.Value); err != nil {
			return err
		}
	}
	return nil
}

func (s *dbStore) UntagSecret(ctx context.Context, secretID string, tagKeys []string) error {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	for _, key := range tagKeys {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM sm_secret_tags WHERE secret_name = $1 AND tag_key = $2`, meta.Name, key); err != nil {
			return err
		}
	}
	return nil
}

func (s *dbStore) GetSecretResourcePolicy(ctx context.Context, secretID string) (string, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return "", err
	}
	const q = `SELECT policy_document FROM sm_secret_policies WHERE secret_name = $1`
	var policy string
	err = s.db.QueryRowContext(ctx, q, meta.Name).Scan(&policy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.DefaultSecretResourcePolicy(meta), nil
	}
	return policy, err
}

func (s *dbStore) PutSecretResourcePolicy(ctx context.Context, secretID, policyDocument string) error {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO sm_secret_policies (secret_name, policy_document)
VALUES ($1, $2)
ON CONFLICT (secret_name) DO UPDATE SET policy_document = EXCLUDED.policy_document, updated_at = NOW()
`
	_, err = s.db.ExecContext(ctx, q, meta.Name, policyDocument)
	return err
}

func (s *dbStore) RotateSecret(ctx context.Context, secretID, rotationLambdaARN string, automaticallyAfterDays int, rotateImmediately bool, clientRequestToken string) (store.SecretRotationResult, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretRotationResult{}, err
	}
	if automaticallyAfterDays == 0 {
		automaticallyAfterDays = 30
	}
	if automaticallyAfterDays < 1 {
		return store.SecretRotationResult{}, errors.New("AutomaticallyAfterDays must be greater than 0")
	}
	meta.RotationEnabled = true
	meta.RotationLambdaARN = strings.TrimSpace(rotationLambdaARN)
	meta.RotationDays = automaticallyAfterDays
	next := time.Now().UTC().Add(time.Duration(automaticallyAfterDays) * 24 * time.Hour)
	meta.NextRotationDate = &next
	versionID := ""
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretRotationResult{}, err
	}
	defer tx.Rollback()
	if rotateImmediately {
		pendingVersionID := clientRequestToken
		if pendingVersionID == "" {
			pendingVersionID = cryptoutil.RandomHex(16)
		}
		currentVersion, err := s.loadSecretVersion(ctx, meta.Name, meta.CurrentVersionID)
		if err != nil {
			return store.SecretRotationResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at) VALUES ($1,$2,$3,$4,$5,$6)`, meta.Name, pendingVersionID, pendingVersionID, currentVersion.EncryptedPayloadB64, currentVersion.IsBinary, time.Now().UTC()); err != nil {
			return store.SecretRotationResult{}, mapSecretDBError(err)
		}
		store.AssignSecretStage(&meta, store.PendingVersionStage, pendingVersionID)
		versionID = pendingVersionID
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET rotation_enabled = $2, rotation_lambda_arn = $3, rotation_days = $4, next_rotation_date = $5, updated_at = NOW() WHERE name = $1`, meta.Name, meta.RotationEnabled, meta.RotationLambdaARN, meta.RotationDays, meta.NextRotationDate); err != nil {
		return store.SecretRotationResult{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretRotationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretRotationResult{}, err
	}
	return store.SecretRotationResult{Metadata: meta, VersionID: versionID}, nil
}

func (s *dbStore) CancelRotateSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	meta.RotationEnabled = false
	meta.RotationLambdaARN = ""
	meta.RotationDays = 0
	meta.NextRotationDate = nil
	store.RemoveSecretStage(&meta, store.PendingVersionStage, "")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET rotation_enabled = FALSE, rotation_lambda_arn = '', rotation_days = 0, next_rotation_date = NULL, updated_at = NOW() WHERE name = $1`, meta.Name); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return meta, nil
}

func (s *dbStore) UpdateSecretVersionStage(ctx context.Context, secretID, versionStage, moveToVersionID, removeFromVersionID string) (store.SecretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if strings.TrimSpace(versionStage) == "" || strings.TrimSpace(moveToVersionID) == "" {
		return store.SecretMetadataRecord{}, errors.New("VersionStage and MoveToVersionId are required")
	}
	if _, err := s.loadSecretVersion(ctx, meta.Name, moveToVersionID); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	store.AssignSecretStage(&meta, versionStage, moveToVersionID)
	if removeFromVersionID != "" {
		store.RemoveSecretStage(&meta, versionStage, removeFromVersionID)
	}
	store.SyncPrimarySecretVersionFields(&meta)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET current_version_id = $2, previous_version_id = $3, updated_at = NOW() WHERE name = $1`, meta.Name, meta.CurrentVersionID, meta.PreviousVersionID); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return meta, nil
}

func (s *dbStore) loadSecretDecorations(ctx context.Context, meta *store.SecretMetadataRecord) error {
	stageMap, err := s.loadSecretStageMap(ctx, meta.Name, meta.CurrentVersionID, meta.PreviousVersionID)
	if err != nil {
		return err
	}
	meta.VersionStages = stageMap
	tags, err := s.loadSecretTags(ctx, meta.Name)
	if err != nil {
		return err
	}
	meta.Tags = tags
	var policy string
	err = s.db.QueryRowContext(ctx, `SELECT policy_document FROM sm_secret_policies WHERE secret_name = $1`, meta.Name).Scan(&policy)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		policy = store.DefaultSecretResourcePolicy(*meta)
	}
	meta.PolicyDocument = policy
	return nil
}

func (s *dbStore) loadSecretStageMap(ctx context.Context, secretName, currentVersionID, previousVersionID string) (map[string][]string, error) {
	const q = `SELECT version_id, stage_label FROM sm_secret_version_stages WHERE secret_name = $1`
	rows, err := s.db.QueryContext(ctx, q, secretName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stageMap := map[string][]string{}
	for rows.Next() {
		var versionID, stage string
		if err := rows.Scan(&versionID, &stage); err != nil {
			return nil, err
		}
		stageMap[versionID] = append(stageMap[versionID], stage)
	}
	if len(stageMap) == 0 {
		return store.BuildFallbackSecretStageMap(currentVersionID, previousVersionID), rows.Err()
	}
	store.MergeSecretStageMaps(stageMap, store.BuildFallbackSecretStageMap(currentVersionID, previousVersionID))
	return stageMap, rows.Err()
}

func (s *dbStore) loadSecretTags(ctx context.Context, secretName string) ([]store.SecretTag, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tag_key, tag_value FROM sm_secret_tags WHERE secret_name = $1 ORDER BY tag_key ASC`, secretName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.SecretTag, 0)
	for rows.Next() {
		var tag store.SecretTag
		if err := rows.Scan(&tag.Key, &tag.Value); err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	return out, rows.Err()
}

func toSecretTags(tags []tagEntry) []store.SecretTag {
	out := make([]store.SecretTag, 0, len(tags))
	for _, tag := range tags {
		out = append(out, store.SecretTag{Key: strings.TrimSpace(tag.Key), Value: tag.Value})
	}
	return out
}

func persistSecretStageRowsTx(ctx context.Context, tx *sql.Tx, secretName string, stageMap map[string][]string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM sm_secret_version_stages WHERE secret_name = $1`, secretName); err != nil {
		return err
	}
	for versionID, stages := range stageMap {
		for _, stage := range stages {
			if _, err := tx.ExecContext(ctx, `INSERT INTO sm_secret_version_stages (secret_name, version_id, stage_label) VALUES ($1, $2, $3)`, secretName, versionID, stage); err != nil {
				return err
			}
		}
	}
	return nil
}
