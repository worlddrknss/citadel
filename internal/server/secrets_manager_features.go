package server

import (
	"net/http"
	"strings"

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

func (s *Server) handleListSecretVersionIDs(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleTagSecret(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleUntagSecret(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleGetSecretResourcePolicy(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handlePutSecretResourcePolicy(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleValidateSecretResourcePolicy(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleCancelRotateSecret(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleUpdateSecretVersionStage(w http.ResponseWriter, r *http.Request) {
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

func toSecretTags(tags []tagEntry) []store.SecretTag {
	out := make([]store.SecretTag, 0, len(tags))
	for _, tag := range tags {
		out = append(out, store.SecretTag{Key: strings.TrimSpace(tag.Key), Value: tag.Value})
	}
	return out
}
