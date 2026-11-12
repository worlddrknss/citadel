package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// awsTimePtr converts an optional time.Time into an optional awsTimestamp,
// preserving nil so omitempty fields stay absent.
func awsTimePtr(t *time.Time) *store.AWSTimestamp {
	if t == nil {
		return nil
	}
	v := store.AWSTimestamp(*t)
	return &v
}

const (
	defaultSecretListLimit = 100
	maxSecretListLimit     = 100
)

type createSecretResponse struct {
	ARN       string `json:"ARN"`
	Name      string `json:"Name"`
	VersionID string `json:"VersionId"`
}

type describeSecretRequest struct {
	SecretID string `json:"SecretId"`
}

type describeSecretResponse struct {
	ARN                string              `json:"ARN"`
	Name               string              `json:"Name"`
	Description        string              `json:"Description,omitempty"`
	KMSKeyID           string              `json:"KmsKeyId,omitempty"`
	CreatedDate        store.AWSTimestamp  `json:"CreatedDate"`
	LastChangedDate    store.AWSTimestamp  `json:"LastChangedDate"`
	DeletedDate        *store.AWSTimestamp `json:"DeletedDate,omitempty"`
	RotationEnabled    bool                `json:"RotationEnabled,omitempty"`
	RotationLambdaARN  string              `json:"RotationLambdaARN,omitempty"`
	NextRotationDate   *store.AWSTimestamp `json:"NextRotationDate,omitempty"`
	VersionIDsToStages map[string][]string `json:"VersionIdsToStages"`
}

type getSecretValueRequest struct {
	SecretID     string `json:"SecretId"`
	VersionID    string `json:"VersionId"`
	VersionStage string `json:"VersionStage"`
}

type getSecretValueResponse struct {
	ARN           string             `json:"ARN"`
	Name          string             `json:"Name"`
	VersionID     string             `json:"VersionId"`
	SecretString  string             `json:"SecretString,omitempty"`
	SecretBinary  string             `json:"SecretBinary,omitempty"`
	VersionStages []string           `json:"VersionStages"`
	CreatedDate   store.AWSTimestamp `json:"CreatedDate"`
}

type putSecretValueResponse struct {
	ARN           string   `json:"ARN"`
	Name          string   `json:"Name"`
	VersionID     string   `json:"VersionId"`
	VersionStages []string `json:"VersionStages"`
}

type updateSecretResponse struct {
	ARN       string `json:"ARN"`
	Name      string `json:"Name"`
	VersionID string `json:"VersionId,omitempty"`
}

type deleteSecretRequest struct {
	SecretID                   string `json:"SecretId"`
	RecoveryWindowInDays       int    `json:"RecoveryWindowInDays"`
	ForceDeleteWithoutRecovery bool   `json:"ForceDeleteWithoutRecovery"`
}

type deleteSecretResponse struct {
	ARN          string              `json:"ARN"`
	Name         string              `json:"Name"`
	DeletionDate *store.AWSTimestamp `json:"DeletionDate,omitempty"`
}

type restoreSecretRequest struct {
	SecretID string `json:"SecretId"`
}

type restoreSecretResponse struct {
	ARN  string `json:"ARN"`
	Name string `json:"Name"`
}

// secretsFilter is a ListSecrets filter, as the AWS API defines it. Values inside
// one filter are OR'd together; separate filters are AND'd. A value prefixed with
// "!" negates that value.
//
// This exists because every AWS SDK sends Filters on ListSecrets, and the request
// decoder rejects unknown fields — so without it, ListSecrets 400s for real
// clients. External Secrets Operator's dataFrom.find sends it on every call,
// which made find unusable and left each app extracting a hand-seeded aggregate
// blob that nothing keeps current.
type secretsFilter struct {
	Key    string   `json:"Key"`
	Values []string `json:"Values"`
}

type listSecretsRequest struct {
	MaxResults int             `json:"MaxResults"`
	NextToken  string          `json:"NextToken"`
	Filters    []secretsFilter `json:"Filters"`
	// IncludePlannedDeletion, as in AWS: secrets scheduled for deletion are left
	// out of ListSecrets unless a caller asks for them. They can't be read
	// (GetSecretValue answers "scheduled for deletion"), so listing them broke
	// External Secrets Operator's dataFrom.find: it lists, then reads every
	// match, and one pending delete failed the whole ExternalSecret.
	IncludePlannedDeletion bool `json:"IncludePlannedDeletion"`
}

type listSecretsResponse struct {
	SecretList []secretListEntry `json:"SecretList"`
	NextToken  string            `json:"NextToken,omitempty"`
}

type secretListEntry struct {
	ARN             string              `json:"ARN"`
	Name            string              `json:"Name"`
	Description     string              `json:"Description,omitempty"`
	KMSKeyID        string              `json:"KmsKeyId,omitempty"`
	CreatedDate     store.AWSTimestamp  `json:"CreatedDate"`
	LastChangedDate store.AWSTimestamp  `json:"LastChangedDate"`
	DeletedDate     *store.AWSTimestamp `json:"DeletedDate,omitempty"`
	PrimaryRegion   string              `json:"PrimaryRegion,omitempty"`
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.CreateSecret"
	var req store.CreateSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "Name is required")
		return
	}
	if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
		return
	}
	// A secret named exactly like a folder shadows that folder's JSON projection:
	// GetSecretValue finds the stored object, so the live view of the folder is
	// never computed and the caller silently receives a frozen copy instead.
	// d76riders lost EMERGENCY_MASTER_KEY that way for five days — the folder had
	// the key, the object at the folder's name did not, and ESO read the object.
	// Such a secret is also unreachable in the UI, which lists a folder's
	// children rather than the folder's own name.
	if shadows, err := s.secretsSvc().NameShadowsFolder(r.Context(), req.Name); err == nil && shadows {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException",
			fmt.Sprintf("%q names a folder that already holds secrets; a secret stored there would shadow the folder's JSON projection and be invisible in the UI", req.Name))
		return
	}
	if s.awsWriteNeedsApproval(r.Context(), req.Name) {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "denied", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", awsApprovalRequiredMessage)
		return
	}
	meta, value, err := s.store.CreateSecret(store.WithActor(r.Context(), requestPrincipal(r)), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, createSecretResponse{ARN: meta.ARN, Name: meta.Name, VersionID: value.VersionID})
}

func (s *Server) handleDescribeSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.DescribeSecret"
	var req describeSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:DescribeSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, describeSecretResponse{
		ARN:                meta.ARN,
		Name:               meta.Name,
		Description:        meta.Description,
		KMSKeyID:           meta.KMSKeyID,
		CreatedDate:        store.AWSTimestamp(meta.CreatedAt),
		LastChangedDate:    store.AWSTimestamp(meta.LastChangedDate),
		DeletedDate:        awsTimePtr(meta.DeletedDate),
		RotationEnabled:    meta.RotationEnabled,
		RotationLambdaARN:  meta.RotationLambdaARN,
		NextRotationDate:   awsTimePtr(meta.NextRotationDate),
		VersionIDsToStages: secretVersionStagesMap(meta),
	})
}

func (s *Server) handleGetSecretValue(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.GetSecretValue"
	var req getSecretValueRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		// P4 folder-JSON projection: if no leaf secret exists by this exact
		// name, the SecretId may name a FOLDER. Serve a JSON object of every
		// key in that folder so AWS-compatible clients (incl. External Secrets
		// Operator) can consume a whole folder as one secret.
		if isSecretNotFound(err) {
			if values, ok, ferr := s.secretsSvc().FolderJSONByName(r.Context(), req.SecretID); ferr == nil && ok {
				blob, merr := json.Marshal(values)
				if merr == nil {
					resp := getSecretValueResponse{
						ARN:          s.store.SecretARNForCtx(r.Context(), req.SecretID),
						Name:         req.SecretID,
						SecretString: string(blob),
						CreatedDate:  store.AWSTimestamp(time.Now().UTC()),
					}
					s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
					writeJSON(w, http.StatusOK, resp)
					return
				}
			}
		}
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:GetSecretValue"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	value, err := s.store.GetSecretValue(r.Context(), req.SecretID, req.VersionID, req.VersionStage)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	resp := getSecretValueResponse{
		ARN:           value.ARN,
		Name:          value.Name,
		VersionID:     value.VersionID,
		VersionStages: value.VersionStages,
		CreatedDate:   store.AWSTimestamp(value.CreatedAt),
	}
	if value.SecretString != nil {
		resp.SecretString = *value.SecretString
	} else {
		resp.SecretBinary = value.SecretBinary
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: value.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePutSecretValue(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.PutSecretValue"
	var req store.PutSecretValueRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:PutSecretValue"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	if s.awsWriteNeedsApproval(r.Context(), meta.Name) {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "denied", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", awsApprovalRequiredMessage)
		return
	}
	value, err := s.store.PutSecretValue(store.WithActor(r.Context(), requestPrincipal(r)), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: value.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, putSecretValueResponse{ARN: value.ARN, Name: value.Name, VersionID: value.VersionID, VersionStages: value.VersionStages})
}

func (s *Server) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.UpdateSecret"
	var req store.UpdateSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	if req.SecretString != "" || req.SecretBinary != "" {
		if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", AuditOrigin: s.auditOrigin(r)})
			writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
			return
		}
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:UpdateSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	var value *store.SecretValueRecord
	if (req.SecretString != "" || req.SecretBinary != "" || strings.TrimSpace(req.KMSKeyID) != "") && s.awsWriteNeedsApproval(r.Context(), meta.Name) {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "denied", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", awsApprovalRequiredMessage)
		return
	}
	meta, value, err = s.store.UpdateSecret(store.WithActor(r.Context(), requestPrincipal(r)), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	resp := updateSecretResponse{ARN: meta.ARN, Name: meta.Name}
	if value != nil {
		resp.VersionID = value.VersionID
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.DeleteSecret"
	var req deleteSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:DeleteSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	meta, err = s.store.DeleteSecret(r.Context(), req.SecretID, req.RecoveryWindowInDays, req.ForceDeleteWithoutRecovery)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, deleteSecretResponse{ARN: meta.ARN, Name: meta.Name, DeletionDate: awsTimePtr(meta.DeletedDate)})
}

func (s *Server) handleRestoreSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.RestoreSecret"
	var req restoreSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:RestoreSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	meta, err = s.store.RestoreSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, restoreSecretResponse{ARN: meta.ARN, Name: meta.Name})
}

// Filter keys we honour. AWS also defines primary-region and owning-service;
// they mean nothing here, so they are rejected rather than silently ignored —
// quietly dropping a filter would return secrets the caller asked to exclude.
const (
	filterKeyName        = "name"
	filterKeyDescription = "description"
	filterKeyTagKey      = "tag-key"
	filterKeyTagValue    = "tag-value"
	filterKeyAll         = "all"
)

func validateSecretsFilters(filters []secretsFilter) error {
	for _, f := range filters {
		switch f.Key {
		case filterKeyName, filterKeyDescription, filterKeyTagKey, filterKeyTagValue, filterKeyAll:
		case "":
			return fmt.Errorf("filter Key is required")
		default:
			return fmt.Errorf("invalid filter key %q", f.Key)
		}
		if len(f.Values) == 0 {
			return fmt.Errorf("filter %q requires at least one value", f.Key)
		}
	}
	return nil
}

// AWS matches filter values as case-insensitive prefixes, not exact or substring
// matches: name "d76riders/prod/" matches d76riders/prod/MAPBOX_TOKEN.
func filterValueMatches(field, value string) bool {
	return strings.HasPrefix(strings.ToLower(field), strings.ToLower(value))
}

func secretMatchesFilters(item store.SecretMetadataRecord, filters []secretsFilter) bool {
	for _, f := range filters {
		if !secretMatchesFilter(item, f) {
			return false
		}
	}
	return true
}

func secretMatchesFilter(item store.SecretMetadataRecord, f secretsFilter) bool {
	// Values within a filter are OR'd, except that a negated value must hold for
	// every candidate — "!foo" excludes, it does not offer an alternative.
	matchedAny := false
	sawPositive := false

	for _, raw := range f.Values {
		negated := strings.HasPrefix(raw, "!")
		value := strings.TrimPrefix(raw, "!")

		hit := secretFieldMatches(item, f.Key, value)

		if negated {
			if hit {
				return false
			}
			continue
		}

		sawPositive = true
		if hit {
			matchedAny = true
		}
	}

	// Only negations: anything not excluded above is a match.
	if !sawPositive {
		return true
	}
	return matchedAny
}

func secretFieldMatches(item store.SecretMetadataRecord, key, value string) bool {
	switch key {
	case filterKeyName:
		return filterValueMatches(item.Name, value)
	case filterKeyDescription:
		return filterValueMatches(item.Description, value)
	case filterKeyAll:
		// "all" searches name, description, and tags together.
		return filterValueMatches(item.Name, value) || filterValueMatches(item.Description, value)
	case filterKeyTagKey, filterKeyTagValue:
		// Tags aren't stored on secrets here, so nothing can match. Reported
		// rather than pretended: a tag filter that always matches would hand back
		// the whole store.
		return false
	}
	return false
}

// listableSecret says whether ListSecrets returns an item: it must match the
// filters, and a secret scheduled for deletion is listed only on request.
func listableSecret(item store.SecretMetadataRecord, req listSecretsRequest) bool {
	if item.DeletedDate != nil && !req.IncludePlannedDeletion {
		return false
	}
	return secretMatchesFilters(item, req.Filters)
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.ListSecrets"
	var req listSecretsRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	limit, err := normalizeSecretListLimit(req.MaxResults)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if err := validateSecretsFilters(req.Filters); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	items, err := s.store.ListSecrets(r.Context())
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InternalServiceError", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServiceError", "list secrets failed")
		return
	}
	entries := make([]secretListEntry, 0, len(items))
	for _, item := range items {
		if !listableSecret(item, req) {
			continue
		}
		entries = append(entries, secretListEntry{
			ARN:             item.ARN,
			Name:            item.Name,
			Description:     item.Description,
			KMSKeyID:        item.KMSKeyID,
			CreatedDate:     store.AWSTimestamp(item.CreatedAt),
			LastChangedDate: store.AWSTimestamp(item.LastChangedDate),
			DeletedDate:     awsTimePtr(item.DeletedDate),
		})
	}
	entries, nextToken, _, err := paginateList(entries, req.NextToken, limit, func(item secretListEntry) string { return item.Name })
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, listSecretsResponse{SecretList: entries, NextToken: nextToken})
}

func validateSecretPayloadFields(secretString, secretBinary string) error {
	if secretString == "" && secretBinary == "" {
		return errors.New("SecretString or SecretBinary is required")
	}
	if secretString != "" && secretBinary != "" {
		return errors.New("SecretString and SecretBinary are mutually exclusive")
	}
	if secretBinary != "" {
		if _, err := base64.StdEncoding.DecodeString(secretBinary); err != nil {
			return errors.New("SecretBinary must be base64")
		}
	}
	return nil
}

func secretVersionStagesMap(meta store.SecretMetadataRecord) map[string][]string {
	store.EnsureSecretStageMap(&meta)
	out := map[string][]string{}
	for versionID, stages := range meta.VersionStages {
		copied := append([]string(nil), stages...)
		sort.Strings(copied)
		out[versionID] = copied
	}
	return out
}

func normalizeSecretListLimit(limit int) (int, error) {
	if limit == 0 {
		return defaultSecretListLimit, nil
	}
	if limit < 0 || limit > maxSecretListLimit {
		return 0, fmt.Errorf("MaxResults must be between 1 and %d", maxSecretListLimit)
	}
	return limit, nil
}

// isSecretNotFound reports whether err represents a missing secret, used to
// trigger the P4 folder-JSON projection fallback in GetSecretValue.
func isSecretNotFound(err error) bool {
	return classifySecretError(err) == "ResourceNotFoundException"
}

func classifySecretError(err error) string {
	switch {
	case errors.Is(err, store.ErrSecretExists):
		return "ResourceExistsException"
	case errors.Is(err, errAccessDenied):
		return "AccessDeniedException"
	case errors.Is(err, sql.ErrNoRows):
		return "ResourceNotFoundException"
	case errors.Is(err, store.ErrSecretPendingDeletion):
		return "InvalidRequestException"
	case errors.Is(err, store.ErrInvalidSecretVersion):
		return "InvalidRequestException"
	default:
		if strings.Contains(err.Error(), "scheduled for deletion") {
			return "InvalidRequestException"
		}
		if strings.Contains(err.Error(), "base64") || strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "mutually exclusive") || strings.Contains(err.Error(), "between 7 and 30") || strings.Contains(err.Error(), "MaxResults") || strings.Contains(err.Error(), "AutomaticallyAfterDays") {
			return "InvalidParameterException"
		}
		return "InternalServiceError"
	}
}

func secretError(w http.ResponseWriter, err error) {
	typ := classifySecretError(err)
	status := http.StatusInternalServerError
	msg := err.Error()
	switch typ {
	case "AccessDeniedException", "ResourceExistsException", "ResourceNotFoundException", "InvalidRequestException", "InvalidParameterException":
		status = http.StatusBadRequest
	default:
		// Never hand storage or crypto internals to the client.
		log.Printf("secrets manager: %v", err)
		msg = "an internal error occurred"
	}
	switch typ {
	case "ResourceNotFoundException":
		msg = "Secrets Manager can't find the specified secret."
	case "ResourceExistsException":
		msg = "a secret with this name already exists"
	}
	writeAWSJSONError(w, status, typ, msg)
}

func (s *Server) authorizeSecretAction(ctx context.Context, r *http.Request, meta store.SecretMetadataRecord, action string) error {
	policy := strings.TrimSpace(meta.PolicyDocument)
	if policy == "" {
		var err error
		policy, err = s.store.GetSecretResourcePolicy(ctx, meta.Name)
		if err != nil {
			return err
		}
	}
	allowed, err := policyAllows(policy, requestPrincipal(r), action, meta.ARN, s.cfg.DefaultDenyPolicy)
	if err != nil {
		return err
	}
	if !allowed {
		return errAccessDenied
	}
	return nil
}
