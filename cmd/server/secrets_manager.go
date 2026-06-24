package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// awsTimestamp marshals a time.Time as an AWS JSON 1.1 protocol epoch-seconds
// number (e.g. 1.50927752e9). AWS SDK clients (including External Secrets
// Operator) deserialize Secrets Manager timestamp fields as JSON numbers and
// reject the RFC3339 string that time.Time's default marshaler emits
// ("expected ... to be a JSON Number, got string instead").
type awsTimestamp time.Time

func (t awsTimestamp) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil
	}
	secs := float64(tt.UnixNano()) / float64(time.Second)
	return []byte(strconv.FormatFloat(secs, 'f', -1, 64)), nil
}

// awsTimePtr converts an optional time.Time into an optional awsTimestamp,
// preserving nil so omitempty fields stay absent.
func awsTimePtr(t *time.Time) *awsTimestamp {
	if t == nil {
		return nil
	}
	v := awsTimestamp(*t)
	return &v
}

const (
	defaultSecretListLimit = 100
	maxSecretListLimit     = 100
	currentVersionStage    = "AWSCURRENT"
	previousVersionStage   = "AWSPREVIOUS"
)

type createSecretRequest struct {
	Name               string `json:"Name"`
	Description        string `json:"Description"`
	KMSKeyID           string `json:"KmsKeyId"`
	SecretString       string `json:"SecretString"`
	SecretBinary       string `json:"SecretBinary"`
	ClientRequestToken string `json:"ClientRequestToken"`
}

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
	CreatedDate        awsTimestamp        `json:"CreatedDate"`
	LastChangedDate    awsTimestamp        `json:"LastChangedDate"`
	DeletedDate        *awsTimestamp       `json:"DeletedDate,omitempty"`
	RotationEnabled    bool                `json:"RotationEnabled,omitempty"`
	RotationLambdaARN  string              `json:"RotationLambdaARN,omitempty"`
	NextRotationDate   *awsTimestamp       `json:"NextRotationDate,omitempty"`
	VersionIDsToStages map[string][]string `json:"VersionIdsToStages"`
}

type getSecretValueRequest struct {
	SecretID     string `json:"SecretId"`
	VersionID    string `json:"VersionId"`
	VersionStage string `json:"VersionStage"`
}

type getSecretValueResponse struct {
	ARN           string       `json:"ARN"`
	Name          string       `json:"Name"`
	VersionID     string       `json:"VersionId"`
	SecretString  string       `json:"SecretString,omitempty"`
	SecretBinary  string       `json:"SecretBinary,omitempty"`
	VersionStages []string     `json:"VersionStages"`
	CreatedDate   awsTimestamp `json:"CreatedDate"`
}

type putSecretValueRequest struct {
	SecretID            string   `json:"SecretId"`
	ClientRequestToken  string   `json:"ClientRequestToken"`
	SecretString        string   `json:"SecretString"`
	SecretBinary        string   `json:"SecretBinary"`
	VersionStagesUnused []string `json:"VersionStages,omitempty"`
}

type putSecretValueResponse struct {
	ARN           string   `json:"ARN"`
	Name          string   `json:"Name"`
	VersionID     string   `json:"VersionId"`
	VersionStages []string `json:"VersionStages"`
}

type updateSecretRequest struct {
	SecretID           string `json:"SecretId"`
	Description        string `json:"Description"`
	KMSKeyID           string `json:"KmsKeyId"`
	SecretString       string `json:"SecretString"`
	SecretBinary       string `json:"SecretBinary"`
	ClientRequestToken string `json:"ClientRequestToken"`
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
	ARN          string        `json:"ARN"`
	Name         string        `json:"Name"`
	DeletionDate *awsTimestamp `json:"DeletionDate,omitempty"`
}

type restoreSecretRequest struct {
	SecretID string `json:"SecretId"`
}

type restoreSecretResponse struct {
	ARN  string `json:"ARN"`
	Name string `json:"Name"`
}

type listSecretsRequest struct {
	MaxResults int    `json:"MaxResults"`
	NextToken  string `json:"NextToken"`
}

type listSecretsResponse struct {
	SecretList []secretListEntry `json:"SecretList"`
	NextToken  string            `json:"NextToken,omitempty"`
}

type secretListEntry struct {
	ARN             string        `json:"ARN"`
	Name            string        `json:"Name"`
	Description     string        `json:"Description,omitempty"`
	KMSKeyID        string        `json:"KmsKeyId,omitempty"`
	CreatedDate     awsTimestamp  `json:"CreatedDate"`
	LastChangedDate awsTimestamp  `json:"LastChangedDate"`
	DeletedDate     *awsTimestamp `json:"DeletedDate,omitempty"`
	PrimaryRegion   string        `json:"PrimaryRegion,omitempty"`
}

type secretMetadataRecord struct {
	ARN               string
	Name              string
	Description       string
	KMSKeyID          string
	CurrentVersionID  string
	PreviousVersionID string
	VersionStages     map[string][]string
	CreatedAt         time.Time
	LastChangedDate   time.Time
	DeletedDate       *time.Time
	Tags              []secretTag
	PolicyDocument    string
	RotationEnabled   bool
	RotationLambdaARN string
	RotationDays      int
	NextRotationDate  *time.Time
}

type secretValueRecord struct {
	ARN           string
	Name          string
	VersionID     string
	SecretString  *string
	SecretBinary  string
	VersionStages []string
	CreatedAt     time.Time
	KMSKeyID      string
}

type secretTag struct {
	Key   string
	Value string
}

type inMemorySecret struct {
	account  string
	metadata secretMetadataRecord
	versions map[string]inMemorySecretVersion
	byToken  map[string]string
}

// memSecretKey builds the composite map key used by the in-memory store so two
// different accounts can hold a secret of the same name without colliding.
func memSecretKey(account, name string) string {
	return account + "\x00" + name
}

type inMemorySecretVersion struct {
	VersionID           string
	ClientRequestToken  string
	EncryptedPayloadB64 string
	IsBinary            bool
	CreatedAt           time.Time
}

func (s *server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.CreateSecret"
	var req createSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "Name is required")
		return
	}
	if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
		return
	}
	meta, value, err := s.store.CreateSecret(r.Context(), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, createSecretResponse{ARN: meta.ARN, Name: meta.Name, VersionID: value.VersionID})
}

func (s *server) handleDescribeSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.DescribeSecret"
	var req describeSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:DescribeSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, describeSecretResponse{
		ARN:                meta.ARN,
		Name:               meta.Name,
		Description:        meta.Description,
		KMSKeyID:           meta.KMSKeyID,
		CreatedDate:        awsTimestamp(meta.CreatedAt),
		LastChangedDate:    awsTimestamp(meta.LastChangedDate),
		DeletedDate:        awsTimePtr(meta.DeletedDate),
		RotationEnabled:    meta.RotationEnabled,
		RotationLambdaARN:  meta.RotationLambdaARN,
		NextRotationDate:   awsTimePtr(meta.NextRotationDate),
		VersionIDsToStages: secretVersionStagesMap(meta),
	})
}

func (s *server) handleGetSecretValue(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.GetSecretValue"
	var req getSecretValueRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
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
						ARN:          s.store.secretARNForCtx(r.Context(), req.SecretID),
						Name:         req.SecretID,
						SecretString: string(blob),
						CreatedDate:  awsTimestamp(time.Now().UTC()),
					}
					s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
					writeJSON(w, http.StatusOK, resp)
					return
				}
			}
		}
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:GetSecretValue"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	value, err := s.store.GetSecretValue(r.Context(), req.SecretID, req.VersionID, req.VersionStage)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	resp := getSecretValueResponse{
		ARN:           value.ARN,
		Name:          value.Name,
		VersionID:     value.VersionID,
		VersionStages: value.VersionStages,
		CreatedDate:   awsTimestamp(value.CreatedAt),
	}
	if value.SecretString != nil {
		resp.SecretString = *value.SecretString
	} else {
		resp.SecretBinary = value.SecretBinary
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: value.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handlePutSecretValue(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.PutSecretValue"
	var req putSecretValueRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:PutSecretValue"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	value, err := s.store.PutSecretValue(r.Context(), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: value.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, putSecretValueResponse{ARN: value.ARN, Name: value.Name, VersionID: value.VersionID, VersionStages: value.VersionStages})
}

func (s *server) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.UpdateSecret"
	var req updateSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	if req.SecretString != "" || req.SecretBinary != "" {
		if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
			s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", Actor: r.RemoteAddr})
			writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
			return
		}
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:UpdateSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	var value *secretValueRecord
	meta, value, err = s.store.UpdateSecret(r.Context(), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	resp := updateSecretResponse{ARN: meta.ARN, Name: meta.Name}
	if value != nil {
		resp.VersionID = value.VersionID
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.DeleteSecret"
	var req deleteSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:DeleteSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	meta, err = s.store.DeleteSecret(r.Context(), req.SecretID, req.RecoveryWindowInDays, req.ForceDeleteWithoutRecovery)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, deleteSecretResponse{ARN: meta.ARN, Name: meta.Name, DeletionDate: awsTimePtr(meta.DeletedDate)})
}

func (s *server) handleRestoreSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.RestoreSecret"
	var req restoreSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:RestoreSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	meta, err = s.store.RestoreSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, restoreSecretResponse{ARN: meta.ARN, Name: meta.Name})
}

func (s *server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.ListSecrets"
	var req listSecretsRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	limit, err := normalizeSecretListLimit(req.MaxResults)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	items, err := s.store.ListSecrets(r.Context())
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InternalServiceError", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServiceError", "list secrets failed")
		return
	}
	entries := make([]secretListEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, secretListEntry{
			ARN:             item.ARN,
			Name:            item.Name,
			Description:     item.Description,
			KMSKeyID:        item.KMSKeyID,
			CreatedDate:     awsTimestamp(item.CreatedAt),
			LastChangedDate: awsTimestamp(item.LastChangedDate),
			DeletedDate:     awsTimePtr(item.DeletedDate),
		})
	}
	entries, nextToken, _, err := paginateList(entries, req.NextToken, limit, func(item secretListEntry) string { return item.Name })
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listSecretsResponse{SecretList: entries, NextToken: nextToken})
}

func (s *dbStore) CreateSecret(ctx context.Context, req createSecretRequest) (secretMetadataRecord, secretValueRecord, error) {
	name := strings.TrimSpace(req.Name)
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = randomHex(16)
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := buildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, req.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, err
	}
	now := time.Now().UTC()
	meta := secretMetadataRecord{
		ARN:               s.secretARNForCtx(ctx, name),
		Name:              name,
		Description:       strings.TrimSpace(req.Description),
		KMSKeyID:          kmsKeyID,
		CurrentVersionID:  versionID,
		PreviousVersionID: "",
		VersionStages:     map[string][]string{versionID: {currentVersionStage}},
		CreatedAt:         now,
		LastChangedDate:   now,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, err
	}
	defer tx.Rollback()
	const insertSecret = `
INSERT INTO sm_secrets (name, arn, description, kms_key_id, current_version_id, previous_version_id, deleted_date, created_at, updated_at, account_id)
VALUES ($1, $2, $3, $4, $5, '', NULL, $6, $7, $8)
`
	if _, err := tx.ExecContext(ctx, insertSecret, meta.Name, meta.ARN, meta.Description, meta.KMSKeyID, meta.CurrentVersionID, meta.CreatedAt, meta.LastChangedDate, s.accountForContext(ctx)); err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, mapSecretDBError(err)
	}
	const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, mapSecretDBError(err)
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, err
	}
	value, err := buildSecretValueRecord(ctx, s.ResolveByID, meta, secretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
	if err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, err
	}
	return meta, value, nil
}

func (s *dbStore) DescribeSecret(ctx context.Context, secretID string) (secretMetadataRecord, error) {
	return s.loadSecretMetadata(ctx, secretID)
}

func (s *dbStore) GetSecretValue(ctx context.Context, secretID, versionID, versionStage string) (secretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return secretValueRecord{}, err
	}
	if meta.DeletedDate != nil {
		return secretValueRecord{}, errors.New("secret scheduled for deletion")
	}
	resolvedVersionID, err := resolveSecretVersionID(meta, versionID, versionStage)
	if err != nil {
		return secretValueRecord{}, err
	}
	version, err := s.loadSecretVersion(ctx, meta.Name, resolvedVersionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return secretValueRecord{}, sql.ErrNoRows
		}
		return secretValueRecord{}, err
	}
	return buildSecretValueRecord(ctx, s.ResolveByID, meta, version)
}

func (s *dbStore) PutSecretValue(ctx context.Context, req putSecretValueRequest) (secretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, req.SecretID)
	if err != nil {
		return secretValueRecord{}, err
	}
	if meta.DeletedDate != nil {
		return secretValueRecord{}, errors.New("secret scheduled for deletion")
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = randomHex(16)
	}
	if existing, err := s.loadSecretVersionByToken(ctx, meta.Name, versionID); err == nil {
		return buildSecretValueRecord(ctx, s.ResolveByID, meta, existing)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return secretValueRecord{}, err
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := buildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, meta.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return secretValueRecord{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return secretValueRecord{}, err
	}
	defer tx.Rollback()
	const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
		return secretValueRecord{}, mapSecretDBError(err)
	}
	promoteSecretVersion(&meta, versionID)
	const updateSecret = `
UPDATE sm_secrets
SET kms_key_id = $2, previous_version_id = current_version_id, current_version_id = $3, updated_at = $4
WHERE name = $1
`
	if _, err := tx.ExecContext(ctx, updateSecret, meta.Name, kmsKeyID, versionID, now); err != nil {
		return secretValueRecord{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return secretValueRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return secretValueRecord{}, err
	}
	meta.KMSKeyID = kmsKeyID
	meta.LastChangedDate = now
	return buildSecretValueRecord(ctx, s.ResolveByID, meta, secretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
}

func (s *dbStore) UpdateSecret(ctx context.Context, req updateSecretRequest) (secretMetadataRecord, *secretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, req.SecretID)
	if err != nil {
		return secretMetadataRecord{}, nil, err
	}
	if meta.DeletedDate != nil {
		return secretMetadataRecord{}, nil, errors.New("secret scheduled for deletion")
	}
	nextDescription := meta.Description
	if strings.TrimSpace(req.Description) != "" {
		nextDescription = strings.TrimSpace(req.Description)
	}
	nextKMSKeyID := meta.KMSKeyID
	if strings.TrimSpace(req.KMSKeyID) != "" {
		resolved, err := s.ResolveByID(ctx, req.KMSKeyID)
		if err != nil {
			return secretMetadataRecord{}, nil, err
		}
		nextKMSKeyID = resolved.ID
	}
	now := time.Now().UTC()
	var value *secretValueRecord
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return secretMetadataRecord{}, nil, err
	}
	defer tx.Rollback()
	ensureSecretStageMap(&meta)
	if req.SecretString != "" || req.SecretBinary != "" {
		versionID := req.ClientRequestToken
		if versionID == "" {
			versionID = randomHex(16)
		}
		if existing, err := s.loadSecretVersionByToken(ctx, meta.Name, versionID); err == nil {
			built, buildErr := buildSecretValueRecord(ctx, s.ResolveByID, meta, existing)
			if buildErr != nil {
				return secretMetadataRecord{}, nil, buildErr
			}
			value = &built
		} else if !errors.Is(err, sql.ErrNoRows) {
			return secretMetadataRecord{}, nil, err
		} else {
			kmsKeyID, encryptedPayloadB64, isBinary, encErr := buildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, nextKMSKeyID, req.SecretString, req.SecretBinary)
			if encErr != nil {
				return secretMetadataRecord{}, nil, encErr
			}
			const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
			if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
				return secretMetadataRecord{}, nil, mapSecretDBError(err)
			}
			promoteSecretVersion(&meta, versionID)
			nextKMSKeyID = kmsKeyID
			built, buildErr := buildSecretValueRecord(ctx, s.ResolveByID, meta, secretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
			if buildErr != nil {
				return secretMetadataRecord{}, nil, buildErr
			}
			value = &built
		}
	}
	const updateSecret = `
UPDATE sm_secrets
SET description = $2, kms_key_id = $3, current_version_id = $4, previous_version_id = $5, updated_at = $6
WHERE name = $1
`
	if _, err := tx.ExecContext(ctx, updateSecret, meta.Name, nextDescription, nextKMSKeyID, meta.CurrentVersionID, meta.PreviousVersionID, now); err != nil {
		return secretMetadataRecord{}, nil, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return secretMetadataRecord{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return secretMetadataRecord{}, nil, err
	}
	meta.Description = nextDescription
	meta.KMSKeyID = nextKMSKeyID
	meta.LastChangedDate = now
	return meta, value, nil
}

func (s *dbStore) DeleteSecret(ctx context.Context, secretID string, recoveryWindowDays int, forceDelete bool) (secretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return secretMetadataRecord{}, err
	}
	if meta.DeletedDate != nil {
		return meta, nil
	}
	deletionDate, err := normalizeSecretDeletion(forceDelete, recoveryWindowDays)
	if err != nil {
		return secretMetadataRecord{}, err
	}
	const q = `UPDATE sm_secrets SET deleted_date = $2, updated_at = NOW() WHERE name = $1`
	if _, err := s.db.ExecContext(ctx, q, meta.Name, deletionDate); err != nil {
		return secretMetadataRecord{}, err
	}
	meta.DeletedDate = &deletionDate
	meta.LastChangedDate = time.Now().UTC()
	return meta, nil
}

func (s *dbStore) RestoreSecret(ctx context.Context, secretID string) (secretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return secretMetadataRecord{}, err
	}
	const q = `UPDATE sm_secrets SET deleted_date = NULL, updated_at = NOW() WHERE name = $1`
	if _, err := s.db.ExecContext(ctx, q, meta.Name); err != nil {
		return secretMetadataRecord{}, err
	}
	meta.DeletedDate = nil
	meta.LastChangedDate = time.Now().UTC()
	return meta, nil
}

func (s *dbStore) ListSecrets(ctx context.Context) ([]secretMetadataRecord, error) {
	q := `
SELECT name, arn, description, kms_key_id, current_version_id, previous_version_id, rotation_enabled, rotation_lambda_arn, rotation_days, next_rotation_date, deleted_date, created_at, updated_at
FROM sm_secrets`
	cond, args := accountFilter(ctx, "account_id", 1)
	if cond != "" {
		q += "\nWHERE " + cond
	}
	q += "\nORDER BY created_at ASC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]secretMetadataRecord, 0)
	for rows.Next() {
		var (
			item        secretMetadataRecord
			nextRotate  sql.NullTime
			deletedDate sql.NullTime
		)
		if err := rows.Scan(&item.Name, &item.ARN, &item.Description, &item.KMSKeyID, &item.CurrentVersionID, &item.PreviousVersionID, &item.RotationEnabled, &item.RotationLambdaARN, &item.RotationDays, &nextRotate, &deletedDate, &item.CreatedAt, &item.LastChangedDate); err != nil {
			return nil, err
		}
		if nextRotate.Valid {
			item.NextRotationDate = &nextRotate.Time
		}
		if deletedDate.Valid {
			item.DeletedDate = &deletedDate.Time
		}
		item.VersionStages = buildFallbackSecretStageMap(item.CurrentVersionID, item.PreviousVersionID)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *dbStore) loadSecretMetadata(ctx context.Context, secretID string) (secretMetadataRecord, error) {
	q := `
SELECT name, arn, description, kms_key_id, current_version_id, previous_version_id, rotation_enabled, rotation_lambda_arn, rotation_days, next_rotation_date, deleted_date, created_at, updated_at
FROM sm_secrets
WHERE (name = $1 OR arn = $1)`
	args := []any{strings.TrimSpace(secretID)}
	if cond, extra := accountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	q += "\nLIMIT 1"
	var (
		item        secretMetadataRecord
		nextRotate  sql.NullTime
		deletedDate sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&item.Name, &item.ARN, &item.Description, &item.KMSKeyID, &item.CurrentVersionID, &item.PreviousVersionID, &item.RotationEnabled, &item.RotationLambdaARN, &item.RotationDays, &nextRotate, &deletedDate, &item.CreatedAt, &item.LastChangedDate)
	if err != nil {
		return secretMetadataRecord{}, err
	}
	if nextRotate.Valid {
		item.NextRotationDate = &nextRotate.Time
	}
	if deletedDate.Valid {
		item.DeletedDate = &deletedDate.Time
	}
	item.VersionStages = buildFallbackSecretStageMap(item.CurrentVersionID, item.PreviousVersionID)
	if err := s.loadSecretDecorations(ctx, &item); err != nil {
		return secretMetadataRecord{}, err
	}
	return item, nil
}

type secretVersionRow struct {
	VersionID           string
	EncryptedPayloadB64 string
	IsBinary            bool
	CreatedAt           time.Time
}

func (s *dbStore) loadSecretVersion(ctx context.Context, secretName, versionID string) (secretVersionRow, error) {
	const q = `
SELECT version_id, encrypted_payload_b64, is_binary, version_created_at
FROM sm_secret_versions
WHERE secret_name = $1 AND version_id = $2
`
	var row secretVersionRow
	err := s.db.QueryRowContext(ctx, q, secretName, versionID).Scan(&row.VersionID, &row.EncryptedPayloadB64, &row.IsBinary, &row.CreatedAt)
	return row, err
}

func (s *dbStore) loadSecretVersionByToken(ctx context.Context, secretName, token string) (secretVersionRow, error) {
	const q = `
SELECT version_id, encrypted_payload_b64, is_binary, version_created_at
FROM sm_secret_versions
WHERE secret_name = $1 AND client_request_token = $2
`
	var row secretVersionRow
	err := s.db.QueryRowContext(ctx, q, secretName, token).Scan(&row.VersionID, &row.EncryptedPayloadB64, &row.IsBinary, &row.CreatedAt)
	return row, err
}

func (s *inMemoryStore) CreateSecret(ctx context.Context, req createSecretRequest) (secretMetadataRecord, secretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secrets == nil {
		s.secrets = map[string]*inMemorySecret{}
	}
	account := s.accountForContext(ctx)
	name := strings.TrimSpace(req.Name)
	if _, ok := s.secrets[memSecretKey(account, name)]; ok {
		return secretMetadataRecord{}, secretValueRecord{}, errSecretExists
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = randomHex(16)
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := buildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, req.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, err
	}
	now := time.Now().UTC()
	meta := secretMetadataRecord{
		ARN:               s.secretARNForCtx(ctx, name),
		Name:              name,
		Description:       strings.TrimSpace(req.Description),
		KMSKeyID:          kmsKeyID,
		CurrentVersionID:  versionID,
		PreviousVersionID: "",
		VersionStages:     map[string][]string{versionID: {currentVersionStage}},
		CreatedAt:         now,
		LastChangedDate:   now,
	}
	secret := &inMemorySecret{
		account:  account,
		metadata: meta,
		versions: map[string]inMemorySecretVersion{},
		byToken:  map[string]string{},
	}
	secret.versions[versionID] = inMemorySecretVersion{VersionID: versionID, ClientRequestToken: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now}
	secret.byToken[versionID] = versionID
	s.secrets[memSecretKey(account, name)] = secret
	value, err := buildSecretValueRecord(ctx, s.ResolveByID, meta, secretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
	if err != nil {
		return secretMetadataRecord{}, secretValueRecord{}, err
	}
	return meta, value, nil
}

func (s *inMemoryStore) DescribeSecret(ctx context.Context, secretID string) (secretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return secretMetadataRecord{}, err
	}
	return secret.metadata, nil
}

func (s *inMemoryStore) GetSecretValue(ctx context.Context, secretID, versionID, versionStage string) (secretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getSecretValueLocked(ctx, secretID, versionID, versionStage)
}

// getSecretValueLocked implements GetSecretValue. The caller must hold s.mu.
func (s *inMemoryStore) getSecretValueLocked(ctx context.Context, secretID, versionID, versionStage string) (secretValueRecord, error) {
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return secretValueRecord{}, err
	}
	if secret.metadata.DeletedDate != nil {
		return secretValueRecord{}, errSecretPendingDeletion
	}
	resolvedVersionID, err := resolveSecretVersionID(secret.metadata, versionID, versionStage)
	if err != nil {
		return secretValueRecord{}, err
	}
	version, ok := secret.versions[resolvedVersionID]
	if !ok {
		return secretValueRecord{}, sql.ErrNoRows
	}
	return buildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, secretVersionRow{VersionID: version.VersionID, EncryptedPayloadB64: version.EncryptedPayloadB64, IsBinary: version.IsBinary, CreatedAt: version.CreatedAt})
}

func (s *inMemoryStore) PutSecretValue(ctx context.Context, req putSecretValueRequest) (secretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putSecretValueLocked(ctx, req)
}

// putSecretValueLocked implements PutSecretValue. The caller must hold s.mu.
func (s *inMemoryStore) putSecretValueLocked(ctx context.Context, req putSecretValueRequest) (secretValueRecord, error) {
	secret, err := s.findSecret(ctx, req.SecretID)
	if err != nil {
		return secretValueRecord{}, err
	}
	if secret.metadata.DeletedDate != nil {
		return secretValueRecord{}, errSecretPendingDeletion
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = randomHex(16)
	}
	if existingVersionID, ok := secret.byToken[versionID]; ok {
		version := secret.versions[existingVersionID]
		return buildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, secretVersionRow{VersionID: version.VersionID, EncryptedPayloadB64: version.EncryptedPayloadB64, IsBinary: version.IsBinary, CreatedAt: version.CreatedAt})
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := buildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, secret.metadata.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return secretValueRecord{}, err
	}
	now := time.Now().UTC()
	secret.metadata.KMSKeyID = kmsKeyID
	promoteSecretVersion(&secret.metadata, versionID)
	secret.metadata.LastChangedDate = now
	secret.byToken[versionID] = versionID
	secret.versions[versionID] = inMemorySecretVersion{VersionID: versionID, ClientRequestToken: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now}
	return buildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, secretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
}

func (s *inMemoryStore) UpdateSecret(ctx context.Context, req updateSecretRequest) (secretMetadataRecord, *secretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, req.SecretID)
	if err != nil {
		return secretMetadataRecord{}, nil, err
	}
	if secret.metadata.DeletedDate != nil {
		return secretMetadataRecord{}, nil, errSecretPendingDeletion
	}
	if strings.TrimSpace(req.Description) != "" {
		secret.metadata.Description = strings.TrimSpace(req.Description)
	}
	if strings.TrimSpace(req.KMSKeyID) != "" {
		resolved, err := s.ResolveByID(ctx, req.KMSKeyID)
		if err != nil {
			return secretMetadataRecord{}, nil, err
		}
		secret.metadata.KMSKeyID = resolved.ID
	}
	secret.metadata.LastChangedDate = time.Now().UTC()
	ensureSecretStageMap(&secret.metadata)
	var value *secretValueRecord
	if req.SecretString != "" || req.SecretBinary != "" {
		putValue, err := s.putSecretValueLocked(ctx, putSecretValueRequest{SecretID: secret.metadata.Name, ClientRequestToken: req.ClientRequestToken, SecretString: req.SecretString, SecretBinary: req.SecretBinary})
		if err != nil {
			return secretMetadataRecord{}, nil, err
		}
		value = &putValue
	}
	return secret.metadata, value, nil
}

func (s *inMemoryStore) DeleteSecret(ctx context.Context, secretID string, recoveryWindowDays int, forceDelete bool) (secretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return secretMetadataRecord{}, err
	}
	deletionDate, err := normalizeSecretDeletion(forceDelete, recoveryWindowDays)
	if err != nil {
		return secretMetadataRecord{}, err
	}
	secret.metadata.DeletedDate = &deletionDate
	secret.metadata.LastChangedDate = time.Now().UTC()
	return secret.metadata, nil
}

func (s *inMemoryStore) RestoreSecret(ctx context.Context, secretID string) (secretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return secretMetadataRecord{}, err
	}
	secret.metadata.DeletedDate = nil
	secret.metadata.LastChangedDate = time.Now().UTC()
	return secret.metadata, nil
}

func (s *inMemoryStore) ListSecrets(ctx context.Context) ([]secretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.secrets) == 0 {
		return nil, nil
	}
	account := s.accountForContext(ctx)
	keys := make([]string, 0, len(s.secrets))
	for key, secret := range s.secrets {
		if secret.account != account {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]secretMetadataRecord, 0, len(keys))
	for _, key := range keys {
		out = append(out, s.secrets[key].metadata)
	}
	return out, nil
}

// findSecret resolves a secret within the caller's account by logical name or
// ARN. Scoping by account ensures one tenant can never resolve another's
// secret, even when they share the same name.
func (s *inMemoryStore) findSecret(ctx context.Context, secretID string) (*inMemorySecret, error) {
	if len(s.secrets) == 0 {
		return nil, sql.ErrNoRows
	}
	account := s.accountForContext(ctx)
	secretID = strings.TrimSpace(secretID)
	if secret, ok := s.secrets[memSecretKey(account, secretID)]; ok {
		return secret, nil
	}
	for _, secret := range s.secrets {
		if secret.account == account && secret.metadata.ARN == secretID {
			return secret, nil
		}
	}
	return nil, sql.ErrNoRows
}

var (
	errSecretExists          = errors.New("secret already exists")
	errSecretPendingDeletion = errors.New("secret scheduled for deletion")
	errInvalidSecretVersion  = errors.New("invalid secret version")
)

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

func buildSecretCiphertext(ctx context.Context, resolveByID func(context.Context, string) (kmsKey, error), resolveDefault func(context.Context) (kmsKey, error), kmsKeyID, secretString, secretBinary string) (string, string, bool, error) {
	var (
		key kmsKey
		err error
	)
	if strings.TrimSpace(kmsKeyID) != "" {
		key, err = resolveByID(ctx, strings.TrimSpace(kmsKeyID))
	} else {
		key, err = resolveDefault(ctx)
	}
	if err != nil {
		return "", "", false, err
	}
	var (
		raw      []byte
		isBinary bool
	)
	if secretBinary != "" {
		raw, err = base64.StdEncoding.DecodeString(secretBinary)
		if err != nil {
			return "", "", false, errors.New("SecretBinary must be base64")
		}
		isBinary = true
	} else {
		raw = []byte(secretString)
	}
	cipherBlob, err := encryptBlob(key.MasterKeyRaw, key.ID, raw, nil)
	if err != nil {
		return "", "", false, err
	}
	return key.ID, base64.StdEncoding.EncodeToString(cipherBlob), isBinary, nil
}

func buildSecretValueRecord(ctx context.Context, resolveByID func(context.Context, string) (kmsKey, error), meta secretMetadataRecord, version secretVersionRow) (secretValueRecord, error) {
	key, err := resolveByID(ctx, meta.KMSKeyID)
	if err != nil {
		return secretValueRecord{}, err
	}
	encoded, err := base64.StdEncoding.DecodeString(version.EncryptedPayloadB64)
	if err != nil {
		return secretValueRecord{}, err
	}
	_, rawBlob, err := decodeCipherBlob(encoded)
	if err != nil {
		return secretValueRecord{}, err
	}
	raw, err := decryptBlob(key.MasterKeyRaw, rawBlob, nil)
	if err != nil {
		return secretValueRecord{}, err
	}
	value := secretValueRecord{
		ARN:           meta.ARN,
		Name:          meta.Name,
		VersionID:     version.VersionID,
		VersionStages: secretStagesForVersion(meta, version.VersionID),
		CreatedAt:     version.CreatedAt,
		KMSKeyID:      meta.KMSKeyID,
	}
	if version.IsBinary {
		value.SecretBinary = base64.StdEncoding.EncodeToString(raw)
	} else {
		secretString := string(raw)
		value.SecretString = &secretString
	}
	return value, nil
}

func secretStagesForVersion(meta secretMetadataRecord, versionID string) []string {
	ensureSecretStageMap(&meta)
	stages := append([]string(nil), meta.VersionStages[versionID]...)
	sort.Strings(stages)
	return stages
}

func secretVersionStagesMap(meta secretMetadataRecord) map[string][]string {
	ensureSecretStageMap(&meta)
	out := map[string][]string{}
	for versionID, stages := range meta.VersionStages {
		copied := append([]string(nil), stages...)
		sort.Strings(copied)
		out[versionID] = copied
	}
	return out
}

func resolveSecretVersionID(meta secretMetadataRecord, versionID, versionStage string) (string, error) {
	if versionID != "" {
		return versionID, nil
	}
	if versionStage == "" || versionStage == currentVersionStage {
		return meta.CurrentVersionID, nil
	}
	if versionStage == previousVersionStage && meta.PreviousVersionID != "" {
		return meta.PreviousVersionID, nil
	}
	ensureSecretStageMap(&meta)
	for candidateVersionID, stages := range meta.VersionStages {
		if containsString(stages, versionStage) {
			return candidateVersionID, nil
		}
	}
	return "", errInvalidSecretVersion
}

func normalizeSecretDeletion(forceDelete bool, recoveryWindowDays int) (time.Time, error) {
	if forceDelete {
		now := time.Now().UTC()
		return now, nil
	}
	if recoveryWindowDays == 0 {
		recoveryWindowDays = 30
	}
	if recoveryWindowDays < 7 || recoveryWindowDays > 30 {
		return time.Time{}, errors.New("RecoveryWindowInDays must be between 7 and 30")
	}
	return time.Now().UTC().Add(time.Duration(recoveryWindowDays) * 24 * time.Hour), nil
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
	case errors.Is(err, errSecretExists):
		return "ResourceExistsException"
	case errors.Is(err, errAccessDenied):
		return "AccessDeniedException"
	case errors.Is(err, sql.ErrNoRows):
		return "ResourceNotFoundException"
	case errors.Is(err, errSecretPendingDeletion):
		return "InvalidRequestException"
	case errors.Is(err, errInvalidSecretVersion):
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
	switch typ {
	case "AccessDeniedException", "ResourceExistsException", "ResourceNotFoundException", "InvalidRequestException", "InvalidParameterException":
		status = http.StatusBadRequest
	}
	writeAWSJSONError(w, status, typ, err.Error())
}

func (s *server) authorizeSecretAction(ctx context.Context, r *http.Request, meta secretMetadataRecord, action string) error {
	policy := strings.TrimSpace(meta.PolicyDocument)
	if policy == "" {
		var err error
		policy, err = s.store.GetSecretResourcePolicy(ctx, meta.Name)
		if err != nil {
			return err
		}
	}
	allowed, err := policyAllows(policy, requestPrincipal(r), action, meta.ARN, s.cfg.defaultDenyPolicy)
	if err != nil {
		return err
	}
	if !allowed {
		return errAccessDenied
	}
	return nil
}

func mapSecretDBError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "duplicate key value") {
		return errSecretExists
	}
	return err
}
