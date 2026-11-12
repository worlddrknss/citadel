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
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
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

type inMemorySecret struct {
	account  string
	metadata store.SecretMetadataRecord
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
	var req store.CreateSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "Name is required")
		return
	}
	if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", Actor: r.RemoteAddr})
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
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException",
			fmt.Sprintf("%q names a folder that already holds secrets; a secret stored there would shadow the folder's JSON projection and be invisible in the UI", req.Name))
		return
	}
	meta, value, err := s.store.CreateSecret(r.Context(), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, createSecretResponse{ARN: meta.ARN, Name: meta.Name, VersionID: value.VersionID})
}

func (s *server) handleDescribeSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.DescribeSecret"
	var req describeSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:DescribeSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
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

func (s *server) handleGetSecretValue(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.GetSecretValue"
	var req getSecretValueRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
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
					s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
					writeJSON(w, http.StatusOK, resp)
					return
				}
			}
		}
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:GetSecretValue"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	value, err := s.store.GetSecretValue(r.Context(), req.SecretID, req.VersionID, req.VersionStage)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
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
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: value.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handlePutSecretValue(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.PutSecretValue"
	var req store.PutSecretValueRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:PutSecretValue"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	value, err := s.store.PutSecretValue(r.Context(), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: value.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, putSecretValueResponse{ARN: value.ARN, Name: value.Name, VersionID: value.VersionID, VersionStages: value.VersionStages})
}

func (s *server) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.UpdateSecret"
	var req store.UpdateSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	if req.SecretString != "" || req.SecretBinary != "" {
		if err := validateSecretPayloadFields(req.SecretString, req.SecretBinary); err != nil {
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidRequestException", Actor: r.RemoteAddr})
			writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
			return
		}
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:UpdateSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	var value *store.SecretValueRecord
	meta, value, err = s.store.UpdateSecret(r.Context(), req)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	resp := updateSecretResponse{ARN: meta.ARN, Name: meta.Name}
	if value != nil {
		resp.VersionID = value.VersionID
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.DeleteSecret"
	var req deleteSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:DeleteSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	meta, err = s.store.DeleteSecret(r.Context(), req.SecretID, req.RecoveryWindowInDays, req.ForceDeleteWithoutRecovery)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, deleteSecretResponse{ARN: meta.ARN, Name: meta.Name, DeletionDate: awsTimePtr(meta.DeletedDate)})
}

func (s *server) handleRestoreSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.RestoreSecret"
	var req restoreSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if strings.TrimSpace(req.SecretID) == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "SecretId is required")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:RestoreSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	meta, err = s.store.RestoreSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: classifySecretError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
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

func (s *server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.ListSecrets"
	var req listSecretsRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	limit, err := normalizeSecretListLimit(req.MaxResults)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	if err := validateSecretsFilters(req.Filters); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	items, err := s.store.ListSecrets(r.Context())
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InternalServiceError", Actor: r.RemoteAddr})
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
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listSecretsResponse{SecretList: entries, NextToken: nextToken})
}

func (s *dbStore) CreateSecret(ctx context.Context, req store.CreateSecretRequest) (store.SecretMetadataRecord, store.SecretValueRecord, error) {
	name := strings.TrimSpace(req.Name)
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = cryptoutil.RandomHex(16)
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, req.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	meta := store.SecretMetadataRecord{
		ARN:               s.SecretARNForCtx(ctx, name),
		Name:              name,
		Description:       strings.TrimSpace(req.Description),
		KMSKeyID:          kmsKeyID,
		CurrentVersionID:  versionID,
		PreviousVersionID: "",
		VersionStages:     map[string][]string{versionID: {store.CurrentVersionStage}},
		CreatedAt:         now,
		LastChangedDate:   now,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	defer tx.Rollback()
	const insertSecret = `
INSERT INTO sm_secrets (name, arn, description, kms_key_id, current_version_id, previous_version_id, deleted_date, created_at, updated_at, account_id)
VALUES ($1, $2, $3, $4, $5, '', NULL, $6, $7, $8)
`
	if _, err := tx.ExecContext(ctx, insertSecret, meta.Name, meta.ARN, meta.Description, meta.KMSKeyID, meta.CurrentVersionID, meta.CreatedAt, meta.LastChangedDate, s.accountForContext(ctx)); err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, mapSecretDBError(err)
	}
	const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, mapSecretDBError(err)
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	value, err := store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	return meta, value, nil
}

func (s *dbStore) DescribeSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	return s.loadSecretMetadata(ctx, secretID)
}

func (s *dbStore) GetSecretValue(ctx context.Context, secretID, versionID, versionStage string) (store.SecretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if meta.DeletedDate != nil {
		return store.SecretValueRecord{}, errors.New("secret scheduled for deletion")
	}
	resolvedVersionID, err := store.ResolveSecretVersionID(meta, versionID, versionStage)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	version, err := s.loadSecretVersion(ctx, meta.Name, resolvedVersionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.SecretValueRecord{}, sql.ErrNoRows
		}
		return store.SecretValueRecord{}, err
	}
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, version)
}

func (s *dbStore) PutSecretValue(ctx context.Context, req store.PutSecretValueRequest) (store.SecretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, req.SecretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if meta.DeletedDate != nil {
		return store.SecretValueRecord{}, errors.New("secret scheduled for deletion")
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = cryptoutil.RandomHex(16)
	}
	if existing, err := s.loadSecretVersionByToken(ctx, meta.Name, versionID); err == nil {
		return store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, existing)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return store.SecretValueRecord{}, err
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, meta.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	defer tx.Rollback()
	const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
		return store.SecretValueRecord{}, mapSecretDBError(err)
	}
	store.PromoteSecretVersion(&meta, versionID)
	const updateSecret = `
UPDATE sm_secrets
SET kms_key_id = $2, previous_version_id = current_version_id, current_version_id = $3, updated_at = $4
WHERE name = $1
`
	if _, err := tx.ExecContext(ctx, updateSecret, meta.Name, kmsKeyID, versionID, now); err != nil {
		return store.SecretValueRecord{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretValueRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretValueRecord{}, err
	}
	meta.KMSKeyID = kmsKeyID
	meta.LastChangedDate = now
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
}

func (s *dbStore) UpdateSecret(ctx context.Context, req store.UpdateSecretRequest) (store.SecretMetadataRecord, *store.SecretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, req.SecretID)
	if err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	if meta.DeletedDate != nil {
		return store.SecretMetadataRecord{}, nil, errors.New("secret scheduled for deletion")
	}
	nextDescription := meta.Description
	if strings.TrimSpace(req.Description) != "" {
		nextDescription = strings.TrimSpace(req.Description)
	}
	nextKMSKeyID := meta.KMSKeyID
	if strings.TrimSpace(req.KMSKeyID) != "" {
		resolved, err := s.ResolveByID(ctx, req.KMSKeyID)
		if err != nil {
			return store.SecretMetadataRecord{}, nil, err
		}
		nextKMSKeyID = resolved.ID
	}
	now := time.Now().UTC()
	var value *store.SecretValueRecord
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	defer tx.Rollback()
	store.EnsureSecretStageMap(&meta)
	if req.SecretString != "" || req.SecretBinary != "" {
		versionID := req.ClientRequestToken
		if versionID == "" {
			versionID = cryptoutil.RandomHex(16)
		}
		if existing, err := s.loadSecretVersionByToken(ctx, meta.Name, versionID); err == nil {
			built, buildErr := store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, existing)
			if buildErr != nil {
				return store.SecretMetadataRecord{}, nil, buildErr
			}
			value = &built
		} else if !errors.Is(err, sql.ErrNoRows) {
			return store.SecretMetadataRecord{}, nil, err
		} else {
			kmsKeyID, encryptedPayloadB64, isBinary, encErr := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, nextKMSKeyID, req.SecretString, req.SecretBinary)
			if encErr != nil {
				return store.SecretMetadataRecord{}, nil, encErr
			}
			const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
			if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
				return store.SecretMetadataRecord{}, nil, mapSecretDBError(err)
			}
			store.PromoteSecretVersion(&meta, versionID)
			nextKMSKeyID = kmsKeyID
			// The freshly written version is sealed under nextKMSKeyID, so the
			// returned value record must decrypt with that key. Update meta's
			// key before building the record to avoid decrypting the new
			// ciphertext with the previous master key (AEAD auth failure).
			meta.KMSKeyID = nextKMSKeyID
			built, buildErr := store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
			if buildErr != nil {
				return store.SecretMetadataRecord{}, nil, buildErr
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
		return store.SecretMetadataRecord{}, nil, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	meta.Description = nextDescription
	meta.KMSKeyID = nextKMSKeyID
	meta.LastChangedDate = now
	return meta, value, nil
}

func (s *dbStore) DeleteSecret(ctx context.Context, secretID string, recoveryWindowDays int, forceDelete bool) (store.SecretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	// Force delete purges the secret immediately, bypassing the recovery
	// window. This works even when the secret is already scheduled for
	// deletion so operators can fully remove a pending item.
	if forceDelete {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return store.SecretMetadataRecord{}, err
		}
		defer func() { _ = tx.Rollback() }()
		for _, q := range []string{
			`DELETE FROM sm_secret_versions WHERE secret_name = $1`,
			`DELETE FROM sm_secret_tags WHERE secret_name = $1`,
			`DELETE FROM sm_secret_policies WHERE secret_name = $1`,
			`DELETE FROM sm_secrets WHERE name = $1`,
		} {
			if _, err := tx.ExecContext(ctx, q, meta.Name); err != nil {
				return store.SecretMetadataRecord{}, err
			}
		}
		if err := tx.Commit(); err != nil {
			return store.SecretMetadataRecord{}, err
		}
		now := time.Now().UTC()
		meta.DeletedDate = &now
		meta.LastChangedDate = now
		return meta, nil
	}
	if meta.DeletedDate != nil {
		return meta, nil
	}
	deletionDate, err := store.NormalizeSecretDeletion(forceDelete, recoveryWindowDays)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	const q = `UPDATE sm_secrets SET deleted_date = $2, updated_at = NOW() WHERE name = $1`
	if _, err := s.db.ExecContext(ctx, q, meta.Name, deletionDate); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	meta.DeletedDate = &deletionDate
	meta.LastChangedDate = time.Now().UTC()
	return meta, nil
}

func (s *dbStore) RestoreSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	const q = `UPDATE sm_secrets SET deleted_date = NULL, updated_at = NOW() WHERE name = $1`
	if _, err := s.db.ExecContext(ctx, q, meta.Name); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	meta.DeletedDate = nil
	meta.LastChangedDate = time.Now().UTC()
	return meta, nil
}

func (s *dbStore) ListSecrets(ctx context.Context) ([]store.SecretMetadataRecord, error) {
	q := `
SELECT name, arn, description, kms_key_id, current_version_id, previous_version_id, rotation_enabled, rotation_lambda_arn, rotation_days, next_rotation_date, deleted_date, created_at, updated_at
FROM sm_secrets`
	cond, args := store.AccountFilter(ctx, "account_id", 1)
	if cond != "" {
		q += "\nWHERE " + cond
	}
	q += "\nORDER BY created_at ASC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.SecretMetadataRecord, 0)
	for rows.Next() {
		var (
			item        store.SecretMetadataRecord
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
		item.VersionStages = store.BuildFallbackSecretStageMap(item.CurrentVersionID, item.PreviousVersionID)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *dbStore) loadSecretMetadata(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	q := `
SELECT name, arn, description, kms_key_id, current_version_id, previous_version_id, rotation_enabled, rotation_lambda_arn, rotation_days, next_rotation_date, deleted_date, created_at, updated_at
FROM sm_secrets
WHERE (name = $1 OR arn = $1)`
	args := []any{strings.TrimSpace(secretID)}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	q += "\nLIMIT 1"
	var (
		item        store.SecretMetadataRecord
		nextRotate  sql.NullTime
		deletedDate sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&item.Name, &item.ARN, &item.Description, &item.KMSKeyID, &item.CurrentVersionID, &item.PreviousVersionID, &item.RotationEnabled, &item.RotationLambdaARN, &item.RotationDays, &nextRotate, &deletedDate, &item.CreatedAt, &item.LastChangedDate)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if nextRotate.Valid {
		item.NextRotationDate = &nextRotate.Time
	}
	if deletedDate.Valid {
		item.DeletedDate = &deletedDate.Time
	}
	item.VersionStages = store.BuildFallbackSecretStageMap(item.CurrentVersionID, item.PreviousVersionID)
	if err := s.loadSecretDecorations(ctx, &item); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return item, nil
}

func (s *dbStore) loadSecretVersion(ctx context.Context, secretName, versionID string) (store.SecretVersionRow, error) {
	const q = `
SELECT version_id, encrypted_payload_b64, is_binary, version_created_at
FROM sm_secret_versions
WHERE secret_name = $1 AND version_id = $2
`
	var row store.SecretVersionRow
	err := s.db.QueryRowContext(ctx, q, secretName, versionID).Scan(&row.VersionID, &row.EncryptedPayloadB64, &row.IsBinary, &row.CreatedAt)
	return row, err
}

func (s *dbStore) loadSecretVersionByToken(ctx context.Context, secretName, token string) (store.SecretVersionRow, error) {
	const q = `
SELECT version_id, encrypted_payload_b64, is_binary, version_created_at
FROM sm_secret_versions
WHERE secret_name = $1 AND client_request_token = $2
`
	var row store.SecretVersionRow
	err := s.db.QueryRowContext(ctx, q, secretName, token).Scan(&row.VersionID, &row.EncryptedPayloadB64, &row.IsBinary, &row.CreatedAt)
	return row, err
}

func (s *inMemoryStore) CreateSecret(ctx context.Context, req store.CreateSecretRequest) (store.SecretMetadataRecord, store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secrets == nil {
		s.secrets = map[string]*inMemorySecret{}
	}
	account := s.accountForContext(ctx)
	name := strings.TrimSpace(req.Name)
	if _, ok := s.secrets[memSecretKey(account, name)]; ok {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, store.ErrSecretExists
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = cryptoutil.RandomHex(16)
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, req.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	meta := store.SecretMetadataRecord{
		ARN:               s.SecretARNForCtx(ctx, name),
		Name:              name,
		Description:       strings.TrimSpace(req.Description),
		KMSKeyID:          kmsKeyID,
		CurrentVersionID:  versionID,
		PreviousVersionID: "",
		VersionStages:     map[string][]string{versionID: {store.CurrentVersionStage}},
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
	value, err := store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	return meta, value, nil
}

func (s *inMemoryStore) DescribeSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return secret.metadata, nil
}

func (s *inMemoryStore) GetSecretValue(ctx context.Context, secretID, versionID, versionStage string) (store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getSecretValueLocked(ctx, secretID, versionID, versionStage)
}

// getSecretValueLocked implements GetSecretValue. The caller must hold s.mu.
func (s *inMemoryStore) getSecretValueLocked(ctx context.Context, secretID, versionID, versionStage string) (store.SecretValueRecord, error) {
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if secret.metadata.DeletedDate != nil {
		return store.SecretValueRecord{}, store.ErrSecretPendingDeletion
	}
	resolvedVersionID, err := store.ResolveSecretVersionID(secret.metadata, versionID, versionStage)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	version, ok := secret.versions[resolvedVersionID]
	if !ok {
		return store.SecretValueRecord{}, sql.ErrNoRows
	}
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, store.SecretVersionRow{VersionID: version.VersionID, EncryptedPayloadB64: version.EncryptedPayloadB64, IsBinary: version.IsBinary, CreatedAt: version.CreatedAt})
}

func (s *inMemoryStore) PutSecretValue(ctx context.Context, req store.PutSecretValueRequest) (store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putSecretValueLocked(ctx, req)
}

// putSecretValueLocked implements PutSecretValue. The caller must hold s.mu.
func (s *inMemoryStore) putSecretValueLocked(ctx context.Context, req store.PutSecretValueRequest) (store.SecretValueRecord, error) {
	secret, err := s.findSecret(ctx, req.SecretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if secret.metadata.DeletedDate != nil {
		return store.SecretValueRecord{}, store.ErrSecretPendingDeletion
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = cryptoutil.RandomHex(16)
	}
	if existingVersionID, ok := secret.byToken[versionID]; ok {
		version := secret.versions[existingVersionID]
		return store.BuildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, store.SecretVersionRow{VersionID: version.VersionID, EncryptedPayloadB64: version.EncryptedPayloadB64, IsBinary: version.IsBinary, CreatedAt: version.CreatedAt})
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, secret.metadata.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	secret.metadata.KMSKeyID = kmsKeyID
	store.PromoteSecretVersion(&secret.metadata, versionID)
	secret.metadata.LastChangedDate = now
	secret.byToken[versionID] = versionID
	secret.versions[versionID] = inMemorySecretVersion{VersionID: versionID, ClientRequestToken: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now}
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
}

func (s *inMemoryStore) UpdateSecret(ctx context.Context, req store.UpdateSecretRequest) (store.SecretMetadataRecord, *store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, req.SecretID)
	if err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	if secret.metadata.DeletedDate != nil {
		return store.SecretMetadataRecord{}, nil, store.ErrSecretPendingDeletion
	}
	if strings.TrimSpace(req.Description) != "" {
		secret.metadata.Description = strings.TrimSpace(req.Description)
	}
	if strings.TrimSpace(req.KMSKeyID) != "" {
		resolved, err := s.ResolveByID(ctx, req.KMSKeyID)
		if err != nil {
			return store.SecretMetadataRecord{}, nil, err
		}
		secret.metadata.KMSKeyID = resolved.ID
	}
	secret.metadata.LastChangedDate = time.Now().UTC()
	store.EnsureSecretStageMap(&secret.metadata)
	var value *store.SecretValueRecord
	if req.SecretString != "" || req.SecretBinary != "" {
		putValue, err := s.putSecretValueLocked(ctx, store.PutSecretValueRequest{SecretID: secret.metadata.Name, ClientRequestToken: req.ClientRequestToken, SecretString: req.SecretString, SecretBinary: req.SecretBinary})
		if err != nil {
			return store.SecretMetadataRecord{}, nil, err
		}
		value = &putValue
	}
	return secret.metadata, value, nil
}

func (s *inMemoryStore) DeleteSecret(ctx context.Context, secretID string, recoveryWindowDays int, forceDelete bool) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	// Force delete purges the secret immediately, even when it is already
	// scheduled for deletion.
	if forceDelete {
		delete(s.secrets, memSecretKey(secret.account, secret.metadata.Name))
		now := time.Now().UTC()
		secret.metadata.DeletedDate = &now
		secret.metadata.LastChangedDate = now
		return secret.metadata, nil
	}
	deletionDate, err := store.NormalizeSecretDeletion(forceDelete, recoveryWindowDays)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	secret.metadata.DeletedDate = &deletionDate
	secret.metadata.LastChangedDate = time.Now().UTC()
	return secret.metadata, nil
}

func (s *inMemoryStore) RestoreSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	secret.metadata.DeletedDate = nil
	secret.metadata.LastChangedDate = time.Now().UTC()
	return secret.metadata, nil
}

func (s *inMemoryStore) ListSecrets(ctx context.Context) ([]store.SecretMetadataRecord, error) {
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
	out := make([]store.SecretMetadataRecord, 0, len(keys))
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
	switch typ {
	case "AccessDeniedException", "ResourceExistsException", "ResourceNotFoundException", "InvalidRequestException", "InvalidParameterException":
		status = http.StatusBadRequest
	}
	writeAWSJSONError(w, status, typ, err.Error())
}

func (s *server) authorizeSecretAction(ctx context.Context, r *http.Request, meta store.SecretMetadataRecord, action string) error {
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

func mapSecretDBError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "duplicate key value") {
		return store.ErrSecretExists
	}
	return err
}
