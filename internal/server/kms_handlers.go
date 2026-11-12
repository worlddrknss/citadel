package server

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

type encryptRequest struct {
	KeyID             string            `json:"KeyId"`
	Plaintext         string            `json:"Plaintext"`
	EncryptionContext map[string]string `json:"EncryptionContext"`
}

type encryptResponse struct {
	CiphertextBlob    string            `json:"CiphertextBlob"`
	KeyID             string            `json:"KeyId"`
	EncryptionContext map[string]string `json:"EncryptionContext,omitempty"`
}

type decryptRequest struct {
	CiphertextBlob    string            `json:"CiphertextBlob"`
	EncryptionContext map[string]string `json:"EncryptionContext"`
}

type decryptResponse struct {
	KeyID             string            `json:"KeyId"`
	Plaintext         string            `json:"Plaintext"`
	EncryptionContext map[string]string `json:"EncryptionContext,omitempty"`
}

type describeKeyRequest struct {
	KeyID string `json:"KeyId"`
}

type describeKeyResponse struct {
	KeyMetadata keyMetadata `json:"KeyMetadata"`
}

type createKeyRequest struct {
	Description string `json:"Description"`
	KeyUsage    string `json:"KeyUsage"`
	KeySpec     string `json:"KeySpec"`
}

type createKeyResponse struct {
	KeyMetadata keyMetadata `json:"KeyMetadata"`
}

type signRequest struct {
	KeyID            string `json:"KeyId"`
	Message          string `json:"Message"`
	MessageType      string `json:"MessageType"`
	SigningAlgorithm string `json:"SigningAlgorithm"`
}

type signResponse struct {
	KeyID            string `json:"KeyId"`
	Signature        string `json:"Signature"`
	SigningAlgorithm string `json:"SigningAlgorithm,omitempty"`
}

type verifyRequest struct {
	KeyID            string `json:"KeyId"`
	Message          string `json:"Message"`
	MessageType      string `json:"MessageType"`
	Signature        string `json:"Signature"`
	SigningAlgorithm string `json:"SigningAlgorithm"`
}

type verifyResponse struct {
	KeyID            string `json:"KeyId"`
	SignatureValid   bool   `json:"SignatureValid"`
	SigningAlgorithm string `json:"SigningAlgorithm,omitempty"`
}

type getPublicKeyRequest struct {
	KeyID string `json:"KeyId"`
}

type getPublicKeyResponse struct {
	KeyID             string   `json:"KeyId"`
	PublicKey         string   `json:"PublicKey"`
	SigningAlgorithms []string `json:"SigningAlgorithms,omitempty"`
	KeySpec           string   `json:"KeySpec,omitempty"`
}

type listKeysResponse struct {
	Keys       []listKeyEntry `json:"Keys"`
	NextMarker string         `json:"NextMarker,omitempty"`
	Truncated  bool           `json:"Truncated"`
}

type listKeysRequest struct {
	Limit  int    `json:"Limit"`
	Marker string `json:"Marker"`
}

type listKeyEntry struct {
	KeyID  string `json:"KeyId"`
	KeyARN string `json:"KeyArn"`
}

type createAliasRequest struct {
	AliasName   string `json:"AliasName"`
	TargetKeyID string `json:"TargetKeyId"`
}

type updateAliasRequest struct {
	AliasName   string `json:"AliasName"`
	TargetKeyID string `json:"TargetKeyId"`
}

type listAliasesResponse struct {
	Aliases    []aliasEntry `json:"Aliases"`
	NextMarker string       `json:"NextMarker,omitempty"`
	Truncated  bool         `json:"Truncated"`
}

type listAliasesRequest struct {
	Limit  int    `json:"Limit"`
	Marker string `json:"Marker"`
}

type aliasEntry struct {
	AliasName   string `json:"AliasName"`
	TargetKeyID string `json:"TargetKeyId"`
}

type keyIDRequest struct {
	KeyID string `json:"KeyId"`
}

type scheduleKeyDeletionRequest struct {
	KeyID               string `json:"KeyId"`
	PendingWindowInDays int    `json:"PendingWindowInDays"`
}

type scheduleKeyDeletionResponse struct {
	KeyID        string    `json:"KeyId"`
	DeletionDate time.Time `json:"DeletionDate"`
}

type createGrantResponse struct {
	GrantID    string `json:"GrantId"`
	GrantToken string `json:"GrantToken"`
}

type listGrantsRequest struct {
	KeyID string `json:"KeyId"`
}

type listGrantsResponse struct {
	Grants []grantListEntry `json:"Grants"`
}

type grantListEntry struct {
	GrantID           string    `json:"GrantId"`
	KeyID             string    `json:"KeyId"`
	GranteePrincipal  string    `json:"GranteePrincipal"`
	RetiringPrincipal string    `json:"RetiringPrincipal,omitempty"`
	Operations        []string  `json:"Operations"`
	Name              string    `json:"Name,omitempty"`
	CreationDate      time.Time `json:"CreationDate"`
}

type revokeGrantRequest struct {
	KeyID   string `json:"KeyId"`
	GrantID string `json:"GrantId"`
}

type retireGrantRequest struct {
	GrantID    string `json:"GrantId"`
	GrantToken string `json:"GrantToken"`
}

type getKeyPolicyRequest struct {
	KeyID      string `json:"KeyId"`
	PolicyName string `json:"PolicyName"`
}

type getKeyPolicyResponse struct {
	Policy string `json:"Policy"`
}

type putKeyPolicyRequest struct {
	KeyID      string `json:"KeyId"`
	PolicyName string `json:"PolicyName"`
	Policy     string `json:"Policy"`
}

type keyMetadata struct {
	AWSAccountID                string    `json:"AWSAccountId"`
	KeyID                       string    `json:"KeyId"`
	Arn                         string    `json:"Arn"`
	CreationDate                time.Time `json:"CreationDate"`
	Enabled                     bool      `json:"Enabled"`
	Description                 string    `json:"Description"`
	KeyUsage                    string    `json:"KeyUsage"`
	KeyState                    string    `json:"KeyState"`
	Origin                      string    `json:"Origin"`
	KeyManager                  string    `json:"KeyManager"`
	CustomerMasterKeySpec       string    `json:"CustomerMasterKeySpec"`
	KeySpec                     string    `json:"KeySpec"`
	EncryptionAlgorithms        []string  `json:"EncryptionAlgorithms"`
	MultiRegion                 bool      `json:"MultiRegion"`
	SigningAlgorithms           []string  `json:"SigningAlgorithms"`
	PendingDeletionWindowInDays int       `json:"PendingDeletionWindowInDays,omitempty"`
}

func (s *Server) handleKMS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "InvalidAction", "method not allowed")
		return
	}
	// Identity comes only from a verified signature, never from headers.
	r.Header.Del("X-KMS-Username")
	r.Header.Del("X-KMS-Account-ID")
	r, ok := s.authenticateAWSJSON(w, r)
	if !ok {
		return
	}

	target := r.Header.Get("X-Amz-Target")
	if s.servePKITarget(w, r, target) {
		return
	}
	switch target {
	case "TrentService.Encrypt":
		s.handleEncrypt(w, r)
	case "TrentService.Decrypt":
		s.handleDecrypt(w, r)
	case "TrentService.DescribeKey":
		s.handleDescribeKey(w, r)
	case "TrentService.CreateKey":
		s.handleCreateKey(w, r)
	case "TrentService.ListKeys":
		s.handleListKeys(w, r)
	case "TrentService.CreateAlias":
		s.handleCreateAlias(w, r)
	case "TrentService.UpdateAlias":
		s.handleUpdateAlias(w, r)
	case "TrentService.ListAliases":
		s.handleListAliases(w, r)
	case "TrentService.EnableKey":
		s.handleSetKeyEnabled(w, r, true)
	case "TrentService.DisableKey":
		s.handleSetKeyEnabled(w, r, false)
	case "TrentService.ScheduleKeyDeletion":
		s.handleScheduleKeyDeletion(w, r)
	case "TrentService.CancelKeyDeletion":
		s.handleCancelKeyDeletion(w, r)
	case "TrentService.CreateGrant":
		s.handleCreateGrant(w, r)
	case "TrentService.ListGrants":
		s.handleListGrants(w, r)
	case "TrentService.RevokeGrant":
		s.handleRevokeGrant(w, r)
	case "TrentService.RetireGrant":
		s.handleRetireGrant(w, r)
	case "TrentService.GetKeyPolicy":
		s.handleGetKeyPolicy(w, r)
	case "TrentService.PutKeyPolicy":
		s.handlePutKeyPolicy(w, r)
	case "TrentService.Sign":
		s.handleSign(w, r)
	case "TrentService.Verify":
		s.handleVerify(w, r)
	case "TrentService.GetPublicKey":
		s.handleGetPublicKey(w, r)
	case "secretsmanager.CreateSecret":
		s.handleCreateSecret(w, r)
	case "secretsmanager.DescribeSecret":
		s.handleDescribeSecret(w, r)
	case "secretsmanager.GetSecretValue":
		s.handleGetSecretValue(w, r)
	case "secretsmanager.PutSecretValue":
		s.handlePutSecretValue(w, r)
	case "secretsmanager.UpdateSecret":
		s.handleUpdateSecret(w, r)
	case "secretsmanager.DeleteSecret":
		s.handleDeleteSecret(w, r)
	case "secretsmanager.RestoreSecret":
		s.handleRestoreSecret(w, r)
	case "secretsmanager.ListSecrets":
		s.handleListSecrets(w, r)
	case "secretsmanager.ListSecretVersionIds":
		s.handleListSecretVersionIDs(w, r)
	case "secretsmanager.TagResource":
		s.handleTagSecret(w, r)
	case "secretsmanager.UntagResource":
		s.handleUntagSecret(w, r)
	case "secretsmanager.GetResourcePolicy":
		s.handleGetSecretResourcePolicy(w, r)
	case "secretsmanager.PutResourcePolicy":
		s.handlePutSecretResourcePolicy(w, r)
	case "secretsmanager.ValidateResourcePolicy":
		s.handleValidateSecretResourcePolicy(w, r)
	case "secretsmanager.RotateSecret":
		s.handleRotateSecret(w, r)
	case "secretsmanager.CancelRotateSecret":
		s.handleCancelRotateSecret(w, r)
	case "secretsmanager.UpdateSecretVersionStage":
		s.handleUpdateSecretVersionStage(w, r)
	case "AmazonSSM.PutParameter":
		s.handleSSMPutParameter(w, r)
	case "AmazonSSM.GetParameter":
		s.handleSSMGetParameter(w, r)
	case "AmazonSSM.GetParameters":
		s.handleSSMGetParameters(w, r)
	case "AmazonSSM.GetParametersByPath":
		s.handleSSMGetParametersByPath(w, r)
	case "AmazonSSM.DeleteParameter":
		s.handleSSMDeleteParameter(w, r)
	case "AmazonSSM.DeleteParameters":
		s.handleSSMDeleteParameters(w, r)
	case "AmazonSSM.DescribeParameters":
		s.handleSSMDescribeParameters(w, r)
	case "AmazonSSM.GetParameterHistory":
		s.handleSSMGetParameterHistory(w, r)
	case "AmazonSSM.LabelParameterVersion":
		s.handleSSMLabelParameterVersion(w, r)
	case "AmazonSSM.AddTagsToResource":
		s.handleSSMAddTagsToResource(w, r)
	case "AmazonSSM.RemoveTagsFromResource":
		s.handleSSMRemoveTagsFromResource(w, r)
	case "AmazonSSM.ListTagsForResource":
		s.handleSSMListTagsForResource(w, r)
	default:
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidAction", "unsupported X-Amz-Target")
	}
}

func (s *Server) handleGetKeyPolicy(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.GetKeyPolicy"
	var req getKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "default"
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key or policy not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:GetKeyPolicy"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	doc, err := s.store.GetKeyPolicy(r.Context(), req.KeyID, req.PolicyName)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key or policy not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, getKeyPolicyResponse{Policy: doc})
}

func (s *Server) handlePutKeyPolicy(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.PutKeyPolicy"
	var req putKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "default"
	}
	if strings.TrimSpace(req.Policy) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Policy is required")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	normalizedPolicy, err := normalizePolicyDocument(req.Policy)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "MalformedPolicyDocumentException", "Policy must be valid JSON")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "MalformedPolicyDocumentException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:PutKeyPolicy"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.store.PutKeyPolicy(r.Context(), req.KeyID, req.PolicyName, normalizedPolicy); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Encrypt"
	var req encryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.Plaintext == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext is required")
		return
	}

	var (
		key store.KMSKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
			writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
			return
		}
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "DependencyTimeoutException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "key lookup failed")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != store.KeyUsageEncryptDecrypt {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support encryption")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != store.KeyUsageEncryptDecrypt {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support decryption")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:Encrypt"); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext must be base64")
		return
	}

	cipherBlob, err := cryptoutil.EncryptBlob(key.MasterKeyRaw, key.ID, plaintext, cryptoutil.CanonicalContext(req.EncryptionContext))
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "encrypt failed")
		return
	}

	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})

	writeJSON(w, http.StatusOK, encryptResponse{
		CiphertextBlob:    base64.StdEncoding.EncodeToString(cipherBlob),
		KeyID:             key.ID,
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Decrypt"
	var req decryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.CiphertextBlob == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob is required")
		return
	}

	cipherBlob, err := base64.StdEncoding.DecodeString(req.CiphertextBlob)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob must be base64")
		return
	}

	keyID, rawBlob, err := cryptoutil.DecodeCipherBlob(cipherBlob)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidCiphertextException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	var key store.KMSKey
	if keyID == "" {
		key, err = s.store.ResolveDefault(r.Context())
	} else {
		key, err = s.store.ResolveByID(r.Context(), keyID)
	}
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: "InvalidCiphertextException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:Decrypt"); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	plaintext, err := cryptoutil.DecryptBlob(key.MasterKeyRaw, rawBlob, cryptoutil.CanonicalContext(req.EncryptionContext))
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidCiphertextException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})

	writeJSON(w, http.StatusOK, decryptResponse{
		KeyID:             key.ID,
		Plaintext:         base64.StdEncoding.EncodeToString(plaintext),
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *Server) handleDescribeKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.DescribeKey"
	var req describeKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	var (
		key store.KMSKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:DescribeKey"); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})

	writeJSON(w, http.StatusOK, describeKeyResponse{
		KeyMetadata: toKeyMetadata(key),
	})
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateKey"
	var req createKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	key, err := s.store.CreateKey(r.Context(), req.Description, req.KeyUsage, req.KeySpec)
	if err != nil {
		errType := "DependencyTimeoutException"
		if errors.Is(err, store.ErrUnsupported) {
			errType = "UnsupportedOperationException"
			writeAWSJSONError(w, http.StatusBadRequest, errType, "CreateKey requires KMS_DB_URL")
		} else {
			writeAWSJSONError(w, http.StatusInternalServerError, errType, "create key failed")
		}
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, createKeyResponse{KeyMetadata: toKeyMetadata(key)})
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListKeys"
	var req listKeysRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	keys, err := s.store.ListKeys(r.Context())
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list keys failed")
		return
	}
	out := make([]listKeyEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, listKeyEntry{KeyID: k.ID, KeyARN: k.ARN})
	}
	out, nextMarker, truncated, err := paginateList(out, req.Marker, limit, func(item listKeyEntry) string { return item.KeyID })
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, listKeysResponse{Keys: out, NextMarker: nextMarker, Truncated: truncated})
}

func (s *Server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateAlias"
	var req createAliasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.AliasName == "" || req.TargetKeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "AliasName and TargetKeyId are required")
		return
	}
	if req.AliasName == store.ManagedDefaultAlias {
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "alias/default is reserved for the account's managed default key")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "UnsupportedOperationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.TargetKeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "target key not found or alias exists")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CreateAlias"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.store.CreateAlias(r.Context(), req.AliasName, req.TargetKeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "target key not found or alias exists")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleUpdateAlias(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.UpdateAlias"
	var req updateAliasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.AliasName == "" || req.TargetKeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "AliasName and TargetKeyId are required")
		return
	}
	if req.AliasName == store.ManagedDefaultAlias {
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "alias/default is immutable and cannot be re-pointed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "UnsupportedOperationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.TargetKeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "alias or key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:UpdateAlias"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.store.UpdateAlias(r.Context(), req.AliasName, req.TargetKeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "alias or key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListAliases"
	var req listAliasesRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	aliases, err := s.store.ListAliases(r.Context())
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list aliases failed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	out := make([]aliasEntry, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, aliasEntry{AliasName: a.AliasName, TargetKeyID: a.TargetKeyID})
	}
	out, nextMarker, truncated, err := paginateList(out, req.Marker, limit, func(item aliasEntry) string { return item.AliasName })
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, listAliasesResponse{Aliases: out, NextMarker: nextMarker, Truncated: truncated})
}

func (s *Server) handleSetKeyEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	action := "TrentService.DisableKey"
	if enabled {
		action = "TrentService.EnableKey"
	}
	var req keyIDRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	policyAction := "kms:DisableKey"
	if enabled {
		policyAction = "kms:EnableKey"
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, policyAction); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if !enabled && key.Managed {
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "the account default key cannot be disabled")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "UnsupportedOperationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.store.SetKeyEnabled(r.Context(), req.KeyID, enabled); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleScheduleKeyDeletion(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ScheduleKeyDeletion"
	var req scheduleKeyDeletionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		return
	}
	if req.PendingWindowInDays == 0 {
		req.PendingWindowInDays = 30
	}
	if req.PendingWindowInDays < 7 || req.PendingWindowInDays > 30 {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "PendingWindowInDays must be between 7 and 30")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:ScheduleKeyDeletion"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if key.Managed {
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "the account default key cannot be scheduled for deletion")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "UnsupportedOperationException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	deletionDate, err := s.store.ScheduleKeyDeletion(r.Context(), req.KeyID, req.PendingWindowInDays)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, scheduleKeyDeletionResponse{KeyID: req.KeyID, DeletionDate: deletionDate})
}

func (s *Server) handleCancelKeyDeletion(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CancelKeyDeletion"
	var req keyIDRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CancelKeyDeletion"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.store.CancelKeyDeletion(r.Context(), req.KeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "reload key failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"KeyMetadata": toKeyMetadata(key)})
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateGrant"
	var req store.CreateGrantRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" || strings.TrimSpace(req.GranteePrincipal) == "" || len(req.Operations) == 0 {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId, GranteePrincipal, and Operations are required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CreateGrant"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	grant, err := s.store.CreateGrant(r.Context(), req)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "create grant failed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, createGrantResponse{GrantID: grant.GrantID, GrantToken: grant.GrantToken})
}

func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListGrants"
	var req listGrantsRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:ListGrants"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	grants, err := s.store.ListGrants(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list grants failed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	out := make([]grantListEntry, 0, len(grants))
	for _, grant := range grants {
		out = append(out, grantListEntry{GrantID: grant.GrantID, KeyID: grant.KeyID, GranteePrincipal: grant.GranteePrincipal, RetiringPrincipal: grant.RetiringPrincipal, Operations: append([]string(nil), grant.Operations...), Name: grant.Name, CreationDate: grant.CreatedAt})
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, listGrantsResponse{Grants: out})
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.RevokeGrant"
	var req revokeGrantRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" || strings.TrimSpace(req.GrantID) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId and GrantId are required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:RevokeGrant"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.store.RevokeGrant(r.Context(), req.KeyID, req.GrantID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "grant not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleRetireGrant(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.RetireGrant"
	var req retireGrantRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if strings.TrimSpace(req.GrantID) == "" && strings.TrimSpace(req.GrantToken) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "GrantId or GrantToken is required")
		return
	}
	if err := s.store.RetireGrant(r.Context(), req.GrantID, req.GrantToken); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "grant not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func keyState(key store.KMSKey) string {
	if key.DeletionDate != nil {
		return "PendingDeletion"
	}
	if key.Enabled {
		return "Enabled"
	}
	return "Disabled"
}

func toKeyMetadata(key store.KMSKey) keyMetadata {
	keyUsage, keySpec := keyUsageAndSpecForMetadata(key)
	return keyMetadata{
		AWSAccountID:                "000000000000",
		KeyID:                       key.ID,
		Arn:                         key.ARN,
		CreationDate:                key.CreatedAt,
		Enabled:                     key.Enabled,
		Description:                 key.Description,
		KeyUsage:                    keyUsage,
		KeyState:                    keyState(key),
		Origin:                      "AWS_KMS",
		KeyManager:                  "CUSTOMER",
		CustomerMasterKeySpec:       keySpec,
		KeySpec:                     keySpec,
		EncryptionAlgorithms:        keyEncryptionAlgorithms(key),
		SigningAlgorithms:           keySigningAlgorithms(key),
		MultiRegion:                 false,
		PendingDeletionWindowInDays: pendingDeletionDays(key.DeletionDate),
	}
}

func keyEncryptionAlgorithms(key store.KMSKey) []string {
	usage, _ := keyUsageAndSpecForMetadata(key)
	if usage != store.KeyUsageEncryptDecrypt {
		return nil
	}
	return []string{store.KeySpecSymmetricDefault}
}

func pendingDeletionDays(deletionDate *time.Time) int {
	if deletionDate == nil {
		return 0
	}
	days := int(time.Until(*deletionDate).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}
