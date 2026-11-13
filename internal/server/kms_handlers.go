package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

type encryptRequest struct {
	KeyID               string            `json:"KeyId"`
	Plaintext           string            `json:"Plaintext"`
	EncryptionContext   map[string]string `json:"EncryptionContext"`
	EncryptionAlgorithm string            `json:"EncryptionAlgorithm"`
	GrantTokens         []string          `json:"GrantTokens"`
	DryRun              bool              `json:"DryRun"`
}

type encryptResponse struct {
	CiphertextBlob      string `json:"CiphertextBlob"`
	KeyID               string `json:"KeyId"`
	EncryptionAlgorithm string `json:"EncryptionAlgorithm"`
}

type decryptRequest struct {
	CiphertextBlob      string            `json:"CiphertextBlob"`
	EncryptionContext   map[string]string `json:"EncryptionContext"`
	KeyID               string            `json:"KeyId"`
	EncryptionAlgorithm string            `json:"EncryptionAlgorithm"`
	GrantTokens         []string          `json:"GrantTokens"`
	DryRun              bool              `json:"DryRun"`
	Recipient           json.RawMessage   `json:"Recipient"`
}

type decryptResponse struct {
	KeyID               string `json:"KeyId"`
	Plaintext           string `json:"Plaintext"`
	EncryptionAlgorithm string `json:"EncryptionAlgorithm"`
}

type describeKeyRequest struct {
	KeyID       string   `json:"KeyId"`
	GrantTokens []string `json:"GrantTokens"`
}

type describeKeyResponse struct {
	KeyMetadata keyMetadata `json:"KeyMetadata"`
}

type createKeyRequest struct {
	Description                    string          `json:"Description"`
	KeyUsage                       string          `json:"KeyUsage"`
	KeySpec                        string          `json:"KeySpec"`
	CustomerMasterKeySpec          string          `json:"CustomerMasterKeySpec"`
	Policy                         string          `json:"Policy"`
	Origin                         string          `json:"Origin"`
	MultiRegion                    bool            `json:"MultiRegion"`
	CustomKeyStoreID               string          `json:"CustomKeyStoreId"`
	XksKeyID                       string          `json:"XksKeyId"`
	BypassPolicyLockoutSafetyCheck bool            `json:"BypassPolicyLockoutSafetyCheck"`
	Tags                           json.RawMessage `json:"Tags"`
}

type createKeyResponse struct {
	KeyMetadata keyMetadata `json:"KeyMetadata"`
}

type signRequest struct {
	KeyID            string   `json:"KeyId"`
	Message          string   `json:"Message"`
	MessageType      string   `json:"MessageType"`
	SigningAlgorithm string   `json:"SigningAlgorithm"`
	GrantTokens      []string `json:"GrantTokens"`
	DryRun           bool     `json:"DryRun"`
}

type signResponse struct {
	KeyID            string `json:"KeyId"`
	Signature        string `json:"Signature"`
	SigningAlgorithm string `json:"SigningAlgorithm,omitempty"`
}

type verifyRequest struct {
	KeyID            string   `json:"KeyId"`
	Message          string   `json:"Message"`
	MessageType      string   `json:"MessageType"`
	Signature        string   `json:"Signature"`
	SigningAlgorithm string   `json:"SigningAlgorithm"`
	GrantTokens      []string `json:"GrantTokens"`
	DryRun           bool     `json:"DryRun"`
}

type verifyResponse struct {
	KeyID            string `json:"KeyId"`
	SignatureValid   bool   `json:"SignatureValid"`
	SigningAlgorithm string `json:"SigningAlgorithm,omitempty"`
}

type getPublicKeyRequest struct {
	KeyID       string   `json:"KeyId"`
	GrantTokens []string `json:"GrantTokens"`
}

type getPublicKeyResponse struct {
	KeyID                string   `json:"KeyId"`
	PublicKey            string   `json:"PublicKey"`
	SigningAlgorithms    []string `json:"SigningAlgorithms,omitempty"`
	EncryptionAlgorithms []string `json:"EncryptionAlgorithms,omitempty"`
	KeySpec              string   `json:"KeySpec,omitempty"`
	KeyUsage             string   `json:"KeyUsage,omitempty"`
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

type deleteAliasRequest struct {
	AliasName string `json:"AliasName"`
}

type listAliasesResponse struct {
	Aliases    []aliasEntry `json:"Aliases"`
	NextMarker string       `json:"NextMarker,omitempty"`
	Truncated  bool         `json:"Truncated"`
}

type listAliasesRequest struct {
	KeyID  string `json:"KeyId"`
	Limit  int    `json:"Limit"`
	Marker string `json:"Marker"`
}

type aliasEntry struct {
	AliasName   string `json:"AliasName"`
	AliasArn    string `json:"AliasArn,omitempty"`
	TargetKeyID string `json:"TargetKeyId,omitempty"`
}

type keyIDRequest struct {
	KeyID string `json:"KeyId"`
}

type scheduleKeyDeletionRequest struct {
	KeyID               string `json:"KeyId"`
	PendingWindowInDays int    `json:"PendingWindowInDays"`
}

type scheduleKeyDeletionResponse struct {
	KeyID               string             `json:"KeyId"`
	DeletionDate        store.AWSTimestamp `json:"DeletionDate"`
	KeyState            string             `json:"KeyState"`
	PendingWindowInDays int                `json:"PendingWindowInDays"`
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
	GrantID           string             `json:"GrantId"`
	KeyID             string             `json:"KeyId"`
	GranteePrincipal  string             `json:"GranteePrincipal"`
	RetiringPrincipal string             `json:"RetiringPrincipal,omitempty"`
	Operations        []string           `json:"Operations"`
	Name              string             `json:"Name,omitempty"`
	CreationDate      store.AWSTimestamp `json:"CreationDate"`
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
	Policy     string `json:"Policy"`
	PolicyName string `json:"PolicyName,omitempty"`
}

type putKeyPolicyRequest struct {
	KeyID                          string `json:"KeyId"`
	PolicyName                     string `json:"PolicyName"`
	Policy                         string `json:"Policy"`
	BypassPolicyLockoutSafetyCheck bool   `json:"BypassPolicyLockoutSafetyCheck"`
}

// keyMetadata is the KMS KeyMetadata structure. Timestamps are AWS JSON
// epoch-seconds numbers; SDKs reject RFC 3339 strings.
type keyMetadata struct {
	AWSAccountID                string              `json:"AWSAccountId"`
	KeyID                       string              `json:"KeyId"`
	Arn                         string              `json:"Arn"`
	CreationDate                store.AWSTimestamp  `json:"CreationDate"`
	DeletionDate                *store.AWSTimestamp `json:"DeletionDate,omitempty"`
	Enabled                     bool                `json:"Enabled"`
	Description                 string              `json:"Description"`
	KeyUsage                    string              `json:"KeyUsage"`
	KeyState                    string              `json:"KeyState"`
	Origin                      string              `json:"Origin"`
	KeyManager                  string              `json:"KeyManager"`
	CustomerMasterKeySpec       string              `json:"CustomerMasterKeySpec"`
	KeySpec                     string              `json:"KeySpec"`
	EncryptionAlgorithms        []string            `json:"EncryptionAlgorithms,omitempty"`
	MultiRegion                 bool                `json:"MultiRegion"`
	SigningAlgorithms           []string            `json:"SigningAlgorithms,omitempty"`
	PendingDeletionWindowInDays int                 `json:"PendingDeletionWindowInDays,omitempty"`
}

func (s *Server) handleKMS(w http.ResponseWriter, r *http.Request) {
	w = beginAWSResponse(w, awsServiceFromTarget(r.Header.Get("X-Amz-Target")))
	r = withAWSProtocol(r)
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
	// Write-ahead audit: a state-changing action is recorded as attempted
	// before it runs, or refused (audit_writeahead.go).
	if awsWriteAhead(target) {
		origin := s.auditOrigin(r)
		origin.Resource = resourceFromBody(r)
		if err := s.beginAuditAttempt(r.Context(), store.AuditEvent{Action: target, AuditOrigin: origin}); err != nil {
			writeAWSJSONError(w, http.StatusInternalServerError, "InternalFailure", "the audit log could not be written; nothing was changed")
			return
		}
	}
	if s.servePKITarget(w, r, target) {
		return
	}
	if s.handleAWSCompatTarget(w, r, target) {
		return
	}
	if s.handleKMSLifecycleTarget(w, r, target) {
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

// kmsResolveForAdmin resolves a key for a management action and checks the
// key policy, writing the error and audit event on failure.
func (s *Server) kmsResolveForAdmin(w http.ResponseWriter, r *http.Request, action, keyID, policyAction string) (store.KMSKey, bool) {
	ctx := r.Context()
	if strings.TrimSpace(keyID) == "" {
		s.kmsValidationError(w, r, action, "", "KeyId is required")
		return store.KMSKey{}, false
	}
	key, err := s.resolveKMSKey(ctx, keyID)
	if err != nil {
		typ := writeKMSKeyLookupError(w, err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return store.KMSKey{}, false
	}
	if err := s.authorizeKeyAction(ctx, r, key, policyAction); err != nil {
		typ := "AccessDeniedException"
		if errors.Is(err, errAccessDenied) {
			writeAWSJSONError(w, http.StatusBadRequest, typ, "access denied by key policy")
		} else {
			typ = writeKMSKeyLookupError(w, err)
		}
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return store.KMSKey{}, false
	}
	return key, true
}

func (s *Server) kmsFail(w http.ResponseWriter, r *http.Request, action, keyID, typ, msg string) {
	writeAWSJSONError(w, http.StatusBadRequest, typ, msg)
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
}

func (s *Server) handleGetKeyPolicy(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.GetKeyPolicy"
	var req getKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "default"
	}
	key, ok := s.kmsResolveForAdmin(w, r, action, req.KeyID, "kms:GetKeyPolicy")
	if !ok {
		return
	}
	doc, err := s.store.GetKeyPolicy(r.Context(), key.ID, req.PolicyName)
	if err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, getKeyPolicyResponse{Policy: doc, PolicyName: req.PolicyName})
}

func (s *Server) handlePutKeyPolicy(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.PutKeyPolicy"
	var req putKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "default"
	}
	if strings.TrimSpace(req.Policy) == "" {
		s.kmsValidationError(w, r, action, req.KeyID, "Policy is required")
		return
	}
	normalizedPolicy, err := normalizePolicyDocument(req.Policy)
	if err != nil {
		s.kmsFail(w, r, action, req.KeyID, "MalformedPolicyDocumentException", "Policy must be valid JSON")
		return
	}
	key, ok := s.kmsResolveForAdmin(w, r, action, req.KeyID, "kms:PutKeyPolicy")
	if !ok {
		return
	}
	if err := s.store.PutKeyPolicy(r.Context(), key.ID, req.PolicyName, normalizedPolicy); err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

// maxKMSPlaintext is the AWS limit for Encrypt's Plaintext.
const maxKMSPlaintext = 4096

func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Encrypt"
	var req encryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.Plaintext == "" {
		s.kmsValidationError(w, r, action, req.KeyID, "Plaintext is required")
		return
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		s.kmsValidationError(w, r, action, req.KeyID, "Plaintext must be base64")
		return
	}
	defer clear(plaintext)
	if len(plaintext) == 0 || len(plaintext) > maxKMSPlaintext {
		s.kmsValidationError(w, r, action, req.KeyID, "Plaintext must be between 1 and 4096 bytes")
		return
	}
	// AWS requires KeyId; Citadel keeps its historical fallback to the
	// account's default key when it is omitted.
	key, ok := s.kmsKeyForCrypto(w, r, action, req.KeyID, "kms:Encrypt", true)
	if !ok {
		return
	}
	if _, err := resolveEncryptionAlgorithm(key, req.EncryptionAlgorithm); err != nil {
		var oe *kmsOpError
		errors.As(err, &oe)
		s.kmsFail(w, r, action, key.ID, oe.Type, oe.Message)
		return
	}
	if req.DryRun {
		s.kmsDryRun(w, r, action, key.ID)
		return
	}
	// Symmetric keys seal under their current material version; RSA keys
	// use RSAES-OAEP-SHA-256.
	cipherBlob, alg, err := kmsEncrypt(key, req.EncryptionAlgorithm, plaintext, req.EncryptionContext)
	if err != nil {
		var oe *kmsOpError
		if errors.As(err, &oe) {
			s.kmsFail(w, r, action, key.ID, oe.Type, oe.Message)
			return
		}
		slog.Error("kms encrypt failed", "key_id", key.ID, "err", err)
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "encrypt failed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "KMSInternalException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, encryptResponse{
		CiphertextBlob:      base64.StdEncoding.EncodeToString(cipherBlob),
		KeyID:               kmsKeyARN(key),
		EncryptionAlgorithm: alg,
	})
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Decrypt"
	ctx := r.Context()
	var req decryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.CiphertextBlob == "" {
		s.kmsValidationError(w, r, action, "", "CiphertextBlob is required")
		return
	}
	if len(req.Recipient) > 0 && string(req.Recipient) != "null" {
		s.kmsValidationError(w, r, action, req.KeyID, "Recipient (Nitro Enclaves attestation) is not supported")
		return
	}
	asymmetric := strings.EqualFold(strings.TrimSpace(req.EncryptionAlgorithm), encAlgRSAOAEP256)
	if !asymmetric && !validSymmetricAlgorithm(req.EncryptionAlgorithm) {
		s.kmsFail(w, r, action, req.KeyID, "InvalidKeyUsageException", "EncryptionAlgorithm "+req.EncryptionAlgorithm+" is not valid for this key")
		return
	}
	cipherBlob, err := base64.StdEncoding.DecodeString(req.CiphertextBlob)
	if err != nil {
		s.kmsValidationError(w, r, action, "", "CiphertextBlob must be base64")
		return
	}
	// RSA ciphertext carries no header: AWS requires KeyId to decrypt it.
	if asymmetric && strings.TrimSpace(req.KeyID) == "" {
		s.kmsValidationError(w, r, action, "", "KeyId is required to decrypt with an asymmetric key")
		return
	}
	keyID := ""
	if asymmetric {
		keyID = req.KeyID
	} else {
		keyID, _, _ = cryptoutil.DecodeCipherBlob(cipherBlob)
	}

	var key store.KMSKey
	switch {
	case asymmetric:
		key, err = s.resolveKMSKey(ctx, keyID)
	case keyID == "":
		key, err = s.store.ResolveDefault(ctx)
	default:
		key, err = s.store.ResolveByID(ctx, keyID)
		if isKMSNotFound(err) && strings.TrimSpace(req.KeyID) == "" {
			// A legacy headerless blob whose random nonce happens to look
			// like a header: it was sealed under the default key.
			if def, derr := s.store.ResolveDefault(ctx); derr == nil {
				if _, oerr := def.DecryptBlob(cipherBlob, cryptoutil.CanonicalContext(req.EncryptionContext)); oerr == nil {
					key, err = def, nil
				}
			}
		}
	}
	if err != nil {
		if isKMSNotFound(err) && !asymmetric {
			// The ciphertext names a key this account cannot see.
			s.kmsFail(w, r, action, keyID, "InvalidCiphertextException", "The ciphertext is invalid.")
			return
		}
		typ := writeKMSKeyLookupError(w, err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	if strings.TrimSpace(req.KeyID) != "" {
		named, err := s.resolveKMSKey(ctx, req.KeyID)
		if err != nil {
			typ := writeKMSKeyLookupError(w, err)
			s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
			return
		}
		if named.ID != key.ID {
			s.kmsFail(w, r, action, named.ID, "IncorrectKeyException", "The key ID in the request does not identify the KMS key that encrypted the ciphertext.")
			return
		}
	}
	if usage, _ := keyUsageAndSpecForMetadata(key); usage != store.KeyUsageEncryptDecrypt {
		s.kmsFail(w, r, action, key.ID, "InvalidKeyUsageException", "key does not support decryption")
		return
	}
	if typ, msg := kmsKeyStateError(key); typ != "" {
		s.kmsFail(w, r, action, key.ID, typ, msg)
		return
	}
	if err := s.authorizeKeyAction(ctx, r, key, "kms:Decrypt"); err != nil {
		s.kmsFail(w, r, action, key.ID, "AccessDeniedException", "access denied by key policy")
		return
	}
	if req.DryRun {
		s.kmsDryRun(w, r, action, key.ID)
		return
	}
	// The blob names its material version, so ciphertext sealed before any
	// rotation still opens.
	plaintext, alg, err := kmsDecrypt(key, req.EncryptionAlgorithm, cipherBlob, req.EncryptionContext)
	if err != nil {
		var oe *kmsOpError
		if errors.As(err, &oe) && oe.Type != "InvalidCiphertextException" {
			s.kmsFail(w, r, action, key.ID, oe.Type, oe.Message)
			return
		}
		s.kmsFail(w, r, action, key.ID, "InvalidCiphertextException", "The ciphertext is invalid or the encryption context does not match.")
		return
	}
	defer clear(plaintext)

	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, decryptResponse{
		KeyID:               kmsKeyARN(key),
		Plaintext:           base64.StdEncoding.EncodeToString(plaintext),
		EncryptionAlgorithm: alg,
	})
}

func (s *Server) handleDescribeKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.DescribeKey"
	var req describeKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}

	var (
		key store.KMSKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.resolveKMSKey(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		typ := writeKMSKeyLookupError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:DescribeKey"); err != nil {
		s.kmsFail(w, r, action, key.ID, "AccessDeniedException", "access denied by key policy")
		return
	}

	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, describeKeyResponse{KeyMetadata: toKeyMetadata(key)})
}

// awsKeySpecsUnsupported are valid AWS KMS key specs Citadel does not offer
// (yet) for CreateKey: they get UnsupportedOperationException rather than a
// validation error.
var awsKeySpecsUnsupported = map[string]bool{
	"ECC_NIST_P521": true, "ECC_SECG_P256K1": true, "SM2": true,
	"HMAC_224": true, "HMAC_256": true, "HMAC_384": true, "HMAC_512": true,
	"ML_DSA_44": true, "ML_DSA_65": true, "ML_DSA_87": true,
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateKey"
	var req createKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.KeySpec == "" {
		req.KeySpec = req.CustomerMasterKeySpec
	}
	usage := strings.ToUpper(strings.TrimSpace(req.KeyUsage))
	switch usage {
	case "", store.KeyUsageEncryptDecrypt, store.KeyUsageSignVerify:
	case "GENERATE_VERIFY_MAC", "KEY_AGREEMENT":
		s.kmsFail(w, r, action, "", "UnsupportedOperationException", "KeyUsage "+usage+" is not supported")
		return
	default:
		s.kmsValidationError(w, r, action, "", "KeyUsage must be ENCRYPT_DECRYPT or SIGN_VERIFY")
		return
	}
	if origin := strings.TrimSpace(req.Origin); origin != "" && origin != "AWS_KMS" {
		s.kmsFail(w, r, action, "", "UnsupportedOperationException", "Origin "+origin+" is not supported")
		return
	}
	if req.MultiRegion || req.CustomKeyStoreID != "" || req.XksKeyID != "" {
		s.kmsFail(w, r, action, "", "UnsupportedOperationException", "multi-Region keys and custom key stores are not supported")
		return
	}
	if _, err := store.NormalizeKeySpec(usage, req.KeySpec); err != nil {
		spec := strings.ToUpper(strings.TrimSpace(req.KeySpec))
		if awsKeySpecsUnsupported[spec] || strings.HasPrefix(spec, "RSA_") || strings.HasPrefix(spec, "ECC_") {
			s.kmsFail(w, r, action, "", "UnsupportedOperationException", "KeySpec "+spec+" is not supported for "+store.NormalizeKeyUsage(usage))
			return
		}
		s.kmsValidationError(w, r, action, "", "KeySpec is not valid")
		return
	}
	var policy string
	if strings.TrimSpace(req.Policy) != "" {
		p, err := normalizePolicyDocument(req.Policy)
		if err != nil {
			s.kmsFail(w, r, action, "", "MalformedPolicyDocumentException", "Policy must be valid JSON")
			return
		}
		policy = p
	}
	key, err := s.store.CreateKey(r.Context(), req.Description, usage, req.KeySpec)
	if err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	if policy != "" {
		if err := s.store.PutKeyPolicy(r.Context(), key.ID, "default", policy); err != nil {
			typ := writeKMSStoreError(w, err)
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
			return
		}
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, createKeyResponse{KeyMetadata: toKeyMetadata(key)})
}

// AWS list markers are opaque. Citadel's are a typed, base64url-wrapped
// cursor (the last item returned), so a forged or stale marker is rejected
// instead of silently restarting the listing.
func encodeListMarker(kind, cursor string) string {
	if cursor == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(kind + ":" + cursor))
}

func decodeListMarker(kind, marker string) (string, error) {
	if marker == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(marker)
	if err != nil || !strings.HasPrefix(string(raw), kind+":") {
		return "", errors.New("Marker is invalid")
	}
	cursor := strings.TrimPrefix(string(raw), kind+":")
	if cursor == "" {
		return "", errors.New("Marker is invalid")
	}
	return cursor, nil
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListKeys"
	var req listKeysRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	after, err := decodeListMarker("k", req.Marker)
	if err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	keys, more, err := s.store.ListKeysPage(r.Context(), after, limit)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "list keys: "+err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "KMSInternalException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	resp := listKeysResponse{Keys: make([]listKeyEntry, 0, len(keys)), Truncated: more}
	for _, k := range keys {
		resp.Keys = append(resp.Keys, listKeyEntry{KeyID: k.ID, KeyARN: k.ARN})
	}
	if more && len(keys) > 0 {
		resp.NextMarker = encodeListMarker("k", keys[len(keys)-1].ID)
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

// kmsAliasARN builds an alias ARN in the caller's account.
func (s *Server) kmsAliasARN(ctx context.Context, aliasName string) string {
	region, acct := s.store.DeploymentIdentity()
	if a, ok := store.CallerAccountFromContext(ctx); ok {
		acct = a
	}
	return arn.Build("kms", region, acct, aliasName)
}

// validateAliasName applies AWS's alias naming rules. alias/aws/ is reserved
// for AWS managed keys and alias/default for Citadel's per-account key.
func validateAliasName(name string) (typ, msg string) {
	switch {
	case !strings.HasPrefix(name, "alias/") || len(name) <= len("alias/") || len(name) > 256:
		return "ValidationException", "AliasName must begin with alias/ and be at most 256 characters"
	case strings.HasPrefix(name, "alias/aws/"):
		return "NotAuthorizedException", "alias/aws/ is reserved for AWS managed keys"
	case name == store.ManagedDefaultAlias:
		return "UnsupportedOperationException", "alias/default is reserved for the account's managed default key"
	}
	for _, c := range strings.TrimPrefix(name, "alias/") {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_-", c)) {
			return "ValidationException", "AliasName may contain only alphanumerics, /, _ and -"
		}
	}
	return "", ""
}

func (s *Server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateAlias"
	var req createAliasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.AliasName == "" || req.TargetKeyID == "" {
		s.kmsValidationError(w, r, action, "", "AliasName and TargetKeyId are required")
		return
	}
	if typ, msg := validateAliasName(req.AliasName); typ != "" {
		s.kmsFail(w, r, action, req.TargetKeyID, typ, msg)
		return
	}
	if strings.HasPrefix(kmsKeyIDFromInput(req.TargetKeyID), "alias/") {
		s.kmsValidationError(w, r, action, req.TargetKeyID, "TargetKeyId must be a key ID or key ARN, not an alias")
		return
	}
	key, ok := s.kmsResolveForAdmin(w, r, action, req.TargetKeyID, "kms:CreateAlias")
	if !ok {
		return
	}
	if _, err := s.store.ResolveByID(r.Context(), req.AliasName); err == nil {
		s.kmsFail(w, r, action, key.ID, "AlreadyExistsException", "An alias with the name "+s.kmsAliasARN(r.Context(), req.AliasName)+" already exists")
		return
	} else if !isKMSNotFound(err) {
		writeKMSKeyLookupError(w, err)
		return
	}
	if err := s.store.CreateAlias(r.Context(), req.AliasName, key.ID); err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleUpdateAlias(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.UpdateAlias"
	var req updateAliasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.AliasName == "" || req.TargetKeyID == "" {
		s.kmsValidationError(w, r, action, "", "AliasName and TargetKeyId are required")
		return
	}
	if req.AliasName == store.ManagedDefaultAlias {
		s.kmsFail(w, r, action, req.TargetKeyID, "UnsupportedOperationException", "alias/default is immutable and cannot be re-pointed")
		return
	}
	if _, err := s.store.ResolveByID(r.Context(), req.AliasName); err != nil {
		typ := writeKMSKeyLookupError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.AliasName, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	key, ok := s.kmsResolveForAdmin(w, r, action, req.TargetKeyID, "kms:UpdateAlias")
	if !ok {
		return
	}
	if err := s.store.UpdateAlias(r.Context(), req.AliasName, key.ID); err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.DeleteAlias"
	var req deleteAliasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if !strings.HasPrefix(req.AliasName, "alias/") {
		s.kmsValidationError(w, r, action, "", "AliasName must begin with alias/")
		return
	}
	if req.AliasName == store.ManagedDefaultAlias {
		s.kmsFail(w, r, action, "", "UnsupportedOperationException", "alias/default is immutable and cannot be deleted")
		return
	}
	key, ok := s.kmsResolveForAdmin(w, r, action, req.AliasName, "kms:DeleteAlias")
	if !ok {
		return
	}
	if err := s.store.DeleteAlias(r.Context(), req.AliasName); err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListAliases"
	var req listAliasesRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	after, err := decodeListMarker("a", req.Marker)
	if err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	targetKeyID := ""
	if strings.TrimSpace(req.KeyID) != "" {
		key, err := s.resolveKMSKey(r.Context(), req.KeyID)
		if err != nil {
			typ := writeKMSKeyLookupError(w, err)
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
			return
		}
		targetKeyID = key.ID
	}
	aliases, more, err := s.store.ListAliasesPage(r.Context(), store.AliasPageQuery{After: after, Limit: limit, TargetKeyID: targetKeyID})
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "list aliases: "+err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "KMSInternalException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	resp := listAliasesResponse{Aliases: make([]aliasEntry, 0, len(aliases)), Truncated: more}
	for _, a := range aliases {
		resp.Aliases = append(resp.Aliases, aliasEntry{AliasName: a.AliasName, AliasArn: s.kmsAliasARN(r.Context(), a.AliasName), TargetKeyID: a.TargetKeyID})
	}
	if more && len(aliases) > 0 {
		resp.NextMarker = encodeListMarker("a", aliases[len(aliases)-1].AliasName)
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSetKeyEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	action, policyAction := "TrentService.DisableKey", "kms:DisableKey"
	if enabled {
		action, policyAction = "TrentService.EnableKey", "kms:EnableKey"
	}
	var req keyIDRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	key, ok := s.kmsResolveForAdmin(w, r, action, req.KeyID, policyAction)
	if !ok {
		return
	}
	if !enabled && key.Managed {
		s.kmsFail(w, r, action, key.ID, "UnsupportedOperationException", "the account default key cannot be disabled")
		return
	}
	if key.DeletionDate != nil {
		s.kmsFail(w, r, action, key.ID, "KMSInvalidStateException", kmsKeyARN(key)+" is pending deletion.")
		return
	}
	if err := s.store.SetKeyEnabled(r.Context(), key.ID, enabled); err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleScheduleKeyDeletion(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ScheduleKeyDeletion"
	var req scheduleKeyDeletionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.PendingWindowInDays == 0 {
		req.PendingWindowInDays = 30
	}
	if req.PendingWindowInDays < 7 || req.PendingWindowInDays > 30 {
		s.kmsValidationError(w, r, action, req.KeyID, "PendingWindowInDays must be between 7 and 30")
		return
	}
	key, ok := s.kmsResolveForAdmin(w, r, action, req.KeyID, "kms:ScheduleKeyDeletion")
	if !ok {
		return
	}
	if key.Managed {
		s.kmsFail(w, r, action, key.ID, "UnsupportedOperationException", "the account default key cannot be scheduled for deletion")
		return
	}
	if key.DeletionDate != nil {
		s.kmsFail(w, r, action, key.ID, "KMSInvalidStateException", kmsKeyARN(key)+" is pending deletion.")
		return
	}
	deletionDate, err := s.store.ScheduleKeyDeletion(r.Context(), key.ID, req.PendingWindowInDays)
	if err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, scheduleKeyDeletionResponse{
		KeyID:               kmsKeyARN(key),
		DeletionDate:        store.AWSTimestamp(deletionDate),
		KeyState:            "PendingDeletion",
		PendingWindowInDays: req.PendingWindowInDays,
	})
}

func (s *Server) handleCancelKeyDeletion(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CancelKeyDeletion"
	var req keyIDRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	key, ok := s.kmsResolveForAdmin(w, r, action, req.KeyID, "kms:CancelKeyDeletion")
	if !ok {
		return
	}
	if key.DeletionDate == nil {
		s.kmsFail(w, r, action, key.ID, "KMSInvalidStateException", kmsKeyARN(key)+" is not pending deletion.")
		return
	}
	if err := s.store.CancelKeyDeletion(r.Context(), key.ID); err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	// As in AWS, a key whose deletion is cancelled comes back Disabled.
	if err := s.store.SetKeyEnabled(r.Context(), key.ID, false); err != nil {
		typ := writeKMSStoreError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{"KeyId": kmsKeyARN(key)})
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
	if err := validateGrantRequest(key, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
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
		out = append(out, grantListEntry{GrantID: grant.GrantID, KeyID: grant.KeyID, GranteePrincipal: grant.GranteePrincipal, RetiringPrincipal: grant.RetiringPrincipal, Operations: append([]string(nil), grant.Operations...), Name: grant.Name, CreationDate: store.AWSTimestamp(grant.CreatedAt)})
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
	grant, err := s.store.FindGrant(r.Context(), strings.TrimSpace(req.GrantID), strings.TrimSpace(req.GrantToken))
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "grant not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "NotFoundException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	// As in AWS: the retiring principal, a grantee holding RetireGrant, or
	// anyone the key policy allows kms:RetireGrant may retire a grant.
	if !s.mayRetireGrant(r, grant) {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "not allowed to retire this grant")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: grant.KeyID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.store.RetireGrant(r.Context(), grant.GrantID, ""); err != nil {
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
	md := keyMetadata{
		AWSAccountID:          accountFromARN(key.ARN),
		KeyID:                 key.ID,
		Arn:                   key.ARN,
		CreationDate:          store.AWSTimestamp(key.CreatedAt),
		DeletionDate:          awsTimePtr(key.DeletionDate),
		Enabled:               key.Enabled && key.DeletionDate == nil,
		Description:           key.Description,
		KeyUsage:              keyUsage,
		KeyState:              keyState(key),
		Origin:                keyOrigin(key),
		KeyManager:            "CUSTOMER",
		CustomerMasterKeySpec: keySpec,
		KeySpec:               keySpec,
		EncryptionAlgorithms:  keyEncryptionAlgorithms(key),
		SigningAlgorithms:     keySigningAlgorithms(key),
		MultiRegion:           false,
	}
	if key.DeletionDate != nil {
		md.PendingDeletionWindowInDays = pendingDeletionDays(key.DeletionDate)
	}
	return md
}

// accountFromARN extracts the account ID from an ARN, defaulting to the
// placeholder account for keys stored without one.
func accountFromARN(a string) string {
	parts := strings.SplitN(a, ":", 6)
	if len(parts) == 6 && parts[4] != "" {
		return parts[4]
	}
	return "000000000000"
}

func keyOrigin(key store.KMSKey) string {
	if key.Origin == "" {
		return store.OriginAWSKMS
	}
	return key.Origin
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
