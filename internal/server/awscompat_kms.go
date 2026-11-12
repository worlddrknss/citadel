package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// KMS compatibility helpers shared by the KMS handlers, plus the data-key and
// re-encryption actions (GenerateDataKey, GenerateDataKeyWithoutPlaintext,
// GenerateDataKeyPair, GenerateDataKeyPairWithoutPlaintext, ReEncrypt).

const (
	kmsSymmetricAlgorithm = "SYMMETRIC_DEFAULT"
	kmsDryRunMessage      = "The request would have succeeded, but the DryRun option is set."
)

// kmsKeyIDFromInput normalizes the KeyId forms AWS accepts — key ID, key
// ARN, alias name, alias ARN — to what the store resolves: a key ID or an
// "alias/..." name.
func kmsKeyIDFromInput(id string) string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, "arn:") {
		parts := strings.SplitN(id, ":", 6)
		if len(parts) == 6 {
			res := parts[5]
			switch {
			case strings.HasPrefix(res, "key/"):
				return strings.TrimPrefix(res, "key/")
			case strings.HasPrefix(res, "alias/"):
				return res
			}
		}
	}
	return id
}

// resolveKMSKey resolves any accepted KeyId form within the caller's account.
func (s *Server) resolveKMSKey(ctx context.Context, keyID string) (store.KMSKey, error) {
	return s.store.ResolveByID(ctx, kmsKeyIDFromInput(keyID))
}

func isKMSNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

// writeKMSKeyLookupError answers a failed key lookup: a missing key is
// NotFoundException, anything else is an internal failure (not a pretend
// NotFound that hides a broken database). It returns the error type written.
func writeKMSKeyLookupError(w http.ResponseWriter, err error) string {
	if isKMSNotFound(err) {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "Key not found or not accessible to this account.")
		return "NotFoundException"
	}
	writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "key lookup failed: "+err.Error())
	return "KMSInternalException"
}

// writeKMSStoreError answers a failed key mutation the same way.
func writeKMSStoreError(w http.ResponseWriter, err error) string {
	switch {
	case isKMSNotFound(err):
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "Key not found or not accessible to this account.")
		return "NotFoundException"
	case errors.Is(err, store.ErrImmutableManagedKey):
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", store.ErrImmutableManagedKey.Error())
		return "UnsupportedOperationException"
	case errors.Is(err, store.ErrAliasExists):
		writeAWSJSONError(w, http.StatusBadRequest, "AlreadyExistsException", "An alias with that name already exists.")
		return "AlreadyExistsException"
	case errors.Is(err, store.ErrUnsupported):
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "This operation is not supported by the configured store.")
		return "UnsupportedOperationException"
	}
	writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", err.Error())
	return "KMSInternalException"
}

// kmsKeyStateError reports why a key cannot be used for a cryptographic
// operation: pending deletion is KMSInvalidStateException, disabled is
// DisabledException.
func kmsKeyStateError(key store.KMSKey) (typ, msg string) {
	if key.DeletionDate != nil {
		return "KMSInvalidStateException", fmt.Sprintf("%s is pending deletion.", key.ARN)
	}
	if !key.Enabled {
		return "DisabledException", fmt.Sprintf("%s is disabled.", key.ARN)
	}
	return "", ""
}

// kmsKeyARN returns the key's ARN, falling back to its ID for keys stored
// without one. AWS returns the ARN in KeyId response members.
func kmsKeyARN(key store.KMSKey) string {
	if key.ARN != "" {
		return key.ARN
	}
	return key.ID
}

func validSymmetricAlgorithm(alg string) bool {
	return alg == "" || alg == kmsSymmetricAlgorithm
}

// kmsKeyForCrypto resolves keyID (or the account default when empty and
// allowDefault), checks usage, state and key policy, and on failure writes the
// error and audit event. ok is false when the handler must stop.
func (s *Server) kmsKeyForCrypto(w http.ResponseWriter, r *http.Request, action, keyID, policyAction string, allowDefault bool) (store.KMSKey, bool) {
	ctx := r.Context()
	var (
		key store.KMSKey
		err error
	)
	switch {
	case strings.TrimSpace(keyID) != "":
		key, err = s.resolveKMSKey(ctx, keyID)
	case allowDefault:
		key, err = s.store.ResolveDefault(ctx)
	default:
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		return store.KMSKey{}, false
	}
	if err != nil {
		typ := writeKMSKeyLookupError(w, err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return store.KMSKey{}, false
	}
	if usage, _ := keyUsageAndSpecForMetadata(key); usage != store.KeyUsageEncryptDecrypt {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", fmt.Sprintf("%s key usage is %s which is not valid for this operation.", kmsKeyARN(key), usage))
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", AuditOrigin: s.auditOrigin(r)})
		return store.KMSKey{}, false
	}
	// RSA ENCRYPT_DECRYPT keys serve Encrypt (RSAES-OAEP) only; data keys and
	// re-encryption need a symmetric key.
	if !key.IsSymmetric() && action != "TrentService.Encrypt" {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", fmt.Sprintf("%s is an asymmetric key, which is not valid for this operation.", kmsKeyARN(key)))
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", AuditOrigin: s.auditOrigin(r)})
		return store.KMSKey{}, false
	}
	if typ, msg := kmsKeyStateError(key); typ != "" {
		writeAWSJSONError(w, http.StatusBadRequest, typ, msg)
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
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

// kmsDryRun answers a DryRun request that passed every check.
func (s *Server) kmsDryRun(w http.ResponseWriter, r *http.Request, action, keyID string) {
	writeAWSJSONError(w, http.StatusPreconditionFailed, "DryRunOperationException", kmsDryRunMessage)
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: keyID, Result: "ok", ErrorType: "DryRunOperationException", AuditOrigin: s.auditOrigin(r)})
}

func (s *Server) kmsValidationError(w http.ResponseWriter, r *http.Request, action, keyID, msg string) {
	writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", msg)
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
}

// ---- GenerateDataKey / GenerateDataKeyWithoutPlaintext ---------------------

type generateDataKeyRequest struct {
	KeyID             string            `json:"KeyId"`
	EncryptionContext map[string]string `json:"EncryptionContext"`
	NumberOfBytes     int               `json:"NumberOfBytes"`
	KeySpec           string            `json:"KeySpec"`
	GrantTokens       []string          `json:"GrantTokens"`
	DryRun            bool              `json:"DryRun"`
	Recipient         json.RawMessage   `json:"Recipient"`
}

type generateDataKeyResponse struct {
	CiphertextBlob string `json:"CiphertextBlob"`
	Plaintext      string `json:"Plaintext,omitempty"`
	KeyID          string `json:"KeyId"`
}

// dataKeyLength validates the KeySpec/NumberOfBytes pair as AWS does.
// maxDataKeyBytes is AWS's upper bound for NumberOfBytes.
const maxDataKeyBytes = 1024

func dataKeyLength(keySpec string, numberOfBytes int) (int, error) {
	switch {
	case keySpec != "" && numberOfBytes != 0:
		return 0, errors.New("KeySpec and NumberOfBytes are mutually exclusive")
	case keySpec == "AES_256":
		return 32, nil
	case keySpec == "AES_128":
		return 16, nil
	case keySpec != "":
		return 0, fmt.Errorf("KeySpec must be AES_256 or AES_128")
	case numberOfBytes < 0 || numberOfBytes > 1024:
		return 0, errors.New("NumberOfBytes must be between 1 and 1024")
	case numberOfBytes == 0:
		return 0, errors.New("one of KeySpec or NumberOfBytes is required")
	}
	return numberOfBytes, nil
}

func (s *Server) handleGenerateDataKey(w http.ResponseWriter, r *http.Request, withPlaintext bool) {
	action, policyAction := "TrentService.GenerateDataKey", "kms:GenerateDataKey"
	if !withPlaintext {
		action, policyAction = "TrentService.GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKeyWithoutPlaintext"
	}
	var req generateDataKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" {
		s.kmsValidationError(w, r, action, "", "KeyId is required")
		return
	}
	if len(req.Recipient) > 0 && string(req.Recipient) != "null" {
		s.kmsValidationError(w, r, action, req.KeyID, "Recipient (Nitro Enclaves attestation) is not supported")
		return
	}
	n, err := dataKeyLength(req.KeySpec, req.NumberOfBytes)
	if err != nil {
		s.kmsValidationError(w, r, action, req.KeyID, err.Error())
		return
	}
	key, ok := s.kmsKeyForCrypto(w, r, action, req.KeyID, policyAction, false)
	if !ok {
		return
	}
	if req.DryRun {
		s.kmsDryRun(w, r, action, key.ID)
		return
	}
	if n < 1 || n > maxDataKeyBytes { // dataKeyLength enforces this; keep the allocation visibly bounded
		s.kmsValidationError(w, r, action, req.KeyID, "NumberOfBytes must be between 1 and 1024")
		return
	}
	plaintext := make([]byte, n)
	if _, err := rand.Read(plaintext); err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "random: "+err.Error())
		return
	}
	blob, err := key.EncryptBlob(plaintext, cryptoutil.CanonicalContext(req.EncryptionContext))
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "encrypt: "+err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "KMSInternalException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	resp := generateDataKeyResponse{CiphertextBlob: base64.StdEncoding.EncodeToString(blob), KeyID: kmsKeyARN(key)}
	if withPlaintext {
		resp.Plaintext = base64.StdEncoding.EncodeToString(plaintext)
	}
	clear(plaintext)
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

// ---- GenerateDataKeyPair / GenerateDataKeyPairWithoutPlaintext -------------

type generateDataKeyPairRequest struct {
	KeyID             string            `json:"KeyId"`
	KeyPairSpec       string            `json:"KeyPairSpec"`
	EncryptionContext map[string]string `json:"EncryptionContext"`
	GrantTokens       []string          `json:"GrantTokens"`
	DryRun            bool              `json:"DryRun"`
	Recipient         json.RawMessage   `json:"Recipient"`
}

type generateDataKeyPairResponse struct {
	KeyID                    string `json:"KeyId"`
	KeyPairSpec              string `json:"KeyPairSpec"`
	PrivateKeyCiphertextBlob string `json:"PrivateKeyCiphertextBlob"`
	PrivateKeyPlaintext      string `json:"PrivateKeyPlaintext,omitempty"`
	PublicKey                string `json:"PublicKey"`
}

// fipsDataKeyPairSpecs are the key pair specs Citadel generates. AWS also
// offers ECC_SECG_P256K1 and SM2, which are not FIPS 140-3 approved, and
// ECC_NIST_P521, which Citadel does not offer for signing keys either.
var fipsDataKeyPairSpecs = map[string]bool{
	store.KeySpecRSA2048: true,
	store.KeySpecRSA3072: true,
	store.KeySpecRSA4096: true,
	store.KeySpecECCP256: true,
	store.KeySpecECCP384: true,
}

func (s *Server) handleGenerateDataKeyPair(w http.ResponseWriter, r *http.Request, withPlaintext bool) {
	action, policyAction := "TrentService.GenerateDataKeyPair", "kms:GenerateDataKeyPair"
	if !withPlaintext {
		action, policyAction = "TrentService.GenerateDataKeyPairWithoutPlaintext", "kms:GenerateDataKeyPairWithoutPlaintext"
	}
	var req generateDataKeyPairRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" {
		s.kmsValidationError(w, r, action, "", "KeyId is required")
		return
	}
	if len(req.Recipient) > 0 && string(req.Recipient) != "null" {
		s.kmsValidationError(w, r, action, req.KeyID, "Recipient (Nitro Enclaves attestation) is not supported")
		return
	}
	spec := strings.ToUpper(strings.TrimSpace(req.KeyPairSpec))
	if !fipsDataKeyPairSpecs[spec] {
		s.kmsValidationError(w, r, action, req.KeyID, "KeyPairSpec must be one of RSA_2048, RSA_3072, RSA_4096, ECC_NIST_P256, ECC_NIST_P384")
		return
	}
	key, ok := s.kmsKeyForCrypto(w, r, action, req.KeyID, policyAction, false)
	if !ok {
		return
	}
	if req.DryRun {
		s.kmsDryRun(w, r, action, key.ID)
		return
	}
	privDER, pubDER, _, _, err := store.GenerateKeyMaterial(store.KeyUsageSignVerify, spec)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "generate key pair: "+err.Error())
		return
	}
	blob, err := key.EncryptBlob(privDER, cryptoutil.CanonicalContext(req.EncryptionContext))
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "encrypt: "+err.Error())
		return
	}
	resp := generateDataKeyPairResponse{
		KeyID:                    kmsKeyARN(key),
		KeyPairSpec:              spec,
		PrivateKeyCiphertextBlob: base64.StdEncoding.EncodeToString(blob),
		PublicKey:                base64.StdEncoding.EncodeToString(pubDER),
	}
	if withPlaintext {
		resp.PrivateKeyPlaintext = base64.StdEncoding.EncodeToString(privDER)
	}
	clear(privDER)
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

// ---- ReEncrypt -------------------------------------------------------------

type reEncryptRequest struct {
	CiphertextBlob                 string            `json:"CiphertextBlob"`
	SourceEncryptionContext        map[string]string `json:"SourceEncryptionContext"`
	SourceKeyID                    string            `json:"SourceKeyId"`
	DestinationKeyID               string            `json:"DestinationKeyId"`
	DestinationEncryptionContext   map[string]string `json:"DestinationEncryptionContext"`
	SourceEncryptionAlgorithm      string            `json:"SourceEncryptionAlgorithm"`
	DestinationEncryptionAlgorithm string            `json:"DestinationEncryptionAlgorithm"`
	GrantTokens                    []string          `json:"GrantTokens"`
	DryRun                         bool              `json:"DryRun"`
}

type reEncryptResponse struct {
	CiphertextBlob                 string `json:"CiphertextBlob"`
	SourceKeyID                    string `json:"SourceKeyId"`
	KeyID                          string `json:"KeyId"`
	SourceEncryptionAlgorithm      string `json:"SourceEncryptionAlgorithm"`
	DestinationEncryptionAlgorithm string `json:"DestinationEncryptionAlgorithm"`
}

func (s *Server) handleReEncrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ReEncrypt"
	ctx := r.Context()
	var req reEncryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	if req.CiphertextBlob == "" || strings.TrimSpace(req.DestinationKeyID) == "" {
		s.kmsValidationError(w, r, action, "", "CiphertextBlob and DestinationKeyId are required")
		return
	}
	if !validSymmetricAlgorithm(req.SourceEncryptionAlgorithm) || !validSymmetricAlgorithm(req.DestinationEncryptionAlgorithm) {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "only SYMMETRIC_DEFAULT is supported by ReEncrypt")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.CiphertextBlob)
	if err != nil {
		s.kmsValidationError(w, r, action, "", "CiphertextBlob must be base64")
		return
	}
	embeddedID, _, err := cryptoutil.DecodeCipherBlob(raw)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "The ciphertext is invalid.")
		return
	}
	var src store.KMSKey
	if embeddedID == "" {
		src, err = s.store.ResolveDefault(ctx)
	} else {
		src, err = s.store.ResolveByID(ctx, embeddedID)
	}
	if err != nil {
		if isKMSNotFound(err) {
			writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "The ciphertext is invalid.")
			s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: embeddedID, Result: "error", ErrorType: "InvalidCiphertextException", AuditOrigin: s.auditOrigin(r)})
			return
		}
		writeKMSKeyLookupError(w, err)
		return
	}
	if strings.TrimSpace(req.SourceKeyID) != "" {
		named, err := s.resolveKMSKey(ctx, req.SourceKeyID)
		if err != nil {
			typ := writeKMSKeyLookupError(w, err)
			s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: req.SourceKeyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
			return
		}
		if named.ID != src.ID {
			writeAWSJSONError(w, http.StatusBadRequest, "IncorrectKeyException", "The key ID in the request does not identify the KMS key that encrypted the ciphertext.")
			s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: named.ID, Result: "error", ErrorType: "IncorrectKeyException", AuditOrigin: s.auditOrigin(r)})
			return
		}
	}
	if typ, msg := kmsKeyStateError(src); typ != "" {
		writeAWSJSONError(w, http.StatusBadRequest, typ, msg)
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: src.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	if err := s.authorizeKeyAction(ctx, r, src, "kms:ReEncryptFrom"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: src.ID, Result: "error", ErrorType: "AccessDeniedException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	dst, ok := s.kmsKeyForCrypto(w, r, action, req.DestinationKeyID, "kms:ReEncryptTo", false)
	if !ok {
		return
	}
	plaintext, err := src.DecryptBlob(raw, cryptoutil.CanonicalContext(req.SourceEncryptionContext))
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "The ciphertext is invalid or the encryption context does not match.")
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: src.ID, Result: "error", ErrorType: "InvalidCiphertextException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	defer clear(plaintext)
	if req.DryRun {
		s.kmsDryRun(w, r, action, dst.ID)
		return
	}
	blob, err := dst.EncryptBlob(plaintext, cryptoutil.CanonicalContext(req.DestinationEncryptionContext))
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "encrypt: "+err.Error())
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: dst.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, reEncryptResponse{
		CiphertextBlob:                 base64.StdEncoding.EncodeToString(blob),
		SourceKeyID:                    kmsKeyARN(src),
		KeyID:                          kmsKeyARN(dst),
		SourceEncryptionAlgorithm:      kmsSymmetricAlgorithm,
		DestinationEncryptionAlgorithm: kmsSymmetricAlgorithm,
	})
}
