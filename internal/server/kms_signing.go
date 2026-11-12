package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

// kmsSigningKey resolves a SIGN_VERIFY key, checks its state and key policy,
// writing the error and audit event on failure.
func (s *Server) kmsSigningKey(w http.ResponseWriter, r *http.Request, action, keyID, policyAction string, needEnabled bool) (store.KMSKey, bool) {
	if strings.TrimSpace(keyID) == "" {
		s.kmsValidationError(w, r, action, "", "KeyId is required")
		return store.KMSKey{}, false
	}
	key, err := s.resolveKMSKey(r.Context(), keyID)
	if err != nil {
		typ := writeKMSKeyLookupError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return store.KMSKey{}, false
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != store.KeyUsageSignVerify && !(action == "TrentService.GetPublicKey" && len(key.PublicKeyRaw) > 0) {
		s.kmsFail(w, r, action, key.ID, "InvalidKeyUsageException", kmsKeyARN(key)+" key usage is "+keyUsage+" which is not valid for this operation.")
		return store.KMSKey{}, false
	}
	if needEnabled {
		if typ, msg := kmsKeyStateError(key); typ != "" {
			s.kmsFail(w, r, action, key.ID, typ, msg)
			return store.KMSKey{}, false
		}
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, policyAction); err != nil {
		if !errors.Is(err, errAccessDenied) {
			typ := writeKMSKeyLookupError(w, err)
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
			return store.KMSKey{}, false
		}
		s.kmsFail(w, r, action, key.ID, "AccessDeniedException", "access denied by key policy")
		return store.KMSKey{}, false
	}
	return key, true
}

func signingAlgorithmOrDefault(key store.KMSKey, alg string) string {
	if alg != "" {
		return alg
	}
	return defaultSigningAlgorithmForKey(key)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Sign"
	var req signRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	key, ok := s.kmsSigningKey(w, r, action, req.KeyID, "kms:Sign", true)
	if !ok {
		return
	}
	req.SigningAlgorithm = signingAlgorithmOrDefault(key, req.SigningAlgorithm)
	if !containsString(keySigningAlgorithms(key), req.SigningAlgorithm) {
		s.kmsFail(w, r, action, key.ID, "InvalidKeyUsageException", "SigningAlgorithm "+req.SigningAlgorithm+" is not valid for "+kmsKeyARN(key))
		return
	}
	digest, _, err := signableDigest(req.Message, req.MessageType, req.SigningAlgorithm, key.KeySpec)
	if err != nil {
		s.kmsValidationError(w, r, action, key.ID, err.Error())
		return
	}
	if req.DryRun {
		s.kmsDryRun(w, r, action, key.ID)
		return
	}
	sig, err := signDigestWithKey(key, req.SigningAlgorithm, digest)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "sign failed: "+err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "KMSInternalException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, signResponse{
		KeyID:            kmsKeyARN(key),
		Signature:        base64.StdEncoding.EncodeToString(sig),
		SigningAlgorithm: req.SigningAlgorithm,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Verify"
	var req verifyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	key, ok := s.kmsSigningKey(w, r, action, req.KeyID, "kms:Verify", true)
	if !ok {
		return
	}
	req.SigningAlgorithm = signingAlgorithmOrDefault(key, req.SigningAlgorithm)
	if !containsString(keySigningAlgorithms(key), req.SigningAlgorithm) {
		s.kmsFail(w, r, action, key.ID, "InvalidKeyUsageException", "SigningAlgorithm "+req.SigningAlgorithm+" is not valid for "+kmsKeyARN(key))
		return
	}
	if err := checkSigningAlgorithm(key, req.SigningAlgorithm); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	digest, _, err := signableDigest(req.Message, req.MessageType, req.SigningAlgorithm, key.KeySpec)
	if err != nil {
		s.kmsValidationError(w, r, action, key.ID, err.Error())
		return
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Signature))
	if err != nil || len(signature) == 0 {
		s.kmsValidationError(w, r, action, key.ID, "Signature must be base64 encoded")
		return
	}
	if req.DryRun {
		s.kmsDryRun(w, r, action, key.ID)
		return
	}
	valid, err := verifyDigestWithKey(key, req.SigningAlgorithm, digest, signature)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "verify failed: "+err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "KMSInternalException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	if !valid {
		// AWS reports a bad signature as an error, not SignatureValid=false.
		s.kmsFail(w, r, action, key.ID, "KMSInvalidSignatureException", "The signature is not valid for the message and key.")
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, verifyResponse{KeyID: kmsKeyARN(key), SignatureValid: true, SigningAlgorithm: req.SigningAlgorithm})
}

func (s *Server) handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.GetPublicKey"
	var req getPublicKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.kmsValidationError(w, r, action, "", err.Error())
		return
	}
	// A disabled key's public key stays readable in AWS only while Enabled;
	// pending-deletion and disabled keys are both rejected.
	key, ok := s.kmsSigningKey(w, r, action, req.KeyID, "kms:GetPublicKey", true)
	if !ok {
		return
	}
	publicB64, err := keyPublicKeyBase64(key)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "KMSInternalException", "public key unavailable: "+err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "KMSInternalException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, getPublicKeyResponse{
		KeyID:                kmsKeyARN(key),
		PublicKey:            publicB64,
		SigningAlgorithms:    keySigningAlgorithms(key),
		KeySpec:              key.KeySpec,
		KeyUsage:             key.KeyUsage,
		EncryptionAlgorithms: keyEncryptionAlgorithms(key),
	})
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
