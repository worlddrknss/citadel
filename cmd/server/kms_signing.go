package main

import (
	"encoding/base64"
	"net/http"
	"strings"
)

func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Sign"
	var req signRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != keyUsageSignVerify {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support signing")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:Sign"); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}
	digest, hashFunc, err := signableDigest(req.Message, req.MessageType, req.SigningAlgorithm, key.KeySpec)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	sig, err := signDigestWithKey(key, req.SigningAlgorithm, digest)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "sign failed")
		return
	}
	_ = hashFunc
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, signResponse{
		KeyID:            key.ID,
		Signature:        base64.StdEncoding.EncodeToString(sig),
		SigningAlgorithm: req.SigningAlgorithm,
	})
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Verify"
	var req verifyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != keyUsageSignVerify {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support verification")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:Verify"); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}
	digest, _, err := signableDigest(req.Message, req.MessageType, req.SigningAlgorithm, key.KeySpec)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Signature))
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Signature must be base64 encoded")
		return
	}
	ok, err := verifyDigestWithKey(key, req.SigningAlgorithm, digest, signature)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "verify failed")
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, verifyResponse{KeyID: key.ID, SignatureValid: ok, SigningAlgorithm: req.SigningAlgorithm})
}

func (s *server) handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.GetPublicKey"
	var req getPublicKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != keyUsageSignVerify {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support public keys")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:GetPublicKey"); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}
	publicB64, err := keyPublicKeyBase64(key)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "public key unavailable")
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, getPublicKeyResponse{
		KeyID:             key.ID,
		PublicKey:         publicB64,
		SigningAlgorithms: keySigningAlgorithms(key),
		KeySpec:           key.KeySpec,
	})
}
