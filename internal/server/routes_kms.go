package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Native /v1 KMS endpoints: grants, rotation, tags, the "Try it" crypto
// operations and the wrapping-key re-wrap. Reads need viewer, writes and
// crypto editor, re-wrap admin. Every key is resolved within the session's
// account, so another account's key is simply "not found".

// registerKMSRoutes registers the native /v1 KMS lifecycle and crypto routes.
func (s *Server) registerKMSRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/kms/grants", s.handleV1CreateKMSGrant)
	mux.HandleFunc("DELETE /v1/kms/grants", s.handleV1RevokeKMSGrant)
	mux.HandleFunc("GET /v1/kms/keys/rotation", s.handleV1GetKMSRotation)
	mux.HandleFunc("POST /v1/kms/keys/rotation", s.handleV1SetKMSRotation)
	mux.HandleFunc("POST /v1/kms/keys/rotate", s.handleV1RotateKMSKeyNow)
	mux.HandleFunc("GET /v1/kms/keys/tags", s.handleV1ListKMSTags)
	mux.HandleFunc("POST /v1/kms/keys/tags", s.handleV1TagKMSKey)
	mux.HandleFunc("DELETE /v1/kms/keys/tags", s.handleV1UntagKMSKey)
	mux.HandleFunc("POST /v1/kms/encrypt", s.handleV1KMSEncrypt)
	mux.HandleFunc("POST /v1/kms/decrypt", s.handleV1KMSDecrypt)
	mux.HandleFunc("POST /v1/kms/sign", s.handleV1KMSSign)
	mux.HandleFunc("POST /v1/kms/verify", s.handleV1KMSVerify)
	mux.HandleFunc("POST /v1/kms/admin/rewrap", s.handleV1KMSRewrap)
	s.registerKMSJobs()
}

// v1KMSKey authenticates the session at minRole and resolves keyID in the
// session's account. On failure it has written the response.
func (s *Server) v1KMSKey(w http.ResponseWriter, r *http.Request, minRole, keyID string) (context.Context, store.KMSKey, bool) {
	_, ctx, ok := s.nativeSession(w, r, minRole)
	if !ok {
		return nil, store.KMSKey{}, false
	}
	key, ok := s.v1ResolveKey(w, ctx, keyID)
	return ctx, key, ok
}

// v1ResolveKey resolves keyID within ctx's account, writing 400/404 on failure.
func (s *Server) v1ResolveKey(w http.ResponseWriter, ctx context.Context, keyID string) (store.KMSKey, bool) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "keyId is required")
		return store.KMSKey{}, false
	}
	if len(keyID) > 2048 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "keyId is too long")
		return store.KMSKey{}, false
	}
	key, err := s.store.ResolveByID(ctx, keyID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("v1 kms: resolve key", "err", err)
		}
		writeNativeError(w, http.StatusNotFound, "not_found", "key not found")
		return store.KMSKey{}, false
	}
	return key, true
}

// decodeV1 decodes a JSON body, writing a stable 400 on failure.
func decodeV1(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := decodeJSONBody(r, v); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON for this endpoint")
		return false
	}
	return true
}

// nativeCodeFor maps AWS-style KMS error types to native error codes.
func nativeCodeFor(awsType string) (int, string) {
	switch awsType {
	case "NotFoundException":
		return http.StatusNotFound, "not_found"
	case "DisabledException":
		return http.StatusConflict, "key_disabled"
	case "KMSInvalidStateException":
		return http.StatusConflict, "invalid_state"
	case "InvalidCiphertextException", "IncorrectKeyException":
		return http.StatusBadRequest, "invalid_ciphertext"
	case "InvalidKeyUsageException":
		return http.StatusBadRequest, "invalid_key_usage"
	case "UnsupportedOperationException":
		return http.StatusBadRequest, "unsupported"
	case "LimitExceededException":
		return http.StatusConflict, "limit_exceeded"
	case "TagException", "ValidationException":
		return http.StatusBadRequest, "invalid_request"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

// writeV1KMSError writes err (a *kmsOpError, a store lifecycle error or an
// internal failure) as a native error and returns the audit error type.
func writeV1KMSError(w http.ResponseWriter, err error, what string) string {
	var oe *kmsOpError
	typ, msg := "", ""
	switch {
	case errors.As(err, &oe):
		typ, msg = oe.Type, oe.Message
	case errors.Is(err, store.ErrRotationUnsupported):
		typ, msg = "UnsupportedOperationException", err.Error()
	case errors.Is(err, store.ErrInvalidRotationPeriod):
		typ, msg = "ValidationException", err.Error()
	case errors.Is(err, store.ErrRotationLimit):
		typ, msg = "LimitExceededException", err.Error()
	case errors.Is(err, store.ErrKeyNotUsable):
		typ, msg = "KMSInvalidStateException", err.Error()
	case errors.Is(err, store.ErrInvalidTags):
		typ, msg = "TagException", err.Error()
	case errors.Is(err, sql.ErrNoRows):
		typ, msg = "NotFoundException", "not found"
	case errors.Is(err, store.ErrUnsupported):
		typ, msg = "UnsupportedOperationException", "not supported by this store"
	default:
		slog.Error("v1 kms operation failed", "op", what, "err", err)
		typ, msg = "KMSInternalException", what+" failed"
	}
	status, code := nativeCodeFor(typ)
	writeNativeError(w, status, code, msg)
	return typ
}

func (s *Server) auditV1(ctx context.Context, r *http.Request, action, keyID, errType string) {
	result := "ok"
	if errType != "" {
		result = "error"
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: keyID, Result: result, ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
}

// ---- grants -------------------------------------------------------------

type v1CreateGrantRequest struct {
	KeyID             string   `json:"keyId"`
	GranteePrincipal  string   `json:"granteePrincipal"`
	Operations        []string `json:"operations"`
	RetiringPrincipal string   `json:"retiringPrincipal"`
	Name              string   `json:"name"`
}

func (s *Server) handleV1CreateKMSGrant(w http.ResponseWriter, r *http.Request) {
	const action = "kms.CreateGrant"
	var req v1CreateGrantRequest
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	if !decodeV1(w, r, &req) {
		return
	}
	key, ok := s.v1ResolveKey(w, ctx, req.KeyID)
	if !ok {
		return
	}
	greq := store.CreateGrantRequest{KeyID: key.ID, GranteePrincipal: req.GranteePrincipal, RetiringPrincipal: req.RetiringPrincipal, Operations: req.Operations, Name: req.Name}
	if err := validateGrantRequest(key, &greq); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		s.auditV1(ctx, r, action, key.ID, "ValidationException")
		return
	}
	grant, err := s.store.CreateGrant(ctx, greq)
	if err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "create grant"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	writeNativeJSON(w, http.StatusOK, map[string]any{"grantId": grant.GrantID, "grantToken": grant.GrantToken})
}

func (s *Server) handleV1RevokeKMSGrant(w http.ResponseWriter, r *http.Request) {
	const action = "kms.RevokeGrant"
	q := r.URL.Query()
	ctx, key, ok := s.v1KMSKey(w, r, "editor", q.Get("keyId"))
	if !ok {
		return
	}
	grantID := strings.TrimSpace(q.Get("grantId"))
	if grantID == "" || len(grantID) > 128 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "grantId is required")
		return
	}
	if err := s.store.RevokeGrant(ctx, key.ID, grantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeNativeError(w, http.StatusNotFound, "not_found", "grant not found")
			s.auditV1(ctx, r, action, key.ID, "NotFoundException")
			return
		}
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "revoke grant"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	writeNativeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// ---- rotation -----------------------------------------------------------

type v1RotationEvent struct {
	RotatedAt     string `json:"rotatedAt"`
	Kind          string `json:"kind"`
	KeyMaterialID string `json:"keyMaterialId,omitempty"`
}

type v1RotationStatus struct {
	KeyID              string            `json:"keyId"`
	Supported          bool              `json:"supported"`
	Enabled            bool              `json:"enabled"`
	RotationPeriodDays int               `json:"rotationPeriodDays"`
	LastRotatedAt      string            `json:"lastRotatedAt,omitempty"`
	NextRotationAt     string            `json:"nextRotationAt,omitempty"`
	History            []v1RotationEvent `json:"history"`
}

func (s *Server) rotationStatus(ctx context.Context, key store.KMSKey) (v1RotationStatus, error) {
	st := v1RotationStatus{KeyID: key.ID, Supported: key.IsSymmetric(), History: []v1RotationEvent{}}
	if !st.Supported {
		return st, nil
	}
	st.Enabled = key.RotationEnabled
	st.RotationPeriodDays = key.RotationPeriodDays
	if st.RotationPeriodDays == 0 {
		st.RotationPeriodDays = store.DefaultRotationPeriodDays
	}
	if key.RotationEnabled && key.NextRotationAt != nil {
		st.NextRotationAt = key.NextRotationAt.UTC().Format(time.RFC3339)
	}
	rotations, err := s.store.ListKeyRotations(ctx, key.ID)
	if err != nil {
		return st, err
	}
	for i, rot := range rotations {
		if i == 0 {
			st.LastRotatedAt = rot.RotatedAt.UTC().Format(time.RFC3339)
		}
		st.History = append(st.History, v1RotationEvent{RotatedAt: rot.RotatedAt.UTC().Format(time.RFC3339), Kind: rot.Kind, KeyMaterialID: rot.MaterialID})
	}
	return st, nil
}

func (s *Server) handleV1GetKMSRotation(w http.ResponseWriter, r *http.Request) {
	ctx, key, ok := s.v1KMSKey(w, r, "viewer", r.URL.Query().Get("keyId"))
	if !ok {
		return
	}
	st, err := s.rotationStatus(ctx, key)
	if err != nil {
		writeV1KMSError(w, err, "read rotation")
		return
	}
	writeNativeJSON(w, http.StatusOK, st)
}

type v1SetRotationRequest struct {
	KeyID              string `json:"keyId"`
	Enabled            bool   `json:"enabled"`
	RotationPeriodDays int    `json:"rotationPeriodDays"`
}

func (s *Server) handleV1SetKMSRotation(w http.ResponseWriter, r *http.Request) {
	var req v1SetRotationRequest
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	if !decodeV1(w, r, &req) {
		return
	}
	action := "kms.DisableKeyRotation"
	if req.Enabled {
		action = "kms.EnableKeyRotation"
	}
	key, ok := s.v1ResolveKey(w, ctx, req.KeyID)
	if !ok {
		return
	}
	if !key.IsSymmetric() {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, store.ErrRotationUnsupported, "set rotation"))
		return
	}
	if req.Enabled && req.RotationPeriodDays != 0 && (req.RotationPeriodDays < store.MinRotationPeriodDays || req.RotationPeriodDays > store.MaxRotationPeriodDays) {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, store.ErrInvalidRotationPeriod, "set rotation"))
		return
	}
	if err := keyUsable(key); err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "set rotation"))
		return
	}
	period := req.RotationPeriodDays
	if !req.Enabled {
		period = 0
	}
	updated, err := s.store.SetKeyRotation(ctx, key.ID, req.Enabled, period)
	if err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "set rotation"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	st, err := s.rotationStatus(ctx, updated)
	if err != nil {
		writeV1KMSError(w, err, "read rotation")
		return
	}
	writeNativeJSON(w, http.StatusOK, st)
}

type v1KeyIDRequest struct {
	KeyID string `json:"keyId"`
}

// handleV1RotateKMSKeyNow rotates a symmetric key's material on demand.
func (s *Server) handleV1RotateKMSKeyNow(w http.ResponseWriter, r *http.Request) {
	const action = "kms.RotateKeyOnDemand"
	var req v1KeyIDRequest
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	if !decodeV1(w, r, &req) {
		return
	}
	key, ok := s.v1ResolveKey(w, ctx, req.KeyID)
	if !ok {
		return
	}
	if _, err := s.store.RotateKeyMaterial(ctx, key.ID, store.RotationKindOnDemand, time.Now().UTC()); err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "rotate key"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	updated, err := s.store.ResolveByID(ctx, key.ID)
	if err != nil {
		writeV1KMSError(w, err, "read rotation")
		return
	}
	st, err := s.rotationStatus(ctx, updated)
	if err != nil {
		writeV1KMSError(w, err, "read rotation")
		return
	}
	writeNativeJSON(w, http.StatusOK, st)
}

// ---- tags ---------------------------------------------------------------

type v1Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (s *Server) handleV1ListKMSTags(w http.ResponseWriter, r *http.Request) {
	ctx, key, ok := s.v1KMSKey(w, r, "viewer", r.URL.Query().Get("keyId"))
	if !ok {
		return
	}
	tags, err := s.store.ListKeyTags(ctx, key.ID)
	if err != nil {
		writeV1KMSError(w, err, "list tags")
		return
	}
	out := make([]v1Tag, 0, len(tags))
	for _, t := range tags {
		out = append(out, v1Tag{Key: t.Key, Value: t.Value})
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": key.ID, "tags": out})
}

type v1TagRequest struct {
	KeyID string  `json:"keyId"`
	Tags  []v1Tag `json:"tags"`
}

func (s *Server) handleV1TagKMSKey(w http.ResponseWriter, r *http.Request) {
	const action = "kms.TagResource"
	var req v1TagRequest
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	if !decodeV1(w, r, &req) {
		return
	}
	key, ok := s.v1ResolveKey(w, ctx, req.KeyID)
	if !ok {
		return
	}
	tags := make([]store.KMSTag, 0, len(req.Tags))
	for _, t := range req.Tags {
		tags = append(tags, store.KMSTag{Key: t.Key, Value: t.Value})
	}
	if err := s.store.TagKey(ctx, key.ID, tags); err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "tag key"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	writeNativeJSON(w, http.StatusOK, map[string]any{"tagged": true})
}

func (s *Server) handleV1UntagKMSKey(w http.ResponseWriter, r *http.Request) {
	const action = "kms.UntagResource"
	q := r.URL.Query()
	ctx, key, ok := s.v1KMSKey(w, r, "editor", q.Get("keyId"))
	if !ok {
		return
	}
	tagKey := strings.TrimSpace(q.Get("tagKey"))
	if tagKey == "" || len(tagKey) > store.MaxTagKeyLength {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "tagKey is required")
		return
	}
	if err := s.store.UntagKey(ctx, key.ID, []string{tagKey}); err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "untag key"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	writeNativeJSON(w, http.StatusOK, map[string]any{"untagged": true})
}

// ---- crypto ("Try it") --------------------------------------------------

type v1EncryptRequest struct {
	KeyID               string            `json:"keyId"`
	Plaintext           string            `json:"plaintext"`
	EncryptionContext   map[string]string `json:"encryptionContext"`
	EncryptionAlgorithm string            `json:"encryptionAlgorithm"`
}

type v1DecryptRequest struct {
	KeyID               string            `json:"keyId"`
	CiphertextBlob      string            `json:"ciphertextBlob"`
	EncryptionContext   map[string]string `json:"encryptionContext"`
	EncryptionAlgorithm string            `json:"encryptionAlgorithm"`
}

func (s *Server) handleV1KMSEncrypt(w http.ResponseWriter, r *http.Request) {
	const action = "kms.Encrypt"
	var req v1EncryptRequest
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	if !decodeV1(w, r, &req) {
		return
	}
	key, ok := s.v1ResolveKey(w, ctx, req.KeyID)
	if !ok {
		return
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "plaintext must be base64")
		s.auditV1(ctx, r, action, key.ID, "ValidationException")
		return
	}
	if err := keyUsable(key); err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "encrypt"))
		return
	}
	blob, alg, err := kmsEncrypt(key, req.EncryptionAlgorithm, plaintext, req.EncryptionContext)
	if err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "encrypt"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": key.ID, "ciphertextBlob": base64.StdEncoding.EncodeToString(blob), "encryptionAlgorithm": alg})
}

func (s *Server) handleV1KMSDecrypt(w http.ResponseWriter, r *http.Request) {
	const action = "kms.Decrypt"
	var req v1DecryptRequest
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	if !decodeV1(w, r, &req) {
		return
	}
	key, ok := s.v1ResolveKey(w, ctx, req.KeyID)
	if !ok {
		return
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.CiphertextBlob))
	if err != nil || len(blob) == 0 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "ciphertextBlob must be base64")
		s.auditV1(ctx, r, action, key.ID, "ValidationException")
		return
	}
	if err := keyUsable(key); err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "decrypt"))
		return
	}
	plaintext, alg, err := kmsDecrypt(key, req.EncryptionAlgorithm, blob, req.EncryptionContext)
	if err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "decrypt"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": key.ID, "plaintext": base64.StdEncoding.EncodeToString(plaintext), "encryptionAlgorithm": alg})
}

type v1SignRequest struct {
	KeyID            string `json:"keyId"`
	Message          string `json:"message"`
	MessageType      string `json:"messageType"`
	SigningAlgorithm string `json:"signingAlgorithm"`
	Signature        string `json:"signature"`
}

// v1SignPrologue validates a sign/verify request against the key. The
// native API requires an explicit, FIPS-approved algorithm valid for the key.
func (s *Server) v1SignPrologue(w http.ResponseWriter, r *http.Request, action string, req *v1SignRequest) (context.Context, store.KMSKey, []byte, bool) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return nil, store.KMSKey{}, nil, false
	}
	if !decodeV1(w, r, req) {
		return nil, store.KMSKey{}, nil, false
	}
	key, ok := s.v1ResolveKey(w, ctx, req.KeyID)
	if !ok {
		return nil, store.KMSKey{}, nil, false
	}
	fail := func(typ, msg string) {
		status, code := nativeCodeFor(typ)
		writeNativeError(w, status, code, msg)
		s.auditV1(ctx, r, action, key.ID, typ)
	}
	if usage, _ := keyUsageAndSpecForMetadata(key); usage != store.KeyUsageSignVerify {
		fail("InvalidKeyUsageException", "key does not support signing")
		return nil, store.KMSKey{}, nil, false
	}
	req.SigningAlgorithm = strings.ToUpper(strings.TrimSpace(req.SigningAlgorithm))
	if req.SigningAlgorithm == "" {
		fail("ValidationException", "signingAlgorithm is required")
		return nil, store.KMSKey{}, nil, false
	}
	if err := checkSigningAlgorithm(key, req.SigningAlgorithm); err != nil {
		fail("ValidationException", err.Error())
		return nil, store.KMSKey{}, nil, false
	}
	if err := keyUsable(key); err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "sign"))
		return nil, store.KMSKey{}, nil, false
	}
	msgType := strings.ToUpper(strings.TrimSpace(req.MessageType))
	if msgType != "RAW" && msgType != "DIGEST" {
		fail("ValidationException", "messageType must be RAW or DIGEST")
		return nil, store.KMSKey{}, nil, false
	}
	if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Message)); err != nil || len(raw) == 0 || len(raw) > 4096 {
		fail("ValidationException", "message must be 1-4096 bytes of base64")
		return nil, store.KMSKey{}, nil, false
	}
	digest, hashFunc, err := signableDigest(req.Message, msgType, req.SigningAlgorithm, key.KeySpec)
	if err != nil {
		fail("ValidationException", "invalid message or signing algorithm")
		return nil, store.KMSKey{}, nil, false
	}
	if msgType == "DIGEST" && len(digest) != hashFunc.Size() {
		fail("ValidationException", "a DIGEST message must be exactly one hash long for this algorithm")
		return nil, store.KMSKey{}, nil, false
	}
	return ctx, key, digest, true
}

func (s *Server) handleV1KMSSign(w http.ResponseWriter, r *http.Request) {
	const action = "kms.Sign"
	var req v1SignRequest
	ctx, key, digest, ok := s.v1SignPrologue(w, r, action, &req)
	if !ok {
		return
	}
	if req.Signature != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "signature is not accepted by sign")
		return
	}
	sig, err := signDigestWithKey(key, req.SigningAlgorithm, digest)
	if err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "sign"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": key.ID, "signature": base64.StdEncoding.EncodeToString(sig), "signingAlgorithm": req.SigningAlgorithm})
}

func (s *Server) handleV1KMSVerify(w http.ResponseWriter, r *http.Request) {
	const action = "kms.Verify"
	var req v1SignRequest
	ctx, key, digest, ok := s.v1SignPrologue(w, r, action, &req)
	if !ok {
		return
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Signature))
	if err != nil || len(sig) == 0 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "signature must be base64")
		s.auditV1(ctx, r, action, key.ID, "ValidationException")
		return
	}
	valid, err := verifyDigestWithKey(key, req.SigningAlgorithm, digest, sig)
	if err != nil {
		s.auditV1(ctx, r, action, key.ID, writeV1KMSError(w, err, "verify"))
		return
	}
	s.auditV1(ctx, r, action, key.ID, "")
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": key.ID, "signatureValid": valid, "signingAlgorithm": req.SigningAlgorithm})
}

// ---- wrapping-key re-wrap -----------------------------------------------

// handleV1KMSRewrap re-wraps all stored material onto the current wrapping
// key (platform admins only): wrapping is deployment-wide.
func (s *Server) handleV1KMSRewrap(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	report, err := s.runKMSRewrap(context.WithoutCancel(ctx), s.auditOrigin(r))
	if err != nil {
		writeNativeError(w, http.StatusInternalServerError, "rewrap_failed", "re-wrap failed; see server logs")
		return
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"scanned": report.Scanned, "rewrapped": report.Rewrapped, "failed": report.Failed,
		"keyMaterial": report.KeyMaterial, "accessKeySecrets": report.AccessKeySecrets,
		"stsSessionSecrets": report.STSSessionSecrets, "acmeKeys": report.ACMEKeys,
	})
}
