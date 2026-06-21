package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

const (
	cipherBlobVersionV1 byte = 1
)

var errUnsupported = errors.New("unsupported operation")

type config struct {
	addr              string
	dbConnString      string
	requireAccessKey  bool
	expectedAccessKey string

	legacyKeyID     string
	legacyMasterKey []byte
}

type server struct {
	cfg   config
	store keyStore
}

type keyStore interface {
	ResolveByID(ctx context.Context, keyID string) (kmsKey, error)
	ResolveDefault(ctx context.Context) (kmsKey, error)
	EnsureBootstrap(ctx context.Context, k kmsKey) error
	CreateKey(ctx context.Context, description string) (kmsKey, error)
	ListKeys(ctx context.Context) ([]kmsKey, error)
	RecordAudit(ctx context.Context, event auditEvent) error
}

type dbStore struct {
	db *sql.DB
}

type inMemoryStore struct {
	k kmsKey
}

type kmsKey struct {
	ID           string
	ARN          string
	MasterKeyRaw []byte
	Description  string
	CreatedAt    time.Time
	Enabled      bool
}

type awsError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

type auditEvent struct {
	Action    string
	KeyID     string
	Result    string
	ErrorType string
	Actor     string
}

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
}

type createKeyResponse struct {
	KeyMetadata keyMetadata `json:"KeyMetadata"`
}

type listKeysResponse struct {
	Keys []listKeyEntry `json:"Keys"`
}

type listKeyEntry struct {
	KeyID  string `json:"KeyId"`
	KeyARN string `json:"KeyArn"`
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

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	store, cleanup, err := buildStore(cfg)
	if err != nil {
		log.Fatalf("failed to initialize key store: %v", err)
	}
	defer cleanup()

	if err := maybeBootstrapFromLegacy(context.Background(), cfg, store); err != nil {
		log.Fatalf("failed to bootstrap key material: %v", err)
	}

	s := &server{cfg: cfg, store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)
	mux.HandleFunc("/healthz", s.handleHealth)

	h := withRequestLogging(mux)

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("go-kms listening on %s", cfg.addr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server exited with error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

func loadConfig() (config, error) {
	cfg := config{
		addr:         envOrDefault("KMS_LISTEN_ADDR", ":8080"),
		dbConnString: os.Getenv("KMS_DB_URL"),
	}

	expectedAccessKey := os.Getenv("KMS_ACCESS_KEY_ID")
	cfg.expectedAccessKey = expectedAccessKey
	cfg.requireAccessKey = expectedAccessKey != ""

	masterKeyB64 := os.Getenv("KMS_MASTER_KEY_B64")
	if masterKeyB64 != "" {
		masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
		if err != nil {
			return config{}, fmt.Errorf("decode KMS_MASTER_KEY_B64: %w", err)
		}
		if len(masterKey) != 32 {
			return config{}, errors.New("KMS_MASTER_KEY_B64 must decode to exactly 32 bytes")
		}
		cfg.legacyMasterKey = masterKey
		cfg.legacyKeyID = envOrDefault("KMS_KEY_ID", "go-kms-default-key")
	}

	if cfg.dbConnString == "" && len(cfg.legacyMasterKey) == 0 {
		return config{}, errors.New("set KMS_DB_URL, or provide legacy KMS_MASTER_KEY_B64")
	}

	return cfg, nil
}

func buildStore(cfg config) (keyStore, func(), error) {
	if cfg.dbConnString == "" {
		if len(cfg.legacyMasterKey) == 0 {
			return nil, nil, errors.New("legacy key is required when KMS_DB_URL is not set")
		}
		k := kmsKey{
			ID:           cfg.legacyKeyID,
			ARN:          envOrDefault("KMS_KEY_ARN", fmt.Sprintf("arn:aws:kms:local:000000000000:key/%s", cfg.legacyKeyID)),
			MasterKeyRaw: cfg.legacyMasterKey,
			Description:  "go-kms key",
			CreatedAt:    time.Now().UTC(),
			Enabled:      true,
		}
		return &inMemoryStore{k: k}, func() {}, nil
	}

	db, err := sql.Open("postgres", cfg.dbConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("open postgres connection: %w", err)
	}
	cleanup := func() {
		_ = db.Close()
	}
	if err := db.Ping(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("ping postgres: %w", err)
	}
	if err := ensureSchema(context.Background(), db); err != nil {
		cleanup()
		return nil, nil, err
	}
	return &dbStore{db: db}, cleanup, nil
}

func ensureSchema(ctx context.Context, db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS kms_keys (
  id TEXT PRIMARY KEY,
  arn TEXT NOT NULL UNIQUE,
  master_key_b64 TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_audit_events (
	id BIGSERIAL PRIMARY KEY,
	action TEXT NOT NULL,
	key_id TEXT,
	result TEXT NOT NULL,
	error_type TEXT,
	actor TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}
	return nil
}

func maybeBootstrapFromLegacy(ctx context.Context, cfg config, store keyStore) error {
	if len(cfg.legacyMasterKey) == 0 {
		return nil
	}
	k := kmsKey{
		ID:           cfg.legacyKeyID,
		ARN:          envOrDefault("KMS_KEY_ARN", fmt.Sprintf("arn:aws:kms:local:000000000000:key/%s", cfg.legacyKeyID)),
		MasterKeyRaw: cfg.legacyMasterKey,
		Description:  "go-kms key",
		CreatedAt:    time.Now().UTC(),
		Enabled:      true,
	}
	if err := store.EnsureBootstrap(ctx, k); err != nil {
		return err
	}
	return nil
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "InvalidAction", "method not allowed")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *server) handleKMS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "InvalidAction", "method not allowed")
		return
	}

	if s.cfg.requireAccessKey {
		if !hasAccessKey(r.Header.Get("Authorization"), s.cfg.expectedAccessKey) {
			writeAWSJSONError(w, http.StatusForbidden, "UnrecognizedClientException", "invalid access key")
			return
		}
	}

	target := r.Header.Get("X-Amz-Target")
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
	default:
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidAction", "unsupported X-Amz-Target")
	}
}

func (s *server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Encrypt"
	var req encryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.Plaintext == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext is required")
		return
	}

	var (
		key kmsKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
			writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
			return
		}
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "key lookup failed")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext must be base64")
		return
	}

	cipherBlob, err := encryptBlob(key.MasterKeyRaw, key.ID, plaintext, canonicalContext(req.EncryptionContext))
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "encrypt failed")
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, encryptResponse{
		CiphertextBlob:    base64.StdEncoding.EncodeToString(cipherBlob),
		KeyID:             key.ID,
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Decrypt"
	var req decryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.CiphertextBlob == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob is required")
		return
	}

	cipherBlob, err := base64.StdEncoding.DecodeString(req.CiphertextBlob)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob must be base64")
		return
	}

	keyID, rawBlob, err := decodeCipherBlob(cipherBlob)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	var key kmsKey
	if keyID == "" {
		key, err = s.store.ResolveDefault(r.Context())
	} else {
		key, err = s.store.ResolveByID(r.Context(), keyID)
	}
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}

	plaintext, err := decryptBlob(key.MasterKeyRaw, rawBlob, canonicalContext(req.EncryptionContext))
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, decryptResponse{
		KeyID:             key.ID,
		Plaintext:         base64.StdEncoding.EncodeToString(plaintext),
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *server) handleDescribeKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.DescribeKey"
	var req describeKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	var (
		key kmsKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, describeKeyResponse{
		KeyMetadata: toKeyMetadata(key),
	})
}

func (s *server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateKey"
	var req createKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	key, err := s.store.CreateKey(r.Context(), req.Description)
	if err != nil {
		errType := "DependencyTimeoutException"
		if errors.Is(err, errUnsupported) {
			errType = "UnsupportedOperationException"
			writeAWSJSONError(w, http.StatusBadRequest, errType, "CreateKey requires KMS_DB_URL")
		} else {
			writeAWSJSONError(w, http.StatusInternalServerError, errType, "create key failed")
		}
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: errType, Actor: r.RemoteAddr})
		return
	}
	if req.Description != "" {
		key.Description = req.Description
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, createKeyResponse{KeyMetadata: toKeyMetadata(key)})
}

func (s *server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListKeys"
	keys, err := s.store.ListKeys(r.Context())
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list keys failed")
		return
	}
	out := make([]listKeyEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, listKeyEntry{KeyID: k.ID, KeyARN: k.ARN})
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listKeysResponse{Keys: out})
}

func keyState(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

func toKeyMetadata(key kmsKey) keyMetadata {
	return keyMetadata{
		AWSAccountID:          "000000000000",
		KeyID:                 key.ID,
		Arn:                   key.ARN,
		CreationDate:          key.CreatedAt,
		Enabled:               key.Enabled,
		Description:           key.Description,
		KeyUsage:              "ENCRYPT_DECRYPT",
		KeyState:              keyState(key.Enabled),
		Origin:                "AWS_KMS",
		KeyManager:            "CUSTOMER",
		CustomerMasterKeySpec: "SYMMETRIC_DEFAULT",
		KeySpec:               "SYMMETRIC_DEFAULT",
		EncryptionAlgorithms:  []string{"SYMMETRIC_DEFAULT"},
		MultiRegion:           false,
	}
}

func (s *server) recordAudit(ctx context.Context, event auditEvent) {
	if err := s.store.RecordAudit(ctx, event); err != nil {
		log.Printf("audit write failed action=%s key=%s: %v", event.Action, event.KeyID, err)
	}
}

func (s *dbStore) ResolveByID(ctx context.Context, keyID string) (kmsKey, error) {
	const q = `
SELECT id, arn, master_key_b64, description, enabled, created_at
FROM kms_keys
WHERE id = $1
`
	var (
		k         kmsKey
		masterB64 string
	)
	err := s.db.QueryRowContext(ctx, q, keyID).Scan(&k.ID, &k.ARN, &masterB64, &k.Description, &k.Enabled, &k.CreatedAt)
	if err != nil {
		return kmsKey{}, err
	}
	k.MasterKeyRaw, err = base64.StdEncoding.DecodeString(masterB64)
	if err != nil {
		return kmsKey{}, fmt.Errorf("decode key material for %s: %w", k.ID, err)
	}
	return k, nil
}

func (s *dbStore) ResolveDefault(ctx context.Context) (kmsKey, error) {
	const keyBySetting = `
SELECT setting_value
FROM kms_settings
WHERE setting_key = 'default_key_id'
`
	var keyID string
	err := s.db.QueryRowContext(ctx, keyBySetting).Scan(&keyID)
	if err == nil {
		return s.ResolveByID(ctx, keyID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return kmsKey{}, err
	}

	const fallback = `
SELECT id
FROM kms_keys
WHERE enabled = TRUE
ORDER BY created_at ASC
LIMIT 1
`
	err = s.db.QueryRowContext(ctx, fallback).Scan(&keyID)
	if err != nil {
		return kmsKey{}, err
	}
	return s.ResolveByID(ctx, keyID)
}

func (s *dbStore) EnsureBootstrap(ctx context.Context, k kmsKey) error {
	masterKeyB64 := base64.StdEncoding.EncodeToString(k.MasterKeyRaw)
	const upsertKey = `
INSERT INTO kms_keys (id, arn, master_key_b64, description, enabled, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (id) DO NOTHING
`
	if _, err := s.db.ExecContext(ctx, upsertKey, k.ID, k.ARN, masterKeyB64, k.Description, k.Enabled, k.CreatedAt); err != nil {
		return fmt.Errorf("bootstrap key row: %w", err)
	}

	const upsertDefault = `
INSERT INTO kms_settings (setting_key, setting_value)
VALUES ('default_key_id', $1)
ON CONFLICT (setting_key) DO NOTHING
`
	if _, err := s.db.ExecContext(ctx, upsertDefault, k.ID); err != nil {
		return fmt.Errorf("bootstrap default key setting: %w", err)
	}
	return nil
}

func (s *dbStore) CreateKey(ctx context.Context, description string) (kmsKey, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return kmsKey{}, err
	}
	id := "go-kms-" + randomHex(12)
	k := kmsKey{
		ID:           id,
		ARN:          fmt.Sprintf("arn:aws:kms:local:000000000000:key/%s", id),
		MasterKeyRaw: raw,
		Description:  description,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	masterKeyB64 := base64.StdEncoding.EncodeToString(k.MasterKeyRaw)
	const q = `
INSERT INTO kms_keys (id, arn, master_key_b64, description, enabled, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	if _, err := s.db.ExecContext(ctx, q, k.ID, k.ARN, masterKeyB64, k.Description, k.Enabled, k.CreatedAt); err != nil {
		return kmsKey{}, err
	}
	return k, nil
}

func (s *dbStore) ListKeys(ctx context.Context) ([]kmsKey, error) {
	const q = `
SELECT id, arn, master_key_b64, description, enabled, created_at
FROM kms_keys
ORDER BY created_at ASC
`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]kmsKey, 0)
	for rows.Next() {
		var (
			k         kmsKey
			masterB64 string
		)
		if err := rows.Scan(&k.ID, &k.ARN, &masterB64, &k.Description, &k.Enabled, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.MasterKeyRaw, err = base64.StdEncoding.DecodeString(masterB64)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *dbStore) RecordAudit(ctx context.Context, event auditEvent) error {
	const q = `
INSERT INTO kms_audit_events (action, key_id, result, error_type, actor)
VALUES ($1, $2, $3, $4, $5)
`
	_, err := s.db.ExecContext(ctx, q, event.Action, event.KeyID, event.Result, event.ErrorType, event.Actor)
	return err
}

func (s *inMemoryStore) ResolveByID(_ context.Context, keyID string) (kmsKey, error) {
	if keyID == "" || keyID == s.k.ID {
		return s.k, nil
	}
	return kmsKey{}, sql.ErrNoRows
}

func (s *inMemoryStore) ResolveDefault(_ context.Context) (kmsKey, error) {
	return s.k, nil
}

func (s *inMemoryStore) EnsureBootstrap(_ context.Context, _ kmsKey) error {
	return nil
}

func (s *inMemoryStore) CreateKey(_ context.Context, _ string) (kmsKey, error) {
	return kmsKey{}, errUnsupported
}

func (s *inMemoryStore) ListKeys(_ context.Context) ([]kmsKey, error) {
	return []kmsKey{s.k}, nil
}

func (s *inMemoryStore) RecordAudit(_ context.Context, _ auditEvent) error {
	return nil
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s target=%s", r.Method, r.URL.Path, r.Header.Get("X-Amz-Target"))
		next.ServeHTTP(w, r)
	})
}

func hasAccessKey(authHeader, accessKey string) bool {
	if accessKey == "" {
		return true
	}
	needle := "Credential=" + accessKey + "/"
	return strings.Contains(authHeader, needle)
}

func canonicalContext(ctx map[string]string) []byte {
	if len(ctx) == 0 {
		return nil
	}
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(ctx[k])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return sum[:]
}

func encryptBlob(masterKey []byte, keyID string, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	raw := make([]byte, 0, len(nonce)+len(ciphertext))
	raw = append(raw, nonce...)
	raw = append(raw, ciphertext...)
	return encodeCipherBlob(keyID, raw), nil
}

func encryptLegacyBlob(masterKey, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptBlob(masterKey, blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(blob) <= nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func decodeCipherBlob(blob []byte) (string, []byte, error) {
	if len(blob) < 2 || blob[0] != cipherBlobVersionV1 {
		return "", blob, nil
	}
	keyLen := int(blob[1])
	if len(blob) < 2+keyLen {
		return "", nil, errors.New("invalid ciphertext header")
	}
	keyID := string(blob[2 : 2+keyLen])
	return keyID, blob[2+keyLen:], nil
}

func encodeCipherBlob(keyID string, raw []byte) []byte {
	if keyID == "" {
		return raw
	}
	keyBytes := []byte(keyID)
	if len(keyBytes) > 255 {
		return raw
	}
	out := make([]byte, 0, 2+len(keyBytes)+len(raw))
	out = append(out, cipherBlobVersionV1)
	out = append(out, byte(len(keyBytes)))
	out = append(out, keyBytes...)
	out = append(out, raw...)
	return out
}

func decodeJSONBody(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeAWSJSONError(w http.ResponseWriter, status int, typ, msg string) {
	writeJSON(w, status, awsError{Type: typ, Message: msg})
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
