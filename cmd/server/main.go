package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
)

type config struct {
	addr              string
	keyID             string
	masterKey         []byte
	requireAccessKey  bool
	expectedAccessKey string
}

type server struct {
	cfg config
}

type awsError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
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

type keyMetadata struct {
	AWSAccountID               string    `json:"AWSAccountId"`
	KeyID                      string    `json:"KeyId"`
	Arn                        string    `json:"Arn"`
	CreationDate               time.Time `json:"CreationDate"`
	Enabled                    bool      `json:"Enabled"`
	Description                string    `json:"Description"`
	KeyUsage                   string    `json:"KeyUsage"`
	KeyState                   string    `json:"KeyState"`
	Origin                     string    `json:"Origin"`
	KeyManager                 string    `json:"KeyManager"`
	CustomerMasterKeySpec      string    `json:"CustomerMasterKeySpec"`
	KeySpec                    string    `json:"KeySpec"`
	EncryptionAlgorithms       []string  `json:"EncryptionAlgorithms"`
	MultiRegion                bool      `json:"MultiRegion"`
	SigningAlgorithms          []string  `json:"SigningAlgorithms"`
	PendingDeletionWindowInDays int      `json:"PendingDeletionWindowInDays,omitempty"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	s := &server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)
	mux.HandleFunc("/healthz", s.handleHealth)

	h := withRequestLogging(mux)

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("go-kms listening on %s (key=%s)", cfg.addr, cfg.keyID)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server exited with error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

func loadConfig() (config, error) {
	addr := envOrDefault("KMS_LISTEN_ADDR", ":8080")
	keyID := envOrDefault("KMS_KEY_ID", "go-kms-default-key")

	masterKeyB64 := os.Getenv("KMS_MASTER_KEY_B64")
	if masterKeyB64 == "" {
		return config{}, errors.New("KMS_MASTER_KEY_B64 is required and must be base64 encoded")
	}

	masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		return config{}, fmt.Errorf("decode KMS_MASTER_KEY_B64: %w", err)
	}
	if len(masterKey) != 32 {
		return config{}, errors.New("KMS_MASTER_KEY_B64 must decode to exactly 32 bytes")
	}

	expectedAccessKey := os.Getenv("KMS_ACCESS_KEY_ID")
	requireAccessKey := expectedAccessKey != ""

	return config{
		addr:              addr,
		keyID:             keyID,
		masterKey:         masterKey,
		requireAccessKey:  requireAccessKey,
		expectedAccessKey: expectedAccessKey,
	}, nil
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
	default:
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidAction", "unsupported X-Amz-Target")
	}
}

func (s *server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	var req encryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.Plaintext == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext is required")
		return
	}
	if req.KeyID != "" && req.KeyID != s.cfg.keyID {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext must be base64")
		return
	}

	cipherBlob, err := encryptBlob(s.cfg.masterKey, plaintext, canonicalContext(req.EncryptionContext))
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "encrypt failed")
		return
	}

	writeJSON(w, http.StatusOK, encryptResponse{
		CiphertextBlob:    base64.StdEncoding.EncodeToString(cipherBlob),
		KeyID:             s.cfg.keyID,
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var req decryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.CiphertextBlob == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob is required")
		return
	}

	cipherBlob, err := base64.StdEncoding.DecodeString(req.CiphertextBlob)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob must be base64")
		return
	}

	plaintext, err := decryptBlob(s.cfg.masterKey, cipherBlob, canonicalContext(req.EncryptionContext))
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	writeJSON(w, http.StatusOK, decryptResponse{
		KeyID:             s.cfg.keyID,
		Plaintext:         base64.StdEncoding.EncodeToString(plaintext),
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *server) handleDescribeKey(w http.ResponseWriter, r *http.Request) {
	var req describeKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.KeyID != "" && req.KeyID != s.cfg.keyID {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}

	arn := envOrDefault("KMS_KEY_ARN", fmt.Sprintf("arn:aws:kms:local:000000000000:key/%s", s.cfg.keyID))
	writeJSON(w, http.StatusOK, describeKeyResponse{
		KeyMetadata: keyMetadata{
			AWSAccountID:          "000000000000",
			KeyID:                 s.cfg.keyID,
			Arn:                   arn,
			CreationDate:          time.Now().UTC(),
			Enabled:               true,
			Description:           "go-kms key",
			KeyUsage:              "ENCRYPT_DECRYPT",
			KeyState:              "Enabled",
			Origin:                "AWS_KMS",
			KeyManager:            "CUSTOMER",
			CustomerMasterKeySpec: "SYMMETRIC_DEFAULT",
			KeySpec:               "SYMMETRIC_DEFAULT",
			EncryptionAlgorithms:  []string{"SYMMETRIC_DEFAULT"},
			MultiRegion:           false,
		},
	})
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

func encryptBlob(masterKey, plaintext, aad []byte) ([]byte, error) {
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
