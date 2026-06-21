package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	k := kmsKey{
		ID:           "go-kms-default-key",
		ARN:          "arn:aws:kms:local:000000000000:key/go-kms-default-key",
		MasterKeyRaw: bytes.Repeat([]byte{1}, 32),
		Description:  "test key",
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	s := &server{cfg: config{}, store: &inMemoryStore{k: k}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	plaintext := []byte("vault-auto-unseal")
	encryptBody := map[string]any{
		"KeyId":     "go-kms-default-key",
		"Plaintext": base64.StdEncoding.EncodeToString(plaintext),
		"EncryptionContext": map[string]string{
			"vault_cluster": "default",
		},
	}

	cipherB64 := callKMS(t, mux, "TrentService.Encrypt", encryptBody)["CiphertextBlob"].(string)

	decryptBody := map[string]any{
		"CiphertextBlob": cipherB64,
		"EncryptionContext": map[string]string{
			"vault_cluster": "default",
		},
	}
	resp := callKMS(t, mux, "TrentService.Decrypt", decryptBody)

	gotPlainB64, ok := resp["Plaintext"].(string)
	if !ok {
		t.Fatalf("missing Plaintext in response: %#v", resp)
	}
	gotPlain, err := base64.StdEncoding.DecodeString(gotPlainB64)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(gotPlain) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", string(gotPlain), string(plaintext))
	}
}

func TestEncryptRejectsUnknownKeyID(t *testing.T) {
	k := kmsKey{
		ID:           "kms-a",
		ARN:          "arn:aws:kms:local:000000000000:key/kms-a",
		MasterKeyRaw: bytes.Repeat([]byte{2}, 32),
		Description:  "test key",
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	s := &server{cfg: config{}, store: &inMemoryStore{k: k}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	body := map[string]any{
		"KeyId":     "kms-b",
		"Plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	}
	rec := post(t, mux, "TrentService.Encrypt", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status got %d want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDecryptLegacyBlobCompatibility(t *testing.T) {
	k := kmsKey{
		ID:           "go-kms-default-key",
		ARN:          "arn:aws:kms:local:000000000000:key/go-kms-default-key",
		MasterKeyRaw: bytes.Repeat([]byte{3}, 32),
		Description:  "test key",
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	s := &server{cfg: config{}, store: &inMemoryStore{k: k}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	plaintext := []byte("legacy-ciphertext")
	rawBlob, err := encryptLegacyBlob(k.MasterKeyRaw, plaintext, canonicalContext(map[string]string{"a": "b"}))
	if err != nil {
		t.Fatalf("encrypt legacy blob: %v", err)
	}

	resp := callKMS(t, mux, "TrentService.Decrypt", map[string]any{
		"CiphertextBlob": base64.StdEncoding.EncodeToString(rawBlob),
		"EncryptionContext": map[string]string{
			"a": "b",
		},
	})

	gotPlainB64, ok := resp["Plaintext"].(string)
	if !ok {
		t.Fatalf("missing Plaintext in response: %#v", resp)
	}
	gotPlain, err := base64.StdEncoding.DecodeString(gotPlainB64)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(gotPlain) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", string(gotPlain), string(plaintext))
	}
}

func callKMS(t *testing.T, h http.Handler, target string, body map[string]any) map[string]any {
	t.Helper()
	rec := post(t, h, target, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d, body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func post(t *testing.T, h http.Handler, target string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
