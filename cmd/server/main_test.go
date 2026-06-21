package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

func TestGetKeyPolicyReturnsDefaultPolicy(t *testing.T) {
	k := kmsKey{
		ID:           "go-kms-default-key",
		ARN:          "arn:aws:kms:local:000000000000:key/go-kms-default-key",
		MasterKeyRaw: bytes.Repeat([]byte{4}, 32),
		Description:  "test key",
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	s := &server{cfg: config{}, store: &inMemoryStore{k: k}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	resp := callKMS(t, mux, "TrentService.GetKeyPolicy", map[string]any{
		"KeyId":      k.ID,
		"PolicyName": "default",
	})

	policy, ok := resp["Policy"].(string)
	if !ok {
		t.Fatalf("missing Policy in response: %#v", resp)
	}
	if policy == "" {
		t.Fatalf("expected non-empty policy")
	}
}

func TestPutAndGetKeyPolicy(t *testing.T) {
	k := kmsKey{
		ID:           "go-kms-default-key",
		ARN:          "arn:aws:kms:local:000000000000:key/go-kms-default-key",
		MasterKeyRaw: bytes.Repeat([]byte{5}, 32),
		Description:  "test key",
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	s := &server{cfg: config{}, store: &inMemoryStore{k: k}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	wantPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowAll","Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*","Resource":"*"}]}`
	callKMS(t, mux, "TrentService.PutKeyPolicy", map[string]any{
		"KeyId":      k.ID,
		"PolicyName": "default",
		"Policy":     wantPolicy,
	})

	resp := callKMS(t, mux, "TrentService.GetKeyPolicy", map[string]any{
		"KeyId":      k.ID,
		"PolicyName": "default",
	})

	gotPolicy, ok := resp["Policy"].(string)
	if !ok {
		t.Fatalf("missing Policy in response: %#v", resp)
	}
	if !bytes.Contains([]byte(gotPolicy), []byte("AllowAll")) {
		t.Fatalf("policy not persisted: %s", gotPolicy)
	}
}

func TestDeriveDeterministicLegacyKeyID(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	sum := sha256.Sum256(master)
	want := "go-kms-" + hex.EncodeToString(sum[:8])
	got := deriveDeterministicLegacyKeyID(master)
	if got != want {
		t.Fatalf("unexpected key id: got %s want %s", got, want)
	}
	if got == "go-kms-default-key" {
		t.Fatalf("legacy key id must not use static default value")
	}
}

func TestDecodeCipherBlobLegacyFallbackOnMalformedHeader(t *testing.T) {
	legacy := []byte{cipherBlobVersionV1, 250, 1, 2, 3, 4}
	keyID, raw, err := decodeCipherBlob(legacy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keyID != "" {
		t.Fatalf("expected empty key id for legacy fallback")
	}
	if !bytes.Equal(raw, legacy) {
		t.Fatalf("expected legacy blob passthrough")
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
