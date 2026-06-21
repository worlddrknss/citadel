package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestListKeysPagination(t *testing.T) {
	keys := []kmsKey{
		{
			ID:           "key-1",
			ARN:          "arn:aws:kms:local:000000000000:key/key-1",
			MasterKeyRaw: bytes.Repeat([]byte{1}, 32),
			CreatedAt:    time.Unix(1, 0).UTC(),
			Enabled:      true,
		},
		{
			ID:           "key-2",
			ARN:          "arn:aws:kms:local:000000000000:key/key-2",
			MasterKeyRaw: bytes.Repeat([]byte{2}, 32),
			CreatedAt:    time.Unix(2, 0).UTC(),
			Enabled:      true,
		},
		{
			ID:           "key-3",
			ARN:          "arn:aws:kms:local:000000000000:key/key-3",
			MasterKeyRaw: bytes.Repeat([]byte{3}, 32),
			CreatedAt:    time.Unix(3, 0).UTC(),
			Enabled:      true,
		},
	}
	s := &server{cfg: config{}, store: &inMemoryStore{keys: keys}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	firstPage := callKMS(t, mux, "TrentService.ListKeys", map[string]any{"Limit": 2})
	keysOut, ok := firstPage["Keys"].([]any)
	if !ok {
		t.Fatalf("missing Keys in response: %#v", firstPage)
	}
	if len(keysOut) != 2 {
		t.Fatalf("expected 2 keys on first page, got %d", len(keysOut))
	}
	if truncated, _ := firstPage["Truncated"].(bool); !truncated {
		t.Fatalf("expected first page to be truncated: %#v", firstPage)
	}
	nextMarker, ok := firstPage["NextMarker"].(string)
	if !ok || nextMarker != "key-2" {
		t.Fatalf("unexpected next marker: %#v", firstPage["NextMarker"])
	}

	secondPage := callKMS(t, mux, "TrentService.ListKeys", map[string]any{"Limit": 2, "Marker": nextMarker})
	keysOut, ok = secondPage["Keys"].([]any)
	if !ok {
		t.Fatalf("missing Keys in response: %#v", secondPage)
	}
	if len(keysOut) != 1 {
		t.Fatalf("expected 1 key on second page, got %d", len(keysOut))
	}
	entry, ok := keysOut[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected key entry: %#v", keysOut[0])
	}
	if got, _ := entry["KeyId"].(string); got != "key-3" {
		t.Fatalf("unexpected second-page key id: %q", got)
	}
	if truncated, _ := secondPage["Truncated"].(bool); truncated {
		t.Fatalf("expected final page to be non-truncated: %#v", secondPage)
	}
}

func TestListKeysRejectsInvalidMarker(t *testing.T) {
	k := kmsKey{
		ID:           "key-1",
		ARN:          "arn:aws:kms:local:000000000000:key/key-1",
		MasterKeyRaw: bytes.Repeat([]byte{1}, 32),
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	s := &server{cfg: config{}, store: &inMemoryStore{k: k}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	rec := post(t, mux, "TrentService.ListKeys", map[string]any{"Marker": "missing"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status got %d want %d", rec.Code, http.StatusBadRequest)
	}
	assertAWSErrorType(t, rec.Body.Bytes(), "ValidationException")
}

func TestListAliasesPagination(t *testing.T) {
	k := kmsKey{
		ID:           "key-1",
		ARN:          "arn:aws:kms:local:000000000000:key/key-1",
		MasterKeyRaw: bytes.Repeat([]byte{1}, 32),
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	aliases := []kmsAlias{
		{AliasName: "alias/app-1", TargetKeyID: "key-1"},
		{AliasName: "alias/app-2", TargetKeyID: "key-1"},
		{AliasName: "alias/app-3", TargetKeyID: "key-1"},
	}
	s := &server{cfg: config{}, store: &inMemoryStore{k: k, aliases: aliases}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	firstPage := callKMS(t, mux, "TrentService.ListAliases", map[string]any{"Limit": 1})
	aliasesOut, ok := firstPage["Aliases"].([]any)
	if !ok {
		t.Fatalf("missing Aliases in response: %#v", firstPage)
	}
	if len(aliasesOut) != 1 {
		t.Fatalf("expected 1 alias on first page, got %d", len(aliasesOut))
	}
	nextMarker, ok := firstPage["NextMarker"].(string)
	if !ok || nextMarker != "alias/app-1" {
		t.Fatalf("unexpected next marker: %#v", firstPage["NextMarker"])
	}
	if truncated, _ := firstPage["Truncated"].(bool); !truncated {
		t.Fatalf("expected first page to be truncated: %#v", firstPage)
	}

	secondPage := callKMS(t, mux, "TrentService.ListAliases", map[string]any{"Limit": 2, "Marker": nextMarker})
	aliasesOut, ok = secondPage["Aliases"].([]any)
	if !ok {
		t.Fatalf("missing Aliases in response: %#v", secondPage)
	}
	if len(aliasesOut) != 2 {
		t.Fatalf("expected 2 aliases on second page, got %d", len(aliasesOut))
	}
	if truncated, _ := secondPage["Truncated"].(bool); truncated {
		t.Fatalf("expected final page to be non-truncated: %#v", secondPage)
	}
}

func TestListKeysAllowsEmptyBody(t *testing.T) {
	k := kmsKey{
		ID:           "key-1",
		ARN:          "arn:aws:kms:local:000000000000:key/key-1",
		MasterKeyRaw: bytes.Repeat([]byte{1}, 32),
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	s := &server{cfg: config{}, store: &inMemoryStore{k: k}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Amz-Target", "TrentService.ListKeys")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d, body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if truncated, _ := out["Truncated"].(bool); truncated {
		t.Fatalf("expected single-page list to be non-truncated: %#v", out)
	}
}

func TestPhaseACompatibilitySuite(t *testing.T) {
	t.Run("unsupported target returns InvalidAction", func(t *testing.T) {
		s := &server{cfg: config{}, store: &inMemoryStore{k: sampleKey(1)}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		rec := post(t, mux, "TrentService.Unknown", map[string]any{})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status got %d want %d", rec.Code, http.StatusBadRequest)
		}
		assertAWSErrorType(t, rec.Body.Bytes(), "InvalidAction")
	})

	t.Run("non-post requests are rejected", func(t *testing.T) {
		s := &server{cfg: config{}, store: &inMemoryStore{k: sampleKey(1)}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status got %d want %d", rec.Code, http.StatusMethodNotAllowed)
		}
		assertAWSErrorType(t, rec.Body.Bytes(), "InvalidAction")
	})

	t.Run("strict sigv4 missing headers returns IncompleteSignature", func(t *testing.T) {
		s := &server{cfg: config{strictSigV4: true}, store: &inMemoryStore{k: sampleKey(1)}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		rec := post(t, mux, "TrentService.ListKeys", map[string]any{})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status got %d want %d", rec.Code, http.StatusForbidden)
		}
		assertAWSErrorType(t, rec.Body.Bytes(), "IncompleteSignature")
	})

	t.Run("access key mismatch returns UnrecognizedClientException", func(t *testing.T) {
		s := &server{cfg: config{requireAccessKey: true, expectedAccessKey: "vault"}, store: &inMemoryStore{k: sampleKey(1)}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		rec := post(t, mux, "TrentService.ListKeys", map[string]any{})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status got %d want %d", rec.Code, http.StatusForbidden)
		}
		assertAWSErrorType(t, rec.Body.Bytes(), "UnrecognizedClientException")
	})

	t.Run("disabled key returns DisabledException on encrypt", func(t *testing.T) {
		key := sampleKey(1)
		key.Enabled = false
		s := &server{cfg: config{}, store: &inMemoryStore{k: key}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		rec := post(t, mux, "TrentService.Encrypt", map[string]any{
			"KeyId":     key.ID,
			"Plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status got %d want %d", rec.Code, http.StatusBadRequest)
		}
		assertAWSErrorType(t, rec.Body.Bytes(), "DisabledException")
	})

	t.Run("describe key returns expected metadata", func(t *testing.T) {
		key := sampleKey(1)
		s := &server{cfg: config{}, store: &inMemoryStore{k: key}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		resp := callKMS(t, mux, "TrentService.DescribeKey", map[string]any{"KeyId": key.ID})
		metadata, ok := resp["KeyMetadata"].(map[string]any)
		if !ok {
			t.Fatalf("missing KeyMetadata: %#v", resp)
		}
		if got, _ := metadata["KeyUsage"].(string); got != "ENCRYPT_DECRYPT" {
			t.Fatalf("unexpected KeyUsage: %q", got)
		}
		if got, _ := metadata["KeySpec"].(string); got != "SYMMETRIC_DEFAULT" {
			t.Fatalf("unexpected KeySpec: %q", got)
		}
	})

	t.Run("create key in memory mode returns UnsupportedOperationException", func(t *testing.T) {
		s := &server{cfg: config{}, store: &inMemoryStore{k: sampleKey(1)}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		rec := post(t, mux, "TrentService.CreateKey", map[string]any{"Description": "demo"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status got %d want %d", rec.Code, http.StatusBadRequest)
		}
		assertAWSErrorType(t, rec.Body.Bytes(), "UnsupportedOperationException")
	})

	t.Run("put key policy rejects malformed policy documents", func(t *testing.T) {
		key := sampleKey(1)
		s := &server{cfg: config{}, store: &inMemoryStore{k: key}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		rec := post(t, mux, "TrentService.PutKeyPolicy", map[string]any{
			"KeyId":      key.ID,
			"PolicyName": "default",
			"Policy":     "not-json",
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status got %d want %d", rec.Code, http.StatusBadRequest)
		}
		assertAWSErrorType(t, rec.Body.Bytes(), "MalformedPolicyDocumentException")
	})

	t.Run("list aliases allows empty body", func(t *testing.T) {
		key := sampleKey(1)
		s := &server{cfg: config{}, store: &inMemoryStore{k: key, aliases: []kmsAlias{{AliasName: "alias/app", TargetKeyID: key.ID}}}}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleKMS)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Amz-Target", "TrentService.ListAliases")
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status: %d, body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestSecretsManagerLifecycle(t *testing.T) {
	key := sampleKey(1)
	s := &server{cfg: config{}, store: &inMemoryStore{k: key}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)

	createResp := callKMS(t, mux, "secretsmanager.CreateSecret", map[string]any{
		"Name":         "prod/app/database",
		"Description":  "database credentials",
		"SecretString": `{"password":"one"}`,
	})
	if got, _ := createResp["Name"].(string); got != "prod/app/database" {
		t.Fatalf("unexpected create secret name: %q", got)
	}

	valueResp := callKMS(t, mux, "secretsmanager.GetSecretValue", map[string]any{
		"SecretId": "prod/app/database",
	})
	if got, _ := valueResp["SecretString"].(string); got != `{"password":"one"}` {
		t.Fatalf("unexpected secret string: %q", got)
	}

	putResp := callKMS(t, mux, "secretsmanager.PutSecretValue", map[string]any{
		"SecretId":     "prod/app/database",
		"SecretString": `{"password":"two"}`,
	})
	if got, _ := putResp["VersionId"].(string); got == "" {
		t.Fatalf("expected version id from put response: %#v", putResp)
	}

	currentResp := callKMS(t, mux, "secretsmanager.GetSecretValue", map[string]any{
		"SecretId": "prod/app/database",
	})
	if got, _ := currentResp["SecretString"].(string); got != `{"password":"two"}` {
		t.Fatalf("unexpected rotated secret string: %q", got)
	}

	describeResp := callKMS(t, mux, "secretsmanager.DescribeSecret", map[string]any{
		"SecretId": "prod/app/database",
	})
	versionMap, ok := describeResp["VersionIdsToStages"].(map[string]any)
	if !ok || len(versionMap) < 2 {
		t.Fatalf("expected current and previous versions in describe response: %#v", describeResp)
	}
	if rotationEnabled, _ := describeResp["RotationEnabled"].(bool); rotationEnabled {
		t.Fatalf("rotation should not be enabled yet: %#v", describeResp)
	}

	listResp := callKMS(t, mux, "secretsmanager.ListSecrets", map[string]any{"MaxResults": 1})
	secretList, ok := listResp["SecretList"].([]any)
	if !ok || len(secretList) != 1 {
		t.Fatalf("expected one secret in list response: %#v", listResp)
	}

	callKMS(t, mux, "secretsmanager.TagResource", map[string]any{
		"SecretId": "prod/app/database",
		"Tags":     []map[string]any{{"Key": "environment", "Value": "prod"}},
	})
	describeResp = callKMS(t, mux, "secretsmanager.DescribeSecret", map[string]any{"SecretId": "prod/app/database"})

	policyDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowRead","Effect":"Allow","Principal":{"AWS":"*"},"Action":["secretsmanager:GetSecretValue"],"Resource":"*"}]}`
	callKMS(t, mux, "secretsmanager.PutResourcePolicy", map[string]any{
		"SecretId":       "prod/app/database",
		"ResourcePolicy": policyDoc,
	})
	policyResp := callKMS(t, mux, "secretsmanager.GetResourcePolicy", map[string]any{"SecretId": "prod/app/database"})
	if got, _ := policyResp["ResourcePolicy"].(string); !strings.Contains(got, "AllowRead") {
		t.Fatalf("unexpected policy response: %#v", policyResp)
	}

	versionListResp := callKMS(t, mux, "secretsmanager.ListSecretVersionIds", map[string]any{"SecretId": "prod/app/database"})
	versions, ok := versionListResp["Versions"].([]any)
	if !ok || len(versions) < 2 {
		t.Fatalf("expected version list response: %#v", versionListResp)
	}

	rotateResp := callKMS(t, mux, "secretsmanager.RotateSecret", map[string]any{
		"SecretId":               "prod/app/database",
		"AutomaticallyAfterDays": 14,
		"RotateImmediately":      true,
	})
	pendingVersionID, _ := rotateResp["VersionId"].(string)
	if pendingVersionID == "" {
		t.Fatalf("expected pending rotation version id: %#v", rotateResp)
	}

	versionListResp = callKMS(t, mux, "secretsmanager.ListSecretVersionIds", map[string]any{"SecretId": "prod/app/database"})
	versions, ok = versionListResp["Versions"].([]any)
	if !ok {
		t.Fatalf("expected versions after rotate: %#v", versionListResp)
	}
	foundPending := false
	for _, raw := range versions {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if entry["VersionId"] == pendingVersionID {
			stages, _ := entry["VersionStages"].([]any)
			for _, stage := range stages {
				if stage == pendingVersionStage {
					foundPending = true
				}
			}
		}
	}
	if !foundPending {
		t.Fatalf("expected pending stage after rotation: %#v", versionListResp)
	}

	callKMS(t, mux, "secretsmanager.UpdateSecretVersionStage", map[string]any{
		"SecretId":        "prod/app/database",
		"VersionStage":    currentVersionStage,
		"MoveToVersionId": pendingVersionID,
	})
	currentResp = callKMS(t, mux, "secretsmanager.GetSecretValue", map[string]any{
		"SecretId":     "prod/app/database",
		"VersionStage": currentVersionStage,
	})
	if got, _ := currentResp["VersionId"].(string); got != pendingVersionID {
		t.Fatalf("expected promoted current version id: %q want %q", got, pendingVersionID)
	}

	callKMS(t, mux, "secretsmanager.CancelRotateSecret", map[string]any{"SecretId": "prod/app/database"})
	validateResp := callKMS(t, mux, "secretsmanager.ValidateResourcePolicy", map[string]any{"ResourcePolicy": policyDoc})
	if passed, _ := validateResp["PolicyValidationPassed"].(bool); !passed {
		t.Fatalf("expected valid policy response: %#v", validateResp)
	}

	callKMS(t, mux, "secretsmanager.DeleteSecret", map[string]any{
		"SecretId":             "prod/app/database",
		"RecoveryWindowInDays": 7,
	})
	rec := post(t, mux, "secretsmanager.GetSecretValue", map[string]any{"SecretId": "prod/app/database"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status got %d want %d", rec.Code, http.StatusBadRequest)
	}
	assertAWSErrorType(t, rec.Body.Bytes(), "InvalidRequestException")

	callKMS(t, mux, "secretsmanager.RestoreSecret", map[string]any{"SecretId": "prod/app/database"})
	restoredResp := callKMS(t, mux, "secretsmanager.GetSecretValue", map[string]any{"SecretId": "prod/app/database"})
	if got, _ := restoredResp["SecretString"].(string); got != `{"password":"two"}` {
		t.Fatalf("unexpected restored secret string: %q", got)
	}
}

func TestSecretsAdminPageRenders(t *testing.T) {
	key := sampleKey(1)
	store := &inMemoryStore{k: key}
	if _, _, err := store.CreateSecret(context.Background(), createSecretRequest{
		Name:         "prod/ui/secret",
		Description:  "ui secret",
		SecretString: `{"token":"abc"}`,
	}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	s := &server{cfg: config{}, store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/secrets", s.handleSecretsAdmin)

	listReq := httptest.NewRequest(http.MethodGet, "/admin/secrets", nil)
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("unexpected list page status: %d", listRec.Code)
	}
	listBody := listRec.Body.String()
	if !strings.Contains(listBody, "Secrets Manager") || !strings.Contains(listBody, "prod/ui/secret") {
		t.Fatalf("unexpected list page body: %s", listBody)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/secrets?secret_id=prod/ui/secret&tab=retrieve", nil)
	detailRec := httptest.NewRecorder()
	mux.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("unexpected detail page status: %d", detailRec.Code)
	}
	detailBody := detailRec.Body.String()
	if !strings.Contains(detailBody, "Retrieve secret value") || !strings.Contains(detailBody, "token") || !strings.Contains(detailBody, "abc") {
		t.Fatalf("unexpected detail page body: %s", detailBody)
	}

	policyReq := httptest.NewRequest(http.MethodGet, "/admin/secrets?secret_id=prod/ui/secret&tab=policy", nil)
	policyRec := httptest.NewRecorder()
	mux.ServeHTTP(policyRec, policyReq)
	if policyRec.Code != http.StatusOK {
		t.Fatalf("unexpected policy page status: %d", policyRec.Code)
	}
	policyBody := policyRec.Body.String()
	if !strings.Contains(policyBody, "Resource policy") || !strings.Contains(policyBody, "Rotation") || !strings.Contains(policyBody, "Tags") {
		t.Fatalf("unexpected policy page body: %s", policyBody)
	}
}

func sampleKey(seed byte) kmsKey {
	return kmsKey{
		ID:           "key-" + string(rune('0'+seed)),
		ARN:          "arn:aws:kms:local:000000000000:key/key-" + string(rune('0'+seed)),
		MasterKeyRaw: bytes.Repeat([]byte{seed}, 32),
		Description:  "test key",
		CreatedAt:    time.Unix(int64(seed), 0).UTC(),
		Enabled:      true,
	}
}

func assertAWSErrorType(t *testing.T, body []byte, wantType string) {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got, _ := resp["__type"].(string); got != wantType {
		t.Fatalf("unexpected error type: got %q want %q body=%s", got, wantType, string(body))
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
