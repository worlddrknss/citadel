package main

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGenerateKeyMaterialSymmetricDefaults(t *testing.T) {
	raw, publicRaw, usage, spec, err := generateKeyMaterial("", "")
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32-byte symmetric key, got %d", len(raw))
	}
	if publicRaw != nil {
		t.Fatalf("expected nil public key for symmetric key, got %d bytes", len(publicRaw))
	}
	if usage != keyUsageEncryptDecrypt {
		t.Fatalf("expected %q, got %q", keyUsageEncryptDecrypt, usage)
	}
	if spec != keySpecSymmetricDefault {
		t.Fatalf("expected %q, got %q", keySpecSymmetricDefault, spec)
	}
}

func TestGenerateKeyMaterialAndSignVerify(t *testing.T) {
	raw, publicRaw, usage, spec, err := generateKeyMaterial(keyUsageSignVerify, keySpecECCP256)
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	key := kmsKey{
		ID:           "test-key",
		MasterKeyRaw: raw,
		PublicKeyRaw: publicRaw,
		KeyUsage:     usage,
		KeySpec:      spec,
	}
	digest := sha256.Sum256([]byte("citadel"))
	sig, err := signDigestWithKey(key, "", digest[:])
	if err != nil {
		t.Fatalf("signDigestWithKey: %v", err)
	}
	ok, err := verifyDigestWithKey(key, "", digest[:], sig)
	if err != nil {
		t.Fatalf("verifyDigestWithKey: %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
	pubB64, err := keyPublicKeyBase64(key)
	if err != nil {
		t.Fatalf("keyPublicKeyBase64: %v", err)
	}
	if pubB64 == "" {
		t.Fatal("expected base64 public key output")
	}
	if _, err := base64.StdEncoding.DecodeString(pubB64); err != nil {
		t.Fatalf("public key should be valid base64: %v", err)
	}
}

func TestKeySigningAlgorithms(t *testing.T) {
	_, publicRaw, usage, spec, err := generateKeyMaterial(keyUsageSignVerify, keySpecRSA2048)
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	key := kmsKey{PublicKeyRaw: publicRaw, KeyUsage: usage, KeySpec: spec}
	algs := keySigningAlgorithms(key)
	if len(algs) != 1 || algs[0] != defaultSignAlgRSA {
		t.Fatalf("unexpected signing algorithms: %#v", algs)
	}
}
