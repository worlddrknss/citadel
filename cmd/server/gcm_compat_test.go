package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// Data sealed by earlier versions (caller-generated nonce, nonce || ciphertext)
// must still decrypt with the module-generated-nonce AEAD.
func TestGCMOpensDataSealedWithCallerNonce(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, gcmNonceSize)
	rand.Read(key)
	rand.Read(nonce)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := cipher.NewGCM(block)
	if err != nil {
		t.Skipf("cannot produce legacy ciphertext in this mode: %v", err)
	}
	aad := []byte("key-id")
	blob := append(append([]byte{}, nonce...), legacy.Seal(nil, nonce, []byte("secret"), aad)...)

	got, err := gcmOpen(key, blob, aad)
	if err != nil || !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("gcmOpen(legacy) = %q, %v", got, err)
	}
}

func TestGCMSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	blob, err := gcmSeal(key, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := gcmOpen(key, blob, []byte("aad")); err != nil || string(got) != "secret" {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	if _, err := gcmOpen(key, blob, []byte("other")); err == nil {
		t.Fatal("wrong AAD must fail")
	}
}

func TestWrapUnwrapKeyMaterialRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s := &dbStore{wrappingKey: key}
	wrapped, nonce, err := s.wrapKeyMaterial("key-1", []byte("material"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.unwrapKeyMaterial("key-1", wrapped, nonce)
	if err != nil || string(got) != "material" {
		t.Fatalf("unwrap = %q, %v", got, err)
	}
	if _, err := s.unwrapKeyMaterial("key-2", wrapped, nonce); err == nil {
		t.Fatal("unwrap with another key ID must fail")
	}
}
