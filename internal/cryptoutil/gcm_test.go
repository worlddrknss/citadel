package cryptoutil

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
	nonce := make([]byte, GCMNonceSize)
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

	got, err := GCMOpen(key, blob, aad)
	if err != nil || !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("gcmOpen(legacy) = %q, %v", got, err)
	}
}

func TestGCMSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	blob, err := GCMSeal(key, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := GCMOpen(key, blob, []byte("aad")); err != nil || string(got) != "secret" {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	if _, err := GCMOpen(key, blob, []byte("other")); err == nil {
		t.Fatal("wrong AAD must fail")
	}
}
