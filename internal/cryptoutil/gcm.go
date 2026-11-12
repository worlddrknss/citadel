package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
)

const (
	CipherBlobVersionV1 byte = 1
)

func CanonicalContext(ctx map[string]string) []byte {
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

// AES-GCM with the nonce generated inside Go's FIPS 140-3 module
// (cipher.NewGCMWithRandomNonce): FIPS 140-only mode refuses GCM with
// caller-supplied IVs. Its output is nonce || ciphertext || tag, the same
// layout citadel has always stored, so existing data decrypts unchanged.
const GCMNonceSize = 12

func GCMSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plaintext, aad), nil
}

func GCMOpen(key, blob, aad []byte) ([]byte, error) {
	if len(blob) <= GCMNonceSize {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, blob, aad)
}

func EncryptBlob(masterKey []byte, keyID string, plaintext, aad []byte) ([]byte, error) {
	raw, err := GCMSeal(masterKey, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return EncodeCipherBlob(keyID, raw), nil
}

func EncryptLegacyBlob(masterKey, plaintext, aad []byte) ([]byte, error) {
	return GCMSeal(masterKey, plaintext, aad)
}

func DecryptBlob(masterKey, blob, aad []byte) ([]byte, error) {
	return GCMOpen(masterKey, blob, aad)
}

func DecodeCipherBlob(blob []byte) (string, []byte, error) {
	if len(blob) < 2 || blob[0] != CipherBlobVersionV1 {
		return "", blob, nil
	}
	keyLen := int(blob[1])
	if len(blob) < 2+keyLen {
		return "", blob, nil
	}
	keyID := string(blob[2 : 2+keyLen])
	raw := blob[2+keyLen:]
	if len(raw) < 12+16 {
		return "", blob, nil
	}
	return keyID, raw, nil
}

func EncodeCipherBlob(keyID string, raw []byte) []byte {
	if keyID == "" {
		return raw
	}
	keyBytes := []byte(keyID)
	if len(keyBytes) > 255 {
		return raw
	}
	out := make([]byte, 0, 2+len(keyBytes)+len(raw))
	out = append(out, CipherBlobVersionV1)
	out = append(out, byte(len(keyBytes)))
	out = append(out, keyBytes...)
	out = append(out, raw...)
	return out
}
