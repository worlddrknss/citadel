package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// KMS cryptographic operations shared by the AWS API (TrentService.*) and
// the native /v1/kms endpoints. Only FIPS 140-3 approved algorithms are
// offered: AES-256-GCM, RSAES-OAEP with SHA-256, RSASSA-PSS and PKCS #1 v1.5
// with SHA-2, and ECDSA on P-256/P-384.

const (
	encAlgSymmetric  = "SYMMETRIC_DEFAULT"
	encAlgRSAOAEP256 = "RSAES_OAEP_SHA_256"

	// maxSymmetricPlaintext is AWS KMS's Encrypt limit.
	maxSymmetricPlaintext = 4096
)

// kmsOpError is a client-facing failure of a KMS operation: Type is the AWS
// error type (also mapped to a native error code) and Message is safe to
// return to the caller.
type kmsOpError struct {
	Type    string
	Message string
}

func (e *kmsOpError) Error() string { return e.Type + ": " + e.Message }

func opErr(typ, msg string) error { return &kmsOpError{Type: typ, Message: msg} }

func keyEncryptionAlgorithms(key store.KMSKey) []string {
	usage, spec := keyUsageAndSpecForMetadata(key)
	if usage != store.KeyUsageEncryptDecrypt {
		return nil
	}
	if spec == store.KeySpecSymmetricDefault {
		return []string{encAlgSymmetric}
	}
	return []string{encAlgRSAOAEP256}
}

// key. An empty algorithm keeps the legacy default for the key spec.
func checkSigningAlgorithm(key store.KMSKey, alg string) error {
	alg = strings.ToUpper(strings.TrimSpace(alg))
	if alg == "" {
		return nil
	}
	for _, a := range keySigningAlgorithms(key) {
		if a == alg {
			return nil
		}
	}
	return fmt.Errorf("signing algorithm %q is not valid for this key", alg)
}

// long), otherwise its hash.
// resolveEncryptionAlgorithm checks alg against the key: symmetric keys
// take SYMMETRIC_DEFAULT (the default), RSA keys require RSAES_OAEP_SHA_256.
func resolveEncryptionAlgorithm(key store.KMSKey, alg string) (string, error) {
	usage, spec := keyUsageAndSpecForMetadata(key)
	if usage != store.KeyUsageEncryptDecrypt {
		return "", opErr("InvalidKeyUsageException", "key does not support encryption")
	}
	alg = strings.ToUpper(strings.TrimSpace(alg))
	if spec == store.KeySpecSymmetricDefault {
		if alg == "" || alg == encAlgSymmetric {
			return encAlgSymmetric, nil
		}
		return "", opErr("InvalidKeyUsageException", "symmetric keys support only SYMMETRIC_DEFAULT")
	}
	if alg == encAlgRSAOAEP256 {
		return alg, nil
	}
	if alg == "" {
		return "", opErr("ValidationException", "EncryptionAlgorithm is required for asymmetric keys")
	}
	return "", opErr("InvalidKeyUsageException", "RSA keys support only RSAES_OAEP_SHA_256")
}

// rsaOAEPMaxPlaintext is the largest message RSAES-OAEP-SHA-256 can carry.
func rsaOAEPMaxPlaintext(pub *rsa.PublicKey) int {
	return pub.Size() - 2*sha256.Size - 2
}

func rsaPublicKey(key store.KMSKey) (*rsa.PublicKey, error) {
	if len(key.PublicKeyRaw) > 0 {
		parsed, err := x509.ParsePKIXPublicKey(key.PublicKeyRaw)
		if err == nil {
			if pub, ok := parsed.(*rsa.PublicKey); ok {
				return pub, nil
			}
		}
	}
	_, pub, err := parsePrivateKey(key.MasterKeyRaw)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rsaPub, nil
}

// kmsEncrypt encrypts plaintext under key. Errors are *kmsOpError for client
// mistakes; anything else is an internal failure.
func kmsEncrypt(key store.KMSKey, alg string, plaintext []byte, encCtx map[string]string) ([]byte, string, error) {
	alg, err := resolveEncryptionAlgorithm(key, alg)
	if err != nil {
		return nil, "", err
	}
	if len(plaintext) == 0 {
		return nil, "", opErr("ValidationException", "Plaintext must not be empty")
	}
	if alg == encAlgSymmetric {
		if len(plaintext) > maxSymmetricPlaintext {
			return nil, "", opErr("ValidationException", "Plaintext must be at most 4096 bytes")
		}
		blob, err := key.EncryptBlob(plaintext, cryptoutil.CanonicalContext(encCtx))
		return blob, alg, err
	}
	if len(encCtx) > 0 {
		return nil, "", opErr("ValidationException", "EncryptionContext is not supported with asymmetric keys")
	}
	pub, err := rsaPublicKey(key)
	if err != nil {
		return nil, "", err
	}
	if len(plaintext) > rsaOAEPMaxPlaintext(pub) {
		return nil, "", opErr("ValidationException", fmt.Sprintf("Plaintext must be at most %d bytes for this key", rsaOAEPMaxPlaintext(pub)))
	}
	out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
	return out, alg, err
}

// kmsDecrypt reverses kmsEncrypt. Any failure to open the ciphertext is an
// InvalidCiphertextException with no detail.
func kmsDecrypt(key store.KMSKey, alg string, blob []byte, encCtx map[string]string) ([]byte, string, error) {
	alg, err := resolveEncryptionAlgorithm(key, alg)
	if err != nil {
		return nil, "", err
	}
	if alg == encAlgSymmetric {
		out, err := key.DecryptBlob(blob, cryptoutil.CanonicalContext(encCtx))
		if err != nil {
			return nil, "", opErr("InvalidCiphertextException", "decrypt failed")
		}
		return out, alg, nil
	}
	if len(encCtx) > 0 {
		return nil, "", opErr("ValidationException", "EncryptionContext is not supported with asymmetric keys")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(key.MasterKeyRaw)
	if err != nil {
		return nil, "", err
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, "", errors.New("not an RSA key")
	}
	out, err := rsa.DecryptOAEP(sha256.New(), nil, priv, blob, nil)
	if err != nil {
		return nil, "", opErr("InvalidCiphertextException", "decrypt failed")
	}
	return out, alg, nil
}
