package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

const (
	defaultSignAlgRSA  = "RSASSA_PKCS1_V1_5_SHA_256"
	defaultSignAlgP256 = "ECDSA_SHA_256"
	defaultSignAlgP384 = "ECDSA_SHA_384"
)

func parsePrivateKey(raw []byte) (crypto.Signer, crypto.PublicKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("parsed private key does not implement crypto.Signer")
	}
	return signer, signer.Public(), nil
}

func publicKeyBytesFromRaw(raw []byte) ([]byte, error) {
	_, pub, err := parsePrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pub)
}

func keyUsageAndSpecForMetadata(key store.KMSKey) (string, string) {
	usage := store.NormalizeKeyUsage(key.KeyUsage)
	if usage == "" {
		usage = store.KeyUsageEncryptDecrypt
	}
	spec := strings.ToUpper(strings.TrimSpace(key.KeySpec))
	if spec == "" {
		spec = store.DefaultKeySpecForUsage(usage)
	}
	return usage, spec
}

// keySpecForPublicKey maps an imported public key to the matching KMS key spec.
func keySpecForPublicKey(pub crypto.PublicKey) (string, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		switch p.N.BitLen() {
		case 2048:
			return store.KeySpecRSA2048, nil
		case 3072:
			return store.KeySpecRSA3072, nil
		case 4096:
			return store.KeySpecRSA4096, nil
		default:
			return "", fmt.Errorf("unsupported RSA key size %d bits (want 2048, 3072 or 4096)", p.N.BitLen())
		}
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			return store.KeySpecECCP256, nil
		case elliptic.P384():
			return store.KeySpecECCP384, nil
		default:
			return "", fmt.Errorf("unsupported EC curve (want P-256 or P-384)")
		}
	default:
		return "", fmt.Errorf("unsupported public key type %T (want RSA or ECDSA)", pub)
	}
}

// defaultSigningAlgorithmForKey returns the canonical KMS signing-algorithm name
// for a SIGN_VERIFY key based on its key spec.
func defaultSigningAlgorithmForKey(key store.KMSKey) string {
	if algs := keySigningAlgorithms(key); len(algs) > 0 {
		return algs[0]
	}
	return defaultSignAlgRSA
}

func keySigningAlgorithms(key store.KMSKey) []string {
	usage, spec := keyUsageAndSpecForMetadata(key)
	if usage != store.KeyUsageSignVerify {
		return nil
	}
	switch spec {
	case store.KeySpecRSA2048, store.KeySpecRSA3072, store.KeySpecRSA4096:
		return []string{defaultSignAlgRSA}
	case store.KeySpecECCP256:
		return []string{defaultSignAlgP256}
	case store.KeySpecECCP384:
		return []string{defaultSignAlgP384}
	default:
		return nil
	}
}

func keyPublicKeyBase64(key store.KMSKey) (string, error) {
	if len(key.PublicKeyRaw) == 0 {
		return "", errors.New("public key unavailable")
	}
	return base64.StdEncoding.EncodeToString(key.PublicKeyRaw), nil
}

func signDigestWithKey(key store.KMSKey, signingAlgorithm string, digest []byte) ([]byte, error) {
	usage, spec := keyUsageAndSpecForMetadata(key)
	if usage != store.KeyUsageSignVerify {
		return nil, fmt.Errorf("key %s does not support signing", key.ID)
	}
	priv, _, err := parsePrivateKey(key.MasterKeyRaw)
	if err != nil {
		return nil, err
	}
	hashFunc, err := hashForSigningAlgorithm(signingAlgorithm, spec)
	if err != nil {
		return nil, err
	}
	return priv.Sign(rand.Reader, digest, hashFunc)
}

func verifyDigestWithKey(key store.KMSKey, signingAlgorithm string, digest, signature []byte) (bool, error) {
	usage, spec := keyUsageAndSpecForMetadata(key)
	if usage != store.KeyUsageSignVerify {
		return false, fmt.Errorf("key %s does not support verification", key.ID)
	}
	_, pub, err := parsePrivateKey(key.MasterKeyRaw)
	if err != nil {
		return false, err
	}
	hashFunc, err := hashForSigningAlgorithm(signingAlgorithm, spec)
	if err != nil {
		return false, err
	}
	switch publicKey := pub.(type) {
	case *rsa.PublicKey:
		return true, rsa.VerifyPKCS1v15(publicKey, hashFunc, digest, signature)
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(publicKey, digest, signature), nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func hashForSigningAlgorithm(signingAlgorithm, keySpec string) (crypto.Hash, error) {
	signingAlgorithm = strings.ToUpper(strings.TrimSpace(signingAlgorithm))
	switch signingAlgorithm {
	case "":
		switch keySpec {
		case store.KeySpecECCP384:
			return crypto.SHA384, nil
		case store.KeySpecRSA4096:
			return crypto.SHA512, nil
		default:
			return crypto.SHA256, nil
		}
	case defaultSignAlgRSA:
		return crypto.SHA256, nil
	case "RSASSA_PKCS1_V1_5_SHA_384":
		return crypto.SHA384, nil
	case "RSASSA_PKCS1_V1_5_SHA_512":
		return crypto.SHA512, nil
	case defaultSignAlgP256:
		return crypto.SHA256, nil
	case defaultSignAlgP384:
		return crypto.SHA384, nil
	case "ECDSA_SHA_512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported signing algorithm %q", signingAlgorithm)
	}
}

func signableDigest(message, messageType string, signingAlgorithm string, keySpec string) ([]byte, crypto.Hash, error) {
	hashFunc, err := hashForSigningAlgorithm(signingAlgorithm, keySpec)
	if err != nil {
		return nil, 0, err
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(message))
	if err != nil {
		return nil, 0, err
	}
	if strings.EqualFold(strings.TrimSpace(messageType), "DIGEST") {
		return data, hashFunc, nil
	}
	if !hashFunc.Available() {
		return nil, 0, fmt.Errorf("hash %v not available", hashFunc)
	}
	h := hashFunc.New()
	if _, err := h.Write(data); err != nil {
		return nil, 0, err
	}
	return h.Sum(nil), hashFunc, nil
}
