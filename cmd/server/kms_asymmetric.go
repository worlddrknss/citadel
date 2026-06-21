package main

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
)

const (
	keyUsageEncryptDecrypt  = "ENCRYPT_DECRYPT"
	keyUsageSignVerify      = "SIGN_VERIFY"
	keySpecSymmetricDefault = "SYMMETRIC_DEFAULT"
	keySpecRSA2048          = "RSA_2048"
	keySpecRSA3072          = "RSA_3072"
	keySpecRSA4096          = "RSA_4096"
	keySpecECCP256          = "ECC_NIST_P256"
	keySpecECCP384          = "ECC_NIST_P384"

	defaultSignAlgRSA  = "RSASSA_PKCS1_V1_5_SHA_256"
	defaultSignAlgP256 = "ECDSA_SHA_256"
	defaultSignAlgP384 = "ECDSA_SHA_384"
)

func normalizeKeyUsage(keyUsage string) string {
	keyUsage = strings.ToUpper(strings.TrimSpace(keyUsage))
	if keyUsage == "" {
		return keyUsageEncryptDecrypt
	}
	if keyUsage != keyUsageEncryptDecrypt && keyUsage != keyUsageSignVerify {
		return keyUsageEncryptDecrypt
	}
	return keyUsage
}

func defaultKeySpecForUsage(keyUsage string) string {
	switch normalizeKeyUsage(keyUsage) {
	case keyUsageSignVerify:
		return keySpecECCP256
	default:
		return keySpecSymmetricDefault
	}
}

func normalizeKeySpec(keyUsage, keySpec string) (string, error) {
	keyUsage = normalizeKeyUsage(keyUsage)
	keySpec = strings.ToUpper(strings.TrimSpace(keySpec))
	if keySpec == "" {
		return defaultKeySpecForUsage(keyUsage), nil
	}
	switch keyUsage {
	case keyUsageEncryptDecrypt:
		if keySpec != keySpecSymmetricDefault {
			return "", fmt.Errorf("invalid key spec %q for %s", keySpec, keyUsage)
		}
		return keySpecSymmetricDefault, nil
	case keyUsageSignVerify:
		switch keySpec {
		case keySpecRSA2048, keySpecRSA3072, keySpecRSA4096, keySpecECCP256, keySpecECCP384:
			return keySpec, nil
		default:
			return "", fmt.Errorf("invalid key spec %q for %s", keySpec, keyUsage)
		}
	default:
		return "", fmt.Errorf("unsupported key usage %q", keyUsage)
	}
}

func generateKeyMaterial(keyUsage, keySpec string) ([]byte, []byte, string, string, error) {
	keyUsage = normalizeKeyUsage(keyUsage)
	normalizedSpec, err := normalizeKeySpec(keyUsage, keySpec)
	if err != nil {
		return nil, nil, "", "", err
	}
	switch keyUsage {
	case keyUsageEncryptDecrypt:
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, "", "", err
		}
		return raw, nil, keyUsageEncryptDecrypt, keySpecSymmetricDefault, nil
	case keyUsageSignVerify:
		priv, pub, err := generateSigningKey(normalizedSpec)
		if err != nil {
			return nil, nil, "", "", err
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, "", "", err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, nil, "", "", err
		}
		return privDER, pubDER, keyUsageSignVerify, normalizedSpec, nil
	default:
		return nil, nil, "", "", fmt.Errorf("unsupported key usage %q", keyUsage)
	}
}

func generateSigningKey(keySpec string) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch keySpec {
	case keySpecRSA2048:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case keySpecRSA3072:
		priv, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case keySpecRSA4096:
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case keySpecECCP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case keySpecECCP384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key spec %q", keySpec)
	}
}

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

func keyUsageAndSpecForMetadata(key kmsKey) (string, string) {
	usage := normalizeKeyUsage(key.KeyUsage)
	if usage == "" {
		usage = keyUsageEncryptDecrypt
	}
	spec := strings.ToUpper(strings.TrimSpace(key.KeySpec))
	if spec == "" {
		spec = defaultKeySpecForUsage(usage)
	}
	return usage, spec
}

func keySigningAlgorithms(key kmsKey) []string {
	usage, spec := keyUsageAndSpecForMetadata(key)
	if usage != keyUsageSignVerify {
		return nil
	}
	switch spec {
	case keySpecRSA2048, keySpecRSA3072, keySpecRSA4096:
		return []string{defaultSignAlgRSA}
	case keySpecECCP256:
		return []string{defaultSignAlgP256}
	case keySpecECCP384:
		return []string{defaultSignAlgP384}
	default:
		return nil
	}
}

func keyPublicKeyBase64(key kmsKey) (string, error) {
	if len(key.PublicKeyRaw) == 0 {
		return "", errors.New("public key unavailable")
	}
	return base64.StdEncoding.EncodeToString(key.PublicKeyRaw), nil
}

func signDigestWithKey(key kmsKey, signingAlgorithm string, digest []byte) ([]byte, error) {
	usage, spec := keyUsageAndSpecForMetadata(key)
	if usage != keyUsageSignVerify {
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

func verifyDigestWithKey(key kmsKey, signingAlgorithm string, digest, signature []byte) (bool, error) {
	usage, spec := keyUsageAndSpecForMetadata(key)
	if usage != keyUsageSignVerify {
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
		case keySpecECCP384:
			return crypto.SHA384, nil
		case keySpecRSA4096:
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
