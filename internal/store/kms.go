package store

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ManagedDefaultAlias is the per-account alias that always resolves to that
// account's immutable, system-provisioned default encryption key. Every account
// owns exactly one such alias; it cannot be deleted, re-pointed, or created by
// callers.
const ManagedDefaultAlias = "alias/default"

// ErrImmutableManagedKey is returned when an operation would disable, delete, or
// re-alias an account's managed default key (or its alias/default alias).
var ErrImmutableManagedKey = errors.New("the account default key is immutable: it cannot be disabled, deleted, or re-aliased")

const (
	KeyUsageEncryptDecrypt  = "ENCRYPT_DECRYPT"
	KeyUsageSignVerify      = "SIGN_VERIFY"
	KeySpecSymmetricDefault = "SYMMETRIC_DEFAULT"
	KeySpecRSA2048          = "RSA_2048"
	KeySpecRSA3072          = "RSA_3072"
	KeySpecRSA4096          = "RSA_4096"
	KeySpecECCP256          = "ECC_NIST_P256"
	KeySpecECCP384          = "ECC_NIST_P384"
)

func NormalizeKeyUsage(keyUsage string) string {
	keyUsage = strings.ToUpper(strings.TrimSpace(keyUsage))
	if keyUsage == "" {
		return KeyUsageEncryptDecrypt
	}
	if keyUsage != KeyUsageEncryptDecrypt && keyUsage != KeyUsageSignVerify {
		return KeyUsageEncryptDecrypt
	}
	return keyUsage
}

func DefaultKeySpecForUsage(keyUsage string) string {
	switch NormalizeKeyUsage(keyUsage) {
	case KeyUsageSignVerify:
		return KeySpecECCP256
	default:
		return KeySpecSymmetricDefault
	}
}

func NormalizeKeySpec(keyUsage, keySpec string) (string, error) {
	keyUsage = NormalizeKeyUsage(keyUsage)
	keySpec = strings.ToUpper(strings.TrimSpace(keySpec))
	if keySpec == "" {
		return DefaultKeySpecForUsage(keyUsage), nil
	}
	switch keyUsage {
	case KeyUsageEncryptDecrypt:
		if keySpec != KeySpecSymmetricDefault {
			return "", fmt.Errorf("invalid key spec %q for %s", keySpec, keyUsage)
		}
		return KeySpecSymmetricDefault, nil
	case KeyUsageSignVerify:
		switch keySpec {
		case KeySpecRSA2048, KeySpecRSA3072, KeySpecRSA4096, KeySpecECCP256, KeySpecECCP384:
			return keySpec, nil
		default:
			return "", fmt.Errorf("invalid key spec %q for %s", keySpec, keyUsage)
		}
	default:
		return "", fmt.Errorf("unsupported key usage %q", keyUsage)
	}
}

func GenerateKeyMaterial(keyUsage, keySpec string) ([]byte, []byte, string, string, error) {
	keyUsage = NormalizeKeyUsage(keyUsage)
	normalizedSpec, err := NormalizeKeySpec(keyUsage, keySpec)
	if err != nil {
		return nil, nil, "", "", err
	}
	switch keyUsage {
	case KeyUsageEncryptDecrypt:
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, "", "", err
		}
		return raw, nil, KeyUsageEncryptDecrypt, KeySpecSymmetricDefault, nil
	case KeyUsageSignVerify:
		priv, pub, err := GenerateSigningKey(normalizedSpec)
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
		return privDER, pubDER, KeyUsageSignVerify, normalizedSpec, nil
	default:
		return nil, nil, "", "", fmt.Errorf("unsupported key usage %q", keyUsage)
	}
}

func GenerateSigningKey(keySpec string) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch keySpec {
	case KeySpecRSA2048:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case KeySpecRSA3072:
		priv, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case KeySpecRSA4096:
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case KeySpecECCP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case KeySpecECCP384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key spec %q", keySpec)
	}
}

type KMSKey struct {
	ID           string
	ARN          string
	MasterKeyRaw []byte
	PublicKeyRaw []byte
	Description  string
	CreatedAt    time.Time
	Enabled      bool
	DeletionDate *time.Time
	KeyUsage     string
	KeySpec      string
	// Managed marks an immutable, system-provisioned key (an account's default
	// key reached via alias/default). Managed keys cannot be disabled, deleted,
	// or re-aliased.
	Managed bool
}

type KMSAlias struct {
	AliasName   string
	TargetKeyID string
}

type KMSGrant struct {
	GrantID           string
	GrantToken        string
	KeyID             string
	GranteePrincipal  string
	RetiringPrincipal string
	Operations        []string
	Name              string
	CreatedAt         time.Time
}

type CreateGrantRequest struct {
	KeyID             string   `json:"KeyId"`
	GranteePrincipal  string   `json:"GranteePrincipal"`
	RetiringPrincipal string   `json:"RetiringPrincipal"`
	Operations        []string `json:"Operations"`
	Name              string   `json:"Name"`
}

func DefaultKeyPolicy(key KMSKey) string {
	policy := map[string]any{
		"Version": "2012-10-17",
		"Id":      "go-kms-default-policy-" + key.ID,
		"Statement": []map[string]any{
			{
				"Sid":       "EnableRootPermissions",
				"Effect":    "Allow",
				"Principal": "*",
				"Action":    "kms:*",
				"Resource":  "*",
			},
		},
	}
	b, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}
