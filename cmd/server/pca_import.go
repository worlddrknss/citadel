package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// parseCertificatePEM decodes the first CERTIFICATE block from PEM input.
func parseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("no PEM-encoded CERTIFICATE block found")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return cert, nil
		}
		pemBytes = rest
	}
}

// parsePrivateKeyPEM decodes a PEM-encoded private key, accepting PKCS#8,
// PKCS#1 (RSA) and SEC1 (EC) encodings. Encrypted keys are rejected.
func parsePrivateKeyPEM(pemBytes []byte) (crypto.Signer, crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM-encoded private key block found")
	}
	//nolint:staticcheck // x509.IsEncryptedPEMBlock is deprecated but still the
	// simplest way to give a clear error for passphrase-protected keys.
	if x509.IsEncryptedPEMBlock(block) {
		return nil, nil, fmt.Errorf("encrypted private keys are not supported; decrypt the key before importing")
	}

	var (
		parsed any
		err    error
	)
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		if parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			if parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
				parsed, err = x509.ParseECPrivateKey(block.Bytes)
			}
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported private key type %T", parsed)
	}
	return signer, signer.Public(), nil
}

// publicKeysEqual reports whether two public keys are identical.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	if ae, ok := a.(equaler); ok {
		return ae.Equal(b)
	}
	return false
}

// certIsSelfSigned reports whether a certificate's subject equals its issuer.
func certIsSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer)
}

// caPathLength extracts the path-length constraint from a CA certificate, if set.
func caPathLength(c *x509.Certificate) *int {
	if !c.BasicConstraintsValid {
		return nil
	}
	if c.MaxPathLen > 0 || c.MaxPathLenZero {
		pl := c.MaxPathLen
		return &pl
	}
	return nil
}
