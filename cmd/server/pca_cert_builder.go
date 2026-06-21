package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"
)

// kmsSigner implements crypto.Signer interface, delegating to internal KMS signing
type kmsSigner struct {
	keyID     string
	signer    internalSignerFunc
	ctx       context.Context
	pubKey    crypto.PublicKey
	algorithm string
}

// newKMSSigner creates a crypto.Signer that delegates to KMS
func newKMSSigner(ctx context.Context, store keyStore, key kmsKey, algorithm string) (*kmsSigner, error) {
	// PublicKeyRaw is already DER-encoded bytes
	pubKey, err := x509.ParsePKIXPublicKey(key.PublicKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	return &kmsSigner{
		keyID:     key.ID,
		signer:    newInternalSigner(store),
		ctx:       ctx,
		pubKey:    pubKey,
		algorithm: algorithm,
	}, nil
}

// Public returns the public key
func (ks *kmsSigner) Public() crypto.PublicKey {
	return ks.pubKey
}

// Sign implements crypto.Signer interface, delegating to KMS
func (ks *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Call internal KMS signing
	return ks.signer(ks.ctx, ks.keyID, ks.algorithm, digest)
}

// generateSerialNumber generates a deterministic serial number for a certificate
func generateSerialNumber() (*big.Int, error) {
	// Generate a random 128-bit number for the serial
	// AWS uses positive integers; crypto/x509 expects big.Int
	serialRaw := make([]byte, 16)
	_, err := rand.Read(serialRaw)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	// Ensure positive by clearing the high bit
	serialRaw[0] &= 0x7F

	serial := new(big.Int).SetBytes(serialRaw)
	return serial, nil
}

// parseCSR parses a PEM-encoded PKCS#10 CSR
func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR: must be PEM-encoded CERTIFICATE REQUEST")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}

	// Verify CSR signature
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}

	return csr, nil
}

// buildRootCA creates and self-signs a root CA certificate
// The CA must have a SIGN_VERIFY KMS key; we use the public key directly
func buildRootCA(ca pcaCertificateAuthority, kmsKey kmsKey) (certPEM, certDER []byte, err error) {
	// PublicKeyRaw is already DER-encoded bytes
	pubKey, err := x509.ParsePKIXPublicKey(kmsKey.PublicKeyRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA public key: %w", err)
	}

	// Parse subject DN from CA record
	subject, err := parseDistinguishedName(ca.SubjectDN)
	if err != nil {
		return nil, nil, fmt.Errorf("parse subject DN: %w", err)
	}

	// Generate serial number
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// Build template
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		Issuer:       subject,
		NotBefore:    ca.NotBefore.Truncate(time.Second),
		NotAfter:     ca.NotAfter.Truncate(time.Second),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,

		// Self-signed
		PublicKey:          pubKey,
		SignatureAlgorithm: x509.SHA256WithRSA, // Will be overridden based on key type
	}

	// For RSA keys
	if _, ok := pubKey.(*rsa.PublicKey); ok {
		template.SignatureAlgorithm = x509.SHA256WithRSA
	}

	// For ECDSA keys
	if _, ok := pubKey.(*ecdsa.PublicKey); ok {
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	}

	// Create the certificate using the KMS signer (self-signed)
	certDER, err = x509.CreateCertificate(rand.Reader, template, template, pubKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create root cert: %w", err)
	}

	// Encode to PEM
	certPEM = encodeCertificatePEM(certDER)

	return certPEM, certDER, nil
}

// buildRootCAWithSigner creates a self-signed root CA certificate using the provided signer
func buildRootCAWithSigner(ca pcaCertificateAuthority, kmsKey kmsKey, signer crypto.Signer) (certPEM, certDER []byte, err error) {
	// PublicKeyRaw is already DER-encoded bytes
	pubKey, err := x509.ParsePKIXPublicKey(kmsKey.PublicKeyRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA public key: %w", err)
	}

	// Parse subject DN from CA record
	subject, err := parseDistinguishedName(ca.SubjectDN)
	if err != nil {
		return nil, nil, fmt.Errorf("parse subject DN: %w", err)
	}

	// Generate serial number
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// Build template
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		Issuer:       subject,
		NotBefore:    ca.NotBefore.Truncate(time.Second),
		NotAfter:     ca.NotAfter.Truncate(time.Second),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,

		PublicKey:          pubKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Set signature algorithm based on key type
	if _, ok := pubKey.(*rsa.PublicKey); ok {
		template.SignatureAlgorithm = x509.SHA256WithRSA
	}
	if _, ok := pubKey.(*ecdsa.PublicKey); ok {
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	}

	// Create the certificate using the provided signer
	certDER, err = x509.CreateCertificate(rand.Reader, template, template, pubKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("create root cert: %w", err)
	}

	// Encode to PEM
	certPEM = encodeCertificatePEM(certDER)

	return certPEM, certDER, nil
}

// buildLeafCertificate creates a leaf certificate from a CSR, signed by the CA
func buildLeafCertificate(csr *x509.CertificateRequest, ca pcaCertificateAuthority, validity validitySpec, kmsKey kmsKey) (certPEM []byte, err error) {
	// Validate CSR subject
	if csr.Subject.String() == "" {
		return nil, fmt.Errorf("CSR must have subject")
	}

	// Generate serial number
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	var notAfter time.Time
	switch validity.Type {
	case "DAYS":
		notAfter = notBefore.Add(time.Duration(validity.Value*24) * time.Hour)
	case "HOURS":
		notAfter = notBefore.Add(time.Duration(validity.Value) * time.Hour)
	case "MONTHS":
		notAfter = notBefore.AddDate(0, int(validity.Value), 0)
	case "YEARS":
		notAfter = notBefore.AddDate(int(validity.Value), 0, 0)
	default:
		return nil, fmt.Errorf("invalid validity type: %s", validity.Type)
	}

	// Parse CA subject for issuer field
	caSubject, err := parseDistinguishedName(ca.SubjectDN)
	if err != nil {
		return nil, fmt.Errorf("parse CA subject DN: %w", err)
	}

	// Build leaf template
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		Issuer:                caSubject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		SignatureAlgorithm:    x509.SHA256WithRSA, // Will be set based on CA key type
	}

	// Copy extensions from CSR if present
	template.ExtraExtensions = csr.Extensions

	// Set signature algorithm based on CA key type
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		template.SignatureAlgorithm = x509.SHA256WithRSA
	}
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	}

	// TODO: Sign using KMS
	// Similar to buildRootCA, this requires KMS integration

	return nil, fmt.Errorf("buildLeafCertificate requires KMS integration for signing")
}

// buildLeafCertificateWithSigner creates a leaf certificate from a CSR, signed by the provided CA signer
func buildLeafCertificateWithSigner(csr *x509.CertificateRequest, ca pcaCertificateAuthority, validity validitySpec, caSigner crypto.Signer, caPubKey crypto.PublicKey) (certPEM, certDER []byte, err error) {
	// Validate CSR subject
	if csr.Subject.String() == "" {
		return nil, nil, fmt.Errorf("CSR must have subject")
	}

	// Generate serial number
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	var notAfter time.Time
	switch validity.Type {
	case "DAYS":
		notAfter = notBefore.Add(time.Duration(validity.Value*24) * time.Hour)
	case "HOURS":
		notAfter = notBefore.Add(time.Duration(validity.Value) * time.Hour)
	case "MONTHS":
		notAfter = notBefore.AddDate(0, int(validity.Value), 0)
	case "YEARS":
		notAfter = notBefore.AddDate(int(validity.Value), 0, 0)
	default:
		return nil, nil, fmt.Errorf("invalid validity type: %s", validity.Type)
	}

	// Parse CA subject for issuer field
	caSubject, err := parseDistinguishedName(ca.SubjectDN)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA subject DN: %w", err)
	}

	// Build leaf template
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		Issuer:                caSubject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Copy extensions from CSR if present
	template.ExtraExtensions = csr.Extensions

	// Set signature algorithm based on key type
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		template.SignatureAlgorithm = x509.SHA256WithRSA
	}
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	}

	// Create the certificate signed by the CA
	certDER, err = x509.CreateCertificate(rand.Reader, template, &x509.Certificate{
		SerialNumber:       big.NewInt(1), // Placeholder for CA cert
		Subject:            caSubject,
		IsCA:               true,
		PublicKey:          caPubKey,
		SignatureAlgorithm: template.SignatureAlgorithm,
	}, caPubKey, caSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("create leaf cert: %w", err)
	}

	// Encode to PEM
	certPEM = encodeCertificatePEM(certDER)

	return certPEM, certDER, nil
}

// parseDistinguishedName parses an X.500 DN string into pkix.Name
// Format: C=country,ST=state,L=locality,O=organization,OU=org_unit,CN=common_name
func parseDistinguishedName(dn string) (pkix.Name, error) {
	var name pkix.Name
	// TODO: Implement proper DN parsing
	// For now, just set CommonName
	// Real implementation would use x509.ParseDistinguishedName or similar
	name.CommonName = dn
	return name, nil
}

// encodeCertificatePEM encodes a DER certificate to PEM format
func encodeCertificatePEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

// generateCSRForDomain generates a PKCS#10 CSR for a domain (for ACM)
func generateCSRForDomain(domain string, altNames []string) ([]byte, error) {
	// Generate ephemeral RSA key for the request
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Build subject alt names
	dnsNames := []string{domain}
	if len(altNames) > 0 {
		dnsNames = append(dnsNames, altNames...)
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Citadel"},
			Country:      []string{"US"},
		},
		DNSNames: dnsNames,
	}

	// Sign CSR with ephemeral key
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return csrDER, nil
}
