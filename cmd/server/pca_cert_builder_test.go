package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"testing"
	"time"
)

// makeSelfSignedCA returns a self-signed CA certificate and its signer for tests.
func makeSelfSignedCA(t *testing.T, priv crypto.Signer, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA", Organization: []string{"Citadel"}, Country: []string{"US"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert
}

func makeCSR(t *testing.T, cn string, dnsNames []string) *x509.CertificateRequest {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, leafKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	csr.PublicKey = &leafKey.PublicKey
	return csr
}

func TestBuildLeafCertificateChainsAndOverrides(t *testing.T) {
	cases := []struct {
		name   string
		newCA  func(t *testing.T) (crypto.Signer, x509.SignatureAlgorithm)
		kmsAlg string
	}{
		{
			name: "RSA CA",
			newCA: func(t *testing.T) (crypto.Signer, x509.SignatureAlgorithm) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("rsa: %v", err)
				}
				return k, x509.SHA256WithRSA
			},
			kmsAlg: "RSASSA_PKCS1_V1_5_SHA_256",
		},
		{
			name: "ECDSA P384 CA",
			newCA: func(t *testing.T) (crypto.Signer, x509.SignatureAlgorithm) {
				k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("ecdsa: %v", err)
				}
				return k, x509.ECDSAWithSHA384
			},
			kmsAlg: "ECDSA_SHA_384",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caSigner, sigAlg := tc.newCA(t)
			caCert := makeSelfSignedCA(t, caSigner, sigAlg)
			ca := pcaCertificateAuthority{
				SubjectDN: caCert.Subject.String(),
				CACertB64: base64.StdEncoding.EncodeToString(caCert.Raw),
			}

			csr := makeCSR(t, "leaf.example.com", []string{"leaf.example.com"})
			overrides := &leafOverrides{
				DNSNames:    []string{"api.example.com"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
			}

			_, certDER, err := buildLeafCertificateWithSigner(csr, ca, validitySpec{Value: 365, Type: "DAYS"}, caSigner, caSigner.Public(), tc.kmsAlg, overrides)
			if err != nil {
				t.Fatalf("build leaf: %v", err)
			}
			leaf, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("parse leaf: %v", err)
			}

			// The leaf must embed the CSR's public key, not the CA's.
			if publicKeysEqual(leaf.PublicKey, caSigner.Public()) {
				t.Fatal("leaf certificate embeds the CA public key instead of the subject's")
			}
			if !publicKeysEqual(leaf.PublicKey, csr.PublicKey) {
				t.Fatal("leaf certificate does not embed the CSR public key")
			}

			// SANs from the CSR and the overrides must both be present.
			if !containsString(leaf.DNSNames, "leaf.example.com") || !containsString(leaf.DNSNames, "api.example.com") {
				t.Fatalf("missing DNS SANs: %v", leaf.DNSNames)
			}
			if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.5" {
				t.Fatalf("missing IP SAN: %v", leaf.IPAddresses)
			}

			// The leaf must verify against the issuing CA.
			pool := x509.NewCertPool()
			pool.AddCert(caCert)
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:       pool,
				DNSName:     "api.example.com",
				CurrentTime: time.Now(),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				t.Fatalf("leaf does not chain to CA: %v", err)
			}
		})
	}
}
