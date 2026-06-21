package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

// CRL (Certificate Revocation List) generation and management

// crlEntry represents a revoked certificate entry
type crlEntry struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	Reason         int // CRL reason code (0-10)
}

// generateCRL creates a CRL signed by the CA
func (s *server) generateCRL(ctx context.Context, ca *pcaCertificateAuthority, caKey *kmsKey, signer crypto.Signer, caPubKey crypto.PublicKey) ([]byte, error) {
	// Load revoked certificates for this CA
	certs, err := s.store.ListCertificates(ctx, ca.CAID)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}

	// Build list of revoked entries
	var revokedCerts []pkix.RevokedCertificate
	for _, cert := range certs {
		if cert.Status == "REVOKED" && cert.RevokedAt != nil && !cert.RevokedAt.IsZero() {
			serialNum := new(big.Int)
			serialNum.SetString(cert.Serial, 10)

			// Map revocation reason string to ASN.1 code (0-10, skipping 7)
			reason := 0 // Unspecified
			switch cert.RevocationReason {
			case "Unspecified":
				reason = 0
			case "KeyCompromise":
				reason = 1
			case "CACompromise":
				reason = 2
			case "AffiliationChanged":
				reason = 3
			case "Superseded":
				reason = 4
			case "CessationOfOperation":
				reason = 5
			case "CertificateHold":
				reason = 6
			case "RemoveFromCRL":
				reason = 8
			case "PrivilegeWithdrawn":
				reason = 9
			case "AACompromise":
				reason = 10
			}

			revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
				SerialNumber:   serialNum,
				RevocationTime: *cert.RevokedAt,
				Extensions: []pkix.Extension{
					{
						Id:       []int{2, 5, 29, 21},
						Critical: false,
						Value: []byte{
							0x0a, 0x01, byte(reason),
						},
					},
				},
			})
		}
	}

	// Parse CA certificate to get issuer name
	caCertDER, err := base64.StdEncoding.DecodeString(ca.CACertB64)
	if err != nil {
		return nil, fmt.Errorf("decode CA cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	// Generate CRL
	nextUpdate := time.Now().Add(7 * 24 * time.Hour) // 7 day CRL validity

	template := &x509.RevocationList{
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(time.Now().Unix()),
		ThisUpdate:          time.Now(),
		NextUpdate:          nextUpdate,
		Issuer:              caCert.Subject,
	}

	// Sign CRL with CA key
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, signer)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %w", err)
	}

	return crlDER, nil
}

// handleGetCRL returns the CRL for a CA
func (s *server) handleGetCRL(w http.ResponseWriter, r *http.Request) {
	const action = "acm-pca.GetCRL"
	var req struct {
		CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
	}

	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	if req.CertificateAuthorityARN == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CertificateAuthorityArn is required")
		return
	}

	// Load CA
	ca, err := s.store.DescribeCertificateAuthority(r.Context(), req.CertificateAuthorityARN)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", err.Error())
		return
	}

	if ca.CACertB64 == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", "CA certificate not found")
		return
	}

	// Load CA key
	caKey, err := s.store.ResolveByID(r.Context(), ca.KMSKeyID)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to load CA key")
		return
	}

	// Parse CA public key
	caPubKey, err := x509.ParsePKIXPublicKey(caKey.PublicKeyRaw)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to parse CA public key")
		return
	}

	// Get signing algorithm from CA (default to RSA if not set)
	sigAlg := "RSASSA_PKCS1_V1_5_SHA_256"
	if caKey.KeySpec != "" {
		switch caKey.KeySpec {
		case "RSA_2048", "RSA_3072", "RSA_4096":
			sigAlg = "RSASSA_PKCS1_V1_5_SHA_256"
		case "ECC_NIST_P256":
			sigAlg = "ECDSA_SHA_256"
		case "ECC_NIST_P384":
			sigAlg = "ECDSA_SHA_384"
		}
	}

	// Create KMS signer
	signer, err := newKMSSigner(r.Context(), s.store, caKey, sigAlg)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to create CA signer")
		return
	}

	// Generate CRL
	crlDER, err := s.generateCRL(r.Context(), &ca, &caKey, signer, caPubKey)
	if err != nil {
		log.Printf("generateCRL error: %v", err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to generate CRL")
		return
	}

	crlB64 := base64.StdEncoding.EncodeToString(crlDER)

	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"CRL": crlB64,
	})
}

// handleCRLDownload serves the CRL in binary DER format
func (s *server) handleCRLDownload(w http.ResponseWriter, r *http.Request) {
	// Extract CA ID from path: /crl/<ca-id>.crl
	caID := r.PathValue("ca_id")
	if caID == "" {
		http.Error(w, "CA ID required", http.StatusBadRequest)
		return
	}

	// Build CA ARN
	caARN := fmt.Sprintf("arn:aws:acm-pca:local:000000000000:certificate-authority/%s", caID)

	// Load CA
	ca, err := s.store.DescribeCertificateAuthority(r.Context(), caARN)
	if err != nil {
		http.Error(w, "CA not found", http.StatusNotFound)
		return
	}

	if ca.CACertB64 == "" {
		http.Error(w, "CA certificate not found", http.StatusNotFound)
		return
	}

	// Load CA key
	caKey, err := s.store.ResolveByID(r.Context(), ca.KMSKeyID)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Parse CA public key
	caPubKey, err := x509.ParsePKIXPublicKey(caKey.PublicKeyRaw)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Get signing algorithm
	sigAlg := "RSASSA_PKCS1_V1_5_SHA_256"
	if caKey.KeySpec != "" {
		switch caKey.KeySpec {
		case "RSA_2048", "RSA_3072", "RSA_4096":
			sigAlg = "RSASSA_PKCS1_V1_5_SHA_256"
		case "ECC_NIST_P256":
			sigAlg = "ECDSA_SHA_256"
		case "ECC_NIST_P384":
			sigAlg = "ECDSA_SHA_384"
		}
	}

	// Create KMS signer
	signer, err := newKMSSigner(r.Context(), s.store, caKey, sigAlg)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Generate CRL
	crlDER, err := s.generateCRL(r.Context(), &ca, &caKey, signer, caPubKey)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Return CRL in DER format
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=ca-%s.crl", caID))
	w.WriteHeader(http.StatusOK)
	w.Write(crlDER)
}
