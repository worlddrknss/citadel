package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

func (s *server) handleCreateCertificateAuthority(w http.ResponseWriter, r *http.Request) {
	const action = "acm-pca.CreateCertificateAuthority"
	var req createCertificateAuthorityRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	// Normalize CA type
	caType := req.CAType
	if caType == "" {
		caType = "ROOT"
	}

	// Validate KeyAlgorithm maps to a valid KMS key spec
	keySpec := ""
	switch req.CertificateAuthorityConfiguration.KeyAlgorithm {
	case "RSA_2048":
		keySpec = keySpecRSA2048
	case "RSA_3072":
		keySpec = keySpecRSA3072
	case "RSA_4096":
		keySpec = keySpecRSA4096
	case "EC_prime256v1":
		keySpec = keySpecECCP256
	case "EC_secp384r1":
		keySpec = keySpecECCP384
	default:
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "unsupported KeyAlgorithm")
		return
	}

	// Create the signing key via KMS
	signingKey, err := s.store.CreateKey(r.Context(), "Private CA key", keyUsageSignVerify, keySpec)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to create CA key")
		return
	}

	// For now, record the CA as CREATING and will need root cert to transition to ACTIVE
	caID := "ca-" + randomHex(12)
	caARN := fmt.Sprintf("arn:aws:acm-pca:local:000000000000:certificate-authority/%s", caID)

	// TODO: Build and self-sign root cert or accept cert for subordinate
	// For Phase A: Create CA and generate self-signed root cert
	ca := pcaCertificateAuthority{
		CAID:        caID,
		ARN:         caARN,
		Type:        caType,
		KMSKeyID:    signingKey.ID,
		SubjectDN:   formatSubjectDN(req.CertificateAuthorityConfiguration.Subject),
		State:       "ACTIVE",
		NotBefore:   time.Now().UTC(),
		NotAfter:    time.Now().UTC().Add(10 * 365 * 24 * time.Hour), // 10-year validity
		Description: "Citadel Private CA",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	// Generate self-signed root certificate via KMS
	signingAlgorithm := req.CertificateAuthorityConfiguration.SigningAlgorithm
	if signingAlgorithm == "" {
		// Default based on key spec
		switch req.CertificateAuthorityConfiguration.KeyAlgorithm {
		case "RSA_2048", "RSA_3072", "RSA_4096":
			signingAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
		case "EC_prime256v1":
			signingAlgorithm = "ECDSA_SHA_256"
		case "EC_secp384r1":
			signingAlgorithm = "ECDSA_SHA_384"
		}
	}

	// Create KMS signer for the CA key
	signer, err := newKMSSigner(r.Context(), s.store, signingKey, signingAlgorithm)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to create CA signer")
		return
	}

	// Generate the self-signed root certificate
	_, certDER, err := buildRootCAWithSigner(ca, signingKey, signer)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to generate CA certificate")
		return
	}

	// Store the generated certificate in the CA record
	ca.CACertB64 = base64.StdEncoding.EncodeToString(certDER)

	// Store the CA in the database
	if err := s.store.CreateCertificateAuthority(r.Context(), ca); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to store CA")
		return
	}

	// Record audit event with CA reference
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: signingKey.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, createCertificateAuthorityResponse{
		CertificateAuthorityARN: ca.ARN,
	})
}

func (s *server) handleDescribeCertificateAuthority(w http.ResponseWriter, r *http.Request) {
	const action = "acm-pca.DescribeCertificateAuthority"
	var req describeCertificateAuthorityRequest
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

	// Load from database
	ca, err := s.store.DescribeCertificateAuthority(r.Context(), req.CertificateAuthorityARN)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", err.Error())
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: ca.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, describeCertificateAuthorityResponse{
		CertificateAuthority: certificateAuthorityRecord{
			ARN:         ca.ARN,
			Type:        ca.Type,
			Status:      ca.State,
			Certificate: ca.CACertB64,
			CreatedAt:   ca.CreatedAt.Format(time.RFC3339),
		},
	})
}

func (s *server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "acm-pca.IssueCertificate"
	var req issueCertificateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	if req.CertificateAuthorityARN == "" || req.CSR == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CertificateAuthorityArn and Csr are required")
		return
	}

	// Load CA from database
	ca, err := s.store.DescribeCertificateAuthority(r.Context(), req.CertificateAuthorityARN)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", err.Error())
		return
	}

	// Load CA's KMS key
	caKey, err := s.store.ResolveByID(r.Context(), ca.KMSKeyID)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to load CA key")
		return
	}

	// Parse CSR from base64
	csrDER, err := base64.StdEncoding.DecodeString(req.CSR)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CSR must be base64-encoded")
		return
	}

	// Parse the CSR
	csr, err := parseCSR(csrDER)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", fmt.Sprintf("invalid CSR: %v", err))
		return
	}

	// Get signing algorithm (or use default)
	signingAlgorithm := req.SigningAlgorithm
	if signingAlgorithm == "" {
		signingAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256" // AWS default
	}

	// Create KMS signer for the CA key
	signer, err := newKMSSigner(r.Context(), s.store, caKey, signingAlgorithm)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to create signer")
		return
	}

	// Parse CA's public key
	caPubKey, err := x509.ParsePKIXPublicKey(caKey.PublicKeyRaw)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to parse CA public key")
		return
	}

	// Build and sign the leaf certificate
	_, certDER, err := buildLeafCertificateWithSigner(csr, ca, req.Validity, signer, caPubKey)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", fmt.Sprintf("failed to build certificate: %v", err))
		return
	}

	// Store the certificate in the database
	certID := "cert-" + randomHex(12)
	certARN := fmt.Sprintf("arn:aws:acm-pca:local:000000000000:certificate/%s", certID)

	// Parse certificate to get serial number and validity
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to parse generated certificate")
		return
	}

	cert := pcaCertificate{
		CertID:    certID,
		CAID:      ca.CAID,
		Serial:    parsedCert.SerialNumber.String(),
		CSRB64:    req.CSR,
		CertB64:   base64.StdEncoding.EncodeToString(certDER),
		Status:    "ISSUED",
		NotBefore: parsedCert.NotBefore,
		NotAfter:  parsedCert.NotAfter,
		Template:  "EndEntityCertificate",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if err := s.store.CreateCertificate(r.Context(), cert); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to store certificate")
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: ca.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})

	// Return certificate ARN
	writeJSON(w, http.StatusOK, issueCertificateResponse{
		CertificateARN: certARN,
	})
}

func (s *server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "acm-pca.GetCertificate"
	var req getCertificateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	// TODO: Look up certificate in database, return PEM
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
	writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", "certificate not found")
}

func (s *server) handleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "acm-pca.RevokeCertificate"
	var req revokeCertificateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	if req.CertificateAuthorityARN == "" || req.CertificateARN == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CertificateAuthorityArn and CertificateArn are required")
		return
	}

	// TODO: Mark certificate as revoked, update CRL
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
	writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", "certificate not found")
}

// formatSubjectDN converts a subjectConfig to an X.500 Distinguished Name string
func formatSubjectDN(subj subjectConfig) string {
	var dn string
	if subj.Country != "" {
		dn += fmt.Sprintf("C=%s,", subj.Country)
	}
	if subj.State != "" {
		dn += fmt.Sprintf("ST=%s,", subj.State)
	}
	if subj.Locality != "" {
		dn += fmt.Sprintf("L=%s,", subj.Locality)
	}
	if subj.Organization != "" {
		dn += fmt.Sprintf("O=%s,", subj.Organization)
	}
	if subj.OrganizationUnit != "" {
		dn += fmt.Sprintf("OU=%s,", subj.OrganizationUnit)
	}
	if subj.CommonName != "" {
		dn += fmt.Sprintf("CN=%s", subj.CommonName)
	} else {
		// Remove trailing comma if CN is empty
		if len(dn) > 0 {
			dn = dn[:len(dn)-1]
		}
	}
	return dn
}
