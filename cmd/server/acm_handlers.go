package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ACM handlers provide a simple certificate request/management interface backed by Private CA

func (s *server) handleACMRequestCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "acm.RequestCertificate"
	var req requestCertificateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	if req.DomainName == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "DomainName is required")
		return
	}

	// For now, use a default CA (Citadel root)
	// In production, lookup CA by domain or tenant
	caARN := s.serverARN("acm-pca", "certificate-authority/citadel-root")

	// Load the default CA
	ca, err := s.store.DescribeCertificateAuthority(r.Context(), caARN)
	if err != nil {
		// Create default CA if it doesn't exist
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", "no CA available for certificate request")
		return
	}

	// For ACM, we generate a self-signed leaf (no CSR from client)
	// In production, this would be a proper CSR from cert-manager or similar

	// Create leaf certificate directly via buildLeafCertificateWithSigner
	// First, load CA's key and create a signer
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

	// Create signer
	signer, err := newKMSSigner(r.Context(), s.store, caKey, "RSASSA_PKCS1_V1_5_SHA_256")
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to create signer")
		return
	}

	// For ACM, we auto-generate a CSR for the domain
	// In production, accept user CSR
	csrDER, err := generateCSRForDomain(req.DomainName, req.SubjectAltNames)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", fmt.Sprintf("failed to generate CSR: %v", err))
		return
	}

	// Parse CSR
	csr, err := parseCSR(csrDER)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", fmt.Sprintf("invalid CSR: %v", err))
		return
	}

	// Issue certificate for 1 year
	validity := validitySpec{Type: "DAYS", Value: 365}
	_, certDER, err := buildLeafCertificateWithSigner(csr, ca, validity, signer, caPubKey, "RSASSA_PKCS1_V1_5_SHA_256", nil)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", fmt.Sprintf("failed to build certificate: %v", err))
		return
	}

	// Store certificate
	certID := randomHex(12)
	certARN := s.serverARN("acm", "certificate/"+certID)

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to parse certificate")
		return
	}

	cert := pcaCertificate{
		CertID:    certID,
		CAID:      ca.CAID,
		Serial:    parsedCert.SerialNumber.String(),
		CSRB64:    base64.StdEncoding.EncodeToString(csrDER),
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

	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, requestCertificateResponse{
		CertificateARN: certARN,
	})
}

func (s *server) handleACMDescribeCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "acm.DescribeCertificate"
	var req describeCertificateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	if req.CertificateARN == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CertificateArn is required")
		return
	}

	// Extract cert ID from ARN
	certID := extractResourceID(req.CertificateARN)
	if certID == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "invalid certificate ARN")
		return
	}

	// Retrieve certificate
	cert, err := s.store.GetCertificate(r.Context(), certID)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", err.Error())
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, describeCertificateResponse{
		Certificate: certificateDetail{
			ARN:       req.CertificateARN,
			Status:    cert.Status,
			Serial:    cert.Serial,
			NotBefore: cert.NotBefore.Format(time.RFC3339),
			NotAfter:  cert.NotAfter.Format(time.RFC3339),
			CreatedAt: cert.CreatedAt.Format(time.RFC3339),
		},
	})
}

func (s *server) handleACMListCertificates(w http.ResponseWriter, r *http.Request) {
	const action = "acm.ListCertificates"
	var req listCertificatesRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	// TODO: Implement pagination and filtering
	// For now, just list all certificates across all CAs

	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listCertificatesResponse{
		CertificateSummaryList: []certificateSummary{},
	})
}

func (s *server) handleACMGetCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "acm.GetCertificate"
	var req acmGetCertificateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	if req.CertificateARN == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CertificateArn is required")
		return
	}

	// Extract cert ID from ARN
	certID := extractResourceID(req.CertificateARN)
	if certID == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "invalid certificate ARN")
		return
	}

	// Retrieve certificate
	cert, err := s.store.GetCertificate(r.Context(), certID)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", err.Error())
		return
	}

	// Decode certificate from base64
	certDER, err := base64.StdEncoding.DecodeString(cert.CertB64)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "failed to decode certificate")
		return
	}

	certPEM := encodeCertificatePEM(certDER)

	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, acmGetCertificateResponse{
		Certificate: string(certPEM),
	})
}

func (s *server) handleACMDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "acm.DeleteCertificate"
	var req deleteCertificateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	if req.CertificateARN == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CertificateArn is required")
		return
	}

	// Extract cert ID from ARN
	certID := extractResourceID(req.CertificateARN)
	if certID == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "invalid certificate ARN")
		return
	}

	// Revoke the certificate
	if err := s.store.RevokeCertificate(r.Context(), certID, "Superceded"); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ResourceNotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ResourceNotFoundException", err.Error())
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	w.WriteHeader(http.StatusNoContent)
}

// extractResourceID extracts the resource ID from an AWS ARN
func extractResourceID(arn string) string {
	// ARN format: arn:aws:service:region:account:resource/id
	parts := strings.Split(arn, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}
