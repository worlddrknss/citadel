package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ACME HTTP handlers implementing RFC 8555

// handleACMEDirectory returns the ACME directory
func (s *server) handleACMEDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "GET required")
		return
	}

	dir := map[string]interface{}{
		"newNonce":   "/acme/new-nonce",
		"newAccount": "/acme/new-account",
		"newOrder":   "/acme/new-order",
		"revokeCert": "/acme/revoke-cert",
		"keyChange":  "/acme/key-change",
		"meta": map[string]interface{}{
			"home":           "https://citadel.local",
			"website":        "https://citadel.local",
			"caaIdentities":  []string{"citadel.local"},
			"termsOfService": "https://citadel.local/terms",
		},
	}
	writeJSON(w, http.StatusOK, dir)
}

// handleACMENewNonce returns a new nonce
func (s *server) handleACMENewNonce(w http.ResponseWriter, r *http.Request) {
	nonce := generateNonce()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// handleACMENewAccount creates or returns an account
func (s *server) handleACMENewAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "POST required")
		return
	}

	// TODO: Implement full JWS verification
	// For now, accept any request

	var req struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
	}

	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "invalid JSON")
		return
	}

	// Generate key thumbprint (simplified - in production, extract from JWS)
	keyThumb := generateNonce()

	account := NewAcmeAccount(keyThumb, req.Contact)

	w.Header().Set("Replay-Nonce", generateNonce())
	w.Header().Set("Location", "/acme/acct/"+account.AccountID)
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":    account.Status,
		"contact":   account.Contact,
		"createdAt": account.CreatedAt.Format(time.RFC3339),
		"orders":    "/acme/acct/" + account.AccountID + "/orders",
	})
}

// handleACMENewOrder creates a new certificate order
func (s *server) handleACMENewOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "POST required")
		return
	}

	var req struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "invalid JSON")
		return
	}

	if len(req.Identifiers) == 0 {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "identifiers required")
		return
	}

	// TODO: Extract account ID from JWS header
	accountID := "acct-system"

	// Convert identifiers
	var identifiers []AcmeIdentifier
	for _, id := range req.Identifiers {
		identifiers = append(identifiers, AcmeIdentifier{
			Type:  id.Type,
			Value: id.Value,
		})
	}

	order := NewAcmeOrder(accountID, identifiers)

	w.Header().Set("Replay-Nonce", generateNonce())
	w.Header().Set("Location", "/acme/order/"+order.OrderID)
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":         order.Status,
		"expires":        order.Expires.Format(time.RFC3339),
		"identifiers":    order.Identifiers,
		"authorizations": order.AuthorizationURLs,
		"finalize":       order.FinalizeURL,
		"createdAt":      order.CreatedAt.Format(time.RFC3339),
	})
}

// handleACMEOrder retrieves or updates an order
func (s *server) handleACMEOrder(w http.ResponseWriter, r *http.Request) {
	orderID := r.PathValue("order_id")
	if orderID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "order ID required")
		return
	}

	// TODO: Look up order from database
	// For now, return a sample order

	order := &AcmeOrder{
		OrderID: orderID,
		Status:  "ready",
		Expires: time.Now().Add(24 * time.Hour),
		Identifiers: []AcmeIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		AuthorizationURLs: []string{"/acme/authz/" + generateID("authz")},
		FinalizeURL:       "/acme/order/" + orderID + "/finalize",
		CreatedAt:         time.Now().Add(-1 * time.Hour),
		UpdatedAt:         time.Now(),
	}

	w.Header().Set("Replay-Nonce", generateNonce())
	w.WriteHeader(http.StatusOK)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         order.Status,
		"expires":        order.Expires.Format(time.RFC3339),
		"identifiers":    order.Identifiers,
		"authorizations": order.AuthorizationURLs,
		"finalize":       order.FinalizeURL,
		"createdAt":      order.CreatedAt.Format(time.RFC3339),
		"updatedAt":      order.UpdatedAt.Format(time.RFC3339),
	})
}

// handleACMEAuthorization retrieves an authorization
func (s *server) handleACMEAuthorization(w http.ResponseWriter, r *http.Request) {
	authzID := r.PathValue("authz_id")
	if authzID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "authorization ID required")
		return
	}

	// TODO: Look up authorization from database
	// For now, return a sample authorization

	authz := &AcmeAuthorization{
		AuthorizationID: authzID,
		Status:          "pending",
		Identifier:      AcmeIdentifier{Type: "dns", Value: "example.com"},
		Challenges: []AcmeChallenge{
			{
				ChallengeID: generateID("chal"),
				Type:        "http-01",
				Status:      "pending",
				URL:         "/acme/challenge/" + generateID("chal"),
				Token:       generateNonce(),
			},
		},
		Expires:   time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now().Add(-1 * time.Hour),
		UpdatedAt: time.Now(),
	}

	w.Header().Set("Replay-Nonce", generateNonce())
	w.WriteHeader(http.StatusOK)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"identifier": authz.Identifier,
		"status":     authz.Status,
		"challenges": authz.Challenges,
		"expires":    authz.Expires.Format(time.RFC3339),
		"createdAt":  authz.CreatedAt.Format(time.RFC3339),
	})
}

// handleACMEChallenge handles challenge validation
func (s *server) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "POST required")
		return
	}

	challengeID := r.PathValue("challenge_id")
	if challengeID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "challenge ID required")
		return
	}

	// TODO: Implement challenge validation
	// For now, mark as valid

	w.Header().Set("Replay-Nonce", generateNonce())
	w.WriteHeader(http.StatusOK)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"type":      "http-01",
		"status":    "valid",
		"validated": time.Now().Format(time.RFC3339),
	})
}

// handleACMEFinalize finalizes an order by issuing a certificate
func (s *server) handleACMEFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "POST required")
		return
	}

	orderID := r.PathValue("order_id")
	if orderID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "order ID required")
		return
	}

	var req struct {
		CSR string `json:"csr"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "invalid JSON")
		return
	}

	if req.CSR == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "CSR required")
		return
	}

	// Decode CSR from base64
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "invalid CSR encoding")
		return
	}

	// Parse CSR
	csr, err := parseCSR(csrDER)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", fmt.Sprintf("invalid CSR: %v", err))
		return
	}

	// Use default CA (Citadel root) to issue certificate
	caARN := s.serverARN("acm-pca", "certificate-authority/citadel-root")
	ca, err := s.store.DescribeCertificateAuthority(r.Context(), caARN)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", "failed to load CA")
		return
	}

	// Load CA key
	caKey, err := s.store.ResolveByID(r.Context(), ca.KMSKeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", "failed to load CA key")
		return
	}

	// Parse CA public key
	caPubKey, err := x509.ParsePKIXPublicKey(caKey.PublicKeyRaw)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", "failed to parse CA public key")
		return
	}

	// Create signer
	signer, err := newKMSSigner(r.Context(), s.store, caKey, "RSASSA_PKCS1_V1_5_SHA_256")
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", "failed to create signer")
		return
	}

	// Issue certificate
	validity := validitySpec{Type: "DAYS", Value: 90}
	_, certDER, err := buildLeafCertificateWithSigner(csr, ca, validity, signer, caPubKey, "RSASSA_PKCS1_V1_5_SHA_256", nil)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", fmt.Sprintf("failed to issue certificate: %v", err))
		return
	}

	// Store certificate in database
	certID := "acme-" + generateID("")
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", "failed to parse certificate")
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
	s.store.CreateCertificate(r.Context(), cert)

	// Encode certificate to PEM
	_ = encodeCertificatePEM(certDER)

	// Return order with certificate
	w.Header().Set("Replay-Nonce", generateNonce())
	w.WriteHeader(http.StatusOK)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "valid",
		"expires":        time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		"identifiers":    []AcmeIdentifier{{Type: "dns", Value: "example.com"}},
		"authorizations": []string{"/acme/authz/" + generateID("authz")},
		"finalize":       "/acme/order/" + orderID + "/finalize",
		"certificate":    "/acme/cert/" + certID,
		"createdAt":      time.Now().Format(time.RFC3339),
	})
}

// handleACMECertificate returns an issued certificate
func (s *server) handleACMECertificate(w http.ResponseWriter, r *http.Request) {
	certID := r.PathValue("cert_id")
	if certID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "certificate ID required")
		return
	}

	// Load certificate from database
	cert, err := s.store.GetCertificate(r.Context(), certID)
	if err != nil {
		writeAWSJSONError(w, http.StatusNotFound, "NotFound", "certificate not found")
		return
	}

	// Decode certificate
	certDER, _ := base64.StdEncoding.DecodeString(cert.CertB64)

	// Return as PEM
	certPEM := encodeCertificatePEM(certDER)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write(certPEM)
}

// handleACMERevokeCert revokes a certificate
func (s *server) handleACMERevokeCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "POST required")
		return
	}

	var req struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "invalid JSON")
		return
	}

	// Decode certificate
	certDER, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "invalid certificate encoding")
		return
	}

	// Parse to get serial number
	_, err2 := x509.ParseCertificate(certDER)
	if err2 != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "BadRequest", "invalid certificate")
		return
	}

	// TODO: Find certificate in database by serial and revoke
	// For now, just return success

	w.Header().Set("Replay-Nonce", generateNonce())
	w.WriteHeader(http.StatusOK)
	writeJSON(w, http.StatusOK, map[string]interface{}{})
}
