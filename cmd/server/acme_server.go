package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// ACME (RFC 8555) certificate automation server
// Provides free certificate issuance for testing and development

// AcmeAccount represents an ACME account
type AcmeAccount struct {
	AccountID     string
	KeyThumbprint string
	Contact       []string
	Status        string // valid, revoked, deactivated
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AcmeOrder represents an ACME order
type AcmeOrder struct {
	OrderID           string
	AccountID         string
	Status            string // pending, ready, processing, valid, invalid
	Expires           time.Time
	Identifiers       []AcmeIdentifier
	AuthorizationURLs []string
	FinalizeURL       string
	Certificate       string // PEM-encoded certificate
	CSR               []byte
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// AcmeIdentifier represents a domain or IP address
type AcmeIdentifier struct {
	Type  string // dns, ip
	Value string
}

// AcmeAuthorization represents an authorization for a domain
type AcmeAuthorization struct {
	AuthorizationID string
	OrderID         string
	AccountID       string
	Identifier      AcmeIdentifier
	Status          string // pending, valid, invalid, revoked, deactivated
	Challenges      []AcmeChallenge
	Expires         time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AcmeChallenge represents a challenge for domain validation
type AcmeChallenge struct {
	ChallengeID string
	Type        string // http-01, dns-01, tls-alpn-01
	Status      string // pending, processing, valid, invalid
	URL         string
	Token       string
	KeyAuth     string
	Validated   *time.Time
	CreatedAt   time.Time
}

// generateNonce generates a cryptographically random nonce
func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateID generates a random resource ID
func generateID(prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	hex := hex.EncodeToString(b)
	if prefix != "" {
		return prefix + "-" + hex
	}
	return hex
}

// NewAcmeAccount creates a new ACME account
func NewAcmeAccount(keyThumbprint string, contact []string) *AcmeAccount {
	now := time.Now().UTC()
	return &AcmeAccount{
		AccountID:     generateID("acct"),
		KeyThumbprint: keyThumbprint,
		Contact:       contact,
		Status:        "valid",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// NewAcmeOrder creates a new ACME order
func NewAcmeOrder(accountID string, identifiers []AcmeIdentifier) *AcmeOrder {
	now := time.Now().UTC()
	order := &AcmeOrder{
		OrderID:     generateID("ord"),
		AccountID:   accountID,
		Status:      "pending",
		Expires:     now.Add(24 * time.Hour),
		Identifiers: identifiers,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Create authorization URLs for each identifier
	for range identifiers {
		order.AuthorizationURLs = append(order.AuthorizationURLs, "/acme/authz/"+generateID("authz"))
	}

	order.FinalizeURL = "/acme/order/" + order.OrderID + "/finalize"

	return order
}

// NewAcmeAuthorization creates a new authorization
func NewAcmeAuthorization(orderID, accountID string, identifier AcmeIdentifier) *AcmeAuthorization {
	now := time.Now().UTC()
	authz := &AcmeAuthorization{
		AuthorizationID: generateID("authz"),
		OrderID:         orderID,
		AccountID:       accountID,
		Identifier:      identifier,
		Status:          "pending",
		Expires:         now.Add(7 * 24 * time.Hour),
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Create challenges for different validation methods
	challenges := []AcmeChallenge{
		{
			ChallengeID: generateID("chal"),
			Type:        "http-01",
			Status:      "pending",
			URL:         "/acme/challenge/" + generateID("chal"),
			Token:       generateNonce(),
			CreatedAt:   now,
		},
		{
			ChallengeID: generateID("chal"),
			Type:        "dns-01",
			Status:      "pending",
			URL:         "/acme/challenge/" + generateID("chal"),
			Token:       generateNonce(),
			CreatedAt:   now,
		},
	}

	authz.Challenges = challenges
	return authz
}

// GenerateKeyThumbprint computes JWK thumbprint per RFC 7638
func GenerateKeyThumbprint(keyBytes []byte) string {
	h := sha256.Sum256(keyBytes)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// computeKeyAuth computes the key authorization for a challenge
func computeKeyAuth(token, keyThumbprint string) string {
	return token + "." + keyThumbprint
}

// computeValidationHash computes the hash for a challenge
func computeValidationHash(token, keyThumbprint string) string {
	keyAuth := computeKeyAuth(token, keyThumbprint)
	h := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
