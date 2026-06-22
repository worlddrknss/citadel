package main

import (
	"context"
	"errors"
	"log"
	"net/http"
)

// verifyDBBackedSigV4 verifies a SigV4 request using DB-backed access keys.
// Returns username, account_id if valid, or error if invalid.
// Also updates last_used_at timestamp.
func (s *server) verifyDBBackedSigV4(r *http.Request, bodyHash string) (username, accountID string, err error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", errors.New("missing Authorization header")
	}

	// Parse the authorization header to extract access key ID
	comp, err := parseAuthorizationHeader(auth)
	if err != nil {
		return "", "", err
	}

	// Query database for the access key
	ctx := context.Background()
	username, accountID, secret, status, err := s.store.GetAccessKeyByID(ctx, comp.accessKey)
	if err != nil {
		return "", "", err
	}

	// Check if key is active
	if status != "Active" {
		return "", "", errors.New("access key is not active")
	}

	// Verify the signature using the retrieved secret
	if err := verifyAWSV4Signature(r, bodyHash, secret); err != nil {
		return "", "", err
	}

	// Record key usage
	if err := s.store.TouchAccessKeyLastUsed(ctx, comp.accessKey); err != nil {
		log.Printf("failed to update key last_used_at: %v", err)
		// Don't fail the request, just log it
	}

	return username, accountID, nil
}

// handleKMSWithDBBackedAuth is a wrapper around handleKMS that performs
// DB-backed SigV4 verification when strictSigV4 is enabled and a database is configured.
func (s *server) handleKMSWithDBBackedAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "InvalidAction", "method not allowed")
		return
	}

	// Use DB-backed verification if enabled and store supports it
	if s.cfg.strictSigV4 && s.isDBBacked() {
		if err := validateSigV4Request(r); err != nil {
			writeAWSJSONError(w, http.StatusForbidden, "IncompleteSignature", "request signature is invalid")
			return
		}

		// Verify using DB-backed keys
		bodyHash, err := drainAndHashBody(r, 1<<20)
		if err != nil {
			writeAWSJSONError(w, http.StatusBadRequest, "InvalidSignatureException", "request signature is invalid")
			return
		}

		username, accountID, err := s.verifyDBBackedSigV4(r, bodyHash)
		if err != nil {
			log.Printf("DB-backed SigV4 verification failed: %v", err)
			writeAWSJSONError(w, http.StatusForbidden, "InvalidSignatureException", "request signature is invalid")
			return
		}

		// Store username/accountID in request context for downstream handlers
		r.Header.Set("X-KMS-Username", username)
		r.Header.Set("X-KMS-Account-ID", accountID)
	}

	// Fall back to normal handleKMS
	s.handleKMS(w, r)
}

// isDBBacked returns true if the store is database-backed.
func (s *server) isDBBacked() bool {
	_, ok := s.store.(*dbStore)
	return ok
}
