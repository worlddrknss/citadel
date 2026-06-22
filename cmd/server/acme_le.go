package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	// settingACMELEDirectoryURL selects which ACME directory Citadel uses as a
	// client. Defaults to the Let's Encrypt staging environment so issuance can
	// be exercised without consuming production rate limits.
	settingACMELEDirectoryURL = "acme_le_directory_url"
	settingACMELEContactEmail = "acme_le_contact_email"

	leStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	leProdDirectoryURL    = "https://acme-v02.api.letsencrypt.org/directory"

	// acmeOrderTimeout bounds the entire HTTP-01 issuance flow.
	acmeOrderTimeout = 3 * time.Minute
)

// acmeChallengeStore holds in-flight HTTP-01 key authorizations keyed by token.
// The public /.well-known/acme-challenge/{token} handler serves these so the
// ACME CA can verify domain control. It is safe for concurrent use.
type acmeChallengeStore struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func newACMEChallengeStore() *acmeChallengeStore {
	return &acmeChallengeStore{tokens: make(map[string]string)}
}

func (c *acmeChallengeStore) set(token, keyAuth string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[token] = keyAuth
}

func (c *acmeChallengeStore) get(token string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.tokens[token]
	return v, ok
}

func (c *acmeChallengeStore) delete(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, token)
}

// challengeSolver abstracts how a domain-control challenge is provisioned and
// cleaned up. HTTP-01 is implemented today; a DNS-01 solver can be added later
// without changing the issuance orchestration.
type challengeSolver interface {
	// supports reports whether this solver can satisfy the challenge type.
	supports(challengeType string) bool
	// present provisions the challenge response for the given token/keyAuth.
	present(token, keyAuth string) error
	// cleanup removes a previously presented challenge.
	cleanup(token string)
}

// httpChallengeSolver satisfies HTTP-01 by serving key authorizations from the
// in-memory challenge store via Citadel's own listener.
type httpChallengeSolver struct {
	store *acmeChallengeStore
}

func (h *httpChallengeSolver) supports(challengeType string) bool {
	return challengeType == "http-01"
}

func (h *httpChallengeSolver) present(token, keyAuth string) error {
	h.store.set(token, keyAuth)
	return nil
}

func (h *httpChallengeSolver) cleanup(token string) {
	h.store.delete(token)
}

// handleACMEChallengeToken serves HTTP-01 key authorizations. It must remain
// unauthenticated and reachable at the well-known path for ACME validation.
func (s *server) handleACMEChallengeToken(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	keyAuth, ok := s.acmeChallenges.get(token)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(keyAuth))
}

// acmeLEDirectoryURL returns the configured ACME directory URL, defaulting to
// Let's Encrypt staging.
func (s *server) acmeLEDirectoryURL(ctx context.Context) string {
	db := s.storeDB()
	if db == nil {
		return leStagingDirectoryURL
	}
	v, err := getSetting(ctx, db, settingACMELEDirectoryURL)
	if err != nil || strings.TrimSpace(v) == "" {
		return leStagingDirectoryURL
	}
	return strings.TrimSpace(v)
}

// acmeLEContactEmail returns the configured ACME account contact email.
func (s *server) acmeLEContactEmail(ctx context.Context) string {
	db := s.storeDB()
	if db == nil {
		return ""
	}
	v, _ := getSetting(ctx, db, settingACMELEContactEmail)
	return strings.TrimSpace(v)
}

// storeDB exposes the underlying *sql.DB when the store is database-backed.
func (s *server) storeDB() *sql.DB {
	if db, ok := s.store.(*dbStore); ok {
		return db.db
	}
	return nil
}

// loadOrCreateACMEClient returns an acme.Client bound to a persisted account
// key for the active directory, registering the account on first use.
func (s *server) loadOrCreateACMEClient(ctx context.Context, directoryURL, contactEmail string) (*acme.Client, error) {
	account, err := s.store.GetACMELEAccount(ctx, directoryURL)
	if err != nil {
		// No account yet: generate a fresh account key.
		accountKey, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			return nil, fmt.Errorf("generate account key: %w", genErr)
		}
		der, mErr := x509.MarshalPKCS8PrivateKey(accountKey)
		if mErr != nil {
			return nil, fmt.Errorf("marshal account key: %w", mErr)
		}
		account = acmeLEAccount{
			DirectoryURL:  directoryURL,
			ContactEmail:  contactEmail,
			AccountKeyDER: der,
		}
	}

	signer, err := x509.ParsePKCS8PrivateKey(account.AccountKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected account key type %T", signer)
	}

	client := &acme.Client{Key: key, DirectoryURL: directoryURL}

	if strings.TrimSpace(account.AccountURI) == "" {
		acct := &acme.Account{}
		if contactEmail != "" {
			acct.Contact = []string{"mailto:" + contactEmail}
		}
		registered, regErr := client.Register(ctx, acct, acme.AcceptTOS)
		if regErr != nil {
			return nil, fmt.Errorf("register acme account: %w", regErr)
		}
		account.AccountURI = registered.URI
		account.ContactEmail = contactEmail
		if err := s.store.UpsertACMELEAccount(ctx, account); err != nil {
			return nil, fmt.Errorf("persist acme account: %w", err)
		}
	}

	return client, nil
}

// issueLetsEncryptCertificate runs the full HTTP-01 issuance flow for the given
// domains and persists the resulting certificate and key. e2e issuance requires
// the listed domains to publicly resolve to this Citadel instance.
func (s *server) issueLetsEncryptCertificate(ctx context.Context, domains []string) (acmeLECertificate, error) {
	domains = normalizeDomains(domains)
	if len(domains) == 0 {
		return acmeLECertificate{}, fmt.Errorf("at least one domain is required")
	}

	directoryURL := s.acmeLEDirectoryURL(ctx)
	contactEmail := s.acmeLEContactEmail(ctx)

	ctx, cancel := context.WithTimeout(ctx, acmeOrderTimeout)
	defer cancel()

	client, err := s.loadOrCreateACMEClient(ctx, directoryURL, contactEmail)
	if err != nil {
		return acmeLECertificate{}, err
	}

	solver := &httpChallengeSolver{store: s.acmeChallenges}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return acmeLECertificate{}, fmt.Errorf("create order: %w", err)
	}

	var presented []string
	defer func() {
		for _, tok := range presented {
			solver.cleanup(tok)
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		authz, aErr := client.GetAuthorization(ctx, authzURL)
		if aErr != nil {
			return acmeLECertificate{}, fmt.Errorf("get authorization: %w", aErr)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if solver.supports(c.Type) {
				chal = c
				break
			}
		}
		if chal == nil {
			return acmeLECertificate{}, fmt.Errorf("no supported (http-01) challenge for %s", authz.Identifier.Value)
		}

		keyAuth, kErr := client.HTTP01ChallengeResponse(chal.Token)
		if kErr != nil {
			return acmeLECertificate{}, fmt.Errorf("compute key authorization: %w", kErr)
		}
		if err := solver.present(chal.Token, keyAuth); err != nil {
			return acmeLECertificate{}, fmt.Errorf("present challenge: %w", err)
		}
		presented = append(presented, chal.Token)

		if _, err := client.Accept(ctx, chal); err != nil {
			return acmeLECertificate{}, fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return acmeLECertificate{}, fmt.Errorf("authorization failed for %s: %w", authz.Identifier.Value, err)
		}
	}

	// Generate the leaf key pair and CSR.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acmeLECertificate{}, fmt.Errorf("generate leaf key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, leafKey)
	if err != nil {
		return acmeLECertificate{}, fmt.Errorf("create csr: %w", err)
	}

	derChain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return acmeLECertificate{}, fmt.Errorf("finalize order: %w", err)
	}
	if len(derChain) == 0 {
		return acmeLECertificate{}, fmt.Errorf("acme returned no certificates")
	}

	leaf, err := x509.ParseCertificate(derChain[0])
	if err != nil {
		return acmeLECertificate{}, fmt.Errorf("parse issued certificate: %w", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derChain[0]})
	var chainBuilder strings.Builder
	for _, der := range derChain {
		chainBuilder.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return acmeLECertificate{}, fmt.Errorf("marshal leaf key: %w", err)
	}

	cert := acmeLECertificate{
		DirectoryURL: directoryURL,
		Domains:      strings.Join(domains, ","),
		Serial:       leaf.SerialNumber.String(),
		CertB64:      base64.StdEncoding.EncodeToString(leafPEM),
		ChainB64:     base64.StdEncoding.EncodeToString([]byte(chainBuilder.String())),
		KeyDER:       keyDER,
		Status:       "ISSUED",
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
	}
	if err := s.store.CreateACMELECertificate(ctx, cert); err != nil {
		return acmeLECertificate{}, fmt.Errorf("store certificate: %w", err)
	}
	return cert, nil
}

// normalizeDomains splits, trims, lowercases, and de-duplicates a set of domain
// tokens separated by commas, spaces, or newlines.
func normalizeDomains(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range in {
		for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
		}) {
			d := strings.ToLower(strings.TrimSpace(tok))
			if d == "" {
				continue
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out
}
