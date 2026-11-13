package server

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

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
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

	// acmeOrderTimeout bounds one background issuance (HTTP-01, or the
	// validation and finalization of a DNS-01 order).
	acmeOrderTimeout = 3 * time.Minute
	// acmeBeginTimeout bounds starting a DNS-01 order, which runs inside the
	// request and must finish well within the server's 30 s WriteTimeout.
	acmeBeginTimeout = 20 * time.Second
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
func (s *Server) handleACMEChallengeToken(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) acmeLEDirectoryURL(ctx context.Context) string {
	db := s.storeDB()
	if db == nil {
		return leStagingDirectoryURL
	}
	v, err := postgres.GetSetting(ctx, db, settingACMELEDirectoryURL)
	if err != nil || strings.TrimSpace(v) == "" {
		return leStagingDirectoryURL
	}
	return strings.TrimSpace(v)
}

// acmeLEContactEmail returns the configured ACME account contact email.
func (s *Server) acmeLEContactEmail(ctx context.Context) string {
	db := s.storeDB()
	if db == nil {
		return ""
	}
	v, _ := postgres.GetSetting(ctx, db, settingACMELEContactEmail)
	return strings.TrimSpace(v)
}

// storeDB exposes the underlying *sql.DB when the store is database-backed.
func (s *Server) storeDB() *sql.DB {
	if db, ok := s.store.(*postgres.Store); ok {
		return db.DB()
	}
	return nil
}

// loadOrCreateACMEClient returns an acme.Client bound to a persisted account
// key for the active directory, registering the account on first use.
func (s *Server) loadOrCreateACMEClient(ctx context.Context, directoryURL, contactEmail string) (*acme.Client, error) {
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
		account = store.ACMELEAccount{
			ID:            cryptoutil.RandomHex(12),
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
	if s.acmeHTTPClient != nil {
		client.HTTPClient = s.acmeHTTPClient
	}

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
//
// It runs in the background (see startLEOrder); ctx bounds it and progress
// reports each step.
func (s *Server) issueLetsEncryptCertificate(ctx context.Context, domains []string, progress func(string)) (store.ACMELECertificate, error) {
	domains = normalizeDomains(domains)
	if len(domains) == 0 {
		return store.ACMELECertificate{}, fmt.Errorf("at least one domain is required")
	}

	directoryURL := s.acmeLEDirectoryURL(ctx)
	contactEmail := s.acmeLEContactEmail(ctx)

	progress("Connecting to the ACME directory")
	client, err := s.loadOrCreateACMEClient(ctx, directoryURL, contactEmail)
	if err != nil {
		return store.ACMELECertificate{}, err
	}

	solver := &httpChallengeSolver{store: s.acmeChallenges}

	progress("Creating the order")
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("create order: %w", err)
	}
	orderURL := order.URI

	var presented []string
	defer func() {
		for _, tok := range presented {
			solver.cleanup(tok)
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		authz, aErr := client.GetAuthorization(ctx, authzURL)
		if aErr != nil {
			return store.ACMELECertificate{}, fmt.Errorf("get authorization: %w", aErr)
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
			return store.ACMELECertificate{}, fmt.Errorf("no supported (http-01) challenge for %s", authz.Identifier.Value)
		}

		keyAuth, kErr := client.HTTP01ChallengeResponse(chal.Token)
		if kErr != nil {
			return store.ACMELECertificate{}, fmt.Errorf("compute key authorization: %w", kErr)
		}
		if err := solver.present(chal.Token, keyAuth); err != nil {
			return store.ACMELECertificate{}, fmt.Errorf("present challenge: %w", err)
		}
		presented = append(presented, chal.Token)

		progress("Validating " + authz.Identifier.Value + " (HTTP-01)")
		if _, err := client.Accept(ctx, chal); err != nil {
			return store.ACMELECertificate{}, fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return store.ACMELECertificate{}, fmt.Errorf("authorization failed for %s: %w", authz.Identifier.Value, err)
		}
	}

	// Wait for the order to become ready for finalization once all
	// authorizations are valid.
	progress("Waiting for the order to be ready")
	if _, err := client.WaitOrder(ctx, orderURL); err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("wait for order to be ready: %w", err)
	}

	progress("Finalizing and downloading the certificate")
	return s.finalizeAndStoreLECert(ctx, client, orderURL, order.FinalizeURL, domains, directoryURL, store.ACMELEOrderHTTP01)
}

// finalizeAndStoreLECert generates the leaf key pair and CSR, finalizes the ACME
// order, and persists the issued certificate (with its wrapped private key). It
// is shared by the HTTP-01 and manual DNS-01 issuance paths once all of an
// order's authorizations are valid.
//
// kind is the challenge type that validated the order; HTTP-01 certificates
// renew automatically by default, DNS-01 ones need the operator.
func (s *Server) finalizeAndStoreLECert(ctx context.Context, client *acme.Client, orderURL, finalizeURL string, domains []string, directoryURL, kind string) (store.ACMELECertificate, error) {
	// Generate the leaf key pair and CSR.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("generate leaf key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, leafKey)
	if err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("create csr: %w", err)
	}

	derChain, err := finalizeOrderCert(ctx, client, orderURL, finalizeURL, csrDER)
	if err != nil {
		return store.ACMELECertificate{}, err
	}
	if len(derChain) == 0 {
		return store.ACMELECertificate{}, fmt.Errorf("acme returned no certificates")
	}

	leaf, err := x509.ParseCertificate(derChain[0])
	if err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("parse issued certificate: %w", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derChain[0]})
	var chainBuilder strings.Builder
	for _, der := range derChain {
		chainBuilder.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("marshal leaf key: %w", err)
	}

	cert := store.ACMELECertificate{
		CertID:       cryptoutil.RandomHex(12),
		DirectoryURL: directoryURL,
		Domains:      strings.Join(domains, ","),
		Serial:       leaf.SerialNumber.String(),
		CertB64:      base64.StdEncoding.EncodeToString(leafPEM),
		ChainB64:     base64.StdEncoding.EncodeToString([]byte(chainBuilder.String())),
		KeyDER:       keyDER,
		Status:       "ISSUED",
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		// Let's Encrypt can renew HTTP-01 names unattended (the challenge is
		// served by Citadel); DNS-01 needs new TXT records each time.
		ChallengeKind: kind,
		AutoRenew:     kind == store.ACMELEOrderHTTP01,
	}
	if err := s.store.CreateACMELECertificate(ctx, cert); err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("store certificate: %w", err)
	}
	return cert, nil
}

// dnsChallengeRecord describes a TXT record an operator must publish at their
// DNS provider to satisfy a manual DNS-01 challenge.
type dnsChallengeRecord struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

// beginLEDNSOrder creates an ACME order for the given domains and returns the
// DNS-01 TXT records the operator must publish, persisting the order so it can
// be completed later. It does not contact the operator's DNS provider; the
// caller publishes the records out of band.
func (s *Server) beginLEDNSOrder(ctx context.Context, domains []string) (string, []dnsChallengeRecord, error) {
	domains = normalizeDomains(domains)
	if len(domains) == 0 {
		return "", nil, fmt.Errorf("at least one domain is required")
	}

	directoryURL := s.acmeLEDirectoryURL(ctx)
	contactEmail := s.acmeLEContactEmail(ctx)

	cctx, cancel := context.WithTimeout(ctx, acmeBeginTimeout)
	defer cancel()

	client, err := s.loadOrCreateACMEClient(cctx, directoryURL, contactEmail)
	if err != nil {
		return "", nil, err
	}

	order, err := client.AuthorizeOrder(cctx, acme.DomainIDs(domains...))
	if err != nil {
		return "", nil, fmt.Errorf("create order: %w", err)
	}

	var records []dnsChallengeRecord
	for _, authzURL := range order.AuthzURLs {
		authz, aErr := client.GetAuthorization(cctx, authzURL)
		if aErr != nil {
			return "", nil, fmt.Errorf("get authorization: %w", aErr)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return "", nil, fmt.Errorf("no dns-01 challenge offered for %s", authz.Identifier.Value)
		}

		value, vErr := client.DNS01ChallengeRecord(chal.Token)
		if vErr != nil {
			return "", nil, fmt.Errorf("compute dns-01 record: %w", vErr)
		}
		records = append(records, dnsChallengeRecord{
			Domain: authz.Identifier.Value,
			Name:   "_acme-challenge." + strings.TrimPrefix(authz.Identifier.Value, "*."),
			Value:  value,
		})
	}

	orderRec := store.ACMELEOrder{
		OrderID:      cryptoutil.RandomHex(12),
		OrderURL:     order.URI,
		DirectoryURL: directoryURL,
		Domains:      strings.Join(domains, ","),
		Status:       store.ACMELEOrderPending,
		Kind:         store.ACMELEOrderDNS01,
		Progress:     "Waiting for the TXT records",
	}
	if err := s.store.CreateACMELEOrder(ctx, orderRec); err != nil {
		return "", nil, fmt.Errorf("persist order: %w", err)
	}
	return orderRec.OrderID, records, nil
}

// completeLEDNSOrder accepts the DNS-01 challenges for a previously-begun order,
// waits for validation, and finalizes issuance. The operator must have already
// published the TXT records returned by beginLEDNSOrder. It runs in the
// background (see startLEOrder); ctx bounds it and progress reports each step.
func (s *Server) completeLEDNSOrder(ctx context.Context, orderRec store.ACMELEOrder, progress func(string)) (store.ACMELECertificate, error) {
	domains := normalizeDomains([]string{orderRec.Domains})
	directoryURL := orderRec.DirectoryURL
	contactEmail := s.acmeLEContactEmail(ctx)
	cctx := ctx

	progress("Connecting to the ACME directory")
	client, err := s.loadOrCreateACMEClient(cctx, directoryURL, contactEmail)
	if err != nil {
		return store.ACMELECertificate{}, err
	}

	order, err := client.GetOrder(cctx, orderRec.OrderURL)
	if err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("get order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, aErr := client.GetAuthorization(cctx, authzURL)
		if aErr != nil {
			return store.ACMELECertificate{}, fmt.Errorf("get authorization: %w", aErr)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return store.ACMELECertificate{}, fmt.Errorf("no dns-01 challenge for %s", authz.Identifier.Value)
		}

		progress("Validating " + authz.Identifier.Value + " (DNS-01)")
		if _, err := client.Accept(cctx, chal); err != nil {
			return store.ACMELECertificate{}, fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(cctx, authzURL); err != nil {
			return store.ACMELECertificate{}, fmt.Errorf("authorization failed for %s (check the TXT records are published and propagated): %w", authz.Identifier.Value, err)
		}
	}

	progress("Waiting for the order to be ready")
	if _, err := client.WaitOrder(cctx, orderRec.OrderURL); err != nil {
		return store.ACMELECertificate{}, fmt.Errorf("wait for order to be ready: %w", err)
	}

	progress("Finalizing and downloading the certificate")
	return s.finalizeAndStoreLECert(cctx, client, orderRec.OrderURL, order.FinalizeURL, domains, directoryURL, store.ACMELEOrderDNS01)
}

// finalizeOrderCert submits the CSR to finalize the order and returns the issued
// certificate chain (DER). It prefers acme.Client.CreateOrderCert, but recovers
// from ACME servers that omit the Location header on the finalize response
// (which breaks CreateOrderCert's internal polling) by polling the known order
// URL and fetching the certificate directly. The CSR has already been submitted
// when the recovery path runs, so it only retrieves the issued certificate.
func finalizeOrderCert(ctx context.Context, client *acme.Client, orderURL, finalizeURL string, csrDER []byte) ([][]byte, error) {
	derChain, _, err := client.CreateOrderCert(ctx, finalizeURL, csrDER, true)
	if err == nil {
		return derChain, nil
	}

	order, werr := client.WaitOrder(ctx, orderURL)
	if werr != nil {
		return nil, fmt.Errorf("finalize order: %w (order poll: %v)", err, werr)
	}
	if order.CertURL == "" {
		return nil, fmt.Errorf("finalize order: %w", err)
	}
	derChain, ferr := client.FetchCert(ctx, order.CertURL, true)
	if ferr != nil {
		return nil, fmt.Errorf("fetch certificate: %w", ferr)
	}
	return derChain, nil
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
