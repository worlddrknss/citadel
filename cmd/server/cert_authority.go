package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Certificate-authority business logic shared by the native Citadel /v1
// certificate endpoints (see native_admin.go). These helpers carry the CA/leaf
// cryptography that used to back the retired html/template certificate admin
// pages; they accept *http.Request only so the native JSON handlers can bridge
// form values onto them without duplicating the signing code.

func (s *server) adminCreateCA(r *http.Request) (string, error) {
	caType := strings.TrimSpace(r.FormValue("ca_type"))
	if caType == "" {
		caType = "ROOT"
	}
	keyAlgorithm := strings.TrimSpace(r.FormValue("key_algorithm"))
	signingAlgorithm := strings.TrimSpace(r.FormValue("signing_algorithm"))
	commonName := strings.TrimSpace(r.FormValue("common_name"))
	organization := strings.TrimSpace(r.FormValue("organization"))
	country := strings.TrimSpace(r.FormValue("country"))
	if commonName == "" {
		return "", fmt.Errorf("common name is required")
	}
	keySpec := ""
	switch keyAlgorithm {
	case "", "RSA_2048":
		keySpec = keySpecRSA2048
		keyAlgorithm = "RSA_2048"
	case "RSA_3072":
		keySpec = keySpecRSA3072
	case "RSA_4096":
		keySpec = keySpecRSA4096
	case "EC_prime256v1":
		keySpec = keySpecECCP256
	case "EC_secp384r1":
		keySpec = keySpecECCP384
	default:
		return "", fmt.Errorf("unsupported key algorithm")
	}
	if signingAlgorithm == "" {
		switch keyAlgorithm {
		case "EC_prime256v1":
			signingAlgorithm = "ECDSA_SHA_256"
		case "EC_secp384r1":
			signingAlgorithm = "ECDSA_SHA_384"
		default:
			signingAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
		}
	}

	signingKey, err := s.store.CreateKey(r.Context(), "Private CA key", keyUsageSignVerify, keySpec)
	if err != nil {
		return "", err
	}

	caID := randomHex(12)
	caARN := s.serverARN("acm-pca", "certificate-authority/"+caID)
	ca := pcaCertificateAuthority{
		CAID:      caID,
		ARN:       caARN,
		Type:      caType,
		KMSKeyID:  signingKey.ID,
		SubjectDN: formatSubjectDN(subjectConfig{Country: country, Organization: organization, CommonName: commonName}),
		State:     "ACTIVE",
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(10 * 365 * 24 * time.Hour),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	signer, err := newKMSSigner(r.Context(), s.store, signingKey, signingAlgorithm)
	if err != nil {
		return "", err
	}
	_, certDER, err := buildRootCAWithSigner(ca, signingKey, signer)
	if err != nil {
		return "", err
	}
	ca.CACertB64 = base64.StdEncoding.EncodeToString(certDER)
	if err := s.store.CreateCertificateAuthority(r.Context(), ca); err != nil {
		return "", err
	}
	s.assignCAKeyAlias(r.Context(), signingKey.ID, commonName, caID)
	return caID, nil
}

// caKeyAlias builds a stable, alias-safe name for a CA signing key so it is
// identifiable in the KMS console. The short CA ID suffix keeps the alias unique
// even when multiple authorities share the same common name.
func caKeyAlias(commonName, caID string) string {
	slug := strings.ToLower(strings.TrimSpace(commonName))
	var b strings.Builder
	lastDash := false
	for _, r := range slug {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}
	slug = strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "private-ca"
	}
	suffix := caID
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	return fmt.Sprintf("alias/ca/%s-%s", slug, suffix)
}

// assignCAKeyAlias attaches a descriptive alias to a CA signing key. Alias
// creation is best-effort: the CA is already persisted, so a naming collision or
// store error should not fail the overall operation.
func (s *server) assignCAKeyAlias(ctx context.Context, keyID, commonName, caID string) {
	alias := caKeyAlias(commonName, caID)
	if err := s.store.CreateAlias(ctx, alias, keyID); err != nil {
		log.Printf("certificates: failed to assign alias %q to CA key %s: %v", alias, keyID, err)
	}
}

func (s *server) adminIssueCert(r *http.Request) error {
	caARN := strings.TrimSpace(r.FormValue("ca_arn"))
	csrPEM := strings.TrimSpace(r.FormValue("csr_pem"))
	if caARN == "" || csrPEM == "" {
		return fmt.Errorf("CA and CSR are required")
	}
	validityDays := int64(365)
	if raw := strings.TrimSpace(r.FormValue("validity_days")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 3650 {
			return fmt.Errorf("validity days must be between 1 and 3650")
		}
		validityDays = int64(n)
	}

	ca, err := s.store.DescribeCertificateAuthority(r.Context(), caARN)
	if err != nil {
		return err
	}
	caKey, err := s.store.ResolveByID(r.Context(), ca.KMSKeyID)
	if err != nil {
		return err
	}
	signingAlgorithm := strings.TrimSpace(r.FormValue("signing_algorithm"))
	if signingAlgorithm == "" {
		signingAlgorithm = defaultSigningAlgorithmForKey(caKey)
	}
	overrides := parseLeafOverrides(r.FormValue("override_cn"), r.FormValue("san_names"))

	csr, err := parseCSR([]byte(csrPEM))
	if err != nil {
		return err
	}
	signer, err := newKMSSigner(r.Context(), s.store, caKey, signingAlgorithm)
	if err != nil {
		return err
	}
	caPubKey, err := x509.ParsePKIXPublicKey(caKey.PublicKeyRaw)
	if err != nil {
		return err
	}
	_, certDER, err := buildLeafCertificateWithSigner(csr, ca, validitySpec{Value: validityDays, Type: "DAYS"}, signer, caPubKey, signingAlgorithm, overrides)
	if err != nil {
		return err
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	cert := pcaCertificate{
		CertID:    randomHex(12),
		CAID:      ca.CAID,
		Serial:    parsedCert.SerialNumber.String(),
		CSRB64:    base64.StdEncoding.EncodeToString([]byte(csrPEM)),
		CertB64:   base64.StdEncoding.EncodeToString(certDER),
		Status:    "ISSUED",
		NotBefore: parsedCert.NotBefore,
		NotAfter:  parsedCert.NotAfter,
		Template:  "EndEntityCertificate",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateCertificate(r.Context(), cert); err != nil {
		return err
	}
	return nil
}

// parseLeafOverrides builds optional subject/SAN overrides from issue-form input.
// SAN tokens may be separated by commas, semicolons or whitespace and are
// classified as IP addresses, email addresses or DNS names.
func parseLeafOverrides(commonName, sanInput string) *leafOverrides {
	commonName = strings.TrimSpace(commonName)
	sanInput = strings.TrimSpace(sanInput)
	if commonName == "" && sanInput == "" {
		return nil
	}
	ov := &leafOverrides{CommonName: commonName}
	tokens := strings.FieldsFunc(sanInput, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch {
		case net.ParseIP(tok) != nil:
			ov.IPAddresses = append(ov.IPAddresses, net.ParseIP(tok))
		case strings.Contains(tok, "@"):
			ov.EmailAddresses = append(ov.EmailAddresses, tok)
		default:
			ov.DNSNames = append(ov.DNSNames, tok)
		}
	}
	return ov
}

// adminImportCA imports an externally generated CA certificate and its matching
// private key so the authority can issue certificates through Citadel.
func (s *server) adminImportCA(r *http.Request) (string, error) {
	certPEM := strings.TrimSpace(r.FormValue("ca_cert_pem"))
	keyPEM := strings.TrimSpace(r.FormValue("ca_key_pem"))
	description := strings.TrimSpace(r.FormValue("description"))
	if certPEM == "" || keyPEM == "" {
		return "", fmt.Errorf("CA certificate and private key are both required")
	}

	caCert, err := parseCertificatePEM([]byte(certPEM))
	if err != nil {
		return "", fmt.Errorf("invalid CA certificate: %w", err)
	}
	if !caCert.IsCA || !caCert.BasicConstraintsValid {
		return "", fmt.Errorf("the supplied certificate is not a CA (basic constraint CA:TRUE is required)")
	}

	signer, pubKey, err := parsePrivateKeyPEM([]byte(keyPEM))
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	if !publicKeysEqual(caCert.PublicKey, pubKey) {
		return "", fmt.Errorf("the private key does not match the CA certificate's public key")
	}

	keySpec, err := keySpecForPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("encode public key: %w", err)
	}

	keyDescription := description
	if keyDescription == "" {
		keyDescription = "Imported CA key"
	}
	key, err := s.store.ImportSigningKey(r.Context(), keyDescription, privDER, pubDER, keySpec)
	if err != nil {
		return "", err
	}

	caType := "SUBORDINATE"
	if certIsSelfSigned(caCert) {
		caType = "ROOT"
	}
	caID := randomHex(12)
	ca := pcaCertificateAuthority{
		CAID:        caID,
		ARN:         s.serverARN("acm-pca", "certificate-authority/"+caID),
		Type:        caType,
		KMSKeyID:    key.ID,
		SubjectDN:   caCert.Subject.String(),
		State:       "ACTIVE",
		CACertB64:   base64.StdEncoding.EncodeToString(caCert.Raw),
		PathLength:  caPathLength(caCert),
		NotBefore:   caCert.NotBefore.UTC(),
		NotAfter:    caCert.NotAfter.UTC(),
		Description: description,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateCertificateAuthority(r.Context(), ca); err != nil {
		return "", err
	}
	s.assignCAKeyAlias(r.Context(), key.ID, caCert.Subject.CommonName, caID)
	return caID, nil
}

// adminRenewCert re-signs the stored CSR of an existing certificate with a fresh
// validity window and serial number, producing a new certificate from the same
// issuing CA. This is the "renew/re-issue" flow.
func (s *server) adminRenewCert(r *http.Request) error {
	certID := strings.TrimSpace(r.FormValue("cert_id"))
	if certID == "" {
		return fmt.Errorf("cert_id is required")
	}
	validityDays := int64(365)
	if raw := strings.TrimSpace(r.FormValue("validity_days")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 3650 {
			return fmt.Errorf("validity days must be between 1 and 3650")
		}
		validityDays = int64(n)
	}

	prev, err := s.store.GetCertificate(r.Context(), certID)
	if err != nil {
		return err
	}
	if prev.Status == "REVOKED" {
		return fmt.Errorf("cannot renew a revoked certificate")
	}
	if strings.TrimSpace(prev.CSRB64) == "" {
		return fmt.Errorf("no stored CSR is available to renew this certificate")
	}
	csrPEM, err := base64.StdEncoding.DecodeString(prev.CSRB64)
	if err != nil {
		return fmt.Errorf("decode stored CSR: %w", err)
	}
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return fmt.Errorf("stored CSR is invalid: %w", err)
	}

	ca, err := s.findCAByID(r.Context(), prev.CAID)
	if err != nil {
		return err
	}
	caKey, err := s.store.ResolveByID(r.Context(), ca.KMSKeyID)
	if err != nil {
		return err
	}
	signingAlgorithm := defaultSigningAlgorithmForKey(caKey)
	signer, err := newKMSSigner(r.Context(), s.store, caKey, signingAlgorithm)
	if err != nil {
		return err
	}
	caPubKey, err := x509.ParsePKIXPublicKey(caKey.PublicKeyRaw)
	if err != nil {
		return err
	}
	_, certDER, err := buildLeafCertificateWithSigner(csr, ca, validitySpec{Value: validityDays, Type: "DAYS"}, signer, caPubKey, signingAlgorithm, nil)
	if err != nil {
		return err
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	cert := pcaCertificate{
		CertID:    randomHex(12),
		CAID:      ca.CAID,
		Serial:    parsedCert.SerialNumber.String(),
		CSRB64:    prev.CSRB64,
		CertB64:   base64.StdEncoding.EncodeToString(certDER),
		Status:    "ISSUED",
		NotBefore: parsedCert.NotBefore,
		NotAfter:  parsedCert.NotAfter,
		Template:  "EndEntityCertificate",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	return s.store.CreateCertificate(r.Context(), cert)
}

// findCAByID resolves a certificate authority by its CA ID.
func (s *server) findCAByID(ctx context.Context, caID string) (pcaCertificateAuthority, error) {
	cas, err := s.store.ListCertificateAuthorities(ctx)
	if err != nil {
		return pcaCertificateAuthority{}, err
	}
	for _, c := range cas {
		if c.CAID == caID {
			return c, nil
		}
	}
	return pcaCertificateAuthority{}, fmt.Errorf("issuing certificate authority not found")
}

func (s *server) adminRevokeCert(r *http.Request) error {
	certID := strings.TrimSpace(r.FormValue("cert_id"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	if certID == "" {
		return fmt.Errorf("cert_id is required")
	}
	if reason == "" {
		reason = "Unspecified"
	}
	return s.store.RevokeCertificate(r.Context(), certID, reason)
}

// leDirectoryEnvLabel maps an ACME directory URL to a short environment label.
func leDirectoryEnvLabel(directoryURL string) string {
	switch strings.TrimSpace(directoryURL) {
	case leProdDirectoryURL:
		return "production"
	case leStagingDirectoryURL, "":
		return "staging"
	default:
		return "custom"
	}
}

// adminRequestLECert issues a publicly-trusted certificate from Let's Encrypt
// for the submitted domains using the HTTP-01 challenge.
func (s *server) adminRequestLECert(r *http.Request) error {
	domains := normalizeDomains([]string{r.FormValue("le_domains")})
	if len(domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	if _, err := s.store.ListACMELECertificates(r.Context()); err != nil {
		return fmt.Errorf("let's encrypt issuance requires a database-backed store")
	}
	_, err := s.issueLetsEncryptCertificate(r.Context(), domains)
	return err
}

// adminSaveLESettings persists the ACME directory selection and contact email.
func (s *server) adminSaveLESettings(r *http.Request) error {
	db := s.storeDB()
	if db == nil {
		return fmt.Errorf("settings require a database-backed store")
	}
	env := strings.TrimSpace(r.FormValue("le_environment"))
	directoryURL := leStagingDirectoryURL
	switch env {
	case "production":
		directoryURL = leProdDirectoryURL
	case "staging", "":
		directoryURL = leStagingDirectoryURL
	case "custom":
		custom := strings.TrimSpace(r.FormValue("le_directory_url"))
		if custom == "" {
			return fmt.Errorf("custom directory URL is required")
		}
		if !strings.HasPrefix(custom, "https://") {
			return fmt.Errorf("directory URL must use https")
		}
		directoryURL = custom
	default:
		return fmt.Errorf("unsupported environment")
	}
	if err := putSetting(r.Context(), db, settingACMELEDirectoryURL, directoryURL); err != nil {
		return err
	}
	email := strings.TrimSpace(r.FormValue("le_contact_email"))
	return putSetting(r.Context(), db, settingACMELEContactEmail, email)
}
