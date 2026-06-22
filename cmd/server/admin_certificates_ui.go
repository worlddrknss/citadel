package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var adminCertificatesTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_certificates.html"))

const uiTimeFormat = "2006-01-02 15:04 MST"

type adminCAView struct {
	CAID        string
	ARN         string
	Type        string
	State       string
	SubjectDN   string
	CommonName  string
	KMSKeyID    string
	Description string
	PathLength  string
	NotBefore   string
	NotAfter    string
	CreatedAt   string
	CACertPEM   string
	CertCount   int
}

type adminCertView struct {
	CertID           string
	Serial           string
	Status           string
	Template         string
	NotBefore        string
	NotAfter         string
	RevokedAt        string
	RevocationReason string
}

type adminCertificatesPageView struct {
	CAs             []adminCAView
	SelectedCA      *adminCAView
	SelectedTab     string
	Certificates    []adminCertView
	ActiveCertCount int
	CurrentUserName string
	CurrentUserRole string
	AccountScope    []string
	CanEdit         bool
	CanAdmin        bool
	Flash           string
	Error           string

	LEDirectoryURL string
	LEDirectoryEnv string
	LEContactEmail string
	LECertificates []adminLECertView
}

type adminLECertView struct {
	CertID    string
	Domains   string
	Serial    string
	Status    string
	Env       string
	NotBefore string
	NotAfter  string
	CreatedAt string
}

func (s *server) handleCertificatesAdmin(w http.ResponseWriter, r *http.Request) {
	requiredRole := "viewer"
	switch strings.TrimSpace(r.URL.Query().Get("action")) {
	case "issue_cert", "renew_cert", "request_le":
		requiredRole = "editor"
	case "create_ca", "import_ca", "revoke_cert", "save_le_settings":
		requiredRole = "admin"
	}
	session, ok := s.requireUISession(w, r, requiredRole)
	if !ok {
		return
	}

	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if action != "" {
		s.handleCertificatesAdminAction(w, r, action)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if dl := strings.TrimSpace(r.URL.Query().Get("download")); dl != "" {
		s.handleCertificatesDownload(w, r, dl)
		return
	}

	cas, err := s.store.ListCertificateAuthorities(r.Context())
	if err != nil {
		http.Error(w, "failed to list certificate authorities", http.StatusInternalServerError)
		return
	}
	sort.Slice(cas, func(i, j int) bool { return cas[i].CreatedAt.After(cas[j].CreatedAt) })

	view := adminCertificatesPageView{
		CAs:             make([]adminCAView, 0, len(cas)),
		Certificates:    []adminCertView{},
		SelectedTab:     strings.TrimSpace(r.URL.Query().Get("tab")),
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
		AccountScope:    append([]string(nil), session.Accounts...),
		CanEdit:         uiCanEdit(session),
		CanAdmin:        uiCanAdmin(session),
		Flash:           r.URL.Query().Get("ok"),
		Error:           r.URL.Query().Get("err"),
	}
	if view.SelectedTab == "" {
		view.SelectedTab = "certificates"
	}

	selectedID := strings.TrimSpace(r.URL.Query().Get("ca_id"))
	selectedARN := strings.TrimSpace(r.URL.Query().Get("ca_arn"))

	for _, ca := range cas {
		entry := buildCAView(ca)
		view.CAs = append(view.CAs, entry)
		if view.SelectedCA == nil && ((selectedID != "" && ca.CAID == selectedID) || (selectedARN != "" && ca.ARN == selectedARN)) {
			sel := entry
			view.SelectedCA = &sel
		}
	}
	if (selectedID != "" || selectedARN != "") && view.SelectedCA == nil && view.Error == "" {
		view.Error = "requested certificate authority was not found"
	}

	if view.SelectedCA != nil {
		certs, err := s.store.ListCertificates(r.Context(), view.SelectedCA.CAID)
		if err == nil {
			sort.Slice(certs, func(i, j int) bool { return certs[i].CreatedAt.After(certs[j].CreatedAt) })
			for _, cert := range certs {
				revokedAt := ""
				if cert.RevokedAt != nil {
					revokedAt = cert.RevokedAt.UTC().Format(uiTimeFormat)
				}
				if cert.Status == "ISSUED" {
					view.ActiveCertCount++
				}
				view.Certificates = append(view.Certificates, adminCertView{
					CertID:           cert.CertID,
					Serial:           cert.Serial,
					Status:           cert.Status,
					Template:         cert.Template,
					NotBefore:        cert.NotBefore.UTC().Format(uiTimeFormat),
					NotAfter:         cert.NotAfter.UTC().Format(uiTimeFormat),
					RevokedAt:        revokedAt,
					RevocationReason: cert.RevocationReason,
				})
			}
		}
		view.SelectedCA.CertCount = len(view.Certificates)
	}

	s.populateLEView(r.Context(), &view)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminCertificatesTemplate.Execute(w, view); err != nil {
		http.Error(w, "failed to render certificates admin view", http.StatusInternalServerError)
		return
	}
}

// buildCAView converts a stored CA into its presentation form for the admin UI.
func buildCAView(ca pcaCertificateAuthority) adminCAView {
	pathLen := "None"
	if ca.PathLength != nil {
		pathLen = strconv.Itoa(*ca.PathLength)
	}
	return adminCAView{
		CAID:        ca.CAID,
		ARN:         ca.ARN,
		Type:        ca.Type,
		State:       ca.State,
		SubjectDN:   ca.SubjectDN,
		CommonName:  subjectCommonName(ca.SubjectDN),
		KMSKeyID:    ca.KMSKeyID,
		Description: ca.Description,
		PathLength:  pathLen,
		NotBefore:   ca.NotBefore.UTC().Format(uiTimeFormat),
		NotAfter:    ca.NotAfter.UTC().Format(uiTimeFormat),
		CreatedAt:   ca.CreatedAt.UTC().Format(uiTimeFormat),
		CACertPEM:   derB64ToPEM(ca.CACertB64, "CERTIFICATE"),
	}
}

// subjectCommonName extracts the CN component from an RFC 2253 style subject DN.
func subjectCommonName(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return dn
}

// derB64ToPEM wraps base64-encoded DER bytes in a PEM block for display/download.
func derB64ToPEM(b64, blockType string) string {
	if strings.TrimSpace(b64) == "" {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// handleCertificatesDownload streams a CA or issued certificate as a PEM file.
func (s *server) handleCertificatesDownload(w http.ResponseWriter, r *http.Request, kind string) {
	var pemData, filename string
	switch kind {
	case "ca_cert":
		caID := strings.TrimSpace(r.URL.Query().Get("ca_id"))
		caARN := strings.TrimSpace(r.URL.Query().Get("ca_arn"))
		cas, err := s.store.ListCertificateAuthorities(r.Context())
		if err != nil {
			http.Error(w, "failed to load certificate authority", http.StatusInternalServerError)
			return
		}
		for _, ca := range cas {
			if (caID != "" && ca.CAID == caID) || (caARN != "" && ca.ARN == caARN) {
				pemData = derB64ToPEM(ca.CACertB64, "CERTIFICATE")
				filename = "ca-" + ca.CAID + ".pem"
				break
			}
		}
	case "cert":
		certID := strings.TrimSpace(r.URL.Query().Get("cert_id"))
		if certID != "" {
			cert, err := s.store.GetCertificate(r.Context(), certID)
			if err == nil {
				pemData = derB64ToPEM(cert.CertB64, "CERTIFICATE")
				filename = "cert-" + cert.CertID + ".pem"
			}
		}
	case "le_cert", "le_chain", "le_key":
		certID := strings.TrimSpace(r.URL.Query().Get("cert_id"))
		if certID != "" {
			cert, err := s.store.GetACMELECertificate(r.Context(), certID)
			if err == nil {
				switch kind {
				case "le_cert":
					if dec, decErr := base64.StdEncoding.DecodeString(cert.CertB64); decErr == nil {
						pemData = string(dec)
						filename = "le-cert-" + cert.CertID + ".pem"
					}
				case "le_chain":
					if dec, decErr := base64.StdEncoding.DecodeString(cert.ChainB64); decErr == nil {
						pemData = string(dec)
						filename = "le-fullchain-" + cert.CertID + ".pem"
					}
				case "le_key":
					if len(cert.KeyDER) > 0 {
						pemData = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cert.KeyDER}))
						filename = "le-key-" + cert.CertID + ".pem"
					}
				}
			}
		}
	}
	if pemData == "" {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = w.Write([]byte(pemData))
}

func (s *server) handleCertificatesAdminAction(w http.ResponseWriter, r *http.Request, action string) {
	if r.Method != http.MethodPost {
		s.redirectCertificatesError(w, r, "action requires POST")
		return
	}
	var err error
	ok := "updated"
	switch action {
	case "create_ca":
		var caID string
		caID, err = s.adminCreateCA(r)
		if err == nil {
			v := url.Values{}
			v.Set("ok", "certificate authority created")
			v.Set("ca_id", caID)
			http.Redirect(w, r, "/certificates?"+v.Encode(), http.StatusSeeOther)
			return
		}
	case "import_ca":
		var caID string
		caID, err = s.adminImportCA(r)
		if err == nil {
			v := url.Values{}
			v.Set("ok", "certificate authority imported")
			v.Set("ca_id", caID)
			http.Redirect(w, r, "/certificates?"+v.Encode(), http.StatusSeeOther)
			return
		}
	case "issue_cert":
		err = s.adminIssueCert(r)
		ok = "certificate issued"
	case "renew_cert":
		err = s.adminRenewCert(r)
		ok = "certificate renewed"
	case "revoke_cert":
		err = s.adminRevokeCert(r)
		ok = "certificate revoked"
	case "request_le":
		err = s.adminRequestLECert(r)
		ok = "let's encrypt certificate requested"
	case "save_le_settings":
		err = s.adminSaveLESettings(r)
		ok = "let's encrypt settings saved"
	default:
		err = fmt.Errorf("unknown action")
	}
	if err != nil {
		s.redirectCertificatesError(w, r, err.Error())
		return
	}
	s.redirectCertificatesOK(w, r, ok)
}

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

// populateLEView fills the Let's Encrypt section of the certificates page.
func (s *server) populateLEView(ctx context.Context, view *adminCertificatesPageView) {
	view.LEDirectoryURL = s.acmeLEDirectoryURL(ctx)
	view.LEDirectoryEnv = leDirectoryEnvLabel(view.LEDirectoryURL)
	view.LEContactEmail = s.acmeLEContactEmail(ctx)

	certs, err := s.store.ListACMELECertificates(ctx)
	if err != nil {
		return
	}
	for _, c := range certs {
		view.LECertificates = append(view.LECertificates, adminLECertView{
			CertID:    c.CertID,
			Domains:   c.Domains,
			Serial:    c.Serial,
			Status:    c.Status,
			Env:       leDirectoryEnvLabel(c.DirectoryURL),
			NotBefore: c.NotBefore.UTC().Format(uiTimeFormat),
			NotAfter:  c.NotAfter.UTC().Format(uiTimeFormat),
			CreatedAt: c.CreatedAt.UTC().Format(uiTimeFormat),
		})
	}
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

func (s *server) redirectCertificatesOK(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/certificates?"+certificatesRedirectValues(r, "ok", msg).Encode(), http.StatusSeeOther)
}

func (s *server) redirectCertificatesError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/certificates?"+certificatesRedirectValues(r, "err", msg).Encode(), http.StatusSeeOther)
}

// certificatesRedirectValues preserves the current CA/tab context across POST redirects
// so actions return the operator to the certificate authority detail page they came from.
func certificatesRedirectValues(r *http.Request, key, msg string) url.Values {
	v := url.Values{}
	v.Set(key, msg)
	if caID := strings.TrimSpace(r.FormValue("ca_id")); caID != "" {
		v.Set("ca_id", caID)
	}
	if tab := strings.TrimSpace(r.FormValue("return_tab")); tab != "" {
		v.Set("tab", tab)
	}
	return v
}
