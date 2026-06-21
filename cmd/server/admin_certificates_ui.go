package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
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
}

func (s *server) handleCertificatesAdmin(w http.ResponseWriter, r *http.Request) {
	requiredRole := "viewer"
	switch strings.TrimSpace(r.URL.Query().Get("action")) {
	case "issue_cert":
		requiredRole = "editor"
	case "create_ca", "revoke_cert":
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
	case "issue_cert":
		err = s.adminIssueCert(r)
		ok = "certificate issued"
	case "revoke_cert":
		err = s.adminRevokeCert(r)
		ok = "certificate revoked"
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
	signingAlgorithm := strings.TrimSpace(r.FormValue("signing_algorithm"))
	if signingAlgorithm == "" {
		signingAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	}

	ca, err := s.store.DescribeCertificateAuthority(r.Context(), caARN)
	if err != nil {
		return err
	}
	caKey, err := s.store.ResolveByID(r.Context(), ca.KMSKeyID)
	if err != nil {
		return err
	}
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
	_, certDER, err := buildLeafCertificateWithSigner(csr, ca, validitySpec{Value: validityDays, Type: "DAYS"}, signer, caPubKey)
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
