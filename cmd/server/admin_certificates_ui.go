package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var adminCertificatesTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_certificates.html"))

type adminCAView struct {
	CAID      string
	ARN       string
	Type      string
	State     string
	SubjectDN string
	NotAfter  string
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
	SelectedCAARN   string
	Certificates    []adminCertView
	CurrentUserName string
	CurrentUserRole string
	TenantScope     []string
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

	cas, err := s.store.ListCertificateAuthorities(r.Context())
	if err != nil {
		http.Error(w, "failed to list certificate authorities", http.StatusInternalServerError)
		return
	}
	sort.Slice(cas, func(i, j int) bool { return cas[i].CreatedAt.After(cas[j].CreatedAt) })

	view := adminCertificatesPageView{
		CAs:             make([]adminCAView, 0, len(cas)),
		Certificates:    []adminCertView{},
		SelectedCAARN:   strings.TrimSpace(r.URL.Query().Get("ca_arn")),
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
		TenantScope:     append([]string(nil), session.Tenants...),
		CanEdit:         uiCanEdit(session),
		CanAdmin:        uiCanAdmin(session),
		Flash:           r.URL.Query().Get("ok"),
		Error:           r.URL.Query().Get("err"),
	}

	for _, ca := range cas {
		entry := adminCAView{
			CAID:      ca.CAID,
			ARN:       ca.ARN,
			Type:      ca.Type,
			State:     ca.State,
			SubjectDN: ca.SubjectDN,
			NotAfter:  ca.NotAfter.UTC().Format(time.RFC3339),
		}
		view.CAs = append(view.CAs, entry)
		if view.SelectedCAARN != "" && ca.ARN == view.SelectedCAARN {
			sel := entry
			view.SelectedCA = &sel
		}
	}
	if view.SelectedCA == nil && len(view.CAs) > 0 {
		sel := view.CAs[0]
		view.SelectedCA = &sel
		view.SelectedCAARN = sel.ARN
	}

	if view.SelectedCA != nil {
		certs, err := s.store.ListCertificates(r.Context(), view.SelectedCA.CAID)
		if err == nil {
			sort.Slice(certs, func(i, j int) bool { return certs[i].CreatedAt.After(certs[j].CreatedAt) })
			for _, cert := range certs {
				revokedAt := ""
				if cert.RevokedAt != nil {
					revokedAt = cert.RevokedAt.UTC().Format(time.RFC3339)
				}
				view.Certificates = append(view.Certificates, adminCertView{
					CertID:           cert.CertID,
					Serial:           cert.Serial,
					Status:           cert.Status,
					Template:         cert.Template,
					NotBefore:        cert.NotBefore.UTC().Format(time.RFC3339),
					NotAfter:         cert.NotAfter.UTC().Format(time.RFC3339),
					RevokedAt:        revokedAt,
					RevocationReason: cert.RevocationReason,
				})
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminCertificatesTemplate.Execute(w, view); err != nil {
		http.Error(w, "failed to render certificates admin view", http.StatusInternalServerError)
		return
	}
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
		err = s.adminCreateCA(r)
		ok = "certificate authority created"
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

func (s *server) adminCreateCA(r *http.Request) error {
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
		return fmt.Errorf("common name is required")
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
		return fmt.Errorf("unsupported key algorithm")
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
		return err
	}

	caID := randomHex(12)
	caARN := fmt.Sprintf("arn:aws:acm-pca:local:000000000000:certificate-authority/%s", caID)
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
		return err
	}
	_, certDER, err := buildRootCAWithSigner(ca, signingKey, signer)
	if err != nil {
		return err
	}
	ca.CACertB64 = base64.StdEncoding.EncodeToString(certDER)
	if err := s.store.CreateCertificateAuthority(r.Context(), ca); err != nil {
		return err
	}
	return nil
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
	v := url.Values{}
	v.Set("ok", msg)
	if caARN := strings.TrimSpace(r.FormValue("ca_arn")); caARN != "" {
		v.Set("ca_arn", caARN)
	}
	http.Redirect(w, r, "/certificates?"+v.Encode(), http.StatusSeeOther)
}

func (s *server) redirectCertificatesError(w http.ResponseWriter, r *http.Request, msg string) {
	v := url.Values{}
	v.Set("err", msg)
	if caARN := strings.TrimSpace(r.FormValue("ca_arn")); caARN != "" {
		v.Set("ca_arn", caARN)
	}
	http.Redirect(w, r, "/certificates?"+v.Encode(), http.StatusSeeOther)
}
