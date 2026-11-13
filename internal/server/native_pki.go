package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// Native /v1 certificate API used by the console.

// registerPKIRoutes registers the routes added by the PKI build-out. The
// pre-existing /v1/certificates routes stay in server.go and are served by
// the handlers in this file.
func (s *Server) registerPKIRoutes(mux *http.ServeMux) {
	s.jobs.Every("certificate-expiry", certificateExpiryInterval, s.certificateExpiryJob)
	mux.HandleFunc("POST /v1/certificates/issue/generate", s.handleV1IssueGeneratedCert)
	mux.HandleFunc("GET /v1/certificates/acme/eab", s.handleV1ListEABKeys)
	mux.HandleFunc("POST /v1/certificates/acme/eab", s.handleV1CreateEABKey)
	mux.HandleFunc("DELETE /v1/certificates/acme/eab", s.handleV1RevokeEABKey)
	mux.HandleFunc("GET /v1/certificates/acme/settings", s.handleV1GetACMESettings)
	mux.HandleFunc("POST /v1/certificates/acme/settings", s.handleV1PutACMESettings)
	mux.Handle("/acme/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.acmeRuntime().handler.ServeHTTP(w, r)
	}))
}

// writePKIError writes a client-safe error for a native request and audits
// the failure.
func (s *Server) writePKIError(w http.ResponseWriter, r *http.Request, ctx context.Context, action, resource string, err error) {
	pe := pkiClientError(action, err)
	if action != "" {
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: resource, Result: "error", ErrorType: pe.code, AuditOrigin: s.auditOrigin(r)})
	}
	writeNativeError(w, pe.status, pe.code, pe.msg)
}

func (s *Server) decodePKIBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := decodeJSONBody(r, v); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON for this endpoint")
		return false
	}
	return true
}

// flexInt accepts a JSON number or a numeric string (the console sends
// validityDays as a string on some forms).
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if strings.TrimSpace(s) == "" {
			*f = 0
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return err
		}
		*f = flexInt(n)
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

func validityDays(n flexInt) (time.Duration, error) {
	if n == 0 {
		return 365 * 24 * time.Hour, nil
	}
	if n < 1 || n > 3650 {
		return 0, pkiInvalid("validityDays must be between 1 and 3650")
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

// ---- list ----

type nativeCertificate struct {
	Source       string `json:"source"`
	ID           string `json:"id"`
	Subject      string `json:"subject"`
	CommonName   string `json:"commonName,omitempty"`
	Serial       string `json:"serial,omitempty"`
	KeyAlgorithm string `json:"keyAlgorithm,omitempty"`
	Status       string `json:"status"`
	NotBefore    string `json:"notBefore,omitempty"`
	NotAfter     string `json:"notAfter,omitempty"`
	CAType       string `json:"caType,omitempty"`
	ParentCAID   string `json:"parentCaId,omitempty"`
	IssuerCAID   string `json:"issuerCaId,omitempty"`
	Template     string `json:"template,omitempty"`
	RevokedAt    string `json:"revokedAt,omitempty"`
	// Issuer is the issuer DN of certificates Citadel did not issue
	// (acm-imported rows).
	Issuer string `json:"issuer,omitempty"`
	// IsCA marks certificate authorities (pca-ca rows).
	IsCA bool `json:"isCA,omitempty"`
	// PathLen is a CA's basic-constraints pathLenConstraint: how many CAs
	// may follow it in a chain (0: it may only issue end-entity
	// certificates). Absent on a CA without a limit.
	PathLen *int `json:"pathLen,omitempty"`
	// RestorableUntil: a DELETED CA can be restored until then.
	RestorableUntil string `json:"restorableUntil,omitempty"`
	// Outstanding counts a CA's issued certificates (and subordinate CAs)
	// that are still valid; it must be 0 before the CA can be deleted.
	Outstanding *int `json:"outstanding,omitempty"`
	// Renewal is a Let's Encrypt certificate's automatic renewal state.
	Renewal *leRenewalJSON `json:"renewal,omitempty"`
	// ExpiringSoon: still valid but expires within 30 days.
	ExpiringSoon bool `json:"expiringSoon"`
}

const expiringSoonWindow = 30 * 24 * time.Hour

func expiringSoon(status string, notAfter, now time.Time) bool {
	switch strings.ToUpper(status) {
	case "REVOKED", "EXPIRED":
		return false
	}
	return !notAfter.IsZero() && notAfter.After(now) && notAfter.Sub(now) <= expiringSoonWindow
}

// displayStatus reports EXPIRED for issued certificates past notAfter even
// before the expiry job has run.
func displayStatus(status string, notAfter, now time.Time) string {
	if (status == "ISSUED" || status == "ACTIVE") && !notAfter.IsZero() && now.After(notAfter) {
		return "EXPIRED"
	}
	return status
}

func certInfo(b64 string) (cn, keyAlg string) {
	cert, err := parseCertificateB64(b64)
	if err != nil {
		return "", ""
	}
	return cert.Subject.CommonName, keyAlgorithmOf(cert.PublicKey)
}

// handleV1ListCertificates returns the account's CAs, the certificates they
// issued, its Let's Encrypt certificates and the certificates imported
// through ACM.
func (s *Server) handleV1ListCertificates(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	now := time.Now().UTC()
	out := make([]nativeCertificate, 0)
	cas, err := s.store.ListCertificateAuthorities(ctx)
	if err != nil {
		s.writePKIError(w, r, ctx, "", "", err)
		return
	}
	for _, ca := range cas {
		cn, alg := certInfo(ca.CACertB64)
		row := nativeCertificate{
			Source: "pca-ca", ID: ca.CAID, Subject: ca.SubjectDN, CommonName: cn, KeyAlgorithm: alg,
			Status: displayStatus(ca.State, ca.NotAfter, now), NotBefore: fmtTime(ca.NotBefore), NotAfter: fmtTime(ca.NotAfter),
			CAType: ca.Type, ParentCAID: ca.ParentCAID, ExpiringSoon: expiringSoon(ca.State, ca.NotAfter, now),
		}
		row.IsCA = true
		if cert, err := parseCertificateB64(ca.CACertB64); err == nil {
			row.Serial = cert.SerialNumber.String()
			row.PathLen = caPathLength(cert)
		}
		s.caLifecycleRow(ctx, &row, ca, now)
		out = append(out, row)
		certs, err := s.store.ListCertificates(ctx, ca.CAID)
		if err != nil {
			s.writePKIError(w, r, ctx, "", "", err)
			return
		}
		for _, c := range certs {
			if c.DeletedAt != nil {
				continue // removed from the inventory; kept for the CRL
			}
			cn, alg := certInfo(c.CertB64)
			row := nativeCertificate{
				Source: "pca-cert", ID: c.CertID, Subject: cn, CommonName: cn, Serial: c.Serial, KeyAlgorithm: alg,
				Status: displayStatus(c.Status, c.NotAfter, now), NotBefore: fmtTime(c.NotBefore), NotAfter: fmtTime(c.NotAfter),
				IssuerCAID: ca.CAID, Template: consoleTemplate(c.Template), ExpiringSoon: expiringSoon(c.Status, c.NotAfter, now),
			}
			if row.Subject == "" {
				row.Subject = c.Serial
			}
			if c.RevokedAt != nil {
				row.RevokedAt = fmtTime(*c.RevokedAt)
			}
			out = append(out, row)
		}
	}
	if leCerts, err := s.store.ListACMELECertificates(ctx); err == nil {
		for _, c := range leCerts {
			cn, alg := certInfo(c.CertB64)
			out = append(out, nativeCertificate{
				Source: "lets-encrypt", ID: c.CertID, Subject: c.Domains, CommonName: cn, Serial: c.Serial, KeyAlgorithm: alg,
				Status: displayStatus(c.Status, c.NotAfter, now), NotBefore: fmtTime(c.NotBefore), NotAfter: fmtTime(c.NotAfter),
				ExpiringSoon: expiringSoon(c.Status, c.NotAfter, now), Renewal: leRenewalOut(c, now),
			})
		}
	} else if !errors.Is(err, store.ErrUnsupported) {
		log.Printf("pki: list Let's Encrypt certificates: %v", err)
	}
	if imported, err := s.importedCertificateRows(ctx, now); err == nil {
		out = append(out, imported...)
	} else if !errors.Is(err, store.ErrUnsupported) {
		log.Printf("pki: list imported certificates: %v", err)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

// ---- certificate authorities ----

type nativeCreateCARequest struct {
	CAType           string `json:"caType"`
	KeyAlgorithm     string `json:"keyAlgorithm"`
	SigningAlgorithm string `json:"signingAlgorithm"` // accepted for compatibility; derived from the key
	CommonName       string `json:"commonName"`
	Organization     string `json:"organization"`
	Country          string `json:"country"`
	ParentCAID       string `json:"parentCaId"`
}

// handleV1CreateCA creates a root CA, or a subordinate CA signed by parentCaId.
func (s *Server) handleV1CreateCA(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.CreateCA"
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeCreateCARequest
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	if !strings.EqualFold(req.CAType, "SUBORDINATE") && strings.TrimSpace(req.ParentCAID) != "" {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("parentCaId is only valid for SUBORDINATE CAs"))
		return
	}
	rec, err := s.pkiCreateCA(ctx, caCreateRequest{Type: req.CAType, KeyAlgorithm: req.KeyAlgorithm, ParentCAID: req.ParentCAID,
		Subject: subjectConfig{CommonName: req.CommonName, Organization: req.Organization, Country: req.Country}})
	if err != nil {
		s.writePKIError(w, r, ctx, action, req.ParentCAID, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: rec.CAID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"caId": rec.CAID, "created": true})
}

type nativeImportCARequest struct {
	CACertPEM   string `json:"caCertPem"`
	CAKeyPEM    string `json:"caKeyPem"`
	Description string `json:"description"`
}

// handleV1ImportCA imports an externally generated CA certificate and key.
func (s *Server) handleV1ImportCA(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.ImportCA"
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeImportCARequest
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	rec, err := s.pkiImportCA(ctx, []byte(req.CACertPEM), []byte(req.CAKeyPEM), req.Description)
	if err != nil {
		s.writePKIError(w, r, ctx, action, "", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: rec.CAID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"caId": rec.CAID, "imported": true})
}

// pkiImportCA stores an external CA and its key. A CA issued by one of the
// account's CAs records that CA as its parent so chains are complete.
func (s *Server) pkiImportCA(ctx context.Context, certPEM, keyPEM []byte, description string) (store.PCACertificateAuthority, error) {
	if len(bytes.TrimSpace(certPEM)) == 0 || len(bytes.TrimSpace(keyPEM)) == 0 {
		return store.PCACertificateAuthority{}, pkiInvalid("CA certificate and private key are both required")
	}
	if len(description) > 256 {
		return store.PCACertificateAuthority{}, pkiInvalid("description must be at most 256 characters")
	}
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return store.PCACertificateAuthority{}, pkiInvalid("CA certificate is not a valid PEM certificate")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return store.PCACertificateAuthority{}, pkiInvalid("the certificate is not a CA certificate (CA:TRUE and keyCertSign are required)")
	}
	if err := checkApprovedPublicKey(cert.PublicKey); err != nil {
		return store.PCACertificateAuthority{}, err
	}
	signer, pub, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return store.PCACertificateAuthority{}, pkiInvalid("private key must be an unencrypted PEM key")
	}
	if !publicKeysEqual(cert.PublicKey, pub) {
		return store.PCACertificateAuthority{}, pkiInvalid("the private key does not match the CA certificate")
	}
	keySpec, err := keySpecForPublicKey(pub)
	if err != nil {
		return store.PCACertificateAuthority{}, pkiInvalid("unsupported CA key type")
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return store.PCACertificateAuthority{}, err
	}
	defer clear(privDER)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return store.PCACertificateAuthority{}, err
	}
	keyDesc := strings.TrimSpace(description)
	if keyDesc == "" {
		keyDesc = "Imported CA key"
	}
	key, err := s.store.ImportSigningKey(ctx, keyDesc, privDER, pubDER, keySpec)
	if err != nil {
		return store.PCACertificateAuthority{}, err
	}
	caType, parentID := "ROOT", ""
	if !certIsSelfSigned(cert) {
		caType = "SUBORDINATE"
		if cas, err := s.store.ListCertificateAuthorities(ctx); err == nil {
			for _, ca := range cas {
				if pc, err := parseCertificateB64(ca.CACertB64); err == nil && cert.CheckSignatureFrom(pc) == nil {
					parentID = ca.CAID
					break
				}
			}
		}
	}
	now := time.Now().UTC()
	caID := cryptoutil.RandomHex(12)
	rec := store.PCACertificateAuthority{
		CAID: caID, ARN: s.pcaCAARN(ctx, caID), Type: caType, KMSKeyID: key.ID, SubjectDN: cert.Subject.String(),
		State: "ACTIVE", CACertB64: base64.StdEncoding.EncodeToString(cert.Raw), PathLength: caPathLength(cert),
		NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), Description: strings.TrimSpace(description),
		ParentCAID: parentID, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateCertificateAuthority(ctx, rec); err != nil {
		return store.PCACertificateAuthority{}, err
	}
	s.assignCAKeyAlias(ctx, key.ID, cert.Subject.CommonName, caID)
	return rec, nil
}

// ---- issuance ----

type nativeIssueCertRequest struct {
	CAARN            string  `json:"caArn"` // CA ID or ARN
	CSRPEM           string  `json:"csrPem"`
	ValidityDays     flexInt `json:"validityDays"`
	SigningAlgorithm string  `json:"signingAlgorithm"` // accepted for compatibility; derived from the CA key
	OverrideCN       string  `json:"overrideCommonName"`
	SANNames         string  `json:"sanNames"`
	Template         string  `json:"template"`
}

// handleV1IssueCert signs a CSR with a private CA.
func (s *Server) handleV1IssueCert(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.IssueCertificate"
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeIssueCertRequest
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	leaf, err := func() (*issuedLeaf, error) {
		if strings.TrimSpace(req.CSRPEM) == "" {
			return nil, pkiInvalid("csrPem is required")
		}
		v, err := validityDays(req.ValidityDays)
		if err != nil {
			return nil, err
		}
		ca, err := s.pkiLoadCA(ctx, req.CAARN)
		if err != nil {
			return nil, err
		}
		csr, err := parseCSRInput([]byte(req.CSRPEM))
		if err != nil {
			return nil, err
		}
		sans := strings.FieldsFunc(req.SANNames, func(c rune) bool {
			return c == ',' || c == ';' || c == ' ' || c == '\n' || c == '\r' || c == '\t'
		})
		return s.pkiIssueLeaf(ctx, leafRequest{CA: ca, CSR: csr, Template: req.Template, CommonName: req.OverrideCN, ExtraSANs: sans, Validity: v})
	}()
	if err != nil {
		s.writePKIError(w, r, ctx, action, req.CAARN, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: leaf.rec.CertID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"issued": true, "certId": leaf.rec.CertID})
}

type nativeGenerateCertRequest struct {
	CAID         string   `json:"caId"`
	CommonName   string   `json:"commonName"`
	SANs         []string `json:"sans"`
	Template     string   `json:"template"`
	KeyAlgorithm string   `json:"keyAlgorithm"`
	ValidityDays flexInt  `json:"validityDays"`
}

// handleV1IssueGeneratedCert generates the key pair inside Citadel, issues a
// certificate for it and returns the private key once. The key is never
// stored or logged.
func (s *Server) handleV1IssueGeneratedCert(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.IssueCertificate"
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeGenerateCertRequest
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	var keyDER []byte
	leaf, err := func() (*issuedLeaf, error) {
		if strings.TrimSpace(req.CommonName) == "" && len(req.SANs) == 0 {
			return nil, pkiInvalid("commonName or sans is required")
		}
		if len(req.SANs) > 100 {
			return nil, pkiInvalid("at most 100 sans are allowed")
		}
		if req.KeyAlgorithm == "" {
			return nil, pkiInvalid("keyAlgorithm is required")
		}
		if _, err := kmsKeySpecForAlgorithm(req.KeyAlgorithm); err != nil {
			return nil, err
		}
		v, err := validityDays(req.ValidityDays)
		if err != nil {
			return nil, err
		}
		ca, err := s.pkiLoadCA(ctx, req.CAID)
		if err != nil {
			return nil, err
		}
		var leaf *issuedLeaf
		leaf, keyDER, err = s.issueWithGeneratedKey(ctx, ca, req.KeyAlgorithm, req.CommonName, req.SANs, req.Template, v)
		return leaf, err
	}()
	defer clear(keyDER)
	if err != nil {
		s.writePKIError(w, r, ctx, action, req.CAID, err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: leaf.rec.CertID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	w.Header().Set("Cache-Control", "no-store")
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"certId":         leaf.rec.CertID,
		"certificatePem": string(encodeCertificatePEM(leaf.cert.Raw)),
		"chainPem":       string(leaf.chainPEM),
		"privateKeyPem":  string(keyPEM),
	})
}

type nativeRevokeCertRequest struct {
	CertID string `json:"certId"`
	Reason string `json:"reason"`
}

// handleV1RevokeCert revokes an issued certificate.
func (s *Server) handleV1RevokeCert(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.RevokeCertificate"
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req nativeRevokeCertRequest
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	err := func() error {
		if strings.TrimSpace(req.CertID) == "" {
			return pkiInvalid("certId is required")
		}
		reason, _, err := normalizeRevocationReason(req.Reason)
		if err != nil {
			return err
		}
		return s.store.RevokeCertificate(ctx, strings.TrimSpace(req.CertID), reason)
	}()
	if err != nil {
		s.writePKIError(w, r, ctx, action, req.CertID, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: req.CertID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

type nativeRenewCertRequest struct {
	CertID       string  `json:"certId"`
	ValidityDays flexInt `json:"validityDays"`
}

// handleV1RenewCert re-signs a certificate's stored CSR with a new serial and
// validity window from the same CA and template.
func (s *Server) handleV1RenewCert(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.RenewCertificate"
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeRenewCertRequest
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	leaf, err := func() (*issuedLeaf, error) {
		v, err := validityDays(req.ValidityDays)
		if err != nil {
			return nil, err
		}
		prev, err := s.store.GetCertificate(ctx, strings.TrimSpace(req.CertID))
		if err != nil {
			return nil, err
		}
		if prev.Status == "REVOKED" {
			return nil, pkiConflict("InvalidStateException", "a revoked certificate cannot be renewed")
		}
		if isSubordinateCATemplate(prev.Template) {
			return nil, pkiConflict("InvalidStateException", "subordinate CA certificates are not renewed as leaf certificates; issue a new one with the subordinate CA template")
		}
		csrPEMBytes, err := base64.StdEncoding.DecodeString(prev.CSRB64)
		if err != nil || len(csrPEMBytes) == 0 {
			return nil, pkiConflict("InvalidStateException", "no stored CSR is available to renew this certificate")
		}
		csr, err := parseCSRInput(csrPEMBytes)
		if err != nil {
			return nil, pkiConflict("InvalidStateException", "the stored CSR can no longer be used")
		}
		old, err := parseCertificateB64(prev.CertB64)
		if err != nil {
			return nil, err
		}
		ca, err := s.store.GetCertificateAuthorityByID(ctx, prev.CAID)
		if err != nil {
			return nil, err
		}
		// Keep the issued names (including any overrides), not just the CSR's.
		var sans []string
		sans = append(sans, old.DNSNames...)
		for _, ip := range old.IPAddresses {
			sans = append(sans, ip.String())
		}
		sans = append(sans, old.EmailAddresses...)
		return s.pkiIssueLeaf(ctx, leafRequest{CA: ca, CSR: csr, Template: templateFromAWSName(prev.Template),
			CommonName: old.Subject.CommonName, ExtraSANs: sans, Validity: v})
	}()
	if err != nil {
		s.writePKIError(w, r, ctx, action, req.CertID, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: leaf.rec.CertID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"renewed": true, "certId": leaf.rec.CertID})
}

// ---- ACME: EAB keys and settings ----

type nativeEABKey struct {
	KID           string `json:"kid"`
	Label         string `json:"label"`
	Status        string `json:"status"`
	CreatedAt     string `json:"createdAt"`
	CreatedBy     string `json:"createdBy"`
	BoundAt       string `json:"boundAt,omitempty"`
	ACMEAccountID string `json:"acmeAccountId,omitempty"`
}

func (s *Server) handleV1ListEABKeys(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	keys, err := s.store.ListEABKeys(ctx)
	if err != nil {
		s.writePKIError(w, r, ctx, "", "", err)
		return
	}
	out := make([]nativeEABKey, 0, len(keys))
	for _, k := range keys {
		nk := nativeEABKey{KID: k.KID, Label: k.Label, Status: k.Status, CreatedAt: fmtTime(k.CreatedAt), CreatedBy: k.CreatedBy, ACMEAccountID: k.ACMEAccountID}
		if k.BoundAt != nil {
			nk.BoundAt = fmtTime(*k.BoundAt)
		}
		out = append(out, nk)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) handleV1CreateEABKey(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.CreateEABKey"
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" || len(label) > 128 || strings.ContainsAny(label, "\r\n") {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("label is required (at most 128 characters, one line)"))
		return
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		s.writePKIError(w, r, ctx, action, "", err)
		return
	}
	defer clear(secret)
	now := time.Now().UTC().Truncate(time.Second)
	k := store.EABKey{KID: "eab_" + cryptoutil.RandomHex(16), Label: label, HMACKey: secret, Status: store.EABStatusUnused, CreatedAt: now, CreatedBy: sess.Username}
	if err := s.store.CreateEABKey(ctx, k); err != nil {
		s.writePKIError(w, r, ctx, action, k.KID, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: k.KID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	w.Header().Set("Cache-Control", "no-store")
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"kid": k.KID, "hmacKey": base64.RawURLEncoding.EncodeToString(secret), "label": label, "createdAt": fmtTime(now),
	})
}

func (s *Server) handleV1RevokeEABKey(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.RevokeEABKey"
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	kid := strings.TrimSpace(r.URL.Query().Get("kid"))
	if kid == "" {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("kid is required"))
		return
	}
	k, err := s.store.RevokeEABKey(ctx, kid)
	if errors.Is(err, store.ErrEABKeyNotFound) {
		err = pkiNotFound("EAB key")
	}
	if err != nil {
		s.writePKIError(w, r, ctx, action, kid, err)
		return
	}
	// Revoking a key also cuts off the ACME account it bound.
	if k.ACMEAccountID != "" {
		if err := s.deactivateACMEAccount(ctx, k.ACMEAccountID); err != nil {
			log.Printf("pki: revoke EAB key %s: deactivating ACME account %s: %v", kid, k.ACMEAccountID, err)
		}
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: kid, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"kid": kid, "revoked": true})
}

// deactivateACMEAccount marks an ACME account revoked so it can make no
// further requests.
func (s *Server) deactivateACMEAccount(ctx context.Context, id string) error {
	st := s.acmeRuntime().acmeStore
	for range 5 {
		a, err := st.GetAccount(ctx, id)
		if err != nil {
			return err
		}
		if a.Status != "valid" {
			return nil
		}
		a.Status = "revoked"
		err = st.UpdateAccount(ctx, a)
		if err == nil || !errors.Is(err, errACMEStale) {
			return err
		}
	}
	return fmt.Errorf("too much contention")
}

type nativeACMESettings struct {
	Enabled                bool     `json:"enabled"`
	DirectoryURL           string   `json:"directoryUrl,omitempty"`
	IssuingCAID            string   `json:"issuingCaId"`
	EffectiveIssuingCAID   string   `json:"effectiveIssuingCaId,omitempty"`
	AllowedDomains         []string `json:"allowedDomains"`
	AllowedIPRanges        []string `json:"allowedIpRanges"`
	ValidationAllowedCIDRs []string `json:"validationAllowedCidrs"`
	UpdatedAt              string   `json:"updatedAt,omitempty"`
	UpdatedBy              string   `json:"updatedBy,omitempty"`
}

func (s *Server) acmeSettingsResponse(ctx context.Context) (nativeACMESettings, error) {
	st, err := s.store.GetACMEServerSettings(ctx)
	if err != nil && !errors.Is(err, store.ErrACMEServerSettingsNotFound) {
		return nativeACMESettings{}, err
	}
	out := nativeACMESettings{
		Enabled: s.cfg.PublicURL != "", IssuingCAID: st.IssuingCAID,
		AllowedDomains: nonNil(st.AllowedDomains), AllowedIPRanges: nonNil(st.AllowedIPRanges), ValidationAllowedCIDRs: nonNil(st.ValidationAllowedCIDRs),
		UpdatedBy: st.UpdatedBy,
	}
	if !st.UpdatedAt.IsZero() {
		out.UpdatedAt = fmtTime(st.UpdatedAt)
	}
	if out.Enabled {
		out.DirectoryURL = s.cfg.PublicURL + "/acme/directory"
	}
	if ca, err := s.acmeIssuingCA(ctx); err == nil {
		out.EffectiveIssuingCAID = ca.CAID
	}
	return out, nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func (s *Server) handleV1GetACMESettings(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	out, err := s.acmeSettingsResponse(ctx)
	if err != nil {
		s.writePKIError(w, r, ctx, "", "", err)
		return
	}
	writeNativeJSON(w, http.StatusOK, out)
}

func (s *Server) handleV1PutACMESettings(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.PutACMESettings"
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req struct {
		IssuingCAID            string   `json:"issuingCaId"`
		AllowedDomains         []string `json:"allowedDomains"`
		AllowedIPRanges        []string `json:"allowedIpRanges"`
		ValidationAllowedCIDRs []string `json:"validationAllowedCidrs"`
	}
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	in, err := func() (store.ACMEServerSettings, error) {
		out := store.ACMEServerSettings{IssuingCAID: strings.TrimSpace(req.IssuingCAID), UpdatedBy: sess.Username}
		if out.IssuingCAID != "" {
			ca, err := s.store.GetCertificateAuthorityByID(ctx, out.IssuingCAID)
			if err != nil {
				return out, err
			}
			if ca.State != "ACTIVE" {
				return out, pkiInvalid("the issuing CA must be ACTIVE")
			}
		}
		if len(req.AllowedDomains) > 200 || len(req.AllowedIPRanges) > 200 || len(req.ValidationAllowedCIDRs) > 200 {
			return out, pkiInvalid("at most 200 entries per list")
		}
		for _, d := range req.AllowedDomains {
			d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
			if !validSANDNSName(d) || strings.HasPrefix(d, "*.") || !strings.Contains(d, ".") {
				return out, pkiInvalid("allowedDomains entry %q must be a domain such as example.com", d)
			}
			out.AllowedDomains = appendUniqueStrings(out.AllowedDomains, d)
		}
		for _, list := range []struct {
			in  []string
			out *[]string
			key string
		}{{req.AllowedIPRanges, &out.AllowedIPRanges, "allowedIpRanges"}, {req.ValidationAllowedCIDRs, &out.ValidationAllowedCIDRs, "validationAllowedCidrs"}} {
			for _, c := range list.in {
				p, err := parseCIDROrAddr(c)
				if err != nil {
					return out, pkiInvalid("%s entry %q must be a CIDR or IP address", list.key, c)
				}
				*list.out = appendUniqueStrings(*list.out, p.String())
			}
		}
		return out, nil
	}()
	if err != nil {
		s.writePKIError(w, r, ctx, action, req.IssuingCAID, err)
		return
	}
	if err := s.store.PutACMEServerSettings(ctx, in); err != nil {
		s.writePKIError(w, r, ctx, action, in.IssuingCAID, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: in.IssuingCAID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	out, err := s.acmeSettingsResponse(ctx)
	if err != nil {
		s.writePKIError(w, r, ctx, "", "", err)
		return
	}
	writeNativeJSON(w, http.StatusOK, out)
}

// ---- Let's Encrypt (ACME client) ----

// handleV1GetLESettings returns the Let's Encrypt directory and contact email.
func (s *Server) handleV1GetLESettings(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	directoryURL := s.acmeLEDirectoryURL(ctx)
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"environment":  leDirectoryEnvLabel(directoryURL),
		"directoryUrl": directoryURL,
		"contactEmail": s.acmeLEContactEmail(ctx),
	})
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

// handleV1SaveLESettings persists the deployment-wide Let's Encrypt directory
// and contact email.
func (s *Server) handleV1SaveLESettings(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.SaveLESettings"
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var req struct {
		Environment  string `json:"environment"`
		DirectoryURL string `json:"directoryUrl"`
		ContactEmail string `json:"contactEmail"`
	}
	if !s.decodePKIBody(w, r, &req) {
		return
	}
	err := func() error {
		db := s.storeDB()
		if db == nil {
			return &pkiError{status: http.StatusNotImplemented, code: "unsupported", msg: "settings require a database-backed store"}
		}
		directoryURL := leStagingDirectoryURL
		switch strings.TrimSpace(req.Environment) {
		case "production":
			directoryURL = leProdDirectoryURL
		case "staging", "":
		case "custom":
			custom := strings.TrimSpace(req.DirectoryURL)
			if !strings.HasPrefix(custom, "https://") || len(custom) > 512 {
				return pkiInvalid("custom directory URL must be an https URL")
			}
			directoryURL = custom
		default:
			return pkiInvalid("environment must be staging, production or custom")
		}
		email := strings.TrimSpace(req.ContactEmail)
		if len(email) > 254 || strings.ContainsAny(email, " \r\n") || (email != "" && !strings.Contains(email, "@")) {
			return pkiInvalid("contactEmail is not a valid email address")
		}
		if err := postgres.PutSetting(ctx, db, settingACMELEDirectoryURL, directoryURL); err != nil {
			return err
		}
		return postgres.PutSetting(ctx, db, settingACMELEContactEmail, email)
	}()
	if err != nil {
		s.writePKIError(w, r, ctx, action, "", err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// leFailure keeps validation messages and hides internal ACME client errors.
func leFailure(op string, err error) error {
	var pe *pkiError
	if errors.As(err, &pe) {
		return err
	}
	log.Printf("pki: %s: %v", op, err)
	return &pkiError{status: http.StatusBadGateway, code: "letsencrypt_failed", awsType: "InternalFailure", msg: op + " failed; see the server log for details"}
}
