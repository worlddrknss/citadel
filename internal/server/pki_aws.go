package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// AWS Certificate Manager (ACM) and ACM Private CA over the AWS JSON 1.1
// protocol. Real SDKs send X-Amz-Target "CertificateManager.<Action>" and
// "ACMPrivateCA.<Action>"; the older "acm." / "acm-pca." spellings Citadel
// used to require are accepted as aliases.

// awsEpoch marshals as epoch seconds, the AWS JSON timestamp format.
type awsEpoch time.Time

func (t awsEpoch) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatFloat(float64(tt.UnixMilli())/1000, 'f', -1, 64)), nil
}

func epochPtr(t time.Time) *awsEpoch {
	if t.IsZero() {
		return nil
	}
	e := awsEpoch(t)
	return &e
}

// callerAccountOr returns the caller account on ctx, or the deployment
// account.
func (s *Server) callerAccountOr(ctx context.Context) string {
	if acct, ok := store.CallerAccountFromContext(ctx); ok {
		return acct
	}
	_, a := s.store.DeploymentIdentity()
	return a
}

func (s *Server) pcaCAARN(ctx context.Context, caID string) string {
	region, _ := s.store.DeploymentIdentity()
	return arn.Build("acm-pca", region, s.callerAccountOr(ctx), "certificate-authority/"+caID)
}

func (s *Server) pcaCertARN(ctx context.Context, caID, certID string) string {
	return s.pcaCAARN(ctx, caID) + "/certificate/" + certID
}

func (s *Server) acmCertARN(ctx context.Context, id string) string {
	region, _ := s.store.DeploymentIdentity()
	return arn.Build("acm", region, s.callerAccountOr(ctx), "certificate/"+id)
}

type awsPKIHandler func(s *Server, ctx context.Context, body []byte) (resp any, resource string, err error)

var acmActions = map[string]awsPKIHandler{
	"RequestCertificate":  (*Server).acmRequestCertificate,
	"DescribeCertificate": (*Server).acmDescribeCertificate,
	"ListCertificates":    (*Server).acmListCertificates,
	"GetCertificate":      (*Server).acmGetCertificate,
	"DeleteCertificate":   (*Server).acmDeleteCertificate,
	"ImportCertificate":   (*Server).acmImportCertificate,
	"ExportCertificate":   (*Server).acmExportCertificate,
	"RenewCertificate":    (*Server).acmRenewCertificate,
}

var pcaActions = map[string]awsPKIHandler{
	"CreateCertificateAuthority":            (*Server).pcaCreateCertificateAuthority,
	"DescribeCertificateAuthority":          (*Server).pcaDescribeCertificateAuthority,
	"ListCertificateAuthorities":            (*Server).pcaListCertificateAuthorities,
	"GetCertificateAuthorityCertificate":    (*Server).pcaGetCertificateAuthorityCertificate,
	"IssueCertificate":                      (*Server).pcaIssueCertificate,
	"GetCertificate":                        (*Server).pcaGetCertificate,
	"RevokeCertificate":                     (*Server).pcaRevokeCertificate,
	"GetCRL":                                (*Server).pcaGetCRL, // Citadel extension
	"GetCertificateAuthorityCsr":            (*Server).pcaGetCertificateAuthorityCsr,
	"ImportCertificateAuthorityCertificate": (*Server).pcaImportCertificateAuthorityCertificate,
}

// servePKITarget handles ACM and ACM PCA targets. It reports false for any
// other target so the caller can dispatch it. The request has already been
// authenticated.
func (s *Server) servePKITarget(w http.ResponseWriter, r *http.Request, target string) bool {
	svc, action, _ := strings.Cut(target, ".")
	var (
		table  map[string]awsPKIHandler
		prefix string
	)
	switch svc {
	case "CertificateManager", "acm":
		table, prefix = acmActions, "acm."
	case "ACMPrivateCA", "acm-pca":
		table, prefix = pcaActions, "acm-pca."
	default:
		return false
	}
	ctx := r.Context()
	auditAction := prefix + action
	h, ok := table[action]
	if !ok {
		writeAWSJSONError(w, http.StatusBadRequest, "UnknownOperationException", "unsupported operation")
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		s.recordAudit(ctx, store.AuditEvent{Action: auditAction, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "request body is too large or unreadable")
		return true
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		body = []byte("{}")
	}
	resp, resource, err := h(s, ctx, body)
	if err != nil {
		pe := pkiClientError(auditAction, err)
		status := http.StatusBadRequest
		if pe.status >= 500 {
			status = http.StatusInternalServerError
		}
		s.recordAudit(ctx, store.AuditEvent{Action: auditAction, KeyID: resource, Result: "error", ErrorType: pe.awsType, AuditOrigin: s.auditOrigin(r)})
		writeAWSJSONError(w, status, pe.awsType, pe.msg)
		return true
	}
	s.recordAudit(ctx, store.AuditEvent{Action: auditAction, KeyID: resource, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	if resp == nil {
		resp = struct{}{}
	}
	writeJSON(w, http.StatusOK, resp)
	return true
}

func decodeAWS(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return pkiInvalid("request body is not valid JSON for this operation")
	}
	return nil
}

// ---- ACM Private CA ----

type pcaSubject struct {
	Country            string `json:"Country,omitempty"`
	State              string `json:"State,omitempty"`
	Locality           string `json:"Locality,omitempty"`
	Organization       string `json:"Organization,omitempty"`
	OrganizationalUnit string `json:"OrganizationalUnit,omitempty"`
	CommonName         string `json:"CommonName,omitempty"`
	SerialNumber       string `json:"SerialNumber,omitempty"`
}

type pcaCAConfig struct {
	KeyAlgorithm     string     `json:"KeyAlgorithm"`
	SigningAlgorithm string     `json:"SigningAlgorithm"`
	Subject          pcaSubject `json:"Subject"`
}

func (s *Server) pcaCreateCertificateAuthority(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateAuthorityConfiguration pcaCAConfig `json:"CertificateAuthorityConfiguration"`
		CertificateAuthorityType          string      `json:"CertificateAuthorityType"`
		Type                              string      `json:"Type"` // legacy Citadel spelling
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	caType := req.CertificateAuthorityType
	if caType == "" {
		caType = req.Type
	}
	cfg := req.CertificateAuthorityConfiguration
	subj := subjectConfig{Country: cfg.Subject.Country, State: cfg.Subject.State, Locality: cfg.Subject.Locality,
		Organization: cfg.Subject.Organization, OrganizationUnit: cfg.Subject.OrganizationalUnit, CommonName: cfg.Subject.CommonName}
	switch strings.ToUpper(strings.TrimSpace(caType)) {
	case "", "ROOT":
	case "SUBORDINATE":
		// As in AWS: the CA starts in PENDING_CERTIFICATE with a CSR for its
		// parent to sign (GetCertificateAuthorityCsr, then
		// ImportCertificateAuthorityCertificate).
		rec, err := s.pkiCreatePendingSubordinateCA(ctx, cfg.KeyAlgorithm, subj)
		if err != nil {
			return nil, "", err
		}
		return map[string]string{"CertificateAuthorityArn": rec.ARN}, rec.ARN, nil
	default:
		return nil, "", pkiInvalid("CertificateAuthorityType must be ROOT or SUBORDINATE")
	}
	rec, err := s.pkiCreateCA(ctx, caCreateRequest{Type: "ROOT", KeyAlgorithm: cfg.KeyAlgorithm, Subject: subj})
	if err != nil {
		return nil, "", err
	}
	return map[string]string{"CertificateAuthorityArn": rec.ARN}, rec.ARN, nil
}

type pcaCADescription struct {
	Arn                               string      `json:"Arn"`
	OwnerAccount                      string      `json:"OwnerAccount,omitempty"`
	CreatedAt                         *awsEpoch   `json:"CreatedAt,omitempty"`
	LastStateChangeAt                 *awsEpoch   `json:"LastStateChangeAt,omitempty"`
	Type                              string      `json:"Type"`
	Serial                            string      `json:"Serial,omitempty"`
	Status                            string      `json:"Status"`
	NotBefore                         *awsEpoch   `json:"NotBefore,omitempty"`
	NotAfter                          *awsEpoch   `json:"NotAfter,omitempty"`
	CertificateAuthorityConfiguration pcaCAConfig `json:"CertificateAuthorityConfiguration"`
	KeyStorageSecurityStandard        string      `json:"KeyStorageSecurityStandard,omitempty"`
	UsageMode                         string      `json:"UsageMode,omitempty"`
}

func describeCA(ca store.PCACertificateAuthority) pcaCADescription {
	d := pcaCADescription{
		Arn: ca.ARN, OwnerAccount: ca.AccountID, Type: ca.Type, Status: ca.State,
		CreatedAt: epochPtr(ca.CreatedAt), LastStateChangeAt: epochPtr(ca.UpdatedAt),
		NotBefore: epochPtr(ca.NotBefore), NotAfter: epochPtr(ca.NotAfter),
		KeyStorageSecurityStandard: "FIPS_140_2_LEVEL_3_OR_HIGHER", UsageMode: "GENERAL_PURPOSE",
	}
	if cert, err := parseCertificateB64(ca.CACertB64); err == nil {
		d.Serial = colonHex(cert.SerialNumber)
		d.CertificateAuthorityConfiguration = pcaCAConfig{
			KeyAlgorithm:     keyAlgorithmOf(cert.PublicKey),
			SigningAlgorithm: awsSigningAlgorithm(cert.SignatureAlgorithm),
			Subject: pcaSubject{
				CommonName:         cert.Subject.CommonName,
				Organization:       first(cert.Subject.Organization),
				OrganizationalUnit: first(cert.Subject.OrganizationalUnit),
				Country:            first(cert.Subject.Country),
				State:              first(cert.Subject.Province),
				Locality:           first(cert.Subject.Locality),
			},
		}
	}
	return d
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func colonHex(n *big.Int) string {
	h := n.Text(16)
	if len(h)%2 == 1 {
		h = "0" + h
	}
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

func awsSigningAlgorithm(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.SHA256WithRSA:
		return "SHA256WITHRSA"
	case x509.SHA384WithRSA:
		return "SHA384WITHRSA"
	case x509.SHA512WithRSA:
		return "SHA512WITHRSA"
	case x509.ECDSAWithSHA256:
		return "SHA256WITHECDSA"
	case x509.ECDSAWithSHA384:
		return "SHA384WITHECDSA"
	case x509.ECDSAWithSHA512:
		return "SHA512WITHECDSA"
	}
	return ""
}

func (s *Server) pcaDescribeCertificateAuthority(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	ca, err := s.pkiLoadCA(ctx, req.CertificateAuthorityArn)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	return map[string]any{"CertificateAuthority": describeCA(ca)}, ca.ARN, nil
}

// pageToken encodes a list offset.
func pageBounds(token string, max, total int) (start, end int, next string, err error) {
	if max <= 0 || max > 1000 {
		max = 100
	}
	if token != "" {
		raw, derr := base64.RawURLEncoding.DecodeString(token)
		n, perr := strconv.Atoi(string(raw))
		if derr != nil || perr != nil || n < 0 || n > total {
			return 0, 0, "", pkiInvalid("NextToken is invalid")
		}
		start = n
	}
	end = start + max
	if end > total {
		end = total
	}
	if end < total {
		next = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	}
	return start, end, next, nil
}

func (s *Server) pcaListCertificateAuthorities(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		MaxResults int    `json:"MaxResults"`
		NextToken  string `json:"NextToken"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	cas, err := s.store.ListCertificateAuthorities(ctx)
	if err != nil {
		return nil, "", err
	}
	sort.SliceStable(cas, func(i, j int) bool { return cas[i].CreatedAt.Before(cas[j].CreatedAt) })
	start, end, next, err := pageBounds(req.NextToken, req.MaxResults, len(cas))
	if err != nil {
		return nil, "", err
	}
	out := make([]pcaCADescription, 0, end-start)
	for _, ca := range cas[start:end] {
		out = append(out, describeCA(ca))
	}
	resp := map[string]any{"CertificateAuthorities": out}
	if next != "" {
		resp["NextToken"] = next
	}
	return resp, "", nil
}

func (s *Server) pcaGetCertificateAuthorityCertificate(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	ca, err := s.pkiLoadCA(ctx, req.CertificateAuthorityArn)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	if ca.State == store.CAStatePendingCertificate {
		return nil, ca.ARN, pkiConflict("InvalidStateException", "certificate authority has no certificate yet; import one with ImportCertificateAuthorityCertificate")
	}
	chain, err := s.pkiChain(ctx, ca)
	if err != nil {
		return nil, ca.ARN, err
	}
	certPEM, rest := splitFirstPEM(chain)
	resp := map[string]string{"Certificate": certPEM}
	if rest != "" {
		resp["CertificateChain"] = rest
	}
	return resp, ca.ARN, nil
}

// splitFirstPEM splits a PEM bundle into its first block and the rest.
func splitFirstPEM(bundle []byte) (string, string) {
	block, rest := pem.Decode(bundle)
	if block == nil {
		return "", ""
	}
	return string(pem.EncodeToMemory(block)), strings.TrimSpace(string(rest))
}

func validityToNotAfter(v struct {
	Value int64  `json:"Value"`
	Type  string `json:"Type"`
}, now time.Time) (time.Time, error) {
	if v.Value <= 0 {
		return time.Time{}, pkiInvalid("Validity.Value must be positive")
	}
	switch strings.ToUpper(v.Type) {
	case "DAYS":
		if v.Value > 3650 {
			return time.Time{}, pkiInvalid("validity must be at most 3650 days")
		}
		return now.AddDate(0, 0, int(v.Value)), nil
	case "MONTHS":
		if v.Value > 120 {
			return time.Time{}, pkiInvalid("validity must be at most 120 months")
		}
		return now.AddDate(0, int(v.Value), 0), nil
	case "YEARS":
		if v.Value > 10 {
			return time.Time{}, pkiInvalid("validity must be at most 10 years")
		}
		return now.AddDate(int(v.Value), 0, 0), nil
	case "ABSOLUTE":
		return time.Unix(v.Value, 0).UTC(), nil
	case "END_DATE":
		t, err := time.Parse("20060102150405", strconv.FormatInt(v.Value, 10))
		if err != nil {
			return time.Time{}, pkiInvalid("END_DATE validity must be YYYYMMDDHHMMSS")
		}
		return t.UTC(), nil
	}
	return time.Time{}, pkiInvalid("Validity.Type must be DAYS, MONTHS, YEARS, ABSOLUTE or END_DATE")
}

func (s *Server) pcaIssueCertificate(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
		Csr                     []byte `json:"Csr"`
		SigningAlgorithm        string `json:"SigningAlgorithm"`
		TemplateArn             string `json:"TemplateArn"`
		Validity                struct {
			Value int64  `json:"Value"`
			Type  string `json:"Type"`
		} `json:"Validity"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	if len(req.Csr) == 0 {
		return nil, "", pkiInvalid("Csr is required")
	}
	ca, err := s.pkiLoadCA(ctx, req.CertificateAuthorityArn)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	tmpl := templateServer
	subCAPathLen := -1
	if req.TemplateArn != "" {
		name := req.TemplateArn[strings.LastIndex(req.TemplateArn, "template/")+len("template/"):]
		switch name {
		case "EndEntityCertificate/V1", "EndEntityServerAuthCertificate/V1":
		case "EndEntityClientAuthCertificate/V1":
			tmpl = templateClient
		default:
			pl, ok := subordinateCATemplates[name]
			if !ok {
				return nil, ca.ARN, pkiInvalid("TemplateArn %q is not supported", name)
			}
			subCAPathLen = pl
		}
	}
	notAfter, err := validityToNotAfter(req.Validity, time.Now().UTC())
	if err != nil {
		return nil, ca.ARN, err
	}
	csr, err := parseCSRInput(req.Csr)
	if err != nil {
		return nil, ca.ARN, err
	}
	if subCAPathLen >= 0 {
		rec, err := s.pkiIssueSubordinateCACert(ctx, ca, csr, subCAPathLen, notAfter)
		if err != nil {
			return nil, ca.ARN, err
		}
		certARN := s.pcaCertARN(ctx, ca.CAID, rec.CertID)
		return map[string]string{"CertificateArn": certARN}, certARN, nil
	}
	leaf, err := s.pkiIssueLeaf(ctx, leafRequest{CA: ca, CSR: csr, Template: tmpl, NotAfter: notAfter})
	if err != nil {
		return nil, ca.ARN, err
	}
	certARN := s.pcaCertARN(ctx, ca.CAID, leaf.rec.CertID)
	return map[string]string{"CertificateArn": certARN}, certARN, nil
}

// pcaCertFromARN resolves ".../certificate-authority/<ca>/certificate/<id>"
// under the given CA.
func (s *Server) pcaCertFromARN(ctx context.Context, ca store.PCACertificateAuthority, certARN string) (store.PCACertificate, error) {
	prefix := ca.ARN + "/certificate/"
	id, ok := strings.CutPrefix(certARN, prefix)
	if !ok || id == "" || strings.Contains(id, "/") {
		return store.PCACertificate{}, pkiNotFound("certificate")
	}
	cert, err := s.store.GetCertificate(ctx, id)
	if err != nil {
		return store.PCACertificate{}, err
	}
	if cert.CAID != ca.CAID {
		return store.PCACertificate{}, pkiNotFound("certificate")
	}
	return cert, nil
}

func certPEMFromB64(b64 string) (string, error) {
	cert, err := parseCertificateB64(b64)
	if err != nil {
		return "", err
	}
	return string(encodeCertificatePEM(cert.Raw)), nil
}

func (s *Server) pcaGetCertificate(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
		CertificateArn          string `json:"CertificateArn"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	ca, err := s.pkiLoadCA(ctx, req.CertificateAuthorityArn)
	if err != nil {
		return nil, req.CertificateArn, err
	}
	cert, err := s.pcaCertFromARN(ctx, ca, req.CertificateArn)
	if err != nil {
		return nil, req.CertificateArn, err
	}
	certPEM, err := certPEMFromB64(cert.CertB64)
	if err != nil {
		return nil, req.CertificateArn, err
	}
	chain, err := s.pkiChain(ctx, ca)
	if err != nil {
		return nil, req.CertificateArn, err
	}
	return map[string]string{"Certificate": certPEM, "CertificateChain": strings.TrimSpace(string(chain))}, req.CertificateArn, nil
}

// parseHexSerial accepts "0a:1b:..." or "0a1b..." and returns the decimal
// form the store keeps.
func parseHexSerial(raw string) (string, bool) {
	h := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), ":", ""))
	if h == "" || len(h) > 64 {
		return "", false
	}
	n, ok := new(big.Int).SetString(h, 16)
	if !ok || n.Sign() <= 0 {
		return "", false
	}
	return n.String(), true
}

func (s *Server) pcaRevokeCertificate(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
		CertificateSerial       string `json:"CertificateSerial"`
		CertificateArn          string `json:"CertificateArn"` // legacy Citadel field
		RevocationReason        string `json:"RevocationReason"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	ca, err := s.pkiLoadCA(ctx, req.CertificateAuthorityArn)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	reason, _, err := normalizeRevocationReason(req.RevocationReason)
	if err != nil {
		return nil, ca.ARN, err
	}
	var cert store.PCACertificate
	switch {
	case req.CertificateSerial != "":
		serial, ok := parseHexSerial(req.CertificateSerial)
		if !ok {
			return nil, ca.ARN, pkiInvalid("CertificateSerial must be a hexadecimal serial number")
		}
		matches, err := s.store.FindCertificatesBySerial(ctx, serial)
		if err != nil {
			return nil, ca.ARN, err
		}
		found := false
		for _, m := range matches {
			if m.CAID == ca.CAID {
				cert, found = m, true
			}
		}
		if !found {
			return nil, ca.ARN, pkiNotFound("certificate")
		}
	case req.CertificateArn != "":
		if cert, err = s.pcaCertFromARN(ctx, ca, req.CertificateArn); err != nil {
			return nil, ca.ARN, err
		}
	default:
		return nil, ca.ARN, pkiInvalid("CertificateSerial is required")
	}
	resource := s.pcaCertARN(ctx, ca.CAID, cert.CertID)
	if err := s.store.RevokeCertificate(ctx, cert.CertID, reason); err != nil {
		return nil, resource, err
	}
	return nil, resource, nil
}

func (s *Server) pcaGetCRL(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	ca, err := s.pkiLoadCA(ctx, req.CertificateAuthorityArn)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	crl, err := s.buildCRL(ctx, ca)
	if err != nil {
		return nil, ca.ARN, err
	}
	return map[string]string{"CRL": base64.StdEncoding.EncodeToString(crl)}, ca.ARN, nil
}

// ---- ACM ----

func acmKeyAlgorithm(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "", "RSA_2048":
		return keyAlgRSA2048, nil
	case "RSA_3072":
		return keyAlgRSA3072, nil
	case "RSA_4096":
		return keyAlgRSA4096, nil
	case "EC_prime256v1":
		return keyAlgP256, nil
	case "EC_secp384r1":
		return keyAlgP384, nil
	}
	return "", pkiInvalid("KeyAlgorithm must be RSA_2048, RSA_3072, RSA_4096, EC_prime256v1 or EC_secp384r1")
}

// issueWithGeneratedKey creates a key pair inside Citadel and issues a leaf
// for it. The caller decides whether the private key is stored.
func (s *Server) issueWithGeneratedKey(ctx context.Context, ca store.PCACertificateAuthority, keyAlg, commonName string, sans []string, tmpl string, validity time.Duration) (*issuedLeaf, []byte, error) {
	key, err := generateLeafKey(keyAlg)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := s.pkiIssueLeaf(ctx, leafRequest{CA: ca, CSR: csr, Template: tmpl, CommonName: commonName, ExtraSANs: sans, Validity: validity})
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return leaf, keyDER, nil
}

func (s *Server) acmRequestCertificate(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		DomainName              string   `json:"DomainName"`
		SubjectAlternativeNames []string `json:"SubjectAlternativeNames"`
		CertificateAuthorityArn string   `json:"CertificateAuthorityArn"`
		KeyAlgorithm            string   `json:"KeyAlgorithm"`
		IdempotencyToken        string   `json:"IdempotencyToken"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	domain := strings.ToLower(strings.TrimSpace(req.DomainName))
	if domain == "" || !validSANDNSName(domain) {
		return nil, "", pkiInvalid("DomainName must be a valid DNS name")
	}
	if len(req.SubjectAlternativeNames) > 100 {
		return nil, "", pkiInvalid("at most 100 SubjectAlternativeNames are allowed")
	}
	if req.CertificateAuthorityArn == "" {
		return nil, "", pkiInvalid("CertificateAuthorityArn is required: Citadel issues private certificates only")
	}
	keyAlg, err := acmKeyAlgorithm(req.KeyAlgorithm)
	if err != nil {
		return nil, "", err
	}
	ca, err := s.pkiLoadCA(ctx, req.CertificateAuthorityArn)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	sans := append([]string{domain}, req.SubjectAlternativeNames...)
	certARN, err := s.acmIdempotent(ctx, "RequestCertificate", req.IdempotencyToken, s.acmCertARN(ctx, cryptoutil.RandomHex(16)),
		[]any{domain, req.SubjectAlternativeNames, ca.ARN, keyAlg}, func(certARN string) error {
			return s.acmIssuePrivate(ctx, ca, certARN, domain, sans, keyAlg)
		})
	if err != nil {
		return nil, certARN, err
	}
	return map[string]string{"CertificateArn": certARN}, certARN, nil
}

// acmIssuePrivate issues a private certificate for ACM with a generated key
// and stores it under certARN.
func (s *Server) acmIssuePrivate(ctx context.Context, ca store.PCACertificateAuthority, certARN, domain string, sans []string, keyAlg string) error {
	leaf, keyDER, err := s.issueWithGeneratedKey(ctx, ca, keyAlg, domain, sans, templateServer, 395*24*time.Hour)
	if err != nil {
		return err
	}
	defer clear(keyDER)
	now := time.Now().UTC()
	c := store.ACMCertificate{
		ARN: certARN, Type: store.ACMTypePrivate, CAID: ca.CAID, PCACertID: leaf.rec.CertID,
		DomainName: domain, SANs: leaf.cert.DNSNames, Serial: leaf.rec.Serial, CertB64: leaf.rec.CertB64,
		ChainPEM: string(leaf.chainPEM), KeyDER: keyDER, Status: "ISSUED",
		NotBefore: leaf.rec.NotBefore, NotAfter: leaf.rec.NotAfter, CreatedAt: now, UpdatedAt: now,
	}
	return s.store.CreateACMCertificate(ctx, c)
}

func acmCertARNArg(body []byte) (string, error) {
	var req struct {
		CertificateArn string `json:"CertificateArn"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return "", err
	}
	if strings.TrimSpace(req.CertificateArn) == "" {
		return "", pkiInvalid("CertificateArn is required")
	}
	return req.CertificateArn, nil
}

type acmCertificateDetail struct {
	CertificateArn          string            `json:"CertificateArn"`
	DomainName              string            `json:"DomainName"`
	SubjectAlternativeNames []string          `json:"SubjectAlternativeNames"`
	Serial                  string            `json:"Serial,omitempty"`
	Subject                 string            `json:"Subject,omitempty"`
	Issuer                  string            `json:"Issuer,omitempty"`
	CreatedAt               *awsEpoch         `json:"CreatedAt,omitempty"`
	IssuedAt                *awsEpoch         `json:"IssuedAt,omitempty"`
	ImportedAt              *awsEpoch         `json:"ImportedAt,omitempty"`
	Status                  string            `json:"Status"`
	NotBefore               *awsEpoch         `json:"NotBefore,omitempty"`
	NotAfter                *awsEpoch         `json:"NotAfter,omitempty"`
	KeyAlgorithm            string            `json:"KeyAlgorithm,omitempty"`
	SignatureAlgorithm      string            `json:"SignatureAlgorithm,omitempty"`
	InUseBy                 []string          `json:"InUseBy"`
	Type                    string            `json:"Type"`
	CertificateAuthorityArn string            `json:"CertificateAuthorityArn,omitempty"`
	RenewalEligibility      string            `json:"RenewalEligibility"`
	KeyUsages               []map[string]any  `json:"KeyUsages,omitempty"`
	ExtendedKeyUsages       []map[string]any  `json:"ExtendedKeyUsages,omitempty"`
	Options                 map[string]string `json:"Options,omitempty"`
}

func (s *Server) describeACM(ctx context.Context, c store.ACMCertificate) acmCertificateDetail {
	d := acmCertificateDetail{
		CertificateArn: c.ARN, DomainName: c.DomainName, SubjectAlternativeNames: c.SANs, Status: c.Status,
		CreatedAt: epochPtr(c.CreatedAt), NotBefore: epochPtr(c.NotBefore), NotAfter: epochPtr(c.NotAfter),
		InUseBy: []string{}, Type: c.Type, RenewalEligibility: "INELIGIBLE",
	}
	if c.Type == store.ACMTypePrivate {
		d.IssuedAt = epochPtr(c.UpdatedAt)
		d.RenewalEligibility = "ELIGIBLE"
		if c.CAID != "" {
			d.CertificateAuthorityArn = s.pcaCAARN(ctx, c.CAID)
		}
	} else {
		d.ImportedAt = epochPtr(c.UpdatedAt)
	}
	if d.SubjectAlternativeNames == nil {
		d.SubjectAlternativeNames = []string{}
	}
	if cert, err := parseCertificateB64(c.CertB64); err == nil {
		d.Serial = colonHex(cert.SerialNumber)
		d.Subject = cert.Subject.String()
		d.Issuer = cert.Issuer.String()
		d.KeyAlgorithm = keyAlgorithmOf(cert.PublicKey)
		d.SignatureAlgorithm = awsSigningAlgorithm(cert.SignatureAlgorithm)
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			d.KeyUsages = append(d.KeyUsages, map[string]any{"Name": "DIGITAL_SIGNATURE"})
		}
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			d.KeyUsages = append(d.KeyUsages, map[string]any{"Name": "KEY_ENCIPHERMENT"})
		}
		for _, e := range cert.ExtKeyUsage {
			switch e {
			case x509.ExtKeyUsageServerAuth:
				d.ExtendedKeyUsages = append(d.ExtendedKeyUsages, map[string]any{"Name": "TLS_WEB_SERVER_AUTHENTICATION", "OID": "1.3.6.1.5.5.7.3.1"})
			case x509.ExtKeyUsageClientAuth:
				d.ExtendedKeyUsages = append(d.ExtendedKeyUsages, map[string]any{"Name": "TLS_WEB_CLIENT_AUTHENTICATION", "OID": "1.3.6.1.5.5.7.3.2"})
			}
		}
	}
	return d
}

// acmStatus reports EXPIRED for an issued certificate past notAfter even
// before the expiry job has run.
func acmStatus(c store.ACMCertificate, now time.Time) string {
	if c.Status == "ISSUED" && now.After(c.NotAfter) {
		return "EXPIRED"
	}
	return c.Status
}

func (s *Server) acmDescribeCertificate(ctx context.Context, body []byte) (any, string, error) {
	certARN, err := acmCertARNArg(body)
	if err != nil {
		return nil, "", err
	}
	c, err := s.store.GetACMCertificate(ctx, certARN)
	if err != nil {
		return nil, certARN, err
	}
	clear(c.KeyDER)
	c.Status = acmStatus(c, time.Now())
	return map[string]any{"Certificate": s.describeACM(ctx, c)}, certARN, nil
}

func (s *Server) acmListCertificates(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateStatuses []string `json:"CertificateStatuses"`
		MaxItems            int      `json:"MaxItems"`
		NextToken           string   `json:"NextToken"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	all, err := s.store.ListACMCertificates(ctx)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	want := map[string]bool{}
	for _, st := range req.CertificateStatuses {
		want[strings.ToUpper(st)] = true
	}
	var certs []store.ACMCertificate
	for _, c := range all {
		c.Status = acmStatus(c, now)
		if len(want) == 0 || want[c.Status] {
			certs = append(certs, c)
		}
	}
	start, end, next, err := pageBounds(req.NextToken, req.MaxItems, len(certs))
	if err != nil {
		return nil, "", err
	}
	out := make([]map[string]any, 0, end-start)
	for _, c := range certs[start:end] {
		d := s.describeACM(ctx, c)
		out = append(out, map[string]any{
			"CertificateArn": c.ARN, "DomainName": c.DomainName, "Status": c.Status, "Type": c.Type,
			"KeyAlgorithm": d.KeyAlgorithm, "NotBefore": d.NotBefore, "NotAfter": d.NotAfter, "CreatedAt": d.CreatedAt,
			"SubjectAlternativeNameSummaries": d.SubjectAlternativeNames, "InUse": false, "RenewalEligibility": d.RenewalEligibility,
		})
	}
	resp := map[string]any{"CertificateSummaryList": out}
	if next != "" {
		resp["NextToken"] = next
	}
	return resp, "", nil
}

func (s *Server) acmGetCertificate(ctx context.Context, body []byte) (any, string, error) {
	certARN, err := acmCertARNArg(body)
	if err != nil {
		return nil, "", err
	}
	c, err := s.store.GetACMCertificate(ctx, certARN)
	if err != nil {
		return nil, certARN, err
	}
	clear(c.KeyDER)
	certPEM, err := certPEMFromB64(c.CertB64)
	if err != nil {
		return nil, certARN, err
	}
	resp := map[string]string{"Certificate": certPEM}
	if strings.TrimSpace(c.ChainPEM) != "" {
		resp["CertificateChain"] = strings.TrimSpace(c.ChainPEM)
	}
	return resp, certARN, nil
}

func (s *Server) acmDeleteCertificate(ctx context.Context, body []byte) (any, string, error) {
	certARN, err := acmCertARNArg(body)
	if err != nil {
		return nil, "", err
	}
	if err := s.store.DeleteACMCertificate(ctx, certARN); err != nil {
		return nil, certARN, err
	}
	return nil, certARN, nil
}

// parseImportedKey parses an unencrypted PEM private key and checks it is
// FIPS-approved.
func parseImportedKey(pemBytes []byte) ([]byte, any, error) {
	signer, pub, err := parsePrivateKeyPEM(pemBytes)
	if err != nil {
		return nil, nil, pkiInvalid("PrivateKey must be an unencrypted PEM private key")
	}
	if err := checkApprovedPublicKey(pub); err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, nil, pkiInvalid("PrivateKey could not be encoded")
	}
	return der, pub, nil
}

func (s *Server) acmImportCertificate(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateArn   string `json:"CertificateArn"`
		Certificate      []byte `json:"Certificate"`
		PrivateKey       []byte `json:"PrivateKey"`
		CertificateChain []byte `json:"CertificateChain"`
		IdempotencyToken string `json:"IdempotencyToken"` // Citadel extension
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	defer clear(req.PrivateKey)
	if len(req.Certificate) == 0 || len(req.PrivateKey) == 0 {
		return nil, req.CertificateArn, pkiInvalid("Certificate and PrivateKey are required")
	}
	cert, err := parseCertificatePEM(req.Certificate)
	if err != nil {
		return nil, req.CertificateArn, pkiInvalid("Certificate must be a PEM certificate")
	}
	if err := checkApprovedPublicKey(cert.PublicKey); err != nil {
		return nil, req.CertificateArn, err
	}
	keyDER, pub, err := parseImportedKey(req.PrivateKey)
	if err != nil {
		return nil, req.CertificateArn, err
	}
	defer clear(keyDER)
	if !publicKeysEqual(cert.PublicKey, pub) {
		return nil, req.CertificateArn, pkiInvalid("the private key does not match the certificate")
	}
	var chain strings.Builder
	rest := req.CertificateChain
	for len(strings.TrimSpace(string(rest))) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, req.CertificateArn, pkiInvalid("CertificateChain must contain only PEM certificates")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, req.CertificateArn, pkiInvalid("CertificateChain contains an invalid certificate")
		}
		chain.Write(pem.EncodeToMemory(block))
	}
	domain := cert.Subject.CommonName
	if len(cert.DNSNames) > 0 {
		domain = cert.DNSNames[0]
	}
	now := time.Now().UTC()
	c := store.ACMCertificate{
		Type: store.ACMTypeImported, DomainName: domain, SANs: cert.DNSNames, Serial: cert.SerialNumber.String(),
		CertB64: base64.StdEncoding.EncodeToString(cert.Raw), ChainPEM: chain.String(), KeyDER: keyDER, Status: "ISSUED",
		NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), CreatedAt: now, UpdatedAt: now,
	}
	if now.After(cert.NotAfter) {
		c.Status = "EXPIRED"
	}
	newARN := req.CertificateArn
	if newARN == "" {
		newARN = s.acmCertARN(ctx, cryptoutil.RandomHex(16))
	}
	// The certificate fixes the key, so the key itself is not part of the
	// parameters compared for an idempotent retry.
	arnOut, err := s.acmIdempotent(ctx, "ImportCertificate", req.IdempotencyToken, newARN,
		[]any{req.CertificateArn, cert.Raw, chain.String()}, func(certARN string) error {
			if req.CertificateArn != "" {
				// Re-import replaces an imported certificate in place.
				prev, err := s.store.GetACMCertificate(ctx, req.CertificateArn)
				if err != nil {
					return err
				}
				clear(prev.KeyDER)
				if prev.Type != store.ACMTypeImported {
					return pkiInvalid("only imported certificates can be re-imported")
				}
				c.ARN = prev.ARN
				return s.store.UpdateACMCertificate(ctx, c)
			}
			c.ARN = certARN
			return s.store.CreateACMCertificate(ctx, c)
		})
	if err != nil {
		return nil, arnOut, err
	}
	return map[string]string{"CertificateArn": arnOut}, arnOut, nil
}

func (s *Server) acmExportCertificate(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateArn string `json:"CertificateArn"`
		Passphrase     []byte `json:"Passphrase"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	defer clear(req.Passphrase)
	if req.CertificateArn == "" {
		return nil, "", pkiInvalid("CertificateArn is required")
	}
	if len(req.Passphrase) < 4 || len(req.Passphrase) > 128 {
		return nil, req.CertificateArn, pkiInvalid("Passphrase must be 4 to 128 bytes")
	}
	c, err := s.store.GetACMCertificate(ctx, req.CertificateArn)
	if err != nil {
		return nil, req.CertificateArn, err
	}
	defer clear(c.KeyDER)
	if c.Type != store.ACMTypePrivate || len(c.KeyDER) == 0 {
		return nil, req.CertificateArn, pkiInvalid("only private certificates issued by Citadel can be exported")
	}
	certPEM, err := certPEMFromB64(c.CertB64)
	if err != nil {
		return nil, req.CertificateArn, err
	}
	encKey, err := encryptPKCS8PEM(c.KeyDER, req.Passphrase)
	if err != nil {
		return nil, req.CertificateArn, err
	}
	return map[string]string{
		"Certificate":      certPEM,
		"CertificateChain": strings.TrimSpace(c.ChainPEM),
		"PrivateKey":       string(encKey),
	}, req.CertificateArn, nil
}

func (s *Server) acmRenewCertificate(ctx context.Context, body []byte) (any, string, error) {
	certARN, err := acmCertARNArg(body)
	if err != nil {
		return nil, "", err
	}
	c, err := s.store.GetACMCertificate(ctx, certARN)
	if err != nil {
		return nil, certARN, err
	}
	defer clear(c.KeyDER)
	if c.Type != store.ACMTypePrivate || len(c.KeyDER) == 0 {
		return nil, certARN, pkiInvalid("only private certificates issued by Citadel can be renewed")
	}
	ca, err := s.store.GetCertificateAuthorityByID(ctx, c.CAID)
	if err != nil {
		return nil, certARN, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(c.KeyDER)
	if err != nil {
		return nil, certARN, fmt.Errorf("stored key: %w", err)
	}
	if _, ok := priv.(crypto.Signer); !ok {
		return nil, certARN, errors.New("stored key is not a signer")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		return nil, certARN, fmt.Errorf("create CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, certARN, err
	}
	leaf, err := s.pkiIssueLeaf(ctx, leafRequest{CA: ca, CSR: csr, Template: templateServer, CommonName: c.DomainName,
		ExtraSANs: append([]string{c.DomainName}, c.SANs...), Validity: 395 * 24 * time.Hour})
	if err != nil {
		return nil, certARN, err
	}
	c.PCACertID, c.Serial, c.CertB64, c.ChainPEM = leaf.rec.CertID, leaf.rec.Serial, leaf.rec.CertB64, string(leaf.chainPEM)
	c.NotBefore, c.NotAfter, c.Status = leaf.rec.NotBefore, leaf.rec.NotAfter, "ISSUED"
	if err := s.store.UpdateACMCertificate(ctx, c); err != nil {
		return nil, certARN, err
	}
	return nil, certARN, nil
}
