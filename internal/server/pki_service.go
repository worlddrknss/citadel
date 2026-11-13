package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Protocol-free private-CA logic shared by the native /v1 certificate API,
// the ACM / ACM PCA AWS APIs and the ACME server's issuer.

// pkiError is a client-facing PKI failure: a stable code and message that are
// safe to return. Anything else is an internal error, logged and reported
// generically.
type pkiError struct {
	status  int
	code    string // native API error code
	awsType string // AWS exception type
	msg     string
}

func (e *pkiError) Error() string { return e.msg }

func pkiInvalid(format string, args ...any) error {
	return &pkiError{status: http.StatusBadRequest, code: "invalid_request", awsType: "ValidationException", msg: fmt.Sprintf(format, args...)}
}

func pkiNotFound(what string) error {
	return &pkiError{status: http.StatusNotFound, code: "not_found", awsType: "ResourceNotFoundException", msg: what + " not found"}
}

func pkiConflict(awsType, format string, args ...any) error {
	return &pkiError{status: http.StatusConflict, code: "conflict", awsType: awsType, msg: fmt.Sprintf(format, args...)}
}

// pkiClientError maps err to a client-safe error, logging internal failures.
func pkiClientError(op string, err error) *pkiError {
	var pe *pkiError
	if errors.As(err, &pe) {
		return pe
	}
	switch {
	case errors.Is(err, store.ErrCANotFound):
		return pkiNotFound("certificate authority").(*pkiError)
	case errors.Is(err, store.ErrCertificateNotFound), errors.Is(err, store.ErrACMCertificateNotFound):
		return pkiNotFound("certificate").(*pkiError)
	case errors.Is(err, store.ErrCertificateAlreadyRevoked):
		return pkiConflict("RequestAlreadyProcessedException", "certificate is already revoked").(*pkiError)
	case errors.Is(err, store.ErrUnsupported):
		return &pkiError{status: http.StatusNotImplemented, code: "unsupported", awsType: "InvalidRequestException", msg: "this operation is not supported by the configured store"}
	}
	log.Printf("pki: %s: %v", op, err)
	return &pkiError{status: http.StatusInternalServerError, code: "internal_error", awsType: "InternalFailure", msg: op + " failed"}
}

// Key algorithms accepted for CA keys and generated leaf keys (FIPS 140-3
// approved sizes and curves only).
const (
	keyAlgP256    = "EC_prime256v1"
	keyAlgP384    = "EC_secp384r1"
	keyAlgRSA2048 = "RSA_2048"
	keyAlgRSA3072 = "RSA_3072"
	keyAlgRSA4096 = "RSA_4096"
)

func kmsKeySpecForAlgorithm(alg string) (string, error) {
	switch alg {
	case keyAlgP256:
		return store.KeySpecECCP256, nil
	case keyAlgP384:
		return store.KeySpecECCP384, nil
	case keyAlgRSA2048:
		return store.KeySpecRSA2048, nil
	case keyAlgRSA3072:
		return store.KeySpecRSA3072, nil
	case keyAlgRSA4096:
		return store.KeySpecRSA4096, nil
	}
	return "", pkiInvalid("keyAlgorithm must be one of EC_prime256v1, EC_secp384r1, RSA_2048, RSA_3072, RSA_4096")
}

// keyAlgorithmOf names a public key the way the console and AWS do.
func keyAlgorithmOf(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return keyAlgP256
		case elliptic.P384():
			return keyAlgP384
		}
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA_%d", k.N.BitLen())
	}
	return ""
}

// checkApprovedPublicKey rejects keys outside the FIPS-approved set.
func checkApprovedPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
		return pkiInvalid("ECDSA keys must use P-256 or P-384")
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048, 3072, 4096:
			return nil
		}
		return pkiInvalid("RSA keys must be 2048, 3072 or 4096 bits")
	}
	return pkiInvalid("key type must be RSA or ECDSA")
}

// generateLeafKey creates a FIPS-approved key pair.
func generateLeafKey(alg string) (crypto.Signer, error) {
	switch alg {
	case keyAlgP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case keyAlgP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case keyAlgRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case keyAlgRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case keyAlgRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, pkiInvalid("keyAlgorithm must be one of EC_prime256v1, EC_secp384r1, RSA_2048, RSA_3072, RSA_4096")
}

// approvedCSRSignature lists FIPS-approved CSR signature algorithms; checking
// first keeps SHA-1/MD5 signatures away from the verifier.
func approvedCSRSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	}
	return false
}

// parseCSRInput accepts a PEM or DER PKCS#10 request and verifies its
// algorithm, key and self-signature.
func parseCSRInput(raw []byte) (*x509.CertificateRequest, error) {
	der := raw
	if block, _ := pem.Decode(bytes.TrimSpace(raw)); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, pkiInvalid("CSR must be a PEM CERTIFICATE REQUEST")
		}
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, pkiInvalid("CSR could not be parsed")
	}
	if !approvedCSRSignature(csr.SignatureAlgorithm) {
		return nil, pkiInvalid("CSR signature algorithm %s is not allowed", csr.SignatureAlgorithm)
	}
	if err := checkApprovedPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, pkiInvalid("CSR signature is invalid")
	}
	return csr, nil
}

func csrPEM(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
}

// caSigner signs with a CA's KMS key in-process. The hash comes from the
// signer options x509 passes, so the signature always matches the
// certificate's declared algorithm.
type caSigner struct {
	key store.KMSKey
	pub crypto.PublicKey
}

func (c *caSigner) Public() crypto.PublicKey { return c.pub }

func (c *caSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, pss := opts.(*rsa.PSSOptions); pss {
		return nil, errors.New("caSigner: RSA-PSS is not supported")
	}
	var alg string
	switch c.pub.(type) {
	case *rsa.PublicKey:
		switch opts.HashFunc() {
		case crypto.SHA256:
			alg = "RSASSA_PKCS1_V1_5_SHA_256"
		case crypto.SHA384:
			alg = "RSASSA_PKCS1_V1_5_SHA_384"
		case crypto.SHA512:
			alg = "RSASSA_PKCS1_V1_5_SHA_512"
		}
	case *ecdsa.PublicKey:
		switch opts.HashFunc() {
		case crypto.SHA256:
			alg = "ECDSA_SHA_256"
		case crypto.SHA384:
			alg = "ECDSA_SHA_384"
		case crypto.SHA512:
			alg = "ECDSA_SHA_512"
		}
	}
	if alg == "" {
		return nil, fmt.Errorf("caSigner: unsupported hash %v", opts.HashFunc())
	}
	return signDigestWithKey(c.key, alg, digest)
}

// caSignatureAlgorithm picks the certificate signature algorithm for a CA key.
func caSignatureAlgorithm(pub crypto.PublicKey) x509.SignatureAlgorithm {
	if k, ok := pub.(*ecdsa.PublicKey); ok {
		if k.Curve == elliptic.P384() {
			return x509.ECDSAWithSHA384
		}
		return x509.ECDSAWithSHA256
	}
	return x509.SHA256WithRSA
}

// loadedCA is a CA ready to sign.
type loadedCA struct {
	rec    store.PCACertificateAuthority
	cert   *x509.Certificate
	signer *caSigner
}

// pkiLoadCA resolves a CA by ID or ARN within the caller's account.
func (s *Server) pkiLoadCA(ctx context.Context, idOrARN string) (store.PCACertificateAuthority, error) {
	idOrARN = strings.TrimSpace(idOrARN)
	if idOrARN == "" {
		return store.PCACertificateAuthority{}, pkiInvalid("a certificate authority is required")
	}
	if strings.HasPrefix(idOrARN, "arn:") {
		return s.store.DescribeCertificateAuthority(ctx, idOrARN)
	}
	return s.store.GetCertificateAuthorityByID(ctx, idOrARN)
}

// pkiSigningCA loads a CA's certificate and key and checks it may sign now.
func (s *Server) pkiSigningCA(ctx context.Context, rec store.PCACertificateAuthority, now time.Time) (*loadedCA, error) {
	if rec.State != "ACTIVE" {
		return nil, pkiConflict("InvalidStateException", "certificate authority is %s, not ACTIVE", strings.ToLower(rec.State))
	}
	cert, err := parseCertificateB64(rec.CACertB64)
	if err != nil {
		return nil, fmt.Errorf("CA %s certificate: %w", rec.CAID, err)
	}
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		return nil, pkiConflict("InvalidStateException", "certificate authority is outside its validity period")
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, pkiConflict("InvalidStateException", "certificate authority certificate may not sign certificates")
	}
	key, err := s.store.ResolveByID(ctx, rec.KMSKeyID)
	if err != nil {
		return nil, fmt.Errorf("CA %s key: %w", rec.CAID, err)
	}
	pub, err := x509.ParsePKIXPublicKey(key.PublicKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("CA %s public key: %w", rec.CAID, err)
	}
	if !publicKeysEqual(pub, cert.PublicKey) {
		return nil, fmt.Errorf("CA %s key does not match its certificate", rec.CAID)
	}
	return &loadedCA{rec: rec, cert: cert, signer: &caSigner{key: key, pub: pub}}, nil
}

// pkiChain returns the PEM chain above a leaf issued by rec: rec's
// certificate followed by its ancestors up to the root.
func (s *Server) pkiChain(ctx context.Context, rec store.PCACertificateAuthority) ([]byte, error) {
	var out bytes.Buffer
	seen := map[string]bool{}
	cur := rec
	for depth := 0; depth < 16; depth++ {
		if seen[cur.CAID] {
			return nil, fmt.Errorf("CA %s: parent cycle", rec.CAID)
		}
		seen[cur.CAID] = true
		cert, err := parseCertificateB64(cur.CACertB64)
		if err != nil {
			return nil, fmt.Errorf("CA %s certificate: %w", cur.CAID, err)
		}
		out.Write(encodeCertificatePEM(cert.Raw))
		if cur.ParentCAID == "" {
			return out.Bytes(), nil
		}
		parent, err := s.store.GetCertificateAuthorityByID(ctx, cur.ParentCAID)
		if err != nil {
			return nil, fmt.Errorf("CA %s parent: %w", cur.CAID, err)
		}
		cur = parent
	}
	return nil, fmt.Errorf("CA %s: chain too deep", rec.CAID)
}

// caCreateRequest describes a new CA.
type caCreateRequest struct {
	Type         string // ROOT or SUBORDINATE
	KeyAlgorithm string
	Subject      subjectConfig
	ParentCAID   string // required for SUBORDINATE
	Description  string
}

const (
	rootCAValidity = 10 * 365 * 24 * time.Hour
	subCAValidity  = 5 * 365 * 24 * time.Hour
)

func validateSubject(subj subjectConfig) error {
	if strings.TrimSpace(subj.CommonName) == "" {
		return pkiInvalid("commonName is required")
	}
	for _, v := range []string{subj.CommonName, subj.Organization, subj.OrganizationUnit, subj.Country, subj.State, subj.Locality} {
		if len(v) > 64 || strings.ContainsAny(v, ",=\r\n") {
			return pkiInvalid("subject fields must be at most 64 characters and must not contain ',', '=' or line breaks")
		}
	}
	if c := strings.TrimSpace(subj.Country); c != "" && len(c) != 2 {
		return pkiInvalid("country must be a two-letter code")
	}
	return nil
}

// pkiCreateCA creates a root CA, or a subordinate CA signed by its parent.
func (s *Server) pkiCreateCA(ctx context.Context, req caCreateRequest) (store.PCACertificateAuthority, error) {
	caType := strings.ToUpper(strings.TrimSpace(req.Type))
	if caType == "" {
		caType = "ROOT"
	}
	if caType != "ROOT" && caType != "SUBORDINATE" {
		return store.PCACertificateAuthority{}, pkiInvalid("caType must be ROOT or SUBORDINATE")
	}
	if req.KeyAlgorithm == "" {
		req.KeyAlgorithm = keyAlgRSA2048
	}
	keySpec, err := kmsKeySpecForAlgorithm(req.KeyAlgorithm)
	if err != nil {
		return store.PCACertificateAuthority{}, err
	}
	for _, f := range []*string{&req.Subject.CommonName, &req.Subject.Organization, &req.Subject.Country} {
		*f = strings.TrimSpace(*f)
	}
	if err := validateSubject(req.Subject); err != nil {
		return store.PCACertificateAuthority{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)

	var parent *loadedCA
	notAfter := now.Add(rootCAValidity)
	pathLen := -1 // unconstrained
	if caType == "SUBORDINATE" {
		if strings.TrimSpace(req.ParentCAID) == "" {
			return store.PCACertificateAuthority{}, pkiInvalid("parentCaId is required for a subordinate CA")
		}
		prec, err := s.pkiLoadCA(ctx, req.ParentCAID)
		if err != nil {
			return store.PCACertificateAuthority{}, err
		}
		if parent, err = s.pkiSigningCA(ctx, prec, now); err != nil {
			return store.PCACertificateAuthority{}, err
		}
		// RFC 5280 §4.2.1.9: a CA with pathLenConstraint 0 may not sign
		// CA certificates; below a constrained parent the child's limit
		// shrinks by one. Under an unconstrained parent the new CA issues
		// end-entity certificates only.
		pc := parent.cert
		switch {
		case pc.MaxPathLen == 0 && pc.MaxPathLenZero:
			return store.PCACertificateAuthority{}, pkiConflict("InvalidStateException", "the parent CA's path length constraint does not allow subordinate CAs")
		case pc.MaxPathLen > 0:
			pathLen = pc.MaxPathLen - 1
		default:
			pathLen = 0
		}
		notAfter = now.Add(subCAValidity)
		if notAfter.After(pc.NotAfter) {
			notAfter = pc.NotAfter
		}
	}

	key, err := s.store.CreateKey(ctx, "Private CA key: "+req.Subject.CommonName, store.KeyUsageSignVerify, keySpec)
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("create CA key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(key.PublicKeyRaw)
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("parse CA public key: %w", err)
	}
	serial, err := generateSerialNumber()
	if err != nil {
		return store.PCACertificateAuthority{}, err
	}
	subject := pkix.Name{CommonName: req.Subject.CommonName}
	if req.Subject.Organization != "" {
		subject.Organization = []string{req.Subject.Organization}
	}
	if req.Subject.OrganizationUnit != "" {
		subject.OrganizationalUnit = []string{req.Subject.OrganizationUnit}
	}
	if req.Subject.Country != "" {
		subject.Country = []string{strings.ToUpper(req.Subject.Country)}
	}
	if req.Subject.State != "" {
		subject.Province = []string{req.Subject.State}
	}
	if req.Subject.Locality != "" {
		subject.Locality = []string{req.Subject.Locality}
	}
	caID := cryptoutil.RandomHex(12)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
	}
	signerKey := crypto.Signer(&caSigner{key: key, pub: pub})
	issuerCert := tmpl
	if parent != nil {
		signerKey, issuerCert = parent.signer, parent.cert
		tmpl.SignatureAlgorithm = caSignatureAlgorithm(parent.signer.pub)
		if dp := s.crlURL(parent.rec.CAID); dp != "" {
			tmpl.CRLDistributionPoints = []string{dp}
		}
	} else {
		tmpl.SignatureAlgorithm = caSignatureAlgorithm(pub)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, pub, signerKey)
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return store.PCACertificateAuthority{}, err
	}
	if parent != nil {
		if err := cert.CheckSignatureFrom(parent.cert); err != nil {
			return store.PCACertificateAuthority{}, fmt.Errorf("verify subordinate CA signature: %w", err)
		}
	}
	rec := store.PCACertificateAuthority{
		CAID:        caID,
		ARN:         s.pcaCAARN(ctx, caID),
		Type:        caType,
		KMSKeyID:    key.ID,
		SubjectDN:   formatSubjectDN(req.Subject),
		State:       "ACTIVE",
		CACertB64:   base64.StdEncoding.EncodeToString(der),
		PathLength:  caPathLength(cert),
		NotBefore:   cert.NotBefore.UTC(),
		NotAfter:    cert.NotAfter.UTC(),
		Description: strings.TrimSpace(req.Description),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if parent != nil {
		rec.ParentCAID = parent.rec.CAID
	}
	if err := s.store.CreateCertificateAuthority(ctx, rec); err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("store CA: %w", err)
	}
	s.assignCAKeyAlias(ctx, key.ID, req.Subject.CommonName, caID)
	return rec, nil
}

// crlURL is the public CRL distribution point for a CA, or "" when no public
// URL is configured.
func (s *Server) crlURL(caID string) string {
	if s.cfg.PublicURL == "" {
		return ""
	}
	return s.cfg.PublicURL + "/crl/" + caID
}

// Certificate templates.
const (
	templateServer = "server"
	templateClient = "client"
)

func awsTemplateName(t string) string {
	if t == templateClient {
		return "EndEntityClientAuthCertificate/V1"
	}
	return "EndEntityServerAuthCertificate/V1"
}

// consoleTemplate is the template name the console shows for a stored AWS
// template name: server, client, or "" when none was recorded or the
// certificate is a subordinate CA certificate.
func consoleTemplate(name string) string {
	if name == "" || isSubordinateCATemplate(name) {
		return ""
	}
	return templateFromAWSName(name)
}

func templateFromAWSName(name string) string {
	if strings.Contains(name, "ClientAuth") {
		return templateClient
	}
	return templateServer
}

// leafRequest describes a leaf certificate to issue.
type leafRequest struct {
	CA         store.PCACertificateAuthority
	CSR        *x509.CertificateRequest
	Template   string // server (default) or client
	CommonName string // overrides the CSR's CN when set
	// ExtraSANs are added to the CSR's SANs. With ExactNames the CSR's
	// names are ignored and these are the certificate's only SANs.
	ExtraSANs  []string
	ExactNames bool
	NotAfter   time.Time // zero means now + Validity
	Validity   time.Duration
}

const maxLeafValidity = 3650 * 24 * time.Hour

// issuedLeaf is a signed, stored leaf certificate.
type issuedLeaf struct {
	rec      store.PCACertificate
	cert     *x509.Certificate
	chainPEM []byte
}

func splitSANs(names []string) (dns []string, ips []net.IP, emails []string, err error) {
	for _, raw := range names {
		n := strings.TrimSpace(raw)
		if n == "" {
			continue
		}
		switch {
		case net.ParseIP(n) != nil:
			ips = appendUniqueIPs(ips, net.ParseIP(n))
		case strings.Contains(n, "@"):
			if len(n) > 254 || strings.ContainsAny(n, " \t\r\n") {
				return nil, nil, nil, pkiInvalid("invalid email SAN %q", n)
			}
			emails = appendUniqueStrings(emails, n)
		default:
			if !validSANDNSName(n) {
				return nil, nil, nil, pkiInvalid("invalid DNS name %q", n)
			}
			dns = appendUniqueStrings(dns, strings.ToLower(n))
		}
	}
	return dns, ips, emails, nil
}

// validSANDNSName accepts LDH names with an optional leading "*." label.
func validSANDNSName(n string) bool {
	n = strings.TrimPrefix(strings.ToLower(n), "*.")
	if n == "" || len(n) > 253 {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// pkiIssueLeaf signs req.CSR with req.CA and stores the certificate.
func (s *Server) pkiIssueLeaf(ctx context.Context, req leafRequest) (*issuedLeaf, error) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := s.pkiSigningCA(ctx, req.CA, now)
	if err != nil {
		return nil, err
	}
	tmplName := req.Template
	if tmplName == "" {
		tmplName = templateServer
	}
	if tmplName != templateServer && tmplName != templateClient {
		return nil, pkiInvalid("template must be server or client")
	}

	subject := pkix.Name{CommonName: req.CSR.Subject.CommonName}
	if !req.ExactNames {
		subject = req.CSR.Subject
		subject.ExtraNames = nil
	}
	if cn := strings.TrimSpace(req.CommonName); cn != "" {
		if len(cn) > 64 {
			return nil, pkiInvalid("commonName must be at most 64 characters")
		}
		subject.CommonName = cn
	}

	var names []string
	if !req.ExactNames {
		names = append(names, req.CSR.DNSNames...)
		for _, ip := range req.CSR.IPAddresses {
			names = append(names, ip.String())
		}
		names = append(names, req.CSR.EmailAddresses...)
	}
	names = append(names, req.ExtraSANs...)
	dns, ips, emails, err := splitSANs(names)
	if err != nil {
		return nil, err
	}
	if len(dns) == 0 && len(ips) == 0 && len(emails) == 0 && subject.CommonName != "" {
		// Relying parties ignore the CN; carry a host-like CN as a SAN.
		if ip := net.ParseIP(subject.CommonName); ip != nil {
			ips = []net.IP{ip}
		} else if tmplName == templateServer && validSANDNSName(subject.CommonName) {
			dns = []string{strings.ToLower(subject.CommonName)}
		}
	}
	if subject.CommonName == "" && len(dns) == 0 && len(ips) == 0 && len(emails) == 0 {
		return nil, pkiInvalid("certificate must have a common name or at least one subject alternative name")
	}

	notAfter := req.NotAfter
	if notAfter.IsZero() {
		v := req.Validity
		if v <= 0 {
			v = 365 * 24 * time.Hour
		}
		if v > maxLeafValidity {
			return nil, pkiInvalid("validity must be at most 3650 days")
		}
		notAfter = now.Add(v)
	}
	if !notAfter.After(now) {
		return nil, pkiInvalid("validity must end in the future")
	}
	// A certificate must not outlive its issuer.
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}

	serial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	usage := x509.KeyUsageDigitalSignature
	if _, isRSA := req.CSR.PublicKey.(*rsa.PublicKey); isRSA && tmplName == templateServer {
		usage |= x509.KeyUsageKeyEncipherment
	}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if tmplName == templateClient {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dns,
		IPAddresses:           ips,
		EmailAddresses:        emails,
		SignatureAlgorithm:    caSignatureAlgorithm(ca.signer.pub),
	}
	if dp := s.crlURL(ca.rec.CAID); dp != "" {
		tmpl.CRLDistributionPoints = []string{dp}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, req.CSR.PublicKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	chain, err := s.pkiChain(ctx, ca.rec)
	if err != nil {
		return nil, err
	}
	rec := store.PCACertificate{
		CertID:    cryptoutil.RandomHex(12),
		CAID:      ca.rec.CAID,
		Serial:    cert.SerialNumber.String(),
		CSRB64:    base64.StdEncoding.EncodeToString(csrPEM(req.CSR)),
		CertB64:   base64.StdEncoding.EncodeToString(der),
		Status:    "ISSUED",
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
		Template:  awsTemplateName(tmplName),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreateCertificate(ctx, rec); err != nil {
		return nil, fmt.Errorf("store certificate: %w", err)
	}
	return &issuedLeaf{rec: rec, cert: cert, chainPEM: chain}, nil
}

// revocationReasons maps AWS / console reason names to RFC 5280 CRLReason
// codes.
var revocationReasons = map[string]int{
	"UNSPECIFIED":                      0,
	"KEY_COMPROMISE":                   1,
	"CERTIFICATE_AUTHORITY_COMPROMISE": 2,
	"AFFILIATION_CHANGED":              3,
	"SUPERSEDED":                       4,
	"CESSATION_OF_OPERATION":           5,
	"PRIVILEGE_WITHDRAWN":              9,
	"A_A_COMPROMISE":                   10,
}

// consoleReasonNames are the CamelCase names stored and shown by the console.
var consoleReasonNames = map[int]string{
	0: "Unspecified", 1: "KeyCompromise", 2: "CACompromise", 3: "AffiliationChanged",
	4: "Superseded", 5: "CessationOfOperation", 9: "PrivilegeWithdrawn", 10: "AACompromise",
}

// normalizeRevocationReason accepts console (KeyCompromise) and AWS
// (KEY_COMPROMISE) spellings and returns the stored name and CRL code.
func normalizeRevocationReason(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return consoleReasonNames[0], 0, nil
	}
	for code, name := range consoleReasonNames {
		if strings.EqualFold(raw, name) {
			return name, code, nil
		}
	}
	if code, ok := revocationReasons[strings.ToUpper(raw)]; ok {
		return consoleReasonNames[code], code, nil
	}
	return "", 0, pkiInvalid("unsupported revocation reason")
}
