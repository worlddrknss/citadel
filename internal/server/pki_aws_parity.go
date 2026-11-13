package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// ACM IdempotencyToken handling and the ACM PCA subordinate CA flow:
//
//	CreateCertificateAuthority (SUBORDINATE)  -> CA in PENDING_CERTIFICATE
//	GetCertificateAuthorityCsr                -> the CA's CSR
//	IssueCertificate on the parent with a SubordinateCACertificate_PathLenN/V1 template
//	ImportCertificateAuthorityCertificate     -> CA ACTIVE

// subordinateCATemplates maps the AWS subordinate CA templates to the path
// length they set.
var subordinateCATemplates = map[string]int{
	"SubordinateCACertificate_PathLen0/V1": 0,
	"SubordinateCACertificate_PathLen1/V1": 1,
	"SubordinateCACertificate_PathLen2/V1": 2,
	"SubordinateCACertificate_PathLen3/V1": 3,
}

// isSubordinateCATemplate reports whether a stored template name issued a
// CA certificate.
func isSubordinateCATemplate(name string) bool {
	return strings.HasPrefix(name, "SubordinateCACertificate_")
}

// acmIdempotencyTokenRe is AWS's IdempotencyToken pattern and length.
var acmIdempotencyTokenRe = regexp.MustCompile(`^\w{1,32}$`)

// acmIdempotent runs create(newARN) unless token was used by the same
// operation in the caller's account within the last hour, in which case the
// ARN of that first request is returned. Reusing a token with different
// parameters is an InvalidParameterException. An empty token always runs
// create.
func (s *Server) acmIdempotent(ctx context.Context, operation, token, newARN string, params any, create func(arn string) error) (string, error) {
	if token == "" {
		return newARN, create(newARN)
	}
	if !acmIdempotencyTokenRe.MatchString(token) {
		return "", pkiInvalid("IdempotencyToken must be 1 to 32 letters, digits or underscores")
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	rec, claimed, err := s.store.ClaimACMIdempotencyToken(ctx, store.ACMIdempotencyRecord{
		Operation: operation, Token: token, ParamsHash: hash, ARN: newARN, CreatedAt: now,
	}, now.Add(-store.ACMIdempotencyWindow))
	if err != nil {
		return "", err
	}
	if !claimed {
		if rec.ParamsHash != hash {
			return "", pkiConflict("InvalidParameterException", "IdempotencyToken was already used with different parameters")
		}
		return rec.ARN, nil
	}
	if err := create(newARN); err != nil {
		// Free the token so a retry of a failed request can succeed.
		if rerr := s.store.ReleaseACMIdempotencyToken(ctx, operation, token, newARN); rerr != nil {
			return newARN, errors.Join(err, rerr)
		}
		return newARN, err
	}
	return newARN, nil
}

func pkixSubject(subj subjectConfig) pkix.Name {
	subject := pkix.Name{CommonName: subj.CommonName}
	if subj.Organization != "" {
		subject.Organization = []string{subj.Organization}
	}
	if subj.OrganizationUnit != "" {
		subject.OrganizationalUnit = []string{subj.OrganizationUnit}
	}
	if subj.Country != "" {
		subject.Country = []string{strings.ToUpper(subj.Country)}
	}
	if subj.State != "" {
		subject.Province = []string{subj.State}
	}
	if subj.Locality != "" {
		subject.Locality = []string{subj.Locality}
	}
	return subject
}

// pkiCreatePendingSubordinateCA creates a subordinate CA key and CSR and
// stores the CA in PENDING_CERTIFICATE.
func (s *Server) pkiCreatePendingSubordinateCA(ctx context.Context, keyAlg string, subj subjectConfig) (store.PCACertificateAuthority, error) {
	if keyAlg == "" {
		keyAlg = keyAlgRSA2048
	}
	keySpec, err := kmsKeySpecForAlgorithm(keyAlg)
	if err != nil {
		return store.PCACertificateAuthority{}, err
	}
	for _, f := range []*string{&subj.CommonName, &subj.Organization, &subj.OrganizationUnit, &subj.Country, &subj.State, &subj.Locality} {
		*f = strings.TrimSpace(*f)
	}
	if err := validateSubject(subj); err != nil {
		return store.PCACertificateAuthority{}, err
	}
	key, err := s.store.CreateKey(ctx, "Private CA key: "+subj.CommonName, store.KeyUsageSignVerify, keySpec)
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("create CA key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(key.PublicKeyRaw)
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("parse CA public key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkixSubject(subj), SignatureAlgorithm: caSignatureAlgorithm(pub),
	}, &caSigner{key: key, pub: pub})
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("create CA CSR: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	caID := cryptoutil.RandomHex(12)
	rec := store.PCACertificateAuthority{
		CAID: caID, ARN: s.pcaCAARN(ctx, caID), Type: "SUBORDINATE", KMSKeyID: key.ID,
		SubjectDN: formatSubjectDN(subj), State: store.CAStatePendingCertificate, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateCertificateAuthority(ctx, rec); err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("store CA: %w", err)
	}
	csrPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := s.store.PutCertificateAuthorityCSR(ctx, caID, base64.StdEncoding.EncodeToString(csrPEMBytes)); err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("store CA CSR: %w", err)
	}
	s.assignCAKeyAlias(ctx, key.ID, subj.CommonName, caID)
	return rec, nil
}

func (s *Server) pcaGetCertificateAuthorityCsr(ctx context.Context, body []byte) (any, string, error) {
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
	csrB64, err := s.store.GetCertificateAuthorityCSR(ctx, ca.CAID)
	if errors.Is(err, store.ErrCANotFound) {
		return nil, ca.ARN, pkiConflict("InvalidStateException", "certificate authority has no CSR: only subordinate CAs created with CreateCertificateAuthority have one")
	}
	if err != nil {
		return nil, ca.ARN, err
	}
	csrPEMBytes, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		return nil, ca.ARN, fmt.Errorf("stored CSR: %w", err)
	}
	return map[string]string{"Csr": string(csrPEMBytes)}, ca.ARN, nil
}

// pkiIssueSubordinateCACert signs a subordinate CA certificate for csr with
// parentRec, as IssueCertificate does with a SubordinateCACertificate
// template, and stores it as one of the parent's issued certificates.
func (s *Server) pkiIssueSubordinateCACert(ctx context.Context, parentRec store.PCACertificateAuthority, csr *x509.CertificateRequest, pathLen int, notAfter time.Time) (store.PCACertificate, error) {
	now := time.Now().UTC().Truncate(time.Second)
	parent, err := s.pkiSigningCA(ctx, parentRec, now)
	if err != nil {
		return store.PCACertificate{}, err
	}
	if err := checkApprovedPublicKey(csr.PublicKey); err != nil {
		return store.PCACertificate{}, err
	}
	if strings.TrimSpace(csr.Subject.CommonName) == "" {
		return store.PCACertificate{}, pkiInvalid("the CSR of a CA certificate must have a common name")
	}
	// RFC 5280 §4.2.1.9: the child's path length must fit below the parent's.
	pc := parent.cert
	switch {
	case pc.MaxPathLen == 0 && pc.MaxPathLenZero:
		return store.PCACertificate{}, pkiConflict("InvalidStateException", "the issuing CA's path length constraint does not allow subordinate CAs")
	case pc.MaxPathLen > 0 && pathLen >= pc.MaxPathLen:
		return store.PCACertificate{}, pkiInvalid("the template's path length must be less than the issuing CA's (%d)", pc.MaxPathLen)
	}
	if !notAfter.After(now) {
		return store.PCACertificate{}, pkiInvalid("validity must end in the future")
	}
	if notAfter.After(pc.NotAfter) {
		notAfter = pc.NotAfter
	}
	serial, err := generateSerialNumber()
	if err != nil {
		return store.PCACertificate{}, err
	}
	subject := csr.Subject
	subject.ExtraNames = nil
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
		SignatureAlgorithm:    caSignatureAlgorithm(parent.signer.pub),
	}
	if dp := s.crlURL(parent.rec.CAID); dp != "" {
		tmpl.CRLDistributionPoints = []string{dp}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, csr.PublicKey, parent.signer)
	if err != nil {
		return store.PCACertificate{}, fmt.Errorf("sign subordinate CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return store.PCACertificate{}, err
	}
	rec := store.PCACertificate{
		CertID: cryptoutil.RandomHex(12), CAID: parent.rec.CAID, Serial: cert.SerialNumber.String(),
		CSRB64: base64.StdEncoding.EncodeToString(csrPEM(csr)), CertB64: base64.StdEncoding.EncodeToString(der),
		Status: "ISSUED", NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
		Template: fmt.Sprintf("SubordinateCACertificate_PathLen%d/V1", pathLen), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateCertificate(ctx, rec); err != nil {
		return store.PCACertificate{}, fmt.Errorf("store certificate: %w", err)
	}
	return rec, nil
}

// parsePEMCertificates decodes every CERTIFICATE block of a PEM bundle.
func parsePEMCertificates(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := raw
	for len(strings.TrimSpace(string(rest))) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("not a PEM certificate bundle")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// pcaImportCertificateAuthorityCertificate installs the signed certificate of
// a pending subordinate CA and activates it. The certificate must be a CA
// certificate for the CA's own key and must chain, through
// CertificateChain, to a self-signed root.
func (s *Server) pcaImportCertificateAuthorityCertificate(ctx context.Context, body []byte) (any, string, error) {
	var req struct {
		CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
		Certificate             []byte `json:"Certificate"`
		CertificateChain        []byte `json:"CertificateChain"`
	}
	if err := decodeAWS(body, &req); err != nil {
		return nil, "", err
	}
	ca, err := s.pkiLoadCA(ctx, req.CertificateAuthorityArn)
	if err != nil {
		return nil, req.CertificateAuthorityArn, err
	}
	if ca.State != store.CAStatePendingCertificate {
		return nil, ca.ARN, pkiConflict("InvalidStateException", "certificate authority is %s, not PENDING_CERTIFICATE", strings.ToLower(ca.State))
	}
	if len(req.Certificate) == 0 {
		return nil, ca.ARN, pkiInvalid("Certificate is required")
	}
	if len(req.CertificateChain) == 0 {
		return nil, ca.ARN, pkiInvalid("CertificateChain is required for a subordinate CA")
	}
	cert, err := parseCertificatePEM(req.Certificate)
	if err != nil {
		return nil, ca.ARN, pkiInvalid("Certificate must be a PEM certificate")
	}
	chain, err := parsePEMCertificates(req.CertificateChain)
	if err != nil || len(chain) == 0 {
		return nil, ca.ARN, pkiInvalid("CertificateChain must contain only PEM certificates")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ca.ARN, pkiInvalid("the certificate is not a CA certificate (CA:TRUE and keyCertSign are required)")
	}
	key, err := s.store.ResolveByID(ctx, ca.KMSKeyID)
	if err != nil {
		return nil, ca.ARN, fmt.Errorf("CA %s key: %w", ca.CAID, err)
	}
	pub, err := x509.ParsePKIXPublicKey(key.PublicKeyRaw)
	if err != nil {
		return nil, ca.ARN, fmt.Errorf("CA %s public key: %w", ca.CAID, err)
	}
	if !publicKeysEqual(pub, cert.PublicKey) {
		return nil, ca.ARN, pkiInvalid("the certificate does not match the certificate authority's key")
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range chain {
		if certIsSelfSigned(c) {
			roots.AddCert(c)
		} else {
			inters.AddCert(c)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, ca.ARN, pkiInvalid("the certificate does not chain to a self-signed root in CertificateChain")
	}
	// Link the issuing Citadel CA, when there is one, so chains are built
	// from it.
	parentID := ""
	if cas, err := s.store.ListCertificateAuthorities(ctx); err == nil {
		for _, other := range cas {
			if other.CAID == ca.CAID || other.State == store.CAStatePendingCertificate {
				continue
			}
			if pc, err := parseCertificateB64(other.CACertB64); err == nil && cert.CheckSignatureFrom(pc) == nil {
				parentID = other.CAID
				break
			}
		}
	}
	ca.CACertB64 = base64.StdEncoding.EncodeToString(cert.Raw)
	ca.SubjectDN = cert.Subject.String()
	ca.PathLength = caPathLength(cert)
	ca.NotBefore, ca.NotAfter = cert.NotBefore.UTC(), cert.NotAfter.UTC()
	ca.ParentCAID = parentID
	if err := s.store.ActivateCertificateAuthority(ctx, ca); err != nil {
		if errors.Is(err, store.ErrCANotPending) {
			return nil, ca.ARN, pkiConflict("InvalidStateException", "certificate authority is not PENDING_CERTIFICATE")
		}
		return nil, ca.ARN, err
	}
	return nil, ca.ARN, nil
}
