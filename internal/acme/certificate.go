package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
)

func badCSR(format string, args ...any) *Problem {
	return newProblem(ProbBadCSR, http.StatusBadRequest, format, args...)
}

// approvedSignatureAlgorithm lists CSR signature algorithms that are FIPS
// approved; checking before CheckSignature avoids invoking SHA-1 or MD5.
func approvedSignatureAlgorithm(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	}
	return false
}

// checkCSR verifies the CSR and that its names exactly match the order.
func checkCSR(der []byte, order *Order, acctKey any) (*x509.CertificateRequest, *Problem) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, badCSR("cannot parse CSR: %v", err)
	}
	if !approvedSignatureAlgorithm(csr.SignatureAlgorithm) {
		return nil, badCSR("CSR signature algorithm %s is not allowed", csr.SignatureAlgorithm)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, badCSR("CSR signature is invalid")
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, badCSR("CSR ECDSA key must use P-256 or P-384")
		}
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < minRSABits || bits > maxRSABits {
			return nil, badCSR("CSR RSA key is %d bits; must be between %d and %d", bits, minRSABits, maxRSABits)
		}
	default:
		return nil, badCSR("CSR key type is not supported (want RSA or ECDSA P-256/P-384)")
	}
	if publicKeysEqual(csr.PublicKey, acctKey) {
		return nil, badCSR("CSR key must not be the account key")
	}
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, badCSR("CSR must not contain email or URI SANs")
	}

	want := map[Identifier]bool{}
	for _, id := range order.Identifiers {
		want[id] = true
	}
	got := map[Identifier]bool{}
	for _, n := range csr.DNSNames {
		got[Identifier{Type: IdentifierDNS, Value: strings.ToLower(n)}] = true
	}
	for _, ip := range csr.IPAddresses {
		id, prob := normalizeIdentifier(Identifier{Type: IdentifierIP, Value: ip.String()})
		if prob != nil {
			return nil, badCSR("CSR has an invalid IP address")
		}
		got[id] = true
	}
	if cn := csr.Subject.CommonName; cn != "" {
		cnID := Identifier{Type: IdentifierDNS, Value: strings.ToLower(cn)}
		if ip := net.ParseIP(cn); ip != nil {
			cnID, _ = normalizeIdentifier(Identifier{Type: IdentifierIP, Value: cn})
		}
		if !got[cnID] {
			return nil, badCSR("CSR common name %q is not among its subject alternative names", cn)
		}
	}
	if len(got) != len(want) {
		return nil, badCSR("CSR names do not exactly match the order identifiers")
	}
	for id := range got {
		if !want[id] {
			return nil, badCSR("CSR contains %s %q which is not in the order", id.Type, id.Value)
		}
	}
	return csr, nil
}

// handleFinalize implements order finalization (§7.4).
func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request, rel, id string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	ctx := r.Context()
	order, prob := s.loadOrder(ctx, req.account, id)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	w.Header().Set("Location", s.url(pathOrder+order.ID))
	if order.Status != StatusReady {
		s.problem(w, newProblem(ProbOrderNotReady, http.StatusForbidden, "order is %s, not ready", order.Status))
		return
	}
	var p struct {
		CSR string `json:"csr"`
	}
	if prob := decodePayload(req.payload, &p); prob != nil {
		s.problem(w, prob)
		return
	}
	der, err := b64.DecodeString(p.CSR)
	if err != nil || len(der) == 0 {
		s.problem(w, badCSR("csr is not base64url DER"))
		return
	}
	csr, prob := checkCSR(der, order, req.key)
	if prob != nil {
		s.problem(w, prob)
		return
	}

	// Claim the order: only one finalize may proceed.
	order.Status = StatusProcessing
	if err := s.store.UpdateOrder(ctx, order); err != nil {
		if errors.Is(err, ErrStale) {
			s.problem(w, newProblem(ProbOrderNotReady, http.StatusForbidden, "order changed concurrently"))
			return
		}
		s.problem(w, s.internal("updating order", err))
		return
	}

	ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.IssueTimeout)
	defer cancel()
	cert, prob := s.issue(ictx, req.account, order, csr)
	if prob != nil {
		order.Status, order.Error = StatusInvalid, prob
	} else {
		order.Status, order.CertificateID = StatusValid, cert.ID
	}
	if err := s.store.UpdateOrder(ictx, order); err != nil {
		s.problem(w, s.internal("updating order", err))
		return
	}
	if prob != nil {
		s.problem(w, prob)
		return
	}
	s.writeJSON(w, http.StatusOK, s.orderJSON(order))
}

func (s *Server) issue(ctx context.Context, acct *Account, order *Order, csr *x509.CertificateRequest) (*Certificate, *Problem) {
	chain, err := s.cfg.Issuer.Issue(ctx, IssueRequest{
		AccountRef:  acct.AccountRef,
		AccountID:   acct.ID,
		OrderID:     order.ID,
		CSR:         csr,
		Identifiers: slices.Clone(order.Identifiers),
		NotAfter:    order.NotAfter,
	})
	if err != nil {
		s.log.Error("acme: issuing certificate", "order", order.ID, "err", err)
		return nil, asProblem(err, ProbServerInternal, http.StatusInternalServerError, "certificate issuance failed")
	}
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, s.internal("issuer returned no PEM certificate", nil)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, s.internal("issuer returned an unparseable certificate", err)
	}
	if !publicKeysEqual(leaf.PublicKey, csr.PublicKey) {
		return nil, s.internal("issued certificate key does not match CSR", nil)
	}
	c := &Certificate{
		ID:        randomID(12),
		AccountID: acct.ID,
		OrderID:   order.ID,
		Serial:    serialHex(leaf.SerialNumber),
		ChainPEM:  chain,
		LeafDER:   leaf.Raw,
		NotAfter:  leaf.NotAfter,
	}
	if err := s.store.CreateCertificate(ctx, c); err != nil {
		return nil, s.internal("storing certificate", err)
	}
	return c, nil
}

// handleCert implements certificate download (§7.4.2).
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request, rel, id string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	if !req.postAsGet() {
		s.problem(w, malformed("certificate download must be POST-as-GET"))
		return
	}
	c, err := s.store.GetCertificate(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		s.problem(w, notFound("certificate"))
		return
	}
	if err != nil {
		s.problem(w, s.internal("loading certificate", err))
		return
	}
	if c.AccountID != req.account.ID {
		s.problem(w, unauthorized("certificate belongs to another account"))
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(c.ChainPEM)
}

// handleRevoke implements certificate revocation (§7.6).
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, rel string) {
	req, prob := s.verify(r, rel, jwkOrKID)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	var p struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if prob := decodePayload(req.payload, &p); prob != nil {
		s.problem(w, prob)
		return
	}
	reason := 0
	if p.Reason != nil {
		reason = *p.Reason
	}
	// RFC 5280 CRLReason; 7 is unused and 8 (removeFromCRL) is not a
	// revocation.
	if reason < 0 || reason > 10 || reason == 7 || reason == 8 {
		s.problem(w, newProblem(ProbBadRevocationReason, http.StatusBadRequest, "unsupported revocation reason %d", reason))
		return
	}
	der, err := b64.DecodeString(p.Certificate)
	if err != nil {
		s.problem(w, malformed("certificate is not base64url DER"))
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		s.problem(w, malformed("cannot parse certificate"))
		return
	}
	ctx := r.Context()
	rec, err := s.store.GetCertificateBySerial(ctx, serialHex(cert.SerialNumber))
	if errors.Is(err, ErrNotFound) {
		s.problem(w, notFound("certificate"))
		return
	}
	if err != nil {
		s.problem(w, s.internal("loading certificate", err))
		return
	}
	// The presented certificate must be byte-identical to the one issued;
	// otherwise a forged certificate with a copied serial could be used.
	if !bytes.Equal(rec.LeafDER, der) {
		s.problem(w, notFound("certificate"))
		return
	}
	if prob := s.authorizeRevocation(ctx, req, rec, cert); prob != nil {
		s.problem(w, prob)
		return
	}
	if rec.Revoked {
		s.problem(w, newProblem(ProbAlreadyRevoked, http.StatusBadRequest, "certificate is already revoked"))
		return
	}
	err = s.cfg.Issuer.Revoke(ctx, cert.SerialNumber, reason)
	if err != nil && !errors.Is(err, ErrAlreadyRevoked) {
		s.problem(w, asProblem(err, ProbServerInternal, http.StatusInternalServerError, "revocation failed"))
		return
	}
	alreadyRevoked := errors.Is(err, ErrAlreadyRevoked)
	for range 5 {
		if rec.Revoked {
			break
		}
		rec.Revoked, rec.RevocationReason = true, reason
		err := s.store.UpdateCertificate(ctx, rec)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrStale) {
			s.problem(w, s.internal("updating certificate", err))
			return
		}
		if rec, err = s.store.GetCertificate(ctx, rec.ID); err != nil {
			s.problem(w, s.internal("loading certificate", err))
			return
		}
	}
	if alreadyRevoked {
		s.problem(w, newProblem(ProbAlreadyRevoked, http.StatusBadRequest, "certificate is already revoked"))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// authorizeRevocation applies RFC 8555 §7.6: the request is signed by the
// certificate's key, by the account that ordered it, or by an account
// holding valid authorizations for every name in it.
func (s *Server) authorizeRevocation(ctx context.Context, req *authedRequest, rec *Certificate, cert *x509.Certificate) *Problem {
	if req.account == nil {
		if publicKeysEqual(cert.PublicKey, req.key) {
			return nil
		}
		return unauthorized("request is not signed by the certificate key")
	}
	if rec.AccountID == req.account.ID {
		return nil
	}
	var ids []Identifier
	for _, n := range cert.DNSNames {
		ids = append(ids, Identifier{Type: IdentifierDNS, Value: strings.TrimPrefix(strings.ToLower(n), "*.")})
	}
	for _, ip := range cert.IPAddresses {
		id, prob := normalizeIdentifier(Identifier{Type: IdentifierIP, Value: ip.String()})
		if prob != nil {
			return unauthorized("account is not authorized to revoke this certificate")
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return unauthorized("account is not authorized to revoke this certificate")
	}
	now := s.now()
	for _, id := range ids {
		if _, err := s.store.FindValidAuthorization(ctx, req.account.ID, id, now); err != nil {
			if errors.Is(err, ErrNotFound) {
				return unauthorized("account is not authorized to revoke this certificate")
			}
			return s.internal("checking authorizations", err)
		}
	}
	return nil
}
