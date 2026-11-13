package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Console display of certificates imported through ACM ImportCertificate,
// and the full certificate chain (leaf to root) of every certificate the
// console shows.

// sourceACMImported is the console source of certificates imported through
// the ACM API. They are read-only in the console apart from deletion.
const sourceACMImported = "acm-imported"

func (s *Server) registerPKIDisplayRoutes(mux *http.ServeMux) {
	mux.HandleFunc("DELETE /v1/certificates/acm", s.handleV1DeleteImportedCertificate)
}

// handleV1DeleteImportedCertificate deletes a certificate imported through
// ACM ImportCertificate (?arn=...). Certificates Citadel issued are revoked,
// not deleted, so they are rejected here.
func (s *Server) handleV1DeleteImportedCertificate(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.DeleteImportedCertificate"
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	certARN := strings.TrimSpace(r.URL.Query().Get("arn"))
	if certARN == "" || len(certARN) > 2048 {
		s.writePKIError(w, r, ctx, action, "", pkiInvalid("arn is required"))
		return
	}
	c, err := s.store.GetACMCertificate(ctx, certARN)
	if err != nil {
		s.writePKIError(w, r, ctx, action, certARN, err)
		return
	}
	clear(c.KeyDER)
	if c.Type != store.ACMTypeImported {
		s.writePKIError(w, r, ctx, action, certARN, pkiInvalid("only imported certificates can be deleted"))
		return
	}
	if err := s.store.DeleteACMCertificate(ctx, certARN); err != nil {
		s.writePKIError(w, r, ctx, action, certARN, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: certARN, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"arn": certARN, "deleted": true})
}

// importedCertificateRows lists the account's ACM-imported certificates as
// console rows.
func (s *Server) importedCertificateRows(ctx context.Context, now time.Time) ([]nativeCertificate, error) {
	all, err := s.store.ListACMCertificates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]nativeCertificate, 0, len(all))
	for _, c := range all {
		if c.Type != store.ACMTypeImported {
			continue // private ACM certificates are listed under their CA
		}
		status := acmStatus(c, now)
		row := nativeCertificate{
			Source: sourceACMImported, ID: c.ARN, Subject: c.DomainName, Serial: c.Serial,
			Status: status, NotBefore: fmtTime(c.NotBefore), NotAfter: fmtTime(c.NotAfter),
			ExpiringSoon: expiringSoon(status, c.NotAfter, now),
		}
		if cert, err := parseCertificateB64(c.CertB64); err == nil {
			row.CommonName = cert.Subject.CommonName
			row.KeyAlgorithm = keyAlgorithmOf(cert.PublicKey)
			row.Issuer = cert.Issuer.String()
			if row.Subject == "" {
				row.Subject = cert.Subject.String()
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// importedCertificateDetail is the detail of an ACM-imported certificate.
func (s *Server) importedCertificateDetail(ctx context.Context, certARN string) (nativeCertificateDetail, bool) {
	c, err := s.store.GetACMCertificate(ctx, certARN)
	if err != nil {
		return nativeCertificateDetail{}, false
	}
	clear(c.KeyDER)
	if c.Type != store.ACMTypeImported {
		return nativeCertificateDetail{}, false
	}
	detail := nativeCertificateDetail{
		Source:    sourceACMImported,
		ID:        c.ARN,
		Status:    acmStatus(c, time.Now()),
		Serial:    c.Serial,
		NotBefore: fmtTime(c.NotBefore),
		NotAfter:  fmtTime(c.NotAfter),
		Domains:   strings.Join(c.SANs, ", "),
		ChainPEM:  strings.TrimSpace(c.ChainPEM),
	}
	if detail.ChainPEM != "" {
		detail.ChainPEM += "\n"
	}
	if pemStr, parsed, perr := decodeCertB64(c.CertB64); perr == nil {
		detail.PEM = pemStr
		applyParsedCert(&detail, parsed)
		detail.Chain = s.certificateChain(ctx, parsed, detail.ChainPEM)
	}
	return detail, true
}

// nativeChainCert is one certificate of a chain, leaf first.
type nativeChainCert struct {
	// Role is "leaf", "intermediate" or "root".
	Role       string `json:"role"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Serial     string `json:"serial"`
	NotBefore  string `json:"notBefore"`
	NotAfter   string `json:"notAfter"`
	IsCA       bool   `json:"isCA"`
	SelfSigned bool   `json:"selfSigned"`
	PEM        string `json:"pem"`
}

// maxChainDepth bounds chain building (and the work a crafted chain causes).
const maxChainDepth = 10

// certificateChain builds the chain from start up to a self-signed root. The
// issuers come from extraPEM (a stored issuer chain) first, then from the
// account's certificate authorities. It stops at the first certificate whose
// issuer it cannot find, so the result is as complete as Citadel's material
// allows; the last element is a root only when it is self-signed.
func (s *Server) certificateChain(ctx context.Context, start *x509.Certificate, extraPEM string) []nativeChainCert {
	if start == nil {
		return nil
	}
	provided := parsePEMCertificates(extraPEM)
	var cas []*x509.Certificate
	if list, err := s.store.ListCertificateAuthorities(ctx); err == nil {
		for _, ca := range list {
			if c, err := parseCertificateB64(ca.CACertB64); err == nil {
				cas = append(cas, c)
			}
		}
	}
	chain := []*x509.Certificate{start}
	for len(chain) < maxChainDepth {
		cur := chain[len(chain)-1]
		if isSelfSigned(cur) {
			break
		}
		next := findIssuer(cur, provided, chain, true)
		if next == nil {
			next = findIssuer(cur, cas, chain, true)
		}
		if next == nil {
			// The importer supplied the chain; trust its name linkage when the
			// signature can't be checked (e.g. a legacy algorithm in FIPS mode).
			next = findIssuer(cur, provided, chain, false)
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
	}
	out := make([]nativeChainCert, 0, len(chain))
	for i, c := range chain {
		selfSigned := isSelfSigned(c)
		role := "intermediate"
		switch {
		case selfSigned:
			role = "root"
		case i == 0 && !c.IsCA:
			role = "leaf"
		}
		out = append(out, nativeChainCert{
			Role: role, Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: fmt.Sprintf("%x", c.SerialNumber),
			NotBefore: fmtTime(c.NotBefore), NotAfter: fmtTime(c.NotAfter), IsCA: c.IsCA, SelfSigned: selfSigned,
			PEM: string(encodeCertificatePEM(c.Raw)),
		})
	}
	return out
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// findIssuer returns the candidate that issued c and is not already in the
// chain. With verify it also requires a valid signature.
func findIssuer(c *x509.Certificate, candidates, chain []*x509.Certificate, verify bool) *x509.Certificate {
	for _, cand := range candidates {
		if !bytes.Equal(cand.RawSubject, c.RawIssuer) || inChain(cand, chain) {
			continue
		}
		if verify && c.CheckSignatureFrom(cand) != nil {
			continue
		}
		return cand
	}
	return nil
}

func inChain(c *x509.Certificate, chain []*x509.Certificate) bool {
	for _, x := range chain {
		if bytes.Equal(x.Raw, c.Raw) {
			return true
		}
	}
	return false
}

// parsePEMCertificates parses the CERTIFICATE blocks of s, skipping any that
// do not parse.
func parsePEMCertificates(s string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(s)
	for len(out) < maxChainDepth {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
	return out
}
