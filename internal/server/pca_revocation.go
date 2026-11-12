package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// CRL (certificate revocation list) generation.

// buildCRL returns a DER CRL for ca listing its revoked certificates. ctx
// decides tenant scope; the public distribution point passes an unscoped
// context.
func (s *Server) buildCRL(ctx context.Context, ca store.PCACertificateAuthority) ([]byte, error) {
	caCert, err := parseCertificateB64(ca.CACertB64)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	key, err := s.store.ResolveByID(ctx, ca.KMSKeyID)
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(key.PublicKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("CA public key: %w", err)
	}
	certs, err := s.store.ListCertificates(ctx, ca.CAID)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	var entries []x509.RevocationListEntry
	for _, c := range certs {
		if c.Status != "REVOKED" || c.RevokedAt == nil {
			continue
		}
		serial, ok := new(big.Int).SetString(c.Serial, 10)
		if !ok {
			continue
		}
		_, code, err := normalizeRevocationReason(c.RevocationReason)
		if err != nil {
			code = 0
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: c.RevokedAt.UTC(), ReasonCode: code})
	}
	now := time.Now().UTC()
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(now.UnixNano()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(7 * 24 * time.Hour),
		SignatureAlgorithm:        caSignatureAlgorithm(pub),
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, caCert, &caSigner{key: key, pub: pub})
}

// handleCRLDownload serves a CA's CRL in DER form at /crl/{ca_id}[.crl].
// Relying parties fetch CRLs anonymously, so this is public.
func (s *Server) handleCRLDownload(w http.ResponseWriter, r *http.Request) {
	caID := strings.TrimSuffix(r.PathValue("ca_id"), ".crl")
	if caID == "" || len(caID) > 64 {
		http.Error(w, "CA not found", http.StatusNotFound)
		return
	}
	ca, err := s.store.GetCertificateAuthorityByID(r.Context(), caID)
	if err != nil {
		http.Error(w, "CA not found", http.StatusNotFound)
		return
	}
	crl, err := s.buildCRL(r.Context(), ca)
	if err != nil {
		log.Printf("crl %s: %v", caID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=ca-%s.crl", caID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(crl)
}
