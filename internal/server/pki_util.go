package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
)

// subjectConfig is a CA subject as entered in the console or AWS API.
type subjectConfig struct {
	Country          string
	State            string
	Locality         string
	Organization     string
	OrganizationUnit string
	CommonName       string
}

// formatSubjectDN renders a subject as "C=..,O=..,CN=.." for display.
func formatSubjectDN(subj subjectConfig) string {
	var parts []string
	for _, kv := range [][2]string{
		{"C", subj.Country}, {"ST", subj.State}, {"L", subj.Locality},
		{"O", subj.Organization}, {"OU", subj.OrganizationUnit}, {"CN", subj.CommonName},
	} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	return strings.Join(parts, ",")
}

// generateSerialNumber returns a random positive 127-bit serial number
// (RFC 5280 allows up to 20 octets; CA/B Forum requires 64 bits of entropy).
func generateSerialNumber() (*big.Int, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	raw[0] &= 0x7F
	if raw[0] == 0 {
		raw[0] = 0x01 // keep the full length so serials never collapse to small values
	}
	return new(big.Int).SetBytes(raw), nil
}

// encodeCertificatePEM encodes a DER certificate to PEM.
func encodeCertificatePEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// parseCertificateB64 decodes base64-encoded DER certificate bytes.
func parseCertificateB64(b64 string) (*x509.Certificate, error) {
	if strings.TrimSpace(b64) == "" {
		return nil, fmt.Errorf("no certificate material")
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

func appendUniqueStrings(existing []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(existing))
	for _, v := range existing {
		seen[strings.ToLower(v)] = struct{}{}
	}
	for _, v := range extra {
		if v == "" {
			continue
		}
		if _, ok := seen[strings.ToLower(v)]; ok {
			continue
		}
		seen[strings.ToLower(v)] = struct{}{}
		existing = append(existing, v)
	}
	return existing
}

func appendUniqueIPs(existing []net.IP, extra ...net.IP) []net.IP {
	seen := make(map[string]struct{}, len(existing))
	for _, v := range existing {
		seen[v.String()] = struct{}{}
	}
	for _, v := range extra {
		if v == nil {
			continue
		}
		if _, ok := seen[v.String()]; ok {
			continue
		}
		seen[v.String()] = struct{}{}
		existing = append(existing, v)
	}
	return existing
}

// caKeyAlias builds a stable, alias-safe name for a CA signing key so it is
// identifiable in the KMS console. The short CA ID suffix keeps the alias
// unique even when several authorities share a common name.
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

// assignCAKeyAlias attaches a descriptive alias to a CA signing key. It is
// best-effort: the CA already exists, so a naming collision must not fail it.
func (s *Server) assignCAKeyAlias(ctx context.Context, keyID, commonName, caID string) {
	alias := caKeyAlias(commonName, caID)
	if err := s.store.CreateAlias(ctx, alias, keyID); err != nil {
		log.Printf("certificates: failed to assign alias %q to CA key %s: %v", alias, keyID, err)
	}
}
