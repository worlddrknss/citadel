package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Native read/write /v1 detail endpoints backing the SPA drawers for KMS keys
// and certificates. They reuse the existing store methods and the same
// cookie/token auth as the rest of the native API so the SPA can present full
// key and certificate metadata without falling back to the SigV4 AWS facade.

type nativeKMSGrant struct {
	GrantID           string   `json:"grantId"`
	GranteePrincipal  string   `json:"granteePrincipal"`
	RetiringPrincipal string   `json:"retiringPrincipal,omitempty"`
	Operations        []string `json:"operations"`
	Name              string   `json:"name,omitempty"`
	CreatedAt         string   `json:"createdAt"`
}

type nativeKMSKeyDetail struct {
	KeyID                string           `json:"keyId"`
	ARN                  string           `json:"arn"`
	Description          string           `json:"description"`
	Enabled              bool             `json:"enabled"`
	KeyUsage             string           `json:"keyUsage"`
	KeySpec              string           `json:"keySpec"`
	KeyState             string           `json:"keyState"`
	CreatedAt            string           `json:"createdAt"`
	DeletionDate         string           `json:"deletionDate,omitempty"`
	EncryptionAlgorithms []string         `json:"encryptionAlgorithms,omitempty"`
	SigningAlgorithms    []string         `json:"signingAlgorithms,omitempty"`
	PolicyDocument       string           `json:"policyDocument"`
	Aliases              []string         `json:"aliases"`
	Grants               []nativeKMSGrant `json:"grants"`
	PublicKeyPEM         string           `json:"publicKeyPem,omitempty"`
}

// handleV1KMSKeyDetail returns the full metadata projection for a single KMS
// key: state, algorithms, key policy, aliases, grants, and (for asymmetric
// keys) the exported public key in PEM form.
func (s *server) handleV1KMSKeyDetail(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	keyID := strings.TrimSpace(r.URL.Query().Get("keyId"))
	if keyID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "keyId is required")
		return
	}
	key, err := s.store.ResolveByID(ctx, keyID)
	if err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "key not found")
		return
	}
	meta := toKeyMetadata(key)
	detail := nativeKMSKeyDetail{
		KeyID:                key.ID,
		ARN:                  key.ARN,
		Description:          key.Description,
		Enabled:              key.Enabled,
		KeyUsage:             meta.KeyUsage,
		KeySpec:              meta.KeySpec,
		KeyState:             meta.KeyState,
		CreatedAt:            key.CreatedAt.UTC().Format(time.RFC3339),
		EncryptionAlgorithms: meta.EncryptionAlgorithms,
		SigningAlgorithms:    meta.SigningAlgorithms,
		Aliases:              []string{},
		Grants:               []nativeKMSGrant{},
	}
	if key.DeletionDate != nil {
		detail.DeletionDate = key.DeletionDate.UTC().Format(time.RFC3339)
	}

	if doc, perr := s.store.GetKeyPolicy(ctx, key.ID, "default"); perr == nil {
		detail.PolicyDocument = doc
	}

	if aliases, aerr := s.store.ListAliases(ctx); aerr == nil {
		for _, a := range aliases {
			if a.TargetKeyID == key.ID {
				detail.Aliases = append(detail.Aliases, a.AliasName)
			}
		}
	}

	if grants, gerr := s.store.ListGrants(ctx, key.ID); gerr == nil {
		for _, g := range grants {
			detail.Grants = append(detail.Grants, nativeKMSGrant{
				GrantID:           g.GrantID,
				GranteePrincipal:  g.GranteePrincipal,
				RetiringPrincipal: g.RetiringPrincipal,
				Operations:        g.Operations,
				Name:              g.Name,
				CreatedAt:         g.CreatedAt.UTC().Format(time.RFC3339),
			})
		}
	}

	if len(key.PublicKeyRaw) > 0 {
		detail.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.PublicKeyRaw}))
	}

	writeNativeJSON(w, http.StatusOK, detail)
}

type nativePutKeyPolicyRequest struct {
	KeyID          string `json:"keyId"`
	PolicyDocument string `json:"policyDocument"`
}

// handleV1PutKMSKeyPolicy replaces the default key policy for a KMS key.
func (s *server) handleV1PutKMSKeyPolicy(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativePutKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "keyId is required")
		return
	}
	if _, err := s.store.ResolveByID(ctx, keyID); err != nil {
		writeNativeError(w, http.StatusNotFound, "not_found", "key not found")
		return
	}
	if err := s.store.PutKeyPolicy(ctx, keyID, "default", req.PolicyDocument); err != nil {
		writeNativeError(w, http.StatusBadRequest, "policy_failed", err.Error())
		return
	}
	s.recordAudit(ctx, auditEvent{Action: "citadel.PutKeyPolicy", KeyID: keyID, Result: "ok", Actor: r.RemoteAddr})
	writeNativeJSON(w, http.StatusOK, map[string]any{"keyId": keyID, "saved": true})
}

type nativeCertificateDetail struct {
	Source             string   `json:"source"`
	ID                 string   `json:"id"`
	Status             string   `json:"status"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	Serial             string   `json:"serial"`
	NotBefore          string   `json:"notBefore,omitempty"`
	NotAfter           string   `json:"notAfter,omitempty"`
	KeyAlgorithm       string   `json:"keyAlgorithm,omitempty"`
	SignatureAlgorithm string   `json:"signatureAlgorithm,omitempty"`
	SANs               []string `json:"sans,omitempty"`
	IsCA               bool     `json:"isCA"`
	CAType             string   `json:"caType,omitempty"`
	Template           string   `json:"template,omitempty"`
	KMSKeyID           string   `json:"kmsKeyId,omitempty"`
	Domains            string   `json:"domains,omitempty"`
	RevokedAt          string   `json:"revokedAt,omitempty"`
	RevocationReason   string   `json:"revocationReason,omitempty"`
	PEM                string   `json:"pem,omitempty"`
	ChainPEM           string   `json:"chainPem,omitempty"`
}

// handleV1CertificateDetail returns the full metadata and PEM material for a
// single CA, issued certificate, or Let's Encrypt certificate.
func (s *server) handleV1CertificateDetail(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	q := r.URL.Query()
	source := strings.TrimSpace(q.Get("source"))
	id := strings.TrimSpace(q.Get("id"))
	if source == "" || id == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "source and id are required")
		return
	}

	switch source {
	case "pca-ca":
		cas, err := s.store.ListCertificateAuthorities(ctx)
		if err != nil {
			writeNativeError(w, http.StatusInternalServerError, "detail_failed", err.Error())
			return
		}
		for _, ca := range cas {
			if ca.CAID != id {
				continue
			}
			detail := nativeCertificateDetail{
				Source:    "pca-ca",
				ID:        ca.CAID,
				Status:    ca.State,
				Subject:   ca.SubjectDN,
				NotBefore: fmtTime(ca.NotBefore),
				NotAfter:  fmtTime(ca.NotAfter),
				IsCA:      true,
				CAType:    ca.Type,
				KMSKeyID:  ca.KMSKeyID,
			}
			if pemStr, cert, perr := decodeCertB64(ca.CACertB64); perr == nil {
				detail.PEM = pemStr
				detail.ChainPEM = pemStr
				applyParsedCert(&detail, cert)
			}
			writeNativeJSON(w, http.StatusOK, detail)
			return
		}
		writeNativeError(w, http.StatusNotFound, "not_found", "certificate authority not found")
		return

	case "pca-cert":
		cert, err := s.store.GetCertificate(ctx, id)
		if err != nil {
			writeNativeError(w, http.StatusNotFound, "not_found", "certificate not found")
			return
		}
		detail := nativeCertificateDetail{
			Source:           "pca-cert",
			ID:               cert.CertID,
			Status:           cert.Status,
			Serial:           cert.Serial,
			NotBefore:        fmtTime(cert.NotBefore),
			NotAfter:         fmtTime(cert.NotAfter),
			Template:         cert.Template,
			RevocationReason: cert.RevocationReason,
		}
		if cert.RevokedAt != nil {
			detail.RevokedAt = fmtTime(*cert.RevokedAt)
		}
		if pemStr, parsed, perr := decodeCertB64(cert.CertB64); perr == nil {
			detail.PEM = pemStr
			applyParsedCert(&detail, parsed)
		}
		// The issuing CA certificate forms the chain.
		if cas, cerr := s.store.ListCertificateAuthorities(ctx); cerr == nil {
			for _, ca := range cas {
				if ca.CAID == cert.CAID {
					if caPEM, _, perr := decodeCertB64(ca.CACertB64); perr == nil {
						detail.ChainPEM = caPEM
					}
					break
				}
			}
		}
		writeNativeJSON(w, http.StatusOK, detail)
		return

	case "lets-encrypt":
		cert, err := s.store.GetACMELECertificate(ctx, id)
		if err != nil {
			writeNativeError(w, http.StatusNotFound, "not_found", "certificate not found")
			return
		}
		detail := nativeCertificateDetail{
			Source:    "lets-encrypt",
			ID:        cert.CertID,
			Status:    cert.Status,
			Serial:    cert.Serial,
			NotBefore: fmtTime(cert.NotBefore),
			NotAfter:  fmtTime(cert.NotAfter),
			Domains:   cert.Domains,
		}
		if pemStr, parsed, perr := decodeCertB64(cert.CertB64); perr == nil {
			detail.PEM = pemStr
			applyParsedCert(&detail, parsed)
		}
		if raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(cert.ChainB64)); derr == nil {
			detail.ChainPEM = string(raw)
		}
		writeNativeJSON(w, http.StatusOK, detail)
		return

	default:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "unknown certificate source")
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// decodeCertB64 decodes a base64-encoded certificate that may itself be either
// raw DER or already-PEM-encoded bytes, returning the PEM string and the parsed
// certificate.
func decodeCertB64(b64 string) (string, *x509.Certificate, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", nil, err
	}
	if bytes.Contains(raw, []byte("-----BEGIN")) {
		block, _ := pem.Decode(raw)
		if block == nil {
			return string(raw), nil, errors.New("invalid PEM material")
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		return string(raw), cert, perr
	}
	cert, perr := x509.ParseCertificate(raw)
	if perr != nil {
		return "", nil, perr
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	return pemStr, cert, nil
}

// applyParsedCert copies parsed x509 fields onto a certificate detail.
func applyParsedCert(d *nativeCertificateDetail, cert *x509.Certificate) {
	if cert == nil {
		return
	}
	if d.Subject == "" {
		d.Subject = cert.Subject.String()
	}
	d.Issuer = cert.Issuer.String()
	if d.Serial == "" && cert.SerialNumber != nil {
		d.Serial = fmt.Sprintf("%x", cert.SerialNumber)
	}
	if d.NotBefore == "" {
		d.NotBefore = fmtTime(cert.NotBefore)
	}
	if d.NotAfter == "" {
		d.NotAfter = fmtTime(cert.NotAfter)
	}
	d.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
	d.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	d.IsCA = d.IsCA || cert.IsCA
	if len(cert.DNSNames) > 0 {
		d.SANs = cert.DNSNames
	}
}
